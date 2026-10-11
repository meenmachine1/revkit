// Debug info: reading it for an image, and turning it into decompiler
// inputs.

#include "debug.h"

#include "revkit/debuginfo/image.h"
#include "revkit/inputs/ghidra_types.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <set>

namespace revkit::inputs {

namespace fs = std::filesystem;

namespace {

// A candidate PDB. The first candidate is the path the PE's CodeView record
// names, which the binary chose: only an MSF 7.00 file of at most 4 GiB is
// read in full, never any other file it points at.
std::optional<std::vector<std::uint8_t>> read_pdb_file(const fs::path &p) {
  static constexpr char kMagic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
  std::error_code ec;
  if (!fs::is_regular_file(p, ec)) return std::nullopt;
  const std::uintmax_t size = fs::file_size(p, ec);
  if (ec || size < sizeof kMagic - 1 || size > (std::uintmax_t{4} << 30)) return std::nullopt;
  std::ifstream in(p, std::ios::binary);
  if (!in) return std::nullopt;
  char head[sizeof kMagic - 1];
  if (!in.read(head, sizeof head) || std::memcmp(head, kMagic, sizeof head) != 0) return std::nullopt;
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
  std::memcpy(bytes.data(), head, sizeof head);
  in.read(reinterpret_cast<char *>(bytes.data() + sizeof head), static_cast<std::streamsize>(size - sizeof head));
  bytes.resize(sizeof head + static_cast<std::size_t>(in.gcount()));
  return bytes;
}

}  // namespace

std::shared_ptr<const DebugInfo> read_debug_info(const loader::Image &image, const fs::path &binary) {
  auto out = std::make_shared<DebugInfo>();
  debuginfo::ImageSections sections = debuginfo::dwarf_sections(image);
  out->warnings = sections.warnings;
  if (!sections.sections.get(".debug_info").empty()) {
    out->dwarf = debuginfo::import_dwarf(sections.sections, out->store);
    // DWARF has link-time addresses; a PIE loaded elsewhere moved.
    if (image.format == loader::Format::elf) out->dwarf_delta = image.image_base - image.file_base;
  }

  if (image.format == loader::Format::pe && image.codeview) {
    const loader::CodeViewRecord &cv = *image.codeview;
    std::vector<fs::path> candidates;
    if (!cv.pdb_path.empty()) {
      candidates.push_back(cv.pdb_path);
      std::string p = cv.pdb_path;
      std::replace(p.begin(), p.end(), '\\', '/');
      if (fs::path name = fs::path(p).filename(); !name.empty() && !binary.empty())
        candidates.push_back(binary.parent_path() / name);
    }
    if (!binary.empty()) candidates.push_back(binary.parent_path() / (binary.stem().string() + ".pdb"));
    for (const fs::path &p : candidates) {
      auto bytes = read_pdb_file(p);
      if (!bytes) continue;
      try {
        debuginfo::PdbIdentity id = debuginfo::read_pdb_identity(*bytes);
        const bool match = cv.rsds ? id.matches(cv.guid, cv.age) : id.signature == cv.signature && id.age == cv.age;
        if (!match) continue;  // another build's PDB
        debuginfo::PdbOptions options;
        options.image_base = image.image_base;  // addresses come out loaded
        out->pdb = debuginfo::read_pdb(*bytes, out->store, options);
        out->pdb_file = p.string();
        break;
      } catch (const debuginfo::PdbError &) {
        continue;
      }
    }
  }
  if (!out->dwarf && !out->pdb) return nullptr;
  return out;
}

namespace {

lift::Mutability mutability_at(const loader::Image &image, std::uint64_t a) {
  for (const loader::Block &b : image.blocks)
    if (a >= b.start && a - b.start < b.size) return b.perms.write ? lift::Mutability::normal : lift::Mutability::constant;
  return lift::Mutability::normal;
}

// What Ghidra's DWARF and PDB importers put in the program, from one
// reader's results (DWARFFunctionImporter: the function's name and its
// signature, with dynamic storage; globals and static locals as data).
class DebugApplier {
 public:
  DebugApplier(const DebugInfo &debug, const loader::Image &image, lift::DecompilerInputs &in, bool ghidra_pdb)
      : ghidra_pdb_(ghidra_pdb),
        debug_(debug),
        image_(image),
        in_(in),
        types_(debug.store, data_org(image, in.language), debug.dwarf ? &debug.dwarf->base_type_names : nullptr) {
    for (lift::FunctionFacts &f : in_.functions) by_entry_[f.entry] = &f;
    for (std::size_t i = 0; i < in_.data.size(); ++i) data_at_[in_.data[i].addr] = i;
  }

  void run() {
    if (debug_.dwarf) apply(*debug_.dwarf, debug_.dwarf_delta, true);
    if (debug_.pdb) {
      apply(*debug_.pdb, 0, false);
      publics(*debug_.pdb);
    }
    for (lift::DecompElement &t : types_.take_definitions()) in_.types.push_back(std::move(t));
  }

 private:
  // Ghidra's PDB applicator labels every S_PUB32 symbol: where a function
  // or data still has a default name (no procedure or data record named
  // it), the public's name replaces it, and thunks named after a function
  // follow it; elsewhere outside code it names the undefined bytes.
  void publics(const debuginfo::PdbDebugInfo &pdb) {
    auto is_default = [](const std::string &n) {
      for (const char *p : {"FUN_", "DAT_", "LAB_", "PTR_", "s_", "u_", "UNK_"})
        if (n.starts_with(p)) return true;
      return false;
    };
    std::map<std::string, std::string> renamed;  // old function name -> new
    for (const debuginfo::PdbPublic &p : pdb.publics) {
      if (p.address == 0 || p.name.empty() || p.name[0] == '?') continue;  // (C++ names: the demangler's)
      if (auto it = by_entry_.find(p.address); it != by_entry_.end()) {
        lift::FunctionFacts &f = *it->second;
        if (applied_.contains(p.address) || !is_default(f.name)) continue;
        renamed.emplace(f.name, p.name);
        f.name = p.name;
        continue;
      }
      if (auto it = data_at_.find(p.address); it != data_at_.end()) {
        lift::DataFacts &d = in_.data[it->second];
        if (d.source_name.empty() && is_default(d.name)) d.name = p.name;
        continue;
      }
      if (p.code || p.function || !image_.memory.is_mapped(p.address)) continue;
      lift::DataFacts d;
      d.addr = p.address;
      d.name = p.name;
      d.type = types_.builtin("undefined");
      d.mutability = mutability_at(image_, p.address);
      data_at_[p.address] = in_.data.size();
      in_.data.push_back(std::move(d));
    }
    // A thunk shows its target's name (thunk_FUN_... for a default one).
    for (lift::FunctionFacts &f : in_.functions)
      if (f.name.starts_with("thunk_"))
        if (auto it = renamed.find(f.name.substr(6)); it != renamed.end()) f.name = it->second;
  }

  void apply(const debuginfo::DebugInfo &info, std::uint64_t delta, bool dwarf) {
    std::set<std::uint64_t> done;
    for (const debuginfo::Function &f : info.functions) {
      const std::uint64_t entry = f.entry + delta;
      auto it = by_entry_.find(entry);
      if (it == by_entry_.end() || f.name.empty()) continue;
      // The first record with a name describes the entry (declaration and
      // definition can both be there).
      if (!done.insert(entry).second) continue;
      applied_.insert(entry);
      function(*it->second, f, dwarf);
      if (dwarf) dwarf_locals(*it->second, f, entry);
    }
    for (const debuginfo::Variable &v : info.variables) variable(v, delta);
  }

  void function(lift::FunctionFacts &ff, const debuginfo::Function &f, bool dwarf) {
    ff.name = f.name;
    ff.source_name = f.qualified_name.empty() ? f.name : f.qualified_name;
    if (f.noreturn) ff.noreturn = true;
    const types::Type *t = f.prototype.valid() ? &debug_.store.get(f.prototype) : nullptr;
    const auto *ft = t != nullptr ? t->as<types::FunctionType>() : nullptr;
    if (ft == nullptr) return;
    ff.signature_source = lift::SignatureSource::imported;
    ff.source_type = debug_.store.hash(f.prototype).hex();
    ff.convention = "default";
    // Ghidra's PDB applicator names a near-C procedure's convention
    // __cdecl (one without parameters too: `char * __cdecl
    // cJSON_Version(void)` in Ghidra's output; "unknown" with the signature
    // locked was "Unknown calling convention -- yet parameter storage is
    // locked"), and doesn't name the parameters (param_N):
    // Options::PdbSignatures::ghidra.
    const bool pdb = !dwarf && ghidra_pdb_;
    if (pdb && ft->cc == types::CallConv::Default) ff.convention = "__cdecl";
    ff.dynamic_storage = true;
    ff.ret.type = types_.ref(ft->ret);
    ff.ret.is_default = false;
    ff.varargs = ft->varargs;
    ff.params.clear();
    for (std::size_t i = 0; i < ft->params.size(); ++i) {
      lift::ParamFacts p;
      p.name = ft->params[i].name.empty() || pdb ? "param_" + std::to_string(i + 1) : ft->params[i].name;
      p.type = types_.ref(ft->params[i].type);
      ff.params.push_back(std::move(p));
    }
  }

  // The language's static frame values (its .dwarf register mapping file):
  // the CFA's stack offset at entry, and the frame register DWARF
  // expressions may use, as a fixed stack offset.
  struct Frame {
    int cfa = 0;
    int frame_reg = -1;
    int frame_offset = 0;
  };
  Frame frame() const {
    const std::string &l = in_.language;
    if (l.starts_with("x86:LE:64")) return {8, 6, -8};
    if (l.starts_with("x86:LE:32")) return {4, 5, -4};
    if (l.starts_with("RISCV:") && image_.bits == 64) return {8, -1, 0};
    if (l.starts_with("RISCV:")) return {4, -1, 0};
    return {0, -1, 0};
  }

  // DWARFFunctionImporter's locals: variables at a stack location, and
  // parameters spilled to the local area as <name>_local (Ghidra's
  // ParamSpillDWARFFunctionFixup); a variable whose location it can't
  // evaluate is a pre comment.
  void dwarf_locals(lift::FunctionFacts &ff, const debuginfo::Function &f, std::uint64_t entry) {
    using L = debuginfo::LocalVariable::Location;
    const Frame fr = frame();
    std::optional<std::int64_t> fb;
    switch (f.frame_base.location) {
      case L::Cfa: fb = fr.cfa; break;
      case L::Register:
        if (f.frame_base.reg == fr.frame_reg) fb = fr.frame_offset;
        break;
      case L::RegisterRelative:
        if (f.frame_base.reg == fr.frame_reg) fb = fr.frame_offset + f.frame_base.offset;
        break;
      default: break;
    }
    auto stack_offset = [&](const debuginfo::LocalVariable &v) -> std::optional<std::int64_t> {
      if (v.location == L::FrameRelative && fb) return *fb + v.offset;
      if (v.location == L::RegisterRelative && v.reg == fr.frame_reg && fr.frame_reg >= 0)
        return fr.frame_offset + v.offset;
      return std::nullopt;
    };
    std::set<std::string> used;
    for (const lift::ParamFacts &p : ff.params) used.insert(p.name);
    std::vector<lift::LocalFacts> locals;
    auto overlaps = [&](std::int64_t off, std::uint64_t size) {
      for (const lift::LocalFacts &l : locals)
        for (const lift::StorageVarnode &sv : l.storage) {
          auto so = static_cast<std::int64_t>(sv.offset);
          if (so < off + static_cast<std::int64_t>(size) && off < so + sv.size) return true;
        }
      return false;
    };
    auto add = [&](std::string name, types::TypeId type, std::int64_t off) {
      const std::uint64_t size = type.valid() ? types_.size(type) : 0;
      if (size == 0 || overlaps(off, size)) return;
      std::string unique = name;
      for (int n = 1; used.contains(unique); ++n) unique = name + "_" + std::to_string(n);
      used.insert(unique);
      lift::LocalFacts l;
      l.name = unique;
      l.storage.push_back({"stack", static_cast<std::uint64_t>(off), static_cast<int>(size)});
      l.type = types_.ref(type);
      l.type_size = static_cast<int>(size);
      l.source_type = debug_.store.hash(type).hex();
      locals.push_back(std::move(l));
    };
    std::map<std::uint64_t, std::string> unresolved;
    for (const debuginfo::LocalVariable &v : f.locals) {
      if (v.name.empty()) continue;
      std::optional<std::int64_t> off = stack_offset(v);
      if (v.is_param) {
        if (off && *off < 0) add(v.name + "_local", v.type, *off);
        continue;
      }
      if (off) {
        add(v.name, v.type, *off);
      } else if (v.location == L::Unknown || v.location == L::FrameRelative || v.location == L::RegisterRelative) {
        const std::uint64_t at = v.scope_start != 0 ? v.scope_start + (entry - f.entry) : entry;
        std::string &c = unresolved[at];
        if (!c.empty()) c += "\n";
        c += "Unresolved local var: " + (v.type.valid() ? types_.name(v.type) : std::string("undefined")) + " " +
             v.name + "@[???]";
      }
    }
    for (lift::LocalFacts &l : locals) ff.locals.push_back(std::move(l));
    for (auto &[at, text] : unresolved) in_.comments.push_back({at, lift::CommentFacts::pre, text});
  }

  void variable(const debuginfo::Variable &v, std::uint64_t delta) {
    const std::uint64_t addr = v.address + delta;
    if (v.name.empty() || !image_.memory.is_mapped(addr)) return;
    lift::DataFacts d;
    d.addr = addr;
    d.name = v.name;
    d.source_name = v.qualified_name.empty() ? v.name : v.qualified_name;
    std::uint64_t size = v.type.valid() ? types_.size(v.type) : 0;
    d.length = size == 0 ? 1 : size;
    d.type = v.type.valid() && size != 0 ? types_.ref(v.type) : types_.builtin("undefined");
    if (v.type.valid()) d.source_type = debug_.store.hash(v.type).hex();
    d.mutability = mutability_at(image_, addr);
    if (v.function_local && !v.scope.empty()) {
      auto [it, fresh] = scopes_.try_emplace(v.scope, 0);
      if (fresh) it->second = 0x4000000000000000ULL | scopes_.size();
      d.ns.emplace_back(it->second, v.scope);
    }
    if (auto it = data_at_.find(addr); it != data_at_.end()) {
      in_.data[it->second] = std::move(d);
    } else {
      data_at_[addr] = in_.data.size();
      in_.data.push_back(std::move(d));
    }
  }

  bool ghidra_pdb_;  // Options::PdbSignatures::ghidra
  std::set<std::uint64_t> applied_;  // entries a debug-info function record named
  const DebugInfo &debug_;
  const loader::Image &image_;
  lift::DecompilerInputs &in_;
  GhidraTypes types_;
  std::map<std::uint64_t, lift::FunctionFacts *> by_entry_;
  std::map<std::uint64_t, std::size_t> data_at_;
  std::map<std::string, std::uint64_t> scopes_;  // static locals' namespaces
};

}  // namespace

void apply_debug_info(const DebugInfo &debug, const loader::Image &image, lift::DecompilerInputs &in,
                      const Options &options) {
  DebugApplier(debug, image, in, options.pdb_signatures == Options::PdbSignatures::ghidra).run();
}

}  // namespace revkit::inputs
