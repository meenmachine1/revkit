// Hashing a program's functions for Function ID (docs/fid.md).

#include "revkit/fid/program.h"

#include "revkit/fid/hash.h"
#include "revkit/lift/sleigh_decoder.hh"

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace revkit::fid {

namespace {

std::string base_language(const std::string &id) {
  if (std::count(id.begin(), id.end(), ':') >= 4) return id.substr(0, id.rfind(':'));
  return id;
}

// Address -> the function whose body holds it (getFunctionContaining).
class BodyIndex {
 public:
  explicit BodyIndex(const analysis::FunctionList &fl) {
    for (std::size_t i = 0; i < fl.functions.size(); ++i)
      for (const facts::AddressRange &r : fl.functions[i].body.ranges())
        ranges_.push_back({r.first.offset, r.last.offset, i});
    std::sort(ranges_.begin(), ranges_.end(), [](const R &a, const R &b) { return a.first < b.first; });
  }
  std::optional<std::size_t> find(std::uint64_t a) const {
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), a, [](std::uint64_t v, const R &r) { return v < r.first; });
    if (it == ranges_.begin()) return std::nullopt;
    --it;
    if (a > it->last) return std::nullopt;
    return it->index;
  }

 private:
  struct R {
    std::uint64_t first, last;
    std::size_t index;
  };
  std::vector<R> ranges_;
};

}  // namespace

const ProgramFunction *ProgramHashes::find(std::uint64_t entry) const {
  auto it = std::lower_bound(functions.begin(), functions.end(), entry,
                             [](const ProgramFunction &f, std::uint64_t e) { return f.entry < e; });
  return it != functions.end() && it->entry == entry ? &*it : nullptr;
}

namespace {

// A PE's base relocations (the .reloc directory): the addresses the loader
// patches, which Ghidra's relocation table lists and FID's hasRelocation
// masks. Read through the image's memory, with every length checked.
void pe_base_relocations(const loader::Image &image, std::vector<std::uint64_t> &out) {
  if (!image.file) return;
  const auto &file = *image.file;
  auto u16 = [&](std::size_t o) -> std::optional<std::uint32_t> {
    if (o + 2 > file.size()) return std::nullopt;
    return std::to_integer<std::uint32_t>(file[o]) | std::to_integer<std::uint32_t>(file[o + 1]) << 8;
  };
  auto u32 = [&](std::size_t o) -> std::optional<std::uint32_t> {
    auto lo = u16(o), hi = u16(o + 2);
    if (!lo || !hi) return std::nullopt;
    return *lo | *hi << 16;
  };
  auto lfanew = u32(0x3c);
  if (!lfanew) return;
  const std::size_t opt = static_cast<std::size_t>(*lfanew) + 24;
  auto magic = u16(opt);
  if (!magic || (*magic != 0x10b && *magic != 0x20b)) return;
  const std::size_t dirs = opt + (*magic == 0x20b ? 112 : 96);
  auto count = u32(dirs - 4);
  if (!count || *count <= 5) return;
  auto rva = u32(dirs + 5 * 8), size = u32(dirs + 5 * 8 + 4);
  if (!rva || !size || *rva == 0 || *size == 0 || *size > (64u << 20)) return;
  std::vector<std::byte> dir(*size);
  if (image.memory.read(image.image_base + *rva, dir) != dir.size()) return;
  auto d16 = [&](std::size_t o) {
    return std::to_integer<std::uint32_t>(dir[o]) | std::to_integer<std::uint32_t>(dir[o + 1]) << 8;
  };
  std::size_t at = 0;
  while (at + 8 <= dir.size()) {
    const std::uint32_t page = d16(at) | d16(at + 2) << 16;
    const std::uint32_t block = d16(at + 4) | d16(at + 6) << 16;
    if (block < 8 || block > dir.size() - at) break;
    for (std::size_t e = at + 8; e + 2 <= at + block; e += 2) {
      const std::uint32_t entry = d16(e);
      const std::uint32_t type = entry >> 12;
      if (type == 0) continue;  // IMAGE_REL_BASED_ABSOLUTE: padding
      out.push_back(image.image_base + page + (entry & 0xfff));
    }
    at += block;
  }
}

}  // namespace

void image_relocations(const loader::Image &image, ProgramSource &source) {
  if (image.format == loader::Format::pe) pe_base_relocations(image, source.relocations);
  for (const loader::Relocation &r : image.relocations) {
    source.relocations.push_back(r.address);
    if (!r.symbol.empty()) source.relocation_symbols.emplace(r.address, r.symbol);
  }
  std::sort(source.relocations.begin(), source.relocations.end());
  source.relocations.erase(std::unique(source.relocations.begin(), source.relocations.end()), source.relocations.end());
}

ProgramHashes hash_program(const ProgramSource &src) {
  if (src.info == nullptr || src.functions == nullptr || !src.read || !src.flow)
    throw FidError("hash_program: incomplete source");
  const analysis::ProgramInfo &info = *src.info;
  const analysis::FunctionList &fl = *src.functions;
  ProgramHashes out;
  out.language = base_language(src.language);
  lift::SleighDecoder decoder(out.language);

  const BodyIndex bodies(fl);
  // Ghidra's no-return set, less thunks whose target returns: discovery
  // makes more entries than Ghidra (code after calls split off), so a call
  // to a busy thunk (operator delete's, free's) more often sits before one,
  // evidence Ghidra doesn't see; a thunk is no-return when what it jumps to
  // is (an import: by its name).
  std::vector<std::uint64_t> no_return;
  {
    std::set<std::uint64_t> all(src.no_return.begin(), src.no_return.end());
    for (std::uint64_t e : src.no_return) {
      const analysis::FunctionInfo *fi = fl.find(e);
      if (fi && (fi->flags & analysis::kFunctionThunk)) {
        if (!fi->import.empty() ? !analysis::is_known_no_return(fi->import)
                                : !all.contains(info.code_address(fi->thunk_target)))
          continue;
      }
      no_return.push_back(e);
    }
  }
  std::vector<std::uint32_t> base_context = decoder.default_context();
  auto context_at = [&](std::uint64_t address, bool thumb) {
    std::vector<std::uint32_t> words = base_context;
    for (const analysis::ContextSetting &c : info.context)
      if (c.range.contains(address)) decoder.set_context(words, c.name, c.value);
    if (!info.isa_context.empty()) decoder.set_context(words, info.isa_context, thumb ? 1 : 0);
    return words;
  };

  HashOptions options;
  options.skip_x86_nops = skips_x86_nops(out.language);
  options.relocated = [&](std::uint64_t first, std::uint64_t last) {
    auto it = std::lower_bound(src.relocations.begin(), src.relocations.end(), first);
    return it != src.relocations.end() && *it <= last;
  };
  // Ghidra makes a scalar operand an address when its analysis put a
  // memory reference on it (constant propagation, as revkit's DataRefs
  // record it): the instruction refers to the scalar's value.
  // An address computed into a register is Ghidra's reference on x86 (LEA,
  // MOV of an address); elsewhere it marks the part of an address an
  // instruction builds (AArch64's ADRP, RISC-V's AUIPC), where Ghidra puts
  // none.
  const bool x86 = out.language.starts_with("x86:");
  const analysis::FlowGraph *current = nullptr;
  options.address_operand = [&](std::uint64_t at, int, const lift::FidObject &scalar) {
    const auto v = static_cast<std::uint64_t>(scalar.value);
    if (current != nullptr) {
      for (const analysis::DataRef &d : current->data_refs)
        if (d.from == at && d.to == v && (x86 || d.access != analysis::DataAccess::address)) return true;
      for (const analysis::FlowRef &r : current->refs)
        if (r.to == v && r.from(*current) == at) return true;
    }
    if (!src.scalar_references) return false;
    // ScalarOperandAnalyzer: the unsigned value, past the first page and
    // not a typical mask, in memory, and not inside a function past its entry.
    const std::uint64_t u = scalar.bits >= 64 || scalar.bits == 0 ? v : v & ((std::uint64_t{1} << scalar.bits) - 1);
    if (u < 4096 || u == 0xffff || u == 0xff00 || u == 0xffffff || u == 0xff0000 || u == 0xff00ff ||
        u == 0xffffffff || u == 0xffffff00 || u == 0xffff0000 || u == 0xff000000)
      return false;
    if (!info.is_mapped(u)) return false;
    if (auto fn = bodies.find(u); fn && fl.functions[*fn].entry.offset != u) return false;  // offcut
    return true;
  };

  const std::size_t n = fl.functions.size();
  out.functions.resize(n);
  // Function index by entry, and thunks followed (getThunkedFunction(true)).
  std::unordered_map<std::uint64_t, std::size_t> by_entry;
  for (std::size_t i = 0; i < n; ++i) by_entry[fl.functions[i].entry.offset] = i;
  auto thunked = [&](std::size_t i) -> std::optional<std::size_t> {
    for (int hops = 0; hops < 16; ++hops) {
      const analysis::FunctionInfo &f = fl.functions[i];
      if (!(f.flags & analysis::kFunctionThunk)) return i;
      if (!f.import.empty()) return std::nullopt;  // an external function: no body
      auto it = by_entry.find(info.code_address(f.thunk_target));
      if (it == by_entry.end()) return std::nullopt;
      i = it->second;
    }
    return std::nullopt;
  };

  // Code units by address, for the bodies.
  const std::vector<analysis::CodeUnit> &code = fl.code;
  std::vector<std::vector<std::pair<std::uint64_t, std::uint64_t>>> calls(n);  // (call insn, target) per function
  std::vector<HashUnit> units;
  std::vector<std::byte> raw(64);
  for (std::size_t i = 0; i < n; ++i) {
    if (src.cancel && src.cancel->load(std::memory_order_relaxed)) throw FidError("cancelled");
    if (src.progress && (i % 64 == 0)) src.progress(i, n);
    const analysis::FunctionInfo &f = fl.functions[i];
    ProgramFunction &pf = out.functions[i];
    pf.entry = f.entry.offset;
    auto nm = src.names.find(pf.entry);
    pf.name = nm != src.names.end() ? nm->second : f.name;
    pf.thunk = (f.flags & analysis::kFunctionThunk) != 0;

    // Instructions in the body, in address order. Code the flow reaches
    // that no function claims is the function's too: discovery cuts bodies
    // after calls to functions it infers never return, where Ghidra's
    // bodies (with its weaker evidence) usually go on.
    auto g = src.flow(f.flow_key());
    std::unordered_set<std::uint64_t> extra;  // the code the flow reaches (below)
    auto in_extent = [&](std::uint64_t a) { return g ? extra.contains(a) : f.body.contains({f.entry.space, a}); };
    struct Piece {
      std::uint64_t address, end;
      bool thumb;
    };
    std::vector<Piece> pieces;
    if (!g) {
      for (const facts::AddressRange &r : f.body.ranges()) {
        auto it = std::lower_bound(code.begin(), code.end(), r.first.offset,
                                   [](const analysis::CodeUnit &c, std::uint64_t a) { return c.address < a; });
        for (; it != code.end() && it->address <= r.last.offset; ++it)
          pieces.push_back({it->address, it->address + it->length, it->thumb});
      }
    } else {
      // What the flow reaches from the entry through unclaimed code,
      // stopping after calls to what Ghidra holds non-returning.
      const bool thumb = (f.flags & analysis::kFunctionThumb) != 0;
      std::vector<std::uint64_t> work{f.entry.offset};
      std::unordered_set<std::uint64_t> seen;
      while (!work.empty()) {
        const std::uint64_t a = work.back();
        work.pop_back();
        if (!seen.insert(a).second) continue;
        const analysis::FlowInsn *fi = g->at(a);
        if (fi == nullptr || fi->length == 0) continue;
        const bool mine = f.body.contains({f.entry.space, a});
        if (!mine && bodies.find(a)) continue;  // another function's code
        pieces.push_back({a, a + fi->length, thumb});
        extra.insert(a);
        bool falls = fi->falls_through;
        if (fi->kind == analysis::FlowKind::call && !fi->fall_override)
          for (std::uint64_t t : fi->targets)
            if (std::binary_search(no_return.begin(), no_return.end(), info.code_address(t))) falls = false;
        if (falls) work.push_back(fi->fallthrough());
        if (fi->kind == analysis::FlowKind::jump || fi->kind == analysis::FlowKind::branch ||
            fi->kind == analysis::FlowKind::jump_indirect)
          for (std::uint64_t t : fi->targets) work.push_back(info.code_address(t));
      }
      std::sort(pieces.begin(), pieces.end(), [](const Piece &a, const Piece &b) { return a.address < b.address; });
    }
    units.clear();
    for (const Piece &p : pieces) {
      std::uint64_t at = p.address;
      while (at < p.end) {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(raw.size(), p.end - at + 16));
        const std::size_t got = src.read(at, std::span(raw.data(), want));
        if (got == 0) break;
        auto fi = decoder.fid(at, std::span(raw.data(), got), context_at(at, p.thumb));
        if (!fi || fi->length == 0 || fi->length > got) break;
        HashUnit u;
        u.address = at;
        u.bytes.resize(fi->length);
        for (std::size_t k = 0; k < fi->length; ++k) u.bytes[k] = std::to_integer<std::uint8_t>(raw[k]);
        u.insn = std::move(*fi);
        at += u.bytes.size();
        units.push_back(std::move(u));
      }
    }
    // Ghidra's analysis turns tail calls into calls (a CALL_RETURN flow
    // override, SharedReturnAnalyzer): a jump to a function's entry, and a
    // computed jump it can't resolve to a table (through an import's
    // pointer). The hash counts them as calls.
    std::unordered_set<std::uint64_t> tail_calls;
    if (g) {
      for (HashUnit &u : units) {
        const analysis::FlowInsn *fi = g->at(u.address);
        if (fi == nullptr || u.insn.call) continue;
        struct Mark {
          HashUnit &u;
          std::unordered_set<std::uint64_t> &tails;
          ~Mark() {
            if (u.insn.call) tails.insert(u.address);
          }
        } mark{u, tail_calls};
        if (fi->tail_call) u.insn.call = true;
        else if (fi->kind == analysis::FlowKind::jump && !fi->targets.empty() &&
                 by_entry.contains(info.code_address(fi->targets.front())) &&
                 info.code_address(fi->targets.front()) != f.entry.offset)
          u.insn.call = true;
        else if (fi->kind == analysis::FlowKind::jump_indirect && fi->targets.empty()) {
          // Only through an import's pointer, loaded just before.
          for (const analysis::DataRef &d : g->data_refs)
            if (d.access == analysis::DataAccess::read && d.from <= u.address && d.from + 32 >= u.address &&
                info.import_at(d.to) != nullptr)
              u.insn.call = true;
        }
      }
    }
    current = g.get();
    pf.hash = hash_function(units, options);
    current = nullptr;

    // Calls and terminators from the flow.
    if (g) {
      for (const analysis::FlowInsn &fi : g->insns) {
        if (!in_extent(fi.address)) continue;
        const bool tail = tail_calls.contains(fi.address);
        if (fi.kind == analysis::FlowKind::ret || tail ||
            (!fi.falls_through && fi.kind != analysis::FlowKind::jump && fi.kind != analysis::FlowKind::jump_indirect))
          pf.has_terminator = true;
        if (tail && fi.kind == analysis::FlowKind::jump) {  // a CALL_RETURN: its reference is a call
          for (std::uint64_t t : fi.targets) calls[i].emplace_back(fi.address, info.code_address(t));
          continue;
        }
        if (fi.kind != analysis::FlowKind::call && fi.kind != analysis::FlowKind::call_indirect) continue;
        if (fi.targets.empty()) {
          // An object file's call through a relocation: the symbol names the callee.
          auto rs = src.relocation_symbols.lower_bound(fi.address);
          if (rs != src.relocation_symbols.end() && rs->first < fi.address + fi.length)
            pf.external_callees.push_back(rs->second);
          continue;
        }
        for (std::uint64_t t : fi.targets) calls[i].emplace_back(fi.address, info.code_address(t));
      }
      for (const auto &[from, to] : g->ref_calls)
        if (in_extent(from)) calls[i].emplace_back(from, info.code_address(to));
    }
  }
  if (src.progress) src.progress(n, n);

  // Callees: per target address once, the function containing it, thunks
  // followed. Callers: who calls an entry or one of its thunks.
  std::vector<std::vector<std::pair<std::uint64_t, std::size_t>>> callers(n);  // (call insn, caller)
  for (std::size_t i = 0; i < n; ++i) {
    std::sort(calls[i].begin(), calls[i].end());
    std::unordered_set<std::uint64_t> done;
    for (const auto &[from, to] : calls[i]) {
      if (!done.insert(to).second) continue;
      auto c = bodies.find(to);
      if (!c) continue;
      const analysis::FunctionInfo &callee = fl.functions[*c];
      if ((callee.flags & analysis::kFunctionThunk) && !callee.import.empty())
        out.functions[i].external_callees.push_back(callee.import);
      if (auto t = thunked(*c)) out.functions[i].callees.push_back(*t);
      // Ghidra's parents: references to the callee's entry (or its thunks').
      if (fl.functions[*c].entry.offset == to) {
        std::size_t target = *c;
        for (int hops = 0; hops < 16; ++hops) {
          callers[target].emplace_back(from, i);
          auto t = thunked(target);
          if (!t || *t == target) break;
          target = *t;
        }
      }
    }
  }
  for (std::size_t i = 0; i < n; ++i) {
    std::sort(callers[i].begin(), callers[i].end());
    std::unordered_set<std::size_t> seen;
    for (const auto &[from, who] : callers[i])
      if (seen.insert(who).second) out.functions[i].callers.push_back(who);
  }
  return out;
}

}  // namespace revkit::fid
