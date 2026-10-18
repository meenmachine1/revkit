// lift::DecompilerInputs from the loader, discovery and debug info.

#include "data.h"
#include "debug.h"
#include "stack_locals.h"
#include "revkit/inputs/demangled.h"
#include "revkit/inputs/ghidra_archive.h"
#include "revkit/inputs/library.h"
#include "revkit/cparse/spec.h"
#include "revkit/inputs/ghidra_types.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/abi.hh"
#include "revkit/lift/context.hh"
#include "revkit/lift/lifter.hh"

#include "revkit/facts/fact_db.h"
#include "revkit/facts/thread_pool.h"

#include <atomic>
#include <optional>
#include <thread>
#include <unordered_set>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>
#include <span>

namespace revkit::inputs {

namespace an = analysis;

namespace {

constexpr std::uint64_t kUndefinedId = 0xc000000000000000ULL;  // Ghidra's DEFAULT data type

lift::DecompElement undefined_ref() {
  return {"typeref", {{"name", std::string("undefined")}, {"id", kUndefinedId}}, {}};
}

lift::DecompElement sized_undefined(int size) {
  return {"typeref", {{"name", "undefined" + std::to_string(size)}, {"id", kUndefinedId | (0xb3 + size)}}, {}};
}

lift::DecompElement undefined_array(std::uint64_t n) {
  return {"type",
          {{"arraysize", static_cast<std::int64_t>(n)},
           {"metatype", std::string("array")},
           {"name", std::string()},
           {"size", static_cast<std::int64_t>(n)}},
          {sized_undefined(1)}};
}

lift::DecompElement pointer_to_undefined(int size) {
  return {"type",
          {{"metatype", std::string("ptr")}, {"name", std::string()}, {"size", std::int64_t{size}}},
          {undefined_ref()}};
}

// A function nothing is known about but its name and body: Ghidra's
// DEFAULT signature, an unlocked void return.
lift::FunctionFacts default_function(std::uint64_t entry, std::string name) {
  lift::FunctionFacts f;
  f.entry = entry;
  f.name = std::move(name);
  f.convention = "unknown";
  f.ret.type = {"void", {}, {}};
  f.ret.storage = std::vector<lift::StorageVarnode>{};
  f.ret.void_storage = true;
  return f;
}

// The 64-bit Windows 7 Thread Environment Block as Ghidra's TEB analyzer
// lays it out (ThreadEnvironmentBlock.create, the analyzer's default
// version): offset, field, type. GuaranteedStackBytes is at 0x748, as
// Ghidra puts it.
struct TebField {
  std::uint32_t offset;
  const char *name;
  const char *type;  // ptr, dword, qword, ushort, CLIENT_ID, GUID, or <elem>[<count>]
};
const TebField kTeb64[] = {
    {0x0, "ExceptionList", "ptr"}, {0x8, "StackBase", "ptr"}, {0x10, "StackLimit", "ptr"},
    {0x18, "SubSystemTib", "ptr"}, {0x20, "FiberData", "ptr"}, {0x28, "ArbitraryUserPointer", "ptr"},
    {0x30, "Self", "ptr"}, {0x38, "EnvironmentPointer", "ptr"}, {0x40, "ClientId", "CLIENT_ID"},
    {0x50, "ActiveRpcHandle", "ptr"}, {0x58, "ThreadLocalStoragePointer", "ptr"},
    {0x60, "ProcessEnvironmentBlock", "ptr"}, {0x68, "LastErrorValue", "dword"},
    {0x6c, "CountOfOwnedCriticalSections", "dword"}, {0x70, "CsrClientThread", "ptr"},
    {0x78, "Win32ThreadInfo", "ptr"}, {0x80, "User32Reserved", "dword[26]"}, {0xe8, "UserReserved", "dword[5]"},
    {0x100, "WOW32Reserved", "ptr"}, {0x108, "CurrentLocale", "dword"}, {0x10c, "FpSoftwareStatusRegister", "dword"},
    {0x110, "SystemReserved1", "ptr[54]"}, {0x2c0, "ExceptionCode", "dword"},
    {0x2c8, "ActivationContextStackPointer", "ptr"}, {0x2d0, "SpareBytes", "uchar[24]"},
    {0x2e8, "TxFsContext", "dword"}, {0x2ee, "Padding1", "uchar[2]"}, {0x2f0, "GdiTebBatch", "qword"},
    {0x748, "GuaranteedStackBytes", "dword"}, {0x7d8, "RealClientId", "CLIENT_ID"},
    {0x7e8, "GdiCachedProcessHandle", "ptr"}, {0x7f0, "GdiClientPID", "dword"}, {0x7f4, "GdiCLientTID", "dword"},
    {0x7f8, "GdiThreadLocalInfo", "ptr"}, {0x800, "Win32ClientInfo", "ptr[62]"}, {0x9f0, "glDispatchTable", "ptr[233]"},
    {0x1138, "glReserved1", "ptr[29]"}, {0x1220, "glReserved2", "ptr"}, {0x1228, "glSectionInfo", "ptr"},
    {0x1230, "glSection", "ptr"}, {0x1238, "glTable", "ptr"}, {0x1240, "glCurrentRC", "ptr"},
    {0x1248, "glContext", "ptr"}, {0x1250, "LastStatusValue", "dword"},
    {0x1268, "StaticUnicodeBuffer", "wchar16[261]"}, {0x1478, "DeallocationStack", "ptr"},
    {0x1480, "TlsSlots", "ptr[64]"}, {0x1680, "TlsLinks.Flink", "ptr"}, {0x1688, "TlsLinks.Blink", "ptr"},
    {0x1690, "Vdm", "ptr"}, {0x1698, "ReservedForNtRpc", "ptr"}, {0x16a0, "DbgSsReserved", "ptr[2]"},
    {0x16b0, "HardErrorMode", "dword"}, {0x16b8, "Instrumentation", "ptr[11]"}, {0x1710, "ActivityId", "GUID"},
    {0x1720, "SubProcessTag", "ptr"}, {0x1728, "EtwLocalData", "ptr"}, {0x1730, "EtwTraceData", "ptr"},
    {0x1738, "WinSockData", "ptr"}, {0x1740, "GdiBatchCount", "dword"}, {0x1744, "IdealProcessorValue", "dword"},
    {0x1750, "ReservedForPerf", "ptr"}, {0x1758, "ReservedForOle", "ptr"}, {0x1760, "WaitingOnLoaderLock", "dword"},
    {0x1768, "SavedPriorityState", "ptr"}, {0x1770, "SoftPatchPtr1", "ptr"}, {0x1778, "ThreadPoolData", "ptr"},
    {0x1780, "TlsExpansionSlots", "ptr"}, {0x1788, "DeallocationBStore", "ptr"}, {0x1790, "BStoreLimit", "ptr"},
    {0x1798, "MuiGeneration", "dword"}, {0x179c, "IsImpersonating", "dword"}, {0x17a0, "NlsCache", "ptr"},
    {0x17a8, "pShimData", "ptr"}, {0x17b0, "HeapVirtualAffinity", "dword"},
    {0x17b8, "CurrentTransactionHandle", "ptr"}, {0x17c0, "ActiveFrame", "ptr"}, {0x17c8, "FlsData", "ptr"},
    {0x17d0, "PreferredLanguages", "ptr"}, {0x17d8, "UserPrefLanguages", "ptr"},
    {0x17e0, "MergedPrefLanguages", "ptr"}, {0x17e8, "MuiImpersonation", "dword"},
    {0x17ec, "CrossTebFlags", "ushort"}, {0x17ee, "SameTebFlags", "ushort"},
    {0x17f0, "TxnScopeEnterCallback", "ptr"}, {0x17f8, "TxnScopeExitCallback", "ptr"},
    {0x1800, "TxnScopeContext", "ptr"}, {0x1808, "LockCount", "dword"}, {0x1810, "ResourceRetValue", "ptr"},
};
constexpr std::uint64_t kTeb64Address = 0xff00000000ULL;  // TEBAnalyzer.findBlockLocation
constexpr std::uint64_t kTeb64Size = 0x1850;
constexpr std::uint64_t kClientIdId = 0x0140000000000001ULL;

lift::DecompElement builtin_type(const char *name, std::uint64_t id, const char *meta, int size, bool is_char = false) {
  std::vector<std::pair<std::string, lift::DecompElement::Value>> a;
  if (is_char) a.emplace_back("char", true);
  a.emplace_back("id", 0xc000000000000000ULL | id);
  a.emplace_back("metatype", std::string(meta));
  a.emplace_back("name", std::string(name));
  a.emplace_back("size", std::int64_t{size});
  return {"type", std::move(a), {}};
}

lift::DecompElement void_pointer() {
  return {"type", {{"metatype", std::string("ptr")}, {"name", std::string()}, {"size", std::int64_t{8}}}, {{"void", {}, {}}}};
}

lift::DecompElement teb_type(const std::string &t) {
  if (auto lb = t.find('['); lb != std::string::npos) {
    lift::DecompElement elem = teb_type(t.substr(0, lb));
    const int n = std::stoi(t.substr(lb + 1));
    int esize = 8;
    if (const auto *sz = elem.attr("size")) esize = static_cast<int>(std::get<std::int64_t>(*sz));
    if (elem.tag == "typeref") esize = 2;  // wchar16
    return {"type",
            {{"arraysize", std::int64_t{n}}, {"metatype", std::string("array")}, {"name", std::string()},
             {"size", std::int64_t{n * esize}}},
            {std::move(elem)}};
  }
  if (t == "ptr") return void_pointer();
  if (t == "dword") return builtin_type("dword", 0x7f, "uint", 4);
  if (t == "qword") return builtin_type("qword", 0xa2, "uint", 8);
  if (t == "ushort") return builtin_type("ushort", 0xc8, "uint", 2);
  if (t == "uchar") return builtin_type("uchar", 0xbe, "uint", 1, true);
  if (t == "wchar16") return {"typeref", {{"id", 0xc0000000000000cbULL}, {"name", std::string("wchar16")}}, {}};
  if (t == "CLIENT_ID") return {"typeref", {{"id", kClientIdId}, {"name", std::string("CLIENT_ID")}}, {}};
  return {"typeref", {{"id", 0xc00000000000006aULL}, {"name", std::string("GUID")}}, {}};
}

// A relocated pointer slot as pointer data named `name`.
lift::DataFacts slot_data(const StaticInputs::Slot &slot, std::string name, unsigned word) {
  lift::DataFacts d;
  d.addr = slot.address;
  d.name = std::move(name);
  d.length = word;
  d.type = pointer_to_undefined(static_cast<int>(word));
  d.mutability = slot.mutability;
  return d;
}

class Assembler {
 public:
  Assembler(const Program &p, const Options &o)
      : p_(p), o_(o), image_(*p.image), riscv_(p.language_id.starts_with("RISCV:")),
        macho_(p.image->format == loader::Format::macho) {}

  // What doesn't depend on discovery, in the order run() lays it out.
  StaticInputs build_static() {
    begin();
    StaticInputs st;
    if (o_.relocations) external_ = external_block(image_);
    memory();
    if (o_.relocations) {
      externals();
      st.external.functions = std::exchange(in_.functions, {});
      st.external.data = std::exchange(in_.data, {});
      for (const ExternalSymbol &x : external_.symbols) st.external_names.emplace_back(x.address, x.name);
      st.patches = relocation_patches(image_, external_);
    }
    if (o_.imports) {
      pe_imports();
      st.imports.external_refs = std::exchange(in_.external_refs, {});
      st.imports.data = std::exchange(in_.data, {});
    }
    if (o_.tracked) {
      thread_block();
      st.thread.data = std::exchange(in_.data, {});
      st.thread.types = std::exchange(in_.types, {});
      st.thread.synthesized_memory = std::exchange(in_.synthesized_memory, {});
      if (thread_block_) st.thread.memory.push_back(in_.memory.back());
    }
    st.memory = std::exchange(in_.memory, {});
    // (A raw image's symbols are its processor spec's labels: the 8051's
    // PCON, AVR's PORTB, which Ghidra's decompiler names too. A Mach-O's
    // are labels: nlist entries have no sizes.)
    if (o_.data && (image_.format == loader::Format::elf || image_.format == loader::Format::raw || macho_))
      st.symbols = symbol_candidates();
    if (o_.data && o_.relocations) st.slots = slot_values(st.patches);
    return st;
  }

  lift::DecompilerInputs run(const StaticInputs &st, SlotNames *slots = nullptr) {
    begin();
    in_.memory = st.memory;
    functions();
    if (o_.data) symbols(st);
    if (o_.relocations) {
      for (const lift::FunctionFacts &f : st.external.functions) {
        external_entries_.insert(f.entry);
        in_.functions.push_back(f);
      }
      in_.data.insert(in_.data.end(), st.external.data.begin(), st.external.data.end());
      for (const auto &[a, name] : st.external_names) names_[a] = name;
      in_.patches = st.patches;
    }
    if (o_.tracked) tracked();
    if (o_.imports) {
      in_.external_refs.insert(in_.external_refs.end(), st.imports.external_refs.begin(), st.imports.external_refs.end());
      in_.data.insert(in_.data.end(), st.imports.data.begin(), st.imports.data.end());
    }
    if (o_.tracked && !st.thread.memory.empty()) {
      in_.synthesized_memory.insert(in_.synthesized_memory.end(), st.thread.synthesized_memory.begin(),
                                    st.thread.synthesized_memory.end());
      in_.data.insert(in_.data.end(), st.thread.data.begin(), st.thread.data.end());
      in_.types.insert(in_.types.end(), st.thread.types.begin(), st.thread.types.end());
      thread_tracked();
    }
    // What naming pointers takes; analyzed data's labels join it first.
    SlotNames names;
    const an::DataList *list = o_.data_analysis ? p_.analysis->data() : nullptr;
    if (list) add_analyzed_values(*list, image_, prefix_, in_, names_, p_.read);
    if (o_.data) {
      in_body(0);
      names.bodies = *bodies_;
      names.prefix = prefix_;
      names.image = &image_;
      names.word = image_.bits / 8;
      if (o_.relocations)
        for (const StaticInputs::Slot &slot : st.slots)
          if (slot.mapped) names.pointers.emplace_back(slot.address, slot.value);
      if (list)
        for (const an::DataItem &d : list->items)
          if (d.kind == an::DataKind::pointer) names.pointers.emplace_back(d.address, d.value);
      std::sort(names.pointers.begin(), names.pointers.end());
      names.names = names_;
    }
    if (list) {
      for (auto &[a, name] : add_analyzed_pointers(*list, image_, names, in_, p_.read)) names_.emplace(a, name);
      names.names = names_;
    }
    if (o_.data && o_.relocations) {
      if (slots != nullptr) {
        *slots = std::move(names);  // named when looked up (pointer_slot)
      } else {
        pointer_slots(st, names);
      }
    }
    // (Without data analysis, firmware still gets its strings.)
    if (o_.data && !list && p_.analysis->info().search) strings();
    if (o_.debug_info && p_.debug) apply_debug_info(*p_.debug, image_, in_, o_);
    drop_overlapped(in_);
    if (o_.library_signatures) library_signatures();
    if (o_.demangle) demangled();
    std::sort(in_.functions.begin(), in_.functions.end(),
              [](const lift::FunctionFacts &a, const lift::FunctionFacts &b) { return a.entry < b.entry; });
    unkey(in_, image_);
    return std::move(in_);
  }

 private:
  void begin() {
    const an::ProgramInfo &info = p_.analysis->info();
    in_ = lift::DecompilerInputs{};
    in_.language = info.language;
    in_.compiler = info.compiler;
    prefix_ = info.qualify_names ? info.code_space + "_" : std::string();
    in_.address_prefix = prefix_;
  }

  std::string hex_name(const char *prefix, std::uint64_t a) const {
    return std::string(prefix) + loader::name_address(image_, a, prefix_);
  }

  void memory() {
    for (const loader::Block &b : image_.blocks) {
      if (b.size == 0) continue;
      lift::BlockFacts m;
      m.name = b.name;
      m.start = b.start;
      m.end = b.start + (b.size - 1);
      m.write = b.perms.write;
      m.execute = b.perms.exec;
      m.initialized = b.initialized;
      m.is_volatile = b.is_volatile;
      in_.memory.push_back(std::move(m));
    }
    if (!external_.empty()) {
      lift::BlockFacts m;
      m.name = "EXTERNAL";
      m.start = external_.start;
      m.end = external_.end;
      m.write = true;
      m.initialized = false;
      m.external = true;
      in_.memory.push_back(std::move(m));
    }
  }

  void functions() {
    const an::FunctionList &list = p_.analysis->functions();
    const std::vector<std::uint64_t> no_return =
        o_.no_return ? ghidra_no_return(list, p_.analysis->no_return_evidence()) : std::vector<std::uint64_t>{};
    const std::map<std::string, std::string> &fixups =
        lift::call_fixup_targets(p_.analysis->info().language, p_.analysis->info().compiler);
    for (const an::FunctionInfo &f : list.functions) {
      lift::FunctionFacts ff = default_function(f.entry.offset, f.name);
      for (const facts::AddressRange &r : f.body.ranges()) ff.body.emplace_back(r.first.offset, r.last.offset);
      if (ff.body.empty()) continue;
      // What Ghidra's database says: the known names and its evidence
      // (function_sets), not discovery's inference.
      if (o_.no_return) ff.noreturn = std::binary_search(no_return.begin(), no_return.end(), ff.entry);
      // Each function decodes in its own instruction set, whatever the
      // image says there and whatever decoding other code left there.
      if (!p_.analysis->info().isa_context.empty()) {
        const bool thumb = (f.flags & an::kFunctionThumb) || !an::two_instruction_sets(p_.analysis->info());
        ff.context.emplace_back(p_.analysis->info().isa_context, thumb ? 1 : 0);
        for (const facts::AddressRange &r : f.reach.ranges()) ff.context_reach.emplace_back(r.first.offset, r.last.offset);
      }
      // A stub shows its import's code label, as Ghidra's thunk of an
      // EXTERNAL function does.
      if (!f.import.empty() && (image_.format == loader::Format::elf || macho_) && o_.relocations)
        ff.label = "<EXTERNAL>_" + f.import;
      // RISC-V PLT stubs end in `jalr t1`, which writes a register, so
      // Ghidra doesn't make them thunks: they keep a default name and say
      // nothing about the import.
      if (riscv_ && !f.import.empty() && in_plt(f.entry.offset)) {
        ff.name = an::default_name(p_.analysis->info(), f.entry.offset);
        ff.label.clear();
        ff.noreturn = false;
      }
      // Ghidra's ELF loader gives an x86 entry point the compiler spec's
      // processEntry convention.
      if (image_.format == loader::Format::elf && p_.language_id.starts_with("x86:") && image_.entry &&
          *image_.entry == ff.entry)
        ff.convention = "processEntry";
      // A function named as the compiler spec's call fixups name their
      // targets (compiler helpers that don't behave as calls: switch
      // helpers, get_pc thunks) has its calls replaced by the fixup's
      // p-code, as Ghidra's Call-Fixup Installer sets it.
      if (!fixups.empty() && f.import.empty())
        if (auto it = fixups.find(ff.name); it != fixups.end()) ff.call_fixup = it->second;
      names_[ff.entry] = ff.name;
      in_.functions.push_back(std::move(ff));
    }
  }

  const char *format_name() const {
    switch (image_.format) {
      case loader::Format::pe: return "pe";
      case loader::Format::elf: return "elf";
      case loader::Format::macho: return "macho";
      default: return "raw";
    }
  }

  bool in_plt(std::uint64_t a) const {
    for (const an::Range &r : p_.analysis->info().plt)
      if (r.contains(a)) return true;
    return false;
  }

  // Symbols the ELF loader makes labels or data of (besides functions):
  // object symbols are data of their size, others labels; absolute ones
  // stay where they say, in no block (RISC-V __global_pointer$). The best
  // at each address, whether or not a function claims it.
  std::vector<StaticInputs::Symbol> symbol_candidates() const {
    std::map<std::uint64_t, const loader::Symbol *> best;
    auto rank = [](const loader::Symbol &s) { return s.bind == loader::SymbolBind::global ? 0 : s.bind == loader::SymbolBind::weak ? 1 : 2; };
    for (const loader::Symbol &s : image_.symbols) {
      if (!s.defined || s.name.empty() || s.name[0] == '$') continue;
      if (s.type == loader::SymbolType::section || s.type == loader::SymbolType::file ||
          s.type == loader::SymbolType::func || s.type == loader::SymbolType::ifunc ||
          s.type == loader::SymbolType::tls)
        continue;
      auto [it, fresh] = best.try_emplace(s.value, &s);
      if (!fresh && rank(s) < rank(*it->second)) it->second = &s;
    }
    std::vector<StaticInputs::Symbol> out;
    out.reserve(best.size());
    for (const auto &[addr, s] : best) {
      const bool data = !macho_ && s->type == loader::SymbolType::object && image_.memory.is_mapped(addr);
      out.push_back({addr, s->name, s->size, data, data ? mutability(addr) : lift::Mutability::normal});
    }
    return out;
  }

  // Those no function claims (by entry or body).
  void symbols(const StaticInputs &st) {
    if (image_.format != loader::Format::elf && image_.format != loader::Format::raw && !macho_) return;
    std::unordered_set<std::uint64_t> entries;
    for (const lift::FunctionFacts &f : in_.functions) entries.insert(f.entry);
    for (const StaticInputs::Symbol &s : st.symbols) {
      if (entries.contains(s.address) || in_body(s.address)) continue;
      if (s.data) {
        lift::DataFacts d;
        d.addr = s.address;
        d.name = s.name;
        d.length = s.size != 0 ? s.size : 1;
        d.type = d.length <= 8 ? (d.length == 1 ? undefined_ref() : sized_undefined(static_cast<int>(d.length)))
                               : undefined_array(d.length);
        d.mutability = s.mutability;
        in_.data.push_back(std::move(d));
      } else {
        in_.labels.push_back({{}, s.address, s.name, {}});
      }
      names_.emplace(s.address, s.name);
    }
  }

  // Firmware (raw images, ProgramInfo::search): ASCII strings in what
  // isn't code, as Ghidra's ASCII Strings analyzer defines them (at least
  // five printable characters, NUL-terminated), so the decompiler shows
  // them as string data (s_<text>_<address>) rather than as addresses.
  void strings() {
    const an::FunctionList &list = p_.analysis->functions();
    std::unordered_set<std::uint64_t> defined;
    for (const lift::DataFacts &d : in_.data) defined.insert(d.addr);
    auto code = list.code.begin();
    const lift::DecompElement chr{"typeref", {{"name", std::string("char")}, {"id", 0xc00000000000007bULL}}, {}};
    for (const loader::Block &b : image_.blocks) {
      if (!b.initialized || b.size == 0 || b.size > (std::uint64_t{1} << 31)) continue;
      std::vector<std::byte> bytes(static_cast<std::size_t>(b.size));
      if (p_.read) p_.read(b.start, bytes);
      else image_.memory.read(b.start, bytes);
      auto printable = [](std::uint8_t c) { return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r'; };
      std::size_t i = 0;
      while (i < bytes.size()) {
        const std::uint64_t a = b.start + i;
        // Skip code.
        while (code != list.code.end() && code->address + code->length <= a) ++code;
        if (code != list.code.end() && code->address <= a) {
          i = static_cast<std::size_t>(code->address + code->length - b.start);
          continue;
        }
        if (!printable(std::to_integer<std::uint8_t>(bytes[i]))) {
          ++i;
          continue;
        }
        std::size_t j = i;
        std::size_t letters = 0;
        while (j < bytes.size() && printable(std::to_integer<std::uint8_t>(bytes[j]))) {
          const auto c = std::to_integer<std::uint8_t>(bytes[j]);
          if (std::isalnum(c) || c == ' ') ++letters;
          ++j;
        }
        const std::uint64_t end = b.start + j;  // the terminator, if any
        bool overlaps_code = code != list.code.end() && code->address <= end;
        if (j - i >= 5 && j < bytes.size() && std::to_integer<std::uint8_t>(bytes[j]) == 0 && !overlaps_code &&
            2 * letters >= j - i && !defined.contains(a)) {
          std::string text(reinterpret_cast<const char *>(bytes.data() + i), j - i);
          lift::DataFacts d;
          d.addr = a;
          std::string label;
          for (char c : text.substr(0, 32)) label += std::isalnum(static_cast<unsigned char>(c)) ? c : '_';
          d.name = "s_" + label + "_" + hex_name("", a).substr(prefix_.size());
          d.length = j - i + 1;
          d.type = {"type",
                    {{"arraysize", static_cast<std::int64_t>(d.length)},
                     {"metatype", std::string("array")},
                     {"name", std::string()},
                     {"size", static_cast<std::int64_t>(d.length)}},
                    {chr}};
          d.string = text;
          names_.emplace(a, d.name);
          in_.data.push_back(std::move(d));
        }
        i = j + 1;
      }
    }
  }

  // Ghidra's functions and labels in the EXTERNAL block.
  void externals() {
    for (const ExternalSymbol &x : external_.symbols) {
      if (x.data) {
        lift::DataFacts d;
        d.addr = x.address;
        d.name = x.name;
        d.length = 1;
        d.type = undefined_ref();
        in_.data.push_back(std::move(d));
      } else {
        lift::FunctionFacts f = default_function(x.address, x.name);
        f.body.emplace_back(x.address, x.address);
        f.label = "<EXTERNAL>_" + x.name;
        if (o_.no_return) f.noreturn = an::is_known_no_return(x.name, macho_);
        in_.functions.push_back(std::move(f));
      }
    }
  }

  void tracked() {
    std::vector<TrackedRegister> regs = tracked_registers(image_, p_.language_id);
    // Analysis's register values from the loader (ProgramInfo::
    // register_defaults: MIPS gp, the PowerPC TOC and small data bases),
    // where a function starts, as Ghidra's program context holds them.
    const std::vector<an::RegisterDefault> &defaults = p_.analysis->info().register_defaults;
    if (regs.empty() && defaults.empty()) return;
    // Per register, by range (disjoint within a register).
    std::map<std::string, std::vector<const an::RegisterDefault *>> by_register;
    for (const an::RegisterDefault &d : defaults) by_register[d.name].push_back(&d);
    for (auto &[name, v] : by_register)
      std::sort(v.begin(), v.end(), [](const an::RegisterDefault *a, const an::RegisterDefault *b) { return a->range < b->range; });
    for (const lift::FunctionFacts &f : in_.functions) {
      if (f.body.empty() || external_entries_.contains(f.entry)) continue;
      std::vector<lift::TrackedFacts> list;
      for (const TrackedRegister &r : regs) {
        lift::TrackedFacts t;
        t.register_name = r.name;
        t.value = r.value;
        list.push_back(std::move(t));
      }
      for (const auto &[name, v] : by_register) {
        auto it = std::upper_bound(v.begin(), v.end(), f.entry, [](std::uint64_t x, const an::RegisterDefault *d) { return x < d->range.first; });
        if (it == v.begin() || !(*std::prev(it))->range.contains(f.entry)) continue;
        lift::TrackedFacts t;
        t.register_name = name;
        t.value = (*std::prev(it))->value;
        list.push_back(std::move(t));
      }
      if (list.empty()) continue;
      auto &out = in_.tracked[f.entry];
      out.insert(out.end(), std::make_move_iterator(list.begin()), std::make_move_iterator(list.end()));
    }
  }

  // PE import slots: Ghidra's external references from the IAT to the
  // imported functions (EXTERNAL space, LIBRARY.DLL::name), and the slots
  // as pointer data.
  void pe_imports() {
    if (image_.format != loader::Format::pe) return;
    const unsigned word = image_.bits / 8;
    for (const loader::Import &imp : image_.imports) {
      if (imp.iat_address == 0) continue;
      std::string name = imp.name;
      if (name.empty() && imp.ordinal) name = "Ordinal_" + std::to_string(*imp.ordinal);
      if (name.empty()) continue;
      std::string library = imp.library;
      for (char &c : library) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
      lift::ExternalRefFacts x;
      x.addr = imp.iat_address;
      x.label = name;
      lift::FunctionFacts f = default_function(0, name);
      f.label = library + "_" + name;
      if (o_.no_return) f.noreturn = an::is_known_no_return(name, macho_);
      x.function = std::move(f);
      in_.external_refs.push_back(std::move(x));
      if (o_.data) {
        lift::DataFacts d;
        d.addr = imp.iat_address;
        d.name = "PTR_" + name + "_" + hex_name("", imp.iat_address);
        d.length = word;
        d.type = pointer_to_undefined(static_cast<int>(word));
        d.mutability = mutability(imp.iat_address);
        in_.data.push_back(std::move(d));
      }
    }
  }

  // Ghidra's TEB analyzer on Visual Studio and clang PEs for x86-64: a
  // thread block at 0xff00000000 whose Self field points at itself, its
  // fields as data, and GS_OFFSET set to it in all code (thread_tracked).
  void thread_block() {
    if (image_.format != loader::Format::pe || image_.bits != 64 || !p_.language_id.starts_with("x86:")) return;
    for (const loader::Block &b : image_.blocks)
      if (b.start < kTeb64Address + kTeb64Size && b.start + b.size > kTeb64Address) return;
    thread_block_ = true;
    lift::BlockFacts m;
    m.name = "tdb";
    m.start = kTeb64Address;
    m.end = kTeb64Address + kTeb64Size - 1;
    m.write = true;
    in_.memory.push_back(std::move(m));
    std::vector<std::uint8_t> bytes(kTeb64Size, 0);
    for (int i = 0; i < 8; ++i) bytes[0x30 + i] = static_cast<std::uint8_t>(kTeb64Address >> (8 * i));
    in_.synthesized_memory.emplace_back(kTeb64Address, std::move(bytes));
    if (o_.data) {
      for (const TebField &f : kTeb64) {
        lift::DataFacts d;
        d.addr = kTeb64Address + f.offset;
        d.name = f.name;
        d.type = teb_type(f.type);
        std::uint64_t size = 8;
        if (const auto *sz = d.type.attr("size")) size = static_cast<std::uint64_t>(std::get<std::int64_t>(*sz));
        else if (std::string(f.type) == "CLIENT_ID" || std::string(f.type) == "GUID") size = 16;
        d.length = size;
        d.mutability = f.offset == 0x30 ? lift::Mutability::constant : lift::Mutability::normal;
        in_.data.push_back(std::move(d));
      }
      in_.types.push_back({"type",
                           {{"alignment", std::int64_t{1}},
                            {"id", kClientIdId},
                            {"metatype", std::string("struct")},
                            {"name", std::string("CLIENT_ID")},
                            {"size", std::int64_t{16}}},
                           {{"field", {{"name", std::string("UniqueProcess")}, {"offset", std::int64_t{0}}}, {void_pointer()}},
                            {"field", {{"name", std::string("UniqueThread")}, {"offset", std::int64_t{8}}}, {void_pointer()}}}});
      in_.types.push_back(
          {"type",
           {{"alignment", std::int64_t{1}},
            {"id", 0xc00000000000006aULL},
            {"metatype", std::string("struct")},
            {"name", std::string("GUID")},
            {"size", std::int64_t{16}}},
           {{"field", {{"name", std::string("Data1")}, {"offset", std::int64_t{0}}}, {builtin_type("dword", 0x7f, "uint", 4)}},
            {"field", {{"name", std::string("Data2")}, {"offset", std::int64_t{4}}}, {builtin_type("word", 0xce, "uint", 2)}},
            {"field", {{"name", std::string("Data3")}, {"offset", std::int64_t{6}}}, {builtin_type("word", 0xce, "uint", 2)}},
            {"field",
             {{"name", std::string("Data4")}, {"offset", std::int64_t{8}}},
             {{"type",
               {{"arraysize", std::int64_t{8}}, {"metatype", std::string("array")}, {"name", std::string()},
                {"size", std::int64_t{8}}},
               {builtin_type("byte", 0x7a, "uint", 1)}}}}}});
    }
  }

  void thread_tracked() {
    for (const lift::FunctionFacts &f : in_.functions) {
      if (f.body.empty()) continue;
      lift::TrackedFacts t;
      t.register_name = "GS_OFFSET";
      t.value = kTeb64Address;
      in_.tracked[f.entry].push_back(std::move(t));
    }
  }

  // Ghidra's Apply Data Archives analyzer: prototypes from the library
  // archives for functions of that name that have none better, and thunks
  // of them take their target's. revkit's own archives first (library.h),
  // then Ghidra's .gdt for the names they don't declare. Unlike Ghidra:
  // - a .gdt prototype applies by name only to an import (or a thunk of
  //   one), never to a function the program defines: generic_clib's _init
  //   is an OpenSSL engine's (int _init(EVP_PKEY_CTX *ctx)). revkit's own
  //   archives declare what their libraries export, so they apply to local
  //   definitions too (a statically linked memcpy);
  // - the C runtime's own functions a program defines (_init, _start,
  //   frame_dummy, ...) take no archive prototype at all;
  // - a .gdt prototype without a calling convention gets the compiler
  //   spec's default, not "unknown" (which locked parameters with no model:
  //   "Unknown calling convention -- yet parameter storage is locked").
  void library_signatures() {
    std::shared_ptr<const LibraryPrototypes> lib = o_.library;
    if (!lib) {
      try {
        const an::ProgramInfo &info = p_.analysis->info();
        lib = default_library(image_, cparse::profile_for_language(info.language, info.compiler, format_name()));
      } catch (const std::exception &) {
      }
    }
    std::shared_ptr<const GhidraArchive> archive;
    if (o_.ghidra_library)
      if (std::optional<std::filesystem::path> root = lift::ghidra_root())
        archive = GhidraArchive::for_program(*root, image_.format == loader::Format::pe, image_.bits);
    if (!lib && !archive) return;
    std::optional<ArchiveTypes> types;
    if (archive) types.emplace(*archive, data_org(image_, p_.language_id));
    std::optional<GhidraTypes> enc;
    if (lib) enc.emplace(lib->store, data_org(image_, p_.language_id), nullptr);
    const std::set<std::string> &models =
        lift::prototype_models(p_.analysis->info().language, p_.analysis->info().compiler);
    auto def_for = [&](const std::string &name) -> const GhidraArchive::FunctionDef * {
      if (name.empty() || !archive) return nullptr;
      if (const auto *d = archive->function(name)) return d;
      if (name[0] == '_') return archive->function(name.substr(1));  // the symbol _name matches name
      return nullptr;
    };
    auto apply_ghidra = [&](lift::FunctionFacts &f, const GhidraArchive::FunctionDef &d) {
      f.signature_source = lift::SignatureSource::imported;
      f.convention = models.contains(d.convention) ? d.convention : std::string("default");
      f.dynamic_storage = true;
      f.ret.type = types->ref(d.ret);
      f.ret.is_default = false;
      f.varargs = d.varargs;
      if (d.noreturn && o_.no_return) f.noreturn = true;
      f.params.clear();
      for (std::size_t i = 0; i < d.params.size(); ++i) {
        lift::ParamFacts p;
        p.name = d.params[i].name.empty() ? "param_" + std::to_string(i + 1) : d.params[i].name;
        p.type = types->ref(d.params[i].type);
        f.params.push_back(std::move(p));
      }
    };
    auto apply_own = [&](lift::FunctionFacts &f, const LibraryFunction &d) {
      const auto *fn = lib->store.get(d.type).as<types::FunctionType>();
      if (fn == nullptr) return false;
      f.signature_source = lift::SignatureSource::imported;
      // The prototype's convention where the compiler spec has a model for
      // it (__stdcall on 32-bit Windows), else the default.
      const std::string cc = convention_name(fn->cc);
      f.convention = !cc.empty() && models.contains(cc) ? cc : std::string("default");
      f.dynamic_storage = true;
      f.ret = lift::FunctionFacts::Return{};
      f.ret.type = enc->ref(fn->ret);
      f.ret.is_default = false;
      f.varargs = fn->varargs;
      if (d.noreturn && o_.no_return) f.noreturn = true;
      f.params.clear();
      for (std::size_t i = 0; i < fn->params.size(); ++i) {
        lift::ParamFacts p;
        p.name = fn->params[i].name.empty() ? "param_" + std::to_string(i + 1) : fn->params[i].name;
        p.type = enc->ref(fn->params[i].type);
        f.params.push_back(std::move(p));
      }
      return true;
    };
    auto apply = [&](lift::FunctionFacts &f, const std::string &name, bool external) {
      if (!external && crt_function(name)) return;  // library.h
      if (lib)
        if (const LibraryFunction *d = lib->find(name); d != nullptr && apply_own(f, *d)) return;
      if (external)
        if (const auto *d = def_for(name)) apply_ghidra(f, *d);
    };
    std::map<std::uint64_t, const an::FunctionInfo *> info;
    for (const an::FunctionInfo &f : p_.analysis->functions().functions) info[f.entry.offset] = &f;
    for (lift::FunctionFacts &f : in_.functions) {
      if (f.signature_source != lift::SignatureSource::default_) continue;
      auto it = info.find(f.entry);
      const an::FunctionInfo *a = it != info.end() ? it->second : nullptr;
      // A thunk of an import gets its target's signature, which is the
      // archive's for the import's name; other thunks are left alone.
      std::string name = f.name;
      bool external = false;
      if (a != nullptr && (a->flags & an::kFunctionThunk)) {
        if (a->import.empty() || f.name != a->import) continue;  // RISC-V PLT stubs aren't thunks to Ghidra
        name = a->import;
        external = true;
      }
      apply(f, name, external);
    }
    for (lift::ExternalRefFacts &x : in_.external_refs)
      if (x.function && x.function->signature_source == lift::SignatureSource::default_)
        apply(*x.function, x.function->name, true);
    if (types)
      for (lift::DecompElement &t : types->take_definitions()) in_.types.push_back(std::move(t));
    if (enc)
      for (lift::DecompElement &t : enc->take_definitions()) in_.types.push_back(std::move(t));
  }

  // The demangler analysis: demangled names for what mangled symbols name,
  // and the mangled signature's prototype for functions that have none
  // better (debug info and library prototypes come first).
  void demangled() {
    std::unordered_map<std::string, std::optional<demangle::Demangled>> cache;
    auto get = [&](const std::string &name) -> const demangle::Demangled * {
      if (name.empty() || demangle::detect(name) == demangle::Scheme::None) return nullptr;
      auto [it, fresh] = cache.try_emplace(name);
      if (fresh) it->second = demangle::parse(name);
      return it->second ? &*it->second : nullptr;
    };
    ClassScopes scopes;
    for (const loader::Symbol &s : image_.symbols)
      if (const demangle::Demangled *d = get(s.name)) scopes.add(*d);
    for (const loader::Export &e : image_.exports)
      if (const demangle::Demangled *d = get(e.name)) scopes.add(*d);
    for (const loader::Import &i : image_.imports)
      if (const demangle::Demangled *d = get(i.name)) scopes.add(*d);
    std::optional<cparse::Profile> profile;
    try {
      const an::ProgramInfo &info = p_.analysis->info();
      profile = cparse::profile_for_language(info.language, info.compiler, format_name());
    } catch (const std::exception &) {
    }
    const DataOrg org = data_org(image_, p_.language_id);
    const std::set<std::string> &models =
        lift::prototype_models(p_.analysis->info().language, p_.analysis->info().compiler);
    // The decompiler prints a name in its namespaces as Ghidra's does
    // (minimally qualified from where it is used).
    auto name = [](std::string &out, lift::NamespacePath &ns, const demangle::Demangled &d) {
      std::vector<std::string> parts = split_qualified(d.name);
      out = parts.back();
      parts.pop_back();
      ns = namespace_path(parts);
    };
    types::TypeStore store;
    GhidraTypes enc(store, org, nullptr);
    // Every function's prototype in one parse.
    std::optional<DemangledPrototypes> batch;
    if (profile) batch.emplace(scopes, *profile, store);
    std::vector<std::pair<lift::FunctionFacts *, std::size_t>> typed;
    auto function = [&](lift::FunctionFacts &f) {
      const demangle::Demangled *d = get(f.name);
      if (d == nullptr) return;
      name(f.name, f.ns, *d);
      if (f.signature_source != lift::SignatureSource::default_ || !batch) return;
      if (std::optional<std::size_t> i = batch->add(*d)) typed.emplace_back(&f, *i);
    };
    for (lift::FunctionFacts &f : in_.functions) function(f);
    for (lift::ExternalRefFacts &x : in_.external_refs) {
      if (!x.function) continue;
      function(*x.function);
      if (const demangle::Demangled *d = get(x.label)) x.label = d->name;
    }
    if (batch) {
      batch->parse();
      for (auto [f, i] : typed)
        if (const std::optional<DemangledPrototype> &p = batch->get(i)) apply_demangled(*f, *p, enc, models);
    }
    for (lift::DataFacts &d : in_.data)
      if (const demangle::Demangled *m = get(d.name)) name(d.name, d.ns, *m);
    for (lift::LabelFacts &l : in_.labels)
      if (const demangle::Demangled *m = get(l.name)) name(l.name, l.ns, *m);
    for (lift::DecompElement &t : enc.take_definitions()) in_.types.push_back(std::move(t));
  }

  // Relocated pointer slots: the pointer each holds (the last patch at an
  // address wins).
  std::vector<StaticInputs::Slot> slot_values(const std::vector<Patch> &patches) const {
    const unsigned word = image_.bits / 8;
    std::map<std::uint64_t, std::uint64_t> value;
    for (const Patch &p : patches) {
      std::uint64_t v = 0;
      for (unsigned i = 0; i < word && i < p.second.size(); ++i) {
        unsigned shift = image_.endian == loader::Endian::little ? 8 * i : 8 * (word - 1 - i);
        v |= std::uint64_t{p.second[i]} << shift;
      }
      value[p.first] = v;
    }
    std::vector<StaticInputs::Slot> out;
    out.reserve(value.size());
    for (const auto &[addr, v] : value) out.push_back({addr, v, mutability(addr), image_.memory.is_mapped(v)});
    return out;
  }

  // Relocated pointer slots are pointer data, named as Ghidra names them
  // (pointer_name).
  void pointer_slots(const StaticInputs &st, const SlotNames &names) {
    const unsigned word = image_.bits / 8;
    std::unordered_set<std::uint64_t> defined;
    for (const lift::DataFacts &d : in_.data) defined.insert(d.addr);
    for (const StaticInputs::Slot &slot : st.slots) {
      if (defined.contains(slot.address)) continue;
      in_.data.push_back(slot_data(slot, pointer_name(slot.address, slot.value, slot.mapped, names), word));
    }
  }

  // Whether any function's body has `a`: every body, merged and sorted
  // once (asked for every symbol and data pointer, so a scan of all
  // functions each time is quadratic on a large program).
  bool in_body(std::uint64_t a) const {
    if (!bodies_) {
      std::vector<std::pair<std::uint64_t, std::uint64_t>> r;
      for (const an::FunctionInfo &f : p_.analysis->functions().functions)
        for (const facts::AddressRange &x : f.body.ranges()) r.emplace_back(x.first.offset, x.last.offset);
      std::sort(r.begin(), r.end());
      std::vector<std::pair<std::uint64_t, std::uint64_t>> merged;
      for (const auto &x : r) {
        if (!merged.empty() && (merged.back().second == UINT64_MAX || x.first <= merged.back().second + 1))
          merged.back().second = std::max(merged.back().second, x.second);
        else
          merged.push_back(x);
      }
      bodies_ = std::move(merged);
    }
    auto it = std::upper_bound(bodies_->begin(), bodies_->end(), a,
                               [](std::uint64_t x, const auto &r) { return x < r.first; });
    return it != bodies_->begin() && std::prev(it)->second >= a;
  }

  lift::Mutability mutability(std::uint64_t a) const {
    for (const loader::Block &b : image_.blocks)
      if (a >= b.start && a - b.start < b.size)
        return b.is_volatile ? lift::Mutability::is_volatile
               : b.perms.write ? lift::Mutability::normal
                               : lift::Mutability::constant;
    return lift::Mutability::normal;
  }

  const Program &p_;
  const Options &o_;
  const loader::Image &image_;
  const bool riscv_;
  const bool macho_;
  lift::DecompilerInputs in_;
  ExternalBlock external_;
  std::string prefix_;
  std::unordered_map<std::uint64_t, std::string> names_;  // functions, symbols and externals, by address
  std::unordered_set<std::uint64_t> external_entries_;      // EXTERNAL functions
  bool thread_block_ = false;
  mutable std::optional<std::vector<std::pair<std::uint64_t, std::uint64_t>>> bodies_;  // see in_body
};

class SnapshotAnalysis : public Analysis {
 public:
  SnapshotAnalysis(std::unique_ptr<facts::FactDb> db, facts::Snapshot snap)
      : db_(std::move(db)), snap_(std::move(snap)) {
    info_ = snap_.get<an::Program>(an::ProgramKey{});
    functions_ = snap_.get<an::Functions>(an::ProgramKey{});
  }
  const an::ProgramInfo &info() override { return *info_; }
  const an::FunctionList &functions() override { return *functions_; }
  const an::FlowGraph &flow(std::uint64_t entry) override {
    auto it = flows_.find(entry);
    if (it == flows_.end()) it = flows_.emplace(entry, snap_.get<an::Flow>(an::Location{{}, entry})).first;
    return *it->second;
  }
  facts::Engine &engine() { return db_->engine(); }
  const an::DataList *data() override {
    if (!data_) data_ = snap_.get<an::Data>(an::ProgramKey{});
    return data_->get();
  }
  const std::vector<std::uint64_t> *no_return_evidence() override {
    if (!evidence_) evidence_ = snap_.get<an::NoReturnEvidence>(an::ProgramKey{});
    return evidence_->get();
  }
  std::shared_ptr<const an::FlowGraph> flow_shared(std::uint64_t entry) override {
    return snap_.get<an::Flow>(an::Location{{}, entry});
  }
  bool concurrent() const override { return true; }

 private:
  std::unique_ptr<facts::FactDb> db_;
  facts::Snapshot snap_;
  facts::Ref<an::ProgramInfo> info_;
  facts::Ref<an::FunctionList> functions_;
  std::optional<facts::Ref<an::DataList>> data_;
  std::optional<facts::Ref<std::vector<std::uint64_t>>> evidence_;
  std::map<std::uint64_t, facts::Ref<an::FlowGraph>> flows_;
};

}  // namespace

std::unique_ptr<Analysis> analyze(const loader::Image &image, const std::string &language_id, unsigned jobs,
                                  std::size_t memo_budget) {
  facts::FactDbOptions dbo;
  dbo.memo_budget = memo_budget;
  dbo.keep_evicted = false;
  auto db = std::make_unique<facts::FactDb>(std::move(dbo));
  an::register_queries(db->engine());
  an::ProgramInfo info = an::describe(image, language_id);
  an::import_image(*db, an::ProgramKey{}, image, info);
  facts::Snapshot snap = db->snapshot();
  // Discovery decodes the flows of each round's new entries and runs its
  // per-function steps on the engine's pool; each thread builds its own
  // SLEIGH engine (about 50 ms and 35 MB).
  std::unique_ptr<facts::ThreadPool> pool;
  if (jobs > 1) {
    pool = std::make_unique<facts::ThreadPool>(std::min<unsigned>(jobs, 1 + static_cast<unsigned>(info.seeds.size() / 2000)));
    db->engine().set_pool(pool.get());
  }
  auto out = std::make_unique<SnapshotAnalysis>(std::move(db), std::move(snap));
  if (pool) out->engine().set_pool(nullptr);
  return out;
}

StaticInputs assemble_static(const Program &program, const Options &options) {
  return Assembler(program, options).build_static();
}

lift::DecompilerInputs assemble_program(const Program &program, const Options &options,
                                        const StaticInputs *static_inputs, SlotNames *slots) {
  if (static_inputs != nullptr) return Assembler(program, options).run(*static_inputs, slots);
  return Assembler(program, options).run(Assembler(program, options).build_static(), slots);
}

lift::DataFacts pointer_slot(const StaticInputs::Slot &slot, const SlotNames &names) {
  lift::DataFacts d = slot_data(slot, pointer_name(slot.address, slot.value, slot.mapped, names), names.word);
  if (names.image != nullptr) unkey(*names.image, d.space, d.addr);
  return d;
}

void unkey(const loader::Image &image, std::string &space, std::uint64_t &addr) {
  if (image.spaces.empty() || !space.empty()) return;
  const loader::SpaceOffset so = loader::split_key(image, addr);
  if (so.space == nullptr) return;
  space = so.space->name;
  addr = so.offset;
}

void unkey(lift::DecompilerInputs &in, const loader::Image &image) {
  if (image.spaces.empty()) return;
  for (lift::DataFacts &d : in.data) unkey(image, d.space, d.addr);
  for (lift::ExternalRefFacts &x : in.external_refs) unkey(image, x.space, x.addr);
  for (lift::LabelFacts &l : in.labels) unkey(image, l.space, l.addr);
  for (lift::BlockFacts &b : in.memory) {
    const std::uint64_t size = b.end - b.start;
    unkey(image, b.space, b.start);
    b.end = b.start + size;
  }
}

lift::DecompilerInputs assemble(const Program &program, const Options &options, unsigned threads) {
  lift::DecompilerInputs in = assemble_program(program, options);
  const an::FunctionList &list = program.analysis->functions();
  program.analysis->info();  // read once, before threads use it
  const FunctionSets sets = function_sets(list, options.no_return ? program.analysis->no_return_evidence() : nullptr);
  std::map<std::uint64_t, lift::FunctionFacts *> by_entry;
  for (lift::FunctionFacts &f : in.functions) by_entry[f.entry] = &f;
  struct Job {
    const an::FunctionInfo *info;
    lift::FunctionFacts *facts;
  };
  std::vector<Job> jobs;
  for (const an::FunctionInfo &f : list.functions)
    if (auto it = by_entry.find(f.entry.offset); it != by_entry.end()) jobs.push_back({&f, it->second});
  // Each function's own facts from its flow, in parallel (each thread
  // decodes with its own SLEIGH engine) when the analysis can be read
  // from several threads, merged in function order. Each flow is held
  // only while its function is done.
  std::vector<FunctionInputs> found(jobs.size());
  if (!program.analysis->concurrent()) threads = 1;
  threads = std::max(1u, std::min<unsigned>(threads, static_cast<unsigned>(jobs.size() / 512 + 1)));
  std::atomic<std::size_t> next{0};
  auto work = [&] {
    lift::Lifter lifter(program.image, program.language_id);
    for (const lift::ContextRegion &c : lift::image_context(*program.image)) lifter.set_context(c.name, c.value, c.start, c.end);
    for (std::size_t k; (k = next.fetch_add(1)) < jobs.size();) {
      std::shared_ptr<const an::FlowGraph> flow = program.analysis->flow_shared(jobs[k].info->flow_key());
      found[k] = assemble_function(program, options, sets, *jobs[k].info, *flow, jobs[k].facts->locals, lifter);
    }
  };
  std::vector<std::thread> pool;
  for (unsigned t = 1; t < threads; ++t) pool.emplace_back(work);
  work();
  for (std::thread &t : pool) t.join();
  for (std::size_t k = 0; k < jobs.size(); ++k) {
    FunctionInputs &fi = found[k];
    for (lift::LocalFacts &l : fi.locals) jobs[k].facts->locals.push_back(std::move(l));
    for (auto &[a, kind] : fi.flow_overrides) in.flow_overrides[a] = std::move(kind);
    for (lift::LabelFacts &l : fi.code_labels) in.code_labels.push_back(std::move(l));
  }
  std::sort(in.code_labels.begin(), in.code_labels.end(),
            [](const lift::LabelFacts &a, const lift::LabelFacts &b) { return a.addr < b.addr; });
  return in;
}

}  // namespace revkit::inputs
