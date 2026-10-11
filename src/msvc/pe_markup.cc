// The PE's own structures as markup (Ghidra's PE loader markup and its
// Windows PE analyzers): headers, sections, data directories, the import,
// export, resource, debug and base relocation directories, the load
// config with the security cookie and the Control Flow Guard tables, TLS
// and its callbacks, x86 SafeSEH handlers, x64 exception data
// (RUNTIME_FUNCTION, UNWIND_INFO, C-specific handler scope tables), and
// MSVC C++ exception handling data (FuncInfo, unwind maps, try maps,
// catch handlers, IP-to-state maps) with the funclets and handlers they
// name as functions.
//
// Everything is read from the image's mapped memory by address (the
// Headers block holds the headers), each table bounded, so a damaged or
// hostile image only gets less markup.

#include "markup_internal.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

namespace revkit::msvc::detail {

namespace {

constexpr std::uint32_t kMaxSections = 96;
constexpr std::uint64_t kMaxEntries = 1 << 20;
constexpr std::uint64_t kMaxNames = 1 << 16;
constexpr std::uint32_t kMaxResourceNodes = 1 << 14;
constexpr std::uint64_t kMaxUnwindInfos = 1 << 17;

std::string hex8(std::uint64_t v, unsigned digits) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%0*llx", static_cast<int>(digits), static_cast<unsigned long long>(v));
  return buf;
}

// MSVC's FuncInfo magic numbers (__CxxFrameHandler3: VC6, VC7, VC8).
bool funcinfo_magic(std::uint32_t m) { return (m & 0x1fffffff) >= 0x19930520 && (m & 0x1fffffff) <= 0x19930522; }

class Pe {
 public:
  Pe(Builder &b, const MarkupOptions &o) : b(b), v(b.v), st(b.store()), o(o) {}

  void run() {
    if (!headers()) return;
    b.pass = "pe";
    sections();
    exports();
    imports();
    resources();
    debug_directory();
    relocations();
    tls();
    load_config();
    exception_data();
    b.pass = "msvc";
    cxx_eh();
    b.pass = "pe";
  }

 private:
  Builder &b;
  const View &v;
  types::TypeStore &st;
  const MarkupOptions &o;

  std::uint64_t base = 0, nt = 0, opt = 0, dirs = 0, sections_at = 0;
  bool wide = false;
  std::uint32_t ndirs = 0, nsections = 0;
  struct Dir {
    std::uint32_t rva = 0, size = 0;
  };
  Dir dir[16];
  struct Section {
    std::uint64_t start = 0, end = 0;  // virtual, exclusive
    bool exec = false;
  };
  std::vector<Section> secs;
  // x64 .pdata entries (begin, end, unwind), for the handlers' functions.
  struct Pdata {
    std::uint64_t begin = 0, end = 0, unwind = 0;
  };
  std::vector<Pdata> pdata;

  bool named(std::uint64_t a) const { return o.named && !o.named(a).empty(); }
  void name_if_free(std::uint64_t a, const std::string &n) {
    if (!named(a)) b.label(a, n);
  }

  types::TypeId dword() { return b.dword(); }
  types::TypeId word() { return b.word(); }
  types::TypeId byte() { return b.byte(); }
  types::TypeId ibo() { return b.ibo32(); }
  types::TypeId ptr_t() { return wide ? b.ulonglong() : dword(); }

  types::TypeId dos_header() {
    std::vector<Builder::F> f{{"e_magic", word()},    {"e_cblp", word()},     {"e_cp", word()},       {"e_crlc", word()},
                              {"e_cparhdr", word()},  {"e_minalloc", word()}, {"e_maxalloc", word()}, {"e_ss", word()},
                              {"e_sp", word()},       {"e_csum", word()},     {"e_ip", word()},       {"e_cs", word()},
                              {"e_lfarlc", word()},   {"e_ovno", word()},     {"e_res", st.array_of(word(), 4)},
                              {"e_oemid", word()},    {"e_oeminfo", word()},  {"e_res2", st.array_of(word(), 10)},
                              {"e_lfanew", st.int_type(4, true, types::IntRank::Long)}};
    return b.struct_("IMAGE_DOS_HEADER", f);
  }
  types::TypeId file_header() {
    return b.struct_("IMAGE_FILE_HEADER", {{"Machine", word()},
                                           {"NumberOfSections", word()},
                                           {"TimeDateStamp", dword()},
                                           {"PointerToSymbolTable", dword()},
                                           {"NumberOfSymbols", dword()},
                                           {"SizeOfOptionalHeader", word()},
                                           {"Characteristics", word()}});
  }
  types::TypeId data_directory() {
    return b.struct_("IMAGE_DATA_DIRECTORY", {{"VirtualAddress", ibo()}, {"Size", dword()}});
  }
  types::TypeId optional_header() {
    std::vector<Builder::F> f{{"Magic", word()},
                              {"MajorLinkerVersion", byte()},
                              {"MinorLinkerVersion", byte()},
                              {"SizeOfCode", dword()},
                              {"SizeOfInitializedData", dword()},
                              {"SizeOfUninitializedData", dword()},
                              {"AddressOfEntryPoint", ibo()},
                              {"BaseOfCode", ibo()}};
    if (!wide) f.push_back({"BaseOfData", ibo()});
    for (auto &x : std::vector<Builder::F>{{"ImageBase", ptr_t()},
                                           {"SectionAlignment", dword()},
                                           {"FileAlignment", dword()},
                                           {"MajorOperatingSystemVersion", word()},
                                           {"MinorOperatingSystemVersion", word()},
                                           {"MajorImageVersion", word()},
                                           {"MinorImageVersion", word()},
                                           {"MajorSubsystemVersion", word()},
                                           {"MinorSubsystemVersion", word()},
                                           {"Win32VersionValue", dword()},
                                           {"SizeOfImage", dword()},
                                           {"SizeOfHeaders", dword()},
                                           {"CheckSum", dword()},
                                           {"Subsystem", word()},
                                           {"DllCharacteristics", word()},
                                           {"SizeOfStackReserve", ptr_t()},
                                           {"SizeOfStackCommit", ptr_t()},
                                           {"SizeOfHeapReserve", ptr_t()},
                                           {"SizeOfHeapCommit", ptr_t()},
                                           {"LoaderFlags", dword()},
                                           {"NumberOfRvaAndSizes", dword()},
                                           {"DataDirectory", st.array_of(data_directory(), 16)}})
      f.push_back(x);
    return b.struct_(wide ? "IMAGE_OPTIONAL_HEADER64" : "IMAGE_OPTIONAL_HEADER32", f);
  }

  bool headers() {
    base = v.base();
    wide = v.wide();
    auto magic = v.u16(base);
    auto lfanew = v.u32(base + 0x3c);
    if (!magic || *magic != 0x5a4d || !lfanew || *lfanew > 0x10000) return false;
    nt = base + *lfanew;
    auto sig = v.u32(nt);
    if (!sig || *sig != 0x4550) return false;
    auto nsec = v.u16(nt + 6);
    auto optsize = v.u16(nt + 20);
    if (!nsec || !optsize) return false;
    nsections = std::min<std::uint32_t>(*nsec, kMaxSections);
    opt = nt + 24;
    sections_at = opt + *optsize;
    const std::uint64_t dir_off = wide ? 112 : 96;
    ndirs = std::min<std::uint32_t>(v.u32(opt + dir_off - 4).value_or(0), 16);
    dirs = opt + dir_off;
    for (std::uint32_t i = 0; i < ndirs && dir_off + (i + 1) * 8 <= *optsize; ++i) {
      dir[i].rva = v.u32(dirs + i * 8).value_or(0);
      dir[i].size = v.u32(dirs + i * 8 + 4).value_or(0);
    }
    b.pass = "pe";
    b.data(base, dos_header(), "IMAGE_DOS_HEADER");
    const types::TypeId oh = optional_header();
    if (*optsize == st.size_of(oh))
      b.data(nt, b.struct_(wide ? "IMAGE_NT_HEADERS64" : "IMAGE_NT_HEADERS32",
                           {{"Signature", dword()}, {"FileHeader", file_header()}, {"OptionalHeader", oh}}));
    else
      b.data(nt, b.struct_("IMAGE_NT_HEADERS_PREFIX", {{"Signature", dword()}, {"FileHeader", file_header()}}));
    b.out.counts["pe_headers"] = 1;
    return true;
  }

  void sections() {
    const types::TypeId sh = b.struct_("IMAGE_SECTION_HEADER", {{"Name", b.chars(8)},
                                                                {"VirtualSize", dword()},
                                                                {"VirtualAddress", ibo()},
                                                                {"SizeOfRawData", dword()},
                                                                {"PointerToRawData", dword()},
                                                                {"PointerToRelocations", dword()},
                                                                {"PointerToLinenumbers", dword()},
                                                                {"NumberOfRelocations", word()},
                                                                {"NumberOfLinenumbers", word()},
                                                                {"Characteristics", dword()}});
    if (nsections > 0) b.data(sections_at, sh, {}, nsections, false);
    for (std::uint32_t i = 0; i < nsections; ++i) {
      const std::uint64_t at = sections_at + std::uint64_t{i} * 40;
      auto vsize = v.u32(at + 8), va = v.u32(at + 12), raw = v.u32(at + 16), ch = v.u32(at + 36);
      if (!vsize || !va || !raw || !ch) break;
      secs.push_back({v.rva(*va), v.rva(*va) + std::max(*vsize, *raw), (*ch & 0x20000000) != 0});
    }
  }

  bool in_exec(std::uint64_t a) const { return v.executable(a); }
  std::uint64_t at(std::uint32_t rva) const { return v.rva(rva); }

  // A NUL-terminated ASCII string at `a`, typed (at most 1 KiB).
  void ascii(std::uint64_t a, std::string name = {}) {
    auto s = v.cstring(a, 1024);
    if (s) b.string(a, s->size() + 1, std::move(name));
  }

  void exports() {
    const Dir &d = dir[0];
    if (d.rva == 0 || d.size < 40) return;
    const std::uint64_t ed = at(d.rva);
    const types::TypeId t = b.struct_("IMAGE_EXPORT_DIRECTORY", {{"Characteristics", dword()},
                                                                  {"TimeDateStamp", dword()},
                                                                  {"MajorVersion", word()},
                                                                  {"MinorVersion", word()},
                                                                  {"Name", ibo()},
                                                                  {"Base", dword()},
                                                                  {"NumberOfFunctions", dword()},
                                                                  {"NumberOfNames", dword()},
                                                                  {"AddressOfFunctions", ibo()},
                                                                  {"AddressOfNames", ibo()},
                                                                  {"AddressOfNameOrdinals", ibo()}});
    if (!b.data(ed, t)) return;
    const std::uint64_t nf = std::min<std::uint64_t>(v.u32(ed + 20).value_or(0), kMaxEntries);
    const std::uint64_t nn = std::min<std::uint64_t>(v.u32(ed + 24).value_or(0), kMaxEntries);
    if (auto n = v.u32(ed + 12); n && *n) ascii(at(*n));
    if (auto f = v.u32(ed + 28); f && *f && nf) b.data(at(*f), ibo(), {}, nf, true);
    if (auto n = v.u32(ed + 32); n && *n && nn) {
      b.data(at(*n), ibo(), {}, nn, true);
      for (std::uint64_t i = 0; i < std::min(nn, kMaxNames); ++i)
        if (auto s = v.u32(at(*n) + i * 4); s && *s) ascii(at(*s));
    }
    if (auto ord = v.u32(ed + 36); ord && *ord && nn) b.data(at(*ord), word(), {}, nn, true);
    b.out.counts["exports"] = nf;
  }

  void imports() {
    const Dir &d = dir[1];
    if (d.rva == 0) return;
    const std::uint64_t first = at(d.rva);
    const types::TypeId desc = b.struct_("IMAGE_IMPORT_DESCRIPTOR", {{"OriginalFirstThunk", ibo()},
                                                                     {"TimeDateStamp", dword()},
                                                                     {"ForwarderChain", dword()},
                                                                     {"Name", ibo()},
                                                                     {"FirstThunk", ibo()}});
    std::uint64_t n = 0;
    while (n < 4096) {
      auto name = v.u32(first + n * 20 + 12), iat = v.u32(first + n * 20 + 16);
      if (!name || !iat || (*name == 0 && *iat == 0)) break;
      ++n;
    }
    if (n == 0) return;
    b.data(first, desc, {}, n + 1, false);
    const unsigned ps = v.pointer();
    const std::uint64_t ordinal = wide ? 1ULL << 63 : 1ULL << 31;
    std::size_t total = 0;
    std::set<std::uint32_t> walked;
    for (std::uint64_t i = 0; i < n; ++i) {
      const std::uint64_t e = first + i * 20;
      if (auto name = v.u32(e + 12); name && *name) ascii(at(*name));
      // The lookup table (the IAT stays the loader's: its slots are the
      // imports' pointers). Descriptors sharing one are walked once, and
      // the walk stops at kMaxNames thunks in all.
      auto ilt = v.u32(e);
      if (!ilt || *ilt == 0 || !walked.insert(*ilt).second || total >= kMaxNames) continue;
      std::uint64_t k = 0;
      for (; k < kMaxNames; ++k) {
        auto value = v.ptr(at(*ilt) + k * ps);
        if (!value || *value == 0) break;
        if ((*value & ordinal) == 0) {
          const std::uint64_t hn = at(static_cast<std::uint32_t>(*value & 0x7fffffff));
          if (auto s = v.cstring(hn + 2, 1024))
            b.data(hn, b.struct_("IMAGE_IMPORT_BY_NAME", {{"Hint", word()}, {"Name", b.chars(s->size() + 1)}}));
        }
      }
      b.data(at(*ilt), ptr_t(), {}, k + 1, true);
      total += k;
    }
    b.out.counts["imports"] = total;
  }

  void resources() {
    const Dir &d = dir[2];
    if (d.rva == 0 || d.size < 16) return;
    const std::uint64_t root = at(d.rva);
    const types::TypeId dirt = b.struct_("IMAGE_RESOURCE_DIRECTORY", {{"Characteristics", dword()},
                                                                       {"TimeDateStamp", dword()},
                                                                       {"MajorVersion", word()},
                                                                       {"MinorVersion", word()},
                                                                       {"NumberOfNamedEntries", word()},
                                                                       {"NumberOfIdEntries", word()}});
    const types::TypeId entry =
        b.struct_("IMAGE_RESOURCE_DIRECTORY_ENTRY", {{"NameOrId", dword()}, {"OffsetToData", dword()}});
    const types::TypeId data = b.struct_("IMAGE_RESOURCE_DATA_ENTRY", {{"OffsetToData", ibo()},
                                                                        {"Size", dword()},
                                                                        {"CodePage", dword()},
                                                                        {"Reserved", dword()}});
    std::vector<std::pair<std::uint64_t, int>> work{{root, 0}};
    std::set<std::uint64_t> seen;
    std::uint32_t nodes = 0, leaves = 0;
    while (!work.empty() && nodes < kMaxResourceNodes) {
      auto [a, depth] = work.back();
      work.pop_back();
      if (!seen.insert(a).second || a < root || a - root >= d.size) continue;
      ++nodes;
      b.data(a, dirt);
      const std::uint32_t n = v.u16(a + 12).value_or(0) + v.u16(a + 14).value_or(0);
      if (n == 0) continue;
      b.data(a + 16, entry, {}, n, true);
      for (std::uint32_t i = 0; i < n && i < 4096; ++i) {
        const std::uint64_t e = a + 16 + std::uint64_t{i} * 8;
        auto name = v.u32(e);
        auto off = v.u32(e + 4);
        if (!name || !off) break;
        if (*name & 0x80000000) {
          // A name: IMAGE_RESOURCE_DIR_STRING_U, a length and UTF-16 characters.
          const std::uint64_t s = root + (*name & 0x7fffffff);
          if (auto len = v.u16(s); len && *len < 1024)
            b.data(s, b.struct_("IMAGE_RESOURCE_DIR_STRING_U_" + std::to_string(*len),
                                {{"Length", word()},
                                 {"NameString", st.array_of(st.int_type(2, false, types::IntRank::WChar), std::max<std::uint16_t>(*len, 1))}}));
        }
        if (*off & 0x80000000) {
          if (depth < 8) work.push_back({root + (*off & 0x7fffffff), depth + 1});
        } else if (b.data(root + *off, data)) {
          ++leaves;
        }
      }
    }
    b.out.counts["resources"] = leaves;
  }

  void debug_directory() {
    const Dir &d = dir[6];
    if (d.rva == 0 || d.size < 28) return;
    const std::uint64_t first = at(d.rva);
    const std::uint64_t n = std::min<std::uint64_t>(d.size / 28, 64);
    b.data(first, b.struct_("IMAGE_DEBUG_DIRECTORY", {{"Characteristics", dword()},
                                                      {"TimeDateStamp", dword()},
                                                      {"MajorVersion", word()},
                                                      {"MinorVersion", word()},
                                                      {"Type", dword()},
                                                      {"SizeOfData", dword()},
                                                      {"AddressOfRawData", ibo()},
                                                      {"PointerToRawData", dword()}}),
           {}, n, false);
    for (std::uint64_t i = 0; i < n; ++i) {
      const std::uint64_t e = first + i * 28;
      auto type = v.u32(e + 12), size = v.u32(e + 16), rva = v.u32(e + 20);
      if (!type || !size || !rva || *rva == 0 || *type != 2) continue;  // CodeView
      const std::uint64_t cv = at(*rva);
      if (v.u32(cv).value_or(0) != 0x53445352 || *size <= 24) continue;  // RSDS
      const types::TypeId guid =
          b.struct_("GUID", {{"Data1", dword()}, {"Data2", word()}, {"Data3", word()}, {"Data4", st.array_of(byte(), 8)}});
      b.data(cv, b.struct_("CV_INFO_PDB70_" + std::to_string(*size - 24),
                           {{"CvSignature", dword()}, {"Signature", guid}, {"Age", dword()}, {"PdbFileName", b.chars(*size - 24)}}));
    }
  }

  void relocations() {
    const Dir &d = dir[5];
    if (d.rva == 0 || d.size < 8) return;
    const types::TypeId blk = b.struct_("IMAGE_BASE_RELOCATION", {{"VirtualAddress", ibo()}, {"SizeOfBlock", dword()}});
    std::uint64_t off = 0;
    std::size_t blocks = 0;
    while (off + 8 <= d.size && blocks < kMaxEntries) {
      const std::uint64_t a = at(d.rva) + off;
      auto size = v.u32(a + 4);
      if (!size || *size < 8 || off + *size > d.size) break;
      b.data(a, blk);
      if (*size > 8) b.data(a + 8, word(), {}, (*size - 8) / 2, true);
      off += (*size + 3) & ~3u;
      ++blocks;
    }
    b.out.counts["relocation_blocks"] = blocks;
  }

  void function(std::uint64_t entry, std::string name, const char *why) {
    if (!in_exec(entry)) return;
    FunctionDef f;
    f.entry = entry;
    if (!named(entry)) f.name = std::move(name);
    f.why = why;
    b.function(std::move(f));
  }

  void tls() {
    const Dir &d = dir[9];
    if (d.rva == 0) return;
    const std::uint64_t td = at(d.rva);
    const types::TypeId t = b.struct_(wide ? "IMAGE_TLS_DIRECTORY64" : "IMAGE_TLS_DIRECTORY32",
                                      {{"StartAddressOfRawData", ptr_t()},
                                       {"EndAddressOfRawData", ptr_t()},
                                       {"AddressOfIndex", ptr_t()},
                                       {"AddressOfCallBacks", ptr_t()},
                                       {"SizeOfZeroFill", dword()},
                                       {"Characteristics", dword()}});
    if (!b.data(td, t, named(td) ? std::string() : "_tls_used")) return;
    auto cbs = v.ptr(td + 3 * v.pointer());
    if (!cbs || *cbs == 0) return;
    std::uint64_t n = 0;
    for (; n < 256; ++n) {
      auto cb = v.ptr(*cbs + n * v.pointer());
      if (!cb || *cb == 0) break;
      function(*cb, "tls_callback_" + std::to_string(n), "tls_callback");
    }
    b.data(*cbs, b.pointer(st.void_type()), {}, n + 1, true);
    if (!named(*cbs)) b.label(*cbs, "__tls_callbacks");
    b.out.counts["tls_callbacks"] = n;
  }

  void load_config() {
    const Dir &d = dir[10];
    if (d.rva == 0) return;
    const std::uint64_t lc = at(d.rva);
    auto size = v.u32(lc);
    if (!size || *size < 8) return;
    // The fields as far as Size says (the structure grew with each SDK).
    std::vector<Builder::F> all{{"Size", dword()},
                                {"TimeDateStamp", dword()},
                                {"MajorVersion", word()},
                                {"MinorVersion", word()},
                                {"GlobalFlagsClear", dword()},
                                {"GlobalFlagsSet", dword()},
                                {"CriticalSectionDefaultTimeout", dword()},
                                {"DeCommitFreeBlockThreshold", ptr_t()},
                                {"DeCommitTotalFreeThreshold", ptr_t()},
                                {"LockPrefixTable", ptr_t()},
                                {"MaximumAllocationSize", ptr_t()},
                                {"VirtualMemoryThreshold", ptr_t()},
                                {wide ? "ProcessAffinityMask" : "ProcessHeapFlags", wide ? ptr_t() : dword()},
                                {wide ? "ProcessHeapFlags" : "ProcessAffinityMask", wide ? dword() : ptr_t()},
                                {"CSDVersion", word()},
                                {"DependentLoadFlags", word()},
                                {"EditList", ptr_t()},
                                {"SecurityCookie", ptr_t()},
                                {"SEHandlerTable", ptr_t()},
                                {"SEHandlerCount", ptr_t()},
                                {"GuardCFCheckFunctionPointer", ptr_t()},
                                {"GuardCFDispatchFunctionPointer", ptr_t()},
                                {"GuardCFFunctionTable", ptr_t()},
                                {"GuardCFFunctionCount", ptr_t()},
                                {"GuardFlags", dword()}};
    std::vector<Builder::F> fields;
    std::uint64_t used = 0;
    std::map<std::string, std::uint64_t> offset;
    for (const Builder::F &f : all) {
      const std::uint32_t al = std::max<std::uint32_t>(1, st.align_of(f.type));
      const std::uint64_t at_ = (used + al - 1) / al * al;
      if (at_ + st.size_of(f.type) > *size) break;
      fields.push_back(f);
      offset[f.name] = at_;
      used = at_ + st.size_of(f.type);
    }
    const types::TypeId t = b.struct_((wide ? "IMAGE_LOAD_CONFIG_DIRECTORY64_" : "IMAGE_LOAD_CONFIG_DIRECTORY32_") +
                                          std::to_string(*size),
                                      fields, types::AggregateKind::Struct, *size);
    b.data(lc, t, named(lc) ? std::string() : "_load_config_used");
    auto field = [&](const char *name) -> std::optional<std::uint64_t> {
      auto it = offset.find(name);
      if (it == offset.end()) return std::nullopt;
      auto x = v.ptr(lc + it->second);
      if (!x || *x == 0) return std::nullopt;
      return x;
    };
    if (auto cookie = field("SecurityCookie"); cookie && v.mapped(*cookie, v.pointer())) {
      b.data(*cookie, ptr_t());
      name_if_free(*cookie, "__security_cookie");
      b.out.counts["security_cookie"] = 1;
    }
    if (auto p = field("GuardCFCheckFunctionPointer")) {
      b.data(*p, b.voidp());
      name_if_free(*p, "__guard_check_icall_fptr");
    }
    if (auto p = field("GuardCFDispatchFunctionPointer")) {
      b.data(*p, b.voidp());
      name_if_free(*p, "__guard_dispatch_icall_fptr");
    }
    // x86 SafeSEH: the registered handlers' RVAs.
    if (auto t = field("SEHandlerTable"); t && !wide) {
      const std::uint64_t n = std::min<std::uint64_t>(field("SEHandlerCount").value_or(0), 1 << 16);
      if (n && b.data(*t, ibo(), named(*t) ? std::string() : "__safe_se_handler_table", n, true)) {
        for (std::uint64_t i = 0; i < n; ++i)
          if (auto r = v.u32(*t + i * 4)) function(at(*r), {}, "seh_handler");
        b.out.counts["seh_handlers"] = n;
      }
    }
    // Control Flow Guard: the valid call targets' RVAs, each followed by
    // as many flag bytes as GuardFlags' stride says.
    if (auto t = field("GuardCFFunctionTable")) {
      const std::uint64_t n = std::min<std::uint64_t>(field("GuardCFFunctionCount").value_or(0), kMaxEntries);
      const std::uint32_t flags = offset.contains("GuardFlags") ? v.u32(lc + offset["GuardFlags"]).value_or(0) : 0;
      const std::uint32_t stride = 4 + ((flags >> 28) & 0xf);
      if (n) {
        types::TypeId e = ibo();
        if (stride > 4)
          e = b.struct_("IMAGE_GUARD_CF_ENTRY_" + std::to_string(stride),
                        {{"Rva", ibo()}, {"Flags", st.array_of(byte(), stride - 4)}}, types::AggregateKind::Struct, 0, true);
        if (b.data(*t, e, named(*t) ? std::string() : "__guard_fids_table", n, true)) {
          for (std::uint64_t i = 0; i < n; ++i)
            if (auto r = v.u32(*t + i * stride)) function(at(*r), {}, "guard_cf");
          b.out.counts["guard_cf_functions"] = n;
        }
      }
    }
  }

  // ---- x64 exception data ----

  types::TypeId runtime_function() {
    return b.struct_("_IMAGE_RUNTIME_FUNCTION_ENTRY",
                     {{"BeginAddress", ibo()}, {"EndAddress", ibo()}, {"UnwindInfoAddressOrData", ibo()}});
  }

  const Pdata *function_of(std::uint64_t a) const {
    auto it = std::upper_bound(pdata.begin(), pdata.end(), a, [](std::uint64_t x, const Pdata &p) { return x < p.begin; });
    if (it == pdata.begin()) return nullptr;
    --it;
    return a < it->end ? &*it : nullptr;
  }

  // Handler data recognized after its UNWIND_INFO.
  struct Handler {
    std::uint64_t handler = 0;  // the language handler
    std::uint64_t data = 0;     // its data
    const Pdata *fn = nullptr;
  };
  std::vector<Handler> handlers;

  void exception_data() {
    const Dir &d = dir[3];
    if (!wide || d.rva == 0 || d.size < 12) return;  // x64's (ARM64's are packed differently)
    if (v.image().machine != 0x8664) return;
    const std::uint64_t first = at(d.rva);
    const std::uint64_t n = std::min<std::uint64_t>(d.size / 12, kMaxEntries);
    for (std::uint64_t i = 0; i < n; ++i) {
      auto bg = v.u32(first + i * 12), en = v.u32(first + i * 12 + 4), un = v.u32(first + i * 12 + 8);
      if (!bg || !en || !un || (*bg == 0 && *en == 0)) break;
      pdata.push_back({at(*bg), at(*en), *un});
    }
    if (pdata.empty()) return;
    b.data(first, runtime_function(), named(first) ? std::string() : "__pdata", pdata.size(), true);
    b.out.counts["pdata_entries"] = pdata.size();
    std::sort(pdata.begin(), pdata.end(), [](const Pdata &x, const Pdata &y) { return x.begin < y.begin; });
    // UNWIND_INFO: version and flags, prologue size, code count, frame
    // register and offset; the codes (2 bytes each, an even count); then a
    // language handler and its data, or a chained RUNTIME_FUNCTION.
    const types::TypeId header = b.struct_("UNWIND_INFO", {{"VersionAndFlags", byte()},
                                                          {"SizeOfProlog", byte()},
                                                          {"CountOfUnwindCodes", byte()},
                                                          {"FrameRegisterAndOffset", byte()}});
    std::set<std::uint64_t> seen;
    std::size_t infos = 0;
    for (const Pdata &p : pdata) {
      if (p.unwind & 1) continue;  // an indirect (chained) entry
      const std::uint64_t ui = at(p.unwind);
      if (!seen.insert(ui).second || infos >= kMaxUnwindInfos) continue;
      auto vf = v.uint(ui, 1), cc = v.uint(ui + 2, 1);
      if (!vf || !cc || (*vf & 7) == 0 || (*vf & 7) > 2) continue;
      if (!b.data(ui, header)) continue;
      ++infos;
      const std::uint64_t codes = (*cc + 1) & ~std::uint64_t{1};
      if (*cc) b.data(ui + 4, word(), {}, codes, true);
      const std::uint64_t after = ui + 4 + codes * 2;
      const unsigned flags = static_cast<unsigned>(*vf >> 3);
      if (flags & 4) {  // UNW_FLAG_CHAININFO
        b.data(after, runtime_function());
      } else if (flags & 3) {  // UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER
        if (auto h = v.u32(after); h && *h) {
          b.data(after, ibo());
          handlers.push_back({at(*h), after + 4, &p});
        }
      }
    }
    b.out.counts["unwind_infos"] = infos;
    // The handlers: functions, and their data where it is recognized (a
    // C-specific handler's scope table; MSVC C++ EH's FuncInfo, below).
    std::size_t scopes = 0;
    std::set<std::uint64_t> made;
    for (const Handler &h : handlers) {
      if (made.insert(h.handler).second) function(h.handler, {}, "eh_handler");
      if (scope_table(h)) ++scopes;
    }
    b.out.counts["c_scope_tables"] = scopes;
  }

  // A __C_specific_handler scope table: a count, then that many entries
  // of (begin, end, filter or 1, target) inside the function.
  bool scope_table(const Handler &h) {
    auto count = v.u32(h.data);
    if (!count || *count == 0 || *count > 256) return false;
    struct E {
      std::uint64_t begin, end, filter, target;
    };
    std::vector<E> es;
    for (std::uint32_t i = 0; i < *count; ++i) {
      const std::uint64_t e = h.data + 4 + std::uint64_t{i} * 16;
      auto bg = v.u32(e), en = v.u32(e + 4), fl = v.u32(e + 8), tg = v.u32(e + 12);
      if (!bg || !en || !fl || !tg) return false;
      E x{at(*bg), at(*en), *fl, *tg ? at(*tg) : 0};
      if (x.begin < h.fn->begin || x.end > h.fn->end || x.begin >= x.end) return false;
      if (x.target != 0 && (x.target < h.fn->begin || x.target >= h.fn->end)) return false;
      if (x.filter > 1 && !in_exec(at(static_cast<std::uint32_t>(x.filter)))) return false;
      es.push_back(x);
    }
    const types::TypeId entry = b.struct_("C_SCOPE_TABLE_ENTRY", {{"BeginAddress", ibo()},
                                                                   {"EndAddress", ibo()},
                                                                   {"HandlerAddress", ibo()},
                                                                   {"JumpTarget", ibo()}});
    // A table that overlaps one already read (or itself, through another
    // unwind info) adds nothing; without this, tables overlapping each
    // other replay their filters.
    if (!b.data(h.data, dword())) return false;
    if (!b.data(h.data + 4, entry, {}, es.size(), true)) return false;
    for (const E &x : es) {
      if (x.filter > 1) function(at(static_cast<std::uint32_t>(x.filter)), "Filter@" + hex8(at(static_cast<std::uint32_t>(x.filter)), 8), "seh_filter");
      if (x.target != 0 && !named(x.target)) b.label(x.target, "__except_" + hex8(x.target, 8));
    }
    return true;
  }

  // ---- MSVC C++ exception handling (__CxxFrameHandler3) ----

  void cxx_eh() {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> infos;  // (FuncInfo, its function or 0)
    if (wide) {
      // x64: the language handler's data is the FuncInfo's RVA.
      for (const Handler &h : handlers) {
        auto fi = v.u32(h.data);
        if (fi && *fi && funcinfo_magic(v.u32(at(*fi)).value_or(0))) {
          b.data(h.data, ibo());
          infos.push_back({at(*fi), h.fn->begin});
        }
      }
    } else {
      // x86: each function's handler is `mov eax, FuncInfo; jmp
      // __CxxFrameHandler3` (its own __ehhandler$ thunk).
      for (const loader::Block &blk : v.image().blocks) {
        if (!blk.perms.exec || !blk.initialized || blk.size > (64u << 20)) continue;
        std::vector<std::uint8_t> bytes = v.block_bytes(blk);
        for (std::size_t i = 0; i + 10 <= bytes.size(); ++i) {
          if (bytes[i] != 0xb8 || bytes[i + 5] != 0xe9) continue;
          std::uint32_t fi = 0;
          std::memcpy(&fi, &bytes[i + 1], 4);
          if (!funcinfo_magic(v.u32(fi).value_or(0))) continue;
          infos.push_back({fi, 0});
          function(blk.start + i, {}, "eh_handler");
        }
      }
    }
    std::sort(infos.begin(), infos.end());
    infos.erase(std::unique(infos.begin(), infos.end(), [](const auto &x, const auto &y) { return x.first == y.first; }),
                infos.end());
    std::size_t done = 0, funclets = 0;
    for (const auto &[fi, fn] : infos)
      if (funcinfo(fi, funclets)) ++done;
    b.out.counts["eh_functions"] = done;
    b.out.counts["eh_handlers"] = funclets;
  }

  // An absolute pointer (32-bit) or an RVA (64-bit) field.
  std::optional<std::uint64_t> ref(std::uint64_t a) const { return v.ref(a); }

  bool funcinfo(std::uint64_t fi, std::size_t &funclets) {
    const types::TypeId r32 = wide ? ibo() : dword();
    std::vector<Builder::F> f{{"magicNumber", dword()},  {"maxState", b.i32()},     {"pUnwindMap", r32},
                              {"nTryBlocks", dword()},   {"pTryBlockMap", r32},     {"nIPMapEntries", dword()},
                              {"pIPToStateMap", r32}};
    if (wide) f.push_back({"dispUnwindHelp", b.i32()});
    f.push_back({"pESTypeList", r32});
    f.push_back({"EHFlags", b.i32()});
    const types::TypeId t = b.struct_("FuncInfo", f);
    if (!b.data(fi, t, named(fi) ? std::string() : "FuncInfo_" + hex8(fi, wide ? 16 : 8))) return false;
    const std::int32_t max_state = v.i32(fi + 4).value_or(0);
    const std::uint32_t ntry = v.u32(fi + 12).value_or(0);
    const std::uint32_t nip = v.u32(fi + 20).value_or(0);
    // Unwind map: (toState, action) per state; actions are funclets.
    if (max_state > 0 && max_state < 65536)
      if (auto um = ref(fi + 8); um && *um) {
        const types::TypeId e = b.struct_("UnwindMapEntry", {{"toState", b.i32()}, {"action", r32}});
        if (b.data(*um, e, {}, static_cast<std::uint64_t>(max_state), true))
          for (std::int32_t i = 0; i < max_state; ++i)
            if (auto act = ref(*um + std::uint64_t(i) * 8 + 4); act && *act && in_exec(*act)) {
              function(*act, "Unwind@" + hex8(*act, 8), "eh_unwind");
              ++funclets;
            }
      }
    // Try blocks: their catch handlers.
    if (ntry > 0 && ntry < 4096)
      if (auto tm = ref(fi + 16); tm && *tm) {
        const types::TypeId hte = handler_type();
        const types::TypeId e = b.struct_("TryBlockMapEntry", {{"tryLow", b.i32()},
                                                               {"tryHigh", b.i32()},
                                                               {"catchHigh", b.i32()},
                                                               {"nCatches", b.i32()},
                                                               {"pHandlerArray", r32}});
        if (b.data(*tm, e, {}, ntry, true))
          for (std::uint32_t i = 0; i < ntry; ++i) {
            const std::uint64_t at_ = *tm + std::uint64_t{i} * 20;
            const std::int32_t n = v.i32(at_ + 12).value_or(0);
            auto ha = ref(at_ + 16);
            if (n <= 0 || n > 1024 || !ha || !*ha) continue;
            const std::uint64_t hsize = st.size_of(hte);
            // Each try block owns its handler array: one that is already
            // claimed (another entry's) isn't replayed.
            if (!b.data(*ha, hte, {}, static_cast<std::uint64_t>(n), true)) continue;
            for (std::int32_t k = 0; k < n; ++k) {
              const std::uint64_t h = *ha + std::uint64_t(k) * hsize;
              auto type = ref(h + 4);
              auto handler = ref(h + (wide ? 12 : 12));
              if (type && *type) type_descriptor(*type);
              if (handler && *handler && in_exec(*handler)) {
                const bool all = !type || *type == 0;
                function(*handler, std::string(all ? "Catch_All@" : "Catch@") + hex8(*handler, 8), "eh_catch");
                ++funclets;
              }
            }
          }
      }
    // IP-to-state map (64-bit).
    if (wide && nip > 0 && nip < (1u << 20))
      if (auto ip = ref(fi + 24); ip && *ip)
        b.data(*ip, b.struct_("IPtoStateMapEntry", {{"Ip", ibo()}, {"State", b.i32()}}), {}, nip, true);
    return true;
  }

  types::TypeId handler_type() {
    std::vector<Builder::F> f{{"adjectives", dword()},
                              {"pType", wide ? ibo() : dword()},
                              {"dispCatchObj", b.i32()},
                              {"addressOfHandler", wide ? ibo() : dword()}};
    if (wide) f.push_back({"dispFrame", dword()});
    return b.struct_("HandlerType", f);
  }

  // A TypeDescriptor a catch names (any type: ".H" is int): typed, and
  // named after its class when it is one (the RTTI pass names those).
  void type_descriptor(std::uint64_t td) {
    const unsigned p = v.pointer();
    auto name = v.cstring(td + 2 * p, 4096);
    if (!name || name->empty() || (*name)[0] != '.') return;
    const types::TypeId t = b.struct_("TypeDescriptor", {{"pVFTable", b.voidp()}, {"spare", b.voidp()}});
    if (b.data(td, t)) b.string(td + 2 * p, name->size() + 1);
  }
};

}  // namespace

void pe_markup(Builder &b, const MarkupOptions &options) { Pe(b, options).run(); }

}  // namespace revkit::msvc::detail
