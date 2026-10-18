// PE32/PE32+ parser.
//
// Policy mirrors the ELF parser: the headers and section table must be valid
// or we throw; data directories (imports, exports, debug, exception data) are
// best effort and add a warning when unreadable.

#include "revkit/loader/load.hh"

#include "reader.hh"

#include <algorithm>
#include <array>
#include <map>

namespace revkit::loader {

namespace {

using detail::checked_add;
using detail::fail;
using detail::hex;
using detail::Reader;

constexpr std::uint16_t kMagicPe32 = 0x10b;
constexpr std::uint16_t kMagicPe32Plus = 0x20b;
constexpr std::uint16_t kMachineAmd64 = 0x8664;
constexpr std::uint16_t kMachineArm64 = 0xaa64;

constexpr std::uint32_t kScnMemExecute = 0x20000000;
constexpr std::uint32_t kScnMemRead = 0x40000000;
constexpr std::uint32_t kScnMemWrite = 0x80000000;

constexpr unsigned kDirExport = 0;
constexpr unsigned kDirImport = 1;
constexpr unsigned kDirException = 3;
constexpr unsigned kDirDebug = 6;
constexpr unsigned kDirClr = 14;  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR

constexpr std::uint32_t kDebugTypeCodeView = 2;

// Caps on table walks, so absurd counts in a small file stay cheap. Real
// images are far below these.
constexpr std::uint64_t kMaxImportDescriptors = 4096;
constexpr std::uint64_t kMaxThunks = 1 << 16;
constexpr std::uint64_t kMaxExports = 1 << 20;
constexpr std::uint64_t kMaxDebugEntries = 64;
constexpr std::uint64_t kMaxPdataEntries = 1 << 20;
constexpr std::uint64_t kMaxNameLength = 4096;
// Totals: descriptors may share (or overlap) one lookup table, and export
// names one string, so per-table caps alone multiply.
constexpr std::uint64_t kMaxImports = 1 << 20;
constexpr std::uint64_t kMaxNameBytes = 64 << 20;

struct DataDir {
  std::uint32_t rva = 0;
  std::uint32_t size = 0;
};

struct RawSection {
  std::string name;
  std::uint32_t virtual_size = 0;
  std::uint32_t virtual_address = 0;
  std::uint32_t raw_size = 0;
  std::uint32_t raw_ptr = 0;
  std::uint32_t characteristics = 0;
};

class PeParser {
 public:
  PeParser(std::shared_ptr<const Bytes> file, const LoadOptions &options)
      : file_(std::move(file)), r_(*file_, Endian::little), options_(options) {}

  Image run() {
    img_.format = Format::pe;
    img_.endian = Endian::little;
    img_.file = file_;
    img_.memory = Memory(file_);

    read_headers();
    read_sections();
    build_memory();
    best_effort("export directory", [&] { read_exports(); });
    best_effort("import directory", [&] { read_imports(); });
    best_effort("debug directory", [&] { read_debug(); });
    best_effort("exception directory", [&] { read_pdata(); });
    best_effort("CLR header", [&] { read_clr(); });
    std::sort(img_.blocks.begin(), img_.blocks.end(),
              [](const Block &a, const Block &b) { return a.start < b.start; });
    return std::move(img_);
  }

 private:
  void warn(std::string msg) { img_.warnings.push_back(std::move(msg)); }

  template <class F>
  void best_effort(const char *what, F &&f) {
    try {
      f();
    } catch (const LoadError &e) {
      warn(std::string("PE: ") + what + ": " + e.what());
    }
  }

  std::uint64_t va(std::uint64_t rva) const {
    std::uint64_t a = base_ + rva;
    return wide_ ? a : (a & 0xffffffffULL);
  }

  void read_headers() {
    r_.require(0, 0x40, "DOS header");
    std::uint32_t lfanew = r_.u32(0x3c);
    r_.require(lfanew, 24, "PE headers");
    if (r_.u32(lfanew) != 0x00004550) fail("PE: missing PE signature at " + hex(lfanew));

    const std::uint64_t coff = std::uint64_t{lfanew} + 4;
    img_.machine = r_.u16(coff);
    nsections_ = r_.u16(coff + 2);
    symtab_ptr_ = r_.u32(coff + 8);
    nsymbols_ = r_.u32(coff + 12);
    std::uint16_t opt_size = r_.u16(coff + 16);
    img_.flags = r_.u16(coff + 18);

    opt_ = coff + 20;
    r_.require(opt_, opt_size, "PE optional header");
    if (opt_size < 2) fail("PE: optional header too small");
    std::uint16_t magic = r_.u16(opt_);
    if (magic == kMagicPe32) wide_ = false;
    else if (magic == kMagicPe32Plus) wide_ = true;
    else fail("PE: bad optional header magic " + hex(magic));
    img_.bits = wide_ ? 64 : 32;

    const std::uint64_t dir_off = wide_ ? 112 : 96;
    if (opt_size < dir_off) fail("PE: optional header too small (" + std::to_string(opt_size) + " bytes)");

    entry_rva_ = r_.u32(opt_ + 16);
    std::uint64_t file_base = wide_ ? r_.u64(opt_ + 24) : r_.u32(opt_ + 28);
    size_of_headers_ = r_.u32(opt_ + 60);
    std::uint32_t ndirs = r_.u32(opt_ + (wide_ ? 108 : 92));

    base_ = options_.image_base.value_or(file_base);
    if (!wide_ && base_ > 0xffffffffULL) fail("PE: image base " + hex(base_) + " does not fit PE32");
    img_.image_base = base_;
    img_.file_base = file_base;
    if (entry_rva_ != 0) img_.entry = va(entry_rva_);

    std::uint64_t avail = (opt_size - dir_off) / 8;
    std::uint64_t n = std::min<std::uint64_t>({ndirs, avail, dirs_.size()});
    for (std::uint64_t i = 0; i < n; ++i) {
      dirs_[i].rva = r_.u32(opt_ + dir_off + i * 8);
      dirs_[i].size = r_.u32(opt_ + dir_off + i * 8 + 4);
    }
    sections_off_ = opt_ + opt_size;
    lfanew_ = lfanew;
  }

  // Resolves "/123" long names through the COFF string table, as MinGW emits.
  std::string section_name(std::span<const std::byte> raw) const {
    std::string name;
    for (std::byte b : raw) {
      if (b == std::byte{0}) break;
      name.push_back(static_cast<char>(b));
    }
    if (name.size() > 1 && name[0] == '/' && symtab_ptr_ != 0) {
      std::uint64_t off = 0;
      for (std::size_t i = 1; i < name.size(); ++i) {
        if (name[i] < '0' || name[i] > '9') return readable(name);
        off = off * 10 + static_cast<std::uint64_t>(name[i] - '0');
      }
      std::uint64_t strtab = std::uint64_t{symtab_ptr_} + std::uint64_t{nsymbols_} * 18;
      std::uint64_t at = strtab + off;
      if (r_.has(at, 1)) {
        try {
          return readable(r_.cstring(at, 256, "PE section name"));
        } catch (const LoadError &) {
        }
      }
    }
    return readable(name);
  }

  // Ghidra replaces non-printable characters in section names with '_'.
  static std::string readable(std::string s) {
    for (char &c : s)
      if (c < 0x20 || c > 0x7e) c = '_';
    return s;
  }

  void read_sections() {
    std::uint64_t table = std::uint64_t{nsections_} * 40;
    r_.require(sections_off_, table, "PE section table");
    for (std::uint64_t i = 0; i < nsections_; ++i) {
      std::uint64_t off = sections_off_ + i * 40;
      RawSection s;
      s.name = section_name(r_.bytes(off, 8, "PE section name"));
      s.virtual_size = r_.u32(off + 8);
      s.virtual_address = r_.u32(off + 12);
      s.raw_size = r_.u32(off + 16);
      s.raw_ptr = r_.u32(off + 20);
      s.characteristics = r_.u32(off + 36);
      if (s.name.empty()) s.name = "SECTION." + std::to_string(i);
      raw_.push_back(s);

      Section out;
      out.name = s.name;
      out.flags = s.characteristics;
      out.addr = va(s.virtual_address);
      out.offset = s.raw_ptr;
      // Ghidra maps the larger of the virtual and raw sizes (file alignment
      // padding included); the gap to the next section is clipped below.
      out.size = s.virtual_size;
      out.virtual_size = s.virtual_size;
      if (s.raw_ptr != 0) out.size = std::max(s.virtual_size, s.raw_size);
      out.file_size = s.raw_ptr != 0 ? std::min<std::uint64_t>(s.raw_size, out.size) : 0;
      out.alloc = true;
      out.perms = {(s.characteristics & kScnMemRead) != 0, (s.characteristics & kScnMemWrite) != 0,
                   (s.characteristics & kScnMemExecute) != 0};
      img_.sections.push_back(std::move(out));
    }
  }

  void add_region(const Region &region, const std::string &what) {
    if (!wide_ && region.size - 1 > 0xffffffffULL - region.start)
      fail("PE: " + what + " at " + hex(region.start) + " overflows the 32-bit address space");
    try {
      img_.memory.add(region);
    } catch (const LoadError &e) {
      fail("PE: " + what + ": " + e.what());
    }
  }

  // Raw-size padding must not run into the next section.
  void clip_sections() {
    for (std::size_t i = 0; i < raw_.size(); ++i) {
      Section &sec = img_.sections[i];
      for (std::size_t j = 0; j < raw_.size(); ++j) {
        if (raw_[j].virtual_address <= raw_[i].virtual_address) continue;
        std::uint64_t gap = raw_[j].virtual_address - raw_[i].virtual_address;
        std::uint64_t floor = std::max<std::uint64_t>(raw_[i].virtual_size, 1);
        if (sec.size > gap && gap >= floor) sec.size = gap;
      }
      sec.file_size = std::min(sec.file_size, sec.size);
    }
  }

  void build_memory() {
    clip_sections();
    // Headers block, sized like Ghidra's: at least through the optional
    // header, at most the file, and never into the first section.
    std::uint64_t hdr = std::uint64_t{lfanew_} + 4 + 20 + (wide_ ? 240 : 224);
    hdr = std::max<std::uint64_t>(hdr, size_of_headers_);
    hdr = std::min<std::uint64_t>(hdr, r_.size());
    for (const RawSection &s : raw_)
      if (s.virtual_address != 0) hdr = std::min<std::uint64_t>(hdr, s.virtual_address);
    if (hdr != 0) {
      Region r{base_, hdr, 0, hdr, {true, false, false}};
      add_region(r, "headers");
      img_.blocks.push_back({"Headers", base_, hdr, r.perms, true});
    }

    for (std::size_t i = 0; i < raw_.size(); ++i) {
      const RawSection &s = raw_[i];
      const Section &sec = img_.sections[i];
      if (sec.size == 0) {
        warn("PE: section " + s.name + " has size zero");
        continue;
      }
      Region r;
      r.start = sec.addr;
      r.size = sec.size;
      r.perms = sec.perms;
      if (s.raw_ptr != 0 && s.raw_size != 0) {
        r.file_offset = s.raw_ptr;
        r.file_size = std::min<std::uint64_t>(s.raw_size, sec.size);
        if (!r_.has(r.file_offset, r.file_size)) {
          warn("PE: section " + s.name + " data is truncated by end of file");
          r.file_size = r.file_offset < r_.size() ? r_.size() - r.file_offset : 0;
        }
      }
      add_region(r, "section " + s.name);
      img_.blocks.push_back({s.name, r.start, r.size, r.perms, r.file_size != 0});
    }
  }

  // File offset for an RVA, if the RVA is backed by file bytes.
  std::optional<std::uint64_t> rva_to_offset(std::uint64_t rva) const {
    if (rva < size_of_headers_ && rva < r_.size()) return rva;
    for (const RawSection &s : raw_) {
      std::uint64_t vsize = std::max(s.virtual_size, s.raw_size);
      if (rva < s.virtual_address || rva - s.virtual_address >= vsize) continue;
      std::uint64_t delta = rva - s.virtual_address;
      if (delta >= s.raw_size || s.raw_ptr == 0) return std::nullopt;
      std::uint64_t off = std::uint64_t{s.raw_ptr} + delta;
      if (off >= r_.size()) return std::nullopt;
      return off;
    }
    return std::nullopt;
  }

  std::uint64_t offset_of(std::uint64_t rva, std::string_view what) const {
    auto off = rva_to_offset(rva);
    if (!off) fail(std::string(what) + ": RVA " + hex(rva) + " is not backed by the file");
    return *off;
  }

  std::uint32_t u32_at(std::uint64_t rva, std::string_view what) const {
    return r_.u32(offset_of(rva, what), what);
  }
  std::uint16_t u16_at(std::uint64_t rva, std::string_view what) const {
    return r_.u16(offset_of(rva, what), what);
  }
  std::string string_at(std::uint64_t rva, std::string_view what) const {
    return r_.cstring(offset_of(rva, what), kMaxNameLength, what);
  }

  bool executable_va(std::uint64_t addr) const {
    const Region *r = img_.memory.find(addr);
    return r != nullptr && r->perms.exec;
  }

  void read_exports() {
    const DataDir &d = dirs_[kDirExport];
    if (d.rva == 0 || d.size == 0) return;
    std::uint64_t dir = d.rva;
    std::uint32_t ordinal_base = u32_at(dir + 16, "export directory");
    std::uint64_t nfuncs = u32_at(dir + 20, "export directory");
    std::uint64_t nnames = u32_at(dir + 24, "export directory");
    std::uint64_t funcs = u32_at(dir + 28, "export directory");
    std::uint64_t names = u32_at(dir + 32, "export directory");
    std::uint64_t ordinals = u32_at(dir + 36, "export directory");
    if (std::uint32_t dll = u32_at(dir + 12, "export directory"); dll != 0) img_.soname = string_at(dll, "export DLL name");
    if (nfuncs > kMaxExports || nnames > kMaxExports) fail("absurd export count " + std::to_string(nfuncs));

    std::multimap<std::uint64_t, std::string> names_by_index;
    std::vector<Export> exports;
    std::uint64_t name_bytes = 0;
    for (std::uint64_t i = 0; i < nnames; ++i) {
      std::uint32_t name_rva = u32_at(names + 4 * i, "export name table");
      std::uint16_t index = u16_at(ordinals + 2 * i, "export ordinal table");
      if (index >= nfuncs) {
        warn("PE: export name " + std::to_string(i) + " has out-of-range ordinal index");
        continue;
      }
      std::string name = string_at(name_rva, "export name");
      name_bytes += name.size();
      if (name_bytes > kMaxNameBytes) {
        warn("PE: export names over " + std::to_string(kMaxNameBytes >> 20) + " MiB; the rest are unnamed");
        break;
      }
      names_by_index.emplace(index, std::move(name));
    }

    for (std::uint64_t i = 0; i < nfuncs; ++i) {
      std::uint32_t rva = u32_at(funcs + 4 * i, "export address table");
      if (rva == 0) continue;
      Export e;
      e.ordinal = static_cast<std::uint32_t>(ordinal_base + i);
      if (rva >= d.rva && rva - d.rva < d.size) e.forwarder = string_at(rva, "export forwarder");
      else e.address = va(rva);

      auto [lo, hi] = names_by_index.equal_range(i);
      if (lo == hi) {
        exports.push_back(e);
      } else {
        for (auto it = lo; it != hi; ++it) {
          Export named = e;
          named.name = it->second;
          exports.push_back(std::move(named));
        }
      }
    }

    // Commit only a fully read table.
    img_.exports = std::move(exports);
    for (const Export &e : img_.exports) {
      if (!e.forwarder.empty()) continue;
      Symbol s;
      s.name = e.name.empty() ? "Ordinal_" + std::to_string(e.ordinal) : e.name;
      s.value = e.address;
      s.type = executable_va(e.address) ? SymbolType::func : SymbolType::object;
      s.bind = SymbolBind::global;
      s.source = SymbolSource::pe_export;
      s.defined = true;
      img_.symbols.push_back(std::move(s));
    }
  }

  void read_imports() {
    const DataDir &d = dirs_[kDirImport];
    if (d.rva == 0) return;
    const std::uint64_t psize = wide_ ? 8 : 4;
    const std::uint64_t ord_flag = wide_ ? (1ULL << 63) : (1ULL << 31);
    std::uint64_t name_bytes = 0;
    for (std::uint64_t i = 0; i < kMaxImportDescriptors; ++i) {
      std::uint64_t desc = std::uint64_t{d.rva} + i * 20;
      std::uint32_t ilt = u32_at(desc, "import descriptor");
      std::uint32_t name_rva = u32_at(desc + 12, "import descriptor");
      std::uint32_t iat = u32_at(desc + 16, "import descriptor");
      if (name_rva == 0 && iat == 0) return;
      std::string library = string_at(name_rva, "import library name");
      if (!library.empty() && std::find(img_.needed.begin(), img_.needed.end(), library) == img_.needed.end() && img_.needed.size() < 4096)
        img_.needed.push_back(library);
      std::uint64_t thunks = ilt != 0 ? ilt : iat;
      for (std::uint64_t j = 0; j < kMaxThunks; ++j) {
        std::uint64_t rva = thunks + j * psize;
        std::uint64_t value = r_.word(offset_of(rva, "import thunk"), wide_, "import thunk");
        if (value == 0) break;
        Import imp;
        imp.library = library;
        imp.iat_address = va(std::uint64_t{iat} + j * psize);
        if ((value & ord_flag) != 0) imp.ordinal = static_cast<std::uint16_t>(value & 0xffff);
        else imp.name = string_at((value & 0x7fffffff) + 2, "import name");
        name_bytes += imp.library.size() + imp.name.size();
        if (img_.imports.size() >= kMaxImports || name_bytes > kMaxNameBytes) {
          warn("PE: over " + std::to_string(kMaxImports) + " imports or " + std::to_string(kMaxNameBytes >> 20) +
               " MiB of their names; truncated");
          return;
        }
        img_.imports.push_back(std::move(imp));
      }
    }
    warn("PE: import directory has too many descriptors; truncated");
  }

  void read_debug() {
    const DataDir &d = dirs_[kDirDebug];
    if (d.rva == 0 || d.size == 0) return;
    std::uint64_t n = std::min<std::uint64_t>(d.size / 28, kMaxDebugEntries);
    for (std::uint64_t i = 0; i < n; ++i) {
      std::uint64_t entry = std::uint64_t{d.rva} + i * 28;
      if (u32_at(entry + 12, "debug entry") != kDebugTypeCodeView) continue;
      std::uint32_t size = u32_at(entry + 16, "debug entry");
      std::uint32_t rva = u32_at(entry + 20, "debug entry");
      std::uint32_t ptr = u32_at(entry + 24, "debug entry");
      std::uint64_t off = ptr != 0 ? ptr : offset_of(rva, "CodeView record");
      std::uint32_t sig = r_.u32(off, "CodeView record");
      std::uint64_t path_off = 0;
      if (sig == 0x53445352) path_off = 24;       // "RSDS": GUID + age
      else if (sig == 0x3031424e) path_off = 16;  // "NB10": offset, time, age
      else continue;
      if (size <= path_off) continue;
      CodeViewRecord cv;
      cv.rsds = sig == 0x53445352;
      if (cv.rsds) {
        auto guid = r_.bytes(checked_add(off, 4, "CodeView record"), 16, "CodeView GUID");
        for (std::size_t k = 0; k < 16; ++k) cv.guid[k] = static_cast<std::uint8_t>(guid[k]);
        cv.age = r_.u32(checked_add(off, 20, "CodeView record"), "CodeView age");
      } else {
        cv.signature = r_.u32(checked_add(off, 8, "CodeView record"), "CodeView signature");
        cv.age = r_.u32(checked_add(off, 12, "CodeView record"), "CodeView age");
      }
      std::uint64_t max = std::min<std::uint64_t>(size - path_off, kMaxNameLength);
      cv.pdb_path = r_.cstring(checked_add(off, path_off, "CodeView record"), max, "PDB path");
      img_.pdb_path = cv.pdb_path;
      img_.codeview = std::move(cv);
      return;
    }
  }

  // x64 and ARM64 images describe every non-leaf function in .pdata.
  void read_pdata() {
    const DataDir &d = dirs_[kDirException];
    if (d.rva == 0 || d.size == 0) return;
    std::vector<FunctionRange> out;
    if (img_.machine == kMachineAmd64) {
      std::uint64_t n = std::min<std::uint64_t>(d.size / 12, kMaxPdataEntries);
      for (std::uint64_t i = 0; i < n; ++i) {
        std::uint64_t e = std::uint64_t{d.rva} + i * 12;
        std::uint32_t begin = u32_at(e, "RUNTIME_FUNCTION");
        std::uint32_t end = u32_at(e + 4, "RUNTIME_FUNCTION");
        if (begin == 0 && end == 0) break;
        // A chained entry (UNWIND_INFO flags UNW_FLAG_CHAININFO) describes a
        // fragment of the function another entry starts (MSVC's
        // shrink-wrapped and separated code), not a function.
        std::uint32_t unwind = u32_at(e + 8, "RUNTIME_FUNCTION");
        if (unwind & 1) continue;  // its unwind data is another RUNTIME_FUNCTION: chained too
        if (unwind != 0) {
          try {
            if (((u32_at(unwind, "UNWIND_INFO") & 0xff) >> 3) & 4) continue;
          } catch (const LoadError &) {
          }
        }
        if (end > begin) out.push_back({va(begin), va(end)});
      }
    } else if (img_.machine == kMachineArm64) {
      std::uint64_t n = std::min<std::uint64_t>(d.size / 8, kMaxPdataEntries);
      for (std::uint64_t i = 0; i < n; ++i) {
        std::uint64_t e = std::uint64_t{d.rva} + i * 8;
        std::uint32_t begin = u32_at(e, "ARM64 RUNTIME_FUNCTION");
        std::uint32_t unwind = u32_at(e + 4, "ARM64 RUNTIME_FUNCTION");
        if (begin == 0 && unwind == 0) break;
        std::uint64_t length = 0;
        if ((unwind & 3) != 0) length = std::uint64_t{(unwind >> 2) & 0x7ff} * 4;  // packed
        else length = std::uint64_t{u32_at(unwind, "ARM64 .xdata") & 0x3ffff} * 4;
        if (length != 0) out.push_back({va(begin), va(begin) + length});
      }
    } else {
      return;
    }
    std::sort(out.begin(), out.end(), [](const FunctionRange &a, const FunctionRange &b) {
      return a.start != b.start ? a.start < b.start : a.end < b.end;
    });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const FunctionRange &a, const FunctionRange &b) { return a.start == b.start; }),
              out.end());
    img_.function_ranges = std::move(out);
  }

  // A .NET assembly: the CLR header (ECMA-335 II.25.3.3) and the metadata
  // root's version string and stream names (II.24.2.1, II.24.2.2).
  void read_clr() {
    const DataDir &d = dirs_[kDirClr];
    if (d.rva == 0 || d.size == 0) return;
    const std::uint32_t cb = u32_at(d.rva, "CLR header");
    if (cb < 72) fail("its size is " + std::to_string(cb) + " bytes, under 72");
    DotNetInfo n;
    n.runtime_major = u16_at(d.rva + 4, "CLR header");
    n.runtime_minor = u16_at(d.rva + 6, "CLR header");
    n.metadata_rva = u32_at(d.rva + 8, "CLR header");
    n.metadata_size = u32_at(d.rva + 12, "CLR header");
    n.flags = u32_at(d.rva + 16, "CLR header");
    n.entry_point = u32_at(d.rva + 20, "CLR header");
    n.resources_rva = u32_at(d.rva + 24, "CLR header");
    n.resources_size = u32_at(d.rva + 28, "CLR header");
    n.il_only = (n.flags & 0x1) != 0;
    n.requires_32bit = (n.flags & 0x2) != 0;
    n.strong_name_signed = (n.flags & 0x8) != 0;
    n.native_entry_point = (n.flags & 0x10) != 0;
    n.prefers_32bit = (n.flags & 0x20000) != 0;
    if (const std::uint32_t mnh = u32_at(d.rva + 64, "CLR header"); mnh != 0) {
      try {
        n.ready_to_run = u32_at(mnh, "ReadyToRun header") == 0x00525452;  // "RTR"
      } catch (const LoadError &) {
      }
    }
    img_.dotnet = n;
    if (n.metadata_rva == 0) return;
    DotNetInfo &out = *img_.dotnet;
    const std::uint64_t root = offset_of(n.metadata_rva, "metadata root");
    if (r_.u32(root, "metadata root") != 0x424a5342) {  // "BSJB"
      warn("PE: CLR header: the metadata root has no BSJB signature");
      return;
    }
    const std::uint32_t vlen = r_.u32(checked_add(root, 12, "metadata root"), "metadata root");
    if (vlen > 255) fail("the metadata version string is " + std::to_string(vlen) + " bytes long");
    const std::uint64_t vstart = checked_add(root, 16, "metadata root");
    if (vlen) {
      auto v = r_.bytes(vstart, vlen, "metadata version");
      for (std::byte b : v) {
        if (b == std::byte{0}) break;
        out.metadata_version.push_back(static_cast<char>(b));
      }
    }
    for (char &c : out.metadata_version)
      if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7e) c = '?';
    const std::uint64_t after = checked_add(vstart, (vlen + 3) & ~3u, "metadata root");
    const std::uint16_t nstreams = r_.u16(checked_add(after, 2, "metadata root"), "metadata root");
    std::uint64_t at = checked_add(after, 4, "metadata root");
    for (std::uint16_t i = 0; i < std::min<std::uint16_t>(nstreams, 16); ++i) {
      const std::uint64_t name_at = checked_add(at, 8, "metadata stream header");
      const std::string name = r_.cstring(name_at, 32, "metadata stream name");
      out.streams.push_back(readable(name));
      at = checked_add(name_at, (name.size() + 1 + 3) & ~std::size_t{3}, "metadata stream header");
    }
  }

  std::shared_ptr<const Bytes> file_;
  Reader r_;
  LoadOptions options_;
  Image img_;

  bool wide_ = false;
  std::uint32_t lfanew_ = 0;
  std::uint64_t opt_ = 0;
  std::uint64_t sections_off_ = 0;
  std::uint16_t nsections_ = 0;
  std::uint32_t symtab_ptr_ = 0;
  std::uint32_t nsymbols_ = 0;
  std::uint32_t entry_rva_ = 0;
  std::uint32_t size_of_headers_ = 0;
  std::uint64_t base_ = 0;
  std::array<DataDir, 16> dirs_{};
  std::vector<RawSection> raw_;
};

}  // namespace

Image parse_pe(std::shared_ptr<const Bytes> file, const LoadOptions &options) {
  if (!file) detail::fail("PE: no input");
  return PeParser(std::move(file), options).run();
}

}  // namespace revkit::loader
