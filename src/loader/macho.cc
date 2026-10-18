// Mach-O parser: thin 32/64-bit files of either byte order and universal
// (fat) files' slices (docs/macho.md).
//
// Policy mirrors the ELF and PE parsers: the header and the load commands
// must be well formed or we throw; everything the load commands point at
// (symbols, the export trie, dyld's bind and rebase opcodes, chained
// fixups, function starts) is best effort, with a warning when unreadable.
// Memory blocks follow Ghidra's MachoProgramBuilder: a block per segment
// (its file bytes, then the rest of its vmsize uninitialized), split into
// a block per section.

#include "revkit/loader/load.hh"

#include "reader.hh"

#include <algorithm>
#include <array>
#include <cstdio>
#include <map>
#include <set>

namespace revkit::loader {

namespace {

using detail::checked_add;
using detail::fail;
using detail::hex;
using detail::Reader;

constexpr std::uint32_t kMhMagic = 0xfeedface;
constexpr std::uint32_t kMhMagic64 = 0xfeedfacf;
constexpr std::uint32_t kMhCigam = 0xcefaedfe;
constexpr std::uint32_t kMhCigam64 = 0xcffaedfe;
constexpr std::uint32_t kFatMagic = 0xcafebabe;
constexpr std::uint32_t kFatMagic64 = 0xcafebabf;

constexpr std::uint32_t kCpuArchAbi64 = 0x01000000;
constexpr std::uint32_t kCpuArchAbi64_32 = 0x02000000;
constexpr std::uint32_t kCpuX86 = 7;
constexpr std::uint32_t kCpuX86_64 = kCpuX86 | kCpuArchAbi64;
constexpr std::uint32_t kCpuArm = 12;
constexpr std::uint32_t kCpuArm64 = kCpuArm | kCpuArchAbi64;
constexpr std::uint32_t kCpuArm64_32 = kCpuArm | kCpuArchAbi64_32;
constexpr std::uint32_t kCpuPpc = 18;
constexpr std::uint32_t kCpuPpc64 = kCpuPpc | kCpuArchAbi64;
constexpr std::uint32_t kCpuSparc = 14;

constexpr std::uint32_t kMhObject = 1;
constexpr std::uint32_t kMhDylibStub = 9;

// Load commands.
constexpr std::uint32_t kLcReqDyld = 0x80000000;
constexpr std::uint32_t kLcSegment = 0x1;
constexpr std::uint32_t kLcSymtab = 0x2;
constexpr std::uint32_t kLcThread = 0x4;
constexpr std::uint32_t kLcUnixThread = 0x5;
constexpr std::uint32_t kLcDysymtab = 0xb;
constexpr std::uint32_t kLcLoadDylib = 0xc;
constexpr std::uint32_t kLcIdDylib = 0xd;
constexpr std::uint32_t kLcLoadDylinker = 0xe;
constexpr std::uint32_t kLcLoadWeakDylib = 0x18 | kLcReqDyld;
constexpr std::uint32_t kLcSegment64 = 0x19;
constexpr std::uint32_t kLcUuid = 0x1b;
constexpr std::uint32_t kLcRpath = 0x1c | kLcReqDyld;
constexpr std::uint32_t kLcCodeSignature = 0x1d;
constexpr std::uint32_t kLcReexportDylib = 0x1f | kLcReqDyld;
constexpr std::uint32_t kLcLazyLoadDylib = 0x20;
constexpr std::uint32_t kLcEncryptionInfo = 0x21;
constexpr std::uint32_t kLcDyldInfo = 0x22;
constexpr std::uint32_t kLcDyldInfoOnly = 0x22 | kLcReqDyld;
constexpr std::uint32_t kLcLoadUpwardDylib = 0x23 | kLcReqDyld;
constexpr std::uint32_t kLcVersionMinMacosx = 0x24;
constexpr std::uint32_t kLcVersionMinIphoneos = 0x25;
constexpr std::uint32_t kLcFunctionStarts = 0x26;
constexpr std::uint32_t kLcMain = 0x28 | kLcReqDyld;
constexpr std::uint32_t kLcDataInCode = 0x29;
constexpr std::uint32_t kLcSourceVersion = 0x2a;
constexpr std::uint32_t kLcEncryptionInfo64 = 0x2c;
constexpr std::uint32_t kLcVersionMinTvos = 0x2f;
constexpr std::uint32_t kLcVersionMinWatchos = 0x30;
constexpr std::uint32_t kLcBuildVersion = 0x32;
constexpr std::uint32_t kLcDyldExportsTrie = 0x33 | kLcReqDyld;
constexpr std::uint32_t kLcDyldChainedFixups = 0x34 | kLcReqDyld;

// Sections.
constexpr std::uint32_t kSectionType = 0xff;
constexpr std::uint32_t kSZerofill = 0x1;
constexpr std::uint32_t kSNonLazySymbolPointers = 0x6;
constexpr std::uint32_t kSLazySymbolPointers = 0x7;
constexpr std::uint32_t kSSymbolStubs = 0x8;
constexpr std::uint32_t kSGbZerofill = 0xc;
constexpr std::uint32_t kSLazyDylibSymbolPointers = 0x10;
constexpr std::uint32_t kSThreadLocalZerofill = 0x12;
constexpr std::uint32_t kSAttrPureInstructions = 0x80000000;
constexpr std::uint32_t kSAttrSomeInstructions = 0x00000400;
constexpr std::uint32_t kSgProtectedVersion1 = 0x8;

// nlist.
constexpr std::uint8_t kNStab = 0xe0;
constexpr std::uint8_t kNPext = 0x10;
constexpr std::uint8_t kNType = 0x0e;
constexpr std::uint8_t kNExt = 0x01;
constexpr std::uint8_t kNUndf = 0x0;
constexpr std::uint8_t kNSect = 0xe;
constexpr std::uint16_t kNWeakRef = 0x0040;
constexpr std::uint16_t kNWeakDef = 0x0080;
constexpr std::uint16_t kNArmThumbDef = 0x0008;

constexpr std::uint32_t kIndirectSymbolLocal = 0x80000000;
constexpr std::uint32_t kIndirectSymbolAbs = 0x40000000;

// Export trie flags.
constexpr std::uint64_t kExportKindMask = 0x03;
constexpr std::uint64_t kExportKindAbsolute = 0x02;
constexpr std::uint64_t kExportReexport = 0x08;
constexpr std::uint64_t kExportStubAndResolver = 0x10;

// Relocation types revkit gives Mach-O fixups (docs/macho.md).
constexpr std::uint32_t kRelocRebaseBase = 0x10;    // + REBASE_TYPE_*
constexpr std::uint32_t kRelocIndirect = 0x20;      // an indirect symbol table slot
constexpr std::uint32_t kRelocChainedBase = 0x8800;  // + DYLD_CHAINED_PTR_*

// Caps, so absurd counts in a small file stay cheap; real files are far
// below them.
constexpr std::uint64_t kMaxLoadCommands = 1 << 16;
constexpr std::uint64_t kMaxSections = 1 << 16;
constexpr std::uint64_t kMaxSymbols = 1 << 24;
constexpr std::uint64_t kMaxNameLength = 1 << 16;
constexpr std::uint64_t kMaxNameBytes = 256 << 20;
constexpr std::uint64_t kMaxFixups = 1 << 24;
constexpr std::uint64_t kMaxExports = 1 << 22;
constexpr std::uint64_t kMaxFunctionStarts = 1 << 22;
constexpr std::uint64_t kMaxSlices = 64;

std::string fixed_name(std::span<const std::byte> raw) {
  std::string s;
  for (std::byte b : raw) {
    if (b == std::byte{0}) break;
    char c = static_cast<char>(b);
    s.push_back(c < 0x20 || c > 0x7e ? '_' : c);
  }
  return s;
}

std::uint32_t be32(std::span<const std::byte> b, std::size_t at) {
  return std::to_integer<std::uint32_t>(b[at]) << 24 | std::to_integer<std::uint32_t>(b[at + 1]) << 16 |
         std::to_integer<std::uint32_t>(b[at + 2]) << 8 | std::to_integer<std::uint32_t>(b[at + 3]);
}

std::uint32_t le32(std::span<const std::byte> b, std::size_t at) {
  return std::to_integer<std::uint32_t>(b[at]) | std::to_integer<std::uint32_t>(b[at + 1]) << 8 |
         std::to_integer<std::uint32_t>(b[at + 2]) << 16 | std::to_integer<std::uint32_t>(b[at + 3]) << 24;
}

bool thin_magic(std::uint32_t m) { return m == kMhMagic || m == kMhMagic64 || m == kMhCigam || m == kMhCigam64; }

// "11.0", "13.2.1" from xxxx.yy.zz nibbles.
std::string version_text(std::uint32_t v) {
  char buf[32];
  const unsigned major = v >> 16, minor = (v >> 8) & 0xff, patch = v & 0xff;
  if (patch != 0) std::snprintf(buf, sizeof buf, "%u.%u.%u", major, minor, patch);
  else std::snprintf(buf, sizeof buf, "%u.%u", major, minor);
  return buf;
}

std::string platform_name(std::uint32_t p) {
  switch (p) {
    case 1: return "macos";
    case 2: return "ios";
    case 3: return "tvos";
    case 4: return "watchos";
    case 5: return "bridgeos";
    case 6: return "maccatalyst";
    case 7: return "iossimulator";
    case 8: return "tvossimulator";
    case 9: return "watchossimulator";
    case 10: return "driverkit";
    case 11: return "visionos";
    case 12: return "visionossimulator";
    default: return "platform " + std::to_string(p);
  }
}

// One parsed segment and its sections, before memory is laid out.
struct RawSection {
  std::string name;
  std::string segment;
  std::uint64_t addr = 0;
  std::uint64_t size = 0;
  std::uint32_t offset = 0;
  std::uint32_t align = 0;
  std::uint32_t flags = 0;
  std::uint32_t reserved1 = 0;
  std::uint32_t reserved2 = 0;
};

// A block being laid out (Ghidra's split-on-section blocks).
struct Piece {
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  std::string name;
  Perms perms;
  bool initialized = true;
  std::uint64_t file_offset = 0;  // in the whole file
  std::uint64_t file_size = 0;

  std::uint64_t end() const { return start + size; }  // exclusive; no wrap (checked when made)
};

class MachoParser {
 public:
  MachoParser(std::shared_ptr<const Bytes> file, const LoadOptions &options)
      : file_(std::move(file)), r_(*file_, Endian::little), options_(options) {}

  Image run() {
    img_.format = Format::macho;
    img_.file = file_;
    img_.memory = Memory(file_);
    img_.macho.emplace();
    select_slice();
    read_header();
    read_load_commands();
    layout_memory();
    best_effort("symbol table", [&] { read_symbols(); });
    best_effort("export trie", [&] { read_exports(); });
    best_effort("function starts", [&] { read_function_starts(); });
    best_effort("data in code", [&] { read_data_in_code(); });
    best_effort("dyld info", [&] { read_dyld_info(); });
    best_effort("chained fixups", [&] { read_chained_fixups(); });
    best_effort("indirect symbols", [&] { read_indirect_symbols(); });
    finish();
    return std::move(img_);
  }

 private:
  void warn(std::string msg) { img_.warnings.push_back(std::move(msg)); }

  template <class F>
  void best_effort(const char *what, F &&f) {
    try {
      f();
    } catch (const LoadError &e) {
      warn(std::string("Mach-O: ") + what + ": " + e.what());
    }
  }

  MachoInfo &info() { return *img_.macho; }
  const MachoInfo &info() const { return *img_.macho; }

  // ---- slices and header ----

  void select_slice() {
    r_.require(0, 4, "Mach-O header");
    const std::uint32_t be = be32(*file_, 0);
    if (be != kFatMagic && be != kFatMagic64) {
      slice_off_ = 0;
      slice_size_ = r_.size();
      return;
    }
    std::vector<MachoSlice> slices = macho_slices(*file_);
    if (slices.empty()) fail("Mach-O: universal header has no readable slices");
    std::size_t pick = macho_default_slice(slices);
    const std::string &want = options_.macho_slice;
    if (!want.empty()) {
      pick = slices.size();
      if (want[0] == '#') {
        std::size_t n = 0;
        bool ok = want.size() > 1;
        for (std::size_t i = 1; i < want.size() && ok; ++i) {
          ok = want[i] >= '0' && want[i] <= '9' && n < 1000;
          n = n * 10 + static_cast<std::size_t>(want[i] - '0');
        }
        if (ok && n < slices.size()) pick = n;
      } else {
        for (std::size_t i = 0; i < slices.size() && pick == slices.size(); ++i)
          if (slices[i].arch == want) pick = i;
      }
      if (pick == slices.size()) {
        std::string have;
        for (const MachoSlice &s : slices) have += (have.empty() ? "" : ", ") + s.arch;
        fail("Mach-O: no slice " + want + " in the universal file (it has " + have + ")");
      }
    }
    info().slices = slices;
    info().slice = pick;
    slice_off_ = slices[pick].offset;
    slice_size_ = slices[pick].size;
  }

  // A file offset in the slice, made absolute; throws past the slice.
  std::uint64_t at(std::uint64_t off, std::uint64_t len, std::string_view what) const {
    if (off > slice_size_ || len > slice_size_ - off)
      fail(std::string(what) + " out of bounds (offset " + hex(off) + ", size " + hex(len) + ", slice size " +
           hex(slice_size_) + ")");
    return slice_off_ + off;
  }

  void read_header() {
    const std::uint64_t h = at(0, 28, "Mach-O header");
    const std::uint32_t magic = le32(*file_, static_cast<std::size_t>(h));
    if (!thin_magic(magic)) fail("Mach-O: bad magic " + hex(magic));
    wide_ = magic == kMhMagic64 || magic == kMhCigam64;
    img_.endian = magic == kMhMagic || magic == kMhMagic64 ? Endian::little : Endian::big;
    r_.set_endian(img_.endian);
    img_.bits = wide_ ? 64 : 32;
    MachoInfo &m = info();
    m.slice_offset = slice_off_;
    m.cputype = r_.u32(h + 4);
    m.cpusubtype = r_.u32(h + 8);
    m.filetype = r_.u32(h + 12);
    ncmds_ = r_.u32(h + 16);
    sizeofcmds_ = r_.u32(h + 20);
    m.header_flags = r_.u32(h + 24);
    m.arch = macho_arch_name(m.cputype, m.cpusubtype);
    img_.machine = m.cputype;
    img_.flags = m.header_flags;
    // A 64-bit CPU type in a 32-bit header (or the reverse) is malformed,
    // except arm64_32 (ILP32 on a 64-bit CPU, 32-bit headers).
    if (m.cputype != kCpuArm64_32 && ((m.cputype & kCpuArchAbi64) != 0) != wide_ &&
        (m.cputype == kCpuX86_64 || m.cputype == kCpuArm64 || m.cputype == kCpuX86 || m.cputype == kCpuArm))
      fail("Mach-O: CPU type " + hex(m.cputype) + " doesn't match the header's word size");
    if (ncmds_ > kMaxLoadCommands) fail("Mach-O: absurd load command count " + std::to_string(ncmds_));
    cmds_ = (wide_ ? 32 : 28);
    at(cmds_, sizeofcmds_, "Mach-O load commands");
  }

  // ---- load commands ----

  std::uint32_t u32(std::uint64_t off, std::string_view what) const { return r_.u32(at(off, 4, what), what); }
  std::uint64_t u64(std::uint64_t off, std::string_view what) const { return r_.u64(at(off, 8, what), what); }
  std::uint64_t word(std::uint64_t off, std::string_view what) const {
    return wide_ ? u64(off, what) : u32(off, what);
  }
  std::string lc_string(std::uint64_t cmd, std::uint32_t cmdsize, std::uint64_t field, std::string_view what) const {
    const std::uint32_t off = u32(cmd + field, what);
    if (off >= cmdsize) fail(std::string(what) + ": string offset " + hex(off) + " is past the command");
    std::uint64_t max = cmdsize - off;
    return r_.cstring(at(cmd + off, max, what), max, what);
  }

  void read_load_commands() {
    MachoInfo &m = info();
    std::uint64_t off = cmds_;
    const std::uint64_t end = cmds_ + sizeofcmds_;
    std::uint64_t nsections = 0;
    std::optional<std::uint64_t> main_entry, thread_entry;
    for (std::uint32_t i = 0; i < ncmds_; ++i) {
      if (end - off < 8) fail("Mach-O: load command " + std::to_string(i) + " runs past sizeofcmds");
      const std::uint32_t cmd = u32(off, "load command");
      const std::uint32_t cmdsize = u32(off + 4, "load command");
      if (cmdsize < 8 || cmdsize > end - off)
        fail("Mach-O: load command " + std::to_string(i) + " has bad size " + hex(cmdsize));
      at(off, cmdsize, "load command");
      auto need = [&](std::uint32_t n, const char *what) {
        if (cmdsize < n) fail(std::string("Mach-O: ") + what + " command too small");
      };
      switch (cmd) {
        case kLcSegment:
        case kLcSegment64: {
          const bool w = cmd == kLcSegment64;
          const std::uint32_t hdr = w ? 72 : 56, sec = w ? 80 : 68;
          need(hdr, "segment");
          MachoSegment s;
          s.name = fixed_name(r_.bytes(at(off + 8, 16, "segment"), 16, "segment name"));
          auto field = [&](std::uint64_t o) { return w ? u64(off + o, "segment") : u32(off + o, "segment"); };
          s.vmaddr = field(24);
          s.vmsize = field(w ? 32 : 28);
          s.fileoff = field(w ? 40 : 32);
          s.filesize = field(w ? 48 : 36);
          const std::uint64_t p = off + (w ? 56 : 40);
          s.maxprot = u32(p, "segment");
          s.initprot = u32(p + 4, "segment");
          const std::uint32_t nsects = u32(p + 8, "segment");
          s.flags = u32(p + 12, "segment");
          if (nsects > (cmdsize - hdr) / sec) fail("Mach-O: segment " + s.name + " has more sections than fit");
          nsections += nsects;
          if (nsections > kMaxSections) fail("Mach-O: absurd section count");
          for (std::uint32_t k = 0; k < nsects; ++k) {
            const std::uint64_t so = off + hdr + std::uint64_t{k} * sec;
            RawSection rs;
            rs.name = fixed_name(r_.bytes(at(so, 16, "section"), 16, "section name"));
            rs.segment = fixed_name(r_.bytes(at(so + 16, 16, "section"), 16, "section name"));
            rs.addr = w ? u64(so + 32, "section") : u32(so + 32, "section");
            rs.size = w ? u64(so + 40, "section") : u32(so + 36, "section");
            const std::uint64_t q = so + (w ? 48 : 40);
            rs.offset = u32(q, "section");
            rs.align = u32(q + 4, "section");
            rs.flags = u32(q + 16, "section");
            rs.reserved1 = u32(q + 20, "section");
            rs.reserved2 = u32(q + 24, "section");
            sections_.push_back(std::move(rs));
          }
          m.segments.push_back(std::move(s));
          break;
        }
        case kLcSymtab:
          need(24, "symtab");
          symtab_ = {u32(off + 8, "symtab"), u32(off + 12, "symtab"), u32(off + 16, "symtab"), u32(off + 20, "symtab")};
          has_symtab_ = true;
          break;
        case kLcDysymtab:
          need(80, "dysymtab");
          indirect_off_ = u32(off + 56, "dysymtab");
          indirect_count_ = u32(off + 60, "dysymtab");
          break;
        case kLcLoadDylib:
        case kLcLoadWeakDylib:
        case kLcReexportDylib:
        case kLcLazyLoadDylib:
        case kLcLoadUpwardDylib: {
          need(24, "dylib");
          MachoDylib d;
          d.name = lc_string(off, cmdsize, 8, "dylib name");
          d.current_version = u32(off + 16, "dylib");
          d.compatibility_version = u32(off + 20, "dylib");
          d.kind = cmd == kLcLoadDylib       ? "load"
                   : cmd == kLcLoadWeakDylib ? "weak"
                   : cmd == kLcReexportDylib ? "reexport"
                   : cmd == kLcLazyLoadDylib ? "lazy"
                                             : "upward";
          if (m.dylibs.size() < 4096) {
            if (std::find(img_.needed.begin(), img_.needed.end(), d.name) == img_.needed.end())
              img_.needed.push_back(d.name);
            m.dylibs.push_back(std::move(d));
          }
          break;
        }
        case kLcIdDylib:
          need(24, "dylib id");
          m.install_name = lc_string(off, cmdsize, 8, "dylib id");
          img_.soname = m.install_name;
          break;
        case kLcLoadDylinker:
          need(12, "dylinker");
          m.dylinker = lc_string(off, cmdsize, 8, "dylinker name");
          break;
        case kLcRpath:
          need(12, "rpath");
          if (m.rpaths.size() < 256) {
            m.rpaths.push_back(lc_string(off, cmdsize, 8, "rpath"));
            img_.runpath.push_back(m.rpaths.back());
          }
          break;
        case kLcUuid: {
          need(24, "uuid");
          auto b = r_.bytes(at(off + 8, 16, "uuid"), 16, "uuid");
          static constexpr char digits[] = "0123456789ABCDEF", lower[] = "0123456789abcdef";
          m.uuid.clear();
          img_.build_id.clear();
          for (std::size_t k = 0; k < 16; ++k) {
            const unsigned v = std::to_integer<unsigned>(b[k]);
            if (k == 4 || k == 6 || k == 8 || k == 10) m.uuid.push_back('-');
            m.uuid.push_back(digits[v >> 4]);
            m.uuid.push_back(digits[v & 15]);
            img_.build_id.push_back(lower[v >> 4]);
            img_.build_id.push_back(lower[v & 15]);
          }
          break;
        }
        case kLcBuildVersion:
          need(24, "build version");
          m.platform = platform_name(u32(off + 8, "build version"));
          m.min_os = version_text(u32(off + 12, "build version"));
          m.sdk = version_text(u32(off + 16, "build version"));
          has_build_version_ = true;
          break;
        case kLcVersionMinMacosx:
        case kLcVersionMinIphoneos:
        case kLcVersionMinTvos:
        case kLcVersionMinWatchos:
          need(16, "version min");
          if (!has_build_version_) {
            m.platform = cmd == kLcVersionMinMacosx     ? "macos"
                         : cmd == kLcVersionMinIphoneos ? "ios"
                         : cmd == kLcVersionMinTvos     ? "tvos"
                                                        : "watchos";
            m.min_os = version_text(u32(off + 8, "version min"));
            m.sdk = version_text(u32(off + 12, "version min"));
          }
          break;
        case kLcSourceVersion: {
          need(16, "source version");
          const std::uint64_t v = u64(off + 8, "source version");
          // A.B.C.D.E packed as a24.b10.c10.d10.e10.
          char buf[96];
          std::snprintf(buf, sizeof buf, "%llu.%llu.%llu.%llu.%llu", static_cast<unsigned long long>(v >> 40),
                        static_cast<unsigned long long>((v >> 30) & 0x3ff), static_cast<unsigned long long>((v >> 20) & 0x3ff),
                        static_cast<unsigned long long>((v >> 10) & 0x3ff), static_cast<unsigned long long>(v & 0x3ff));
          std::string s = buf;
          while (s.size() > 2 && s.ends_with(".0")) s.resize(s.size() - 2);
          m.source_version = s;
          break;
        }
        case kLcCodeSignature:
          need(16, "code signature");
          m.code_signature = true;
          m.code_signature_offset = u32(off + 8, "code signature");
          m.code_signature_size = u32(off + 12, "code signature");
          break;
        case kLcEncryptionInfo:
        case kLcEncryptionInfo64:
          need(20, "encryption info");
          m.has_encryption_info = true;
          m.crypt_offset = u32(off + 8, "encryption info");
          m.crypt_size = u32(off + 12, "encryption info");
          m.cryptid = u32(off + 16, "encryption info");
          m.encrypted = m.encrypted || m.cryptid != 0;
          break;
        case kLcDyldInfo:
        case kLcDyldInfoOnly:
          need(48, "dyld info");
          m.dyld_info = true;
          for (unsigned k = 0; k < 10; ++k) dyld_info_[k] = u32(off + 8 + 4 * k, "dyld info");
          break;
        case kLcDyldExportsTrie:
          need(16, "exports trie");
          exports_trie_ = {u32(off + 8, "exports trie"), u32(off + 12, "exports trie")};
          break;
        case kLcDyldChainedFixups:
          need(16, "chained fixups");
          m.chained_fixups = true;
          chained_ = {u32(off + 8, "chained fixups"), u32(off + 12, "chained fixups")};
          break;
        case kLcFunctionStarts:
          need(16, "function starts");
          function_starts_ = {u32(off + 8, "function starts"), u32(off + 12, "function starts")};
          break;
        case kLcDataInCode:
          need(16, "data in code");
          data_in_code_ = {u32(off + 8, "data in code"), u32(off + 12, "data in code")};
          break;
        case kLcMain:
          need(24, "main");
          if (!main_entry) {
            const std::uint64_t e = u64(off + 8, "main");
            if (e != 0) main_entry = e;
          }
          break;
        case kLcUnixThread:
        case kLcThread:
          if (auto pc = thread_pc(off, cmdsize); pc && (!thread_entry || cmd == kLcUnixThread)) thread_entry = pc;
          break;
        default:
          break;
      }
      off += cmdsize;
    }
    if (main_entry) main_offset_ = main_entry;
    thread_entry_ = thread_entry;
  }

  // The initial PC of a thread command's first state (Ghidra's
  // ThreadCommand: one flavor per CPU type).
  std::optional<std::uint64_t> thread_pc(std::uint64_t cmd, std::uint32_t cmdsize) const {
    if (cmdsize < 16) return std::nullopt;
    const std::uint32_t flavor = u32(cmd + 8, "thread");
    const std::uint32_t count = u32(cmd + 12, "thread");  // 32-bit words
    const std::uint64_t state = cmd + 16;
    const std::uint64_t avail = (cmdsize - 16) / 4;
    auto word32 = [&](std::uint64_t index) -> std::optional<std::uint64_t> {
      if (index >= count || index >= avail) return std::nullopt;
      return u32(state + 4 * index, "thread state");
    };
    auto word64 = [&](std::uint64_t index) -> std::optional<std::uint64_t> {
      if (2 * index + 1 >= count || 2 * index + 1 >= avail) return std::nullopt;
      return u64(state + 8 * index, "thread state");
    };
    switch (info().cputype) {
      case kCpuX86: return flavor == 1 ? word32(10) : std::nullopt;            // eip
      case kCpuX86_64: return flavor == 4 ? word64(16) : std::nullopt;         // rip
      case kCpuArm: return flavor == 1 ? word32(15) : std::nullopt;            // pc
      case kCpuArm64:
      case kCpuArm64_32: return flavor == 6 ? word64(32) : std::nullopt;       // pc
      case kCpuPpc: return flavor == 1 ? word32(0) : std::nullopt;             // srr0
      case kCpuPpc64: return flavor == 5 ? word64(0) : std::nullopt;
      default: return std::nullopt;
    }
  }

  // ---- memory ----

  std::uint64_t slid(std::uint64_t vmaddr) const {
    const std::uint64_t a = vmaddr + slide_;
    return wide_ ? a : (a & 0xffffffffULL);
  }

  static Perms segment_perms(std::uint32_t prot) { return {(prot & 1) != 0, (prot & 2) != 0, (prot & 4) != 0}; }

  // Ghidra's Section.isWrite/isExecute (all sections are readable).
  static Perms section_perms(const RawSection &s) {
    Perms p;
    p.read = true;
    p.write = s.name.starts_with("__got") ||
              (s.segment != "__TEXT" && s.segment != "__TEXT_EXEC" && s.segment != "__PRELINK_TEXT" && s.name != "__const");
    p.exec = s.name == "__text" || s.segment == "__TEXT_EXEC" ||
             (s.flags & (kSAttrPureInstructions | kSAttrSomeInstructions)) != 0;
    // Objective-C's references and class data, read-only as Ghidra's
    // Objective-C analyzer makes them (ObjcUtils.setBlocksReadOnly), so a
    // message send's selector and a class reference fold to what they
    // point to; and the ivar offsets, so `self->ivar` reads as a field.
    static constexpr std::string_view kReadOnly[] = {"__objc_data",     "__objc_classrefs", "__objc_msgrefs",
                                                     "__objc_selrefs",  "__objc_superrefs", "__objc_protorefs",
                                                     "__objc_ivar"};
    for (std::string_view n : kReadOnly)
      if (s.name == n) p.write = false;
    return p;
  }

  static bool zerofill(std::uint32_t flags) {
    const std::uint32_t t = flags & kSectionType;
    return t == kSZerofill || t == kSGbZerofill || t == kSThreadLocalZerofill;
  }

  bool fits(std::uint64_t start, std::uint64_t size) const {
    if (size == 0) return false;
    const std::uint64_t top = wide_ ? ~std::uint64_t{0} : 0xffffffffULL;
    return start <= top && size - 1 <= top - start;
  }

  // Adds a piece where nothing is yet; false when it would overlap.
  bool add_piece(Piece p) {
    auto it = std::lower_bound(pieces_.begin(), pieces_.end(), p.start,
                               [](const Piece &a, std::uint64_t s) { return a.start < s; });
    if (it != pieces_.end() && it->start < p.end()) return false;
    if (it != pieces_.begin() && std::prev(it)->end() > p.start) return false;
    pieces_.insert(it, std::move(p));
    return true;
  }

  // Splits the piece containing `a` (if `a` is inside it, not at its start).
  void split_at(std::uint64_t a) {
    for (std::size_t i = 0; i < pieces_.size(); ++i) {
      Piece &p = pieces_[i];
      if (a <= p.start || a >= p.end()) continue;
      Piece right = p;
      const std::uint64_t off = a - p.start;
      right.start = a;
      right.size = p.size - off;
      if (p.file_size > off) {
        right.file_offset = p.file_offset + off;
        right.file_size = p.file_size - off;
      } else {
        right.file_size = 0;
      }
      p.size = off;
      p.file_size = std::min(p.file_size, off);
      pieces_.insert(pieces_.begin() + static_cast<std::ptrdiff_t>(i) + 1, std::move(right));
      return;
    }
  }

  void layout_memory() {
    MachoInfo &m = info();
    // The image base: the lowest segment with file bytes (Ghidra's
    // getMachoBaseAddress); the Mach-O header is there.
    std::optional<std::uint64_t> base;
    for (const MachoSegment &s : m.segments)
      if (s.filesize > 0 && (!base || s.vmaddr < *base)) base = s.vmaddr;
    file_base_ = base.value_or(0);
    if (options_.image_base) slide_ = *options_.image_base - file_base_;
    if (!wide_ && (options_.image_base.value_or(0) > 0xffffffffULL))
      fail("Mach-O: image base " + hex(*options_.image_base) + " does not fit a 32-bit image");
    img_.file_base = file_base_;
    img_.image_base = slid(file_base_);
    for (MachoSegment &s : m.segments) s.vmaddr = slid(s.vmaddr);

    if (m.filetype == kMhDylibStub) return;
    for (const MachoSegment &s : m.segments) {
      if (s.name == "__PAGEZERO") continue;
      if (s.vmsize == 0) {
        if (s.vmaddr != 0 && s.filesize > 0)
          warn("Mach-O: segment " + s.name + " has file bytes but no memory size (an overlay); not mapped");
        continue;
      }
      if (!fits(s.vmaddr, s.vmsize)) {
        warn("Mach-O: segment " + s.name + " at " + hex(s.vmaddr) + " wraps the address space; not mapped");
        continue;
      }
      if ((s.flags & kSgProtectedVersion1) != 0) m.encrypted = true;
      const Perms perms = segment_perms(s.initprot);
      std::uint64_t filesize = std::min(s.filesize, s.vmsize);
      std::uint64_t fileoff = 0;
      if (filesize > 0) {
        if (s.fileoff > slice_size_ || filesize > slice_size_ - s.fileoff) {
          warn("Mach-O: segment " + s.name + " data is truncated by end of file");
          filesize = s.fileoff < slice_size_ ? slice_size_ - s.fileoff : 0;
        }
        fileoff = slice_off_ + s.fileoff;
      }
      bool ok = true;
      if (filesize > 0) ok = add_piece({s.vmaddr, filesize, s.name, perms, true, fileoff, filesize});
      if (ok && s.vmsize > filesize)
        ok = add_piece({s.vmaddr + filesize, s.vmsize - filesize, s.name, perms, false, 0, 0});
      if (!ok) warn("Mach-O: segment " + s.name + " at " + hex(s.vmaddr) + " overlaps another; not mapped");
    }

    // Sections split their segments' blocks and name them.
    for (const RawSection &rs : sections_) {
      Section out;
      out.name = rs.name;
      out.segment = rs.segment;
      out.type = rs.flags & kSectionType;
      out.flags = rs.flags;
      out.addr = slid(rs.addr);
      out.size = rs.size;
      out.offset = rs.offset != 0 ? slice_off_ + rs.offset : 0;
      out.file_size = zerofill(rs.flags) || rs.offset == 0 ? 0 : rs.size;
      if (out.file_size != 0 && (rs.offset > slice_size_ || rs.size > slice_size_ - rs.offset)) {
        warn("Mach-O: section " + rs.segment + "," + rs.name + " data is truncated by end of file");
        out.file_size = rs.offset < slice_size_ ? slice_size_ - rs.offset : 0;
      }
      out.info = rs.reserved1;
      out.entsize = rs.reserved2;
      out.addralign = rs.align < 64 ? std::uint64_t{1} << rs.align : 0;
      out.alloc = true;
      out.perms = section_perms(rs);
      img_.sections.push_back(out);
      if (m.filetype == kMhDylibStub) continue;
      if (rs.size == 0 || (rs.offset == 0 && !zerofill(rs.flags))) continue;
      if (!fits(out.addr, rs.size)) {
        warn("Mach-O: section " + rs.segment + "," + rs.name + " wraps the address space");
        continue;
      }
      const std::uint64_t first = out.addr, last = out.addr + (rs.size - 1);
      bool any = false;
      for (const Piece &p : pieces_) any = any || (p.start <= last && first < p.end());
      if (!any) {
        // Outside every segment: a block of its own, as Ghidra makes one.
        Piece p{first, rs.size, rs.name, out.perms, out.file_size != 0, out.offset, out.file_size};
        if (!add_piece(std::move(p))) warn("Mach-O: section " + rs.name + " overlaps a segment");
        continue;
      }
      split_at(first);
      if (last + 1 != 0) split_at(last + 1);
      for (Piece &p : pieces_)
        if (p.start >= first && p.start <= last) {
          p.name = rs.name;
          p.perms = out.perms;
        }
    }

    for (const Piece &p : pieces_) {
      Region r{p.start, p.size, p.file_offset, p.file_size, p.perms};
      if (!p.initialized) r.file_offset = 0, r.file_size = 0;
      try {
        img_.memory.add(r);
      } catch (const LoadError &e) {
        warn(std::string("Mach-O: block ") + p.name + ": " + e.what());
        continue;
      }
      img_.blocks.push_back({p.name, p.start, p.size, p.perms, p.initialized});
    }

    // The entry point: LC_MAIN, else LC_UNIXTHREAD/LC_THREAD (Ghidra's
    // priority).
    if (main_offset_) {
      const MachoSegment *text = segment("__TEXT");
      if (text != nullptr) img_.entry = text->vmaddr + *main_offset_;
    }
    if (!img_.entry && thread_entry_) img_.entry = slid(*thread_entry_);
    if (img_.entry && !wide_) *img_.entry &= 0xffffffffULL;
  }

  const MachoSegment *segment(std::string_view name) const {
    for (const MachoSegment &s : img_.macho->segments)
      if (s.name == name) return &s;
    return nullptr;
  }

  // ---- linkedit reads ----

  // A LEB128 reader over a slice range.
  struct Leb {
    const Reader &r;
    std::uint64_t pos, end;
    bool done() const { return pos >= end; }
    std::uint8_t byte() {
      if (pos >= end) fail("truncated opcode stream");
      return r.u8(pos++);
    }
    std::uint64_t uleb() {
      std::uint64_t v = 0;
      for (unsigned shift = 0;; shift += 7) {
        const std::uint8_t b = byte();
        if (shift < 64) v |= std::uint64_t{b & 0x7fu} << shift;
        else if ((b & 0x7f) != 0) fail("ULEB128 overflows 64 bits");
        if ((b & 0x80) == 0) return v;
        if (shift > 70) fail("ULEB128 too long");
      }
    }
    std::int64_t sleb() {
      std::uint64_t v = 0;
      unsigned shift = 0;
      std::uint8_t b = 0;
      do {
        b = byte();
        if (shift < 64) v |= std::uint64_t{b & 0x7fu} << shift;
        shift += 7;
        if (shift > 70) fail("SLEB128 too long");
      } while ((b & 0x80) != 0);
      if (shift < 64 && (b & 0x40) != 0) v |= ~std::uint64_t{0} << shift;
      return static_cast<std::int64_t>(v);
    }
    std::string cstring() {
      std::string s;
      for (;;) {
        const std::uint8_t c = byte();
        if (c == 0) return s;
        if (s.size() >= kMaxNameLength) fail("name too long");
        s.push_back(static_cast<char>(c));
      }
    }
  };

  Leb leb(std::uint32_t off, std::uint32_t size, std::string_view what) const {
    const std::uint64_t a = at(off, size, what);
    return Leb{r_, a, a + size};
  }

  void read_symbols() {
    if (!has_symtab_) return;
    const auto [symoff, nsyms, stroff, strsize] = symtab_;
    if (nsyms > kMaxSymbols) fail("absurd symbol count " + std::to_string(nsyms));
    const std::uint64_t entsize = wide_ ? 16 : 12;
    const std::uint64_t table = at(symoff, std::uint64_t{nsyms} * entsize, "symbol table");
    const std::uint64_t strings = at(stroff, strsize, "string table");
    std::uint64_t name_bytes = 0;
    nlist_.reserve(nsyms);
    for (std::uint64_t i = 0; i < nsyms; ++i) {
      const std::uint64_t e = table + i * entsize;
      Nlist n;
      const std::uint32_t strx = r_.u32(e);
      n.type = r_.u8(e + 4);
      n.sect = r_.u8(e + 5);
      n.desc = r_.u16(e + 6);
      n.value = wide_ ? r_.u64(e + 8) : r_.u32(e + 8);
      if (strx != 0 && strx < strsize) {
        const std::uint64_t max = std::min<std::uint64_t>(strsize - strx, kMaxNameLength);
        try {
          n.name = r_.cstring(strings + strx, max, "symbol name");
        } catch (const LoadError &) {
          n.name.clear();
        }
      }
      name_bytes += n.name.size();
      if (name_bytes > kMaxNameBytes) {
        warn("Mach-O: symbol names over " + std::to_string(kMaxNameBytes >> 20) + " MiB; the rest are dropped");
        break;
      }
      nlist_.push_back(std::move(n));
    }

    for (const Nlist &n : nlist_) {
      if ((n.type & kNStab) != 0 || n.name.empty()) continue;
      const std::uint8_t t = n.type & kNType;
      Symbol s;
      s.name = n.name;
      s.source = SymbolSource::symtab;
      const bool ext = (n.type & kNExt) != 0;
      s.bind = ext && (n.type & kNPext) == 0 ? ((n.desc & (kNWeakDef | kNWeakRef)) != 0 ? SymbolBind::weak : SymbolBind::global)
                                             : SymbolBind::local;
      if (t == kNSect) {
        s.defined = true;
        s.value = slid(n.value);
        s.section_index = n.sect;  // 1-based, as nlist counts sections
        const bool code = in_code_section(s.value);
        s.type = code ? SymbolType::func : SymbolType::object;
        if (code && info().cputype == kCpuArm && (n.desc & kNArmThumbDef) != 0) s.value |= 1;
        img_.symbols.push_back(std::move(s));
      } else if (t == kNUndf && ext) {
        s.defined = false;
        if (n.value != 0) {
          s.type = SymbolType::common;  // a tentative definition, n_value its size
          s.size = n.value;
        }
        img_.symbols.push_back(std::move(s));
      }
      // N_ABS, N_INDR and N_PBUD symbols name nothing in memory.
    }
  }

  // Whether `a` is in a section of code: a function there, data elsewhere
  // (the header's part of __TEXT is executable, and __mh_execute_header
  // is no function).
  bool in_code_section(std::uint64_t a) const {
    for (const Section &sec : img_.sections)
      if (sec.perms.exec && a >= sec.addr && a - sec.addr < sec.size) return true;
    return false;
  }

  // The library a two-level-namespace ordinal names.
  std::string library(std::int64_t ordinal) const {
    const auto &d = img_.macho->dylibs;
    if (ordinal > 0 && static_cast<std::uint64_t>(ordinal) <= d.size()) return d[static_cast<std::size_t>(ordinal - 1)].name;
    return {};
  }

  void read_exports() {
    std::uint32_t off = exports_trie_.first, size = exports_trie_.second;
    if (size == 0 && info().dyld_info) off = dyld_info_[8], size = dyld_info_[9];
    if (size == 0) return;
    const std::uint64_t start = at(off, size, "export trie");
    const MachoSegment *text = segment("__TEXT");
    const std::uint64_t base = text != nullptr ? text->vmaddr : img_.image_base;
    std::vector<Export> out;
    std::set<std::uint64_t> visited;
    // Depth-first over (node offset, name so far).
    std::vector<std::pair<std::uint64_t, std::string>> stack{{0, {}}};
    while (!stack.empty()) {
      auto [node, prefix] = std::move(stack.back());
      stack.pop_back();
      if (node >= size || !visited.insert(node).second) continue;
      if (visited.size() > kMaxExports) fail("too many export trie nodes");
      Leb l{r_, start + node, start + size};
      const std::uint64_t terminal = l.uleb();
      const std::uint64_t children = l.pos + terminal;
      if (terminal != 0) {
        if (terminal > size) fail("export trie node runs past the trie");
        Leb t{r_, l.pos, std::min(children, start + size)};
        const std::uint64_t flags = t.uleb();
        Export e;
        e.name = prefix;
        if ((flags & kExportReexport) != 0) {
          const std::int64_t ordinal = static_cast<std::int64_t>(t.uleb());
          std::string imported = t.cstring();
          e.forwarder = library(ordinal) + ":" + (imported.empty() ? prefix : imported);
        } else {
          const std::uint64_t addr = t.uleb();
          e.address = (flags & kExportKindMask) == kExportKindAbsolute ? addr : base + addr;
          if (!wide_) e.address &= 0xffffffffULL;
          if ((flags & kExportStubAndResolver) != 0) (void)t.uleb();  // the resolver
        }
        out.push_back(std::move(e));
        if (out.size() > kMaxExports) fail("too many exports");
      }
      Leb c{r_, children, start + size};
      if (c.done()) continue;
      const std::uint8_t count = c.byte();
      for (unsigned k = 0; k < count; ++k) {
        std::string edge = c.cstring();
        const std::uint64_t child = c.uleb();
        if (prefix.size() + edge.size() > kMaxNameLength) fail("export name too long");
        stack.emplace_back(child, prefix + edge);
      }
    }
    std::sort(out.begin(), out.end(), [](const Export &a, const Export &b) { return a.name < b.name; });
    img_.exports = std::move(out);
    // Exports no symbol names (a stripped file keeps its trie).
    std::set<std::string> named;
    for (const Symbol &s : img_.symbols)
      if (s.defined) named.insert(s.name);
    for (const Export &e : img_.exports) {
      if (!e.forwarder.empty() || e.name.empty() || named.contains(e.name)) continue;
      Symbol s;
      s.name = e.name;
      s.value = e.address;
      s.type = in_code_section(e.address) ? SymbolType::func : SymbolType::object;
      s.bind = SymbolBind::global;
      s.source = SymbolSource::macho_export;
      s.defined = true;
      img_.symbols.push_back(std::move(s));
    }
  }

  void read_function_starts() {
    const auto [off, size] = function_starts_;
    if (size == 0) return;
    const MachoSegment *text = segment("__TEXT");
    std::uint64_t addr = text != nullptr ? text->vmaddr : img_.image_base;
    Leb l = leb(off, size, "function starts");
    std::vector<std::uint64_t> out;
    while (!l.done()) {
      const std::uint64_t delta = l.uleb();
      if (delta == 0) break;
      addr += delta;
      out.push_back(wide_ ? addr : addr & 0xffffffffULL);
      if (out.size() > kMaxFunctionStarts) fail("too many function starts");
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    info().function_starts = std::move(out);
  }

  void read_data_in_code() {
    const auto [off, size] = data_in_code_;
    if (size < 8) return;
    const std::uint64_t a = at(off, size, "data in code");
    for (std::uint64_t k = 0; k + 8 <= size && data_in_code_ranges_.size() < (1u << 20); k += 8) {
      const std::uint32_t o = r_.u32(a + k);
      const std::uint16_t len = r_.u16(a + k + 4);
      if (len == 0) continue;
      const std::uint64_t s = img_.image_base + o;
      data_in_code_ranges_.push_back({s, s + len});
    }
  }

  // ---- fixups ----

  // A bind's slot address from a segment index and offset.
  std::optional<std::uint64_t> seg_addr(std::uint64_t seg, std::uint64_t off) const {
    const auto &segs = img_.macho->segments;
    if (seg >= segs.size()) return std::nullopt;
    const std::uint64_t a = segs[seg].vmaddr + off;
    return wide_ ? a : a & 0xffffffffULL;
  }

  void add_fixup(Relocation r) {
    if (img_.relocations.size() >= kMaxFixups) fail("over " + std::to_string(kMaxFixups) + " fixups");
    img_.relocations.push_back(std::move(r));
  }

  void add_bind(std::uint64_t addr, std::uint32_t type, RelocationKind kind, const std::string &name,
                std::int64_t ordinal, std::int64_t addend) {
    Relocation r;
    r.address = addr;
    r.type = type;
    r.kind = kind;
    r.symbol = name;
    r.addend = addend;
    add_fixup(std::move(r));
    if (!name.empty()) {
      Import imp;
      imp.library = library(ordinal);
      imp.name = name;
      imp.iat_address = addr;
      img_.imports.push_back(std::move(imp));
    }
  }

  void add_rebase(std::uint64_t addr, std::uint32_t type, std::uint64_t target) {
    Relocation r;
    r.address = addr;
    r.type = type;
    r.kind = RelocationKind::relative;
    r.addend = static_cast<std::int64_t>(target);
    r.target = wide_ ? target : target & 0xffffffffULL;
    add_fixup(std::move(r));
  }

  void read_dyld_info() {
    if (!info().dyld_info) return;
    const std::uint32_t ptr = wide_ ? 8 : 4;
    // Rebases: the stored word is the link-time target; it moves by the slide.
    if (dyld_info_[1] != 0) {
      Leb l = leb(dyld_info_[0], dyld_info_[1], "rebase opcodes");
      std::uint64_t seg = 0, off = 0;
      std::uint32_t type = 1;
      bool have_seg = false;
      auto rebase = [&] {
        if (!have_seg) fail("rebase before a segment is set");
        auto a = seg_addr(seg, off);
        if (!a) fail("rebase in segment " + std::to_string(seg) + ", which doesn't exist");
        std::array<std::byte, 8> b{};
        const std::size_t n = img_.memory.read(*a, std::span<std::byte>(b.data(), ptr));
        std::uint64_t v = 0;
        for (unsigned i = 0; i < ptr; ++i)
          v |= std::uint64_t{std::to_integer<std::uint8_t>(b[img_.endian == Endian::little ? i : ptr - 1 - i])} << (8 * i);
        if (n == ptr) add_rebase(*a, kRelocRebaseBase + type, v + slide_);
        off += ptr;
      };
      while (!l.done()) {
        const std::uint8_t b = l.byte();
        const std::uint8_t op = b & 0xf0, imm = b & 0x0f;
        if (op == 0x00) break;  // DONE
        switch (op) {
          case 0x10: type = imm; break;
          case 0x20: seg = imm, off = l.uleb(), have_seg = true; break;
          case 0x30: off += l.uleb(); break;
          case 0x40: off += std::uint64_t{imm} * ptr; break;
          case 0x50: for (unsigned k = 0; k < imm; ++k) rebase(); break;
          case 0x60: {
            const std::uint64_t n = l.uleb();
            if (n > kMaxFixups) fail("absurd rebase count");
            for (std::uint64_t k = 0; k < n; ++k) rebase();
            break;
          }
          case 0x70: rebase(), off += l.uleb(); break;
          case 0x80: {
            const std::uint64_t n = l.uleb(), skip = l.uleb();
            if (n > kMaxFixups) fail("absurd rebase count");
            for (std::uint64_t k = 0; k < n; ++k) rebase(), off += skip;
            break;
          }
          default: fail("unknown rebase opcode " + hex(b));
        }
      }
    }
    read_binds(dyld_info_[2], dyld_info_[3], BindTable::normal);
    read_binds(dyld_info_[4], dyld_info_[5], BindTable::weak);
    read_binds(dyld_info_[6], dyld_info_[7], BindTable::lazy);
  }

  enum class BindTable { normal, weak, lazy };

  void read_binds(std::uint32_t offset, std::uint32_t size, BindTable table) {
    if (size == 0) return;
    const char *what = table == BindTable::normal ? "bind opcodes" : table == BindTable::weak ? "weak bind opcodes" : "lazy bind opcodes";
    Leb l = leb(offset, size, what);
    const std::uint32_t ptr = wide_ ? 8 : 4;
    std::uint64_t seg = 0, off = 0;
    bool have_seg = false;
    std::int64_t ordinal = 0, addend = 0;
    std::uint32_t type = 1;
    std::string name;
    bool non_weak = false;
    // Threaded binds (arm64e before chained fixups): an ordinal table the
    // DO_BINDs fill, then chains of ARM64E pointers.
    bool threaded = false;
    std::vector<std::pair<std::string, std::int64_t>> ordinals;  // symbol, library ordinal
    auto bind = [&] {
      if (!have_seg) fail("bind before a segment is set");
      if (threaded) {
        if (ordinals.size() >= kMaxFixups) fail("absurd threaded bind table");
        ordinals.emplace_back(name, ordinal);
        return;
      }
      auto a = seg_addr(seg, off);
      if (!a) fail("bind in segment " + std::to_string(seg) + ", which doesn't exist");
      off += ptr;
      if (table == BindTable::weak && non_weak) return;  // a strong definition, nothing to bind
      const RelocationKind kind = type != 1             ? RelocationKind::other
                                  : table == BindTable::lazy ? RelocationKind::jump_slot
                                                             : RelocationKind::glob_dat;
      add_bind(*a, type, kind, name, ordinal, addend);
    };
    while (!l.done()) {
      const std::uint8_t b = l.byte();
      const std::uint8_t op = b & 0xf0, imm = b & 0x0f;
      switch (op) {
        case 0x00:  // DONE: the lazy table's entries each end with one
          if (table != BindTable::lazy) return;
          break;
        case 0x10: ordinal = imm; break;
        case 0x20: ordinal = static_cast<std::int64_t>(l.uleb()); break;
        case 0x30: ordinal = imm == 0 ? 0 : static_cast<std::int8_t>(0xf0 | imm); break;
        case 0x40:
          name = l.cstring();
          non_weak = (imm & 0x8) != 0;
          break;
        case 0x50: type = imm; break;
        case 0x60: addend = l.sleb(); break;
        case 0x70: seg = imm, off = l.uleb(), have_seg = true; break;
        case 0x80: off += l.uleb(); break;
        case 0x90: bind(); break;
        case 0xa0: bind(), off += l.uleb(); break;
        case 0xb0: bind(), off += std::uint64_t{imm} * ptr; break;
        case 0xc0: {
          const std::uint64_t n = l.uleb(), skip = l.uleb();
          if (n > kMaxFixups) fail("absurd bind count");
          for (std::uint64_t k = 0; k < n; ++k) bind(), off += skip;
          break;
        }
        case 0xd0:  // THREADED
          if (imm == 0x00) {  // SET_BIND_ORDINAL_TABLE_SIZE_ULEB
            const std::uint64_t n = l.uleb();
            if (n > kMaxFixups) fail("absurd threaded bind table");
            ordinals.clear();
            ordinals.reserve(static_cast<std::size_t>(n));
            threaded = true;
          } else if (imm == 0x01) {  // APPLY: a chain starts at the current address
            if (!have_seg) fail("threaded apply before a segment is set");
            auto a = seg_addr(seg, off);
            if (!a) fail("threaded apply in a segment that doesn't exist");
            walk_chain(*a, 1 /* DYLD_CHAINED_PTR_ARM64E */, 0, &ordinals_view(ordinals));
          } else {
            fail("unknown threaded bind sub-opcode " + hex(imm));
          }
          break;
        default: fail("unknown bind opcode " + hex(b));
      }
    }
  }

  // Chained imports: (name, library ordinal, addend), by ordinal.
  struct ChainImport {
    std::string name;
    std::int64_t library = 0;
    std::int64_t addend = 0;
  };
  std::vector<ChainImport> threaded_imports_;
  const std::vector<ChainImport> &ordinals_view(const std::vector<std::pair<std::string, std::int64_t>> &o) {
    threaded_imports_.clear();
    for (const auto &[n, lib] : o) threaded_imports_.push_back({n, lib, 0});
    return threaded_imports_;
  }

  static unsigned chain_stride(std::uint32_t fmt) {
    switch (fmt) {
      case 1: case 9: case 12: case 13: return 8;
      case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 10: return 4;
      default: return 1;  // 11 (x86_64 kernel cache) and unknown
    }
  }
  static bool chain_32(std::uint32_t fmt) { return fmt == 3 || fmt == 4 || fmt == 5; }

  // One chain of fixups from `addr` (mach header relative pointer formats
  // per dyld's fixup-chains.h).
  void walk_chain(std::uint64_t addr, std::uint32_t fmt, std::uint32_t max_valid_pointer,
                  const std::vector<ChainImport> *imports) {
    const unsigned stride = chain_stride(fmt);
    const unsigned size = chain_32(fmt) ? 4 : 8;
    const std::uint32_t type = kRelocChainedBase + fmt;
    for (std::uint64_t steps = 0;; ++steps) {
      if (steps > (1u << 20)) fail("chain too long");
      std::array<std::byte, 8> b{};
      if (img_.memory.read(addr, std::span<std::byte>(b.data(), size)) != size)
        fail("chained fixup at " + hex(addr) + " is outside the image");
      std::uint64_t v = 0;
      for (unsigned i = 0; i < size; ++i)
        v |= std::uint64_t{std::to_integer<std::uint8_t>(b[img_.endian == Endian::little ? i : size - 1 - i])} << (8 * i);
      std::uint64_t next = 0;
      auto bind = [&](std::uint64_t ord, std::int64_t addend) {
        if (imports == nullptr || ord >= imports->size()) {
          warn("Mach-O: chained bind at " + hex(addr) + " names import " + std::to_string(ord) + ", which doesn't exist");
          return;
        }
        const ChainImport &ci = (*imports)[static_cast<std::size_t>(ord)];
        add_bind(addr, type, RelocationKind::glob_dat, ci.name, ci.library, ci.addend + addend);
      };
      switch (fmt) {
        case 1: case 7: case 9: case 12: {  // ARM64E variants
          const bool is_bind = (v >> 62) & 1, auth = (v >> 63) & 1;
          next = (v >> 51) & 0x7ff;
          if (is_bind) {
            const std::uint64_t ord = fmt == 12 ? (v & 0xffffff) : (v & 0xffff);
            std::int64_t addend = 0;
            if (!auth) {
              std::uint64_t a = (v >> 32) & 0x7ffff;
              if (a & 0x40000) a |= ~std::uint64_t{0x7ffff};
              addend = static_cast<std::int64_t>(a);
            }
            bind(ord, addend);
          } else if (auth) {
            add_rebase(addr, type, img_.image_base + (v & 0xffffffffULL));
          } else {
            std::uint64_t high8 = (v >> 43) & 0xff;
            const std::uint64_t target = v & 0x7ffffffffffULL;
            std::uint64_t t = (high8 << 56) | target;
            if (fmt == 1) t += slide_;  // vmaddr
            else t += img_.image_base;  // offset from the header
            add_rebase(addr, type, t);
          }
          break;
        }
        case 2: case 6: {  // 64, 64_OFFSET
          next = (v >> 51) & 0xfff;
          if ((v >> 63) & 1) {
            bind(v & 0xffffff, static_cast<std::int64_t>((v >> 24) & 0xff));
          } else {
            const std::uint64_t high8 = (v >> 36) & 0xff;
            std::uint64_t t = (high8 << 56) | (v & 0xfffffffffULL);
            t += fmt == 6 ? img_.image_base : slide_;
            add_rebase(addr, type, t);
          }
          break;
        }
        case 3: {  // 32
          next = (v >> 26) & 0x1f;
          if ((v >> 31) & 1) {
            bind(v & 0xfffff, static_cast<std::int64_t>((v >> 20) & 0x3f));
          } else {
            std::uint64_t t = v & 0x3ffffff;
            if (max_valid_pointer != 0 && t > max_valid_pointer) {
              // A non-pointer stored as a biased value; not slid.
              t -= (0x04000000 + std::uint64_t{max_valid_pointer}) / 2;
              add_rebase(addr, type, t);
            } else {
              add_rebase(addr, type, t + slide_);
            }
          }
          break;
        }
        case 4: next = (v >> 30) & 0x3, add_rebase(addr, type, (v & 0x3fffffff) + img_.image_base); break;
        case 5: next = (v >> 26) & 0x3f, add_rebase(addr, type, (v & 0x3ffffff) + slide_); break;
        case 8: case 11: next = (v >> 51) & 0xfff, add_rebase(addr, type, (v & 0x3fffffff) + img_.image_base); break;
        case 10: next = (v >> 51) & 0x7ff, add_rebase(addr, type, (v & 0x7ffffffffffULL) + slide_); break;
        case 13: next = (v >> 52) & 0x7ff, add_rebase(addr, type, (v & 0x3ffffffffULL) + img_.image_base); break;
        default: fail("unsupported chained pointer format " + std::to_string(fmt));
      }
      if (next == 0) return;
      addr += next * stride;
    }
  }

  void read_chained_fixups() {
    if (!info().chained_fixups) return;
    const auto [off, size] = chained_;
    if (size < 28) fail("header too small");
    const std::uint64_t h = at(off, size, "chained fixups");
    const std::uint32_t starts = r_.u32(h + 4), imports_off = r_.u32(h + 8), symbols_off = r_.u32(h + 12);
    const std::uint32_t imports_count = r_.u32(h + 16), imports_format = r_.u32(h + 20);
    const std::uint32_t symbols_format = r_.u32(h + 24);
    if (symbols_format != 0) fail("compressed symbol names (format " + std::to_string(symbols_format) + ") aren't supported");
    const std::uint32_t isize = imports_format == 1 ? 4 : imports_format == 2 ? 8 : imports_format == 3 ? 16 : 0;
    if (isize == 0) fail("unknown imports format " + std::to_string(imports_format));
    if (imports_off > size || std::uint64_t{imports_count} * isize > size - imports_off) fail("imports run past the fixups");
    if (symbols_off > size) fail("symbols start past the fixups");
    std::vector<ChainImport> imports;
    imports.reserve(imports_count);
    for (std::uint32_t i = 0; i < imports_count; ++i) {
      const std::uint64_t e = h + imports_off + std::uint64_t{i} * isize;
      ChainImport ci;
      std::uint64_t name_off = 0;
      if (imports_format == 3) {
        const std::uint64_t v = r_.u64(e);
        const std::uint64_t lib = v & 0xffff;
        ci.library = lib > 0xfff0 ? static_cast<std::int16_t>(lib) : static_cast<std::int64_t>(lib);
        name_off = v >> 32;
        ci.addend = static_cast<std::int64_t>(r_.u64(e + 8));
      } else {
        const std::uint32_t v = r_.u32(e);
        const std::uint32_t lib = v & 0xff;
        ci.library = lib > 0xf0 ? static_cast<std::int8_t>(lib) : static_cast<std::int64_t>(lib);
        name_off = v >> 9;
        if (imports_format == 2) ci.addend = static_cast<std::int32_t>(r_.u32(e + 4));
      }
      if (name_off < size - symbols_off)
        ci.name = r_.cstring(h + symbols_off + name_off, std::min<std::uint64_t>(size - symbols_off - name_off, kMaxNameLength),
                             "chained import name");
      imports.push_back(std::move(ci));
    }

    if (starts == 0) return;
    if (starts > size - 4) fail("starts run past the fixups");
    const std::uint64_t si = h + starts;
    const std::uint32_t seg_count = r_.u32(si);
    if (std::uint64_t{seg_count} * 4 > size - starts - 4) fail("segment table runs past the fixups");
    for (std::uint32_t s = 0; s < seg_count; ++s) {
      const std::uint32_t seg_off = r_.u32(si + 4 + 4 * std::uint64_t{s});
      if (seg_off == 0) continue;
      if (seg_off > size - starts || size - starts - seg_off < 22) fail("segment starts run past the fixups");
      const std::uint64_t ss = si + seg_off;
      const std::uint32_t ss_size = r_.u32(ss);
      const std::uint16_t page_size = r_.u16(ss + 4), fmt = r_.u16(ss + 6);
      const std::uint64_t segment_offset = r_.u64(ss + 8);
      const std::uint32_t max_valid = r_.u32(ss + 16);
      const std::uint16_t page_count = r_.u16(ss + 20);
      if (ss_size < 22 || ss_size > size - starts - seg_off || std::uint64_t{page_count} * 2 > ss_size - 22)
        fail("segment starts are malformed");
      if (info().chained_pointer_format == 0) info().chained_pointer_format = fmt;
      for (std::uint32_t p = 0; p < page_count; ++p) {
        const std::uint16_t start = r_.u16(ss + 22 + 2 * std::uint64_t{p});
        if (start == 0xffff) continue;  // DYLD_CHAINED_PTR_START_NONE
        const std::uint64_t page = img_.image_base + segment_offset + std::uint64_t{p} * page_size;
        auto walk = [&](std::uint64_t in_page) {
          try {
            walk_chain(page + in_page, fmt, max_valid, &imports);
          } catch (const LoadError &e) {
            warn(std::string("Mach-O: chained fixups: ") + e.what());
          }
        };
        if ((start & 0x8000) != 0 && chain_32(fmt)) {
          // DYLD_CHAINED_PTR_START_MULTI: an overflow list of starts.
          std::uint32_t idx = start & 0x7fff;
          for (unsigned k = 0; k < 64; ++k, ++idx) {
            if (std::uint64_t{idx} >= (ss_size - 22) / 2) break;
            const std::uint16_t o = r_.u16(ss + 22 + 2 * std::uint64_t{idx});
            walk(o & 0x7fff);
            if ((o & 0x8000) != 0) break;  // DYLD_CHAINED_PTR_START_LAST
          }
        } else {
          walk(start);
        }
      }
    }
  }

  // Pointer and stub sections' slots from the indirect symbol table, where
  // nothing above bound them (files without dyld info).
  void read_indirect_symbols() {
    if (indirect_count_ == 0) return;
    if (indirect_count_ > kMaxSymbols) fail("absurd indirect symbol count");
    const std::uint64_t table = at(indirect_off_, std::uint64_t{indirect_count_} * 4, "indirect symbol table");
    std::set<std::uint64_t> bound;
    for (const Relocation &r : img_.relocations)
      if (!r.symbol.empty()) bound.insert(r.address);
    const std::uint32_t ptr = wide_ ? 8 : 4;
    for (const Section &s : img_.sections) {
      const std::uint32_t t = s.type;
      const bool pointers = t == kSNonLazySymbolPointers || t == kSLazySymbolPointers || t == kSLazyDylibSymbolPointers;
      const bool stubs = t == kSSymbolStubs;
      if (!pointers && !stubs) continue;
      const std::uint64_t step = stubs ? s.entsize : ptr;
      if (step == 0 || s.size == 0) continue;
      if (stubs) {
        // The stubs, PLT-like: functions the indirect symbols name.
        img_.plt_sections.push_back({s.name, s.addr, s.size, 0, s.entsize});
      }
      const std::uint64_t n = s.size / step;
      for (std::uint64_t k = 0; k < n; ++k) {
        const std::uint64_t idx = std::uint64_t{s.info} + k;
        if (idx >= indirect_count_) break;
        const std::uint32_t sym = r_.u32(table + 4 * idx);
        if ((sym & (kIndirectSymbolLocal | kIndirectSymbolAbs)) != 0 || sym >= nlist_.size()) continue;
        const Nlist &nl = nlist_[sym];
        if (nl.name.empty()) continue;
        const std::uint64_t a = s.addr + k * step;
        if (stubs) {
          stub_names_.emplace(a, nl.name);
          continue;
        }
        if (bound.contains(a)) continue;
        Relocation r;
        r.address = a;
        r.type = kRelocIndirect;
        r.kind = t == kSNonLazySymbolPointers ? RelocationKind::glob_dat : RelocationKind::jump_slot;
        r.symbol = nl.name;
        add_fixup(std::move(r));
        Import imp;
        imp.library = library((nl.desc >> 8) & 0xff);
        imp.name = nl.name;
        imp.iat_address = a;
        img_.imports.push_back(std::move(imp));
      }
    }
  }

  void finish() {
    std::stable_sort(img_.relocations.begin(), img_.relocations.end(),
                     [](const Relocation &a, const Relocation &b) { return a.address < b.address; });
    std::stable_sort(img_.imports.begin(), img_.imports.end(),
                     [](const Import &a, const Import &b) { return a.iat_address < b.iat_address; });
    std::sort(img_.plt_sections.begin(), img_.plt_sections.end(),
              [](const PltSection &a, const PltSection &b) { return a.start < b.start; });
    std::sort(img_.blocks.begin(), img_.blocks.end(), [](const Block &a, const Block &b) { return a.start < b.start; });
    MachoInfo &m = info();
    m.data_in_code = std::move(data_in_code_ranges_);
    std::sort(m.data_in_code.begin(), m.data_in_code.end());
    m.stub_names = std::move(stub_names_);
    if (m.encrypted)
      warn("Mach-O: the file is encrypted (LC_ENCRYPTION_INFO cryptid " + std::to_string(m.cryptid) + ", file offset " +
           hex(m.crypt_offset) + ", size " + hex(m.crypt_size) + "); its code can't be read");
  }

  struct Nlist {
    std::string name;
    std::uint8_t type = 0;
    std::uint8_t sect = 0;
    std::uint16_t desc = 0;
    std::uint64_t value = 0;
  };

  std::shared_ptr<const Bytes> file_;
  Reader r_;
  LoadOptions options_;
  Image img_;

  std::uint64_t slice_off_ = 0;
  std::uint64_t slice_size_ = 0;
  bool wide_ = false;
  std::uint32_t ncmds_ = 0;
  std::uint32_t sizeofcmds_ = 0;
  std::uint64_t cmds_ = 0;
  std::uint64_t file_base_ = 0;
  std::uint64_t slide_ = 0;
  std::vector<RawSection> sections_;
  std::vector<Piece> pieces_;
  bool has_symtab_ = false;
  bool has_build_version_ = false;
  std::array<std::uint32_t, 4> symtab_{};
  std::uint32_t indirect_off_ = 0;
  std::uint32_t indirect_count_ = 0;
  std::array<std::uint32_t, 10> dyld_info_{};
  std::pair<std::uint32_t, std::uint32_t> exports_trie_{};
  std::pair<std::uint32_t, std::uint32_t> chained_{};
  std::pair<std::uint32_t, std::uint32_t> function_starts_{};
  std::pair<std::uint32_t, std::uint32_t> data_in_code_{};
  std::optional<std::uint64_t> main_offset_;
  std::optional<std::uint64_t> thread_entry_;
  std::vector<Nlist> nlist_;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> data_in_code_ranges_;
  std::map<std::uint64_t, std::string> stub_names_;
};

}  // namespace

std::string macho_arch_name(std::uint32_t cputype, std::uint32_t cpusubtype) {
  const std::uint32_t sub = cpusubtype & 0x00ffffff;
  switch (cputype) {
    case kCpuX86: return "i386";
    case kCpuX86_64: return sub == 8 ? "x86_64h" : "x86_64";
    case kCpuArm64: return sub == 2 ? "arm64e" : "arm64";
    case kCpuArm64_32: return "arm64_32";
    case kCpuArm:
      switch (sub) {
        case 5: return "armv4t";
        case 6: return "armv6";
        case 7: return "armv5";
        case 8: return "xscale";
        case 9: return "armv7";
        case 10: return "armv7f";
        case 11: return "armv7s";
        case 12: return "armv7k";
        case 13: return "armv8";
        case 14: return "armv6m";
        case 15: return "armv7m";
        case 16: return "armv7em";
        default: return "arm";
      }
    case kCpuPpc: return "ppc";
    case kCpuPpc64: return "ppc64";
    case kCpuSparc: return "sparc";
    default: return "cpu " + hex(cputype);
  }
}

bool is_macho(std::span<const std::byte> file) {
  if (file.size() < 8) return false;
  if (thin_magic(le32(file, 0))) return true;
  return !macho_slices(file).empty();
}

std::vector<MachoSlice> macho_slices(std::span<const std::byte> file) {
  std::vector<MachoSlice> out;
  if (file.size() < 8) return out;
  const std::uint32_t magic = be32(file, 0);
  if (magic != kFatMagic && magic != kFatMagic64) return out;
  const bool wide = magic == kFatMagic64;
  const std::uint32_t n = be32(file, 4);
  // Java class files share 0xcafebabe; their next word (a version, 45 or
  // more) is never a plausible slice count.
  if (n == 0 || n > kMaxSlices) return out;
  const std::uint64_t entry = wide ? 32 : 20;
  if (file.size() < 8 + n * entry) return out;
  for (std::uint32_t i = 0; i < n; ++i) {
    const std::size_t e = static_cast<std::size_t>(8 + i * entry);
    MachoSlice s;
    s.cputype = be32(file, e);
    s.cpusubtype = be32(file, e + 4);
    if (wide) {
      s.offset = std::uint64_t{be32(file, e + 8)} << 32 | be32(file, e + 12);
      s.size = std::uint64_t{be32(file, e + 16)} << 32 | be32(file, e + 20);
      s.align = be32(file, e + 24);
    } else {
      s.offset = be32(file, e + 8);
      s.size = be32(file, e + 12);
      s.align = be32(file, e + 16);
    }
    if (s.offset > file.size() || s.size > file.size() - s.offset || s.size < 28) return {};
    if (!thin_magic(le32(file, static_cast<std::size_t>(s.offset)))) return {};
    s.arch = macho_arch_name(s.cputype, s.cpusubtype);
    out.push_back(std::move(s));
  }
  return out;
}

std::size_t macho_default_slice(const std::vector<MachoSlice> &slices) {
  for (std::uint32_t want : {kCpuArm64, kCpuX86_64})
    for (std::size_t i = 0; i < slices.size(); ++i)
      if (slices[i].cputype == want) return i;
  return 0;
}

Image parse_macho(std::shared_ptr<const Bytes> file, const LoadOptions &options) {
  if (!file) detail::fail("Mach-O: no input");
  return MachoParser(std::move(file), options).run();
}

}  // namespace revkit::loader
