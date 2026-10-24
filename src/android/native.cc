// What the native libraries of an APK say about themselves: the ELF
// header, the dynamic symbols they export (through the section headers, or
// through PT_DYNAMIC and its hash tables when the sections are stripped),
// DT_NEEDED and DT_SONAME, the GNU build ID; and for Flutter, the Dart
// snapshot headers at libapp.so's _kDart*SnapshotData symbols and the
// engine's labelled version strings. From the ELF specification and Dart's
// runtime/vm/snapshot.h (the header: magic, length, kind, the 32-character
// version hash, the feature string). Written for revkit; what to report
// for Flutter follows rea's docs/flutter-analysis.md.
#include "reader.hh"

#include <algorithm>
#include <cstring>
#include <set>

namespace revkit::android {

using detail::Reader;

namespace {

struct Load {
  std::uint64_t vaddr, offset, filesz;
};

struct Elf {
  Reader r;
  bool is64;
  std::vector<Load> loads;
  std::optional<std::uint64_t> offset_of(std::uint64_t vaddr, std::uint64_t n = 1) const {
    for (const Load &l : loads)
      if (vaddr >= l.vaddr && vaddr - l.vaddr < l.filesz && n <= l.filesz - (vaddr - l.vaddr)) return l.offset + (vaddr - l.vaddr);
    return std::nullopt;
  }
};

std::string machine_name(std::uint16_t m, bool is64, std::string &abi) {
  switch (m) {
    case 3: abi = "x86"; return "x86";
    case 8: abi = is64 ? "mips64" : "mips"; return "MIPS";
    case 40: abi = "armeabi-v7a"; return "ARM";
    case 62: abi = "x86_64"; return "x86-64";
    case 183: abi = "arm64-v8a"; return "AArch64";
    case 243: abi = is64 ? "riscv64" : "riscv32"; return "RISC-V";
    default: abi.clear(); return "machine " + std::to_string(m);
  }
}

void notes(const Reader &r, std::uint64_t off, std::uint64_t size, std::string &build_id) {
  std::uint64_t p = off, end = off + size;
  while (p + 12 <= end && r.fits(p, 12)) {
    const std::uint32_t namesz = r.u32(p), descsz = r.u32(p + 4), type = r.u32(p + 8);
    const std::uint64_t name = p + 12, desc = name + ((static_cast<std::uint64_t>(namesz) + 3) & ~3ull);
    const std::uint64_t next = desc + ((static_cast<std::uint64_t>(descsz) + 3) & ~3ull);
    if (next > end || !r.fits(desc, descsz)) return;
    if (type == 3 && namesz == 4 && r.fits(name, 4) && std::memcmp(r.bytes().data() + name, "GNU", 4) == 0 && descsz > 0 &&
        descsz <= 64 && build_id.empty())
      build_id = detail::hex_bytes(r.sub(desc, descsz, "a build ID"));
    p = next;
  }
}

}  // namespace

ElfInfo parse_elf(Bytes data, const ElfLimits &limits) {
  if (data.size() < 52 || std::memcmp(data.data(), "\x7f" "ELF", 4) != 0) throw Error("not an ELF file");
  ElfInfo info;
  const std::uint8_t cls = static_cast<std::uint8_t>(data[4]), enc = static_cast<std::uint8_t>(data[5]);
  if ((cls != 1 && cls != 2) || (enc != 1 && enc != 2)) throw Error("an ELF file of an unknown class or byte order");
  info.is64 = cls == 2;
  info.big_endian = enc == 2;
  Elf e{Reader(data, info.big_endian), info.is64, {}};
  const Reader &r = e.r;
  info.type = r.u16(16);
  info.machine = r.u16(18);
  info.machine_name = machine_name(info.machine, info.is64, info.abi);
  const std::uint64_t phoff = info.is64 ? r.u64(32) : r.u32(28), shoff = info.is64 ? r.u64(40) : r.u32(32);
  const std::uint16_t phent = r.u16(info.is64 ? 54 : 42), phnum = r.u16(info.is64 ? 56 : 44),
                      shent = r.u16(info.is64 ? 58 : 46), shnum = r.u16(info.is64 ? 60 : 48);
  std::optional<std::uint64_t> dyn_off, dyn_size;
  if (phnum != 0 && phent >= (info.is64 ? 56 : 32) && r.fits(phoff, static_cast<std::uint64_t>(phnum) * phent)) {
    for (std::uint16_t i = 0; i < phnum; ++i) {
      const std::uint64_t p = phoff + static_cast<std::uint64_t>(i) * phent;
      const std::uint32_t type = r.u32(p);
      const std::uint64_t off = info.is64 ? r.u64(p + 8) : r.u32(p + 4), vaddr = info.is64 ? r.u64(p + 16) : r.u32(p + 8),
                          filesz = info.is64 ? r.u64(p + 32) : r.u32(p + 16);
      if (type == 1 && r.fits(off, filesz)) e.loads.push_back({vaddr, off, filesz});
      if (type == 2 && r.fits(off, filesz)) dyn_off = off, dyn_size = filesz;
      if (type == 4 && r.fits(off, filesz)) notes(r, off, filesz, info.build_id);
    }
  } else if (phnum != 0) {
    info.warnings.push_back("the program headers lie outside the file");
  }
  // Sections: the dynamic symbol table and its strings, notes.
  struct Section {
    std::uint32_t type, link;
    std::uint64_t offset, size, entsize;
  };
  std::vector<Section> sections;
  if (shoff != 0 && shnum != 0 && shent >= (info.is64 ? 64 : 40) && r.fits(shoff, static_cast<std::uint64_t>(shnum) * shent)) {
    for (std::uint16_t i = 0; i < shnum; ++i) {
      const std::uint64_t s = shoff + static_cast<std::uint64_t>(i) * shent;
      Section sec{r.u32(s + 4), r.u32(s + (info.is64 ? 40 : 24)), info.is64 ? r.u64(s + 24) : r.u32(s + 16),
                  info.is64 ? r.u64(s + 32) : r.u32(s + 20), info.is64 ? r.u64(s + 56) : r.u32(s + 36)};
      sections.push_back(sec);
      if (sec.type == 7 && info.build_id.empty() && r.fits(sec.offset, sec.size)) notes(r, sec.offset, sec.size, info.build_id);
    }
  }
  std::optional<std::uint64_t> symtab, strtab, strsz, count;
  std::uint64_t syment = info.is64 ? 24 : 16;
  for (const Section &s : sections)
    if (s.type == 11 && s.link < sections.size() && r.fits(s.offset, s.size)) {
      symtab = s.offset;
      if (s.entsize >= syment) syment = s.entsize;
      count = s.size / syment;
      strtab = sections[s.link].offset;
      strsz = sections[s.link].size;
      break;
    }
  // PT_DYNAMIC: the needed libraries and soname, and the symbols when no
  // section names them.
  std::vector<std::uint64_t> needed;
  std::optional<std::uint64_t> soname, dt_strtab, dt_strsz, dt_symtab, dt_hash, dt_gnu_hash;
  if (dyn_off) {
    const std::uint64_t w = info.is64 ? 16 : 8;
    for (std::uint64_t p = *dyn_off; p + w <= *dyn_off + *dyn_size; p += w) {
      const std::uint64_t tag = info.is64 ? r.u64(p) : r.u32(p), val = info.is64 ? r.u64(p + 8) : r.u32(p + 4);
      if (tag == 0) break;
      if (tag == 1 && needed.size() < 256) needed.push_back(val);
      else if (tag == 14) soname = val;
      else if (tag == 5) dt_strtab = val;
      else if (tag == 10) dt_strsz = val;
      else if (tag == 6) dt_symtab = val;
      else if (tag == 11 && val >= syment && val <= 64) syment = val;
      else if (tag == 4) dt_hash = val;
      else if (tag == 0x6ffffef5) dt_gnu_hash = val;
    }
  }
  std::optional<std::uint64_t> dyn_str = dt_strtab ? e.offset_of(*dt_strtab) : std::nullopt;
  std::uint64_t dyn_strsz = dt_strsz.value_or(0);
  if (dyn_str && (!r.fits(*dyn_str, dyn_strsz) || dyn_strsz == 0)) dyn_strsz = r.size() - *dyn_str;
  auto dyn_string = [&](std::uint64_t off) {
    std::string s;
    if (dyn_str && off < dyn_strsz) r.cstr(*dyn_str + off, std::min<std::uint64_t>(4096, dyn_strsz - off), s);
    return detail::clean_utf8(s);
  };
  for (std::uint64_t n : needed) info.needed.push_back(dyn_string(n));
  if (soname) info.soname = dyn_string(*soname);
  if (!symtab && dt_symtab) {
    symtab = e.offset_of(*dt_symtab);
    strtab = dyn_str;
    strsz = dyn_strsz;
    if (dt_hash)
      if (auto h = e.offset_of(*dt_hash, 8)) count = r.u32(*h + 4);
    if (!count && dt_gnu_hash)
      if (auto g = e.offset_of(*dt_gnu_hash, 16)) {
        const std::uint32_t nb = r.u32(*g), symoff = r.u32(*g + 4), bloom = r.u32(*g + 8);
        const std::uint64_t buckets = *g + 16 + static_cast<std::uint64_t>(bloom) * (info.is64 ? 8 : 4);
        if (nb < (1u << 24) && r.fits(buckets, 4ull * nb)) {
          std::uint32_t last = 0;
          for (std::uint32_t b = 0; b < nb; ++b) last = std::max(last, r.u32(buckets + 4ull * b));
          if (last < symoff) {
            count = symoff;
          } else {
            const std::uint64_t chain = buckets + 4ull * nb;
            for (std::uint64_t i = last; i - symoff < limits.max_symbols; ++i) {
              const std::uint64_t at = chain + 4 * (i - symoff);
              if (!r.fits(at, 4)) break;
              if (r.u32(at) & 1) {
                count = i + 1;
                break;
              }
            }
          }
        }
      }
    if (!count && symtab) info.warnings.push_back("no hash table says how many dynamic symbols there are");
  }
  if (symtab && count && strtab) {
    const std::uint64_t n = std::min<std::uint64_t>(*count, limits.max_symbols);
    if (*count > limits.max_symbols) info.warnings.push_back("more than " + std::to_string(limits.max_symbols) + " dynamic symbols; the rest are left out");
    for (std::uint64_t i = 1; i < n; ++i) {
      const std::uint64_t s = *symtab + i * syment;
      if (!r.fits(s, info.is64 ? 24 : 16)) {
        info.warnings.push_back("the dynamic symbol table runs past the file");
        break;
      }
      const std::uint32_t name = r.u32(s);
      const std::uint8_t st_info = r.u8(s + (info.is64 ? 4 : 12)), other = r.u8(s + (info.is64 ? 5 : 13));
      const std::uint16_t shndx = r.u16(s + (info.is64 ? 6 : 14));
      const std::uint64_t value = info.is64 ? r.u64(s + 8) : r.u32(s + 4), size = info.is64 ? r.u64(s + 16) : r.u32(s + 8);
      const unsigned bind = st_info >> 4, type = st_info & 15;
      if (shndx == 0 || (bind != 1 && bind != 2 && bind != 10) || (other & 3) == 1 || (other & 3) == 2) continue;
      if (type == 3 || type == 4) continue;  // sections and files
      ElfSymbol sym;
      if (name < strsz.value_or(0)) {
        std::string t;
        r.cstr(*strtab + name, std::min<std::uint64_t>(4096, *strsz - name), t);
        sym.name = detail::clean_utf8(t);
      }
      if (sym.name.empty()) continue;
      sym.value = value;
      sym.size = size;
      sym.type = static_cast<std::uint8_t>(type);
      sym.file_offset = e.offset_of(value);
      info.exports.push_back(std::move(sym));
    }
  }
  return info;
}

FlutterApp read_flutter_app(Bytes libapp) {
  FlutterApp app;
  const ElfInfo elf = parse_elf(libapp);
  app.warnings = elf.warnings;
  const Reader r(libapp, elf.big_endian);
  static const char *names[] = {"_kDartVmSnapshotData", "_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotData",
                                "_kDartIsolateSnapshotInstructions"};
  std::set<std::string> hashes;
  std::string vm_hash, isolate_hash;
  for (const char *n : names)
    for (const ElfSymbol &s : elf.exports) {
      if (s.name != n) continue;
      DartSnapshot snap;
      snap.symbol = n;
      snap.size = s.size;
      if (!s.file_offset) {
        app.warnings.push_back(std::string(n) + " isn't in the file's loaded bytes");
        app.snapshots.push_back(std::move(snap));
        break;
      }
      snap.file_offset = *s.file_offset;
      const bool data = std::string_view(n).ends_with("Data");
      if (data && r.fits(snap.file_offset, 52) && r.u32(snap.file_offset) == 0xdcdcf5f5u) {
        snap.header = true;
        snap.length = r.u64(snap.file_offset + 4);
        snap.kind = r.u64(snap.file_offset + 12);
        static const char *kinds[] = {"full", "full-core", "full-jit", "full-aot"};
        snap.kind_name = snap.kind < 4 ? kinds[snap.kind] : "kind " + std::to_string(snap.kind);
        const Bytes h = r.sub(snap.file_offset + 20, 32, "a snapshot hash");
        std::string hash(reinterpret_cast<const char *>(h.data()), 32);
        if (std::all_of(hash.begin(), hash.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })) {
          snap.hash = hash;
          hashes.insert(hash);
          (std::string_view(n).starts_with("_kDartVm") ? vm_hash : isolate_hash) = hash;
        } else {
          app.warnings.push_back(std::string(n) + "'s header has no version hash");
        }
        std::string features;
        if (r.cstr(snap.file_offset + 52, 1024, features)) snap.features = detail::clean_utf8(features);
        if (app.features.empty()) app.features = snap.features;
        if (s.size != 0 && snap.length + 4 > s.size)
          app.warnings.push_back(std::string(n) + "'s header says " + std::to_string(snap.length) + " bytes; the symbol is " +
                                 std::to_string(s.size));
      } else if (data) {
        app.warnings.push_back(std::string(n) + " doesn't start with the snapshot magic f5f5dcdc");
      }
      app.snapshots.push_back(std::move(snap));
      break;
    }
  app.hash_candidates.assign(hashes.begin(), hashes.end());
  if (hashes.size() == 1) app.snapshot_hash = *hashes.begin();
  else if (hashes.size() > 1) app.warnings.push_back("the VM's and the isolate's snapshot hashes differ");
  if (app.snapshots.empty()) app.warnings.push_back("no _kDart*Snapshot* symbols are exported");
  else if (vm_hash.empty() || isolate_hash.empty()) app.warnings.push_back("only one of the VM and isolate snapshot headers was read");
  return app;
}

FlutterEngine read_flutter_engine(Bytes lib) {
  FlutterEngine engine;
  engine.build_id = parse_elf(lib).build_id;
  // Printable runs: "Dart VM version: ..." and the toolchain's
  // "Android (...) clang version ..." lines.
  const auto *p = reinterpret_cast<const unsigned char *>(lib.data());
  std::size_t start = 0;
  for (std::size_t i = 0; i <= lib.size(); ++i) {
    const bool printable = i < lib.size() && p[i] >= 0x20 && p[i] < 0x7f;
    if (printable) continue;
    const std::size_t n = i - start;
    if (n >= 16 && n <= 600) {
      const std::string_view s(reinterpret_cast<const char *>(p + start), n);
      if (s.starts_with("Dart VM version:") && engine.dart_version.empty() && n <= 216)
        engine.dart_version = std::string(s.substr(16).starts_with(" ") ? s.substr(17) : s.substr(16));
      else if (s.starts_with("Android (") && s.find(") clang version ") != std::string_view::npos && engine.toolchain.size() < 4 &&
               std::find(engine.toolchain.begin(), engine.toolchain.end(), s) == engine.toolchain.end())
        engine.toolchain.emplace_back(s);
    }
    start = i + 1;
  }
  return engine;
}

}  // namespace revkit::android
