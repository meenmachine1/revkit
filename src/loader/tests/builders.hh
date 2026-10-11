// Synthetic ELF and PE images for tests: small, exact, and easy to corrupt.
#pragma once

#include "revkit/loader/image.hh"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <unistd.h>
#include <memory>
#include <string>
#include <vector>

namespace revkit::testing {

class ByteWriter {
 public:
  explicit ByteWriter(bool big = false) : big_(big) {}

  std::size_t size() const { return out_.size(); }
  void pad_to(std::size_t n) {
    if (out_.size() < n) out_.resize(n, 0);
  }
  void align(std::size_t a) { pad_to((out_.size() + a - 1) / a * a); }
  void put(std::uint64_t v, unsigned n) {
    for (unsigned i = 0; i < n; ++i) {
      unsigned shift = 8 * (big_ ? n - 1 - i : i);
      out_.push_back(static_cast<std::uint8_t>(v >> shift));
    }
  }
  void put_at(std::size_t off, std::uint64_t v, unsigned n) {
    pad_to(off + n);
    for (unsigned i = 0; i < n; ++i) {
      unsigned shift = 8 * (big_ ? n - 1 - i : i);
      out_[off + i] = static_cast<std::uint8_t>(v >> shift);
    }
  }
  void bytes(const std::vector<std::uint8_t> &b) { out_.insert(out_.end(), b.begin(), b.end()); }
  void bytes_at(std::size_t off, const std::vector<std::uint8_t> &b) {
    pad_to(off + b.size());
    std::copy(b.begin(), b.end(), out_.begin() + static_cast<std::ptrdiff_t>(off));
  }
  void str_at(std::size_t off, const std::string &s) {
    std::vector<std::uint8_t> b(s.begin(), s.end());
    b.push_back(0);
    bytes_at(off, b);
  }
  std::vector<std::uint8_t> &data() { return out_; }

 private:
  bool big_;
  std::vector<std::uint8_t> out_;
};

inline std::shared_ptr<const loader::Bytes> to_bytes(const std::vector<std::uint8_t> &v) {
  auto b = std::make_shared<loader::Bytes>(v.size());
  for (std::size_t i = 0; i < v.size(); ++i) (*b)[i] = std::byte{v[i]};
  return b;
}

struct ElfSpec {
  bool wide = true;
  bool big = false;
  std::uint16_t machine = 62;
  std::uint16_t type = 2;  // ET_EXEC
  std::uint32_t flags = 0;
  std::uint64_t entry = 0;
};

// Each add_load() creates one PT_LOAD segment holding one section.
class ElfBuilder {
 public:
  explicit ElfBuilder(ElfSpec spec) : spec_(spec) {}

  void add_load(const std::string &name, std::uint64_t vaddr, std::vector<std::uint8_t> data,
                std::uint32_t pflags, std::uint64_t mem_size = 0, bool nobits = false) {
    loads_.push_back({name, vaddr, std::move(data), pflags, mem_size, nobits});
  }

  // `section` is the 1-based index in add_load order (0 = undefined).
  void add_symbol(const std::string &name, std::uint64_t value, std::uint64_t size, std::uint8_t type,
                  std::uint8_t bind, std::uint16_t section) {
    syms_.push_back({name, value, size, type, bind, section});
  }

  std::vector<std::uint8_t> build() const {
    const bool w = spec_.wide;
    const unsigned ehsize = w ? 64 : 52, phent = w ? 56 : 32, shent = w ? 64 : 40, syment = w ? 24 : 16;
    ByteWriter b(spec_.big);
    const std::size_t phoff = ehsize;
    std::size_t off = phoff + loads_.size() * phent;

    // Section data.
    std::vector<std::size_t> data_off;
    for (const Load &l : loads_) {
      off = (off + 15) / 16 * 16;
      data_off.push_back(off);
      if (!l.nobits) {
        b.bytes_at(off, l.data);
        off += l.data.size();
      }
    }

    // String tables and symbols.
    std::string strtab(1, '\0');
    std::vector<std::size_t> sym_name;
    for (const Sym &s : syms_) {
      sym_name.push_back(strtab.size());
      strtab += s.name + '\0';
    }
    std::string shstrtab(1, '\0');
    std::vector<std::size_t> sec_name;
    std::vector<std::string> names;
    for (const Load &l : loads_) names.push_back(l.name);
    names.insert(names.end(), {".symtab", ".strtab", ".shstrtab"});
    for (const std::string &n : names) {
      sec_name.push_back(shstrtab.size());
      shstrtab += n + '\0';
    }

    off = (off + 7) / 8 * 8;
    const std::size_t symtab_off = off;
    ByteWriter syms(spec_.big);
    syms.pad_to(syment);  // null symbol
    for (std::size_t i = 0; i < syms_.size(); ++i) {
      const Sym &s = syms_[i];
      std::uint8_t info = static_cast<std::uint8_t>((s.bind << 4) | s.type);
      if (w) {
        syms.put(sym_name[i], 4);
        syms.put(info, 1);
        syms.put(0, 1);
        syms.put(s.section, 2);
        syms.put(s.value, 8);
        syms.put(s.size, 8);
      } else {
        syms.put(sym_name[i], 4);
        syms.put(s.value, 4);
        syms.put(s.size, 4);
        syms.put(info, 1);
        syms.put(0, 1);
        syms.put(s.section, 2);
      }
    }
    b.bytes_at(symtab_off, syms.data());
    const std::size_t strtab_off = symtab_off + syms.size();
    b.str_at(strtab_off, strtab.substr(0, strtab.size() - 1));
    const std::size_t shstrtab_off = strtab_off + strtab.size();
    b.str_at(shstrtab_off, shstrtab.substr(0, shstrtab.size() - 1));
    std::size_t shoff = (shstrtab_off + shstrtab.size() + 7) / 8 * 8;
    const std::size_t shnum = loads_.size() + 4;  // null + loads + symtab/strtab/shstrtab

    // ELF header.
    b.bytes_at(0, {0x7f, 'E', 'L', 'F', static_cast<std::uint8_t>(w ? 2 : 1),
                   static_cast<std::uint8_t>(spec_.big ? 2 : 1), 1});
    b.put_at(16, spec_.type, 2);
    b.put_at(18, spec_.machine, 2);
    b.put_at(20, 1, 4);
    if (w) {
      b.put_at(24, spec_.entry, 8);
      b.put_at(32, phoff, 8);
      b.put_at(40, shoff, 8);
      b.put_at(48, spec_.flags, 4);
      b.put_at(52, ehsize, 2);
      b.put_at(54, phent, 2);
      b.put_at(56, loads_.size(), 2);
      b.put_at(58, shent, 2);
      b.put_at(60, shnum, 2);
      b.put_at(62, shnum - 1, 2);
    } else {
      b.put_at(24, spec_.entry, 4);
      b.put_at(28, phoff, 4);
      b.put_at(32, shoff, 4);
      b.put_at(36, spec_.flags, 4);
      b.put_at(40, ehsize, 2);
      b.put_at(42, phent, 2);
      b.put_at(44, loads_.size(), 2);
      b.put_at(46, shent, 2);
      b.put_at(48, shnum, 2);
      b.put_at(50, shnum - 1, 2);
    }

    // Program headers.
    for (std::size_t i = 0; i < loads_.size(); ++i) {
      const Load &l = loads_[i];
      std::size_t p = phoff + i * phent;
      std::uint64_t filesz = l.nobits ? 0 : l.data.size();
      std::uint64_t memsz = l.mem_size != 0 ? l.mem_size : l.data.size();
      if (w) {
        b.put_at(p, 1, 4);
        b.put_at(p + 4, l.pflags, 4);
        b.put_at(p + 8, data_off[i], 8);
        b.put_at(p + 16, l.vaddr, 8);
        b.put_at(p + 24, l.vaddr, 8);
        b.put_at(p + 32, filesz, 8);
        b.put_at(p + 40, memsz, 8);
        b.put_at(p + 48, 16, 8);
      } else {
        b.put_at(p, 1, 4);
        b.put_at(p + 4, data_off[i], 4);
        b.put_at(p + 8, l.vaddr, 4);
        b.put_at(p + 12, l.vaddr, 4);
        b.put_at(p + 16, filesz, 4);
        b.put_at(p + 20, memsz, 4);
        b.put_at(p + 24, l.pflags, 4);
        b.put_at(p + 28, 16, 4);
      }
    }

    // Section headers.
    auto shdr = [&](std::size_t idx, std::size_t name, std::uint32_t type, std::uint64_t flags,
                    std::uint64_t addr, std::uint64_t offset, std::uint64_t size, std::uint32_t link,
                    std::uint32_t info, std::uint64_t entsize) {
      std::size_t s = shoff + idx * shent;
      b.put_at(s, name, 4);
      b.put_at(s + 4, type, 4);
      if (w) {
        b.put_at(s + 8, flags, 8);
        b.put_at(s + 16, addr, 8);
        b.put_at(s + 24, offset, 8);
        b.put_at(s + 32, size, 8);
        b.put_at(s + 40, link, 4);
        b.put_at(s + 44, info, 4);
        b.put_at(s + 48, 1, 8);
        b.put_at(s + 56, entsize, 8);
      } else {
        b.put_at(s + 8, flags, 4);
        b.put_at(s + 12, addr, 4);
        b.put_at(s + 16, offset, 4);
        b.put_at(s + 20, size, 4);
        b.put_at(s + 24, link, 4);
        b.put_at(s + 28, info, 4);
        b.put_at(s + 32, 1, 4);
        b.put_at(s + 36, entsize, 4);
      }
    };
    shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    for (std::size_t i = 0; i < loads_.size(); ++i) {
      const Load &l = loads_[i];
      std::uint64_t flags = 0x2;  // SHF_ALLOC
      if (l.pflags & 2) flags |= 0x1;
      if (l.pflags & 1) flags |= 0x4;
      std::uint64_t size = l.mem_size != 0 ? l.mem_size : l.data.size();
      shdr(i + 1, sec_name[i], l.nobits ? 8 : 1, flags, l.vaddr, data_off[i], size, 0, 0, 0);
    }
    const std::size_t n = loads_.size();
    shdr(n + 1, sec_name[n], 2, 0, 0, symtab_off, syms.size(), static_cast<std::uint32_t>(n + 2), 1, syment);
    shdr(n + 2, sec_name[n + 1], 3, 0, 0, strtab_off, strtab.size(), 0, 0, 0);
    shdr(n + 3, sec_name[n + 2], 3, 0, 0, shstrtab_off, shstrtab.size(), 0, 0, 0);
    b.pad_to(shoff + shnum * shent);
    return b.data();
  }

 private:
  struct Load {
    std::string name;
    std::uint64_t vaddr;
    std::vector<std::uint8_t> data;
    std::uint32_t pflags;
    std::uint64_t mem_size;
    bool nobits;
  };
  struct Sym {
    std::string name;
    std::uint64_t value, size;
    std::uint8_t type, bind;
    std::uint16_t section;
  };
  ElfSpec spec_;
  std::vector<Load> loads_;
  std::vector<Sym> syms_;
};

// A PE32+ AMD64 DLL: .text (code), .rdata (exports, imports, debug/RSDS),
// .pdata. Offsets of interesting fields are exposed for corruption tests.
struct PeImage {
  std::vector<std::uint8_t> bytes;
  std::size_t lfanew = 0x80;
  std::size_t opt = 0;           // optional header offset
  std::size_t section_table = 0;
  std::size_t export_dir_off = 0;  // file offset of the export directory
  std::size_t import_dir_off = 0;
};

inline PeImage build_pe(bool wide = true) {
  PeImage pe;
  ByteWriter b;
  const std::uint64_t base = wide ? 0x140000000ULL : 0x10000000ULL;
  // RVA -> file offset: .text 0x1000->0x400, .rdata 0x2000->0x600, .pdata 0x3000->0xa00.
  auto f = [](std::uint32_t rva) -> std::size_t {
    if (rva >= 0x3000) return rva - 0x3000 + 0xa00;
    if (rva >= 0x2000) return rva - 0x2000 + 0x600;
    return rva - 0x1000 + 0x400;
  };

  b.bytes_at(0, {'M', 'Z'});
  b.put_at(0x3c, pe.lfanew, 4);
  b.bytes_at(pe.lfanew, {'P', 'E', 0, 0});
  const std::size_t coff = pe.lfanew + 4;
  const unsigned opt_size = wide ? 240 : 224;
  b.put_at(coff, wide ? 0x8664 : 0x14c, 2);
  b.put_at(coff + 2, 3, 2);  // sections
  b.put_at(coff + 16, opt_size, 2);
  b.put_at(coff + 18, 0x2022, 2);  // executable, large-address-aware, DLL
  pe.opt = coff + 20;
  const std::size_t o = pe.opt;
  b.put_at(o, wide ? 0x20b : 0x10b, 2);
  b.put_at(o + 16, 0x1000, 4);  // entry
  if (wide) b.put_at(o + 24, base, 8);
  else b.put_at(o + 28, base, 4);
  b.put_at(o + 32, 0x1000, 4);  // section alignment
  b.put_at(o + 36, 0x200, 4);   // file alignment
  b.put_at(o + 56, 0x4000, 4);  // size of image
  b.put_at(o + 60, 0x400, 4);   // size of headers
  const std::size_t dirs = o + (wide ? 112 : 96);
  b.put_at(o + (wide ? 108 : 92), 16, 4);
  auto dir = [&](unsigned i, std::uint32_t rva, std::uint32_t size) {
    b.put_at(dirs + i * 8, rva, 4);
    b.put_at(dirs + i * 8 + 4, size, 4);
  };
  dir(0, 0x2000, 0x100);  // export
  dir(1, 0x2100, 0x28);   // import
  if (wide) dir(3, 0x3000, 24);  // exception (.pdata)
  dir(6, 0x2300, 28);     // debug

  pe.section_table = o + opt_size;
  auto section = [&](unsigned i, const char *name, std::uint32_t vsize, std::uint32_t rva, std::uint32_t rawsize,
                     std::uint32_t rawptr, std::uint32_t chars) {
    std::size_t s = pe.section_table + i * 40;
    b.str_at(s, name);
    b.put_at(s + 8, vsize, 4);
    b.put_at(s + 12, rva, 4);
    b.put_at(s + 16, rawsize, 4);
    b.put_at(s + 20, rawptr, 4);
    b.put_at(s + 36, chars, 4);
  };
  section(0, ".text", 0x20, 0x1000, 0x200, 0x400, 0x60000020);
  section(1, ".rdata", 0x400, 0x2000, 0x400, 0x600, 0x40000040);
  section(2, ".pdata", 0x18, 0x3000, 0x200, 0xa00, 0x40000040);

  // .text: f1 at 0x1000 "mov eax,1; ret", f2 at 0x1010 "xor eax,eax; ret".
  b.bytes_at(f(0x1000), {0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3});
  b.bytes_at(f(0x1010), {0x31, 0xc0, 0xc3});

  // Export directory at 0x2000: two functions, names "one" and "two".
  pe.export_dir_off = f(0x2000);
  const std::size_t e = pe.export_dir_off;
  b.put_at(e + 12, 0x2080, 4);  // dll name
  b.put_at(e + 16, 1, 4);       // ordinal base
  b.put_at(e + 20, 2, 4);       // functions
  b.put_at(e + 24, 2, 4);       // names
  b.put_at(e + 28, 0x2040, 4);
  b.put_at(e + 32, 0x2050, 4);
  b.put_at(e + 36, 0x2060, 4);
  b.put_at(f(0x2040), 0x1000, 4);
  b.put_at(f(0x2044), 0x1010, 4);
  b.put_at(f(0x2050), 0x2070, 4);
  b.put_at(f(0x2054), 0x2074, 4);
  b.put_at(f(0x2060), 0, 2);
  b.put_at(f(0x2062), 1, 2);
  b.str_at(f(0x2070), "one");
  b.str_at(f(0x2074), "two");
  b.str_at(f(0x2080), "test.dll");

  // Import directory at 0x2100: KERNEL32.dll!ExitProcess and ordinal 7.
  pe.import_dir_off = f(0x2100);
  const std::size_t im = pe.import_dir_off;
  b.put_at(im, 0x2140, 4);       // ILT
  b.put_at(im + 12, 0x2180, 4);  // name
  b.put_at(im + 16, 0x2160, 4);  // IAT
  const unsigned ps = wide ? 8 : 4;
  const std::uint64_t ord_flag = wide ? (1ULL << 63) : (1ULL << 31);
  b.put_at(f(0x2140), 0x21a0, ps);
  b.put_at(f(0x2140) + ps, ord_flag | 7, ps);
  b.put_at(f(0x2160), 0x21a0, ps);
  b.put_at(f(0x2160) + ps, ord_flag | 7, ps);
  b.str_at(f(0x2180), "KERNEL32.dll");
  b.put_at(f(0x21a0), 0, 2);
  b.str_at(f(0x21a2), "ExitProcess");

  // Debug directory at 0x2300 -> CodeView RSDS record at 0x2320.
  b.put_at(f(0x2300) + 12, 2, 4);
  b.put_at(f(0x2300) + 16, 24 + 32, 4);
  b.put_at(f(0x2300) + 20, 0x2320, 4);
  b.put_at(f(0x2300) + 24, f(0x2320), 4);
  b.bytes_at(f(0x2320), {'R', 'S', 'D', 'S'});
  for (int i = 0; i < 16; ++i) b.put_at(f(0x2320) + 4 + i, 0x10 + i, 1);  // GUID
  b.put_at(f(0x2320) + 20, 3, 4);                                         // age
  b.str_at(f(0x2320) + 24, "C:\\build\\test.pdb");

  // .pdata: RUNTIME_FUNCTIONs for f1 [0x1000,0x1006) and f2 [0x1010,0x1013).
  b.put_at(f(0x3000), 0x1000, 4);
  b.put_at(f(0x3004), 0x1006, 4);
  b.put_at(f(0x3010) - 4, 0x1010, 4);
  b.put_at(f(0x3010), 0x1013, 4);

  b.pad_to(0xc00);
  pe.bytes = b.data();
  return pe;
}

// A fresh scratch directory for one test.
inline std::filesystem::path scratch_dir(const std::string &name) {
  auto dir = std::filesystem::temp_directory_path() / ("revkit-test-" + std::to_string(::getpid()) + "-" + name);
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  return dir;
}

// Compile `source` with `compiler` and `flags` into `out`. False if the
// compiler is missing or fails (callers skip the test then).
inline bool compile(const std::string &compiler, const std::string &source, const std::string &flags,
                    const std::filesystem::path &out) {
  if (compiler.empty()) return false;
  auto src = out.parent_path() / (out.filename().string() + ".c");
  {
    std::ofstream s(src);
    s << source;
  }
  std::string cmd = compiler + " " + flags + " " + src.string() + " -o " + out.string() + " 2>/dev/null";
  return std::system(cmd.c_str()) == 0 && std::filesystem::exists(out);
}

inline std::vector<std::uint8_t> read_file(const std::filesystem::path &p) {
  std::ifstream in(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

}  // namespace revkit::testing
