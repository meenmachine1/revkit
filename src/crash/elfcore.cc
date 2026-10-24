// ELF core files, from the ELF specification and Linux's core dump layout
// (include/uapi/linux/elfcore.h, the per-architecture user_regs_struct /
// user_pt_regs, fs/binfmt_elf.c's note order): PT_LOAD segments, and in
// PT_NOTE one NT_PRSTATUS per thread (the dumping thread first),
// NT_PRPSINFO, NT_SIGINFO, NT_AUXV and NT_FILE. Written for revkit.
#include "reader.hh"

#include <algorithm>
#include <set>

namespace revkit::crash {

using detail::Reader;

namespace {

constexpr std::uint32_t kPrStatus = 1, kPrPsInfo = 3, kAuxv = 6, kSigInfo = 0x53494749, kFile = 0x46494c45;
constexpr std::uint64_t kAtEntry = 9, kAtSysinfoEhdr = 33;

struct Layout {
  std::vector<const char *> names;
  unsigned word = 8;
};

// pr_reg's registers, in order, by e_machine.
std::optional<Layout> registers_of(std::uint16_t machine, bool wide) {
  switch (machine) {
    case 62:
      return Layout{{"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
                     "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"},
                    8};
    case 3:
      return Layout{{"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax", "eip", "cs",
                     "eflags", "esp", "ss"},
                    4};
    case 183: {
      Layout l;
      static const char *x[] = {"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",  "x10",
                                "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21",
                                "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30"};
      l.names.assign(std::begin(x), std::end(x));
      l.names.push_back("sp");
      l.names.push_back("pc");
      l.names.push_back("cpsr");
      return l;
    }
    case 40:
      return Layout{{"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
                     "cpsr", "orig_r0"},
                    4};
    case 243:
      return Layout{{"pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
                     "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"},
                    wide ? 8u : 4u};
    default: return std::nullopt;
  }
}

std::string arch_of(std::uint16_t m) {
  switch (m) {
    case 62: return "x86-64";
    case 3: return "x86";
    case 183: return "AArch64";
    case 40: return "ARM";
    case 243: return "RISC-V";
    case 8: return "MIPS";
    case 20: return "PowerPC";
    case 21: return "PowerPC64";
    default: return "machine " + std::to_string(m);
  }
}

std::string group_of(std::string_view n) {
  if (n == "eflags" || n == "cpsr") return "flags";
  if (n == "cs" || n == "ss" || n == "ds" || n == "es" || n == "fs" || n == "gs") return "segment";
  if (n == "orig_rax" || n == "orig_eax" || n == "orig_r0" || n == "fs_base" || n == "gs_base") return "system";
  return "general";
}

std::string base_name(const std::string &p) {
  const auto s = p.find_last_of('/');
  return s == std::string::npos ? p : p.substr(s + 1);
}

}  // namespace

CrashDump parse_elf_core(Bytes file, const Limits &limits) {
  if (file.size() < 52 || std::memcmp(file.data(), "\x7f" "ELF", 4) != 0) throw Error("not an ELF file");
  const std::uint8_t cls = static_cast<std::uint8_t>(file[4]), enc = static_cast<std::uint8_t>(file[5]);
  if ((cls != 1 && cls != 2) || (enc != 1 && enc != 2)) throw Error("an ELF file of an unknown class or byte order");
  const bool wide = cls == 2;
  const Reader r(file, enc == 2);
  if (r.u16(16) != 4) throw Error("not an ELF core file (e_type is " + std::to_string(r.u16(16)) + ")");
  CrashDump d;
  d.format = Format::elf_core;
  d.machine = r.u16(18);
  d.arch = arch_of(d.machine);
  d.pointer_size = wide ? 8 : 4;
  d.big_endian = enc == 2;
  std::uint64_t phoff = wide ? r.u64(32) : r.u32(28);
  const std::uint16_t phent = r.u16(wide ? 54 : 42);
  std::uint64_t phnum = r.u16(wide ? 56 : 44);
  if (phnum == 0xffff) {  // PN_XNUM: the count is section 0's sh_info
    const std::uint64_t shoff = wide ? r.u64(40) : r.u32(32);
    phnum = r.u32(shoff + (wide ? 44 : 28), "section 0");
  }
  if (phent < (wide ? 56 : 32)) throw Error("e_phentsize is too small");
  if (phnum > limits.max_segments + 16) throw Error("the core has too many program headers");
  r.need(phoff, phnum * phent, "the program headers");
  const auto layout = registers_of(d.machine, wide);
  if (!layout) d.warnings.push_back("registers of " + d.arch + " cores aren't read");
  std::optional<int> si_signo;
  // Program headers may all name one note segment, or overlapping ones: a
  // note (by its offset in the file) is read once, whichever segment holds
  // it, and the mapped files are capped across all of them (bug scrub
  // part 3: a million headers re-read one NT_FILE of 256K files).
  std::set<std::uint64_t> notes_read;
  for (std::uint64_t i = 0; i < phnum; ++i) {
    const std::uint64_t p = phoff + i * phent;
    const std::uint32_t type = r.u32(p);
    const std::uint32_t flags = wide ? r.u32(p + 4) : r.u32(p + 24);
    const std::uint64_t off = wide ? r.u64(p + 8) : r.u32(p + 4), vaddr = wide ? r.u64(p + 16) : r.u32(p + 8),
                        filesz = wide ? r.u64(p + 32) : r.u32(p + 16), memsz = wide ? r.u64(p + 40) : r.u32(p + 20);
    if (type == 1) {
      Segment s;
      s.address = vaddr;
      s.size = memsz;
      s.file_offset = off;
      s.file_size = std::min(filesz, memsz);
      if (s.file_size != 0 && (!r.fits(off, 0) || off + s.file_size > file.size())) {
        d.warnings.push_back("the segment at " + detail::hex(vaddr) + " runs past the end of the file (a truncated core)");
        s.file_size = off < file.size() ? file.size() - off : 0;
      }
      s.perms = std::string(flags & 4 ? "r" : "-") + (flags & 2 ? "w" : "-") + (flags & 1 ? "x" : "-");
      if (d.memory.size() < limits.max_segments) d.memory.push_back(s);
      continue;
    }
    if (type != 4) continue;
    if (!r.fits(off, filesz)) {
      d.warnings.push_back("a note segment lies outside the file");
      continue;
    }
    for (std::uint64_t n = off; n + 12 <= off + filesz;) {
      const std::uint32_t namesz = r.u32(n), descsz = r.u32(n + 4), ntype = r.u32(n + 8);
      const std::uint64_t name = n + 12, desc = name + ((static_cast<std::uint64_t>(namesz) + 3) & ~3ull);
      const std::uint64_t next = desc + ((static_cast<std::uint64_t>(descsz) + 3) & ~3ull);
      if (next > off + filesz || desc > off + filesz) {
        d.warnings.push_back("a note runs past its segment");
        break;
      }
      const std::uint64_t here = n;
      n = next;
      if (!notes_read.insert(here).second) continue;
      const std::string owner = r.str(name, namesz);
      if (owner != "CORE") continue;
      try {
        if (ntype == kPrStatus) {
          if (d.threads.size() >= limits.max_threads) continue;
          Thread t;
          t.signal = static_cast<std::int16_t>(r.u16(desc + 12, "a thread's status"));
          t.id = static_cast<std::uint32_t>(r.u32(desc + (wide ? 32 : 24), "a thread's status"));
          if (d.threads.empty()) {
            d.pid = static_cast<std::int32_t>(r.u32(desc + (wide ? 32 : 24)));
            d.ppid = static_cast<std::int32_t>(r.u32(desc + (wide ? 36 : 28)));
            if (!si_signo) d.signal = t.signal;
          }
          if (layout) {
            const std::uint64_t reg = desc + (wide ? 112 : 72);
            const std::uint64_t need = layout->names.size() * layout->word;
            if (reg + need > desc + descsz) {
              d.warnings.push_back("thread " + std::to_string(t.id) + "'s registers don't fit its status note");
            } else {
              for (std::size_t k = 0; k < layout->names.size(); ++k) {
                Register rg;
                rg.name = layout->names[k];
                rg.value = r.le_bytes(reg + k * layout->word, layout->word, "a register");
                rg.group = group_of(rg.name);
                t.registers.push_back(std::move(rg));
              }
            }
          }
          d.threads.push_back(std::move(t));
        } else if (ntype == kPrPsInfo) {
          // 64-bit: uid and gid 32-bit at 16; i386 and ARM: 16-bit at 8 (a 124-byte note).
          if (wide) {
            d.uid = r.u32(desc + 16);
            d.gid = r.u32(desc + 20);
            d.command = detail::clean(r.str(desc + 40, std::min<std::uint32_t>(16, descsz > 40 ? descsz - 40 : 0)));
            d.args = detail::clean(r.str(desc + 56, std::min<std::uint32_t>(80, descsz > 56 ? descsz - 56 : 0)));
          } else {
            const bool small_ids = descsz == 124;
            d.uid = small_ids ? r.u16(desc + 8) : r.u32(desc + 8);
            d.gid = small_ids ? r.u16(desc + 10) : r.u32(desc + 12);
            const std::uint64_t f = desc + (small_ids ? 28 : 32);
            d.command = detail::clean(r.str(f, std::min<std::uint64_t>(16, desc + descsz > f ? desc + descsz - f : 0)));
            d.args = detail::clean(r.str(f + 16, std::min<std::uint64_t>(80, desc + descsz > f + 16 ? desc + descsz - f - 16 : 0)));
          }
          while (!d.args.empty() && d.args.back() == ' ') d.args.pop_back();
        } else if (ntype == kSigInfo) {
          si_signo = static_cast<std::int32_t>(r.u32(desc, "siginfo"));
          d.signal = *si_signo;
          d.signal_code = static_cast<std::int32_t>(r.u32(desc + 8, "siginfo"));
          const int s = d.signal;
          if (d.signal_code > 0 && (s == 11 || s == 7 || s == 4 || s == 8 || s == 5))
            d.fault_address = r.word(desc + (wide ? 16 : 12), wide, "siginfo's address");
        } else if (ntype == kAuxv) {
          const unsigned w = wide ? 8 : 4;
          for (std::uint64_t a = desc; a + 2 * w <= desc + descsz; a += 2 * w) {
            const std::uint64_t key = r.word(a, wide), val = r.word(a + w, wide);
            if (key == 0) break;
            d.auxv[key] = val;
          }
        } else if (ntype == kFile) {
          const unsigned w = wide ? 8 : 4;
          const std::uint64_t count = r.word(desc, wide), page = r.word(desc + w, wide);
          if (count > limits.max_files || count * 3 * w + 2 * w > descsz) {
            d.warnings.push_back("NT_FILE says it has more files than fit in it");
            continue;
          }
          std::uint64_t names = desc + 2 * w + count * 3 * w;
          for (std::uint64_t k = 0; k < count && d.files.size() < limits.max_files; ++k) {
            const std::uint64_t e = desc + 2 * w + k * 3 * w;
            MappedFile f;
            f.start = r.word(e, wide);
            f.end = r.word(e + w, wide);
            f.file_offset = r.word(e + 2 * w, wide) * page;
            const std::uint64_t left = desc + descsz > names ? desc + descsz - names : 0;
            f.path = r.str(names, std::min<std::uint64_t>(left, 4096));
            names += f.path.size() + 1;
            if (f.end < f.start) continue;
            d.files.push_back(std::move(f));
          }
        }
      } catch (const Error &e) {
        d.warnings.push_back(std::string("a note: ") + e.what());
      }
    }
  }
  detail::sort_memory(d);
  if (d.threads.empty()) d.warnings.push_back("the core has no thread status (NT_PRSTATUS)");
  d.signal_name = crash::signal_name(d.signal);
  if (si_signo) d.code_name = signal_code_name(d.signal, d.signal_code);
  detail::describe(d);
  // Modules: NT_FILE's mappings by path; the one holding AT_ENTRY is the program.
  std::vector<std::string> order;
  std::map<std::string, Module> by_path;
  for (const MappedFile &f : d.files) {
    auto [it, fresh] = by_path.try_emplace(f.path);
    Module &m = it->second;
    if (fresh) {
      order.push_back(f.path);
      m.path = f.path;
      m.name = base_name(f.path);
      m.base = f.start;
      m.size = f.end - f.start;
    } else {
      const std::uint64_t end = std::max(m.base + m.size, f.end);
      m.base = std::min(m.base, f.start);
      m.size = end - m.base;
    }
  }
  const auto entry = d.auxv.find(kAtEntry);
  for (const std::string &p : order) {
    if (d.modules.size() >= limits.max_modules) break;
    Module m = by_path[p];
    if (entry != d.auxv.end() && entry->second >= m.base && entry->second - m.base < m.size) m.main = true;
    d.modules.push_back(std::move(m));
  }
  if (entry == d.auxv.end() && !d.modules.empty()) d.modules.front().main = true;
  // The vDSO, when the auxiliary vector says where it is.
  if (auto v = d.auxv.find(kAtSysinfoEhdr); v != d.auxv.end() && v->second != 0)
    for (const Segment &s : d.memory)
      if (s.address == v->second) {
        Module m;
        m.name = m.path = "[vdso]";
        m.base = s.address;
        m.size = s.size;
        d.modules.push_back(m);
      }
  return d;
}

}  // namespace revkit::crash
