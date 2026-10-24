// Windows minidumps (MDMP), from the format as Microsoft's
// minidumpapiset.h and winnt.h's CONTEXT records describe it: the stream
// directory; the thread, module, memory, Memory64, exception, system info,
// misc info, memory info, thread name and comment streams; the thread
// contexts of x86-64, x86, ARM64 and ARM; a module's CodeView record (RSDS:
// the PDB's GUID and age; BpEL: an ELF build ID, as breakpad writes). Written
// for revkit.
#include "reader.hh"

#include <algorithm>
#include <set>
#include <cstdio>

namespace revkit::crash {

using detail::Reader;

namespace {

enum : std::uint32_t {
  kThreadList = 3,
  kModuleList = 4,
  kMemoryList = 5,
  kException = 6,
  kSystemInfo = 7,
  kMemory64List = 9,
  kCommentA = 10,
  kCommentW = 11,
  kMiscInfo = 15,
  kMemoryInfoList = 16,
  kThreadNames = 24,
};

// A MINIDUMP_STRING: its length in bytes, then UTF-16.
std::string md_string(const Reader &r, std::uint32_t rva) {
  const std::uint32_t bytes = r.u32(rva, "a string");
  if (bytes > (1u << 16)) throw Error("a string is longer than 64 KiB");
  return detail::utf16(r, rva + 4ull, bytes / 2);
}

std::string base_name(const std::string &p) {
  const auto s = p.find_last_of("/\\");
  return s == std::string::npos ? p : p.substr(s + 1);
}

// The registers of a CONTEXT record, by the dump's processor architecture.
std::vector<Register> context(const Reader &r, std::uint64_t at, std::uint32_t size, std::uint16_t arch) {
  std::vector<Register> regs;
  auto add = [&](const char *name, std::uint64_t off, unsigned n, const char *group = "general") {
    if (off + n > size) throw Error("the thread context is too short");
    std::vector<std::uint8_t> v = r.le_bytes(at + off, n, "a thread context");
    regs.push_back({name, std::move(v), group});
  };
  switch (arch) {
    case 9: {  // AMD64 CONTEXT
      static const std::pair<const char *, unsigned> gp[] = {
          {"rax", 120}, {"rcx", 128}, {"rdx", 136}, {"rbx", 144}, {"rsp", 152}, {"rbp", 160}, {"rsi", 168}, {"rdi", 176},
          {"r8", 184},  {"r9", 192},  {"r10", 200}, {"r11", 208}, {"r12", 216}, {"r13", 224}, {"r14", 232}, {"r15", 240},
          {"rip", 248}};
      for (auto [n, o] : gp) add(n, o, 8);
      add("eflags", 68, 4, "flags");
      static const std::pair<const char *, unsigned> seg[] = {{"cs", 56}, {"ds", 58}, {"es", 60}, {"fs", 62}, {"gs", 64}, {"ss", 66}};
      for (auto [n, o] : seg) add(n, o, 2, "segment");
      add("mxcsr", 52, 4, "system");
      break;
    }
    case 0: {  // x86 CONTEXT
      static const std::pair<const char *, unsigned> gp[] = {{"eax", 176}, {"ecx", 172}, {"edx", 168}, {"ebx", 164},
                                                             {"esp", 196}, {"ebp", 180}, {"esi", 160}, {"edi", 156},
                                                             {"eip", 184}};
      for (auto [n, o] : gp) add(n, o, 4);
      add("eflags", 192, 4, "flags");
      static const std::pair<const char *, unsigned> seg[] = {{"cs", 188}, {"ss", 200}, {"ds", 152}, {"es", 148}, {"fs", 144}, {"gs", 140}};
      for (auto [n, o] : seg) add(n, o, 4, "segment");
      break;
    }
    case 12: case 0x8003: {  // ARM64_NT_CONTEXT
      static const char *x[] = {"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",
                                "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
                                "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"};
      for (unsigned i = 0; i < 29; ++i) add(x[i], 8 + 8 * i, 8);
      add("x29", 240, 8);
      add("x30", 248, 8);
      add("sp", 256, 8);
      add("pc", 264, 8);
      add("cpsr", 4, 4, "flags");
      break;
    }
    case 5: {  // ARM CONTEXT
      static const char *g[] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"};
      for (unsigned i = 0; i < 13; ++i) add(g[i], 4 + 4 * i, 4);
      add("sp", 56, 4);
      add("lr", 60, 4);
      add("pc", 64, 4);
      add("cpsr", 68, 4, "flags");
      break;
    }
    default: break;
  }
  return regs;
}

std::string arch_name(std::uint16_t a) {
  switch (a) {
    case 0: return "x86";
    case 5: return "ARM";
    case 6: return "IA-64";
    case 9: return "x86-64";
    case 12: case 0x8003: return "AArch64";
    default: return "architecture " + std::to_string(a);
  }
}

std::string perms_of(std::uint32_t protect) {
  switch (protect & 0xff) {
    case 0x02: return "r--";
    case 0x04: case 0x08: return "rw-";
    case 0x10: return "--x";
    case 0x20: return "r-x";
    case 0x40: case 0x80: return "rwx";
    case 0x01: return "---";
    default: return "";
  }
}

}  // namespace

CrashDump parse_minidump(Bytes file, const Limits &limits) {
  const Reader r(file);
  if (file.size() < 32 || std::memcmp(file.data(), "MDMP", 4) != 0) throw Error("not a minidump (no MDMP signature)");
  if ((r.u32(4) & 0xffff) != 0xa793) throw Error("a minidump of an unknown version");
  CrashDump d;
  d.format = Format::minidump;
  const std::uint32_t streams = r.u32(8), dir = r.u32(12);
  d.timestamp = r.u32(20);
  if (streams > 4096) throw Error("the minidump has too many streams");
  r.need(dir, 12ull * streams, "the stream directory");
  struct Stream {
    std::uint32_t type, size, rva;
  };
  std::vector<Stream> list;
  for (std::uint32_t i = 0; i < streams; ++i) {
    Stream s{r.u32(dir + 12ull * i), r.u32(dir + 12ull * i + 4), r.u32(dir + 12ull * i + 8)};
    if (s.type == 0) continue;
    if (!r.fits(s.rva, s.size)) {
      d.warnings.push_back("stream " + std::to_string(s.type) + " lies outside the file");
      continue;
    }
    list.push_back(s);
  }
  auto find = [&](std::uint32_t type) -> const Stream * {
    for (const Stream &s : list)
      if (s.type == type) return &s;
    return nullptr;
  };
  // The processor first: it decides how contexts read.
  std::uint16_t arch = 0xffff;
  if (const Stream *s = find(kSystemInfo); s && s->size >= 56) {
    arch = r.u16(s->rva);
    const std::uint8_t cpus = r.u8(s->rva + 6);
    const std::uint32_t major = r.u32(s->rva + 8), minor = r.u32(s->rva + 12), build = r.u32(s->rva + 16),
                        platform = r.u32(s->rva + 20);
    switch (platform) {
      case 2: d.os = "Windows " + std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(build); break;
      case 0x8101: d.os = "macOS"; break;
      case 0x8102: d.os = "iOS"; break;
      case 0x8201: d.os = "Linux"; break;
      case 0x8202: d.os = "Solaris"; break;
      case 0x8203: d.os = "Android"; break;
      case 0x8205: d.os = "Fuchsia"; break;
      default: d.os = "platform " + std::to_string(platform);
    }
    if (const std::uint32_t csd = r.u32(s->rva + 24); csd != 0)
      try {
        const std::string sp = md_string(r, csd);
        if (!sp.empty()) d.os += " " + sp;
      } catch (const Error &) {
      }
    d.cpu = arch_name(arch) + ", " + std::to_string(cpus) + " processor" + (cpus == 1 ? "" : "s");
  } else {
    d.warnings.push_back("no system info stream: the processor is guessed from the thread contexts");
  }
  auto set_arch = [&](std::uint16_t a) {
    d.arch = arch_name(a);
    d.pointer_size = (a == 0 || a == 5) ? 4 : 8;
    d.machine = a == 9 ? 62 : a == 0 ? 3 : (a == 12 || a == 0x8003) ? 183 : a == 5 ? 40 : 0;
  };
  // Threads, and their contexts.
  if (const Stream *s = find(kThreadList)) {
    const std::uint32_t n = r.u32(s->rva, "the thread list");
    if (n > limits.max_threads || 4ull + 48ull * n > s->size) throw Error("the thread list has more threads than fit in it");
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::uint64_t t = s->rva + 4ull + 48ull * i;
      Thread th;
      th.id = r.u32(t);
      th.teb = r.u64(t + 16);
      th.stack_start = r.u64(t + 24);
      th.stack_size = r.u32(t + 32);
      const std::uint32_t stack_rva = r.u32(t + 36);
      const std::uint32_t csize = r.u32(t + 40), crva = r.u32(t + 44);
      if (arch == 0xffff) {
        // Guess by the context's size: AMD64 1232, x86 716, ARM64 912, ARM 416.
        arch = csize >= 1232 ? 9 : csize == 912 ? 12 : csize >= 716 ? 0 : csize == 416 ? 5 : 0xffff;
      }
      if (th.stack_size != 0 && d.memory.size() < limits.max_segments)
        d.memory.push_back({th.stack_start, th.stack_size, stack_rva, th.stack_size, "rw-"});
      try {
        r.need(crva, csize, "a thread context");
        th.registers = context(r, crva, csize, arch);
      } catch (const Error &e) {
        d.warnings.push_back("thread " + std::to_string(th.id) + ": " + e.what());
      }
      d.threads.push_back(std::move(th));
    }
  }
  if (arch != 0xffff) set_arch(arch);
  else d.arch = "unknown";
  // Modules.
  if (const Stream *s = find(kModuleList)) {
    const std::uint32_t n = r.u32(s->rva, "the module list");
    if (n > limits.max_modules || 4ull + 108ull * n > s->size) throw Error("the module list has more modules than fit in it");
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::uint64_t m = s->rva + 4ull + 108ull * i;
      Module mod;
      mod.base = r.u64(m);
      mod.size = r.u32(m + 8);
      mod.checksum = r.u32(m + 12);
      mod.timestamp = r.u32(m + 16);
      try {
        mod.path = md_string(r, r.u32(m + 20));
      } catch (const Error &e) {
        d.warnings.push_back(std::string("a module's name: ") + e.what());
      }
      mod.name = base_name(mod.path);
      if (r.u32(m + 24) == 0xFEEF04BD) {
        const std::uint32_t ms = r.u32(m + 32), ls = r.u32(m + 36);
        mod.version = std::to_string(ms >> 16) + "." + std::to_string(ms & 0xffff) + "." + std::to_string(ls >> 16) + "." +
                      std::to_string(ls & 0xffff);
      }
      const std::uint32_t cv_size = r.u32(m + 76), cv_rva = r.u32(m + 80);
      if (cv_size >= 4 && r.fits(cv_rva, cv_size)) {
        const std::uint32_t sig = r.u32(cv_rva);
        if (sig == 0x53445352 && cv_size >= 24) {  // "RSDS"
          char g[64];
          std::snprintf(g, sizeof g, "%08X%04X%04X", r.u32(cv_rva + 4), r.u16(cv_rva + 8), r.u16(cv_rva + 10));
          std::string guid = g;
          for (int k = 0; k < 8; ++k) {
            std::snprintf(g, sizeof g, "%02X", r.u8(cv_rva + 12 + k));
            guid += g;
          }
          std::snprintf(g, sizeof g, "%X", r.u32(cv_rva + 20));
          mod.pdb_guid = guid + g;
          mod.pdb_name = detail::clean(r.str(cv_rva + 24, cv_size - 24));
        } else if (sig == 0x4270454c) {  // "BpEL": an ELF build ID
          for (std::uint32_t k = 4; k < cv_size && k < 4 + 64; ++k) {
            char h[4];
            std::snprintf(h, sizeof h, "%02x", r.u8(cv_rva + k));
            mod.build_id += h;
          }
        }
      }
      if (i == 0) mod.main = true;
      d.modules.push_back(std::move(mod));
    }
  }
  // Memory.
  if (const Stream *s = find(kMemoryList)) {
    const std::uint32_t n = r.u32(s->rva, "the memory list");
    if (n > limits.max_segments || 4ull + 16ull * n > s->size) throw Error("the memory list has more ranges than fit in it");
    // The ranges kept so far, for the duplicate check: a set, not a scan of
    // the list for each (a million ranges were 10^12 compares).
    std::set<std::pair<std::uint64_t, std::uint64_t>> have;
    for (const Segment &x : d.memory) have.emplace(x.address, x.size);
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::uint64_t m = s->rva + 4ull + 16ull * i;
      Segment seg{r.u64(m), r.u32(m + 8), r.u32(m + 12), r.u32(m + 8), ""};
      if (!r.fits(seg.file_offset, seg.file_size)) {
        d.warnings.push_back("memory at " + detail::hex(seg.address) + " lies outside the file");
        seg.file_size = seg.file_offset < file.size() ? file.size() - seg.file_offset : 0;
      }
      // A thread's stack is listed again here: keep one.
      if (have.emplace(seg.address, seg.size).second) d.memory.push_back(seg);
    }
  }
  if (const Stream *s = find(kMemory64List)) {
    const std::uint64_t n = r.u64(s->rva, "the memory64 list");
    std::uint64_t at = r.u64(s->rva + 8);
    if (n > limits.max_segments || 16ull + 16ull * n > s->size) throw Error("the memory64 list has more ranges than fit in it");
    for (std::uint64_t i = 0; i < n; ++i) {
      const std::uint64_t m = s->rva + 16 + 16 * i;
      Segment seg{r.u64(m), r.u64(m + 8), at, r.u64(m + 8), ""};
      if (at > file.size() || seg.size > file.size() - at) {
        d.warnings.push_back("memory at " + detail::hex(seg.address) + " runs past the end of the file");
        seg.file_size = at < file.size() ? file.size() - at : 0;
      }
      at = seg.size > UINT64_MAX - at ? UINT64_MAX : at + seg.size;
      d.memory.push_back(seg);
    }
  }
  detail::sort_memory(d);
  // Memory info: each range's protection.
  if (const Stream *s = find(kMemoryInfoList); s && s->size >= 16) {
    const std::uint32_t hsize = r.u32(s->rva), esize = r.u32(s->rva + 4);
    const std::uint64_t n = r.u64(s->rva + 8);
    // The memory is sorted: each range's segments are found by a binary
    // search, and what all ranges mark is budgeted (overlapping ranges
    // could each cover every segment: n x m, with no cancel; bug scrub
    // part 3).
    std::uint64_t marked = 0;
    const std::uint64_t budget = 4 * static_cast<std::uint64_t>(limits.max_segments);
    if (esize >= 48 && n <= limits.max_segments && hsize + n * esize <= s->size)
      for (std::uint64_t i = 0; i < n && marked <= budget; ++i) {
        const std::uint64_t e = s->rva + hsize + i * esize;
        const std::uint64_t base = r.u64(e), size = r.u64(e + 24);
        const std::string p = perms_of(r.u32(e + 36));
        if (p.empty()) continue;
        auto it = std::lower_bound(d.memory.begin(), d.memory.end(), base,
                                   [](const Segment &x, std::uint64_t a) { return x.address < a; });
        for (; it != d.memory.end() && it->address - base < size && marked <= budget; ++it, ++marked) it->perms = p;
      }
    if (marked > budget) d.warnings.push_back("the memory info list's ranges overlap too much: some protections not read");
  }
  // The exception.
  if (const Stream *s = find(kException); s && s->size >= 168) {
    const std::uint32_t tid = r.u32(s->rva);
    d.exception_code = r.u32(s->rva + 8);
    d.exception_flags = r.u32(s->rva + 12);
    d.exception_address = r.u64(s->rva + 24);
    const std::uint32_t np = std::min<std::uint32_t>(r.u32(s->rva + 32), 15);
    for (std::uint32_t k = 0; k < np; ++k) d.exception_parameters.push_back(r.u64(s->rva + 40 + 8ull * k));
    d.exception_name = crash::exception_name(d.exception_code);
    if ((d.exception_code == 0xC0000005 || d.exception_code == 0xC0000006) && np >= 2) {
      d.access = d.exception_parameters[0] == 0 ? "read" : d.exception_parameters[0] == 1 ? "write" : d.exception_parameters[0] == 8 ? "execute" : "access";
      d.fault_address = d.exception_parameters[1];
    }
    for (std::size_t i = 0; i < d.threads.size(); ++i)
      if (d.threads[i].id == tid) {
        d.crashed_thread = i;
        // The context at the exception, rather than in the handler that wrote the dump.
        const std::uint32_t csize = r.u32(s->rva + 160), crva = r.u32(s->rva + 164);
        if (csize != 0 && arch != 0xffff)
          try {
            r.need(crva, csize, "the exception's context");
            d.threads[i].registers = context(r, crva, csize, arch);
          } catch (const Error &e) {
            d.warnings.push_back(std::string("the exception's context: ") + e.what());
          }
      }
  }
  // Misc info: the process id.
  if (const Stream *s = find(kMiscInfo); s && s->size >= 12)
    if (r.u32(s->rva + 4) & 1) d.pid = r.u32(s->rva + 8);
  // Thread names (Windows 10's SetThreadDescription).
  if (const Stream *s = find(kThreadNames); s && s->size >= 4) {
    const std::uint32_t n = r.u32(s->rva);
    for (std::uint32_t i = 0; i < n && 4ull + 12ull * (i + 1) <= s->size; ++i) {
      const std::uint32_t tid = r.u32(s->rva + 4 + 12ull * i);
      const std::uint64_t rva = r.u64(s->rva + 8 + 12ull * i);
      for (Thread &t : d.threads)
        if (t.id == tid && rva < file.size()) try {
            t.name = md_string(r, static_cast<std::uint32_t>(rva));
          } catch (const Error &) {
          }
    }
  }
  for (const Stream &s : list) {
    if (s.type == kCommentA) d.comments.push_back(detail::clean(r.str(s.rva, std::min<std::uint32_t>(s.size, 4096))));
    if (s.type == kCommentW) d.comments.push_back(detail::utf16(r, s.rva, std::min<std::uint32_t>(s.size, 8192) / 2));
  }
  if (d.threads.empty()) d.warnings.push_back("the minidump has no thread list");
  detail::describe(d);
  return d;
}

}  // namespace revkit::crash
