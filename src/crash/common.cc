// What both dump formats share: the names of signals, signal codes and
// Windows exceptions, reading dumped memory, finding a module.
#include "reader.hh"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace revkit::crash {

std::string_view to_string(Format f) { return f == Format::elf_core ? "elf-core" : "minidump"; }

std::string signal_name(int s) {
  static const char *names[] = {nullptr,   "SIGHUP",  "SIGINT",    "SIGQUIT", "SIGILL",  "SIGTRAP", "SIGABRT",
                                "SIGBUS",  "SIGFPE",  "SIGKILL",   "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE",
                                "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP",
                                "SIGTTIN", "SIGTTOU", "SIGURG",    "SIGXCPU", "SIGXFSZ", "SIGVTALRM",
                                "SIGPROF", "SIGWINCH", "SIGIO",    "SIGPWR",  "SIGSYS"};
  if (s > 0 && s < static_cast<int>(std::size(names))) return names[s];
  if (s >= 34 && s <= 64) return "SIGRT" + std::to_string(s - 34);
  return s == 0 ? std::string() : "signal " + std::to_string(s);
}

std::string signal_code_name(int sig, int code) {
  switch (code) {
    case 0: return "SI_USER";
    case 0x80: return "SI_KERNEL";
    case -1: return "SI_QUEUE";
    case -2: return "SI_TIMER";
    case -3: return "SI_MESGQ";
    case -4: return "SI_ASYNCIO";
    case -5: return "SI_SIGIO";
    case -6: return "SI_TKILL";
    default: break;
  }
  auto pick = [&](std::initializer_list<const char *> names) -> std::string {
    if (code >= 1 && static_cast<std::size_t>(code) <= names.size()) return names.begin()[code - 1];
    return "code " + std::to_string(code);
  };
  switch (sig) {
    case 11: return pick({"SEGV_MAPERR", "SEGV_ACCERR", "SEGV_BNDERR", "SEGV_PKUERR", "SEGV_ACCADI", "SEGV_ADIDERR",
                          "SEGV_ADIPERR", "SEGV_MTEAERR", "SEGV_MTESERR", "SEGV_CPERR"});
    case 7: return pick({"BUS_ADRALN", "BUS_ADRERR", "BUS_OBJERR", "BUS_MCEERR_AR", "BUS_MCEERR_AO"});
    case 4: return pick({"ILL_ILLOPC", "ILL_ILLOPN", "ILL_ILLADR", "ILL_ILLTRP", "ILL_PRVOPC", "ILL_PRVREG", "ILL_COPROC",
                         "ILL_BADSTK", "ILL_BADIADDR"});
    case 8: return pick({"FPE_INTDIV", "FPE_INTOVF", "FPE_FLTDIV", "FPE_FLTOVF", "FPE_FLTUND", "FPE_FLTRES", "FPE_FLTINV",
                         "FPE_FLTSUB", "FPE_FLTUNK", "FPE_CONDTRAP"});
    case 5: return pick({"TRAP_BRKPT", "TRAP_TRACE", "TRAP_BRANCH", "TRAP_HWBKPT", "TRAP_UNK", "TRAP_PERF"});
    case 17: return pick({"CLD_EXITED", "CLD_KILLED", "CLD_DUMPED", "CLD_TRAPPED", "CLD_STOPPED", "CLD_CONTINUED"});
    case 31: return code == 1 ? "SYS_SECCOMP" : "code " + std::to_string(code);
    default: return "code " + std::to_string(code);
  }
}

std::string exception_name(std::uint32_t code) {
  switch (code) {
    case 0xC0000005: return "EXCEPTION_ACCESS_VIOLATION";
    case 0xC0000006: return "EXCEPTION_IN_PAGE_ERROR";
    case 0xC0000008: return "EXCEPTION_INVALID_HANDLE";
    case 0xC000001D: return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case 0xC0000025: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case 0xC0000026: return "EXCEPTION_INVALID_DISPOSITION";
    case 0xC000008C: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case 0xC000008D: return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case 0xC000008E: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case 0xC000008F: return "EXCEPTION_FLT_INEXACT_RESULT";
    case 0xC0000090: return "EXCEPTION_FLT_INVALID_OPERATION";
    case 0xC0000091: return "EXCEPTION_FLT_OVERFLOW";
    case 0xC0000092: return "EXCEPTION_FLT_STACK_CHECK";
    case 0xC0000093: return "EXCEPTION_FLT_UNDERFLOW";
    case 0xC0000094: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case 0xC0000095: return "EXCEPTION_INT_OVERFLOW";
    case 0xC0000096: return "EXCEPTION_PRIV_INSTRUCTION";
    case 0xC00000FD: return "EXCEPTION_STACK_OVERFLOW";
    case 0xC0000374: return "STATUS_HEAP_CORRUPTION";
    case 0xC0000409: return "STATUS_STACK_BUFFER_OVERRUN";
    case 0xC0000602: return "STATUS_FAIL_FAST_EXCEPTION";
    case 0x80000001: return "EXCEPTION_GUARD_PAGE";
    case 0x80000002: return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case 0x80000003: return "EXCEPTION_BREAKPOINT";
    case 0x80000004: return "EXCEPTION_SINGLE_STEP";
    case 0x40000015: return "STATUS_FATAL_APP_EXIT";
    case 0x40010005: return "DBG_CONTROL_C";
    case 0xE06D7363: return "a C++ exception (0xE06D7363)";
    case 0xE0434352: return "a .NET exception (0xE0434352)";
    default: {
      char b[24];
      std::snprintf(b, sizeof b, "exception 0x%08X", code);
      return b;
    }
  }
}

const Module *CrashDump::module_at(std::uint64_t a) const {
  for (const Module &m : modules)
    if (a >= m.base && a - m.base < m.size) return &m;
  return nullptr;
}

std::size_t CrashDump::read(Bytes file, std::uint64_t address, std::span<std::uint8_t> out,
                            std::vector<std::pair<std::uint32_t, std::uint32_t>> *missing) const {
  std::fill(out.begin(), out.end(), 0);
  std::vector<bool> have(out.size(), false);
  std::size_t got = 0;
  // The first segment that could overlap: memory is sorted by address.
  auto it = std::upper_bound(memory.begin(), memory.end(), address,
                             [](std::uint64_t a, const Segment &s) { return a < s.address; });
  if (it != memory.begin()) --it;
  const std::uint64_t end = address + out.size();
  for (; it != memory.end() && it->address < end; ++it) {
    const Segment &s = *it;
    if (s.address + s.size <= address) continue;
    const std::uint64_t lo = std::max(address, s.address);
    const std::uint64_t hi = std::min(end, s.address + std::min(s.size, s.file_size));
    if (hi <= lo) continue;
    const std::uint64_t foff = s.file_offset + (lo - s.address);
    if (foff >= file.size()) continue;
    const std::uint64_t n = std::min<std::uint64_t>(hi - lo, file.size() - foff);
    std::memcpy(out.data() + (lo - address), file.data() + foff, n);
    for (std::uint64_t k = 0; k < n; ++k)
      if (!have[lo - address + k]) {
        have[lo - address + k] = true;
        ++got;
      }
  }
  if (missing != nullptr)
    for (std::size_t i = 0; i < have.size();) {
      if (have[i]) {
        ++i;
        continue;
      }
      std::size_t j = i;
      while (j < have.size() && !have[j]) ++j;
      missing->emplace_back(static_cast<std::uint32_t>(i), static_cast<std::uint32_t>(j - i));
      i = j;
    }
  return got;
}

bool is_elf_core(Bytes h) {
  if (h.size() < 20 || std::memcmp(h.data(), "\x7f" "ELF", 4) != 0) return false;
  const bool be = static_cast<std::uint8_t>(h[5]) == 2;
  const std::uint16_t type = be ? static_cast<std::uint16_t>(static_cast<unsigned>(h[16]) << 8 | static_cast<unsigned>(h[17]))
                                : static_cast<std::uint16_t>(static_cast<unsigned>(h[17]) << 8 | static_cast<unsigned>(h[16]));
  return type == 4;
}

bool is_minidump(Bytes h) { return h.size() >= 32 && std::memcmp(h.data(), "MDMP", 4) == 0; }

CrashDump parse(Bytes file, const Limits &limits) {
  if (is_elf_core(file)) return parse_elf_core(file, limits);
  if (is_minidump(file)) return parse_minidump(file, limits);
  throw Error("not a crash dump (neither an ELF core file nor a minidump)");
}

namespace detail {

std::string clean(std::string_view s) {
  std::string out;
  for (char c : s) out += (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7f) ? '?' : c;
  return out;
}

std::string utf16(const Reader &r, std::uint64_t off, std::size_t units) {
  std::string out;
  for (std::size_t i = 0; i < units; ++i) {
    std::uint32_t c = r.u16(off + 2 * i, "a string");
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < units) {
      const std::uint32_t lo = r.u16(off + 2 * (i + 1), "a string");
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
        ++i;
      }
    }
    if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff)) c = c == 0 ? 0 : 0xfffd;
    if (c == 0) break;
    if (c < 0x80) {
      out += static_cast<char>(c);
    } else if (c < 0x800) {
      out += static_cast<char>(0xc0 | (c >> 6));
      out += static_cast<char>(0x80 | (c & 0x3f));
    } else if (c < 0x10000) {
      out += static_cast<char>(0xe0 | (c >> 12));
      out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
      out += static_cast<char>(0x80 | (c & 0x3f));
    } else {
      out += static_cast<char>(0xf0 | (c >> 18));
      out += static_cast<char>(0x80 | ((c >> 12) & 0x3f));
      out += static_cast<char>(0x80 | ((c >> 6) & 0x3f));
      out += static_cast<char>(0x80 | (c & 0x3f));
    }
  }
  return out;
}

std::string hex(std::uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
  return b;
}

void describe(CrashDump &d) {
  if (d.format == Format::elf_core) {
    if (d.signal == 0) {
      d.reason = "no signal recorded";
      return;
    }
    d.reason = d.signal_name;
    if (!d.code_name.empty() && d.code_name.rfind("code ", 0) != 0 && d.code_name.rfind("SI_", 0) != 0)
      d.reason += " (" + d.code_name + ")";
    else if (d.code_name.rfind("SI_", 0) == 0)
      d.reason += " (" + d.code_name + ", sent)";
    if (d.fault_address) d.reason += " at " + hex(*d.fault_address);
  } else {
    if (d.exception_code == 0) {
      d.reason = "no exception recorded";
      return;
    }
    d.reason = d.exception_name;
    if (d.exception_code == 0xC0000005 && d.fault_address)
      d.reason += " (" + (d.access.empty() ? std::string("access") : d.access) + " of " + hex(*d.fault_address) + ")";
    if (d.exception_address) d.reason += " at " + hex(*d.exception_address);
  }
}

void sort_memory(CrashDump &d) {
  std::sort(d.memory.begin(), d.memory.end(), [](const Segment &a, const Segment &b) { return a.address < b.address; });
}

}  // namespace detail

}  // namespace revkit::crash
