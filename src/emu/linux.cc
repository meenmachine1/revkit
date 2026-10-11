// Linux system calls: enough of the kernel for small programs and the
// start-up code of static C libraries. Everything is deterministic: the
// clock advances with the step count, AT_RANDOM and getrandom are fixed.
#include "impl.hh"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace revkit::emu {

namespace {

constexpr std::int64_t kEBADF = 9, kENOENT = 2, kEFAULT = 14, kENOTTY = 25, kENOSYS = 38, kENODEV = 19,
                       kEINVAL = 22, kENOMEM = 12;

std::string hexs(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

std::uint64_t align_up(std::uint64_t v, std::uint64_t a) { return (v + a - 1) & ~(a - 1); }

enum class Call {
  read, write, writev, exit, exit_group, brk, mmap, mmap2, munmap, mprotect, arch_prctl, set_tid_address, getpid,
  gettid, getppid, getuid, geteuid, getgid, getegid, uname, clock_gettime, ioctl, close, openat, open, fstat,
  newfstatat, rt_sigaction, rt_sigprocmask, sigaltstack, set_robust_list, rseq, prlimit64, getrandom, futex,
  madvise, readlinkat, readlink, sched_yield, nanosleep, set_tls, set_thread_area, tgkill, kill, lseek, access,
  faccessat, getcwd, gettimeofday, time, exit_unknown
};

struct Entry {
  std::uint64_t number;
  Call call;
};

// System call numbers per table (arch/*/entry/syscalls, asm-generic/unistd.h).
const std::vector<Entry> &table(const std::string &name) {
  static const std::vector<Entry> x86_64 = {
      {0, Call::read}, {1, Call::write}, {2, Call::open}, {3, Call::close}, {5, Call::fstat}, {8, Call::lseek},
      {9, Call::mmap}, {10, Call::mprotect}, {11, Call::munmap}, {12, Call::brk}, {13, Call::rt_sigaction},
      {14, Call::rt_sigprocmask}, {16, Call::ioctl}, {20, Call::writev}, {21, Call::access}, {24, Call::sched_yield},
      {28, Call::madvise}, {35, Call::nanosleep}, {39, Call::getpid}, {60, Call::exit}, {62, Call::kill},
      {63, Call::uname}, {79, Call::getcwd}, {89, Call::readlink}, {96, Call::gettimeofday}, {102, Call::getuid},
      {104, Call::getgid}, {107, Call::geteuid}, {108, Call::getegid}, {110, Call::getppid}, {131, Call::sigaltstack},
      {158, Call::arch_prctl}, {186, Call::gettid}, {201, Call::time}, {202, Call::futex}, {205, Call::set_thread_area},
      {218, Call::set_tid_address}, {228, Call::clock_gettime}, {231, Call::exit_group}, {234, Call::tgkill},
      {257, Call::openat}, {262, Call::newfstatat}, {267, Call::readlinkat}, {269, Call::faccessat},
      {273, Call::set_robust_list}, {302, Call::prlimit64}, {318, Call::getrandom}, {334, Call::rseq}};
  static const std::vector<Entry> generic = {
      {17, Call::getcwd}, {29, Call::ioctl}, {48, Call::faccessat}, {56, Call::openat}, {57, Call::close},
      {62, Call::lseek}, {63, Call::read}, {64, Call::write}, {66, Call::writev}, {78, Call::readlinkat},
      {79, Call::newfstatat}, {80, Call::fstat}, {93, Call::exit}, {94, Call::exit_group}, {96, Call::set_tid_address},
      {98, Call::futex}, {99, Call::set_robust_list}, {101, Call::nanosleep}, {113, Call::clock_gettime},
      {124, Call::sched_yield}, {129, Call::kill}, {131, Call::tgkill}, {132, Call::sigaltstack},
      {134, Call::rt_sigaction}, {135, Call::rt_sigprocmask}, {160, Call::uname}, {169, Call::gettimeofday},
      {172, Call::getpid}, {173, Call::getppid}, {174, Call::getuid}, {175, Call::geteuid}, {176, Call::getgid},
      {177, Call::getegid}, {178, Call::gettid}, {214, Call::brk}, {215, Call::munmap}, {222, Call::mmap},
      {226, Call::mprotect}, {233, Call::madvise}, {261, Call::prlimit64}, {278, Call::getrandom}, {293, Call::rseq}};
  static const std::vector<Entry> i386 = {
      {1, Call::exit}, {3, Call::read}, {4, Call::write}, {5, Call::open}, {6, Call::close}, {13, Call::time},
      {19, Call::lseek}, {20, Call::getpid}, {33, Call::access}, {37, Call::kill}, {45, Call::brk},
      {54, Call::ioctl}, {64, Call::getppid}, {78, Call::gettimeofday}, {85, Call::readlink}, {90, Call::mmap},
      {91, Call::munmap}, {122, Call::uname}, {125, Call::mprotect}, {146, Call::writev}, {158, Call::sched_yield},
      {162, Call::nanosleep}, {174, Call::rt_sigaction}, {175, Call::rt_sigprocmask}, {183, Call::getcwd},
      {186, Call::sigaltstack}, {192, Call::mmap2}, {197, Call::fstat}, {199, Call::getuid}, {200, Call::getgid},
      {201, Call::geteuid}, {202, Call::getegid}, {219, Call::madvise}, {224, Call::gettid}, {240, Call::futex},
      {243, Call::set_thread_area}, {252, Call::exit_group}, {258, Call::set_tid_address}, {265, Call::clock_gettime},
      {270, Call::tgkill}, {295, Call::openat}, {300, Call::newfstatat}, {311, Call::set_robust_list},
      {340, Call::prlimit64}, {355, Call::getrandom}, {386, Call::rseq}};
  static const std::vector<Entry> arm = {
      {1, Call::exit}, {3, Call::read}, {4, Call::write}, {5, Call::open}, {6, Call::close}, {19, Call::lseek},
      {20, Call::getpid}, {33, Call::access}, {37, Call::kill}, {45, Call::brk}, {54, Call::ioctl},
      {64, Call::getppid}, {78, Call::gettimeofday}, {85, Call::readlink}, {91, Call::munmap}, {122, Call::uname},
      {125, Call::mprotect}, {146, Call::writev}, {158, Call::sched_yield}, {162, Call::nanosleep},
      {174, Call::rt_sigaction}, {175, Call::rt_sigprocmask}, {183, Call::getcwd}, {186, Call::sigaltstack},
      {192, Call::mmap2}, {197, Call::fstat}, {199, Call::getuid}, {200, Call::getgid}, {201, Call::geteuid},
      {202, Call::getegid}, {220, Call::madvise}, {224, Call::gettid}, {240, Call::futex}, {248, Call::exit_group},
      {256, Call::set_tid_address}, {263, Call::clock_gettime}, {268, Call::tgkill}, {322, Call::openat},
      {327, Call::newfstatat}, {338, Call::set_robust_list}, {369, Call::prlimit64}, {384, Call::getrandom},
      {398, Call::rseq}, {0xf0005, Call::set_tls}};
  if (name == "x86_64") return x86_64;
  if (name == "i386") return i386;
  if (name == "arm") return arm;
  return generic;
}

const char *call_name(Call c) {
  switch (c) {
    case Call::read: return "read";
    case Call::write: return "write";
    case Call::writev: return "writev";
    case Call::exit: return "exit";
    case Call::exit_group: return "exit_group";
    case Call::brk: return "brk";
    case Call::mmap: return "mmap";
    case Call::mmap2: return "mmap2";
    case Call::munmap: return "munmap";
    case Call::mprotect: return "mprotect";
    case Call::arch_prctl: return "arch_prctl";
    case Call::set_tid_address: return "set_tid_address";
    case Call::uname: return "uname";
    case Call::clock_gettime: return "clock_gettime";
    case Call::getrandom: return "getrandom";
    default: return nullptr;
  }
}

}  // namespace

std::optional<detail::SyscallAbi> linux_syscall_abi(const std::string &language) {
  detail::SyscallAbi a;
  if (language.rfind("x86:LE:64", 0) == 0) {
    a = {"syscall", std::nullopt, "RAX", {"RDI", "RSI", "RDX", "R10", "R8", "R9"}, "RAX", "x86_64"};
  } else if (language.rfind("x86:LE:32", 0) == 0) {
    a = {"swi", 0x80, "EAX", {"EBX", "ECX", "EDX", "ESI", "EDI", "EBP"}, "EAX", "i386"};
  } else if (language.rfind("AARCH64", 0) == 0) {
    a = {"CallSupervisor", std::nullopt, "x8", {"x0", "x1", "x2", "x3", "x4", "x5"}, "x0", "generic"};
  } else if (language.rfind("ARM", 0) == 0) {
    a = {"software_interrupt", std::nullopt, "r7", {"r0", "r1", "r2", "r3", "r4", "r5"}, "r0", "arm"};
  } else if (language.rfind("RISCV", 0) == 0) {
    a = {"ecall", std::nullopt, "a7", {"a0", "a1", "a2", "a3", "a4", "a5"}, "a0", "generic"};
  } else {
    return std::nullopt;
  }
  return a;
}

std::uint64_t x86_rflags(const Emulator::Impl &m) {
  auto flag = [&](const char *name) -> std::uint64_t {
    auto i = m.find_reg(name);
    return i && m.get_reg(m.registers[*i]).lo() != 0 ? 1 : 0;
  };
  return flag("CF") | 0x2 | flag("PF") << 2 | flag("AF") << 4 | flag("ZF") << 6 | flag("SF") << 7 | flag("TF") << 8 |
         0x200 | flag("DF") << 10 | flag("OF") << 11;
}

void install_linux(Emulator &emu) {
  Emulator::Impl &m = emu.internals();
  if (!m.syscall_abi) m.syscall_abi = linux_syscall_abi(m.language);
  if (!m.syscall_abi) return;
  const std::string tname = m.syscall_abi->table;
  std::string machine = "x86_64";
  if (tname == "i386") machine = "i686";
  else if (tname == "arm") machine = "armv7l";
  else if (m.language.rfind("AARCH64", 0) == 0) machine = "aarch64";
  else if (m.language.rfind("RISCV", 0) == 0) machine = m.pointer_size == 8 ? "riscv64" : "riscv32";

  emu.on_syscall([tname, machine](Emulator &e, Syscall &sc) {
    Emulator::Impl &m = e.internals();
    const unsigned ptr = m.pointer_size;
    const auto &tab = table(tname);
    auto it = std::find_if(tab.begin(), tab.end(), [&](const Entry &x) { return x.number == sc.number; });
    auto err = [&](std::int64_t code) { sc.result = static_cast<std::uint64_t>(-code); };
    if (it == tab.end()) {
      if (m.options.unknown_syscalls_fail) {
        err(kENOSYS);
        sc.note = "syscall " + std::to_string(sc.number) + " = -ENOSYS";
        return HookAction::proceed;
      }
      sc.note = "unhandled system call " + std::to_string(sc.number);
      return HookAction::stop;
    }
    const auto &a = sc.args;
    auto read_buf = [&](std::uint64_t at, std::uint64_t n, std::string &out) {
      out.resize(n);
      return n == 0 || e.read_memory(at, std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(out.data()), n));
    };
    auto emit = [&](std::uint64_t fd, const std::string &data) -> bool {
      if (fd == 1) m.out += data;
      else if (fd == 2) m.err += data;
      else return false;
      return true;
    };
    auto put_word = [&](std::uint64_t at, std::uint32_t size, std::uint64_t v) { return e.write_word(at, size, v); };
    switch (it->call) {
      case Call::write: {
        std::string data;
        if (a[2] > (64u << 20)) err(kEINVAL);
        else if (!read_buf(a[1], a[2], data)) err(kEFAULT);
        else if (!emit(a[0], data)) err(kEBADF);
        else sc.result = a[2];
        break;
      }
      case Call::writev: {
        std::uint64_t total = 0;
        bool ok = true;
        for (std::uint64_t i = 0; i < a[2] && i < 1024 && ok; ++i) {
          auto base = e.read_word(a[1] + i * 2 * ptr, ptr), len = e.read_word(a[1] + i * 2 * ptr + ptr, ptr);
          std::string data;
          ok = base && len && *len <= (64u << 20) && read_buf(*base, *len, data);
          if (ok && !emit(a[0], data)) {
            err(kEBADF);
            ok = false;
            total = sc.result;
            break;
          }
          if (ok) total += *len;
        }
        if (ok) sc.result = total;
        else if (total == 0) err(kEFAULT);
        break;
      }
      case Call::read: {
        if (a[0] != 0) {
          err(kEBADF);
          break;
        }
        const std::string &in = m.options.stdin_data;
        const std::uint64_t n = std::min<std::uint64_t>(a[2], in.size() - std::min<std::uint64_t>(m.stdin_pos, in.size()));
        if (n > 0 && !e.write_memory(a[1], std::span<const std::uint8_t>(
                                               reinterpret_cast<const std::uint8_t *>(in.data() + m.stdin_pos), n))) {
          err(kEFAULT);
          break;
        }
        m.stdin_pos += n;
        sc.result = n;
        break;
      }
      case Call::exit:
      case Call::exit_group:
        sc.exited = true;
        sc.exit_code = static_cast<std::int32_t>(a[0]);
        sc.note = std::string(it->call == Call::exit ? "exit" : "exit_group") + "(" + std::to_string(sc.exit_code) + ")";
        return HookAction::proceed;
      case Call::brk: {
        std::uint64_t want = a[0];
        if (want > m.brk_start && want > m.brk) {
          const std::uint64_t old_end = align_up(m.brk, detail::kPageSize), new_end = align_up(want, detail::kPageSize);
          if (new_end > old_end) {
            try {
              e.map("heap", old_end, new_end - old_end, {true, true, false});
            } catch (const EmuError &) {
              want = m.brk;  // no room
            }
          }
        }
        if (want >= m.brk_start) m.brk = want;
        sc.result = m.brk;
        break;
      }
      case Call::mmap:
      case Call::mmap2: {
        const std::uint64_t len = align_up(a[1], detail::kPageSize);
        const std::uint64_t flags = a[3];
        const bool anonymous = (flags & 0x20) != 0, fixed = (flags & 0x10) != 0;
        if (len == 0) {
          err(kEINVAL);
          break;
        }
        if (!anonymous) {
          err(kENODEV);
          break;
        }
        std::optional<std::uint64_t> at;
        if (fixed) {
          e.unmap(a[0], len);
          at = a[0];
        } else {
          at = e.find_free(len, a[0] != 0 ? a[0] : m.mmap_hint);
          if (!at) at = e.find_free(len, 0x10000);
        }
        if (!at) {
          err(kENOMEM);
          break;
        }
        try {
          e.map("mmap_" + hexs(*at).substr(2), *at, len, {(a[2] & 1) != 0, (a[2] & 2) != 0, (a[2] & 4) != 0});
        } catch (const EmuError &) {
          err(kENOMEM);
          break;
        }
        if (!fixed) m.mmap_hint = *at + len;
        sc.result = *at;
        break;
      }
      case Call::munmap:
        e.unmap(a[0], align_up(a[1], detail::kPageSize));
        sc.result = 0;
        break;
      case Call::arch_prctl:
        if (a[0] == 0x1002 && m.find_reg("FS_OFFSET")) {
          e.write_register("FS_OFFSET", a[1]);
          sc.result = 0;
        } else if (a[0] == 0x1001 && m.find_reg("GS_OFFSET")) {
          e.write_register("GS_OFFSET", a[1]);
          sc.result = 0;
        } else if (a[0] == 0x1003 && m.find_reg("FS_OFFSET")) {
          sc.result = put_word(a[1], 8, e.read_register("FS_OFFSET")) ? 0 : static_cast<std::uint64_t>(-kEFAULT);
        } else {
          err(kEINVAL);
        }
        break;
      case Call::set_tls:
        if (m.find_reg("tpidruro")) e.write_register("tpidruro", a[0]);
        sc.result = 0;
        break;
      case Call::set_tid_address:
      case Call::getpid:
      case Call::gettid: sc.result = 1000; break;
      case Call::getppid: sc.result = 1; break;
      case Call::getuid:
      case Call::geteuid:
      case Call::getgid:
      case Call::getegid: sc.result = 1000; break;
      case Call::uname: {
        std::vector<std::uint8_t> buf(6 * 65, 0);
        const char *fields[] = {"Linux", "revkit", "6.0.0", "#1 revkit-emu", machine.c_str(), "(none)"};
        for (int i = 0; i < 6; ++i) std::memcpy(buf.data() + 65 * i, fields[i], std::strlen(fields[i]));
        sc.result = e.write_memory(a[0], buf) ? 0 : static_cast<std::uint64_t>(-kEFAULT);
        break;
      }
      case Call::clock_gettime:
      case Call::gettimeofday: {
        // A deterministic clock: a microsecond per thousand steps.
        const std::uint64_t ns = m.steps * 1000;
        const std::uint32_t word = ptr;
        bool ok = put_word(a[it->call == Call::clock_gettime ? 1 : 0], word, ns / 1000000000) &&
                  put_word(a[it->call == Call::clock_gettime ? 1 : 0] + word, word,
                           it->call == Call::clock_gettime ? ns % 1000000000 : (ns % 1000000000) / 1000);
        sc.result = ok ? 0 : static_cast<std::uint64_t>(-kEFAULT);
        break;
      }
      case Call::time: sc.result = m.steps / 1000000; break;
      case Call::getrandom: {
        std::vector<std::uint8_t> buf(std::min<std::uint64_t>(a[1], 256));
        for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<std::uint8_t>(0x5a ^ i);
        sc.result = e.write_memory(a[0], buf) ? buf.size() : static_cast<std::uint64_t>(-kEFAULT);
        break;
      }
      case Call::ioctl: err(kENOTTY); break;
      case Call::open:
      case Call::openat:
      case Call::access:
      case Call::faccessat:
      case Call::readlink:
      case Call::readlinkat: err(kENOENT); break;
      case Call::fstat:
      case Call::newfstatat:
      case Call::prlimit64:
      case Call::rseq:
      case Call::getcwd:
      case Call::lseek:
      case Call::set_thread_area: err(kENOSYS); break;
      case Call::close:
      case Call::mprotect:
      case Call::madvise:
      case Call::rt_sigaction:
      case Call::rt_sigprocmask:
      case Call::sigaltstack:
      case Call::set_robust_list:
      case Call::futex:
      case Call::sched_yield:
      case Call::nanosleep: sc.result = 0; break;
      case Call::kill:
      case Call::tgkill:
        sc.exited = true;
        sc.exit_code = 128 + static_cast<std::int32_t>(a[it->call == Call::kill ? 1 : 2]);
        sc.note = "killed by signal " + std::to_string(sc.exit_code - 128);
        return HookAction::proceed;
      case Call::exit_unknown: break;
    }
    if (tname == "x86_64" && m.find_reg("R11")) e.write_register("R11", x86_rflags(m));
    const char *name = call_name(it->call);
    std::ostringstream note;
    note << "syscall " << (name ? name : std::to_string(sc.number).c_str()) << "(";
    for (int i = 0; i < 3; ++i) note << (i ? ", " : "") << hexs(a[static_cast<std::size_t>(i)]);
    note << ") = " << static_cast<std::int64_t>(sc.result);
    sc.note = note.str();
    return HookAction::proceed;
  });
}

}  // namespace revkit::emu
