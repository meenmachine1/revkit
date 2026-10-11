# @category Analysis/System calls
# @description Comments every system call instruction with the call's name, from the number
# @description loaded into the syscall register just before it (Linux x86-64, x86, AArch64, ARM).
# @context program
# @arg dry_run:bool=false Report without commenting
"""Comment syscalls (ListInstructions over the executable blocks)."""
from revkit.script import *

X86_64 = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 6: "lstat", 7: "poll", 8: "lseek",
    9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
    15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev", 21: "access",
    22: "pipe", 23: "select", 24: "sched_yield", 25: "mremap", 26: "msync", 27: "mincore", 28: "madvise",
    32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep", 37: "alarm", 39: "getpid", 40: "sendfile",
    41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
    48: "shutdown", 49: "bind", 50: "listen", 51: "getsockname", 52: "getpeername", 53: "socketpair",
    54: "setsockopt", 55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill", 63: "uname", 72: "fcntl", 73: "flock", 74: "fsync", 75: "fdatasync",
    76: "truncate", 77: "ftruncate", 78: "getdents", 79: "getcwd", 80: "chdir", 81: "fchdir", 82: "rename",
    83: "mkdir", 84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink", 89: "readlink",
    90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 95: "umask", 96: "gettimeofday", 97: "getrlimit",
    98: "getrusage", 99: "sysinfo", 101: "ptrace", 102: "getuid", 104: "getgid", 105: "setuid", 106: "setgid",
    107: "geteuid", 108: "getegid", 109: "setpgid", 110: "getppid", 111: "getpgrp", 112: "setsid",
    157: "prctl", 158: "arch_prctl", 186: "gettid", 200: "tkill", 201: "time", 202: "futex",
    217: "getdents64", 218: "set_tid_address", 228: "clock_gettime", 230: "clock_nanosleep",
    231: "exit_group", 234: "tgkill", 257: "openat", 262: "newfstatat", 273: "set_robust_list",
    302: "prlimit64", 318: "getrandom", 319: "memfd_create", 322: "execveat", 334: "rseq", 435: "clone3",
}
I386 = {1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve", 20: "getpid",
        37: "kill", 45: "brk", 54: "ioctl", 90: "mmap", 91: "munmap", 102: "socketcall", 125: "mprotect",
        162: "nanosleep", 192: "mmap2", 252: "exit_group"}
AARCH64 = {17: "getcwd", 23: "dup", 24: "dup3", 25: "fcntl", 29: "ioctl", 35: "unlinkat", 56: "openat",
           57: "close", 62: "lseek", 63: "read", 64: "write", 66: "writev", 93: "exit", 94: "exit_group",
           96: "set_tid_address", 98: "futex", 101: "nanosleep", 113: "clock_gettime", 124: "sched_yield",
           129: "kill", 134: "rt_sigaction", 135: "rt_sigprocmask", 160: "uname", 172: "getpid",
           173: "getppid", 174: "getuid", 178: "gettid", 198: "socket", 203: "connect", 214: "brk",
           215: "munmap", 220: "clone", 221: "execve", 222: "mmap", 226: "mprotect", 278: "getrandom"}
ARM = {1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve", 20: "getpid",
       37: "kill", 45: "brk", 54: "ioctl", 91: "munmap", 125: "mprotect", 192: "mmap2", 248: "exit_group",
       281: "socket", 283: "connect"}

lang = current_program.summary().language.language_id
if lang.startswith("x86:LE:64"):
    table, number_regs, is_syscall = X86_64, {"EAX", "RAX"}, lambda i: i.mnemonic.upper() == "SYSCALL"
elif lang.startswith("x86:LE:32"):
    table, number_regs = I386, {"EAX"}
    is_syscall = lambda i: i.mnemonic.upper() == "INT" and any(t.kind == 3 and t.value == 0x80 for t in i.tokens)
elif lang.startswith("AARCH64"):
    table, number_regs, is_syscall = AARCH64, {"x8", "w8"}, lambda i: i.mnemonic.lower() == "svc"
elif lang.startswith("ARM"):
    table, number_regs, is_syscall = ARM, {"r7"}, lambda i: i.mnemonic.lower() in ("svc", "swi")
else:
    raise SystemExit(f"comment_syscalls: no syscall table for {lang}")


def loaded_number(insn):
    """The constant a mov-like instruction puts in the syscall register, or None."""
    regs = [t.text for t in insn.tokens if t.kind == 2]
    scalars = [t.value for t in insn.tokens if t.kind == 3]
    if not regs or regs[0] not in number_regs:
        return None
    if insn.mnemonic.lower() in ("mov", "movz", "movs") and len(regs) == 1 and len(scalars) == 1:
        return scalars[0]
    if insn.mnemonic.upper() == "XOR" and len(regs) == 2 and regs[0] == regs[1]:
        return 0
    return -1  # the register is set some other way


blocks = [b for b in current_program.memory_map() if b.execute and b.initialized]
found = 0
for b in blocks:
    monitor.message(f"Scanning {b.name}")
    window = []
    for insn in instructions(b.range.first.offset, b.range.last.offset, pcode=False):
        monitor.check_cancelled()
        if is_syscall(insn):
            number = None
            for prev in reversed(window):
                n = loaded_number(prev)
                if n is not None:
                    number = n if n >= 0 else None
                    break
            name = table.get(number) if number is not None else None
            text = f"syscall {name} ({number})" if name else (f"syscall {number}" if number is not None else "syscall (number unknown)")
            print(f"0x{insn.address.offset:x}: {text}")
            if not args["dry_run"]:
                comment(insn.address, text)
            found += 1
            window = []
            continue
        if insn.flow in (2, 3, 4, 5, 6, 7):  # anything but fall-through ends the window
            window = []
        else:
            window = (window + [insn])[-8:]
print(f"{found} system call(s)")
