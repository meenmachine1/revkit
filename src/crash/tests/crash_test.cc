// revkit::crash on real ELF core files made at test time (a crashing
// program and its library under the host's kernel, or gcore when
// core_pattern hands cores to a helper; an AArch64 program under
// qemu-aarch64, which writes its guest's core), on 32-bit cores built here
// (i386 and ARM note layouts), on minidumps written by
// tests/data/crash/make_minidump.py for programs built with mingw, and on
// hostile bytes.
#include "revkit/crash/crash.hh"

#include <gtest/gtest.h>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <thread>

namespace revkit::crash {
namespace {

namespace fs = std::filesystem;

bool sh(const std::string &cmd) { return std::system(("set -e; { " + cmd + "; } >/dev/null 2>&1").c_str()) == 0; }
bool have(const std::string &tool) { return sh("command -v " + tool); }

std::vector<std::byte> slurp(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::string s((std::istreambuf_iterator<char>(in)), {});
  std::vector<std::byte> out(s.size());
  std::memcpy(out.data(), s.data(), s.size());
  return out;
}

class TempDir {
 public:
  TempDir() {
    std::string t = (fs::temp_directory_path() / "rk-crash-test-XXXXXX").string();
    if (!mkdtemp(t.data())) throw std::runtime_error("mkdtemp");
    path_ = t;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  const fs::path &path() const { return path_; }
  fs::path operator/(const std::string &s) const { return path_ / s; }

 private:
  fs::path path_;
};

const std::string kData = std::string(REVKIT_SOURCE_DIR) + "/tests/data/crash/";

std::uint64_t reg(const Thread &t, const std::string &name) {
  for (const Register &r : t.registers)
    if (r.name == name) {
      std::uint64_t v = 0;
      for (std::size_t i = 0; i < r.value.size() && i < 8; ++i) v |= std::uint64_t(r.value[i]) << (8 * i);
      return v;
    }
  ADD_FAILURE() << "no register " << name;
  return 0;
}

const Module *module(const CrashDump &d, const std::string &name) {
  for (const Module &m : d.modules)
    if (m.name == name) return &m;
  return nullptr;
}

// A core of tests/data/crash/crash.c crashing in libcrash.so: the kernel's
// when core_pattern writes a file, else gcore's of the program stopped
// (then the signal is the stop's, not the crash's).
struct HostCore {
  fs::path core;
  bool from_kernel = false;
};

std::optional<HostCore> make_host_core(const TempDir &d) {
  const std::string dir = d.path().string();
  if (!sh("cd " + dir + " && cc -O1 -g -shared -fPIC -o libcrash.so " + kData + "libcrash.c && cc -O1 -g -o crash " +
          kData + "crash.c -L. -lcrash -Wl,-rpath,'$ORIGIN' -pthread"))
    return std::nullopt;
  std::ifstream pat("/proc/sys/kernel/core_pattern");
  std::string pattern;
  std::getline(pat, pattern);
  HostCore out;
  if (!pattern.empty() && pattern[0] != '|') {
    // The kernel writes it relative to the cwd ("core", "core.%p").
    (void)!std::system(("cd " + dir + " && sh -c 'ulimit -c unlimited; exec ./crash' >/dev/null 2>&1").c_str());
    for (const auto &e : fs::directory_iterator(d.path()))
      if (e.path().filename().string().rfind("core", 0) == 0) {
        out.core = e.path();
        out.from_kernel = true;
        return out;
      }
  }
  if (!have("gcore")) return std::nullopt;
  const pid_t pid = fork();
  if (pid == 0) {
    if (chdir(dir.c_str()) != 0) _exit(1);
    execl("./crash", "./crash", "stop", static_cast<char *>(nullptr));
    _exit(127);
  }
  int status = 0;
  if (waitpid(pid, &status, WUNTRACED) != pid || !WIFSTOPPED(status)) return std::nullopt;
  const bool ok = sh("cd " + dir + " && gcore -o gcore " + std::to_string(pid));
  kill(pid, SIGKILL);
  waitpid(pid, &status, 0);
  if (!ok) return std::nullopt;
  out.core = d / ("gcore." + std::to_string(pid));
  if (!fs::exists(out.core)) return std::nullopt;
  return out;
}

TEST(ElfCore, ACrashOnTheHost) {
  TempDir d;
  auto hc = make_host_core(d);
  if (!hc) GTEST_SKIP() << "no core: cc, a core_pattern that writes files, or gcore needed";
  const std::vector<std::byte> bytes = slurp(hc->core);
  ASSERT_TRUE(is_elf_core(bytes));
  const CrashDump c = parse(bytes);
  EXPECT_EQ(c.format, Format::elf_core);
  EXPECT_EQ(c.arch, "x86-64");
  EXPECT_EQ(c.pointer_size, 8u);
  ASSERT_EQ(c.threads.size(), 2u);
  EXPECT_EQ(c.command, "crash");
  EXPECT_NE(c.pid, 0);
  const Module *exe = module(c, "crash"), *lib = module(c, "libcrash.so");
  ASSERT_NE(exe, nullptr);
  ASSERT_NE(lib, nullptr);
  EXPECT_TRUE(exe->main);
  EXPECT_FALSE(lib->main);
  EXPECT_NE(module(c, "libc.so.6"), nullptr);
  EXPECT_TRUE(c.auxv.contains(9));  // AT_ENTRY, in the program
  EXPECT_GE(c.auxv.at(9), exe->base);
  EXPECT_LT(c.auxv.at(9) - exe->base, exe->size);
  const Thread &t = c.threads[c.crashed_thread];
  EXPECT_EQ(t.registers.size(), 27u);
  if (hc->from_kernel) {
    EXPECT_EQ(c.signal, 11);
    EXPECT_EQ(c.signal_name, "SIGSEGV");
    EXPECT_EQ(c.code_name, "SEGV_MAPERR");
    ASSERT_TRUE(c.fault_address);
    EXPECT_EQ(*c.fault_address, 0u);
    EXPECT_EQ(c.reason, "SIGSEGV (SEGV_MAPERR) at 0x0");
    EXPECT_EQ(c.crashed_thread, 0u);
    EXPECT_EQ(c.threads[0].signal, 11);
    // The pc is in libcrash.so's code; rdi (where) is null.
    const std::uint64_t pc = reg(t, "rip");
    EXPECT_EQ(c.module_at(pc), lib);
    EXPECT_EQ(reg(t, "rdi"), 0u);
    // Its code page wasn't dumped (a file-backed mapping); the stack was.
    std::uint8_t code[4];
    std::vector<std::pair<std::uint32_t, std::uint32_t>> missing;
    EXPECT_EQ(c.read(bytes, pc, code, &missing), 0u);
    ASSERT_EQ(missing.size(), 1u);
    std::uint8_t stack[64];
    missing.clear();
    EXPECT_EQ(c.read(bytes, reg(t, "rsp"), stack, &missing), sizeof stack);
    EXPECT_TRUE(missing.empty());
  }
  // The second thread waits in libc.
  EXPECT_EQ(c.module_at(reg(c.threads[1], "rip")), module(c, "libc.so.6"));
  // Mapped files with their offsets.
  bool lib_text = false;
  for (const MappedFile &f : c.files)
    if (f.path.ends_with("/libcrash.so") && f.file_offset != 0) lib_text = true;
  EXPECT_TRUE(lib_text);
  for (const std::string &w : c.warnings) ADD_FAILURE() << w;
}

TEST(ElfCore, AArch64UnderQemu) {
  if (!have("qemu-aarch64") || !have("aarch64-linux-gnu-gcc")) GTEST_SKIP() << "needs qemu-aarch64 and aarch64-linux-gnu-gcc";
  TempDir d;
  const std::string dir = d.path().string();
  {
    std::ofstream src(d / "seg.c");
    src << "__attribute__((noinline)) int store(int *p, int v) { *p = v; return v; }\n"
           "__attribute__((noinline)) int outer(int *p) { return store(p, 42) + 1; }\n"
           "int main(void) { return outer((int *)0); }\n";
  }
  ASSERT_TRUE(sh("cd " + dir + " && aarch64-linux-gnu-gcc -O1 -static -o seg seg.c"));
  (void)!std::system(("cd " + dir + " && sh -c 'ulimit -c unlimited; exec qemu-aarch64 ./seg' >/dev/null 2>&1").c_str());
  fs::path core;
  for (const auto &e : fs::directory_iterator(d.path()))
    if (e.path().filename().string().rfind("qemu_seg", 0) == 0) core = e.path();
  if (core.empty()) GTEST_SKIP() << "qemu-aarch64 wrote no core";
  const std::vector<std::byte> bytes = slurp(core);
  const CrashDump c = parse(bytes);
  EXPECT_EQ(c.arch, "AArch64");
  ASSERT_EQ(c.threads.size(), 1u);
  EXPECT_EQ(c.signal, 11);
  EXPECT_EQ(c.command, "seg");
  const Thread &t = c.threads[0];
  ASSERT_EQ(t.registers.size(), 34u);
  EXPECT_EQ(t.registers.back().name, "cpsr");
  EXPECT_EQ(reg(t, "x0"), 0u);   // p
  EXPECT_EQ(reg(t, "x1"), 42u);  // v
  // qemu leaves read-only code out too; the stack is there.
  std::uint8_t insn[4], stack[16];
  EXPECT_EQ(c.read(bytes, reg(t, "pc"), insn), 0u);
  EXPECT_EQ(c.read(bytes, reg(t, "sp"), stack), sizeof stack);
}

// A 32-bit core as the kernel writes one: PT_NOTE (NT_PRSTATUS with
// pr_reg at 72, NT_PRPSINFO of 124 bytes with 16-bit ids, NT_SIGINFO with
// si_addr at 12, NT_AUXV, NT_FILE) and a PT_LOAD of stack.
std::vector<std::byte> core32(std::uint16_t machine, const std::vector<std::uint32_t> &regs, std::uint32_t pc_index) {
  std::string notes;
  auto note = [&](std::uint32_t type, const std::string &desc) {
    auto put = [&](std::uint32_t v) { notes.append(reinterpret_cast<const char *>(&v), 4); };
    put(5);
    put(static_cast<std::uint32_t>(desc.size()));
    put(type);
    notes += std::string("CORE\0\0\0\0", 8);
    notes += desc;
    while (notes.size() % 4) notes += '\0';
  };
  auto u32 = [](std::uint32_t v) { return std::string(reinterpret_cast<const char *>(&v), 4); };
  std::string prs(72 + 4 * regs.size() + 4, '\0');
  prs[0] = 11;      // si_signo
  prs[12] = 11;     // pr_cursig
  std::memcpy(prs.data() + 24, "\x39\x30\0\0", 4);  // pr_pid 12345
  for (std::size_t i = 0; i < regs.size(); ++i) std::memcpy(prs.data() + 72 + 4 * i, &regs[i], 4);
  note(1, prs);
  std::string ps(124, '\0');
  ps[8] = static_cast<char>(0xe8), ps[9] = 0x03;  // uid 1000
  std::memcpy(ps.data() + 28, "crash32", 7);
  std::memcpy(ps.data() + 44, "./crash32 -x", 12);
  note(3, ps);
  std::string si(128, '\0');
  si[0] = 11;
  si[8] = 2;  // SEGV_ACCERR
  std::memcpy(si.data() + 12, "\x00\x10\x00\x00", 4);  // si_addr 0x1000
  note(0x53494749, si);
  note(6, u32(9) + u32(0x8048100) + u32(0) + u32(0));
  std::string files = u32(1) + u32(4096) + u32(0x8048000) + u32(0x8049000) + u32(0) + "/usr/bin/crash32" + std::string(1, '\0');
  note(0x46494c45, files);
  const std::uint32_t phoff = 52, ph = 32, nph = 2;
  const std::uint32_t notes_off = phoff + ph * nph;
  const std::uint32_t load_off = (notes_off + static_cast<std::uint32_t>(notes.size()) + 0xfff) & ~0xfffu;
  std::string f(load_off + 0x1000, '\0');
  const unsigned char ident[] = {0x7f, 'E', 'L', 'F', 1, 1, 1, 0};
  std::memcpy(f.data(), ident, 8);
  auto w16 = [&](std::size_t o, std::uint16_t v) { std::memcpy(f.data() + o, &v, 2); };
  auto w32 = [&](std::size_t o, std::uint32_t v) { std::memcpy(f.data() + o, &v, 4); };
  w16(16, 4);
  w16(18, machine);
  w32(20, 1);
  w32(28, phoff);
  w16(40, 52);
  w16(42, ph);
  w16(44, nph);
  w32(phoff, 4);  // PT_NOTE
  w32(phoff + 4, notes_off);
  w32(phoff + 16, static_cast<std::uint32_t>(notes.size()));
  w32(phoff + ph, 1);  // PT_LOAD: the stack at 0xbffff000
  w32(phoff + ph + 4, load_off);
  w32(phoff + ph + 8, 0xbffff000);
  w32(phoff + ph + 16, 0x1000);
  w32(phoff + ph + 20, 0x1000);
  w32(phoff + ph + 24, 6);
  std::memcpy(f.data() + notes_off, notes.data(), notes.size());
  std::memcpy(f.data() + load_off, "STACK", 5);
  (void)pc_index;
  std::vector<std::byte> out(f.size());
  std::memcpy(out.data(), f.data(), f.size());
  return out;
}

TEST(ElfCore, ThirtyTwoBit) {
  std::vector<std::uint32_t> x86(17);
  for (std::size_t i = 0; i < x86.size(); ++i) x86[i] = 0x100 + static_cast<std::uint32_t>(i);
  x86[12] = 0x8048123;  // eip
  x86[15] = 0xbffff800;  // esp
  const auto b = core32(3, x86, 12);
  const CrashDump c = parse(b);
  EXPECT_EQ(c.arch, "x86");
  EXPECT_EQ(c.pointer_size, 4u);
  ASSERT_EQ(c.threads.size(), 1u);
  EXPECT_EQ(c.threads[0].id, 12345u);
  EXPECT_EQ(reg(c.threads[0], "eip"), 0x8048123u);
  EXPECT_EQ(reg(c.threads[0], "esp"), 0xbffff800u);
  EXPECT_EQ(reg(c.threads[0], "ebx"), 0x100u);
  EXPECT_EQ(c.reason, "SIGSEGV (SEGV_ACCERR) at 0x1000");
  EXPECT_EQ(c.uid, 1000u);
  EXPECT_EQ(c.command, "crash32");
  EXPECT_EQ(c.args, "./crash32 -x");
  ASSERT_EQ(c.modules.size(), 1u);
  EXPECT_EQ(c.modules[0].name, "crash32");
  EXPECT_TRUE(c.modules[0].main);
  std::uint8_t s[5];
  EXPECT_EQ(c.read(b, 0xbffff000, s), 5u);
  EXPECT_EQ(std::memcmp(s, "STACK", 5), 0);

  std::vector<std::uint32_t> arm(18);
  for (std::size_t i = 0; i < arm.size(); ++i) arm[i] = static_cast<std::uint32_t>(i);
  arm[15] = 0x10450;  // pc
  arm[16] = 0x60000030;  // cpsr: Thumb
  const CrashDump a = parse(core32(40, arm, 15));
  EXPECT_EQ(a.arch, "ARM");
  ASSERT_EQ(a.threads.at(0).registers.size(), 18u);
  EXPECT_EQ(reg(a.threads[0], "pc"), 0x10450u);
  EXPECT_EQ(reg(a.threads[0], "lr"), 14u);
  EXPECT_EQ(reg(a.threads[0], "cpsr"), 0x60000030u);
}

std::optional<fs::path> minidump(const TempDir &d, const std::string &arch, const std::string &compiler) {
  std::string pe;
  if (!compiler.empty()) {
    if (!have(compiler)) return std::nullopt;
    pe = (d / ("win-" + arch + ".exe")).string();
    if (!sh(compiler + " -O1 -o " + pe + " " + kData + "win.c")) return std::nullopt;
  }
  const fs::path out = d / (arch + ".dmp");
  if (!sh("python3 -I " + kData + "make_minidump.py " + out.string() + " --arch " + arch + (pe.empty() ? "" : " --pe " + pe)))
    return std::nullopt;
  return out;
}

TEST(Minidump, X86_64FromMingw) {
  TempDir d;
  auto path = minidump(d, "amd64", "x86_64-w64-mingw32-gcc");
  if (!path) GTEST_SKIP() << "needs x86_64-w64-mingw32-gcc and python3";
  const std::vector<std::byte> b = slurp(*path);
  ASSERT_TRUE(is_minidump(b));
  const CrashDump c = parse(b);
  EXPECT_EQ(c.format, Format::minidump);
  EXPECT_EQ(c.arch, "x86-64");
  EXPECT_EQ(c.os, "Windows 10.0.19045");
  EXPECT_EQ(c.cpu, "x86-64, 8 processors");
  EXPECT_EQ(c.pid, 4242);
  ASSERT_EQ(c.threads.size(), 2u);
  EXPECT_EQ(c.threads[0].name, "main thread");
  EXPECT_EQ(c.threads[1].name, "worker");
  EXPECT_EQ(c.crashed_thread, 0u);
  EXPECT_EQ(c.exception_code, 0xC0000005u);
  EXPECT_EQ(c.exception_name, "EXCEPTION_ACCESS_VIOLATION");
  EXPECT_EQ(c.access, "write");
  ASSERT_TRUE(c.fault_address);
  EXPECT_EQ(*c.fault_address, 0u);
  const Thread &t = c.threads[0];
  EXPECT_EQ(*c.exception_address, reg(t, "rip"));
  EXPECT_EQ(reg(t, "rcx"), 0u);
  EXPECT_EQ(reg(t, "rdx"), 7u);
  ASSERT_EQ(c.modules.size(), 2u);
  const Module &m = c.modules[0];
  EXPECT_EQ(m.name, "win-amd64.exe");
  EXPECT_EQ(m.path, "C:\\build\\win-amd64.exe");
  EXPECT_TRUE(m.main);
  EXPECT_EQ(m.version, "1.2.3.4");
  EXPECT_EQ(m.pdb_name, "win.pdb");
  EXPECT_EQ(m.pdb_guid, "123456789ABCDEF001020304050607083");
  EXPECT_EQ(c.modules[1].name, "KERNEL32.DLL");
  EXPECT_EQ(c.modules[1].version, "10.0.19041.1");
  EXPECT_EQ(c.module_at(reg(t, "rip")), &c.modules[0]);
  EXPECT_EQ(c.reason, "EXCEPTION_ACCESS_VIOLATION (write of 0x0) at 0x" + [&] {
    char h[24];
    std::snprintf(h, sizeof h, "%llx", static_cast<unsigned long long>(reg(t, "rip")));
    return std::string(h);
  }());
  // The stack: the return address into caller at rsp.
  std::uint8_t ret[8];
  EXPECT_EQ(c.read(b, reg(t, "rsp"), ret), 8u);
  std::uint64_t r = 0;
  std::memcpy(&r, ret, 8);
  EXPECT_EQ(c.module_at(r), &c.modules[0]);
  // The heap from Memory64, with memory info's protection.
  std::uint8_t heap[4];
  EXPECT_EQ(c.read(b, 0x20000000, heap), 4u);
  EXPECT_EQ(std::memcmp(heap, "HEAP", 4), 0);
  for (const Segment &s : c.memory) EXPECT_EQ(s.perms, "rw-");
  // The code isn't in the dump.
  std::vector<std::pair<std::uint32_t, std::uint32_t>> missing;
  std::uint8_t code[2];
  EXPECT_EQ(c.read(b, reg(t, "rip"), code, &missing), 0u);
  EXPECT_EQ(c.comments, std::vector<std::string>{"revkit test dump"});
  for (const std::string &w : c.warnings) ADD_FAILURE() << w;
}

TEST(Minidump, X86FromMingwAndArm64) {
  TempDir d;
  if (auto path = minidump(d, "x86", "i686-w64-mingw32-gcc")) {
    const std::vector<std::byte> b = slurp(*path);
    const CrashDump c = parse(b);
    EXPECT_EQ(c.arch, "x86");
    EXPECT_EQ(c.pointer_size, 4u);
    const Thread &t = c.threads.at(0);
    EXPECT_EQ(reg(t, "eax"), 7u);
    EXPECT_EQ(reg(t, "edx"), 0u);
    EXPECT_EQ(*c.exception_address, reg(t, "eip"));
    EXPECT_EQ(c.module_at(reg(t, "eip")), &c.modules.at(0));
    std::uint8_t ret[4];
    EXPECT_EQ(c.read(b, reg(t, "esp"), ret), 4u);
  }
  auto path = minidump(d, "arm64", "");
  if (!path) GTEST_SKIP();
  const CrashDump a = parse(slurp(*path));
  EXPECT_EQ(a.arch, "AArch64");
  const Thread &t = a.threads.at(0);
  EXPECT_EQ(t.registers.size(), 34u);
  EXPECT_EQ(reg(t, "pc"), 0x140001000u);
  EXPECT_EQ(reg(t, "x1"), 7u);
  EXPECT_EQ(reg(t, "cpsr"), 0x60000000u);
}

template <class Fn>
void Hostile(const std::vector<std::byte> &good, Fn &&fn) {
  for (std::size_t n = 0; n < good.size(); n += std::max<std::size_t>(1, good.size() / 300)) {
    std::vector<std::byte> t(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(n));
    try {
      fn(t);
    } catch (const Error &) {
    }
  }
  std::mt19937 rng(77);
  for (int i = 0; i < 300; ++i) {
    std::vector<std::byte> t = good;
    for (int k = 0; k < 1 + i % 6; ++k) t[rng() % std::min<std::size_t>(t.size(), 1 << 16)] = std::byte(rng() & 0xff);
    try {
      fn(t);
    } catch (const Error &) {
    }
  }
}

TEST(CrashDumps, HostileInput) {
  auto check = [](const std::vector<std::byte> &b) {
    const CrashDump c = parse(b);
    std::uint8_t buf[64];
    for (const Thread &t : c.threads)
      for (const Register &r : t.registers)
        if (r.name == "rsp" || r.name == "esp" || r.name == "sp") {
          std::uint64_t v = 0;
          for (std::size_t i = 0; i < r.value.size(); ++i) v |= std::uint64_t(r.value[i]) << (8 * i);
          c.read(b, v, buf);
        }
  };
  std::vector<std::uint32_t> x86(17, 1);
  Hostile(core32(3, x86, 12), check);
  TempDir d;
  if (auto path = minidump(d, "arm64", "")) Hostile(slurp(*path), check);
  if (auto path = minidump(d, "amd64", "x86_64-w64-mingw32-gcc")) Hostile(slurp(*path), check);
  EXPECT_THROW(parse(std::vector<std::byte>(16)), Error);
}

// Bug scrub part 3: program headers that all name one note segment read
// its notes once (2,000 headers to one NT_FILE: one file, one thread).
TEST(CrashDumps, NotesNamedTwiceAreReadOnce) {
  std::vector<std::uint32_t> x86(17, 1);
  std::vector<std::byte> b = core32(3, x86, 12);
  auto r32 = [&](std::size_t o) {
    std::uint32_t v;
    std::memcpy(&v, b.data() + o, 4);
    return v;
  };
  const std::uint32_t phoff = r32(28);
  std::vector<std::byte> note(b.begin() + phoff, b.begin() + phoff + 32), load(b.begin() + phoff + 32, b.begin() + phoff + 64);
  const std::uint32_t at = static_cast<std::uint32_t>(b.size());
  b.insert(b.end(), load.begin(), load.end());
  for (int i = 0; i < 2000; ++i) b.insert(b.end(), note.begin(), note.end());
  const std::uint32_t n = 2001;
  std::memcpy(b.data() + 28, &at, 4);
  std::memcpy(b.data() + 44, &n, 2);
  const CrashDump c = parse(b);
  EXPECT_EQ(c.threads.size(), 1u);
  EXPECT_EQ(c.files.size(), 1u);
  ASSERT_EQ(c.modules.size(), 1u);
  EXPECT_EQ(c.modules[0].name, "crash32");
}

// Bug scrub part 3: a minidump's memory list of 200,000 ranges and a memory
// info list of as many ranges that each cover all of them: the duplicate
// check and the protections are no longer n x m (4 x 10^10 steps).
TEST(CrashDumps, MinidumpListsAreNotQuadratic) {
  constexpr std::uint32_t kN = 200000;
  std::vector<std::byte> b;
  auto u32 = [&](std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(std::byte(v >> (8 * i) & 0xff));
  };
  auto u64 = [&](std::uint64_t v) {
    u32(static_cast<std::uint32_t>(v));
    u32(static_cast<std::uint32_t>(v >> 32));
  };
  const std::uint32_t mem = 32 + 2 * 12, mem_size = 4 + 16 * kN;
  const std::uint32_t info = mem + mem_size, info_size = 16 + 48 * kN;
  u32(0x504d444d);  // MDMP
  u32(0xa793);
  u32(2);   // streams
  u32(32);  // directory
  u32(0);
  u32(0);
  u64(0);
  u32(5), u32(mem_size), u32(mem);         // MemoryListStream
  u32(16), u32(info_size), u32(info);      // MemoryInfoListStream
  u32(kN);
  for (std::uint32_t i = 0; i < kN; ++i) u64(0x10000ull * (i + 1)), u32(0x1000), u32(0);
  u32(16), u32(48), u64(kN);
  for (std::uint32_t i = 0; i < kN; ++i) {
    u64(0), u64(0), u32(0x04), u32(0), u64(~0ull >> 1), u32(0x1000), u32(0x04), u32(0x20000), u32(0);
  }
  const auto start = std::chrono::steady_clock::now();
  const CrashDump c = parse(b);
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(60));
  EXPECT_EQ(c.memory.size(), kN);
  EXPECT_EQ(c.memory[0].perms, "rw-");
}

TEST(CrashDumps, Names) {
  EXPECT_EQ(signal_name(11), "SIGSEGV");
  EXPECT_EQ(signal_name(6), "SIGABRT");
  EXPECT_EQ(signal_name(40), "SIGRT6");
  EXPECT_EQ(signal_code_name(11, 1), "SEGV_MAPERR");
  EXPECT_EQ(signal_code_name(7, 1), "BUS_ADRALN");
  EXPECT_EQ(signal_code_name(8, 1), "FPE_INTDIV");
  EXPECT_EQ(signal_code_name(6, -6), "SI_TKILL");
  EXPECT_EQ(exception_name(0xC00000FD), "EXCEPTION_STACK_OVERFLOW");
  EXPECT_EQ(exception_name(0x12345678), "exception 0x12345678");
}

}  // namespace
}  // namespace revkit::crash
