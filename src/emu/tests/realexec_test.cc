// The emulator against real execution: each program in programs/ runs
// natively (x86-64) or under qemu-user (AArch64, RISC-V 64), and in the
// emulator. They must agree on
//   - the registers at rk_finish (the program dumps them; the emulator
//     stops there on a breakpoint),
//   - the memory the program filled (rk_mem),
//   - stdout, stderr and the exit status.
// Differences the specs themselves cause are masked, each with its reason.
#include "util.hh"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

namespace revkit::emu {
namespace {

namespace fs = std::filesystem;

struct Case {
  std::string program, arch, opt;
};

std::string name_of(const ::testing::TestParamInfo<Case> &info) {
  return info.param.program + "_" + info.param.arch + "_" + info.param.opt;
}

std::vector<Case> cases() {
  std::vector<Case> out;
  for (const char *p : {"arith", "loops", "calls", "memory", "floats", "syscalls"})
    for (const char *a : {"x86_64", "aarch64", "riscv64"})
      for (const char *o : {"O0", "O2"}) out.push_back({p, a, o});
  return out;
}

// What rk_finish saves, slot by slot: the register's name in the emulator,
// and the bits to compare.
struct Slot {
  std::string reg;  // empty: composed (flags)
  std::uint64_t mask = ~std::uint64_t{0};
};

std::map<int, Slot> slots(const std::string &arch) {
  std::map<int, Slot> s;
  if (arch == "x86_64") {
    const char *names[] = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                           "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15"};
    for (int i = 0; i < 16; ++i) s[i] = {names[i]};
    // Ghidra's x86 spec leaves AF alone in most arithmetic, so it differs
    // from the hardware's; R11 holds RFLAGS after SYSCALL.
    s[11].mask = ~std::uint64_t{0x10};
    // RFLAGS by PUSHFQ: CF PF ZF SF IF DF OF. Bit 1 (always 1 on hardware)
    // and AF aren't in the spec's packflags.
    s[16] = {"", 0xec5};
  } else if (arch == "aarch64") {
    for (int i = 0; i <= 30; ++i) s[i] = {"x" + std::to_string(i)};
    s[31] = {"sp"};
    s[32] = {""};  // NZCV
  } else {
    const char *names[] = {"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0",
                           "a1",   "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5",
                           "s6",   "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
    for (int i = 1; i < 32; ++i) s[i] = {names[i]};
  }
  return s;
}

std::uint64_t composed_flags(const Emulator &e, const std::string &arch) {
  auto f = [&](const char *n) -> std::uint64_t { return e.read_register(n) != 0 ? 1 : 0; };
  if (arch == "x86_64")
    return f("CF") | f("PF") << 2 | f("AF") << 4 | f("ZF") << 6 | f("SF") << 7 | f("IF") << 9 | f("DF") << 10 |
           f("OF") << 11;
  return f("NG") << 31 | f("ZR") << 30 | f("CY") << 29 | f("OV") << 28;
}

// "label=hex" lines.
std::map<std::string, std::uint64_t> parse(const std::string &out) {
  std::map<std::string, std::uint64_t> m;
  std::istringstream in(out);
  std::string line;
  while (std::getline(in, line)) {
    auto eq = line.find('=');
    if (eq == std::string::npos || line.size() - eq - 1 != 16) continue;
    m[line.substr(0, eq)] = std::strtoull(line.c_str() + eq + 1, nullptr, 16);
  }
  return m;
}

class RealExecution : public ::testing::TestWithParam<Case> {};

TEST_P(RealExecution, MatchesTheMachine) {
  const Case &c = GetParam();
  if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  // Ghidra's RISC-V spec moves a double to an integer register (fmv.x.d)
  // through the address of a temporary, which reads the wrong register; -O2
  // uses that instruction (docs/emulator.md, "Limits").
  if (c.program == "floats" && c.arch == "riscv64" && c.opt == "O2") GTEST_SKIP() << "Ghidra's fmv.x.d";
  const fs::path bin = fs::path(REVKIT_EMU_PROGRAM_DIR) / (c.program + "-" + c.arch + "-" + c.opt);
  if (!fs::exists(bin)) GTEST_SKIP() << "no compiler for " << c.arch;
  std::string runner;
  if (c.arch == "aarch64") runner = REVKIT_QEMU_AARCH64;
  if (c.arch == "riscv64") runner = REVKIT_QEMU_RISCV64;
  if (c.arch != "x86_64" && runner.empty()) GTEST_SKIP() << "no qemu-user for " << c.arch;

  const fs::path err_file = fs::path(::testing::TempDir()) / (bin.filename().string() + ".stderr");
  int status = 0;
  const std::string native =
      testing::run_command((runner.empty() ? "" : runner + " ") + bin.string() + " </dev/null 2>" + err_file.string(), status);
  std::string native_err;
  {
    std::ifstream in(err_file);
    native_err.assign(std::istreambuf_iterator<char>(in), {});
  }
  ASSERT_GE(status, 0);

  auto image = std::make_shared<const loader::Image>(loader::load_file(bin));
  Options o;
  o.trace_capacity = 64;
  Emulator e(image, o);
  e.start(*image->entry);
  std::uint64_t finish = 0, mem = 0;
  for (const loader::Symbol &s : image->symbols) {
    if (s.name == "rk_finish") finish = s.value;
    if (s.name == "rk_mem") mem = s.value;
  }
  ASSERT_NE(finish, 0u);
  ASSERT_NE(mem, 0u);
  e.add_breakpoint(finish);
  RunOptions ro;
  ro.max_steps = 50000000;
  Stop s = e.run(ro);
  ASSERT_EQ(s.kind, StopKind::breakpoint) << to_string(s.kind) << ": " << s.detail;

  // Registers as the machine had them entering rk_finish.
  const auto dumped = parse(native);
  for (const auto &[index, slot] : slots(c.arch)) {
    char label[8];
    std::snprintf(label, sizeof label, "r%02d", index);
    auto it = dumped.find(label);
    ASSERT_NE(it, dumped.end()) << label;
    const std::uint64_t mine = slot.reg.empty() ? composed_flags(e, c.arch) : e.read_register(slot.reg);
    EXPECT_EQ(mine & slot.mask, it->second & slot.mask)
        << label << " (" << (slot.reg.empty() ? "flags" : slot.reg) << ")";
  }
  // Memory the program filled.
  for (int i = 0; i < 64; ++i) {
    char label[8];
    std::snprintf(label, sizeof label, "m%02d", i);
    auto word = e.read_word(mem + 8 * i, 8);
    ASSERT_TRUE(word);
    EXPECT_EQ(*word, dumped.at(label)) << label;
  }

  // The rest of the run: output (the register lines masked as above) and status.
  s = e.run(ro);
  ASSERT_EQ(s.kind, StopKind::exited) << to_string(s.kind) << ": " << s.detail;
  EXPECT_EQ(s.exit_code & 0xff, status);
  const auto emulated = parse(e.stdout_data());
  std::istringstream a(native), b(e.stdout_data());
  std::string la, lb;
  int lines = 0;
  const auto slot_map = slots(c.arch);
  while (std::getline(a, la)) {
    ASSERT_TRUE(static_cast<bool>(std::getline(b, lb))) << "emulator output ends before: " << la;
    ++lines;
    if (la.size() == 20 && la[0] == 'r' && la[3] == '=') {
      const int index = std::atoi(la.substr(1, 2).c_str());
      const std::uint64_t mask = slot_map.count(index) ? slot_map.at(index).mask : ~std::uint64_t{0};
      EXPECT_EQ(std::strtoull(la.c_str() + 4, nullptr, 16) & mask, std::strtoull(lb.c_str() + 4, nullptr, 16) & mask)
          << la << " vs " << lb;
    } else {
      EXPECT_EQ(la, lb);
    }
  }
  EXPECT_FALSE(static_cast<bool>(std::getline(b, lb))) << "emulator printed more: " << lb;
  EXPECT_GT(lines, 64);
  EXPECT_EQ(e.stderr_data(), native_err);
  EXPECT_GT(e.trace().summary().steps, 100u);
}

INSTANTIATE_TEST_SUITE_P(Programs, RealExecution, ::testing::ValuesIn(cases()), name_of);

// A dynamically linked, position-independent program: relocations applied,
// imports bound to stubs, __libc_start_main calling main, output through
// the printf/puts stubs.
TEST(LibraryStubs, DynamicProgramMatchesTheMachine) {
  if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  const fs::path bin = fs::path(REVKIT_EMU_PROGRAM_DIR) / "dynamic-x86_64";
  if (!fs::exists(bin)) GTEST_SKIP() << "no x86-64 compiler";
  int status = 0;
  const std::string native = testing::run_command(bin.string() + " </dev/null", status);
  auto image = std::make_shared<const loader::Image>(loader::load_file(bin, {std::nullopt, true}));
  Options o;
  o.argv = {bin.string()};
  Emulator e(image, o);
  e.start(*image->entry);
  Stop s = e.run({});
  ASSERT_EQ(s.kind, StopKind::exited) << to_string(s.kind) << ": " << s.detail;
  EXPECT_EQ(e.stdout_data(), native);
  EXPECT_EQ(s.exit_code, status);
  EXPECT_GE(e.trace().summary().stub_calls, 7u);
  ASSERT_TRUE(e.import_address("puts"));
}

// Static glibc: its start-up (TLS through arch_prctl or TPIDR, IRELATIVE
// resolvers that read CPUID or HWCAP), stdio and atexit, as on the machine.
TEST(StaticLibc, MatchesTheMachine) {
  if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  for (const std::string arch : {"x86_64", "aarch64"}) {
    const fs::path bin = fs::path(REVKIT_EMU_PROGRAM_DIR) / ("libc-" + arch);
    const std::string runner = arch == "aarch64" ? REVKIT_QEMU_AARCH64 : "";
    if (!fs::exists(bin) || (arch != "x86_64" && runner.empty())) continue;
    int status = 0;
    const std::string native = testing::run_command((runner.empty() ? "" : runner + " ") + bin.string() + " </dev/null", status);
    auto image = std::make_shared<const loader::Image>(loader::load_file(bin));
    Options o;
    o.argv = {bin.string()};
    Emulator e(image, o);
    e.start(*image->entry);
    RunOptions ro;
    ro.max_steps = 20000000;
    Stop s = e.run(ro);
    ASSERT_EQ(s.kind, StopKind::exited) << arch << ": " << to_string(s.kind) << ": " << s.detail;
    EXPECT_EQ(s.exit_code, status) << arch;
    EXPECT_EQ(e.stdout_data(), native) << arch;
    EXPECT_NE(native.find("3.142"), std::string::npos);
  }
}

// A call to an import without a built-in stub is skipped, returning the
// configured value; the prototype decides whether there is a value.
TEST(LibraryStubs, SkippedImportsReturnTheConfiguredValue) {
  if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  const fs::path bin = fs::path(REVKIT_EMU_PROGRAM_DIR) / "dynamic-x86_64";
  if (!fs::exists(bin)) GTEST_SKIP() << "no x86-64 compiler";
  auto image = std::make_shared<const loader::Image>(loader::load_file(bin, {std::nullopt, true}));
  Options o;
  o.import_return = 0x1234;
  o.library_stubs = false;  // strlen, malloc, ... are all skipped now
  o.prototypes = [](std::string_view name) -> std::optional<ImportPrototype> {
    ImportPrototype p;
    p.returns_value = name != "free" && name != "puts";
    return p;
  };
  Emulator e(image, o);
  e.start(*image->entry);
  Stop s = e.run({});
  // __libc_start_main is skipped too: it "returns" 0x1234 into _start,
  // which halts (hlt after the call).
  EXPECT_NE(s.kind, StopKind::unmapped) << s.detail;
  EXPECT_EQ(e.read_register("RAX"), 0x1234u);
  EXPECT_TRUE(e.stdout_data().empty());
  EXPECT_EQ(e.trace().summary().stub_calls, 1u);
}

}  // namespace
}  // namespace revkit::emu
