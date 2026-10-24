// CrashTarget over a dump built here (docs/crash-dumps.md): registers by
// SLEIGH name and the derived flags, threads, memory as dumped and from the
// backing, the stop, refusals; and the CFI interpreter's remember/restore
// state, which GCC's epilogues rely on to bring the CFA back.
#include "revkit/debug/crash_target.hh"
#include "revkit/debug/unwind.hh"

#include <gtest/gtest.h>

#include <cstring>

namespace revkit::debug {
namespace {

std::vector<std::uint8_t> le(std::uint64_t v, unsigned n) {
  std::vector<std::uint8_t> out(n);
  for (unsigned i = 0; i < n; ++i) out[i] = static_cast<std::uint8_t>(v >> (8 * i));
  return out;
}

crash::CrashDump dump(std::vector<std::byte> &file) {
  crash::CrashDump d;
  d.format = crash::Format::elf_core;
  d.arch = "x86-64";
  d.machine = 62;
  d.signal = 11;
  d.signal_name = "SIGSEGV";
  d.fault_address = 0x10;
  d.reason = "SIGSEGV (SEGV_MAPERR) at 0x10";
  for (std::uint64_t tid : {100u, 101u}) {
    crash::Thread t;
    t.id = tid;
    t.registers = {{"rax", le(tid, 8), "general"}, {"rsp", le(0x7000 + tid, 8), "general"},
                   {"rip", le(0x401000 + tid, 8), "general"}, {"eflags", le(0x41, 8), "flags"}};
    d.threads.push_back(t);
  }
  file.assign(0x200, std::byte{0xcc});
  std::memcpy(file.data() + 0x100, "STACKDATA", 9);
  d.memory = {{0x7000, 0x100, 0x100, 0x100, "rw-"}, {0x401000, 0x1000, 0, 0, "r-x"}};
  crash::Module m;
  m.name = "prog";
  m.path = "/bin/prog";
  m.base = 0x400000;
  m.size = 0x3000;
  m.main = true;
  d.modules = {m};
  return d;
}

TEST(CrashTarget, ReadsTheDump) {
  std::vector<std::byte> file;
  crash::CrashDump d = dump(file);
  CrashTargetOptions o;
  o.language = "x86:LE:64:default";
  o.sleigh_registers = {{"RAX", 8}, {"RSP", 8}, {"RIP", 8}, {"rflags", 8}, {"ZF", 1}};
  o.description = "core of prog";
  CrashTarget t(nullptr, file, d, o);
  EXPECT_EQ(t.kind(), "crash-dump");
  EXPECT_EQ(t.state(), TargetState::stopped);
  EXPECT_EQ(t.pc_register(), "RIP");
  EXPECT_EQ(t.sp_register(), "RSP");
  EXPECT_EQ(t.last_stop().kind, StopKind::signal);
  EXPECT_EQ(t.last_stop().signal, 11);
  EXPECT_EQ(*t.last_stop().address, 0x10u);
  EXPECT_EQ(t.last_stop().pc, 0x401064u);
  EXPECT_EQ(t.last_stop().thread, "100");
  EXPECT_EQ(t.read_register_u64("RAX"), 100u);
  EXPECT_EQ(t.read_register_u64("rax"), 100u);
  EXPECT_EQ(t.read_register_u64("ZF"), 1u);  // bit 6 of eflags 0x41
  EXPECT_EQ(t.read_register_u64("CF"), 1u);
  ASSERT_EQ(t.threads().size(), 2u);
  EXPECT_TRUE(t.threads()[0].current);
  t.select_thread("101");
  EXPECT_EQ(t.current_thread(), "101");
  EXPECT_EQ(t.read_register_u64("RAX"), 101u);
  EXPECT_THROW(t.select_thread("7"), DebugError);
  // Memory: the stack as dumped; code from the backing; the rest unreadable.
  std::uint8_t buf[9];
  std::vector<ByteRange> bad;
  EXPECT_EQ(t.read_memory(0x7000, buf, &bad), 9u);
  EXPECT_TRUE(bad.empty());
  EXPECT_EQ(std::memcmp(buf, "STACKDATA", 9), 0);
  EXPECT_EQ(t.read_memory(0x401000, buf, &bad), 0u);
  EXPECT_EQ(bad.size(), 1u);
  t.set_backing([](std::uint64_t at, std::span<std::uint8_t> out) -> std::size_t {
    if (at < 0x401000) return 0;
    const std::size_t n = std::min<std::size_t>(out.size(), 4);
    for (std::size_t i = 0; i < n; ++i) out[i] = 0x90;
    return n;
  });
  bad.clear();
  EXPECT_EQ(t.read_memory(0x401000, buf, &bad), 4u);
  ASSERT_EQ(bad.size(), 1u);
  EXPECT_EQ(bad[0].offset, 4u);
  EXPECT_EQ(buf[0], 0x90);
  EXPECT_EQ(buf[4], 0);
  // Read-only.
  EXPECT_THROW(t.resume({}), DebugError);
  EXPECT_THROW(t.write_register("RAX", le(1, 8)), DebugError);
  EXPECT_THROW(t.insert_breakpoint(BreakKind::software, 0x401000, 1), DebugError);
  ASSERT_EQ(t.modules().size(), 1u);
  EXPECT_TRUE(t.modules()[0].main);
  ASSERT_EQ(t.memory_map().size(), 2u);
  EXPECT_EQ(t.memory_map()[1].perms, "r-x");
}

TEST(Cfi, RestoreStateBringsBackTheCfa) {
  // A CIE (code align 1, data align -8, ra 16; CFA = rsp+8, ra at cfa-8) and
  // an FDE: push rbp (cfa+16, rbp at cfa-16), mov rbp,rsp (cfa = rbp+16),
  // then an epilogue in the middle of the function: remember, cfa = rsp+8,
  // ret, restore.
  std::vector<std::uint8_t> s;
  auto u32 = [&](std::uint32_t v) { for (int i = 0; i < 4; ++i) s.push_back(static_cast<std::uint8_t>(v >> (8 * i))); };
  auto u64 = [&](std::uint64_t v) { for (int i = 0; i < 8; ++i) s.push_back(static_cast<std::uint8_t>(v >> (8 * i))); };
  const std::vector<std::uint8_t> cie = {0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 16, 1, 0x00, 0x0c, 7, 8, 0x90, 1, 0, 0};
  u32(static_cast<std::uint32_t>(cie.size()));
  s.insert(s.end(), cie.begin(), cie.end());
  const std::size_t fde_at = s.size();
  const std::vector<std::uint8_t> insns = {0x41, 0x0e, 0x10, 0x86, 0x02, 0x43, 0x0d, 0x06, 0x44, 0x0a, 0x0c, 0x07, 0x08, 0x41, 0x0b, 0, 0, 0};
  u32(static_cast<std::uint32_t>(4 + 8 + 8 + 1 + insns.size()));
  u32(static_cast<std::uint32_t>(fde_at + 4));  // back to the CIE
  u64(0x1000);
  u64(0x40);
  s.push_back(0);  // no augmentation data
  s.insert(s.end(), insns.begin(), insns.end());
  u32(0);
  CfiTable t;
  t.add_section(s, 0, true, 8, false, 0);
  ASSERT_EQ(t.size(), 1u);
  auto at = [&](std::uint64_t pc) { return t.row_at(pc).value(); };
  EXPECT_EQ(at(0x1000).cfa_reg, 7);
  EXPECT_EQ(at(0x1001).cfa_offset, 16);
  EXPECT_EQ(at(0x1004).cfa_reg, 6);
  EXPECT_EQ(at(0x1008).cfa_reg, 7);  // the epilogue: rsp+8
  EXPECT_EQ(at(0x1008).cfa_offset, 8);
  EXPECT_EQ(at(0x1009).cfa_reg, 6);  // restored: rbp+16 again
  EXPECT_EQ(at(0x1009).cfa_offset, 16);
  EXPECT_EQ(at(0x1009).rules.at(6).n, -16);
}

}  // namespace
}  // namespace revkit::debug
