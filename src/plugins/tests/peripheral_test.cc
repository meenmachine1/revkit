// Peripheral plugins (kind "peripheral", docs/firmware-emulation.md): a live
// instance per machine whose state carries from call to call, the grants
// model for its imports, failures that stop the run instead of the daemon,
// and the tick-timer example driving interrupts in a bare-metal program.
#include "revkit/plugins/host.h"
#include "revkit/plugins/peripheral.h"

#include "revkit/emu/machine.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

namespace revkit::plugins {
namespace {

namespace fs = std::filesystem;

std::string manifest(const std::string &name, const std::string &extra = "") {
  return R"({"name": ")" + name + R"(", "version": "1.0.0", "kind": "peripheral", "interface": 1)" + extra + "}";
}

// A peripheral whose read returns a counter that grows with every read
// (state that persists), plus `extra` exports and imports.
std::string counter_wat(const std::string &read_body = "", const std::string &imports = "", const std::string &extra = "") {
  return R"((module
  )" + imports + R"(
  (memory (export "memory") 1)
  (global $n (mut i64) (i64.const 0))
  (func (export "rk_abi_version") (result i32) (i32.const 1))
  (func (export "rk_alloc") (param i32) (result i32) (i32.const 8192))
  (func (export "rk_peripheral_buffer") (result i32) (i32.const 4096))
  (func (export "rk_peripheral_init") (param i32 i32) (result i32) (i32.const 0))
  (func (export "rk_peripheral_read") (param $off i64) (param $size i32) (result i64)
    )" + read_body + R"(
    (global.set $n (i64.add (global.get $n) (i64.const 1)))
    (i64.add (global.get $n) (local.get $off)))
  (func (export "rk_peripheral_write") (param i64 i32 i64) (result i32) (i32.const 0))
  )" + extra + R"()
)";
}

class RecordingHost final : public PeripheralHost {
 public:
  std::uint64_t now() override { return 42; }
  void schedule(std::int64_t at) override { scheduled = at; }
  void irq(std::uint32_t line, bool level) override { irqs.emplace_back(line, level); }
  void output(std::string_view bytes) override { out += bytes; }
  bool bus_read(std::uint64_t, std::span<std::uint8_t> o) override {
    for (std::size_t i = 0; i < o.size(); ++i) o[i] = static_cast<std::uint8_t>(i + 1);
    return true;
  }
  bool bus_write(std::uint64_t, std::span<const std::uint8_t>) override { return true; }
  void log(std::string_view) override {}
  std::int64_t scheduled = -2;
  std::vector<std::pair<std::uint32_t, bool>> irqs;
  std::string out;
};

TEST(PeripheralPlugins, StateCarriesFromCallToCall) {
  if (!Host::available()) GTEST_SKIP() << "built without wasmtime";
  Host host;
  auto p = host.load(manifest("counter"), counter_wat());
  RecordingHost rh;
  std::string error;
  auto inst = p->instantiate(rh, error);
  ASSERT_TRUE(inst) << error;
  ASSERT_TRUE(inst->init("{}"));
  std::uint64_t v = 0;
  ASSERT_TRUE(inst->read(0, 4, v));
  EXPECT_EQ(v, 1u);
  ASSERT_TRUE(inst->read(0x10, 4, v));
  EXPECT_EQ(v, 0x12u);  // the second read, at 0x10
  EXPECT_EQ(inst->calls(), 5u);  // rk_peripheral_buffer, rk_alloc and init for the configuration, two reads
}

TEST(PeripheralPlugins, ImportsFollowTheGrants) {
  if (!Host::available()) GTEST_SKIP() << "built without wasmtime";
  const std::string bus = R"((import "revkit:plugin/v1" "bus_read" (func $bus (param i64 i32 i32) (result i32))))";
  const std::string body = "(drop (call $bus (i64.const 0) (i32.const 0) (i32.const 4)))";
  {
    Host host;
    // Requested but not granted: rejected at load with what to do.
    try {
      host.load(manifest("dma", R"(, "capabilities": ["bus"])"), counter_wat(body, bus));
      FAIL() << "loaded without the bus grant";
    } catch (const std::runtime_error &e) {
      EXPECT_NE(std::string(e.what()).find("--plugin-grant dma=bus"), std::string::npos) << e.what();
    }
    // Not requested: rejected too.
    EXPECT_THROW(host.load(manifest("dma2"), counter_wat(body, bus)), std::runtime_error);
  }
  HostOptions o;
  o.grants["dma"] = {Capability::bus};
  Host host(o);
  auto p = host.load(manifest("dma", R"(, "capabilities": ["bus"])"), counter_wat(body, bus));
  RecordingHost rh;
  std::string error;
  auto inst = p->instantiate(rh, error);
  ASSERT_TRUE(inst) << error;
  std::uint64_t v = 0;
  EXPECT_TRUE(inst->read(0, 4, v));
  // irq and output are granted by default; peripherals can't ask for program facts.
  const std::string irq = R"((import "revkit:plugin/v1" "irq_set" (func $irq (param i32 i32))))";
  EXPECT_NO_THROW(host.load(manifest("irqer", R"(, "capabilities": ["irq"])"),
                            counter_wat("(call $irq (i32.const 0) (i32.const 1))", irq)));
  EXPECT_THROW(host.load(manifest("nosy", R"(, "capabilities": ["memory"])"), counter_wat()), std::runtime_error);
  // Other kinds can't use the peripheral imports.
  const std::string now = R"((import "revkit:plugin/v1" "now" (func $now (result i64))))";
  try {
    host.load(R"({"name": "a", "version": "1.0.0", "kind": "analyzer", "interface": 1})", R"((module )" + now + R"(
      (memory (export "memory") 1)
      (func (export "rk_abi_version") (result i32) (i32.const 1))
      (func (export "rk_alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "rk_analyze") (param i32 i32) (result i32) (i32.const 0))))");
    FAIL() << "an analyzer imported now";
  } catch (const std::runtime_error &e) {
    EXPECT_NE(std::string(e.what()).find("only peripherals"), std::string::npos) << e.what();
  }
}

TEST(PeripheralPlugins, ImportsReachTheHost) {
  if (!Host::available()) GTEST_SKIP() << "built without wasmtime";
  Host host;
  const std::string imports = R"(
  (import "revkit:plugin/v1" "now" (func $now (result i64)))
  (import "revkit:plugin/v1" "schedule" (func $schedule (param i64)))
  (import "revkit:plugin/v1" "irq_set" (func $irq (param i32 i32)))
  (import "revkit:plugin/v1" "output" (func $out (param i32 i32))))";
  const std::string extra = R"(
  (data (i32.const 64) "hi")
  (func (export "rk_peripheral_tick") (param $t i64) (result i32)
    (call $irq (i32.const 0) (i32.const 1))
    (call $out (i32.const 64) (i32.const 2))
    (call $schedule (i64.add (call $now) (i64.const 100)))
    (i32.const 0)))";
  auto p = host.load(manifest("ticker", R"(, "capabilities": ["irq", "output"])"), counter_wat("", imports, extra));
  RecordingHost rh;
  std::string error;
  auto inst = p->instantiate(rh, error);
  ASSERT_TRUE(inst) << error;
  ASSERT_TRUE(inst->tick(42));
  EXPECT_EQ(rh.scheduled, 142);
  ASSERT_EQ(rh.irqs.size(), 1u);
  EXPECT_TRUE(rh.irqs[0].second);
  EXPECT_EQ(rh.out, "hi");
}

TEST(PeripheralPlugins, AFailingPluginStopsTheRunNotTheHost) {
  if (!Host::available() || std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP();
  lift::initialize(REVKIT_GHIDRA_ROOT);
  Host host;
  host.load(manifest("spin", R"(, "limits": {"fuel": 1000000})"), counter_wat("(loop $l (br $l))"));
  // A machine whose code reads the plugin's register: ldr r0, [r1]; b .
  auto bytes = std::make_shared<loader::Bytes>(8);
  const std::uint8_t code[8] = {0x00, 0x00, 0x91, 0xe5, 0xfe, 0xff, 0xff, 0xea};
  for (int i = 0; i < 8; ++i) (*bytes)[static_cast<std::size_t>(i)] = std::byte(code[i]);
  loader::RawOptions ro;
  ro.language = "ARM:LE:32:v4t";
  auto image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, ro));
  emu::Options eo;
  eo.language = "ARM:LE:32:v4t:default";
  emu::Emulator e(image, eo);
  emu::MachineSpec spec = emu::parse_machine(R"({"cpu": "arm", "entry": 0, "registers": {"r1": "0x10000000"},
    "peripherals": [{"name": "bad", "kind": "plugin:spin", "base": "0x10000000"}]})");
  emu::MachineOptions mo;
  mo.factory = peripheral_factory(host);
  e.attach_machine(spec, mo);
  const emu::Stop s = e.run({});
  EXPECT_EQ(s.kind, emu::StopKind::hook);
  EXPECT_NE(s.detail.find("out of fuel"), std::string::npos) << s.detail;
  // Unknown plugins are machine errors.
  emu::Emulator e2(image, eo);
  spec.peripherals[0].kind = "plugin:nope";
  EXPECT_THROW(e2.attach_machine(spec, mo), emu::MachineError);
}

// The tick-timer example in a bare-metal program on Versatile/PB.
TEST(PeripheralPlugins, TickTimerInterruptsAProgram) {
  if (!Host::available() || std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_EXAMPLE_PLUGINS).empty() ||
      std::string(REVKIT_FWEMU_CLANG).empty())
    GTEST_SKIP() << "needs wasmtime, Ghidra, the example plugins and clang";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::string out = std::string(REVKIT_FWEMU_TEST_OUT);
  const std::string cmd = std::string("sh ") + REVKIT_FWEMU_DIR + "/build.sh " + REVKIT_FWEMU_CLANG + " ld.lld llvm-objcopy " +
                          out + " >/dev/null 2>&1";
  ASSERT_EQ(std::system(cmd.c_str()), 0) << cmd;
  Host host;
  host.load(fs::path(REVKIT_EXAMPLE_PLUGINS) / "tick-timer.wasm");
  std::ifstream in(fs::path(REVKIT_FWEMU_DIR) / "versatilepb_plugin.json");
  std::stringstream text;
  text << in.rdbuf();
  const emu::MachineSpec spec = emu::parse_machine(text.str());
  auto run = [&] {
    const fs::path bin = fs::path(out) / "arm_plugin.bin";
    auto image =
        std::make_shared<const loader::Image>(loader::load_raw_file(bin, emu::machine_raw_options(spec, fs::file_size(bin))));
    emu::Options eo;
    eo.language = spec.language;
    eo.trace_capacity = 1 << 12;
    emu::Emulator e(image, eo);
    emu::MachineOptions mo;
    mo.factory = peripheral_factory(host);
    e.attach_machine(spec, mo);
    const emu::Stop s = e.run({});
    EXPECT_EQ(s.kind, emu::StopKind::exited) << s.detail;
    return std::make_pair(e.stdout_data(), emu::trace_json(e));
  };
  const auto a = run(), b = run();
  EXPECT_EQ(a.first, "plugin test\nvia plugin: 3\ncount 3\ndone\n");
  EXPECT_EQ(a.second, b.second);  // deterministic, plugin and all
}

}  // namespace
}  // namespace revkit::plugins
