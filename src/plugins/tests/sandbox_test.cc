// The sandbox: hostile and broken plugins, written in WAT, must fail
// cleanly (a failed call or a rejected load), never crash or hang the host.

#include "revkit/plugins/host.h"

#include <gtest/gtest.h>

#include <atomic>
#include <fstream>
#include <thread>

namespace revkit::plugins {
namespace {

class FakeFacts final : public FactProvider {
 public:
  std::string program_info() override { return {}; }
  std::size_t memory_read(std::uint64_t addr, std::span<std::byte> out) override {
    reads.fetch_add(1);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = std::byte(static_cast<unsigned char>(addr + i));
    return out.size();
  }
  std::uint64_t file_size() override { return 3; }
  std::size_t file_read(std::uint64_t, std::span<std::byte> out) override {
    std::size_t n = std::min<std::size_t>(out.size(), 3);
    for (std::size_t i = 0; i < n; ++i) out[i] = std::byte('a' + i);
    return n;
  }
  std::string functions() override { return std::string(4, '\0'); }
  std::optional<std::string> function_code(std::uint64_t) override { return std::nullopt; }
  std::string symbol_name(std::uint64_t) override {
    if (throw_on_name) throw std::runtime_error("the store went away");
    return "main";
  }
  std::atomic<int> reads{0};
  bool throw_on_name = false;
};

std::string manifest(const std::string &name, const std::string &extra = "", const std::string &kind = "analyzer",
                     int interface_version = 1) {
  return R"({"name": ")" + name + R"(", "version": "1.0.0", "kind": ")" + kind + R"(", "interface": )" +
         std::to_string(interface_version) + extra + "}";
}

// An analyzer whose rk_analyze body is `body`; it has set_output, an empty
// fact list at 16 and a heap at 1024.
std::string analyzer_wat(const std::string &body, const std::string &imports = "", int version = 1) {
  return R"((module
  (import "revkit:plugin/v1" "set_output" (func $out (param i32 i32)))
  )" + imports + R"(
  (memory (export "memory") 1)
  (data (i32.const 16) "\00\00\00\00")
  (func (export "rk_abi_version") (result i32) (i32.const )" +
         std::to_string(version) + R"())
  (func (export "rk_alloc") (param $n i32) (result i32) (i32.const 1024))
  (func $recurse (param i32) (result i32) (call $recurse (i32.add (local.get 0) (i32.const 1))))
  (func (export "rk_analyze") (param $p i32) (param $n i32) (result i32)
    )" + body + R"(
    (call $out (i32.const 16) (i32.const 4))
    (i32.const 0))
))";
}

class Sandbox : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!Host::available()) GTEST_SKIP() << "built without wasmtime";
  }
  CallResult run(const Plugin &p) {
    std::vector<DerivedItem> items;
    return run_analyzer(p, abi::Scope::program, 0, facts_, items);
  }
  FakeFacts facts_;
};

TEST_F(Sandbox, AWellBehavedPluginRuns) {
  Host host;
  auto p = host.load(manifest("ok"), analyzer_wat(""));
  CallResult r = run(*p);
  EXPECT_TRUE(r.ok()) << r.error;
  EXPECT_GT(r.fuel_consumed, 0u);
  EXPECT_EQ(p->id(), "ok@1.0.0");
  EXPECT_EQ(p->fingerprint().size(), 32u);
}

TEST_F(Sandbox, AnInfiniteLoopRunsOutOfFuel) {
  Host host;
  auto p = host.load(manifest("spin", R"(, "limits": {"fuel": 5000000})"), analyzer_wat("(loop $l (br $l))"));
  auto start = std::chrono::steady_clock::now();
  CallResult r = run(*p);
  EXPECT_EQ(r.failure, Failure::out_of_fuel) << r.error;
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
  EXPECT_GE(r.fuel_consumed, 5000000u);
  // Deterministic: the same budget fails the same way, at the same point.
  CallResult again = run(*p);
  EXPECT_EQ(again.failure, Failure::out_of_fuel);
  EXPECT_EQ(again.fuel_consumed, r.fuel_consumed);
}

TEST_F(Sandbox, HostCallsCostFuelToo) {
  // A loop of cheap wasm around an expensive import still runs out.
  Host host;
  auto p = host.load(manifest("reader", R"(, "capabilities": ["memory"], "limits": {"fuel": 3000000})"),
                     analyzer_wat("(loop $l (drop (call $read (i64.const 0) (i32.const 2048) (i32.const 60000))) (br $l))",
                                  R"((import "revkit:plugin/v1" "memory_read" (func $read (param i64 i32 i32) (result i32))))"));
  CallResult r = run(*p);
  EXPECT_EQ(r.failure, Failure::out_of_fuel) << r.error;
  // 1000 per call plus 1 per 8 bytes: a few hundred calls, not millions.
  EXPECT_LT(facts_.reads.load(), 500);
}

TEST_F(Sandbox, WallClockBackstopStopsWhatFuelAllows) {
  HostOptions o;
  o.defaults.wall = std::chrono::milliseconds(200);
  o.maximum.fuel = UINT64_MAX / 2;
  Host host(o);
  auto p = host.load(manifest("slow", R"(, "limits": {"fuel": 4000000000000000000})"), analyzer_wat("(loop $l (br $l))"));
  auto start = std::chrono::steady_clock::now();
  CallResult r = run(*p);
  EXPECT_EQ(r.failure, Failure::timeout) << r.error;
  EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(10));
}

TEST_F(Sandbox, MemoryIsCappedAndGrowthPastItFails) {
  Host host;  // 64 MiB default: 1024 pages
  // Growing to exactly the cap works...
  auto fits = host.load(manifest("fits"),
                        analyzer_wat("(if (i32.eq (memory.grow (i32.const 1023)) (i32.const -1)) (then (return (i32.const 7))))"));
  CallResult r = run(*fits);
  EXPECT_TRUE(r.ok()) << r.error;
  // ...one page more doesn't: memory.grow returns -1 and the plugin fails.
  auto over = host.load(manifest("over"),
                        analyzer_wat("(if (i32.eq (memory.grow (i32.const 1024)) (i32.const -1)) (then (return (i32.const 7))))"));
  r = run(*over);
  EXPECT_EQ(r.failure, Failure::plugin_error);
  EXPECT_EQ(r.error, "returned 7");
  // A plugin that keeps allocating until it can't, then traps, is out of memory.
  auto hog = host.load(manifest("hog"),
                       analyzer_wat("(loop $l (br_if $l (i32.ne (memory.grow (i32.const 16)) (i32.const -1)))) unreachable"));
  r = run(*hog);
  EXPECT_EQ(r.failure, Failure::out_of_memory) << r.error;
  // The manifest can ask for less.
  auto small = host.load(manifest("small", R"(, "limits": {"memory_mb": 1})"),
                         analyzer_wat("(if (i32.eq (memory.grow (i32.const 16)) (i32.const -1)) (then (return (i32.const 7))))"));
  r = run(*small);
  EXPECT_EQ(r.failure, Failure::plugin_error);
}

TEST_F(Sandbox, InitialMemoryOverTheCapIsRejectedAtLoad) {
  Host host;
  std::string wat = analyzer_wat("");
  wat.replace(wat.find("(memory (export \"memory\") 1)"), 28, "(memory (export \"memory\") 2000)");
  EXPECT_THROW(
      try { host.load(manifest("big"), wat); } catch (const std::runtime_error &e) {
        EXPECT_NE(std::string(e.what()).find("initial memory"), std::string::npos) << e.what();
        throw;
      },
      std::runtime_error);
}

TEST_F(Sandbox, TrapsAreFailedCalls) {
  Host host;
  for (const auto &[name, body] : std::vector<std::pair<std::string, std::string>>{
           {"unreachable", "unreachable"},
           {"oob-load", "(drop (i32.load (i32.const 0x7ffffff0)))"},
           {"div-zero", "(drop (i32.div_u (i32.const 1) (i32.const 0)))"},
           {"stack-overflow", "(drop (call $recurse (i32.const 0)))"},
           {"bad-pointer", "(call $out (i32.const 0x7ffff000) (i32.const 4096))"},
       }) {
    auto p = host.load(manifest(name), analyzer_wat(body));
    CallResult r = run(*p);
    EXPECT_EQ(r.failure, Failure::trap) << name << ": " << r.error;
    EXPECT_FALSE(r.error.empty()) << name;
  }
  // The host is fine afterwards.
  auto ok = host.load(manifest("after"), analyzer_wat(""));
  EXPECT_TRUE(run(*ok).ok());
}

TEST_F(Sandbox, FailEndsTheCallWithAMessage) {
  Host host;
  const std::string fail = R"((import "revkit:plugin/v1" "fail" (func $fail (param i32 i32)))
  (data (i32.const 64) "bad pattern"))";
  auto p = host.load(manifest("quitter"), analyzer_wat("(call $fail (i32.const 64) (i32.const 11))", fail));
  CallResult r = run(*p);
  EXPECT_EQ(r.failure, Failure::plugin_error);
  EXPECT_EQ(r.error, "bad pattern");
}

TEST_F(Sandbox, MalformedOutputIsRejected) {
  Host host;
  // A list claiming a million facts in four bytes.
  std::string wat = analyzer_wat("");
  wat.replace(wat.find(R"("\00\00\00\00")"), 14, R"("\40\42\0f\00")");
  auto p = host.load(manifest("liar"), wat);
  CallResult r = run(*p);
  EXPECT_EQ(r.failure, Failure::bad_output) << r.error;
}

TEST_F(Sandbox, InterfaceVersionMismatchIsRejected) {
  Host host;
  auto expect_reject = [&](const std::string &m, const std::string &wat, const std::string &needle) {
    try {
      host.load(m, wat);
      ADD_FAILURE() << "loaded";
    } catch (const std::runtime_error &e) {
      EXPECT_NE(std::string(e.what()).find(needle), std::string::npos) << e.what();
    }
  };
  // The manifest names an interface this host doesn't speak.
  expect_reject(manifest("future", "", "analyzer", 2), analyzer_wat("", "", 2), "interface version mismatch");
  // The module was built for another interface than its manifest says.
  expect_reject(manifest("liar"), analyzer_wat("", "", 2), "built for interface 2");
  // Missing entry points.
  expect_reject(manifest("wrong-kind", R"(, "command": {})", "command"), analyzer_wat(""), "rk_command");
}

TEST_F(Sandbox, NoAmbientAuthority) {
  Host host;
  auto expect_reject = [&](const std::string &m, const std::string &wat, const std::string &needle) {
    try {
      host.load(m, wat);
      ADD_FAILURE() << "loaded";
    } catch (const std::runtime_error &e) {
      EXPECT_NE(std::string(e.what()).find(needle), std::string::npos) << e.what();
    }
  };
  // WASI is not there at all: no clocks, randomness, files or sockets.
  for (const char *wasi : {R"((import "wasi_snapshot_preview1" "clock_time_get" (func (param i32 i64 i32) (result i32))))",
                           R"((import "wasi_snapshot_preview1" "random_get" (func (param i32 i32) (result i32))))",
                           R"((import "wasi_snapshot_preview1" "path_open" (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32))))",
                           R"((import "wasi:sockets/tcp" "connect" (func)))"})
    expect_reject(manifest("wasi"), analyzer_wat("", wasi), "no WASI");
  // An import the interface doesn't have.
  expect_reject(manifest("unknown"), analyzer_wat("", R"((import "revkit:plugin/v1" "exec" (func)))"),
                "doesn't have");
  // A capability-gated import without the capability in the manifest.
  const std::string file_read =
      R"((import "revkit:plugin/v1" "file_read" (func $fr (param i64 i32 i32) (result i32))))";
  expect_reject(manifest("sneaky"), analyzer_wat("", file_read), "needs capability \"file\"");
  // The binary itself is readable only with an explicit grant...
  expect_reject(manifest("reader", R"(, "capabilities": ["file"])"), analyzer_wat("", file_read), "not granted");
  // ...which an operator gives by name.
  HostOptions o;
  o.grants["reader"] = {Capability::file};
  Host granted(o);
  auto p = granted.load(manifest("reader", R"(, "capabilities": ["file"])"),
                        analyzer_wat("(if (i32.ne (call $fr (i64.const 0) (i32.const 2048) (i32.const 16)) (i32.const 3)) "
                                     "(then (return (i32.const 9))))",
                                     file_read));
  CallResult r = run(*p);
  EXPECT_TRUE(r.ok()) << r.error;
  // Imports with the wrong signature don't link.
  expect_reject(manifest("badsig", R"(, "capabilities": ["memory"])"),
                analyzer_wat("", R"((import "revkit:plugin/v1" "memory_read" (func (param i32))))"), "cannot link");
}

TEST_F(Sandbox, ExceptionsFromFactsReachTheCaller) {
  Host host;
  auto p = host.load(manifest("names", R"(, "capabilities": ["code"])"),
                     analyzer_wat("(drop (call $name (i64.const 0)))",
                                  R"((import "revkit:plugin/v1" "symbol_name" (func $name (param i64) (result i32))))"));
  facts_.throw_on_name = true;
  EXPECT_THROW(run(*p), std::runtime_error);
  facts_.throw_on_name = false;
  EXPECT_TRUE(run(*p).ok());
}

TEST_F(Sandbox, EveryCallStartsFresh) {
  // A global counter in the module: each call sees its initial value.
  Host host;
  std::string wat = R"((module
  (import "revkit:plugin/v1" "set_output" (func $out (param i32 i32)))
  (memory (export "memory") 1)
  (global $calls (mut i32) (i32.const 0))
  (data (i32.const 16) "\00\00\00\00")
  (func (export "rk_abi_version") (result i32) (i32.const 1))
  (func (export "rk_alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "rk_analyze") (param i32 i32) (result i32)
    (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
    (i32.store (i32.const 32) (i32.add (i32.load (i32.const 32)) (i32.const 1)))
    (if (i32.ne (global.get $calls) (i32.const 1)) (then (return (i32.const 1))))
    (if (i32.ne (i32.load (i32.const 32)) (i32.const 1)) (then (return (i32.const 2))))
    (call $out (i32.const 16) (i32.const 4))
    (i32.const 0))
))";
  auto p = host.load(manifest("fresh"), wat);
  for (int i = 0; i < 3; ++i) EXPECT_TRUE(run(*p).ok()) << i;
}

TEST_F(Sandbox, ConcurrentCalls) {
  Host host;
  auto p = host.load(manifest("busy", R"(, "limits": {"fuel": 2000000})"),
                     analyzer_wat("(loop $l (br_if $l (i32.ne (call $c) (i32.const 0))))",
                                  "(global $i (mut i32) (i32.const 100000))\n"
                                  "(func $c (result i32) (global.set $i (i32.sub (global.get $i) (i32.const 1))) (global.get $i))"));
  std::vector<std::thread> threads;
  std::atomic<int> ok{0};
  for (int t = 0; t < 8; ++t)
    threads.emplace_back([&] {
      FakeFacts facts;
      for (int i = 0; i < 5; ++i) {
        std::vector<DerivedItem> items;
        if (run_analyzer(*p, abi::Scope::program, 0, facts, items).ok()) ok.fetch_add(1);
      }
    });
  for (auto &t : threads) t.join();
  EXPECT_EQ(ok.load(), 40);
}

TEST_F(Sandbox, RejectedPluginsInADirectoryDontStopTheOthers) {
  auto dir = std::filesystem::temp_directory_path() / ("revkit-plugins-" + std::to_string(::getpid()));
  std::filesystem::remove_all(dir);
  std::filesystem::create_directories(dir);
  auto write = [&](const std::string &name, const std::string &text) { std::ofstream(dir / name) << text; };
  write("good.json", manifest("good"));
  write("good.wasm", wat_to_wasm(analyzer_wat("")));
  write("bad.json", manifest("bad"));
  write("bad.wasm", "\0asm garbage");
  write("lonely.wasm", wat_to_wasm(analyzer_wat("")));
  Host host;
  auto rejected = host.load_dir(dir);
  ASSERT_EQ(rejected.size(), 2u);
  EXPECT_EQ(rejected[0].name, "bad");
  EXPECT_NE(rejected[1].error.find("no manifest"), std::string::npos) << rejected[1].error;
  ASSERT_EQ(host.plugins().size(), 1u);
  EXPECT_EQ(host.plugins()[0]->manifest().name, "good");
  EXPECT_EQ(find_by_fingerprint(host.plugins()[0]->fingerprint()), host.plugins()[0]);
  std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace revkit::plugins
