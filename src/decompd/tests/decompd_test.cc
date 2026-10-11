// Decompiling through workers: bundles, the worker pool, failures.

#include "builders.hh"

#include "revkit/decompd/batch.h"
#include "revkit/decompd/builder.h"
#include "revkit/decompd/bundle.h"
#include "revkit/decompd/lift_mode.h"
#include "revkit/decompd/pool.h"
#include "revkit/decompd/runner.h"
#include "revkit/lift/decompile.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <thread>

namespace revkit::decompd {
namespace {

using lift::DecompilerInputs;
using lift::FunctionFacts;
using lift::StorageVarnode;
using loader::Image;
using testing::ElfBuilder;
using testing::to_bytes;

constexpr std::uint64_t kText = 0x1000, kData = 0x2000, kRodata = 0x3000;

// x86-64: caller (calls callee), callee, a global load, a string pointer,
// a jump to unmapped memory, and a loop.
//   0x1000 caller: mov edi,5; call 0x1010; ret
//   0x1010 callee: mov eax,edi; ret
//   0x1020 global: mov eax,[0x2000]; ret
//   0x1030 string: lea rax,[rip+0x1fc9] (0x3000); ret
//   0x1040 bad:    jmp 0x9000 (unmapped)
//   0x1050 loop:   xor eax,eax; add eax,edi; dec edi; jnz 0x1052; ret
std::vector<std::uint8_t> program_text() {
  std::vector<std::uint8_t> t(0x60, 0xcc);
  auto put = [&](std::size_t at, std::initializer_list<std::uint8_t> bytes) {
    for (std::uint8_t b : bytes) t[at++] = b;
  };
  put(0x00, {0xbf, 0x05, 0x00, 0x00, 0x00, 0xe8, 0x06, 0x00, 0x00, 0x00, 0xc3});
  put(0x10, {0x89, 0xf8, 0xc3});
  put(0x20, {0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0xc3});
  put(0x30, {0x48, 0x8d, 0x05, 0xc9, 0x1f, 0x00, 0x00, 0xc3});
  put(0x40, {0xe9, 0xbb, 0x7f, 0x00, 0x00});
  put(0x50, {0x31, 0xc0, 0x01, 0xf8, 0xff, 0xcf, 0x75, 0xfa, 0xc3});
  return t;
}

std::shared_ptr<const Image> program_image() {
  ElfBuilder b({.wide = true, .big = false, .machine = 62, .type = 2, .flags = 0, .entry = kText});
  b.add_load(".text", kText, program_text(), 5);
  b.add_load(".data", kData, std::vector<std::uint8_t>(16, 0), 6);
  std::vector<std::uint8_t> ro(0x20, 0);
  const char hello[] = "hello";
  std::copy(hello, hello + sizeof hello, ro.begin());
  b.add_load(".rodata", kRodata, ro, 4);
  return std::make_shared<const Image>(loader::parse(to_bytes(b.build())));
}

FunctionFacts function(std::uint64_t entry, std::string name, std::uint64_t last) {
  FunctionFacts f;
  f.entry = entry;
  f.name = std::move(name);
  f.body = {{entry, last}};
  f.convention = "unknown";
  f.extrapop = 8;
  f.ret.type = {"void", {}, {}};
  f.ret.storage = std::vector<StorageVarnode>{};
  f.ret.void_storage = true;
  return f;
}

std::shared_ptr<DecompilerInputs> inputs() {
  auto in = std::make_shared<DecompilerInputs>();
  in->functions = {function(0x1000, "caller", 0x100a), function(0x1010, "callee", 0x1012),
                   function(0x1020, "load_global", 0x1027), function(0x1030, "string_ptr", 0x1037),
                   function(0x1040, "jumps_away", 0x1044), function(0x1050, "loop", 0x1058)};
  in->memory = {{".text", kText, kText + 0x5f, false, true, true, false, false, {}},
                {".data", kData, kData + 0xf, true, false, true, false, false, {}},
                {".rodata", kRodata, kRodata + 0x1f, false, false, true, false, false, {}}};
  return in;
}

const std::vector<std::uint64_t> kEntries = {0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050};

class Decompd : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
    ::unsetenv("REVKIT_DECOMPD_FAULT");
  }
  void TearDown() override { ::unsetenv("REVKIT_DECOMPD_FAULT"); }

  static lift::DecompileConfig config() {
    lift::DecompileConfig c;
    c.image = program_image();
    c.language_id = "x86:LE:64:default:gcc";
    c.inputs = inputs();
    c.threads = 2;
    return c;
  }

  // The bundle for `entry`, predicted as the batch driver predicts it.
  struct Built {
    std::unique_ptr<ProgramImage> program;
    std::unique_ptr<lift::FactLookup> lookup;
    std::unique_ptr<LiftBundleBuilder> builder;
  };
  static Built build(std::uint64_t entry, bool predict_anything = true) {
    lift::DecompileConfig c = config();
    Built b;
    b.program = std::make_unique<ProgramImage>(c.image, c.language_id, lift::ArchitectureOptions::Patches{});
    b.lookup = lift::lookup_inputs(c.inputs, c.image.get());
    b.builder = std::make_unique<LiftBundleBuilder>(*b.program, Mode::c_text, entry, *b.lookup, c.inputs->memory, "");
    Prediction p;
    if (predict_anything) {
      lift::Lifter lifter(c.image, "x86:LE:64:default");
      std::vector<std::pair<std::uint64_t, std::uint64_t>> body;
      for (const FunctionFacts &f : c.inputs->functions)
        if (f.entry == entry) body = f.body;
      p = predict(lifter, *b.program, entry, body, c.inputs->memory);
    }
    b.builder->add(p);
    return b;
  }

  static std::string in_process(std::uint64_t entry) {
    lift::InputDecompiler d(config());
    lift::DecompileResult r = d.decompile(entry);
    return r.ok ? r.c : "error: " + r.error;
  }
};

TEST_F(Decompd, BundlesEncodeCanonically) {
  Built a = build(0x1000), b = build(0x1000);
  const std::string ea = encode_bundle(a.builder->bundle()), eb = encode_bundle(b.builder->bundle());
  EXPECT_EQ(ea, eb);
  EXPECT_EQ(bundle_hash(ea), bundle_hash(eb));
  EXPECT_EQ(bundle_hash(ea).substr(0, 3), "b2-");
  const Bundle d = decode_bundle(ea);
  EXPECT_EQ(encode_bundle(d), ea);
  EXPECT_EQ(d.entry, 0x1000u);
  EXPECT_EQ(d.mode, Mode::c_text);
  EXPECT_FALSE(d.chunks.empty());
  // The caller's bundle answers for its callee.
  ASSERT_TRUE(d.lift.addresses.contains({std::string(), 0x1010}));
  EXPECT_GE(d.lift.addresses.at({std::string(), 0x1010}).starts, 0);
  EXPECT_THROW(decode_bundle(ea.substr(0, ea.size() / 2)), facts::DecodeError);
  EXPECT_THROW(decode_bundle("not a bundle"), facts::DecodeError);
}

TEST_F(Decompd, MissingBytesReadAsUnreadable) {
  Built b = build(0x1000);
  Bundle bundle = b.builder->bundle();
  BundleMemory mem;
  mem.set(&bundle);
  std::uint8_t buf[4];
  EXPECT_EQ(mem.read(0x1000, buf), 4u);  // present
  EXPECT_EQ(buf[0], 0xbf);
  EXPECT_EQ(mem.read(0x9000, buf), 0u);  // unmapped: no miss
  EXPECT_TRUE(mem.missed().empty());
  bundle.chunks.erase(0x2000 / kChunk);
  EXPECT_EQ(mem.read(0x2000, buf), 0u);  // mapped but absent: a miss, no made-up bytes
  EXPECT_EQ(mem.missed(), std::set<std::uint64_t>{0x2000 / kChunk});
}

TEST_F(Decompd, WorkersDecompileAsInProcess) {
  BatchStats stats;
  std::vector<lift::DecompileResult> out = decompile_functions(config(), kEntries, &stats);
  ASSERT_EQ(out.size(), kEntries.size());
  for (std::size_t i = 0; i < kEntries.size(); ++i) {
    SCOPED_TRACE(kEntries[i]);
    EXPECT_EQ(out[i].ok ? out[i].c : "error: " + out[i].error, in_process(kEntries[i]));
  }
  EXPECT_EQ(stats.bundles, kEntries.size());
  EXPECT_TRUE(stats.failures.empty());
  EXPECT_GE(stats.pool.spawned, 1u);
  // The same through the in-process debugging mode.
  PoolOptions local;
  local.in_process = true;
  std::vector<lift::DecompileResult> again = decompile_functions(config(), kEntries, nullptr, {}, local);
  for (std::size_t i = 0; i < kEntries.size(); ++i) EXPECT_EQ(again[i].c, out[i].c);
}

TEST_F(Decompd, MissedAnswersAreFilledAndTheRunRepeated) {
  // Nothing predicted: the worker misses the callee, its bytes, ...
  Built b = build(0x1000, false);
  LiftSource source(*b.builder);
  WorkerPool pool;
  BundledRun run = run_bundled(pool, source, {}, 0x1000);
  ASSERT_TRUE(run.outcome.result);
  EXPECT_FALSE(run.failure);
  EXPECT_GT(run.misses, 0u);
  EXPECT_GT(run.runs, 1u);
  EXPECT_FALSE(run.unresolved);
  EXPECT_EQ(decode_result(run.outcome.result->payload).c, in_process(0x1000));
  // The final bundle answers everything: run alone, nothing is missed.
  Runner runner;
  RunResult alone = runner.run(run.bundle, {});
  EXPECT_TRUE(alone.misses.empty());
  EXPECT_EQ(decode_result(alone.payload).c, in_process(0x1000));
}

TEST_F(Decompd, FailuresAreClassifiedAndCostOneRun) {
  Built b = build(0x1020);
  const std::string bundle = encode_bundle(b.builder->bundle());
  struct Case {
    const char *fault;
    FailureKind kind;
  };
  for (const Case &c : {Case{"segv", FailureKind::segv}, Case{"fpe", FailureKind::fpe}, Case{"abort", FailureKind::abort},
                        Case{"oom", FailureKind::oom}, Case{"hang", FailureKind::timeout}}) {
    SCOPED_TRACE(c.fault);
    ::setenv("REVKIT_DECOMPD_FAULT", (std::string(c.fault) + "@1020").c_str(), 1);
    PoolOptions o;
    o.workers = 1;
    o.grace_seconds = 0.5;
    WorkerPool pool(o);
    Limits limits;
    limits.timeout_seconds = 0.2;  // a hang is killed at 0.2 * 1.25 + 0.5 s
    Outcome out = pool.run(bundle, limits);
    ASSERT_TRUE(out.failure);
    EXPECT_EQ(out.failure->kind, c.kind) << out.failure->detail;
    if (c.kind == FailureKind::oom) EXPECT_NE(out.failure->stderr_tail.find("out of memory"), std::string::npos);
    std::optional<Failure> f = failure_of(out, 0x1020, bundle_hash(bundle), limits);
    ASSERT_TRUE(f);
    EXPECT_EQ(f->bundle_hash, bundle_hash(bundle));
    EXPECT_EQ(f->decompiler_build, decompiler_build());
    // The pool replaced the worker: another function decompiles.
    Built ok = build(0x1010);
    Outcome next = pool.run(encode_bundle(ok.builder->bundle()), {});
    ASSERT_TRUE(next.result) << (next.failure ? next.failure->detail : "");
    EXPECT_TRUE(decode_result(next.result->payload).ok);
    EXPECT_EQ(pool.stats().spawned, 2u);
  }
}

TEST_F(Decompd, WorkersAreRecycled) {
  PoolOptions o;
  o.workers = 1;
  o.recycle_after = 2;
  WorkerPool pool(o);
  Built b = build(0x1010);
  const std::string bundle = encode_bundle(b.builder->bundle());
  for (int i = 0; i < 5; ++i) ASSERT_TRUE(pool.run(bundle, {}).result);
  EXPECT_EQ(pool.stats().spawned, 3u);  // runs 1-2, 3-4, 5
  EXPECT_EQ(pool.stats().recycled, 2u);
  EXPECT_GT(pool.workers_rss(), 0u);
}

TEST_F(Decompd, EvictedRunsAreNotFailures) {
  // Two runs in flight (each sleeps first); the larger is stopped to stay
  // within memory, and says so; the other finishes; the last run in flight
  // is never evicted.
  ::setenv("REVKIT_DECOMPD_FAULT", "sleep1500@1010", 1);
  PoolOptions o;
  o.workers = 2;
  WorkerPool pool(o);
  Built b = build(0x1010);
  const std::string bundle = encode_bundle(b.builder->bundle());
  Outcome first, second;
  std::thread t1([&] { first = pool.run(bundle, {}); });
  std::thread t2([&] { second = pool.run(bundle, {}); });
  std::this_thread::sleep_for(std::chrono::milliseconds(700));
  EXPECT_GT(pool.live_rss(), 0u);
  EXPECT_TRUE(pool.evict_largest());
  EXPECT_FALSE(pool.evict_largest());  // one left in flight
  t1.join();
  t2.join();
  EXPECT_NE(first.evicted, second.evicted);
  const Outcome &done = first.evicted ? second : first;
  ASSERT_TRUE(done.result);
  EXPECT_FALSE(first.failure || second.failure);
  EXPECT_EQ(pool.stats().evicted, 1u);
}

TEST_F(Decompd, CooperativeStopsAreFailures) {
  Built b = build(0x1050);
  WorkerPool pool;
  Limits limits;
  limits.max_varnodes = 1;
  Outcome out = pool.run(encode_bundle(b.builder->bundle()), limits);
  ASSERT_TRUE(out.result);
  EXPECT_EQ(out.result->stopped, lift::DecompileStop::too_large);
  std::optional<Failure> f = failure_of(out, 0x1050, "h", limits);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->kind, FailureKind::oom);
  EXPECT_EQ(pool.stats().recycled, 1u);  // a stopped run's worker is replaced
}

}  // namespace
}  // namespace revkit::decompd
