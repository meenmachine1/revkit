// Function discovery on compiled fixtures (fixtures/*.c), built at test time
// with the host compiler and, when present, clang and cross compilers.

#include "builders.hh"
#include "../internal.h"

#include "revkit/analysis/analysis.h"
#include "revkit/facts/thread_pool.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace revkit::analysis {
namespace {

using facts::Address;

std::string read_source(const std::string &name) {
  std::ifstream in(std::string(REVKIT_FIXTURES) + "/" + name);
  std::stringstream s;
  s << in.rdbuf();
  return s.str();
}

// A fixture binary analysed in its own in-memory fact store.
struct Analysed {
  std::shared_ptr<const loader::Image> image;
  std::unique_ptr<facts::FactDb> db = std::make_unique<facts::FactDb>();
  ProgramInfo info;
  facts::Ref<FunctionList> functions;

  facts::Snapshot snapshot() { return db->snapshot(); }
  const FunctionInfo *at(std::uint64_t entry) const { return functions->find(entry); }
  const FunctionInfo *named(const std::string &name) const {
    for (const FunctionInfo &f : functions->functions)
      if (f.name == name) return &f;
    return nullptr;
  }
  const loader::Block *block_at(std::uint64_t a) const {
    for (const loader::Block &b : image->blocks)
      if (a >= b.start && a - b.start < b.size) return &b;
    return nullptr;
  }
};

std::unique_ptr<Analysed> analyse(const std::filesystem::path &file, unsigned threads = 1) {
  auto a = std::make_unique<Analysed>();
  a->image = std::make_shared<const loader::Image>(
      loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true}));
  auto lang = loader::guess_language(*a->image);
  if (!lang) throw std::runtime_error("no language for " + file.string());
  register_queries(a->db->engine());
  a->info = describe(*a->image, lang->id());
  import_image(*a->db, ProgramKey{}, *a->image, a->info);
  facts::Snapshot snap = a->db->snapshot();
  if (threads > 1) {
    // The seeds' flows decoded in parallel first, as the backend does, and
    // discovery's own steps on the pool.
    std::vector<Location> seeds;
    for (const Seed &s : a->info.seeds) seeds.push_back({{}, s.address});
    facts::ThreadPool pool(threads);
    snap.get_all<Flow>(seeds, &pool);
    a->db->engine().set_pool(&pool);
    a->functions = snap.get<Functions>(ProgramKey{});
    a->db->engine().set_pool(nullptr);
    return a;
  }
  a->functions = snap.get<Functions>(ProgramKey{});
  return a;
}

// Address of each defined function symbol, from an unstripped twin.
std::map<std::string, std::uint64_t> symbols(const std::filesystem::path &file) {
  loader::Image img = loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true});
  std::map<std::string, std::uint64_t> out;
  for (const loader::Symbol &s : img.symbols)
    if (s.defined && s.type == loader::SymbolType::func) out[s.name] = s.value;
  return out;
}

class Analysis : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
  }
};

// ---- freestanding: discovery, no-return, jump tables, padding ----

struct Toolchain {
  std::string name;
  std::string cc;     // compiler command, possibly with --target
  std::string flags;  // extra flags (optimization, linker)
};

std::vector<Toolchain> toolchains() {
  std::vector<Toolchain> out;
  auto add = [&](std::string name, std::string cc, std::string flags) {
    out.push_back({std::move(name), std::move(cc), std::move(flags)});
  };
  add("x86_64-gcc-O2", REVKIT_TEST_CC, "-O2");
  add("x86_64-gcc-O0", REVKIT_TEST_CC, "-O0");
  if (!std::string(REVKIT_TEST_CLANG).empty()) {
    add("x86_64-clang-O2", REVKIT_TEST_CLANG, "-O2 -fuse-ld=lld");
    add("aarch64-clang-O2", std::string(REVKIT_TEST_CLANG) + " --target=aarch64-linux-gnu", "-O2 -fuse-ld=lld");
  }
  if (!std::string(REVKIT_TEST_AARCH64_CC).empty()) {
    add("aarch64-gcc-O2", REVKIT_TEST_AARCH64_CC, "-O2");
    add("aarch64-gcc-O0", REVKIT_TEST_AARCH64_CC, "-O0");
  }
  if (!std::string(REVKIT_TEST_RISCV64_CC).empty()) add("riscv64-gcc-O2", REVKIT_TEST_RISCV64_CC, "-O2");
  return out;
}

constexpr const char *kFreestanding =
    "-nostdlib -static -ffreestanding -fno-pie -no-pie -fno-asynchronous-unwind-tables -fno-unwind-tables "
    "-fno-optimize-sibling-calls -falign-functions=16";

class Freestanding : public Analysis, public ::testing::WithParamInterface<Toolchain> {
 protected:
  // Builds the fixture twice from the same code: with symbols (to learn
  // where each function is) and stripped (what gets analysed).
  void SetUp() override {
    Analysis::SetUp();
    if (IsSkipped()) return;
    const Toolchain &t = GetParam();
    dir_ = testing::scratch_dir("analysis-" + t.name);
    std::string flags = std::string(kFreestanding) + " " + t.flags;
    if (!testing::compile(t.cc, read_source("freestanding.c"), flags, dir_ / "named") ||
        !testing::compile(t.cc, read_source("freestanding.c"), flags + " -s", dir_ / "stripped"))
      GTEST_SKIP() << t.name << " can't build the fixture";
    names_ = symbols(dir_ / "named");
  }

  std::uint64_t sym(const std::string &name) {
    auto it = names_.find(name);
    if (it == names_.end()) ADD_FAILURE() << "no symbol " << name;
    return it == names_.end() ? 0 : it->second;
  }

  std::filesystem::path dir_;
  std::map<std::string, std::uint64_t> names_;
};

TEST_P(Freestanding, FindsEveryFunctionFromTheEntryAlone) {
  auto a = analyse(dir_ / "stripped");
  ASSERT_EQ(a->info.seeds.size(), 1u);  // the entry point
  EXPECT_EQ(a->info.seeds[0].address, *a->image->entry);

  std::vector<std::string> expected = {"_start", "sys_exit", "fail", "check", "dispatch", "masked"};
  for (int i = 0; i < 10; ++i) expected.push_back("m" + std::to_string(i));
  for (int i = 0; i < 8; ++i) expected.push_back("k" + std::to_string(i));
  for (const std::string &name : expected) {
    const FunctionInfo *f = a->at(sym(name));
    ASSERT_NE(f, nullptr) << name;
    if (name != "_start") {
      EXPECT_TRUE(f->flags & kFunctionDiscovered) << name;
      EXPECT_EQ(f->name, default_name(a->info, sym(name)));
    }
  }
  EXPECT_EQ(a->functions->functions.size(), expected.size());
  EXPECT_EQ(a->at(sym("_start"))->name, "entry");
}

TEST_P(Freestanding, InfersNoReturn) {
  auto a = analyse(dir_ / "stripped");
  for (const char *name : {"sys_exit", "fail", "_start"}) {
    const FunctionInfo *f = a->at(sym(name));
    ASSERT_NE(f, nullptr) << name;
    EXPECT_TRUE(f->flags & kFunctionNoReturn) << name;
    EXPECT_EQ(f->no_return, NoReturnReason::inferred) << name;
  }
  for (const char *name : {"check", "dispatch", "masked", "m0", "k7"}) {
    const FunctionInfo *f = a->at(sym(name));
    ASSERT_NE(f, nullptr) << name;
    EXPECT_FALSE(f->flags & kFunctionNoReturn) << name;
  }
}

TEST_P(Freestanding, FollowsJumpTables) {
  auto a = analyse(dir_ / "stripped");
  facts::Snapshot snap = a->snapshot();
  // Each case's call is inside the switch's body.
  auto calls_from = [&](const char *fn) {
    std::set<std::uint64_t> out;
    const FunctionInfo *f = a->at(sym(fn));
    if (!f) return out;
    auto flow = snap.get<Flow>(Location{{}, f->entry.offset});
    for (const FlowInsn &i : flow->insns)
      if (i.kind == FlowKind::call && f->body.contains(Address{a->info.space, i.address}))
        out.insert(i.targets.begin(), i.targets.end());
    return out;
  };
  std::set<std::uint64_t> from_dispatch = calls_from("dispatch");
  for (int i = 0; i < 10; ++i) EXPECT_TRUE(from_dispatch.contains(sym("m" + std::to_string(i)))) << "m" << i;
  std::set<std::uint64_t> from_masked = calls_from("masked");
  for (int i = 0; i < 8; ++i) EXPECT_TRUE(from_masked.contains(sym("k" + std::to_string(i)))) << "k" << i;
}

TEST_P(Freestanding, BodiesStopAtPaddingAndOtherFunctions) {
  auto a = analyse(dir_ / "stripped");
  facts::Snapshot snap = a->snapshot();
  lift::Lifter lifter(a->image, a->info.language);
  std::set<std::uint64_t> entries;
  for (const FunctionInfo &f : a->functions->functions) entries.insert(f.entry.offset);

  facts::AddressSet covered;
  for (const FunctionInfo &f : a->functions->functions) {
    auto flow = snap.get<Flow>(Location{{}, f.entry.offset});
    for (const facts::AddressRange &r : f.body.ranges()) {
      EXPECT_FALSE(covered.intersects(r)) << f.name << ": bodies overlap";
      // A range ends where flow can't continue: a jump, a return, a call
      // that never returns, or the start of another function.
      const FlowInsn *last = nullptr;
      for (const FlowInsn &i : flow->insns)
        if (r.contains(Address{a->info.space, i.address})) last = &i;
      ASSERT_NE(last, nullptr);
      EXPECT_EQ(last->address + last->length - 1, r.last.offset) << f.name;
      bool stops = !last->falls_through || entries.contains(last->address + last->length);
      if (last->kind == FlowKind::call)
        for (std::uint64_t t : last->targets)
          if (const FunctionInfo *callee = a->at(t)) stops = stops || (callee->flags & kFunctionNoReturn);
      EXPECT_TRUE(stops) << f.name << " body ends at " << std::hex << r.last.offset << " but flow goes on";
    }
    covered.add(f.body);
  }

  // Everything in .text outside every body is alignment padding (no-ops or
  // zeros), or dead code after a call that never returns (gcc -O0 emits
  // epilogues there): never code a body should have had.
  std::set<std::uint64_t> dead_after;  // where code after a no-return call starts
  for (const FunctionInfo &f : a->functions->functions) {
    auto flow = snap.get<Flow>(Location{{}, f.entry.offset});
    for (const FlowInsn &i : flow->insns)
      if (i.kind == FlowKind::call && f.body.contains(Address{a->info.space, i.address}))
        for (std::uint64_t t : i.targets)
          if (const FunctionInfo *callee = a->at(t); callee && (callee->flags & kFunctionNoReturn))
            dead_after.insert(i.address + i.length);
  }
  const loader::Block *text = nullptr;
  for (const loader::Block &b : a->image->blocks)
    if (b.name == ".text") text = &b;
  ASSERT_NE(text, nullptr);
  std::size_t padding = 0;
  bool dead = false;
  for (std::uint64_t at = text->start; at < text->start + text->size;) {
    if (covered.contains(Address{a->info.space, at})) {
      ++at;
      dead = false;
      continue;
    }
    if (dead_after.contains(at)) dead = true;
    if (dead) {
      ++at;
      continue;
    }
    std::array<std::byte, 1> b{};
    a->image->memory.read(at, b);
    if (b[0] == std::byte{0}) {
      ++at;
      ++padding;
      continue;
    }
    auto insn = lifter.lift(at);
    ASSERT_TRUE(insn) << std::hex << at;
    std::string m = insn->mnemonic;
    std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return std::tolower(c); });
    EXPECT_TRUE(m.find("nop") != std::string::npos || m == "int3" || m == "udf") << std::hex << at << " " << insn->text;
    at += insn->length;
    ++padding;
  }
  EXPECT_GT(padding, 0u);  // -falign-functions=16 left some
}

TEST_P(Freestanding, SameResultOnAnyNumberOfThreads) {
  auto one = analyse(dir_ / "stripped", 1);
  for (unsigned threads : {2u, 8u}) {
    auto many = analyse(dir_ / "stripped", threads);
    EXPECT_EQ(*many->functions, *one->functions) << threads << " threads";
  }
}

INSTANTIATE_TEST_SUITE_P(Toolchains, Freestanding, ::testing::ValuesIn(toolchains()),
                         [](const ::testing::TestParamInfo<Toolchain> &i) {
                           std::string n = i.param.name;
                           std::replace(n.begin(), n.end(), '-', '_');
                           return n;
                         });

// ---- a computed goto: an interpreter's byte-indexed dispatch table ----

class ComputedGoto : public Analysis, public ::testing::WithParamInterface<Toolchain> {
 protected:
  void SetUp() override {
    Analysis::SetUp();
    if (IsSkipped()) return;
    const Toolchain &t = GetParam();
    dir_ = testing::scratch_dir("analysis-goto-" + t.name);
    const std::string flags = std::string(kFreestanding) + " " + t.flags;
    if (!testing::compile(t.cc, read_source("computed_goto.c"), flags, dir_ / "named") ||
        !testing::compile(t.cc, read_source("computed_goto.c"), flags + " -s", dir_ / "stripped"))
      GTEST_SKIP() << t.name << " can't build the fixture";
    names_ = symbols(dir_ / "named");
  }
  std::filesystem::path dir_;
  std::map<std::string, std::uint64_t> names_;
};

// The table is followed: every handler is in interp's body, and the
// functions only the handlers call are found (the function list's Size
// was a few dozen bytes for such a function, CPython's eval loop).
TEST_P(ComputedGoto, FollowsAByteIndexedTable) {
  auto a = analyse(dir_ / "stripped");
  const FunctionInfo *interp = a->at(names_.at("interp"));
  ASSERT_NE(interp, nullptr);
  facts::Snapshot snap = a->snapshot();
  auto flow = snap.get<Flow>(Location{{}, interp->entry.offset});
  std::set<std::uint64_t> calls;
  for (const FlowInsn &i : flow->insns)
    if (i.kind == FlowKind::call && interp->body.contains(Address{a->info.space, i.address}))
      calls.insert(i.targets.begin(), i.targets.end());
  for (int n = 0; n < 6; ++n) {
    const std::string g = "g" + std::to_string(n);
    EXPECT_TRUE(calls.contains(names_.at(g))) << g;
    EXPECT_NE(a->at(names_.at(g)), nullptr) << g;
  }
}

INSTANTIATE_TEST_SUITE_P(Toolchains, ComputedGoto, ::testing::ValuesIn(toolchains()),
                         [](const ::testing::TestParamInfo<Toolchain> &i) {
                           std::string n = i.param.name;
                           std::replace(n.begin(), n.end(), '-', '_');
                           return n;
                         });

// ---- imports: PLT and IAT stubs ----

struct ImportCase {
  std::string name;
  std::string cc;
  std::string flags;
  bool stubs;  // calls go through stubs (not -fno-plt)
};

class Imports : public Analysis, public ::testing::WithParamInterface<ImportCase> {};

TEST_P(Imports, StubsTakeTheImportsNameAndNoReturnFollows) {
  const ImportCase &c = GetParam();
  auto dir = testing::scratch_dir("analysis-imports-" + c.name);
  const auto exe = dir / "prog.exe";  // mingw adds .exe to any other name
  if (c.cc.empty() || !testing::compile(c.cc, read_source("imports.c"), c.flags, exe))
    GTEST_SKIP() << c.name << " can't build the fixture";
  auto a = analyse(exe);

  if (c.stubs) {
    for (const char *name : {"puts", "exit", "abort"}) {
      const FunctionInfo *f = a->named(name);
      ASSERT_NE(f, nullptr) << name;
      EXPECT_TRUE(f->flags & kFunctionThunk) << name;
      EXPECT_EQ(f->import, name);
      EXPECT_TRUE(a->info.import_at(f->thunk_target)) << name;
      const loader::Block *b = a->block_at(f->entry.offset);
      ASSERT_NE(b, nullptr);
      if (a->image->format == loader::Format::elf) {
        EXPECT_EQ(b->name.rfind(".plt", 0), 0u) << name << " in " << b->name;
      }
    }
    EXPECT_EQ(a->named("exit")->no_return, NoReturnReason::named);
    EXPECT_EQ(a->named("abort")->no_return, NoReturnReason::named);
    EXPECT_EQ(a->named("puts")->no_return, NoReturnReason::none);
  }
  // die() ends in exit(): it never returns, whether exit is reached through
  // a stub or through the GOT. (PE symbols aren't read: no names there.)
  if (a->image->format == loader::Format::pe) return;
  const FunctionInfo *die = nullptr;
  for (const FunctionInfo &f : a->functions->functions)
    if (f.name.rfind("die", 0) == 0) die = &f;
  ASSERT_NE(die, nullptr);
  EXPECT_EQ(die->no_return, NoReturnReason::inferred);
  const FunctionInfo *main_fn = a->named("main");
  ASSERT_NE(main_fn, nullptr);
  EXPECT_FALSE(main_fn->flags & kFunctionNoReturn);
}

std::vector<ImportCase> import_cases() {
  std::vector<ImportCase> out;
  out.push_back({"x86_64", REVKIT_TEST_CC, "-O2", true});
  out.push_back({"x86_64_noplt", REVKIT_TEST_CC, "-O2 -fno-plt", false});
  out.push_back({"x86_64_lazy", REVKIT_TEST_CC, "-O2 -fcf-protection=none -Wl,-z,lazy", true});
  out.push_back({"aarch64", REVKIT_TEST_AARCH64_CC, "-O2", true});
  out.push_back({"riscv64", REVKIT_TEST_RISCV64_CC, "-O2", true});
  out.push_back({"mingw", REVKIT_TEST_MINGW_CC, "-O2", true});
  return out;
}

INSTANTIATE_TEST_SUITE_P(Toolchains, Imports, ::testing::ValuesIn(import_cases()),
                         [](const ::testing::TestParamInfo<ImportCase> &i) { return i.param.name; });

// ---- the fact engine ----

class Freestanding86 : public Analysis {
 protected:
  void SetUp() override {
    Analysis::SetUp();
    if (IsSkipped()) return;
    dir_ = testing::scratch_dir("analysis-engine");
    std::string flags = std::string(kFreestanding) + " -O2 -DSPLIT_PAGES";
    if (!testing::compile(REVKIT_TEST_CC, read_source("freestanding.c"), flags, dir_ / "named") ||
        !testing::compile(REVKIT_TEST_CC, read_source("freestanding.c"), flags + " -s", dir_ / "stripped"))
      GTEST_SKIP() << "no host compiler";
    names_ = symbols(dir_ / "named");
    if (loader::load_file(dir_ / "named").machine != 62) GTEST_SKIP() << "host isn't x86-64";
  }
  std::filesystem::path dir_;
  std::map<std::string, std::uint64_t> names_;
};

TEST_F(Freestanding86, DerivedFactsCarryRuleVersionAndInputs) {
  auto a = analyse(dir_ / "stripped");
  facts::Snapshot snap = a->snapshot();
  auto all = snap.fact<Functions>(ProgramKey{});
  EXPECT_EQ(all.rule, "analysis.functions");
  EXPECT_EQ(all.rule_version, Functions::version);
  EXPECT_EQ(all.confidence, facts::Confidence::Certain);
  EXPECT_TRUE(std::any_of(all.inputs.begin(), all.inputs.end(),
                          [](const std::string &i) { return i.rfind("analysis.flow(", 0) == 0; }));

  auto flow = snap.fact<Flow>(Location{{}, names_.at("dispatch")});
  EXPECT_EQ(flow.rule, "analysis.flow");
  EXPECT_TRUE(std::any_of(flow.inputs.begin(), flow.inputs.end(),
                          [](const std::string &i) { return i.rfind("page(", 0) == 0; }));
  EXPECT_FALSE(flow.value->insns.empty());

  auto one = snap.fact<Function>(Location{{}, names_.at("check")});
  EXPECT_EQ(one.value->entry.offset, names_.at("check"));
  auto none = snap.fact<Function>(Location{{}, names_.at("check") + 1});
  EXPECT_EQ(none.confidence, facts::Confidence::Uncertain);
  EXPECT_TRUE(none.value->name.empty());

  // Not code: nothing to decode, nothing to call a function.
  auto data = snap.fact<Flow>(Location{{}, 0x10});
  EXPECT_TRUE(data.value->insns.empty());
  EXPECT_EQ(data.confidence, facts::Confidence::Uncertain);
}

TEST_F(Freestanding86, PatchedBytesRecomputeOnlyWhatReadThem) {
  auto a = analyse(dir_ / "stripped");
  facts::Snapshot before = a->snapshot();
  const std::uint64_t fail = names_.at("fail"), check = names_.at("check"), m9 = names_.at("m9");
  ASSERT_EQ(a->at(fail)->no_return, NoReturnReason::inferred);
  ASSERT_NE(fail / facts::kPageSize, m9 / facts::kPageSize);
  const auto check_body = a->at(check)->body;
  facts::Engine &engine = a->db->engine();

  // A byte no query read (on a page of its own, far from the image)
  // changes nothing: every memo is re-validated, nothing recomputed.
  {
    auto tx = a->db->begin();
    tx.write_bytes(Address{a->info.space, 0x70000000}, std::string(1, '\x42'));
    tx.commit();
    engine.reset_stats();
    EXPECT_EQ(*a->snapshot().get<Functions>(ProgramKey{}), *a->functions);
    EXPECT_EQ(engine.stats<Flow>().executions, 0u);
    EXPECT_EQ(engine.stats<Functions>().executions, 0u);
  }

  // fail() now returns at once: it isn't no-return any more, so check()
  // goes on after calling it.
  {
    auto tx = a->db->begin();
    tx.write_bytes(Address{a->info.space, fail}, std::string(1, '\xc3'));  // ret
    tx.commit();
  }
  engine.reset_stats();
  facts::Snapshot snap = a->snapshot();
  auto after = snap.get<Functions>(ProgramKey{});
  const FunctionInfo *patched = after->find(fail);
  ASSERT_NE(patched, nullptr);
  EXPECT_EQ(patched->no_return, NoReturnReason::none);
  EXPECT_NE(after->find(check)->body, check_body);
  EXPECT_EQ(after->find(m9)->body, a->at(m9)->body);

  // Only flows that read the patched page decoded again; m9's, on a page
  // of its own, was re-validated by fingerprint.
  facts::QueryStats flow = engine.stats<Flow>();
  EXPECT_GT(flow.validations, 0u);
  EXPECT_LT(flow.executions, a->functions->functions.size());
  EXPECT_EQ(engine.stats<Functions>().executions, 1u);

  // A snapshot taken before the patch still answers for its revision.
  EXPECT_EQ(before.get<Functions>(ProgramKey{})->find(fail)->no_return, NoReturnReason::inferred);
}

// Without patches, decoding reads one patch.page gate per page and no
// patch.span at all (docs/patching.md).
TEST_F(Freestanding86, WithoutPatchesNoSpanIsRead) {
  auto a = analyse(dir_ / "stripped");
  facts::Engine &engine = a->db->engine();
  EXPECT_EQ(engine.stats<facts::PatchSpan>().executions, 0u);
  EXPECT_GT(engine.stats<facts::PatchedPage>().executions, 0u);
  facts::Snapshot snap = a->snapshot();
  for (const FunctionInfo &f : a->functions->functions) {
    auto flow = snap.fact<Flow>(Location{{}, f.flow_key()});
    auto read = [&](std::string_view rule) {
      return std::any_of(flow.inputs.begin(), flow.inputs.end(),
                         [&](const std::string &i) { return i.rfind(std::string(rule) + "(", 0) == 0; });
    };
    EXPECT_TRUE(read("patch.page")) << f.name;
    EXPECT_FALSE(read("patch.span")) << f.name;
  }
}

// A patch asserted after the import re-decodes the flows near it: the
// first one near a page, the flows that read that page; once the page has
// one, only the flows that read the patched 256-byte span. Every other
// flow keeps its memo, and retracting the patches brings the first decode
// back.
TEST_F(Freestanding86, APatchAfterImportRedecodesOnlyNearIt) {
  auto a = analyse(dir_ / "stripped");
  const std::uint64_t m9 = names_.at("m9"), k7 = names_.at("k7");
  ASSERT_EQ(m9 % facts::kPageSize, 0u);  // -DSPLIT_PAGES
  ASSERT_EQ(k7 / facts::kPageSize, m9 / facts::kPageSize);
  ASSERT_NE(k7 >> facts::kSpanShift, m9 >> facts::kSpanShift);
  const facts::SpaceId space = a->info.space;
  const facts::Provenance me = facts::Provenance::user("me");
  facts::Engine &engine = a->db->engine();

  // Each function's flow and what it read ("rule(key in hex)"), by entry.
  struct Read {
    facts::Ref<FlowGraph> flow;
    std::vector<std::string> inputs;
  };
  auto flows = [&] {
    std::map<std::uint64_t, Read> out;
    facts::Snapshot snap = a->snapshot();
    for (const FunctionInfo &f : snap.get<Functions>(ProgramKey{})->functions) {
      auto fact = snap.fact<Flow>(Location{{}, f.flow_key()});
      out[f.entry.offset] = {fact.value, fact.inputs};
    }
    return out;
  };
  auto dep = [](std::string_view rule, const auto &key) {
    std::string out(rule);
    out += '(';
    for (unsigned char c : facts::encode_to_string(key)) {
      static constexpr char kHex[] = "0123456789abcdef";
      out += kHex[c >> 4];
      out += kHex[c & 15];
    }
    return out + ')';
  };
  auto reads = [](const Read &r, const std::string &d) {
    return std::find(r.inputs.begin(), r.inputs.end(), d) != r.inputs.end();
  };
  const auto before = flows();
  ASSERT_TRUE(before.contains(m9) && before.contains(k7));

  // 1. ret over m9's first instruction, the first patch near its page: m9
  // decodes as one return, and no flow that didn't read the page (its
  // patch.page gate) decoded again.
  const std::string m9_page = dep("patch.page", facts::PageKey{space, m9 / facts::kPageSize});
  facts::Seq first = 0;
  {
    auto tx = a->db->begin();
    first = tx.assert_fact(me, facts::FactKey::patch(Address{space, m9}), std::string("\xc3"));
    tx.commit();
  }
  engine.reset_stats();
  const auto one = flows();
  ASSERT_EQ(one.at(m9).flow->insns.size(), 1u);
  EXPECT_EQ(one.at(m9).flow->insns[0].kind, FlowKind::ret);
  std::size_t kept = 0;
  for (const auto &[entry, r] : before) {
    EXPECT_FALSE(reads(r, dep("patch.span", facts::PatchSpan::Key{space, m9 >> facts::kSpanShift})));
    if (!one.contains(entry) || reads(r, m9_page)) continue;
    EXPECT_EQ(one.at(entry).flow, r.flow) << std::hex << entry << " decoded again";
    ++kept;
  }
  EXPECT_GT(kept, 0u);
  EXPECT_LT(engine.stats<Flow>().executions, before.size());

  // 2. ret over k7 too, on the page that has a patch now: its gate holds
  // still, so only the flows that read k7's span decode again. m9's, at
  // the page's start, is one that keeps its memo.
  const std::string k7_span = dep("patch.span", facts::PatchSpan::Key{space, k7 >> facts::kSpanShift});
  facts::Seq second = 0;
  {
    auto tx = a->db->begin();
    second = tx.assert_fact(me, facts::FactKey::patch(Address{space, k7}), std::string("\xc3"));
    tx.commit();
  }
  const auto two = flows();
  ASSERT_EQ(two.at(k7).flow->insns.size(), 1u);
  ASSERT_FALSE(reads(one.at(m9), k7_span));
  kept = 0;
  for (const auto &[entry, r] : one) {
    if (!two.contains(entry) || !reads(r, m9_page) || reads(r, k7_span)) continue;
    EXPECT_EQ(two.at(entry).flow, r.flow) << std::hex << entry << " decoded again";
    ++kept;
  }
  EXPECT_GT(kept, 0u);

  // 3. Both retracted: the first decode is back, and the functions too.
  {
    auto tx = a->db->begin();
    tx.retract(me, second);
    tx.retract(me, first);
    tx.commit();
  }
  const auto back = flows();
  ASSERT_EQ(back.size(), before.size());
  for (const auto &[entry, r] : before) EXPECT_EQ(*back.at(entry).flow, *r.flow) << std::hex << entry;
  EXPECT_EQ(*a->snapshot().get<Functions>(ProgramKey{}), *a->functions);
}

TEST_F(Freestanding86, ConcurrentReadersAgree) {
  auto a = analyse(dir_ / "stripped");
  // A fresh store read by many threads at once: the same functions, and no
  // races in the decoder pool or the engine (run under the tsan preset).
  auto b = std::make_unique<Analysed>();
  b->image = a->image;
  register_queries(b->db->engine());
  b->info = a->info;
  import_image(*b->db, ProgramKey{}, *b->image, b->info);
  facts::Snapshot snap = b->snapshot();
  std::vector<Location> keys;
  for (const FunctionInfo &f : a->functions->functions) keys.push_back({{}, f.entry.offset});
  facts::ThreadPool pool(8);
  auto infos = snap.get_all<Function>(keys, &pool);
  for (std::size_t i = 0; i < keys.size(); ++i) EXPECT_EQ(*infos[i], a->functions->functions[i]);
}

// Two programs in one store, each under its own key and code space, give
// what each gives alone.
TEST_F(Freestanding86, ProgramsShareAStoreByKey) {
  auto named = analyse(dir_ / "named"), stripped = analyse(dir_ / "stripped");
  facts::FactDb db;
  register_queries(db.engine());
  ProgramInfo a = describe(*named->image, loader::guess_language(*named->image)->id(), 16);
  ProgramInfo b = describe(*stripped->image, loader::guess_language(*stripped->image)->id(), 18);
  {
    auto tx = db.begin();
    stage_image(tx, ProgramKey{"p/named"}, *named->image, a);
    stage_image(tx, ProgramKey{"p/stripped"}, *stripped->image, b);
    tx.commit();
  }
  facts::Snapshot snap = db.snapshot();
  auto one = snap.get<Functions>(ProgramKey{"p/named"}), two = snap.get<Functions>(ProgramKey{"p/stripped"});
  ASSERT_EQ(one->functions.size(), named->functions->functions.size());
  ASSERT_EQ(two->functions.size(), stripped->functions->functions.size());
  for (std::size_t i = 0; i < one->functions.size(); ++i) {
    EXPECT_EQ(one->functions[i].name, named->functions->functions[i].name);
    EXPECT_EQ(one->functions[i].entry, (facts::Address{16, named->functions->functions[i].entry.offset}));
  }
  for (std::size_t i = 0; i < two->functions.size(); ++i)
    EXPECT_EQ(two->functions[i].body.ranges().size(), stripped->functions->functions[i].body.ranges().size());
  EXPECT_EQ(one->code, named->functions->code);
  EXPECT_EQ(snap.get<Function>(Location{{"p/named"}, names_.at("check")})->name, "check");
  EXPECT_EQ(snap.get<Function>(Location{{"p/stripped"}, names_.at("check")})->name,
            default_name(b, names_.at("check")));
  EXPECT_EQ(snap.fact<Flow>(Location{{"p/named"}, names_.at("check")}).inputs.front(), "analysis.program(p/named)");
}

// The code the listing shows: every walked instruction, in order, the
// padding between functions left out.
TEST_F(Freestanding86, CodeIsWhatFunctionsReach) {
  auto a = analyse(dir_ / "stripped");
  const auto &code = a->functions->code;
  ASSERT_GT(code.size(), 50u);
  for (std::size_t i = 0; i < code.size(); ++i) {
    if (i) EXPECT_LE(code[i - 1].address + code[i - 1].length, code[i].address);
    bool in_body = false;
    for (const FunctionInfo &f : a->functions->functions)
      in_body |= f.body.contains(Address{a->info.space, code[i].address});
    EXPECT_TRUE(in_body) << std::hex << code[i].address;
  }
  // m9 is page-aligned: the bytes before it are padding, never code.
  const std::uint64_t m9 = names_.at("m9");
  auto at = std::lower_bound(code.begin(), code.end(), m9, [](const CodeUnit &c, std::uint64_t x) { return c.address < x; });
  ASSERT_NE(at, code.begin());
  EXPECT_LT(std::prev(at)->address + std::prev(at)->length + 64, m9);
}

// FUNCTION_BOUNDS and FLOW_OVERRIDE assertions feed discovery, and an edit
// re-runs only the flows that read it (through its span of the key index).
// Asserted bodies of two entries that overlap (concurrent bounds edits on
// two daemons, docs/collab.md) come out disjoint: a contested address goes
// to the claiming entry closest at or before it, whichever edit came first.
TEST_F(Freestanding86, OverlappingAssertedBodiesAreMadeDisjoint) {
  const std::uint64_t lo = std::min(names_.at("m0"), names_.at("m3")), hi = std::max(names_.at("m0"), names_.at("m3"));
  ASSERT_GT(hi, lo + 1);
  std::vector<FunctionList> results;
  for (bool reversed : {false, true}) {
    auto a = analyse(dir_ / "stripped");
    const facts::SpaceId space = a->info.space;
    auto body = [&](std::uint64_t first, std::uint64_t last) {
      return facts::AddressSet(facts::AddressRange{{space, first}, {space, last}});
    };
    std::vector<std::pair<std::uint64_t, facts::AddressSet>> edits{{lo, body(lo, hi + 4)}, {hi, body(lo + 1, hi + 8)}};
    if (reversed) std::reverse(edits.begin(), edits.end());
    for (auto &[entry, set] : edits) {
      auto tx = a->db->begin();
      tx.assert_fact(facts::Provenance::user(reversed ? "b" : "a"), facts::FactKey::function({space, entry}), set);
      tx.commit();
    }
    auto fs = a->snapshot().get<Functions>(ProgramKey{});
    ASSERT_NE(fs->find(lo), nullptr);
    ASSERT_NE(fs->find(hi), nullptr);
    EXPECT_EQ(fs->find(lo)->body, body(lo, hi - 1));
    EXPECT_EQ(fs->find(hi)->body, body(hi, hi + 8));
    results.push_back(*fs);
  }
  EXPECT_EQ(results[0].functions.size(), results[1].functions.size());
  for (std::size_t i = 0; i < results[0].functions.size(); ++i)
    EXPECT_EQ(results[0].functions[i].body, results[1].functions[i].body);
}

TEST_F(Freestanding86, AssertionsSteerDiscovery) {
  auto a = analyse(dir_ / "stripped");
  facts::Engine &engine = a->db->engine();
  const facts::SpaceId space = a->info.space;
  const std::uint64_t m3 = names_.at("m3"), m0 = names_.at("m0"), check = names_.at("check"),
                      fail = names_.at("fail"), dispatch = names_.at("dispatch");
  const facts::Provenance user = facts::Provenance::user("t");
  auto assert_fact = [&](facts::FactKey k, facts::FactValue v) {
    auto tx = a->db->begin();
    facts::Seq s = tx.assert_fact(user, std::move(k), std::move(v));
    tx.commit();
    engine.reset_stats();
    return s;
  };
  auto retract = [&](facts::Seq s) {
    auto tx = a->db->begin();
    tx.retract(user, s);
    tx.commit();
    engine.reset_stats();
  };
  auto now = [&] { return a->snapshot().get<Functions>(ProgramKey{}); };
  const std::size_t count = a->functions->functions.size();
  // The flows that read the overrides near `at`: those with a flow
  // instruction in its 256-byte span of the key index.
  auto readers = [&](std::uint64_t at) {
    std::uint64_t n = 0;
    facts::Snapshot snap = a->snapshot();
    for (const FunctionInfo &f : now()->functions) {
      auto g = snap.get<Flow>(Location{{}, f.entry.offset});
      n += std::any_of(g->insns.begin(), g->insns.end(), [&](const FlowInsn &i) {
        return i.kind != FlowKind::fall && i.address >> facts::kSpanShift == at >> facts::kSpanShift;
      });
    }
    engine.reset_stats();
    return n;
  };

  // Not a function: m3 leaves the list and the code, though dispatch calls
  // it. No flow read that fact, so none re-runs.
  facts::Seq gone = assert_fact(facts::FactKey::function({space, m3}), kNotAFunction);
  auto after = now();
  EXPECT_EQ(after->find(m3), nullptr);
  EXPECT_EQ(after->functions.size(), count - 1);
  EXPECT_FALSE(std::any_of(after->code.begin(), after->code.end(), [&](const CodeUnit &c) { return c.address == m3; }));
  EXPECT_EQ(engine.stats<Flow>().executions, 0u);
  EXPECT_EQ(engine.stats<Functions>().executions, 1u);

  // Asserted back as an entry, with a body of its first byte: a function
  // again, flagged, and m3's flow validated rather than decoded again.
  facts::AddressSet first_byte(facts::AddressRange{{space, m3}, {space, m3}});
  facts::Seq back = assert_fact(facts::FactKey::function({space, m3}), first_byte);
  retract(gone);
  after = now();
  ASSERT_NE(after->find(m3), nullptr);
  EXPECT_EQ(after->find(m3)->body, first_byte);
  EXPECT_EQ(after->find(m3)->flags & (kFunctionAssertedEntry | kFunctionAssertedBody),
            kFunctionAssertedEntry | kFunctionAssertedBody);
  EXPECT_EQ(engine.stats<Flow>().executions, 0u);
  // An asserted body is taken out of the others: m0's first byte to m3.
  retract(back);
  assert_fact(facts::FactKey::function({space, m3}), facts::AddressSet(facts::AddressRange{{space, m0}, {space, m0}}));
  after = now();
  EXPECT_FALSE(after->find(m0)->body.contains({space, m0}));
  EXPECT_TRUE(after->find(m3)->body.contains({space, m0}));
  EXPECT_EQ(after->functions.size(), count);

  // A flow override on check's call to fail, read as a branch: fail is no
  // longer called, so it is not a function and check's body goes on into
  // its code. Only flows that read the span re-run (and all but check's
  // come out the same).
  auto check_flow = a->snapshot().get<Flow>(Location{{}, check});
  std::uint64_t call = 0;
  for (const FlowInsn &i : check_flow->insns)
    if (i.kind == FlowKind::call && i.targets == std::vector<std::uint64_t>{fail}) call = i.address;
  ASSERT_NE(call, 0u);
  const std::uint64_t near_call = readers(call);
  facts::Seq branch =
      assert_fact(facts::FactKey::flow_override({space, call}), static_cast<std::int64_t>(FlowOverride::branch));
  after = now();
  EXPECT_EQ(after->find(fail), nullptr);
  EXPECT_TRUE(after->find(check)->body.contains({space, fail}));
  // (fail's own flow isn't read again: fail is no entry now.)
  EXPECT_GE(engine.stats<Flow>().executions, 1u);
  EXPECT_LE(engine.stats<Flow>().executions, near_call);
  EXPECT_LT(near_call, count / 2);
  EXPECT_EQ(a->snapshot().get<Flow>(Location{{}, check})->at(call)->kind, FlowKind::jump);

  // CALL_RETURN on dispatch's call to m0: a tail call there.
  retract(branch);
  auto dispatch_flow = a->snapshot().get<Flow>(Location{{}, dispatch});
  std::uint64_t to_m0 = 0;
  for (const FlowInsn &i : dispatch_flow->insns)
    if (i.kind == FlowKind::call && i.targets == std::vector<std::uint64_t>{m0}) to_m0 = i.address;
  ASSERT_NE(to_m0, 0u);
  const std::uint64_t near_m0 = readers(to_m0);
  assert_fact(facts::FactKey::flow_override({space, to_m0}), static_cast<std::int64_t>(FlowOverride::call_return));
  after = now();
  const FlowInsn *tail = a->snapshot().get<Flow>(Location{{}, dispatch})->at(to_m0);
  ASSERT_NE(tail, nullptr);
  EXPECT_TRUE(tail->tail_call);
  EXPECT_FALSE(tail->falls_through);
  EXPECT_EQ(engine.stats<Flow>().executions, near_m0);
  EXPECT_NE(after->find(fail), nullptr);
  EXPECT_FALSE(after->find(dispatch)->flags & kFunctionNoReturn);
}

TEST(FlowOverrides, FollowGhidra) {
  auto with = [](FlowKind kind, bool falls, FlowOverride o) {
    FlowInsn i{0x1000, 5, kind, falls, false, {0x2000}};
    detail::apply_override(i, o);
    return i;
  };
  FlowInsn i = with(FlowKind::call, true, FlowOverride::branch);
  EXPECT_EQ(i.kind, FlowKind::jump);
  EXPECT_FALSE(i.falls_through);
  EXPECT_EQ(i.targets, std::vector<std::uint64_t>{0x2000});
  i = with(FlowKind::jump, false, FlowOverride::call);
  EXPECT_EQ(i.kind, FlowKind::call);
  EXPECT_TRUE(i.falls_through);
  i = with(FlowKind::jump, false, FlowOverride::call_return);
  EXPECT_EQ(i.kind, FlowKind::call);
  EXPECT_TRUE(i.tail_call);
  EXPECT_FALSE(i.falls_through);
  i = with(FlowKind::branch, true, FlowOverride::call_return);  // left alone, as Ghidra does
  EXPECT_EQ(i.kind, FlowKind::branch);
  i = with(FlowKind::branch, true, FlowOverride::ret);  // a conditional return
  EXPECT_EQ(i.kind, FlowKind::ret);
  EXPECT_TRUE(i.falls_through);
  EXPECT_TRUE(i.targets.empty());
  i = with(FlowKind::jump_indirect, false, FlowOverride::ret);
  EXPECT_EQ(i.kind, FlowKind::ret);
  EXPECT_FALSE(i.falls_through);
  i = with(FlowKind::fall, true, FlowOverride::ret);  // not a flow instruction
  EXPECT_EQ(i.kind, FlowKind::fall);
}

// FALLTHROUGH values, and a FlowInsn's override through its codec.
TEST(FallthroughOverrides, ValuesAndCodec) {
  EXPECT_EQ(fallthrough_override(facts::FactValue{}), std::nullopt);
  EXPECT_EQ(fallthrough_override(facts::FactValue{kDefaultFallthrough}), std::nullopt);
  EXPECT_EQ(fallthrough_override(facts::FactValue{kNoFallthrough}), (FallthroughOverride{false, 0}));
  EXPECT_EQ(fallthrough_override(facts::FactValue{facts::Address{1, 0x1009}}), (FallthroughOverride{true, 0x1009}));
  FlowInsn i{0x1000, 5, FlowKind::call, true, false, {0x2000}};
  EXPECT_EQ(i.fallthrough(), 0x1005u);
  i.fall_override = true;
  i.fall_to = 0x0ff0;  // backwards
  i.conditional = true;
  EXPECT_EQ(i.fallthrough(), 0x0ff0u);
  FlowGraph g;
  g.entry = 0x1000;
  g.insns.push_back(i);
  FlowInsn none{0x1005, 2, FlowKind::fall, false};
  none.fall_override = true;
  g.insns.push_back(none);
  g.refs.push_back({0, RefKind::fallthrough, false, 0x0ff0});
  const FlowGraph back = facts::decode_from_string<FlowGraph>(facts::encode_to_string(g));
  EXPECT_EQ(back, g);
  EXPECT_EQ(back.insns[0].fallthrough(), 0x0ff0u);
  EXPECT_TRUE(back.insns[1].fall_override);
  EXPECT_FALSE(back.insns[1].falls_through);
}

// ---- raw firmware on other processors ----

// A SuperH-4 image written out by hand: every call goes through a register
// loaded from a literal pool (jsr @rN), and a task function is only passed
// as a pointer, with a prologue no start pattern knows. Discovery resolves
// the call (raw images, every processor) and makes a function of the
// pointer's target, a valid subroutine (Ghidra's Reference analyzer).
TEST(RawFirmware, SuperHComputedCallsAndPointersToCode) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::vector<std::uint16_t> words = {
      0xd002,  // 00 mov.l @(0xc),r0     r0 = create
      0xd403,  // 02 mov.l @(0x10),r4    r4 = task (an argument)
      0x400b,  // 04 jsr @r0
      0x0009,  // 06 nop
      0xaffe,  // 08 bra 08
      0x0009,  // 0a nop
      0x0020, 0x8c00,  // 0c .long create
      0x0040, 0x8c00,  // 10 .long task
  };
  std::vector<std::uint16_t> image(0x60, 0);
  std::copy(words.begin(), words.end(), image.begin());
  // create at 0x20: push r8, keep the argument, return
  const std::vector<std::uint16_t> create = {0x2f86, 0x6843, 0x000b, 0x68f6};
  std::copy(create.begin(), create.end(), image.begin() + 0x10);
  // task at 0x40: push r8, mov #1,r8, add r8,r4, return
  const std::vector<std::uint16_t> task = {0x2f86, 0xe801, 0x348c, 0x000b, 0x68f6};
  std::copy(task.begin(), task.end(), image.begin() + 0x20);
  auto bytes = std::make_shared<loader::Bytes>(image.size() * 2);
  for (std::size_t i = 0; i < image.size(); ++i) {
    (*bytes)[2 * i] = static_cast<std::byte>(image[i] & 0xff);
    (*bytes)[2 * i + 1] = static_cast<std::byte>(image[i] >> 8);
  }
  loader::RawOptions o;
  o.language = "SuperH4:LE:32:default:default";
  constexpr std::uint64_t base = 0x8c000000;
  o.base = base;
  o.entry = base;
  auto img = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  facts::FactDb db;
  register_queries(db.engine());
  ProgramInfo info = describe(*img, o.language);
  ASSERT_TRUE(info.search);
  import_image(db, ProgramKey{}, *img, info);
  auto functions = db.snapshot().get<Functions>(ProgramKey{});
  std::set<std::uint64_t> entries;
  for (const FunctionInfo &f : functions->functions) entries.insert(f.entry.offset);
  EXPECT_EQ(entries, (std::set<std::uint64_t>{base, base + 0x20, base + 0x40}));
  ASSERT_NE(functions->find(base + 0x40), nullptr);
  EXPECT_TRUE(functions->find(base + 0x40)->flags & kFunctionSearched);
  // The literal pool is data, never decoded.
  for (const CodeUnit &c : functions->code)
    EXPECT_FALSE(c.address >= base + 0xc && c.address < base + 0x14) << std::hex << c.address;
}

// Cortex-M firmware loaded at its flash address (0x08000000, an STM32's),
// with no entry given: the vector table at the image's start is read as
// pointers (the spec's code_ptr symbols, which it places at 0), so Reset,
// NMI and an external interrupt's handler are functions named after their
// vectors, and the table itself is data, never decoded as Thumb code.
TEST(RawFirmware, CortexMVectorTableAtTheFlashBase) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr std::uint64_t base = 0x08000000;
  std::vector<std::uint32_t> words(0x60 / 4, 0);
  words[0] = 0x20001000;                  // initial stack pointer
  words[1] = base + 0x4c + 1;             // Reset (Thumb)
  words[2] = base + 0x50 + 1;             // NMI
  words[3] = base + 0x50 + 1;             // HardFault: the same handler
  words[0x40 / 4] = base + 0x54 + 1;      // the first external interrupt (the spec's "IRQ")
  words[0x44 / 4] = base + 0x58 + 1;      // the second, IRQ1
  words[0x48 / 4] = 0xffffffff;           // erased flash: the table ends
  auto bytes = std::make_shared<loader::Bytes>(0x60);
  for (std::size_t i = 0; i < words.size(); ++i)
    for (int b = 0; b < 4; ++b) (*bytes)[4 * i + b] = static_cast<std::byte>(words[i] >> (8 * b));
  auto put16 = [&](std::size_t at, std::uint16_t v) {
    (*bytes)[at] = static_cast<std::byte>(v & 0xff);
    (*bytes)[at + 1] = static_cast<std::byte>(v >> 8);
  };
  put16(0x4c, 0xe7fe);  // Reset: b .
  put16(0x50, 0x4770);  // NMI: bx lr
  put16(0x54, 0x4770);  // IRQ: bx lr
  put16(0x58, 0x4770);  // IRQ1: bx lr
  loader::RawOptions o;
  o.language = "ARM:LE:32:Cortex:default";
  o.base = base;
  auto img = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  facts::FactDb db;
  register_queries(db.engine());
  ProgramInfo info = describe(*img, o.language);
  import_image(db, ProgramKey{}, *img, info);
  auto functions = db.snapshot().get<Functions>(ProgramKey{});
  auto name_at = [&](std::uint64_t a) {
    const FunctionInfo *f = functions->find(a);
    return f ? f->name : std::string("(none)");
  };
  EXPECT_EQ(name_at(base + 0x4c), "Reset");
  EXPECT_EQ(name_at(base + 0x50), "NMI");
  EXPECT_EQ(name_at(base + 0x54), "IRQ");
  EXPECT_EQ(name_at(base + 0x58), "IRQ1");
  for (const CodeUnit &c : functions->code)
    EXPECT_FALSE(c.address >= base && c.address < base + 0x48) << "vector table decoded at " << std::hex << c.address;
}

// A shrink-wrapped MIPS function: two early exits, each a branch with its
// delay slot, and a load they test, before the prologue a start pattern
// knows (addiu sp, sp, -32; sw gp, 16(sp)), 20 bytes into the function.
// Nothing calls it; it starts at its first early exit, not at the
// prologue, and its exit block is its own.
TEST(RawFirmware, MipsShrinkWrappedPrologueAfterSeveralEarlyExits) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::vector<std::uint32_t> words = {
      // 00 main (the entry): addiu sp, sp, -24; sw ra, 20(sp); jal helper;
      // nop; lw ra, 20(sp); jr ra; addiu sp, sp, 24
      0x27bdffe8, 0xafbf0014, 0x0c000007, 0x00000000, 0x8fbf0014, 0x03e00008, 0x27bd0018,
      // 1c helper: jr ra; li v0, 1
      0x03e00008, 0x24020001,
      // 24 f: beqz a0, out; move v0, zero; lw v1, 4(a0); beqz v1, out; nop
      0x1080000c, 0x00001021, 0x8c830004, 0x10600009, 0x00000000,
      // 38 addiu sp, sp, -32; sw gp, 16(sp); sw ra, 28(sp); jal helper;
      // move a0, v1; lw ra, 28(sp); jr ra; addiu sp, sp, 32
      0x27bdffe0, 0xafbc0010, 0xafbf001c, 0x0c000007, 0x00602021, 0x8fbf001c, 0x03e00008, 0x27bd0020,
      // 58 out: jr ra; nop
      0x03e00008, 0x00000000,
  };
  auto bytes = std::make_shared<loader::Bytes>(0x80);
  for (std::size_t i = 0; i < words.size(); ++i)
    for (int b = 0; b < 4; ++b) (*bytes)[4 * i + b] = static_cast<std::byte>(words[i] >> (24 - 8 * b));
  loader::RawOptions o;
  o.language = "MIPS:BE:32:default:default";
  constexpr std::uint64_t base = 0x80000000;
  o.base = base;
  o.entry = base;
  auto img = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  facts::FactDb db;
  register_queries(db.engine());
  ProgramInfo info = describe(*img, o.language);
  ASSERT_TRUE(info.search);
  ASSERT_FALSE(info.patterns.empty());
  import_image(db, ProgramKey{}, *img, info);
  auto functions = db.snapshot().get<Functions>(ProgramKey{});
  std::set<std::uint64_t> entries;
  for (const FunctionInfo &f : functions->functions) entries.insert(f.entry.offset);
  EXPECT_TRUE(entries.contains(base + 0x24)) << "the shrink-wrapped function, from its first early exit";
  EXPECT_FALSE(entries.contains(base + 0x38));
  const FunctionInfo *f = functions->find(base + 0x24);
  ASSERT_NE(f, nullptr);
  for (std::uint64_t a : {0x24u, 0x30u, 0x38u, 0x58u}) EXPECT_TRUE(f->body.contains(facts::Address{f->entry.space, base + a})) << std::hex << a;
}

// AVR (avr8: code space addressed in 16-bit words, registers mapped into
// the data space "mem"): keys are byte offsets, an icall through a Z loaded
// with a word address reaches the function at twice it, register values go
// through R30/R31 at mem:0x1e, and default names count words.
TEST(RawFirmware, AvrWordAddressedCode) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  // The vectors: reset jumps to 0x100, the others return.
  std::vector<std::uint16_t> image = {0x940c, 0x0080};  // jmp 0x100
  image.resize(0x80, 0x9518);                          // reti
  const std::vector<std::uint16_t> main_code = {
      0xeae0,  // 100 ldi r30, 0xa0   (f's word address)
      0xe0f0,  // 102 ldi r31, 0x00
      0x9509,  // 104 icall
      0xcfff,  // 106 rjmp .
  };
  image.insert(image.end(), main_code.begin(), main_code.end());
  image.resize(0xa0, 0x0000);
  // f at byte 0x140: lds r24, 0x0100; inc r24; sts 0x0100, r24; ret
  const std::vector<std::uint16_t> f = {0x9180, 0x0100, 0x9583, 0x9380, 0x0100, 0x9508};
  image.insert(image.end(), f.begin(), f.end());
  auto bytes = std::make_shared<loader::Bytes>(image.size() * 2);
  for (std::size_t i = 0; i < image.size(); ++i) {
    (*bytes)[2 * i] = static_cast<std::byte>(image[i] & 0xff);
    (*bytes)[2 * i + 1] = static_cast<std::byte>(image[i] >> 8);
  }
  loader::RawOptions o;
  o.language = "avr8:LE:16:default:gcc";
  o.entry = 0;
  auto img = std::make_shared<const loader::Image>(loader::parse_raw(bytes, o));
  // The processor spec's data space blocks, keyed in "mem".
  const loader::AddressSpace *mem = loader::find_space(*img, "mem");
  ASSERT_NE(mem, nullptr);
  ASSERT_TRUE(img->memory.is_mapped(mem->base + 0x100));
  facts::FactDb db;
  register_queries(db.engine());
  ProgramInfo info = describe(*img, o.language);
  EXPECT_EQ(info.code_space, "code");
  EXPECT_EQ(info.code_wordsize(), 2u);
  import_image(db, ProgramKey{}, *img, info);
  auto functions = db.snapshot().get<Functions>(ProgramKey{});
  std::set<std::uint64_t> entries;
  for (const FunctionInfo &fi : functions->functions) entries.insert(fi.entry.offset);
  EXPECT_TRUE(entries.contains(0x140)) << "icall through Z = 0xa0 (words)";
  const FunctionInfo *callee = functions->find(0x140);
  ASSERT_NE(callee, nullptr);
  EXPECT_EQ(callee->name, "FUN_code_00a0");
  EXPECT_EQ(default_name(info, 0x74), "FUN_code_003a");
  EXPECT_EQ(address_name(info, "DAT_", mem->base + 0x100), "DAT_mem_0100");
  // The data access lands in mem, not in code.
  auto flow = db.snapshot().get<Flow>(Location{{}, 0x140});
  bool mem_ref = false;
  for (const DataRef &r : flow->data_refs) mem_ref = mem_ref || r.to == mem->base + 0x100;
  EXPECT_TRUE(mem_ref);
}

// An ARM (v7, little-endian) raw image at 0 put together from words, and
// its discovery.
struct ArmImage {
  std::vector<std::uint8_t> bytes;

  explicit ArmImage(std::size_t size) : bytes(size, 0) {}
  void arm(std::size_t at, std::initializer_list<std::uint32_t> words) {
    for (std::uint32_t w : words)
      for (int i = 0; i < 4; ++i) bytes.at(at++) = static_cast<std::uint8_t>(w >> (8 * i));
  }
  void thumb(std::size_t at, std::initializer_list<std::uint16_t> words) {
    for (std::uint16_t w : words)
      for (int i = 0; i < 2; ++i) bytes.at(at++) = static_cast<std::uint8_t>(w >> (8 * i));
  }
  void text(std::size_t at, std::string_view s) {
    for (char c : s) bytes.at(at++) = static_cast<std::uint8_t>(c);
  }
  void word(std::size_t at, std::uint32_t w) { arm(at, {w}); }
  // Thumb `bl target` at `at`.
  void bl(std::size_t at, std::size_t target) {
    const auto off = static_cast<std::uint32_t>(target - (at + 4));
    thumb(at, {static_cast<std::uint16_t>(0xf000 | ((off >> 12) & 0x7ff)),
               static_cast<std::uint16_t>(0xf800 | ((off >> 1) & 0x7ff))});
  }
  // Reset: ARM code that jumps to Thumb code at 0x40 through a literal.
  void reset_to_thumb_main() {
    vectors();
    arm(0x00, {0xea000006});                          // b 0x20
    arm(0x20, {0xe59f0004, 0xe12fff10, 0xeafffffe});  // ldr r0, [pc, #4]; bx r0; b .
    word(0x2c, 0x41);
  }
  // `b .` in every exception vector but reset, which is the caller's.
  void vectors() {
    for (std::size_t v = 4; v < 0x20; v += 4) arm(v, {0xeafffffe});
  }

  struct Result {
    facts::Ref<FunctionList> functions;
    std::set<std::uint64_t> entries;
    bool decoded(std::uint64_t first, std::uint64_t last) const {
      for (const CodeUnit &c : functions->code)
        if (c.address + c.length > first && c.address <= last) return true;
      return false;
    }
  };
  Result discover() const {
    auto data = std::make_shared<loader::Bytes>(bytes.size());
    for (std::size_t i = 0; i < bytes.size(); ++i) (*data)[i] = static_cast<std::byte>(bytes[i]);
    loader::RawOptions o;
    o.language = "ARM:LE:32:v7:default";
    auto img = std::make_shared<const loader::Image>(loader::parse_raw(data, o));
    facts::FactDb db;
    register_queries(db.engine());
    ProgramInfo info = describe(*img, o.language);
    import_image(db, ProgramKey{}, *img, info);
    Result r;
    r.functions = db.snapshot().get<Functions>(ProgramKey{});
    for (const FunctionInfo &f : r.functions->functions) r.entries.insert(f.entry.offset);
    return r;
  }
};

// Zeroed (or erased) memory decodes on ARM (andeq r0, r0, r0): a run of
// more than 16 instructions of one repeated byte is fill, not code. A call
// into it makes no function, and code that runs into it stops there.
TEST(RawFirmware, FillIsNotCode) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  ArmImage image(0x400);
  image.vectors();
  image.arm(0x00, {0xea000006});              // b 0x20
  image.arm(0x20, {0xeb000036, 0xe3a00001});  // bl 0x100; mov r0, #1; then zeros
  auto r = image.discover();
  EXPECT_TRUE(r.entries.contains(0));
  EXPECT_FALSE(r.entries.contains(0x100));
  EXPECT_TRUE(r.decoded(0x20, 0x27));
  EXPECT_FALSE(r.decoded(0x28, 0x3ff));

  // A short run (16 instructions, then real code) is still code.
  ArmImage padded(0x400);
  padded.vectors();
  padded.arm(0x00, {0xea000006});              // b 0x20
  padded.arm(0x20, {0xe3a00001});              // mov r0, #1; 16 zero words
  padded.arm(0x64, {0xe12fff1e});              // bx lr
  auto p = padded.discover();
  EXPECT_TRUE(p.decoded(0x24, 0x67));
}

// On a raw image nothing marks data, and text, random bytes and zeroed
// words all decode as Thumb code. What only a pointer or unproven code
// vouches for must be code by its own bytes.
TEST(RawFirmware, TextAndRandomBytesAreNotCode) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  ArmImage image(0x400);
  image.reset_to_thumb_main();
  // main at 0x40: push {lr}; bl helper; ldr r0, =text + 1; ldr r2, =random + 1; pop {pc}
  image.thumb(0x40, {0xb500});
  image.bl(0x42, 0x60);
  image.thumb(0x46, {0x4801, 0x4a02, 0xbd00});
  // helper at 0x60: movs r0, #1; bx lr
  image.thumb(0x60, {0x2001, 0x4770});
  // Strings, and a pointer to the odd address after a file name's last
  // letter (the terminator of one string, as a length-prefixed or packed
  // table has them): read as a Thumb pointer it is "c\0size..." as code,
  // which decodes, down to a "pG" that is bx lr.
  static const char raw[] = "drivers/uart/uart_ble.c\0size != 0\0cfg: opGain %d\0callback != NULL\0unknown dut\0";
  const std::string_view strings(raw, sizeof raw - 1);
  image.text(0x100, strings);
  const std::size_t c = 0x100 + strings.find(".c") + 1;
  ASSERT_EQ(c % 2, 0u);
  ASSERT_EQ((0x100 + strings.find("pG")) % 2, 0u);
  image.word(0x4c, static_cast<std::uint32_t>(c + 1));
  // Bytes as random as compressed data (every value once), that start
  // with what decodes as a whole subroutine: movs r0, #1; bx lr.
  for (std::size_t i = 0; i < 0x100; ++i) image.bytes[0x200 + i] = static_cast<std::uint8_t>(i * 167 + 13);
  image.thumb(0x200, {0x2001, 0x4770});
  image.word(0x50, 0x201);
  auto r = image.discover();
  EXPECT_TRUE(r.entries.contains(0x40));
  EXPECT_TRUE(r.entries.contains(0x60));
  for (std::uint64_t e : r.entries) EXPECT_LT(e, 0x100u) << std::hex << e;
  EXPECT_FALSE(r.decoded(0x100, 0x3ff));
}

// Code nothing refers to is still found (as Ghidra's ARM Aggressive
// Instruction Finder finds it), in the instruction set of the code before
// it; what it calls becomes a function only if that is credible code: not
// a table of small numbers, whose zeroed halves decode as movs r0, r0.
TEST(RawFirmware, UnreferencedCodeAndWhatItCalls) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  ArmImage image(0x400);
  image.reset_to_thumb_main();
  image.thumb(0x40, {0xb500});  // main: push {lr}; bl helper; pop {pc}
  image.bl(0x42, 0x60);
  image.thumb(0x46, {0xbd00});
  image.thumb(0x60, {0x2001, 0x4770});  // helper: movs r0, #1; bx lr
  // Unreferenced, with no prologue a start pattern knows:
  // movs r0, #5; bl helper; bl leaf; bl table; adds r0, #1; bx lr
  image.thumb(0x64, {0x2005});
  image.bl(0x66, 0x60);
  image.bl(0x6a, 0xc0);
  image.bl(0x6e, 0x300);
  image.thumb(0x72, {0x3001, 0x4770});
  image.thumb(0xc0, {0x3002, 0x4770});  // leaf: adds r0, #2; bx lr
  for (std::uint32_t i = 0; i < 16; ++i) image.word(0x300 + 4 * i, i);  // a table: 0, 1, 2, ...
  image.thumb(0x340, {0x4770});
  auto r = image.discover();
  EXPECT_TRUE(r.decoded(0x64, 0x75));
  bool thumb = false;
  for (const CodeUnit &c : r.functions->code)
    if (c.address == 0x64) thumb = c.thumb;
  EXPECT_TRUE(thumb);
  EXPECT_TRUE(r.entries.contains(0xc0));
  EXPECT_FALSE(r.entries.contains(0x300));
  EXPECT_FALSE(r.decoded(0x300, 0x3ff));
}

// ---- raw images with nothing to start from ----

// An 8-bit image with no vectors, entry point or start patterns (a 6502
// blob at 0, whose vectors at 0xfffa are outside it), discovered.
struct Blob {
  facts::Ref<FunctionList> functions;
  std::set<std::uint64_t> entries;
  bool decoded(std::uint64_t first, std::uint64_t last) const {
    for (const CodeUnit &c : functions->code)
      if (c.address + c.length > first && c.address <= last) return true;
    return false;
  }
};

Blob discover_blob(const std::vector<std::uint8_t> &image, const std::string &language, std::uint64_t base) {
  auto data = std::make_shared<loader::Bytes>(image.size());
  for (std::size_t i = 0; i < image.size(); ++i) (*data)[i] = static_cast<std::byte>(image[i]);
  loader::RawOptions o;
  o.language = language;
  o.base = base;
  auto img = std::make_shared<const loader::Image>(loader::parse_raw(data, o));
  facts::FactDb db;
  register_queries(db.engine());
  ProgramInfo info = describe(*img, o.language);
  EXPECT_TRUE(info.seeds.empty());
  import_image(db, ProgramKey{}, *img, info);
  Blob b;
  b.functions = db.snapshot().get<Functions>(ProgramKey{});
  for (const FunctionInfo &f : b.functions->functions) b.entries.insert(f.entry.offset);
  return b;
}

std::vector<std::uint8_t> from_hex(std::string_view hex) {
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
    out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
  return out;
}

// One hand-assembled program per processor, the same routines in each: a
// table of 23 bytes first (24 on AVR, whose code is word-aligned), then
// delay, read_key, put_char, newline, init, clear_line, checksum, process
// (calling delay, clear_line and checksum) and last main, which calls
// init, then loops calling read_key, put_char, newline and process;
// then text and a table. Only delay and put_char are called from more
// than one place.
struct BlobCase {
  const char *language;
  std::uint64_t base;
  std::size_t header;  // the table before the code
  const char *code;
  std::vector<std::uint64_t> functions;  // offsets: delay ... process, main
};

const std::vector<BlobCase> &blob_cases() {
  static const std::vector<BlobCase> cases = {
      {"6502:LE:16:default:default", 0, 23,
       "56312e320003070f1f3f7fff0102040810204080000905a9008d20d08d21d0a2009d0004e8d0fa60ad01dcc9fff0f929"
       "7f60489d0004e82044006860a90d203200a20060a02088d0fd60ad0004c941d009204400205b0020660060a920a02799"
       "00048810fa60a90018a000790004c8c028d0f88d000320440060a200201700202800c90df0062032004c7f00203c0020"
       "4a004c7f00",
       {23, 40, 50, 60, 68, 74, 91, 102, 122}},
      {"z80:LE:16:default:default", 0x8000, 23,
       "56312e320003070f1f3f7fff0102040810204080000905afd3102100400640772310fcc9db01b728fbe67fc9c5d302cd"
       "3f80c1c93e0dcd2c803e0acd2c80c9062010fec93a0040fe41c0cd3f80cd5480cd6080c921004006283e20772310fcc9"
       "af2100400628862310fc320041cd3f80c931ffffcd1780cd2480fe0d2806cd2c80c37780cd3480cd4480c37780",
       {23, 36, 44, 52, 63, 68, 84, 96, 113}},
      {"8051:BE:16:default:default", 0, 23,
       "56312e320003070f1f3f7fff0102040810204080000905e4f5909040007f40f0a3dffc223098fdc298e599547f22f599"
       "1200443099fdc29922740d12002e740a12002e227e20defe22904000e0b4410912004412005a120066229040007f2874"
       "20f0a3dffc227d009040007f28e02dfda3dffaedf53012004422758160120017120024b40d0912003912004902008012"
       "002e020080",
       {23, 36, 46, 57, 68, 73, 90, 102, 122}},
      {"avr8:LE:16:default:gcc", 0x1000, 24,
       "56312e320003070f1f3f7fff01020408102040800009050080e08ab9a0e0b1e090e48d939a95e9f708958091c0008030"
       "e1f38091c60008959f938093c60007d09f9108958de0f8df8ae0f6df089590e29a95f1f7089580910001813419f4f7df"
       "02d009d00895a0e0b1e080e298e28d939a95e9f7089580e0a0e0b1e098e22d91820f9a95e1f780930002e1df08950fef"
       "0dbf08e00ebfc0dfc8df8d3011f0ccdffbcfd0dfd8dff8cf",
       {24, 42, 56, 68, 78, 86, 102, 118, 142}},
  };
  return cases;
}

// Discovery found nothing to start from, and fell back to routines called
// from more than one place, then to code that calls them: every routine
// is a function, and the table before the code and the text after it are
// not code.
TEST(RawFirmware, BlobsWithoutEntryPoints) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  static const char trailer[] = "HIGH SCORES\0\x0a\x14\x1e\x28\x32\x3c\x46\x50PLAYER ONE\0PLAYER TWO";
  for (const BlobCase &c : blob_cases()) {
    SCOPED_TRACE(c.language);
    std::vector<std::uint8_t> image = from_hex(c.code);
    const std::size_t end = image.size();
    image.insert(image.end(), trailer, trailer + sizeof trailer);
    if (image.size() % 2) image.push_back(0);
    const Blob b = discover_blob(image, c.language, c.base);
    std::set<std::uint64_t> want;
    for (std::uint64_t f : c.functions) want.insert(c.base + f);
    EXPECT_EQ(b.entries, want);
    EXPECT_FALSE(b.decoded(c.base, c.base + c.header - 1));
    EXPECT_FALSE(b.decoded(c.base + end, c.base + image.size() - 1));
    for (std::uint64_t f : c.functions) EXPECT_TRUE(b.decoded(c.base + f, c.base + f)) << std::hex << f;
  }
}

// Data, text and bytes as random as compressed data give no functions in
// the fallback either: strings, tables (counting, a sine, pointers), fill,
// and records that hold a call instruction to bytes that decode as a small
// routine, once exactly repeated and once with a field that counts.
TEST(RawFirmware, BlobsOfDataTextAndRandomBytesHaveNoCode) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  struct Case {
    const char *language;
    std::uint64_t base;
    std::vector<std::uint8_t> (*call)(std::uint64_t);
    std::vector<std::uint8_t> routine;  // load 1, store it, return
  };
  const std::vector<Case> cases = {
      {"6502:LE:16:default:default", 0,
       [](std::uint64_t t) { return std::vector<std::uint8_t>{0x20, std::uint8_t(t), std::uint8_t(t >> 8)}; },
       {0xa9, 0x01, 0x8d, 0x00, 0x03, 0x60}},
      {"z80:LE:16:default:default", 0x8000,
       [](std::uint64_t t) { return std::vector<std::uint8_t>{0xcd, std::uint8_t(t), std::uint8_t(t >> 8)}; },
       {0x3e, 0x01, 0x32, 0x00, 0x41, 0xc9}},
      {"8051:BE:16:default:default", 0,
       [](std::uint64_t t) { return std::vector<std::uint8_t>{0x12, std::uint8_t(t >> 8), std::uint8_t(t)}; },
       {0x74, 0x01, 0xf5, 0x30, 0x22, 0x00}},
      {"avr8:LE:16:default:gcc", 0x1000,
       [](std::uint64_t t) {  // call (a word address)
         return std::vector<std::uint8_t>{0x0e, 0x94, std::uint8_t(t / 2), std::uint8_t(t / 2 >> 8)};
       },
       {0x81, 0xe0, 0x80, 0x93, 0x00, 0x02, 0x08, 0x95}},
  };
  std::uint64_t x = 987654321;
  std::vector<std::uint8_t> random;
  for (int i = 0; i < 4096; ++i) {
    x = x * 6364136223846793005u + 1442695040888963407u;
    random.push_back(static_cast<std::uint8_t>(x >> 56));
  }
  std::string text;
  for (int i = 0; i < 8; ++i)
    text += "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of "
            "foolishness, it was the epoch of belief, it was the epoch of incredulity.\n";
  for (const Case &c : cases) {
    SCOPED_TRACE(c.language);
    std::vector<std::uint8_t> data;
    for (const char *s : {"Press any key to continue", "Error %d: device not ready", "COPYRIGHT 1984 ACME SOFTWARE",
                          "LOAD \"*\",8,1", "Ready.", "Insert disk 2 and press RETURN", "Game over"})
      data.insert(data.end(), s, s + std::char_traits<char>::length(s) + 1);
    if (data.size() % 2) data.push_back(0);
    for (int i = 0; i < 64; ++i) data.push_back(static_cast<std::uint8_t>(i));
    const std::size_t sine = data.size();
    for (int i = 0; i < 64; ++i) data.push_back(static_cast<std::uint8_t>(127 + 127 * std::sin(i * 2 * M_PI / 64)));
    std::copy(c.routine.begin(), c.routine.end(), data.begin() + static_cast<std::ptrdiff_t>(sine));
    data.insert(data.end(), random.begin(), random.begin() + 256);
    data.insert(data.end(), 64, 0xff);
    data.insert(data.end(), 64, 0x00);
    for (int i = 0; i < 16; ++i) {
      data.push_back(static_cast<std::uint8_t>(0x40 * i));
      data.push_back(static_cast<std::uint8_t>((0x1000 + 0x40 * i) >> 8));
    }
    const std::vector<std::uint8_t> call = c.call(c.base + sine);
    for (int i = 0; i < 6; ++i) {
      data.insert(data.end(), call.begin(), call.end());
      data.insert(data.end(), {0x11, 0x55});
    }
    if (data.size() % 2) data.push_back(0);
    for (std::uint8_t i = 0; i < 6; ++i) {
      data.insert(data.end(), call.begin(), call.end());
      data.insert(data.end(), {i, 0x55});
    }
    for (const auto &[what, image] :
         {std::pair<const char *, std::vector<std::uint8_t>>{"data", data},
          {"text", std::vector<std::uint8_t>(text.begin(), text.end())},
          {"random", random}}) {
      SCOPED_TRACE(what);
      const Blob b = discover_blob(image, c.language, c.base);
      EXPECT_TRUE(b.entries.empty());
      EXPECT_TRUE(b.functions->code.empty());
    }
  }
}

// ---- small pieces ----

TEST(NoReturnNames, IgnoreLeadingUnderscores) {
  for (const char *n : {"exit", "_exit", "__stack_chk_fail", "abort", "_Unwind_Resume", "__assert_fail",
                        "longjmp", "__longjmp_chk", "ExitProcess", "__cxa_throw", "err", "_ZSt9terminatev"})
    EXPECT_TRUE(is_known_no_return(n)) << n;
  for (const char *n : {"puts", "_cexit", "atexit", "exit_group_wrapper", ""}) EXPECT_FALSE(is_known_no_return(n)) << n;
}

TEST(DefaultNames, MatchGhidra) {
  ProgramInfo info;
  EXPECT_EQ(default_name(info, 0x101000), "FUN_00101000");
  EXPECT_EQ(default_name(info, 0x140001000), "FUN_140001000");
  info.qualify_names = true;
  EXPECT_EQ(default_name(info, 0x101000), "FUN_ram_00101000");
}

TEST(Codecs, RoundTrip) {
  ProgramInfo info;
  info.language = "x86:LE:64:default";
  info.code = {{0x1000, 0x1fff}};
  info.seeds = {{0x1000, static_cast<std::uint16_t>(kSeedEntry | kSeedSymbol), "main", true}};
  info.imports = {{0x3000, "puts"}};
  info.context = {{"TMode", 1, {0x1000, 0x10ff}}};
  info.references = true;
  info.mapped = {{0x1000, 0x3fff}};
  EXPECT_EQ(facts::decode_from_string<ProgramInfo>(facts::encode_to_string(info)), info);

  FlowGraph g;
  g.entry = 0x1000;
  g.insns = {{0x1000, 5, FlowKind::call, true, false, {0x2000}}, {0x1005, 2, FlowKind::branch, true, false, {0xff0}},
             {0x1007, 6, FlowKind::jump_indirect, false, true, {}}, {0x100d, 1, FlowKind::ret, false, false, {}},
             {0x100e, 8, FlowKind::call, false, false, {0x3000}, true, 4}};
  g.refs = {{0, RefKind::call, false, 0x2000}, {0, RefKind::data_read, false, 0x900},
            {4, RefKind::call, false, 0x3000}, {4, RefKind::data_write, true, 0x3008}};
  EXPECT_EQ(facts::decode_from_string<FlowGraph>(facts::encode_to_string(g)), g);
  EXPECT_EQ(g.refs[3].from(g), 0x1012u);
  FunctionList l;
  l.functions.push_back({{1, 0x1000}, "f", facts::AddressSet({{1, 0x1000}, {1, 0x100f}}), kFunctionAssertedEntry});
  l.code = {{0x1000, 5, 0}, {0x1005, 8, 4}, {0x2000, 1, 0}};
  EXPECT_EQ(facts::decode_from_string<FunctionList>(facts::encode_to_string(l)), l);
  EXPECT_EQ(facts::decode_from_string<Location>(facts::encode_to_string(Location{"p/x", 0x401000})),
            (Location{"p/x", 0x401000}));
  EXPECT_THROW(facts::decode_from_string<FlowGraph>(std::string("\x01\x00\x01\x00\x05\x7f\x00", 7)),
               facts::DecodeError);
}

}  // namespace
}  // namespace revkit::analysis
