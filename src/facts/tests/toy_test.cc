// The engine driven by a realistic pipeline: bytes -> instructions -> xrefs
// -> summaries that read names, global types and struct layouts.
#include "toy_program.h"

#include "revkit/facts/thread_pool.h"

#include <gtest/gtest.h>

#include <set>

namespace revkit::facts {
namespace {

using namespace toy;

const Provenance kAlice = Provenance::user("alice");

ProgramSpec small_spec() {
  ProgramSpec spec;
  spec.functions = 400;
  spec.insns_per_function = 40;
  spec.globals = 48;
  spec.structs = 6;
  spec.seed = 7;
  spec.functions_per_commit = 128;
  return spec;
}

class ToyTest : public ::testing::Test {
 protected:
  ToyTest() {
    register_queries(db_.engine());
    prog_ = generate(db_, small_spec());
  }

  std::vector<Ref<std::string>> summaries(ThreadPool *pool = nullptr) {
    return db_.snapshot().get_all<FunctionSummary>(prog_.functions, pool);
  }

  // Functions with a field access to a global whose type is struct s.
  std::set<Address> users_of_struct(std::uint32_t s) {
    std::set<Address> out;
    auto snap = db_.snapshot();
    for (Address f : prog_.functions)
      for (const Xref &x : *snap.get<FunctionXrefs>(f))
        if (x.kind == XrefKind::Field && prog_.global_struct[(x.to.offset - 0x10000000) / 16] == s)
          out.insert(f);
    return out;
  }

  void assert_fact(const Provenance &who, FactKey k, FactValue v) {
    auto tx = db_.begin();
    tx.assert_fact(who, std::move(k), std::move(v));
    tx.commit();
  }

  FactDb db_;
  Program prog_;
};

TEST_F(ToyTest, DecodesWhatWasGenerated) {
  auto snap = db_.snapshot();
  std::uint64_t insns = 0;
  for (Address f : prog_.functions) {
    auto l = snap.get<DecodeFunction>(f);
    EXPECT_FALSE(l->truncated);
    ASSERT_FALSE(l->insns.empty());
    EXPECT_EQ(l->insns.back().op, kRet);
    insns += l->insns.size();
  }
  EXPECT_EQ(insns, prog_.instructions);
  auto s = snap.get<FunctionSummary>(prog_.functions[0]);
  EXPECT_NE(s->find("() {"), std::string::npos);

  // An undefined struct gives an uncertain layout.
  auto f = snap.fact<StructLayout>("NoSuchStruct");
  EXPECT_EQ(f.confidence, Confidence::Uncertain);
  EXPECT_TRUE(f.value->fields.empty());
  EXPECT_EQ(snap.fact<StructLayout>("S1").confidence, Confidence::Certain);
  EXPECT_EQ(snap.fact<StructLayout>("S1").inputs, std::vector<std::string>{"fact(typedef:S1)"});
  auto decoded = snap.fact<DecodeFunction>(Address{1, 0x400000});
  EXPECT_EQ(decoded.rule, "toy.decode");
  ASSERT_GE(decoded.inputs.size(), 2u);
  EXPECT_EQ(decoded.inputs[0], "fact(function@1:0x400000)");
}

TEST_F(ToyTest, RetypingAStructRerunsOnlyFunctionsThatUseIt) {
  summaries();
  const std::uint32_t target = 3;
  std::set<Address> users = users_of_struct(target);
  ASSERT_FALSE(users.empty());
  ASSERT_LT(users.size(), prog_.functions.size());
  auto before = summaries();
  db_.engine().reset_stats();

  // f0 becomes 8 bytes wide, so every later field moves.
  assert_fact(kAlice, FactKey::type_def(struct_name(target)), "f0:long;f1:int;f2:int;f3:ptr;f4:int");
  auto after = summaries();

  EXPECT_EQ(db_.engine().stats<StructLayout>().executions, 1u);
  EXPECT_EQ(db_.engine().stats<FunctionSummary>().executions, users.size());
  EXPECT_EQ(db_.engine().stats<FunctionXrefs>().executions, 0u);
  EXPECT_EQ(db_.engine().stats<DecodeFunction>().executions, 0u);
  std::size_t changed = 0;
  for (std::size_t i = 0; i < prog_.functions.size(); ++i) {
    if (*before[i] != *after[i]) {
      ++changed;
      EXPECT_TRUE(users.count(prog_.functions[i])) << i;
    }
  }
  EXPECT_GT(changed, 0u);
}

TEST_F(ToyTest, EquivalentStructDefinitionIsCutOffEarly) {
  summaries();
  db_.engine().reset_stats();
  // Same layout, different text.
  assert_fact(kAlice, FactKey::type_def(struct_name(3)), " f0 : int ; f1:int;f2:int;f3:int; f4:int ");
  summaries();
  EXPECT_EQ(db_.engine().stats<StructLayout>().executions, 1u);
  EXPECT_EQ(db_.engine().stats<FunctionSummary>().executions, 0u);
  EXPECT_EQ(db_.engine().stats<FunctionSummary>().validations, prog_.functions.size());
}

TEST_F(ToyTest, RenamingAFunctionRerunsItsCallers) {
  summaries();
  Address callee = prog_.functions[10];
  std::set<Address> readers{callee};
  auto snap = db_.snapshot();
  for (Address f : prog_.functions)
    for (const Xref &x : *snap.get<FunctionXrefs>(f))
      if (x.kind == XrefKind::Call && x.to == callee) readers.insert(f);
  db_.engine().reset_stats();

  assert_fact(kAlice, FactKey::name(callee), "parse_config");
  auto after = summaries();
  EXPECT_EQ(db_.engine().stats<FunctionSummary>().executions, readers.size());
  for (std::size_t i = 0; i < prog_.functions.size(); ++i) {
    if (readers.count(prog_.functions[i]) && prog_.functions[i] != callee) {
      EXPECT_NE(after[i]->find("parse_config();"), std::string::npos);
    }
  }
}

TEST_F(ToyTest, PatchingARegisterIsCutOffAtXrefs) {
  summaries();
  // Rewrite the register byte of the first ALU or mov in function 5.
  Address f = prog_.functions[5];
  auto insns = db_.snapshot().get<DecodeFunction>(f);
  const Insn *target = nullptr;
  for (const Insn &in : insns->insns)
    if (in.op == kAlu || in.op == kMovImm) {
      target = &in;
      break;
    }
  ASSERT_NE(target, nullptr);
  db_.engine().reset_stats();
  {
    auto tx = db_.begin();
    std::string reg(1, static_cast<char>((target->reg + 1) & 15));
    tx.write_bytes(Address{f.space, insns->start.offset + target->offset + 1}, reg);
    tx.commit();
  }
  summaries();
  // Every function on the patched page re-decodes (it read the page), but
  // only function 5's instructions changed; its xrefs come out identical, so
  // no summary reruns.
  EXPECT_GE(db_.engine().stats<DecodeFunction>().executions, 1u);
  EXPECT_LE(db_.engine().stats<DecodeFunction>().executions, 200u);
  EXPECT_EQ(db_.engine().stats<FunctionXrefs>().executions, 1u);
  EXPECT_EQ(db_.engine().stats<FunctionSummary>().executions, 0u);
}

TEST_F(ToyTest, RevertingAnAgentRestoresEveryDerivedFact) {
  auto original = summaries();
  Provenance agent = Provenance::agent("namer", "0.1");
  {
    auto tx = db_.begin();
    for (int i = 0; i < 25; ++i)
      tx.assert_fact(agent, FactKey::name(prog_.functions[i * 7]), "agent_fn_" + std::to_string(i));
    tx.assert_fact(agent, FactKey::type_def(struct_name(2)), "f0:ptr;f1:ptr");
    tx.commit();
  }
  auto renamed = summaries();
  std::size_t diffs = 0;
  for (std::size_t i = 0; i < original.size(); ++i) diffs += *original[i] != *renamed[i];
  EXPECT_GT(diffs, 0u);

  auto tx = db_.begin();
  tx.revert(kAlice, agent);
  tx.commit();
  auto restored = summaries();
  for (std::size_t i = 0; i < original.size(); ++i) EXPECT_EQ(*restored[i], *original[i]) << i;
}

TEST(ToyDeterminism, SameResultsForAnyThreadCount) {
  ProgramSpec spec = small_spec();
  spec.functions = 600;
  std::vector<std::string> reference;
  for (unsigned threads : {1u, 2u, 3u, 8u, 16u}) {
    FactDb db;
    register_queries(db.engine());
    Program prog = generate(db, spec);
    ThreadPool pool(threads);
    auto got = db.snapshot().get_all<FunctionSummary>(prog.functions, &pool);
    // And again after an edit, through re-validation.
    {
      auto tx = db.begin();
      tx.assert_fact(kAlice, FactKey::type_def("S1"), "a:char;b:ptr");
      tx.assert_fact(kAlice, FactKey::name(prog.functions[3]), "renamed");
      tx.commit();
    }
    auto again = db.snapshot().get_all<FunctionSummary>(prog.functions, &pool);
    std::vector<std::string> flat;
    for (auto &s : got) flat.push_back(*s);
    for (auto &s : again) flat.push_back(*s);
    if (reference.empty()) reference = flat;
    else EXPECT_EQ(flat, reference) << threads << " threads";
  }
}

}  // namespace
}  // namespace revkit::facts
