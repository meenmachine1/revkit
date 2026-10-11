#include "revkit/inputs/param_id.h"

#include "revkit/inputs/codec.h"

#include <gtest/gtest.h>

#include <set>

namespace revkit::inputs {
namespace {

CallGraphNode node(std::uint64_t entry, std::vector<std::uint64_t> calls, bool entry_point = false) {
  CallGraphNode n;
  n.entry = entry;
  n.calls = std::move(calls);
  n.entry_point = entry_point;
  return n;
}

CallGraphNode thunk(std::uint64_t entry, std::optional<std::uint64_t> target) {
  CallGraphNode n;
  n.entry = entry;
  n.thunk = true;
  n.thunk_target = target;
  if (!target) n.external = 1;
  return n;
}

using Deps = std::vector<std::uint64_t>;

TEST(ParamIdPlan, CalleesFirst) {
  // main -> a -> b, main -> b
  ParamIdPlan p = param_id_plan({node(0x100, {0x200, 0x300}, true), node(0x200, {0x300}), node(0x300, {})});
  EXPECT_EQ(p.nodes, (Deps{0x100, 0x200, 0x300}));
  EXPECT_EQ(p.dependencies_of(0x100), (Deps{0x200, 0x300}));
  EXPECT_EQ(p.dependencies_of(0x200), (Deps{0x300}));
  EXPECT_EQ(p.dependencies_of(0x300), Deps{});
  EXPECT_EQ(p.rounds(), (std::vector<Deps>{{0x300}, {0x200}, {0x100}}));
}

TEST(ParamIdPlan, RecursionDropsTheCallBack) {
  // main -> a <-> b, a -> a: the walk reaches a first, so a depends on b
  // and b's call back to a (and a's call to itself) is dropped.
  ParamIdPlan p = param_id_plan({node(0x100, {0x200}, true), node(0x200, {0x200, 0x300}), node(0x300, {0x200})});
  EXPECT_EQ(p.dependencies_of(0x100), (Deps{0x200}));
  EXPECT_EQ(p.dependencies_of(0x200), (Deps{0x300}));
  EXPECT_EQ(p.dependencies_of(0x300), Deps{});
}

TEST(ParamIdPlan, CyclesNothingCallsIntoStartAtTheLowestAddress) {
  // a <-> b, called by nothing else: neither is a start, so the walk
  // starts at the lowest address left.
  ParamIdPlan p = param_id_plan({node(0x500, {0x400}), node(0x400, {0x500})});
  EXPECT_EQ(p.dependencies_of(0x400), (Deps{0x500}));
  EXPECT_EQ(p.dependencies_of(0x500), Deps{});
}

TEST(ParamIdPlan, ThunksAreTheirTargets) {
  // main calls a thunk of f and a thunk of an import.
  ParamIdPlan p = param_id_plan(
      {node(0x100, {0x180, 0x190}, true), thunk(0x180, 0x200), thunk(0x190, std::nullopt), node(0x200, {})});
  EXPECT_EQ(p.nodes, (Deps{0x100, 0x200}));
  EXPECT_EQ(p.dependencies_of(0x100), (Deps{0x200}));
  EXPECT_EQ(p.thunks.at(0x180), std::optional<std::uint64_t>(0x200));
  EXPECT_EQ(p.thunks.at(0x190), std::nullopt);
  EXPECT_EQ(facts::decode_from_string<ParamIdPlan>(facts::encode_to_string(p)), p);
}

// java.util.HashSet<Address> iteration order, checked against OpenJDK 21:
// keys from an LCG, inserted in ascending order; FNV-1a over the order.
TEST(ParamIdPlan, JavaHashSetOrder) {
  struct Case {
    std::uint64_t seed;
    int n;
    std::uint64_t stride;
    std::uint64_t fnv;
  };
  const Case cases[] = {
      {1, 200, 16, 5924212218845291299ULL},   {2, 700, 16, 9530999679337817475ULL},
      {3, 2500, 16, 4995524027732593363ULL},  {4, 4000, 4, 1651569740865075887ULL},
      {5, 1500, 64, 4030636565930377235ULL},  {6, 300, 1, 13192088034145835389ULL},
  };
  for (const Case &c : cases) {
    std::set<std::uint64_t> keys;
    std::uint64_t x = c.seed;
    while (keys.size() < static_cast<std::size_t>(c.n)) {
      x = x * 6364136223846793005ULL + 1442695040888963407ULL;
      keys.insert(0x140001000ULL + ((x >> 33) % static_cast<std::uint64_t>(c.n * 4)) * c.stride);
    }
    std::uint64_t h = 1469598103934665603ULL;
    for (std::uint64_t k : java_address_set_order({keys.begin(), keys.end()})) h = (h ^ k) * 1099511628211ULL;
    EXPECT_EQ(h, c.fnv) << "seed " << c.seed;
  }
}

TEST(ParamId, SkipsAndApplies) {
  lift::FunctionFacts f;
  f.entry = 0x1000;
  f.name = "FUN_00001000";
  f.convention = "unknown";
  EXPECT_FALSE(param_id_skip(f, false, {}));
  EXPECT_TRUE(param_id_skip(f, true, {}));
  lift::BlockFacts plt;
  plt.name = ".plt";
  plt.start = 0x1000;
  plt.end = 0x1fff;
  EXPECT_TRUE(param_id_skip(f, false, {plt}));
  lift::FunctionFacts imported = f;
  imported.signature_source = lift::SignatureSource::imported;
  EXPECT_TRUE(param_id_skip(imported, false, {}));

  lift::CommittedSignature s;
  s.status = lift::CommittedSignature::Status::committed;
  s.convention = "__fastcall";
  lift::ParamFacts p;
  p.name = "param_1";
  p.storage = {{"register", 8, 8}};
  p.type = {"typeref", {{"id", std::uint64_t{0xc0000000000000bbULL}}, {"name", std::string("undefined8")}}, {}};
  s.params.push_back(p);
  lift::FunctionFacts g = f;
  apply_param_id(g, s);
  EXPECT_EQ(g.signature_source, lift::SignatureSource::analysis);
  EXPECT_EQ(g.convention, std::optional<std::string>("__fastcall"));
  ASSERT_EQ(g.params.size(), 1u);
  EXPECT_EQ(g.params[0].storage, p.storage);
  // A void return keeps the function's: DEFAULT, no storage.
  EXPECT_TRUE(g.ret.is_default);
  EXPECT_FALSE(g.ret.storage.has_value());
  // Not committed: nothing changes.
  lift::FunctionFacts h = f;
  s.status = lift::CommittedSignature::Status::failed;
  apply_param_id(h, s);
  EXPECT_EQ(h.signature_source, lift::SignatureSource::default_);
  EXPECT_TRUE(h.params.empty());
  s.status = lift::CommittedSignature::Status::committed;
  EXPECT_EQ(facts::encode_to_string(facts::decode_from_string<lift::CommittedSignature>(facts::encode_to_string(s))),
            facts::encode_to_string(s));
}

TEST(ParamId, DefaultEnablement) {
  loader::Image pe;
  pe.format = loader::Format::pe;
  lift::BlockFacts b;
  b.start = 0x140000000;
  b.end = b.start + (1 << 20) - 1;
  EXPECT_TRUE(param_id_default(pe, {b}));
  b.end = b.start + (2 << 20) - 1;
  EXPECT_FALSE(param_id_default(pe, {b}));
  loader::Image elf;
  elf.format = loader::Format::elf;
  b.end = b.start + 0xfff;
  EXPECT_FALSE(param_id_default(elf, {b}));
  EXPECT_TRUE(param_id_enabled(ParamIdMode::on, elf, {b}));
  EXPECT_FALSE(param_id_enabled(ParamIdMode::off, pe, {b}));
}

}  // namespace
}  // namespace revkit::inputs
