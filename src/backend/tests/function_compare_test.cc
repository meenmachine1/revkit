// Which variables of two decompilations correspond (function_compare.h):
// parameters by position, the rest by the instructions and C lines that
// print them; and the decompiler's default names.
#include "function_compare.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace revkit::backend {
namespace {

// A decompilation built by hand: variables, then lines of tokens. A token
// "@name" is the variable `name` (printed from the line's instruction), any
// other is text.
struct Builder {
  pb::DecompiledFunction f;

  int Var(const std::string &name, pb::VariableKind kind, int param = -1) {
    pb::Variable *v = f.add_variables();
    v->set_index(static_cast<std::uint32_t>(f.variables_size() - 1));
    v->set_kind(kind);
    v->set_name(name);
    v->set_storage_key(param >= 0 ? "param:" + std::to_string(param) : "stack:" + name);
    if (param >= 0) v->set_parameter_index(static_cast<std::uint32_t>(param));
    return static_cast<int>(v->index());
  }

  void Line(std::uint64_t address, const std::vector<std::string> &tokens) {
    pb::CodeLine *l = f.add_lines();
    for (const std::string &t : tokens) {
      pb::CodeToken *x = l->add_tokens();
      if (t.starts_with("@")) {
        const std::string name = t.substr(1);
        for (const pb::Variable &v : f.variables())
          if (v.name() == name) {
            x->set_variable_index(v.index());
            x->set_kind(v.kind() == pb::VARIABLE_KIND_PARAMETER ? pb::CODE_TOKEN_KIND_PARAMETER
                                                               : pb::CODE_TOKEN_KIND_LOCAL_VARIABLE);
          }
        x->set_text(name);
      } else {
        x->set_kind(pb::CODE_TOKEN_KIND_OPERATOR);
        x->set_text(t);
      }
      if (address) x->mutable_address()->set_offset(address);
    }
  }
};

TEST(FunctionCompare, DefaultNames) {
  for (const char *n : {"param_1", "local_14", "local_res8", "uVar1", "pcVar12", "auVar3", "uStack_14", "auStack_38",
                        "iStack20", "VVar1", "pNVar14", "pTStack_30", "in_RAX", "unaff_RBX", "extraout_EAX", "stack0x00000008", ""})
    EXPECT_TRUE(IsDefaultVariableName(n)) << n;
  for (const char *n : {"count", "argc", "Var1", "i", "p", "myVar1x", "stackTop", "localCount", "uVarious", "Var", "myVariable", "local_count", "in_buf",
                        "param_x"})
    EXPECT_FALSE(IsDefaultVariableName(n)) << n;
}

TEST(FunctionCompare, ParametersByPositionLocalsByInstructions) {
  // A: debug names; B: the decompiler's, other storage, other order.
  Builder a, b;
  const int argc = a.Var("argc", pb::VARIABLE_KIND_PARAMETER, 0);
  const int argv = a.Var("argv", pb::VARIABLE_KIND_PARAMETER, 1);
  const int sum = a.Var("sum", pb::VARIABLE_KIND_LOCAL);
  const int i = a.Var("i", pb::VARIABLE_KIND_LOCAL);
  const int g = a.Var("table", pb::VARIABLE_KIND_GLOBAL);
  const int p2 = b.Var("param_2", pb::VARIABLE_KIND_PARAMETER, 1);
  const int p1 = b.Var("param_1", pb::VARIABLE_KIND_PARAMETER, 0);
  const int iv = b.Var("iVar2", pb::VARIABLE_KIND_LOCAL);
  const int uv = b.Var("uVar1", pb::VARIABLE_KIND_LOCAL);
  const int extra = b.Var("local_10", pb::VARIABLE_KIND_LOCAL);
  a.Line(0x10, {"@sum", " = ", "0", ";"});
  a.Line(0x14, {"@i", " = ", "@argc", ";"});
  a.Line(0x18, {"@sum", " = ", "@sum", " + ", "@i", ";"});
  // B: moved (other addresses), the same statements, B's own names.
  b.Line(0x110, {"@uVar1", " = ", "0", ";"});
  b.Line(0x114, {"@iVar2", " = ", "@param_1", ";"});
  b.Line(0x118, {"@uVar1", " = ", "@uVar1", " + ", "@iVar2", ";"});
  b.Line(0x11c, {"@local_10", " = ", "1", ";"});
  const std::unordered_map<std::uint64_t, std::uint64_t> partner{{0x10, 0x110}, {0x14, 0x114}, {0x18, 0x118}};
  auto pairs = PairVariables(a.f, b.f, partner);
  auto partner_of = [&](int x) {
    for (const VariablePairing &p : pairs)
      if (p.a == x) return p.b;
    return -2;
  };
  EXPECT_EQ(partner_of(argc), p1);
  EXPECT_EQ(partner_of(argv), p2);
  EXPECT_EQ(partner_of(sum), uv);
  EXPECT_EQ(partner_of(i), iv);
  EXPECT_EQ(partner_of(g), -2) << "globals aren't paired";
  // B's extra local is listed alone, after A's.
  ASSERT_FALSE(pairs.empty());
  EXPECT_EQ(pairs.back().a, -1);
  EXPECT_EQ(pairs.back().b, extra);
  for (const VariablePairing &p : pairs)
    if (p.a == sum) {
      EXPECT_EQ(p.instructions, 3u);  // two lines print sum, one of them twice
      EXPECT_EQ(p.lines, 3u);
      EXPECT_FALSE(p.parameter);
    } else if (p.a == argc) {
      EXPECT_TRUE(p.parameter);
    }
}

TEST(FunctionCompare, TiesStayUnpaired) {
  // `x = y;` once on each side, the instruction map silent: the line pairs
  // x with p and y with q; nothing else does.
  Builder a, b;
  const int x = a.Var("x", pb::VARIABLE_KIND_LOCAL);
  const int y = a.Var("y", pb::VARIABLE_KIND_LOCAL);
  const int p = b.Var("p", pb::VARIABLE_KIND_LOCAL);
  const int q = b.Var("q", pb::VARIABLE_KIND_LOCAL);
  a.Line(0x10, {"@x", " = ", "@y", ";"});
  b.Line(0x20, {"@p", " = ", "@q", ";"});
  auto pairs = PairVariables(a.f, b.f, {});
  ASSERT_EQ(pairs.size(), 2u);
  EXPECT_EQ(pairs[0].a, x);
  EXPECT_EQ(pairs[0].b, p);
  EXPECT_EQ(pairs[1].a, y);
  EXPECT_EQ(pairs[1].b, q);
  // Two statements that read the same with names abstracted, in another
  // order: `x = 1; y = 1;` against `q = 1; p = 1;`. The lines align in
  // order (x with q, y with p) and nothing contradicts it.
  Builder c, d;
  c.Var("x", pb::VARIABLE_KIND_LOCAL);
  c.Var("y", pb::VARIABLE_KIND_LOCAL);
  d.Var("p", pb::VARIABLE_KIND_LOCAL);
  d.Var("q", pb::VARIABLE_KIND_LOCAL);
  c.Line(0x10, {"@x", " = ", "1", ";"});
  c.Line(0x14, {"@y", " = ", "1", ";"});
  d.Line(0x20, {"@q", " = ", "1", ";"});
  d.Line(0x24, {"@p", " = ", "1", ";"});
  // The instruction map says otherwise for both (x is p, y is q): one vote
  // each way, a tie, so nothing pairs.
  auto tied = PairVariables(c.f, d.f, {{0x10, 0x24}, {0x14, 0x20}});
  for (const VariablePairing &v : tied) EXPECT_TRUE(v.a < 0 || v.b < 0) << v.a << " " << v.b;
}

TEST(FunctionCompare, Deterministic) {
  Builder a, b;
  for (int k = 0; k < 6; ++k) a.Var("v" + std::to_string(k), pb::VARIABLE_KIND_LOCAL);
  for (int k = 0; k < 6; ++k) b.Var("w" + std::to_string(k), pb::VARIABLE_KIND_LOCAL);
  for (int k = 0; k < 6; ++k) {
    a.Line(0x10 + 4 * k, {"@v" + std::to_string(k), " = ", std::to_string(k), ";"});
    b.Line(0x20 + 4 * k, {"@w" + std::to_string(5 - k), " = ", std::to_string(k), ";"});
  }
  const auto one = PairVariables(a.f, b.f, {});
  for (int run = 0; run < 3; ++run) {
    const auto again = PairVariables(a.f, b.f, {});
    ASSERT_EQ(one.size(), again.size());
    for (std::size_t k = 0; k < one.size(); ++k) EXPECT_EQ(one[k].b, again[k].b);
  }
  // Each statement is unique: v_k = k pairs with w_(5-k).
  for (const VariablePairing &p : one) {
    ASSERT_GE(p.a, 0);
    EXPECT_EQ(p.b, 5 - p.a);
  }
}

}  // namespace
}  // namespace revkit::backend
