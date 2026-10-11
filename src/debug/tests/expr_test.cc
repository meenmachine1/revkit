// Debugger expressions (expr.hh) over a fake target: registers, memory,
// symbols and a struct type.
#include "revkit/debug/expr.hh"

#include <gtest/gtest.h>

#include <cstring>
#include <map>

#include <strings.h>

namespace revkit::debug::expr {
namespace {

class Types : public TypeSource {
 public:
  Types() {
    auto point = std::make_shared<Type>();
    point->kind = Type::Kind::struct_;
    point->size = 16;
    point->name = "struct point";
    point->fields = {{"x", 0, 0, 0, "", integer(4, true)},
                     {"y", 4, 0, 0, "", integer(4, true)},
                     {"name", 8, 0, 0, "h-charp", nullptr}};
    point_ = point;
    auto cp = std::make_shared<Type>();
    cp->kind = Type::Kind::pointer;
    cp->size = 8;
    cp->name = "char *";
    cp->target = builtin("char", 8);
    charp_ = cp;
    auto flags = std::make_shared<Type>();
    flags->kind = Type::Kind::struct_;
    flags->size = 4;
    flags->name = "struct flags";
    flags->fields = {{"a", 0, 0, 3, "", integer(4, false)}, {"b", 0, 3, 5, "", integer(4, true)}};
    flags_ = flags;
  }
  TypeP by_hash(const std::string &h) override { return h == "h-charp" ? charp_ : h == "h-point" ? point_ : nullptr; }
  TypeP by_name(const std::string &n) override {
    if (n == "struct point" || n == "point_t") return point_;
    if (n == "struct flags") return flags_;
    return nullptr;
  }
  TypeP point_, charp_, flags_;
};

class Fake {
 public:
  Fake() {
    regs["RAX"] = 0x2a;
    regs["RSP"] = 0x7000;
    regs["RBP"] = 0x7020;
    put(0x7000, std::vector<std::uint8_t>{0x10, 0x20, 0, 0, 0, 0, 0, 0});
    // struct point at 0x8000: {3, -4, "hi"}
    put32(0x8000, 3);
    put32(0x8004, static_cast<std::uint32_t>(-4));
    put64(0x8008, 0x9000);
    put(0x9000, std::vector<std::uint8_t>{'h', 'i', 0});
    put32(0x700c, 7);  // [RBP - 0x14]
    put32(0xa000, (5u << 3) | 6u);  // flags: a = 6, b = 5
    ctx.types = &types;
    ctx.lookup = [this](const std::string &name, bool reg_only) -> std::optional<Value> {
      for (const auto &[r, v] : regs)
        if (strcasecmp(r.c_str(), name.c_str()) == 0) {
          Value out;
          out.type = undefined(8);
          out.reg = r;
          for (int i = 0; i < 8; ++i) out.bytes.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
          return out;
        }
      if (reg_only) return std::nullopt;
      if (name == "origin") {  // a typed global
        Value out;
        out.type = types.point_;
        out.address = 0x8000;
        return out;
      }
      if (name == "main") {  // an untyped symbol: its address
        Value out;
        out.type = undefined(8);
        for (int i = 0; i < 8; ++i) out.bytes.push_back(static_cast<std::uint8_t>(0x401000ull >> (8 * i)));
        return out;
      }
      return std::nullopt;
    };
    ctx.read = [this](std::uint64_t a, std::span<std::uint8_t> out) {
      std::size_t n = 0;
      for (; n < out.size(); ++n) {
        auto it = mem.find(a + n);
        if (it == mem.end()) break;
        out[n] = it->second;
      }
      return n;
    };
    ctx.symbolize = [](std::uint64_t a) { return a == 0x401000 ? std::string("main") : std::string(); };
  }
  void put(std::uint64_t a, const std::vector<std::uint8_t> &b) {
    for (std::size_t i = 0; i < b.size(); ++i) mem[a + i] = b[i];
  }
  void put32(std::uint64_t a, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) mem[a + i] = static_cast<std::uint8_t>(v >> (8 * i));
  }
  void put64(std::uint64_t a, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) mem[a + i] = static_cast<std::uint8_t>(v >> (8 * i));
  }
  std::string eval(const std::string &text) {
    auto e = Expression::parse(text, [this](const std::string &n) { return types.by_name(n) != nullptr; });
    return format(e.evaluate(ctx), ctx).text;
  }
  Types types;
  std::map<std::string, std::uint64_t> regs;
  std::map<std::uint64_t, std::uint8_t> mem;
  Context ctx;
};

TEST(Expr, ArithmeticAndPrecedence) {
  Fake f;
  EXPECT_EQ(f.eval("1 + 2 * 3"), "7");
  EXPECT_EQ(f.eval("(1 + 2) * 3"), "9");
  EXPECT_EQ(f.eval("0x10 - 1"), "15");
  EXPECT_EQ(f.eval("-7 / 2"), "-3");
  EXPECT_EQ(f.eval("7 % 3 == 1 && 2 > 1"), "1");
  EXPECT_EQ(f.eval("1 << 4 | 1"), "17");
  EXPECT_EQ(f.eval("~0u"), "4294967295");
  EXPECT_EQ(f.eval("1 ? 5 : 6"), "5");
  EXPECT_EQ(f.eval("1.5 * 2"), "3");
  EXPECT_EQ(f.eval("'A' + 1"), "66");
  EXPECT_EQ(f.eval("(char)65"), "65 'A'");
  EXPECT_EQ(f.eval("(unsigned char)-1"), "255 '\\xff'");
  EXPECT_EQ(f.eval("sizeof(struct point)"), "16");
  EXPECT_THROW(f.eval("1 / 0"), ExprError);
  EXPECT_THROW(f.eval("1 +"), ExprError);
  EXPECT_THROW(f.eval("nosuch + 1"), ExprError);
}

TEST(Expr, RegistersMemoryAndTypes) {
  Fake f;
  EXPECT_EQ(f.eval("RAX"), "0x2a");
  EXPECT_EQ(f.eval("$rax + 1"), "43");
  EXPECT_EQ(f.eval("*$RSP"), "0x2010");
  EXPECT_EQ(f.eval("*(int *)($RBP - 0x14)"), "7");
  EXPECT_EQ(f.eval("*(short *)RSP"), "8208");
  EXPECT_EQ(f.eval("origin.x"), "3");
  EXPECT_EQ(f.eval("origin.y"), "-4");
  EXPECT_EQ(f.eval("origin.name"), "0x9000 \"hi\"");
  EXPECT_EQ(f.eval("origin.name[1]"), "105 'i'");
  EXPECT_EQ(f.eval("origin"), "{x = 3, y = -4, name = 0x9000 \"hi\"}");
  EXPECT_EQ(f.eval("((struct point *)0x8000)->y"), "-4");
  EXPECT_EQ(f.eval("((point_t *)0x8000)->x + 1"), "4");
  EXPECT_EQ(f.eval("&origin.y"), "0x8004");
  EXPECT_EQ(f.eval("(&origin)[0].x"), "3");
  EXPECT_EQ(f.eval("((struct flags *)0xa000)->a"), "6");
  EXPECT_EQ(f.eval("((struct flags *)0xa000)->b"), "5");
  EXPECT_EQ(f.eval("main"), "0x401000");
  EXPECT_EQ(f.eval("(void *)main"), "0x401000 <main>");
  EXPECT_EQ(f.eval("main + 0x10"), "4198416");
  // Memory not readable: the value is unknown; using it is an error.
  EXPECT_EQ(f.eval("*(int *)0x1234"), "??");
  EXPECT_THROW(f.eval("*(int *)0x1234 + 1"), ExprError);
  EXPECT_THROW(f.eval("origin.z"), ExprError);
  // A condition.
  auto e = Expression::parse("origin.x == 3 && $RAX > 40");
  EXPECT_TRUE(truthy(e.evaluate(f.ctx), false));
  auto children = format(Expression::parse("origin").evaluate(f.ctx), f.ctx).children;
  ASSERT_EQ(children.size(), 3u);
  EXPECT_EQ(children[1].name, "y");
  EXPECT_EQ(children[1].text, "-4");
  EXPECT_EQ(children[1].address, 0x8004u);
}

}  // namespace
}  // namespace revkit::debug::expr
