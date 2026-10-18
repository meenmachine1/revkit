// Structure inference on synthetic observations (structures.h): classes of
// passed-on pointers, their fields, conflicts, buffers and nested fields.

#include "abi.h"
#include "structures.h"

#include "revkit/infer/types_bridge.h"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <random>

namespace revkit::infer {
namespace {

const DataOrg kLp64{8, 8, true};
const char *const kRegs[] = {"RDI", "RSI", "RDX", "RCX"};

VType T(const char *spelling) { return *parse_type(spelling, kLp64); }

const Abi &sysv() { return *abi_for("x86:LE:64:default", false); }

Slot param(int i, VType t = VType::pointer_to(VType::integer(8, Sign::is_signed), 8)) {
  Slot s;
  s.reg = kRegs[i];
  s.size = 8;
  s.type = std::move(t);
  return s;
}

PointerAccess load(std::int64_t off, std::uint32_t size, ValueKind v = ValueKind::unknown) {
  PointerAccess a;
  a.offset = off;
  a.size = size;
  a.kind = AccessKind::load;
  a.value = v;
  return a;
}

PointerAccess store(std::int64_t off, std::uint32_t size, ValueKind v = ValueKind::unknown) {
  PointerAccess a = load(off, size, v);
  a.kind = AccessKind::store;
  return a;
}

PointerAccess passed(std::uint64_t call, std::uint64_t callee, int parameter) {
  PointerAccess a;
  a.kind = AccessKind::passed;
  a.address = call;
  a.callee = callee;
  a.parameter = parameter;
  return a;
}

// A call at `address` to `target` passing the caller's parameter `from`
// (or another value, -1) as each argument.
CallSite call(std::uint64_t address, std::uint64_t target, std::vector<int> from) {
  CallSite c;
  c.address = address;
  c.target = target;
  c.locked = true;
  for (std::size_t j = 0; j < from.size(); ++j) {
    Slot a = param(static_cast<int>(j));
    a.from_param = from[j];
    c.args.push_back(a);
  }
  return c;
}

struct Program {
  std::map<std::uint64_t, Observation> obs;
  FixpointResult r;
  std::map<std::uint64_t, Prototype> library;

  Observation &fn(std::uint64_t entry, int params = 1) {
    Observation &o = obs[entry];
    o.ok = true;
    Prototype p;
    p.ret = VType::void_type();
    for (int i = 0; i < params; ++i) {
      o.params.push_back(param(i));
      p.params.push_back(T("long *"));
    }
    r.prototypes.emplace_back(entry, p);
    std::sort(r.prototypes.begin(), r.prototypes.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
    return o;
  }
  PointerUse &use(std::uint64_t entry, int p = 0) {
    Observation &o = obs.at(entry);
    for (PointerUse &u : o.pointer_uses)
      if (u.param == p) return u;
    o.pointer_uses.push_back({});
    o.pointer_uses.back().param = p;
    return o.pointer_uses.back();
  }
  void run(bool shuffle = false) {
    std::vector<std::pair<std::uint64_t, const Observation *>> in;
    for (const auto &[e, o] : obs) in.emplace_back(e, &o);
    if (shuffle) std::shuffle(in.begin(), in.end(), std::mt19937(7));
    infer_structures(in, r, sysv(), kLp64, [&](std::uint64_t t) -> std::optional<Prototype> {
      auto it = library.find(t);
      if (it == library.end()) return std::nullopt;
      return it->second;
    });
  }
  std::string param_type(std::uint64_t entry, int p = 0) const { return print(r.find(entry)->params.at(p), kLp64); }
  const InferredStructure *of(std::uint64_t entry, int p = 0) const {
    const VType &t = r.find(entry)->params.at(p);
    if (!t.is_pointer() || t.target().meta != Meta::struct_) return nullptr;
    return r.structure(t.target().name);
  }
};

const InferredField *field(const InferredStructure &s, std::uint64_t off) {
  for (const InferredField &f : s.fields)
    if (f.offset == off) return &f;
  return nullptr;
}

TEST(Structures, APointerPassedOnIsOneStructureWithEveryFunctionsFields) {
  Program p;
  // f(s) reads a pointer at 0 and an int at 8, and passes s to g; g(s)
  // writes 8 bytes at 0x10 and reads the int at 8.
  p.fn(0x1000).calls.push_back(call(0x1010, 0x2000, {0}));
  p.use(0x1000).accesses = {load(0, 8, ValueKind::pointer), load(8, 4, ValueKind::signed_int), passed(0x1010, 0x2000, 0)};
  p.fn(0x2000);
  p.use(0x2000).accesses = {store(0x10, 8), load(8, 4, ValueKind::signed_int)};
  p.run();
  ASSERT_EQ(p.r.structures.size(), 1u);
  const InferredStructure &s = p.r.structures[0];
  EXPECT_EQ(s.name, "astruct_1");
  EXPECT_EQ(p.param_type(0x1000), "astruct_1 *");
  EXPECT_EQ(p.param_type(0x2000), "astruct_1 *");
  EXPECT_EQ(s.size, 0x18u);
  EXPECT_EQ(s.functions, 2u);
  EXPECT_EQ(s.parameters, 2u);
  ASSERT_EQ(s.fields.size(), 3u);
  EXPECT_EQ(print(field(s, 0)->type, kLp64), "char *");
  EXPECT_EQ(print(field(s, 8)->type, kLp64), "int");
  EXPECT_EQ(field(s, 0x10)->size, 8u);
  // The same whatever order the functions come in.
  Program q = p;
  for (auto &[e, proto] : q.r.prototypes) proto.params[0] = T("long *");
  q.r.structures.clear();
  q.run(true);
  EXPECT_EQ(q.r.structures, p.r.structures);
}

TEST(Structures, TwoStructuresThroughOneGenericFunctionAreSplit) {
  Program p;
  // a and b pass their pointers to h (a void * it only frees): a's holds
  // a pointer at 0, b's a double at 0 and an int at 8.
  p.fn(0x1000).calls.push_back(call(0x1010, 0x3000, {0}));
  p.use(0x1000).accesses = {load(0, 8, ValueKind::pointer), load(0xc, 4, ValueKind::signed_int), load(0, 8)};
  p.fn(0x2000).calls.push_back(call(0x2010, 0x3000, {0}));
  p.use(0x2000).accesses = {load(0, 8, ValueKind::floating), store(8, 4, ValueKind::signed_int), load(8, 4)};
  p.fn(0x3000);
  p.run();
  ASSERT_EQ(p.r.structures.size(), 2u);
  const InferredStructure *a = p.of(0x1000), *b = p.of(0x2000);
  ASSERT_TRUE(a && b);
  EXPECT_NE(a->name, b->name);
  EXPECT_EQ(print(field(*a, 0)->type, kLp64), "char *");
  EXPECT_EQ(print(field(*b, 0)->type, kLp64), "double");
  // The generic function, with no accesses of its own, keeps its type.
  EXPECT_EQ(p.param_type(0x3000), "long *");
}

TEST(Structures, BuffersArraysAndStringsStayPointers) {
  Program p;
  // Bytes at constant offsets: a buffer.
  p.fn(0x1000);
  p.use(0x1000).accesses = {load(0, 1), load(1, 1), store(2, 1)};
  // Ints at their stride: an array.
  p.fn(0x2000);
  p.use(0x2000).accesses = {load(0, 4, ValueKind::signed_int), load(4, 4), load(8, 4, ValueKind::signed_int)};
  // Mixed accesses, but passed to strlen's char *: a string.
  p.fn(0x3000).calls.push_back(call(0x3010, 0x9000, {0}));
  p.use(0x3000).accesses = {load(0, 1), load(4, 4), passed(0x3010, 0x9000, 0)};
  Prototype strlen;
  strlen.ret = T("ulong");
  strlen.params = {T("char *")};
  p.library[0x9000] = strlen;
  // One offset only.
  p.fn(0x4000);
  p.use(0x4000).accesses = {load(8, 4), load(8, 4), store(8, 4)};
  // A library struct's pointer is never replaced.
  p.fn(0x5000);
  p.r.prototypes.back().second.params[0] = T("_IO_FILE *");
  p.use(0x5000).accesses = {load(0, 4), load(8, 8, ValueKind::pointer)};
  // Bytes one by one through a run of eight and more (an unrolled
  // checksum), and words: a buffer still.
  p.fn(0x6000);
  for (int i = 0; i < 12; ++i) p.use(0x6000).accesses.push_back(load(i, 1));
  p.use(0x6000).accesses.push_back(load(0x10, 8));
  p.use(0x6000).accesses.push_back(load(0x18, 8));
  p.run();
  EXPECT_TRUE(p.r.structures.empty());
  EXPECT_EQ(p.param_type(0x1000), "long *");
  EXPECT_EQ(p.param_type(0x6000), "long *");
  EXPECT_EQ(p.param_type(0x3000), "long *");
  EXPECT_EQ(p.param_type(0x5000), "_IO_FILE *");
}

TEST(Structures, AFieldPassedOnPointsToItsOwnStructure) {
  Program p;
  // f(s) and g(s) read s->0x18 and, through it, an int at 0 and a pointer
  // at 8; f passes it to h, which reads an int at 4 through it, and g
  // passes s to f.
  for (std::uint64_t e : {0x1000, 0x2000}) {
    p.fn(e).calls.push_back(call(e + 0x10, 0x3000, {-1}));
    if (e == 0x2000) p.obs.at(e).calls.push_back(call(0x2020, 0x1000, {0}));
    PointerUse &u = p.use(e);
    u.accesses = {load(0x18, 8, ValueKind::pointer), load(0, 4, ValueKind::signed_int)};
    PointerUse::Field f;
    f.offset = 0x18;
    f.accesses = {load(0, 4, ValueKind::signed_int), load(8, 8, ValueKind::pointer)};
    if (e == 0x1000) f.accesses.push_back(passed(0x1010, 0x3000, 0));
    u.fields.push_back(f);
  }
  p.fn(0x3000);
  p.use(0x3000).accesses = {load(4, 4, ValueKind::unsigned_int)};
  p.run();
  ASSERT_EQ(p.r.structures.size(), 2u);
  const InferredStructure *outer = p.of(0x1000);
  ASSERT_TRUE(outer);
  EXPECT_EQ(p.of(0x2000), outer);  // one field: f's and g's are one class (congruence)
  const InferredField *f = field(*outer, 0x18);
  ASSERT_TRUE(f);
  ASSERT_TRUE(f->type.is_pointer());
  EXPECT_EQ(f->type.target().meta, Meta::struct_);
  const InferredStructure *inner = p.r.structure(f->type.target().name);
  ASSERT_TRUE(inner);
  EXPECT_EQ(p.of(0x3000), inner);  // h's parameter is that field's value
  EXPECT_EQ(print(field(*inner, 4)->type, kLp64), "uint");
  EXPECT_EQ(inner->functions, 3u);
}

TEST(Structures, ALinkedNodePointsToItself) {
  Program p;
  // n->next at 8 is passed back to the same function (a list walk).
  p.fn(0x1000).calls.push_back(call(0x1010, 0x1000, {-1}));
  PointerUse &u = p.use(0x1000);
  u.accesses = {load(0, 4, ValueKind::signed_int), load(8, 8, ValueKind::pointer)};
  PointerUse::Field f;
  f.offset = 8;
  f.accesses = {load(0, 4, ValueKind::signed_int), passed(0x1010, 0x1000, 0)};
  u.fields.push_back(f);
  p.run();
  ASSERT_EQ(p.r.structures.size(), 1u);
  const InferredStructure &s = p.r.structures[0];
  EXPECT_EQ(print(field(s, 8)->type, kLp64), "astruct_1 *");
  // As types: a complete struct that points to itself.
  types::TypeStore store;
  const StructureIds ids = to_types(p.r.structures, store, kLp64);
  const auto *agg = store.get(ids.at("astruct_1")).as<types::AggregateType>();
  ASSERT_TRUE(agg);
  EXPECT_TRUE(agg->complete);
  EXPECT_EQ(agg->size, 0x10u);
  ASSERT_EQ(agg->fields.size(), 2u);
  EXPECT_EQ(agg->fields[1].name, "field_0x8");
  const auto *next = store.get(agg->fields[1].type).as<types::PointerType>();
  ASSERT_TRUE(next);
  EXPECT_EQ(next->target, ids.at("astruct_1"));
}

TEST(Structures, AListWalkedThroughAParameterPointsToItself) {
  Program p;
  // for (; p; p = p->next) sum += p->value: the value loaded at 8 flows
  // back into the parameter.
  p.fn(0x1000);
  PointerUse &u = p.use(0x1000);
  u.accesses = {load(0, 4, ValueKind::signed_int), load(8, 8, ValueKind::pointer), load(0, 4, ValueKind::signed_int)};
  u.self = {8};
  p.run();
  ASSERT_EQ(p.r.structures.size(), 1u);
  EXPECT_EQ(print(field(p.r.structures[0], 8)->type, kLp64), "astruct_1 *");
}

TEST(Structures, AStackOfPairsIsAnArrayOfThem) {
  Program p;
  // top[-1].value, top[-1].tag, top[0].value, top[-2].tag: elements of 16
  // bytes, a pointer and a tag byte.
  p.fn(0x1000);
  p.use(0x1000).accesses = {load(-0x10, 8, ValueKind::pointer), load(-8, 1), store(0, 8), store(8, 1), load(-0x18, 1)};
  p.run();
  ASSERT_EQ(p.r.structures.size(), 1u);
  const InferredStructure &s = p.r.structures[0];
  EXPECT_EQ(s.size, 0x10u);
  ASSERT_EQ(s.fields.size(), 2u);
  EXPECT_EQ(print(field(s, 0)->type, kLp64), "char *");
  EXPECT_EQ(field(s, 8)->size, 1u);
  EXPECT_EQ(p.param_type(0x1000), "astruct_1 *");
}

TEST(Structures, SizesRoundUpToTheFieldsAlignment) {
  Program p;
  // A pointer at 0 and a byte at 8: 16 bytes, as a compiler lays it out.
  p.fn(0x1000);
  p.use(0x1000).accesses = {load(0, 8, ValueKind::pointer), load(8, 1), store(8, 1)};
  p.run();
  ASSERT_EQ(p.r.structures.size(), 1u);
  EXPECT_EQ(p.r.structures[0].size, 0x10u);
}

}  // namespace
}  // namespace revkit::infer
