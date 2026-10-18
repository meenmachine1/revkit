// revkit::infer: the type lattice, the signature databases, the merge
// rules on synthetic evidence, and inference end to end on a compiled,
// stripped program.

#include "builders.hh"

#include "abi.h"
#include "merge.h"
#include "sigdb.h"

#include "revkit/analysis/analysis.h"
#include "revkit/facts/fact_db.h"
#include "revkit/facts/thread_pool.h"
#include "revkit/infer/ghidra_types.h"
#include "revkit/infer/infer.h"
#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <cstddef>
#include <map>

namespace revkit::infer {
namespace {

const DataOrg kLp64{8, 8, true};
const DataOrg kLlp64{8, 4, true};

VType T(const char *spelling, const DataOrg &org = kLp64) { return *parse_type(spelling, org); }

// ---- lattice ----

TEST(VType, ParsesAndPrintsGhidraNotation) {
  for (const char *s : {"int", "uint", "ulong", "char * *", "_IO_FILE *", "undefined8", "double", "void *", "bool"})
    EXPECT_EQ(print(T(s), kLp64), s);
  // An 8-byte integer is long on LP64 and long long on LLP64.
  EXPECT_EQ(print(VType::integer(8, Sign::is_unsigned), kLp64), "ulong");
  EXPECT_EQ(print(VType::integer(8, Sign::is_unsigned), kLlp64), "ulonglong");
  EXPECT_EQ(T("long", kLlp64).size, 4);
}

TEST(VType, FunctionTypesPrintAsGhidraNamesThem) {
  Prototype p;
  p.ret = T("int");
  p.params = {T("int"), T("int")};
  EXPECT_EQ(print(VType::pointer_to(VType::code_of(p), 8), kLp64), "_func_int_int_int *");
  p.ret = T("void");
  p.params = {T("int *"), T("void *")};
  EXPECT_EQ(print(VType::code_of(p), kLp64), "_func_void_int_ptr_void_ptr");
}

TEST(VType, JoinIsTheMostSpecificConsistentType) {
  // Anything beats unknown; of two unknowns, the wider.
  EXPECT_EQ(join(T("undefined8"), T("long")), T("long"));
  EXPECT_EQ(join(VType::unknown(0), T("undefined8")), T("undefined8"));
  // A pointer beats an integer of its size (pointer arithmetic).
  EXPECT_EQ(join(T("long"), T("char *")), T("char *"));
  // Pointer targets: void and unknown say the least.
  EXPECT_EQ(join(T("void *"), T("char *")), T("char *"));
  EXPECT_EQ(join(T("undefined *"), T("int *")), T("int *"));
  // Known signedness beats unknown; conflicts keep the first.
  EXPECT_EQ(join(VType::integer(4, Sign::unknown), T("uint")), T("uint"));
  EXPECT_EQ(join(T("int"), T("uint")), T("int"));
  // Plain char beats a byte.
  EXPECT_EQ(join(T("uchar"), T("char")), T("char"));
  // A signature beats a bare code type.
  Prototype p;
  p.ret = T("int");
  EXPECT_EQ(join(VType::code_type(), VType::code_of(p)), VType::code_of(p));
  // Widening keeps only size and pointer-ness.
  EXPECT_EQ(widen(T("int *")), T("undefined *"));
  EXPECT_EQ(widen(T("uint")), T("undefined4"));
}

TEST(VType, CodecRoundTrips) {
  Prototype p;
  p.ret = T("char *");
  p.params = {T("int"), VType::pointer_to(VType::code_of(p), 8), T("_IO_FILE *")};
  p.varargs = true;
  p.source = "test";
  EXPECT_EQ(facts::decode_from_string<Prototype>(facts::encode_to_string(p)), p);
}

// ---- signature databases ----

TEST(SigDb, FindsLibraryPrototypesWithTypedefsResolved) {
  loader::Image elf;
  elf.format = loader::Format::elf;
  const SigDb &db = SigDb::for_image(elf);
  auto fopen = db.find("fopen", kLp64);
  ASSERT_TRUE(fopen);
  EXPECT_EQ(fopen->print("fopen", kLp64), "_IO_FILE * fopen(char * param_1, char * param_2)");
  auto printf = db.find("printf", kLp64);
  ASSERT_TRUE(printf);
  EXPECT_TRUE(printf->varargs);
  // Versioned and ISO-alias names find the plain one.
  EXPECT_TRUE(db.find("memcpy@GLIBC_2.14", kLp64));
  EXPECT_TRUE(db.find("__isoc99_sscanf", kLp64));
  EXPECT_FALSE(db.find("no_such_function_anywhere", kLp64));
  // qsort's comparator and main's optional parameters.
  auto cmp = db.callback("qsort", 3, kLp64);
  ASSERT_TRUE(cmp);
  EXPECT_EQ(cmp->print("f", kLp64), "int f(void * param_1, void * param_2)");
  auto main = db.callback("__libc_start_main", 0, kLp64);
  ASSERT_TRUE(main);
  EXPECT_EQ(main->source, "callback-optional");

  loader::Image pe;
  pe.format = loader::Format::pe;
  auto sleep = SigDb::for_image(pe).find("Sleep", kLlp64);
  ASSERT_TRUE(sleep);
  // DWORD is unsigned long, 4 bytes on LLP64; types keep size and sign,
  // not C's rank, so it prints as uint.
  EXPECT_EQ(sleep->print("Sleep", kLlp64), "void Sleep(uint param_1)");
}

TEST(SigDb, PriorsComeFromTheHeaders) {
  const Priors &p = SigDb::priors(kLp64);
  EXPECT_EQ(print(p.unknown_return(8), kLp64), "int");  // an untyped RAX
  EXPECT_EQ(print(p.integer_param(4), kLp64), "int");
  EXPECT_EQ(print(p.integer_param(8), kLp64), "ulong");  // size_t
  EXPECT_EQ(print(p.pointee, kLp64), "char");
  EXPECT_EQ(print(SigDb::priors(kLlp64).integer_param(8), kLlp64), "ulonglong");
}

// ---- merging evidence ----

Slot Reg(const char *reg, std::uint8_t size, const char *type) {
  Slot s;
  s.reg = reg;
  s.size = size;
  s.type = T(type);
  s.used = size;
  return s;
}

TEST(Merge, OrdersParametersAndNarrowsTheReturnRegister) {
  const Abi *sysv = abi_for("x86:LE:64:default:gcc", false);
  ASSERT_NE(sysv, nullptr);
  Observation self;
  self.ok = true;
  self.params = {Reg("XMM0", 8, "double"), Reg("RDI", 8, "char *"), Reg("RSI", 4, "uint")};
  self.ret = Reg("RAX", 8, "undefined8");
  self.ret_natural = 4;  // a 4-byte value zero-extended into RAX
  Evidence ev;
  ev.self0 = &self;
  Prototype p = finalize(merge(sysv, ev, kLp64), kLp64);
  // Integer arguments first, then floats; parameter signedness takes the
  // headers' prior, an untyped narrow return int.
  EXPECT_EQ(p.print("f", kLp64), "int f(char * param_1, int param_2, double param_3)");
}

// An unknown 8-byte return: the headers' commonest return that fits (int)
// when shown, its register's width when a decompiler is told it, so a
// caller reading the whole register reads the value, not CONCAT44.
TEST(Merge, KeepReturnWidthForTheDecompiler) {
  const Abi *sysv = abi_for("x86:LE:64:default:gcc", false);
  Observation self;
  self.ok = true;
  self.params = {Reg("RDI", 8, "char *")};
  self.ret = Reg("RAX", 8, "undefined8");
  Evidence ev;
  ev.self0 = &self;
  const Prototype merged = merge(sysv, ev, kLp64);
  EXPECT_EQ(finalize(merged, kLp64).ret.size, 4u);
  EXPECT_EQ(finalize(merged, kLp64, true).ret.size, 8u);
  EXPECT_EQ(finalize(merged, kLp64, true).params, finalize(merged, kLp64).params);
}

TEST(Merge, CallersTypeWhatTheCalleeDoesNotKnow) {
  const Abi *sysv = abi_for("x86:LE:64:default:gcc", false);
  Observation self;
  self.ok = true;
  self.params = {Reg("RDI", 8, "undefined8"), Reg("RSI", 8, "long")};
  CallSite site;
  site.args = {Reg("RDI", 8, "_IO_FILE *"), Reg("RSI", 8, "undefined8")};
  site.args[1].constants = {0x401000};
  site.args[1].data_address = true;  // a static buffer
  Evidence ev;
  ev.self0 = &self;
  ev.unlocked = {&site};
  Prototype p = finalize(merge(sysv, ev, kLp64), kLp64);
  EXPECT_EQ(p.print("f", kLp64), "void f(_IO_FILE * param_1, char * param_2)");
}

TEST(Merge, VariadicPrologueKeepsTheNamedParameters) {
  const Abi *aarch64 = abi_for("AARCH64:LE:64:v8A:default", false);
  ASSERT_NE(aarch64, nullptr);
  Observation self;
  self.ok = true;
  for (int i = 0; i < 8; ++i) self.params.push_back(Reg(("x" + std::to_string(i)).c_str(), 8, "undefined8"));
  self.params[0].type = T("char *");
  // The register save area: x2..x7 stored before anything writes them.
  self.spills = {"x29", "x30", "x2", "x3", "x4", "x5", "x6", "x7"};
  self.ret = Reg("x0", 8, "int");
  Evidence ev;
  ev.self0 = &self;
  Prototype p = finalize(merge(aarch64, ev, kLp64), kLp64);
  EXPECT_TRUE(p.varargs);
  EXPECT_EQ(p.params.size(), 2u);

  // System V: AL read.
  const Abi *sysv = abi_for("x86:LE:64:default:gcc", false);
  Observation v;
  v.ok = true;
  v.params = {Reg("RDI", 4, "int")};
  v.reads_al = true;
  ev.self0 = &v;
  EXPECT_EQ(finalize(merge(sysv, ev, kLp64), kLp64).print("f", kLp64), "void f(int param_1, ...)");
}

TEST(Merge, TableFamiliesVoteAndUnsignedWins) {
  Prototype a;
  a.ret = T("int");
  a.params = {T("int")};
  Prototype b = a, c = a;
  c.ret = T("uint");
  b.params = {T("undefined4")};
  auto v = family_vote(a, {a, b, c});
  ASSERT_TRUE(v);
  EXPECT_EQ(v->print("f", kLp64), "uint f(int param_1)");
  // Members that disagree on arity aren't one type.
  Prototype d;
  d.params = {T("int"), T("int"), T("int")};
  Prototype e;
  EXPECT_FALSE(family_vote(a, {a, d, e}));
}

// ---- end to end ----

constexpr const char *kProgram = R"(
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*binop)(int, int);
__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int sub(int a, int b) { return a - b; }
__attribute__((noinline)) int mul(int a, int b) { return a * b; }
static const binop table[] = {add, sub, mul};

__attribute__((noinline)) int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

__attribute__((noinline)) long sum(int n, ...) {
  va_list ap;
  va_start(ap, n);
  long s = 0;
  for (int i = 0; i < n; i++) s += va_arg(ap, int);
  va_end(ap);
  return s;
}

__attribute__((noinline)) unsigned long length_of(const char *s) { return strlen(s) + 1; }

__attribute__((noinline)) void report(FILE *f, const char *what, int n) { fprintf(f, "%s %d\n", what, n); }

struct state { long a; int b; };
// The decompiler's own view of s is an integer (pointer arithmetic,
// *(int *)(param_1 + 8)); its caller's is a pointer (*param_1 = ...).
__attribute__((noinline)) int field_b(struct state *s) { return s->b * 3; }
__attribute__((noinline)) int with_state(struct state *s, int v) {
  s->a = v;
  return field_b(s) + 1;
}

// fatal never returns, but only its callers say so: nothing after their
// calls to it (no-return evidence), as discovery's own inference can't
// tell through the indirect call. Each caller's call ends it, and the next
// function's code, which reads four argument registers, follows.
typedef void (*fatal_fn)(int);
static void fatal_default(int c) { exit(c); }
fatal_fn volatile on_fatal = fatal_default;
__attribute__((noinline, noreturn)) void fatal(int c) {
  on_fatal(c);
  __builtin_unreachable();
}
__attribute__((noinline)) int checked1(int *p, int n) {
  if (!p) fatal(n);
  return *p + n;
}
__attribute__((noinline)) long sum4a(long a, long b, long c, long d) { return a * b + c * d; }
__attribute__((noinline)) int checked2(int *p, int n) {
  if (!p) fatal(n + 1);
  return *p - n;
}
__attribute__((noinline)) long sum4b(long a, long b, long c, long d) { return a - b + c * d; }
__attribute__((noinline)) int checked3(int *p, int n) {
  if (!p) fatal(n + 2);
  return *p * n;
}
__attribute__((noinline)) long sum4c(long a, long b, long c, long d) { return a ^ b ^ (c * d); }

// A tail call (jmp) into a variadic function, whose register save area
// stores every argument register: warn_if's decompilation must stop at the
// jump, not take in log_line's code.
__attribute__((noinline)) void log_line(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}
__attribute__((noinline, optimize("O2", "optimize-sibling-calls"))) void warn_if(int c) {
  if (c > 3) log_line("big %d\n", c);
}

// `found` is only passed on: check never writes RDX before calling lookup,
// which reads it.
__attribute__((noinline)) long lookup(long *tab, int i, int *found) {
  long v = tab[i];
  if (found) *found = v != 0;
  return v;
}
__attribute__((noinline)) long check(long *tab, int i, int *found) {
  long v = lookup(tab, i, found);
  if (v == 0) return tab[0] + i;
  return v;
}
// And on through check, which only passes it on too.
__attribute__((noinline)) long check_twice(long *tab, int i, int *found) {
  long v = check(tab, i, found);
  return v + tab[1] + i;
}

// One pointer passed on unchanged: its callers see what it points to
// differently (a byte at its start here, a long there), but it is one
// value, one type.
struct rec { long a; long b; };
__attribute__((noinline)) long rec_sum(struct rec *p) { return p->a + p->b * 2; }
__attribute__((noinline)) long rec_low(struct rec *p) { return *(unsigned char *)p + rec_sum(p); }
__attribute__((noinline)) long rec_all(struct rec *p) { return p->a * 5 + rec_sum(p); }
__attribute__((noinline)) long rec_all2(struct rec *p) { return p->a - rec_sum(p); }

// Structures for pointers passed on: a list of nodes (an int, a double, a
// next pointer, a flag byte) walked and filled through several functions,
// and a holder whose field points to the first node.
struct node { int val; double w; struct node *next; unsigned char flag; };
struct holder { long n; int count; struct node *head; };
__attribute__((noinline)) double node_sum(struct node *p) {
  double s = 0;
  for (; p; p = p->next) s += p->val * p->w + p->flag;
  return s;
}
__attribute__((noinline)) void node_mark(struct node *p, int v) {
  p->val = v;
  p->flag = 1;
  p->w = node_sum(p);
}
__attribute__((noinline)) double holder_sum(struct holder *h) {
  h->count++;
  return node_sum(h->head) + h->n;
}
__attribute__((noinline)) double holder_mark(struct holder *h, int v) {
  node_mark(h->head, v + h->count);
  return holder_sum(h);
}

int main(int argc, char **argv) {
  int v[4] = {argc, 3, 1, 2};
  qsort(v, 4, sizeof(int), cmp);
  int r = table[argc % 3](v[0], v[1]);
  struct state st = {0, argc};
  r += with_state(&st, v[2]);
  long tab[3] = {argc, 2, 0};
  int found = 0;
  r += (int)check(tab, argc % 3, &found) + found;
  r += (int)check_twice(tab, argc % 2, &found) + found;
  r += checked1(&v[0], argc) + checked2(&v[1], argc) + checked3(&v[2], argc);
  r += (int)(sum4a(argc, 2, 3, 4) + sum4b(argc, 5, 6, 7) + sum4c(argc, 8, 9, 10));
  warn_if(argc);
  struct rec rc = {argc, 2};
  r += (int)(rec_low(&rc) + rec_all(&rc) + rec_all2(&rc));
  struct node n2 = {argc, 1.5, 0, 0}, n1 = {2, 0.5, &n2, 1};
  struct holder h = {argc, 0, &n1};
  r += (int)holder_mark(&h, argc);
  report(stdout, argv[0], r + (int)sum(3, 1, 2, 3) + (int)length_of(argv[0]));
  return 0;
}
)";

class EndToEnd : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    lift::initialize(REVKIT_GHIDRA_ROOT);
    dir_ = testing::scratch_dir("infer-e2e");
    if (!testing::compile(REVKIT_TEST_CC, kProgram, "-O1", dir_ / "named") ||
        !testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -s", dir_ / "stripped"))
      GTEST_SKIP() << "no C compiler";
  }
  std::filesystem::path dir_;
};

TEST_F(EndToEnd, InfersPrototypesOfAStrippedProgram) {
  // Where each function is, from the twin with symbols.
  std::map<std::string, std::uint64_t> at;
  loader::LoadOptions lo;
  lo.ghidra_image_base = true;
  for (const loader::Symbol &s : loader::load_file(dir_ / "named", lo).symbols)
    if (s.defined && s.type == loader::SymbolType::func) at[s.name] = s.value;

  auto image = std::make_shared<const loader::Image>(loader::load_file(dir_ / "stripped", lo));
  auto lang = loader::guess_language(*image);
  ASSERT_TRUE(lang);
  facts::FactDb db;
  analysis::register_queries(db.engine());
  register_queries(db.engine());
  const analysis::ProgramKey prog{"p"};
  {
    auto tx = db.begin();
    analysis::stage_image(tx, prog, *image, analysis::describe(*image, lang->id()));
    stage_image(tx, prog, image, lang->id(), "stripped");
    tx.commit();
  }
  facts::ThreadPool pool(4);
  facts::Snapshot snap = db.snapshot();
  FixpointResult r = run(snap, prog, &pool);
  EXPECT_TRUE(r.converged);
  EXPECT_LE(r.rounds, 16u);

  const DataOrg org = data_org(*image);
  auto proto = [&](const char *name) {
    auto p = prototype_for(snap, {prog, at.at(name)});
    return p ? p->print(name, org) : std::string("(none)");
  };
  // qsort's comparator: the library's type.
  EXPECT_EQ(proto("cmp"), "int cmp(void * param_1, void * param_2)");
  // A table member, with its siblings.
  EXPECT_EQ(proto("add"), "int add(int param_1, int param_2)");
  EXPECT_EQ(proto("mul"), "int mul(int param_1, int param_2)");
  // Variadic. (Its long return, untyped in RAX, takes the int prior: a
  // known gap, docs/infer.md.)
  auto sum = prototype_for(snap, {prog, at.at("sum")});
  ASSERT_TRUE(sum);
  EXPECT_TRUE(sum->varargs);
  EXPECT_EQ(sum->params.size(), 1u);
  // A FILE * and a string, from fprintf.
  EXPECT_EQ(proto("report"), "void report(_IO_FILE * param_1, char * param_2, int param_3)");
  auto length_of = prototype_for(snap, {prog, at.at("length_of")});
  ASSERT_TRUE(length_of);
  ASSERT_EQ(length_of->params.size(), 1u);
  EXPECT_EQ(print(length_of->params[0], org), "char *");
  // A pointer the caller has, passed to a callee whose own view is an
  // integer: the caller's type, not the cast to the callee's previous
  // view that the locked call shows.
  auto field_b = prototype_for(snap, {prog, at.at("field_b")});
  ASSERT_TRUE(field_b);
  ASSERT_EQ(field_b->params.size(), 1u);
  EXPECT_TRUE(field_b->params[0].is_pointer()) << field_b->print("field_b", org);
  // Callers of a function only call sites say never returns: their
  // decompilations stop at the call, not in the next function's code.
  for (const char *name : {"checked1", "checked2", "checked3"}) {
    auto p = prototype_for(snap, {prog, at.at(name)});
    ASSERT_TRUE(p) << name;
    EXPECT_EQ(p->params.size(), 2u) << p->print(name, org);
  }
  // A parameter only passed on to a callee that reads it.
  auto check = prototype_for(snap, {prog, at.at("check")});
  ASSERT_TRUE(check);
  EXPECT_EQ(check->params.size(), 3u) << check->print("check", org);
  auto check_twice = prototype_for(snap, {prog, at.at("check_twice")});
  ASSERT_TRUE(check_twice);
  EXPECT_EQ(check_twice->params.size(), 3u) << check_twice->print("check_twice", org);
  // A pointer passed on unchanged has one type all the way down.
  {
    std::vector<std::string> types;
    for (const char *name : {"rec_sum", "rec_low", "rec_all", "rec_all2"}) {
      auto p = prototype_for(snap, {prog, at.at(name)});
      ASSERT_TRUE(p && !p->params.empty()) << name;
      types.push_back(print(p->params[0], org));
    }
    for (const std::string &t : types) EXPECT_EQ(t, types[0]) << ::testing::PrintToString(types);
  }
  // Structures for the classes of passed-on pointers: node_sum's,
  // node_mark's and the holder's head field are one (inferred) structure,
  // whose next field points to itself; the holder's is another.
  {
    auto param_struct = [&](const char *name) -> const InferredStructure * {
      auto p = prototype_for(snap, {prog, at.at(name)});
      if (!p || p->params.empty() || !p->params[0].is_pointer() || p->params[0].target().meta != Meta::struct_) return nullptr;
      return r.structure(p->params[0].target().name);
    };
    auto field_at = [](const InferredStructure &s, std::uint64_t off) -> const InferredField * {
      for (const InferredField &f : s.fields)
        if (f.offset == off) return &f;
      return nullptr;
    };
    const InferredStructure *node = param_struct("node_sum"), *holder = param_struct("holder_sum");
    ASSERT_TRUE(node && holder) << proto("node_sum") << " / " << proto("holder_sum");
    EXPECT_TRUE(node->name.starts_with("astruct_")) << node->name;
    EXPECT_EQ(param_struct("node_mark"), node) << proto("node_mark");
    EXPECT_EQ(param_struct("holder_mark"), holder) << proto("holder_mark");
    EXPECT_NE(node, holder);
    const InferredField *next = field_at(*node, 0x10);  // struct node: val 0, w 8, next 0x10, flag 0x18
    ASSERT_TRUE(next);
    EXPECT_EQ(print(next->type, org), node->name + " *");
    const InferredField *val = field_at(*node, 0), *w = field_at(*node, 8);
    ASSERT_TRUE(val && w);
    EXPECT_EQ(print(val->type, org), "int");
    EXPECT_EQ(print(w->type, org), "double");
    const InferredField *head = field_at(*holder, 0x10);
    ASSERT_TRUE(head);
    EXPECT_EQ(print(head->type, org), node->name + " *");
    EXPECT_EQ(holder->size, 0x18u);
  }
  // A function that ends in a jump to another's entry calls it.
  auto warn_if = prototype_for(snap, {prog, at.at("warn_if")});
  ASSERT_TRUE(warn_if);
  EXPECT_EQ(warn_if->params.size(), 1u) << warn_if->print("warn_if", org);
  EXPECT_FALSE(warn_if->varargs) << warn_if->print("warn_if", org);
  // main, through __libc_start_main.
  EXPECT_EQ(proto("main"), "int main(int param_1, char * * param_2)");

  // The pool keeps a lifter per thread that used it until trimmed (a
  // daemon trims after each run: ~200 MB per open program otherwise).
  auto input = snap.get<ImageInput>(prog);
  ASSERT_TRUE(input->pool);
  EXPECT_GT(input->pool->idle_lifters(), 0u);
  input->pool->trim();
  EXPECT_EQ(input->pool->idle_lifters(), 0u);
}

// What inference locks into prototypes must be a type the decompiler can
// take: no zero-size types or degenerate arrays. A pointer to a struct known
// only by name stays the decompiler's own forward declaration (incomplete,
// size 0); the fork guards the split that divided by it (patches/0003).
TEST_F(EndToEnd, DegenerateTypesNeverReachTheDecompiler) {
  loader::LoadOptions lo;
  lo.ghidra_image_base = true;
  auto image = std::make_shared<const loader::Image>(loader::load_file(dir_ / "stripped", lo));
  auto lang = loader::guess_language(*image);
  ASSERT_TRUE(lang);
  std::ostringstream errors;
  std::unique_ptr<lift::ImageArchitecture> arch;
  {
    auto globals = lift::lock_ghidra_globals();
    arch = std::make_unique<lift::ImageArchitecture>(image, "image", lang->id(), &errors);
  }
  arch->init_image();
  ghidra::TypeFactory &tf = *arch->types;

  ghidra::Datatype *file = value_type(*arch, VType::pointer_to(VType::structure("_IO_FILE"), 8));
  ASSERT_EQ(file->getMetatype(), ghidra::TYPE_PTR);
  EXPECT_EQ(static_cast<ghidra::TypePointer *>(file)->getPtrTo()->getName(), "_IO_FILE");
  EXPECT_TRUE(decompiler_safe(*file));

  ghidra::TypeStruct *opaque = tf.getTypeStruct("__jmp_buf_tag");  // size 0
  ghidra::Datatype *of_opaque = tf.getTypeArray(4, opaque);          // zero-size elements
  ghidra::Datatype *none = tf.getTypeArray(0, tf.getBase(4, ghidra::TYPE_INT));
  EXPECT_FALSE(decompiler_safe(*of_opaque));
  EXPECT_FALSE(decompiler_safe(*tf.getTypePointer(8, of_opaque, 1)));
  EXPECT_FALSE(decompiler_safe(*none));
  EXPECT_TRUE(decompiler_safe(*tf.getTypeArray(2, tf.getBase(4, ghidra::TYPE_INT))));
  for (const VType &t : {VType::unknown(0), VType::integer(0, Sign::unknown), VType::floating(3),
                         VType::pointer_to(VType::unknown(0), 8), VType::code_type()})
    EXPECT_TRUE(decompiler_safe(*value_type(*arch, t))) << print(t, kLp64);
}

}  // namespace
}  // namespace revkit::infer
