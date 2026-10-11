// Structures from pointer use and from a listing selection
// (TypeService.AutoStructure; docs/types.md, "Structures from pointer
// use"): Auto Create, Auto Fill in, into callees, applied as one request
// and undone, on a program compiled at test time.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <map>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

// struct item: next 0, count 8, kind 0xc, tag 0xe, weight 0x10, total
// 0x18; 0x20 bytes. walk() reads next (and next->kind), kind and tag and
// writes total;
// bump(), which walk() passes the pointer to, reads and writes count and
// weight; mark() gets &it->total. chain() walks a list in a local (a
// register at -O1, a stack slot at -O0), push() through a temporary.
constexpr const char *kProgram = R"(
struct item { struct item *next; int count; short kind; signed char tag; double weight; long total; };
struct conf { int magic; short port; short flags; const char *name; };
struct conf config = {0x1234, 80, 3, "server"};
__attribute__((noinline)) void bump(struct item *it) { it->count++; it->weight *= 2.0; }
__attribute__((noinline)) void mark(long *p) { *p += 1; }
__attribute__((noinline)) void push(struct item *it) { struct item *top = it->next; top->tag = 0; it->next = top + 1; }
struct item *head;
__attribute__((noinline)) struct item *first(void) { return head; }
__attribute__((noinline)) long chain(void) {
  long s = 0;
  for (struct item *n = first(); n != 0; n = n->next) s += n->kind + n->total;
  return s;
}
__attribute__((noinline)) long sum2(struct item *it) { return it->kind + it->count; }
__attribute__((noinline)) void deep(struct item *it) { it->next->count += 1; it->next->next->tag = 0; }
__attribute__((noinline)) long walk(struct item *it) {
  long t = it->kind + it->tag;
  if (it->next != 0) t += it->next->kind;
  it->total = t;
  bump(it);
  mark(&it->total);
  return t;
}
int main(int argc, char **argv) {
  (void)argv;
  static struct item a, b;
  a.next = argc > 2 ? &b : 0;
  a.kind = (short)argc;
  head = &b;
  push(&b);
  deep(&a);
  return (int)walk(&a) + config.port + (int)chain() + (int)sum2(&b);
}
)";

class AutoStructTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("auto-struct");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -fno-pie -no-pie -fno-inline", exe_);
    // Unoptimized: chain()'s n lives in a stack slot.
    exe0_ = dir / "prog0";
    compiled0_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O0 -fno-pie -no-pie", exe0_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(exe_.string());
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id_ = resp.program().program_id();
    pb::ListFunctionsRequest fr;
    fr.set_program_id(id_);
    fr.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse fs;
    ASSERT_TRUE(backend_->ListFunctions(ctx_, fr, fs).ok());
    for (const auto &f : fs.functions()) functions_[f.name()] = f.entry().offset();
    ASSERT_TRUE(functions_.contains("walk") && functions_.contains("bump"));
  }

  pb::DecompiledFunction Decompile(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  api::Status Auto(std::uint64_t entry, const std::string &key, pb::AutoStructureMode mode, pb::AutoStructureResponse &resp,
                   std::optional<std::uint32_t> depth = std::nullopt, const std::string &name = {}) {
    pb::AutoStructureRequest req;
    req.set_program_id(id_);
    req.mutable_variable()->mutable_function()->set_offset(entry);
    req.mutable_variable()->set_storage_key(key);
    req.set_mode(mode);
    if (depth) req.set_call_depth(*depth);
    req.set_name(name);
    return backend_->AutoStructure(ctx_, req, resp);
  }

  // What a client asserts to apply a response: the nodes, the binding, and
  // a retype of the variable (or a data definition at the range).
  pb::AppendAssertionsResponse Apply(const pb::AutoStructureResponse &r, const pb::AssertionBody &last) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    for (const auto &n : r.nodes()) *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = n;
    if (!r.named_key().empty())
      req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(r.struct_index());
    // A field target: the outer structure's next version takes its name.
    if (r.has_outer_index())
      req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(r.outer_index());
    if (last.ByteSizeLong() != 0) *req.add_assertions()->mutable_body() = last;
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  pb::AssertionBody RetypeLocal(std::uint64_t entry, const std::string &key, const std::string &hash) {
    pb::AssertionBody b;
    auto *l = b.mutable_retype()->mutable_target()->mutable_local();
    l->mutable_function()->set_offset(entry);
    l->set_storage_key(key);
    b.mutable_retype()->mutable_type()->set_type_hash(hash);
    return b;
  }
  void Undo(const pb::AppendAssertionsResponse &done) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    for (const auto &a : done.assertions()) req.add_seqs(a.seq());
    pb::RetractAssertionsResponse resp;
    auto st = backend_->RetractAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  }

  static std::map<std::uint64_t, const pb::AutoStructureField *> ByOffset(const pb::AutoStructureResponse &r) {
    std::map<std::uint64_t, const pb::AutoStructureField *> out;
    for (const auto &f : r.fields()) out[f.offset()] = &f;
    return out;
  }
  static const pb::Variable *Param(const pb::DecompiledFunction &f, std::uint32_t i) {
    for (const auto &v : f.variables())
      if (v.kind() == pb::VARIABLE_KIND_PARAMETER && v.parameter_index() == i) return &v;
    return nullptr;
  }

  static inline std::filesystem::path exe_, exe0_;
  static inline bool compiled_ = false, compiled0_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
  std::map<std::string, std::uint64_t> functions_;
};

TEST_F(AutoStructTest, CreatesAStructureFromTheAccessesAndTheCalleesAndAppliesIt) {
  const std::uint64_t walk = functions_.at("walk");
  const pb::DecompiledFunction before = Decompile(walk);
  const pb::Variable *it = Param(before, 0);
  ASSERT_NE(it, nullptr);

  // This function only: next, kind, tag, total, and &total passed to mark.
  pb::AutoStructureResponse local;
  ASSERT_TRUE(Auto(walk, it->storage_key(), pb::AUTO_STRUCTURE_MODE_CREATE, local, 0).ok());
  auto f = ByOffset(local);
  EXPECT_TRUE(f.contains(0) && f.contains(0xc) && f.contains(0xe) && f.contains(0x18)) << local.c_definition();
  EXPECT_FALSE(f.contains(8)) << local.c_definition();
  EXPECT_EQ(local.name(), "astruct");
  EXPECT_EQ(local.named_key(), "struct astruct");
  if (f.contains(0)) EXPECT_EQ(f[0]->type_display(), "undefined1 *");  // Ghidra's undefined *
  if (f.contains(0x18)) EXPECT_EQ(f[0x18]->name(), "field_0x18");
  bool passed = false;
  for (const auto &a : local.accesses())
    passed |= a.kind() == pb::POINTER_ACCESS_KIND_PASSED && a.callee().offset() == functions_.at("bump");
  EXPECT_TRUE(passed);

  // Into bump (depth 1, the default): count and weight too.
  pb::AutoStructureResponse r;
  ASSERT_TRUE(Auto(walk, it->storage_key(), pb::AUTO_STRUCTURE_MODE_CREATE, r).ok());
  f = ByOffset(r);
  ASSERT_TRUE(f.contains(8) && f.contains(0x10)) << r.c_definition();
  EXPECT_EQ(f[8]->size(), 4u);
  EXPECT_EQ(f[0x10]->size(), 8u);
  EXPECT_EQ(f[0x10]->type_display(), "double") << r.c_definition();
  EXPECT_EQ(r.size(), 0x20u);
  for (const auto &[off, field] : f)
    EXPECT_TRUE(off == 0 || off == 8 || off == 0xc || off == 0xe || off == 0x10 || off == 0x18) << off << "\n" << r.c_definition();
  EXPECT_EQ(r.functions_size(), 3);  // walk, bump, and mark (&it->total)
  EXPECT_EQ(r.nodes(r.struct_index()).kind(), pb::TYPE_KIND_STRUCT);
  EXPECT_EQ(r.nodes(r.pointer_index()).kind(), pb::TYPE_KIND_POINTER);

  // Applied: one request, the variable typed, the name bound; undone.
  auto done = Apply(r, RetypeLocal(walk, it->storage_key(), r.pointer_hash()));
  pb::DecompiledFunction after = Decompile(walk);
  ASSERT_NE(Param(after, 0), nullptr);
  EXPECT_EQ(Param(after, 0)->type().display(), "struct astruct *");
  EXPECT_EQ(Param(after, 0)->type().hash(), r.pointer_hash());
  // The parameter is type-locked, so the body reads and writes its fields
  // (kind, tag, total), not offsets from an untyped pointer.
  EXPECT_EQ(before.text().find("->field_"), std::string::npos) << before.text();
  for (const char *field : {"->field_0xc", "->field_0xe", "->field_0x18"})
    EXPECT_NE(after.text().find(field), std::string::npos) << field << "\n" << after.text();
  pb::FindTypesRequest ft;
  ft.set_program_id(id_);
  ft.set_name_contains("astruct");
  pb::FindTypesResponse found;
  ASSERT_TRUE(backend_->FindTypes(ctx_, ft, found).ok());
  EXPECT_GE(found.types_size(), 1);

  // A second structure gets the next name.
  pb::AutoStructureResponse again;
  ASSERT_TRUE(Auto(functions_.at("bump"), "param:0", pb::AUTO_STRUCTURE_MODE_CREATE, again).ok());
  EXPECT_EQ(again.name(), "astruct_1");
  // A name the program has is refused.
  pb::AutoStructureResponse taken;
  EXPECT_EQ(Auto(walk, it->storage_key(), pb::AUTO_STRUCTURE_MODE_CREATE, taken, 1, "astruct").code, StatusCode::kAlreadyExists);

  Undo(done);
  after = Decompile(walk);
  EXPECT_EQ(Param(after, 0)->type().display(), it->type().display());
  EXPECT_EQ(after.text(), before.text());
}

// The preview's edits (feature auto-struct-edit): a field renamed and
// retyped, one removed, one added in filler; a retype that runs into the
// next field, a bad name and a name used twice are refused per field while
// the rest apply; the applied structure has the edits.
TEST_F(AutoStructTest, EditsRenameRetypeRemoveAndAddFieldsAndRefuseWhatDoesntFit) {
  const std::uint64_t walk = functions_.at("walk");
  const pb::DecompiledFunction before = Decompile(walk);
  const pb::Variable *it = Param(before, 0);
  ASSERT_NE(it, nullptr);
  pb::AutoStructureRequest req;
  req.set_program_id(id_);
  req.mutable_variable()->mutable_function()->set_offset(walk);
  req.mutable_variable()->set_storage_key(it->storage_key());
  req.set_mode(pb::AUTO_STRUCTURE_MODE_CREATE);
  req.set_name("item_edit");
  auto edit = [&](std::uint64_t off) {
    auto *e = req.add_edits();
    e->set_offset(off);
    return e;
  };
  // 0x8 count: renamed and retyped (int -> unsigned int).
  auto *e = edit(8);
  e->set_name("count");
  e->set_type_c("unsigned int");
  // 0xc kind: a declaration names it too.
  edit(0xc)->set_type_c("short kind");
  // 0xe tag: grown to 4 bytes runs into weight at 0x10: refused.
  edit(0xe)->set_type_c("int");
  // 0x18: removed; then added back as a long named total.
  edit(0x18)->set_remove(true);
  e = edit(0x18);
  e->set_add(true);
  e->set_name("total");
  e->set_type_c("long");
  // Refused: a name that isn't C, a name used twice, a type that doesn't parse, nothing at 0x4.
  edit(0)->set_name("1next");
  edit(0x10)->set_name("count");
  edit(0x10)->set_type_c("struct nope_t_xyz");
  edit(4)->set_name("nothing");

  pb::AutoStructureResponse r;
  auto st = backend_->AutoStructure(ctx_, req, r);
  ASSERT_TRUE(st.ok()) << st.message;
  auto f = ByOffset(r);
  ASSERT_TRUE(f.contains(8) && f.contains(0xc) && f.contains(0xe) && f.contains(0x18)) << r.c_definition();
  EXPECT_EQ(f[8]->name(), "count");
  EXPECT_EQ(f[8]->type_display(), "unsigned int");
  EXPECT_TRUE(f[8]->edited());
  EXPECT_EQ(f[0xc]->name(), "kind");
  EXPECT_EQ(f[0xc]->type_display(), "short");
  EXPECT_EQ(f[0xe]->size(), 1u) << "the retype into weight is left out";
  EXPECT_FALSE(f[0xe]->edited());
  EXPECT_EQ(f[0x18]->name(), "total");
  EXPECT_EQ(f[0x18]->type_display(), "long");
  EXPECT_EQ(f[0]->name(), "field_0x0");
  EXPECT_EQ(r.size(), 0x20u);
  std::map<std::uint64_t, std::string> errors;
  for (const auto &x : r.field_errors()) errors[x.offset()] += x.message() + ";";
  EXPECT_NE(errors[0xe].find("runs into"), std::string::npos) << errors[0xe];
  EXPECT_NE(errors[0xe].find("0x10"), std::string::npos) << errors[0xe];
  EXPECT_NE(errors[0].find("not a C name"), std::string::npos) << errors[0];
  EXPECT_NE(errors[0x10].find("named count"), std::string::npos) << errors[0x10];
  EXPECT_NE(errors[0x10].find("has no size"), std::string::npos) << errors[0x10];  // an unknown struct is incomplete
  EXPECT_NE(errors[4].find("no field"), std::string::npos) << errors[4];
  EXPECT_EQ(errors.size(), 4u);

  // A removed field is filler: nothing at 0x18 without the add.
  pb::AutoStructureRequest rm = req;
  rm.clear_edits();
  rm.add_edits()->set_offset(0x18);
  rm.mutable_edits(0)->set_remove(true);
  pb::AutoStructureResponse removed;
  ASSERT_TRUE(backend_->AutoStructure(ctx_, rm, removed).ok());
  EXPECT_FALSE(ByOffset(removed).contains(0x18)) << removed.c_definition();
  EXPECT_EQ(removed.field_errors_size(), 0);

  // Applied: the decompiler reads the edited names and types.
  auto done = Apply(r, RetypeLocal(walk, it->storage_key(), r.pointer_hash()));
  const pb::DecompiledFunction after = Decompile(walk);
  EXPECT_EQ(Param(after, 0)->type().display(), "struct item_edit *");
  EXPECT_NE(after.text().find("->kind"), std::string::npos) << after.text();
  EXPECT_NE(after.text().find("->total"), std::string::npos) << after.text();
  Undo(done);
}

// A parameter typed in a function nothing gave a prototype (no debug
// info, no inference) locks only the inputs: the return stays the
// decompiler's, so the code computing it stays (it was a locked void, and
// sum2's body became `return;`). The same for Auto create structure's
// retype of the parameter, and for a prototype whose return is Ghidra's
// DEFAULT type ("undefined": Edit Function with the return left as it is).
TEST_F(AutoStructTest, ATypedParameterLeavesTheReturnToTheDecompiler) {
  ASSERT_TRUE(functions_.contains("sum2"));
  const std::uint64_t sum2 = functions_.at("sum2");
  const pb::DecompiledFunction before = Decompile(sum2);
  const pb::Variable *it = Param(before, 0);
  ASSERT_NE(it, nullptr);
  ASSERT_NE(before.text().find("return"), std::string::npos) << before.text();
  ASSERT_NE(before.text().find(" + "), std::string::npos) << before.text();
  auto keeps_return = [&](const std::string &what) {
    const pb::DecompiledFunction f = Decompile(sum2);
    EXPECT_NE(f.prototype().return_type().display(), "void") << what << "\n" << f.text();
    EXPECT_NE(f.text().find(" + "), std::string::npos) << what << ": the sum is gone\n" << f.text();
    EXPECT_EQ(f.text().find("return;"), std::string::npos) << what << "\n" << f.text();
    for (const auto &w : f.warnings()) EXPECT_EQ(w.find("Unknown calling convention"), std::string::npos) << what << ": " << w;
    return f;
  };
  // Auto create structure, applied: the parameter is a struct pointer.
  pb::AutoStructureResponse r;
  ASSERT_TRUE(Auto(sum2, it->storage_key(), pb::AUTO_STRUCTURE_MODE_CREATE, r, 0, "sum2_t").ok());
  auto applied = Apply(r, RetypeLocal(sum2, it->storage_key(), r.pointer_hash()));
  const pb::DecompiledFunction typed = keeps_return("auto-struct");
  EXPECT_EQ(Param(typed, 0)->type().display(), "struct sum2_t *");
  Undo(applied);
  // A plain retype of the parameter (Set type on param_1).
  pb::AppendAssertionsRequest req;
  req.set_program_id(id_);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  auto *rt = req.add_assertions()->mutable_body()->mutable_retype();
  rt->mutable_target()->mutable_local()->mutable_function()->set_offset(sum2);
  rt->mutable_target()->mutable_local()->set_storage_key(it->storage_key());
  rt->mutable_type()->set_c_declaration("short *");
  pb::AppendAssertionsResponse retyped;
  auto st = backend_->AppendAssertions(ctx_, req, retyped);
  ASSERT_TRUE(st.ok()) << st.message;
  keeps_return("retype param_1");
  Undo(retyped);
  // A prototype with the return undefined: the decompiler's return, the
  // parameters as declared.
  pb::AppendAssertionsRequest preq;
  preq.set_program_id(id_);
  preq.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  auto *pr = preq.add_assertions()->mutable_body()->mutable_retype();
  pr->mutable_target()->mutable_address()->set_offset(sum2);
  pr->mutable_type()->set_c_declaration("undefined sum2(char *p)");
  pb::AppendAssertionsResponse proto;
  st = backend_->AppendAssertions(ctx_, preq, proto);
  ASSERT_TRUE(st.ok()) << st.message;
  const pb::DecompiledFunction undef = keeps_return("undefined return");
  EXPECT_NE(undef.text().find("char *p"), std::string::npos) << undef.text();
  Undo(proto);
  EXPECT_EQ(Decompile(sum2).text(), before.text());
}

// Chained structures (feature auto-struct-edit): a field of a structure the
// code reads a pointer from becomes a pointer to a structure made from what
// is read through it (it->next->count), one level and then the next
// (it->next->next->tag), each applied as one request with the outer
// structure's next version; a field too small for a pointer and one nothing
// reads through are refused.
TEST_F(AutoStructTest, ChainsStructuresThroughFieldsTwoLevelsDeep) {
  ASSERT_TRUE(functions_.contains("deep"));
  const std::uint64_t deep = functions_.at("deep");
  const pb::DecompiledFunction before = Decompile(deep);
  const pb::Variable *it = Param(before, 0);
  ASSERT_NE(it, nullptr);
  const std::string key = it->storage_key();
  // The outer structure from deep's own accesses: next at 0.
  pb::AutoStructureResponse outer;
  ASSERT_TRUE(Auto(deep, key, pb::AUTO_STRUCTURE_MODE_CREATE, outer, 0, "chain_a").ok());
  ASSERT_TRUE(ByOffset(outer).contains(0)) << outer.c_definition();
  auto a1 = Apply(outer, RetypeLocal(deep, key, outer.pointer_hash()));

  auto field = [&](const std::string &hash, std::uint64_t off, const std::string &base, const std::string &name, pb::AutoStructureResponse &r,
                   const std::vector<pb::AutoStructureFieldEdit> &edits = {}) {
    pb::AutoStructureRequest req;
    for (const auto &e : edits) *req.add_edits() = e;
    req.set_program_id(id_);
    auto *f = req.mutable_field();
    f->mutable_function()->set_offset(deep);
    f->set_struct_hash(hash);
    f->set_offset(off);
    f->set_base_storage_key(base);
    req.set_mode(pb::AUTO_STRUCTURE_MODE_CREATE);
    req.set_call_depth(0);
    req.set_name(name);
    return backend_->AutoStructure(ctx_, req, r);
  };
  // Level one: it->next (at 0) holds a pointer; through it, next (0) and count (8).
  pb::AutoStructureResponse b;
  auto st = field(outer.struct_hash(), 0, key, "chain_b", b);
  ASSERT_TRUE(st.ok()) << st.message;
  auto fb = ByOffset(b);
  ASSERT_TRUE(fb.contains(0) && fb.contains(8)) << b.c_definition();
  EXPECT_EQ(fb[8]->size(), 4u);
  ASSERT_TRUE(b.has_outer_index());
  EXPECT_EQ(b.outer_named_key(), "struct chain_a");
  EXPECT_EQ(b.nodes(b.outer_index()).kind(), pb::TYPE_KIND_STRUCT);
  auto a2 = Apply(b, {});
  std::string text = Decompile(deep).text();
  EXPECT_NE(text.find("->field_0x0->field_0x8"), std::string::npos) << text;

  // Level two: it->next->next (chain_b at 0, read through param->0x0): tag
  // at 0xe; an edit adds a pointer-sized field at 0 nothing reads through.
  pb::AutoStructureResponse c;
  pb::AutoStructureFieldEdit spare;
  spare.set_offset(0);
  spare.set_add(true);
  spare.set_name("spare");
  spare.set_type_c("void *");
  st = field(b.struct_hash(), 0, key + "->0x0", "chain_c", c, {spare});
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_TRUE(ByOffset(c).contains(0xe)) << c.c_definition();
  EXPECT_EQ(c.outer_named_key(), "struct chain_b");
  auto a3 = Apply(c, {});
  text = Decompile(deep).text();
  EXPECT_NE(text.find("->field_0x0->field_0x0->field_0xe"), std::string::npos) << text;
  // Without naming the base: every variable that points to chain_a (the parameter).
  pb::AutoStructureResponse any;
  st = field(outer.struct_hash(), 0, "", "chain_d", any);
  EXPECT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(ByOffset(any).contains(8)) << any.c_definition();
  // chain_b is only a field's value: no variable points to it.
  EXPECT_EQ(field(b.struct_hash(), 0, "", "chain_d", any).code, StatusCode::kFailedPrecondition);

  // Refused: count is 4 bytes; nothing is read through chain_c's tag.
  pb::AutoStructureResponse small;
  st = field(b.struct_hash(), 8, key + "->0x0", "", small);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition);
  EXPECT_NE(st.message.find("too small for a pointer"), std::string::npos) << st.message;
  pb::AutoStructureResponse none;
  st = field(c.struct_hash(), 0, key + "->0x0->0x0", "", none);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition) << st.message;
  EXPECT_NE(st.message.find("isn't used as a pointer"), std::string::npos) << st.message;

  Undo(a3);
  Undo(a2);
  Undo(a1);
  EXPECT_EQ(Decompile(deep).text(), before.text());
}

// A local retyped to a structure pointer is type-locked too, by every path
// a client has: Auto create structure on the local (one request), and Set
// type by a C declaration naming the structure; the body reads the fields
// through it. Undone, the code is as it was.
TEST_F(AutoStructTest, RetypedLocalsAreTypedInTheBody) {
  const std::uint64_t chain = functions_.at("chain");
  const pb::DecompiledFunction before = Decompile(chain);
  EXPECT_EQ(before.text().find("->"), std::string::npos) << before.text();
  // n: the pointer-sized local the loop walks (kind at 0xc, total at 0x18).
  std::string key;
  pb::AutoStructureResponse r;
  for (const auto &v : before.variables()) {
    if (v.kind() != pb::VARIABLE_KIND_LOCAL) continue;
    pb::AutoStructureResponse made;
    if (!Auto(chain, v.storage_key(), pb::AUTO_STRUCTURE_MODE_CREATE, made, 0).ok()) continue;
    auto f = ByOffset(made);
    if (f.contains(0xc) && f.contains(0x18)) {
      key = v.storage_key();
      r = made;
      break;
    }
  }
  ASSERT_FALSE(key.empty()) << before.text();
  EXPECT_TRUE(key.starts_with("register:")) << key;

  auto done = Apply(r, RetypeLocal(chain, key, r.pointer_hash()));
  pb::DecompiledFunction after = Decompile(chain);
  for (const char *field : {"->field_0xc", "->field_0x18"})
    EXPECT_NE(after.text().find(field), std::string::npos) << field << "\n" << after.text();
  const pb::Variable *n = nullptr;
  for (const auto &v : after.variables())
    if (v.storage_key() == key) n = &v;
  ASSERT_NE(n, nullptr) << "the local keeps its key\n" << after.text();
  EXPECT_EQ(n->type().hash(), r.pointer_hash());
  Undo(done);
  EXPECT_EQ(Decompile(chain).text(), before.text());

  // Set type by C declaration, once the structure exists: the same.
  pb::AutoStructureResponse s;
  ASSERT_TRUE(Auto(functions_.at("walk"), "param:0", pb::AUTO_STRUCTURE_MODE_CREATE, s).ok());
  auto made = Apply(s, RetypeLocal(functions_.at("walk"), "param:0", s.pointer_hash()));
  pb::AssertionBody typed;
  auto *l = typed.mutable_retype()->mutable_target()->mutable_local();
  l->mutable_function()->set_offset(chain);
  l->set_storage_key(key);
  typed.mutable_retype()->mutable_type()->set_c_declaration("struct astruct *");
  auto retyped = Apply(pb::AutoStructureResponse(), typed);
  after = Decompile(chain);
  for (const char *field : {"->field_0xc", "->field_0x18"})
    EXPECT_NE(after.text().find(field), std::string::npos) << field << "\n" << after.text();
  Undo(retyped);
  Undo(made);
  EXPECT_EQ(Decompile(chain).text(), before.text());
}

// Over a prototype the user locked (a C declaration): the parameter's
// type replaces the one there, and calls to it are typed by it too.
TEST_F(AutoStructTest, ParameterRetypeOverALockedPrototype) {
  const std::uint64_t walk = functions_.at("walk");
  pb::AutoStructureResponse r;
  ASSERT_TRUE(Auto(walk, "param:0", pb::AUTO_STRUCTURE_MODE_CREATE, r).ok());
  pb::AssertionBody proto;
  proto.mutable_retype()->mutable_target()->mutable_address()->set_offset(walk);
  proto.mutable_retype()->mutable_type()->set_c_declaration("long walk(long *it)");
  auto locked = Apply(pb::AutoStructureResponse(), proto);
  const pb::DecompiledFunction before = Decompile(walk);
  EXPECT_NE(before.text().find("long *it"), std::string::npos) << before.text();
  EXPECT_EQ(before.text().find("->"), std::string::npos) << before.text();
  auto done = Apply(r, RetypeLocal(walk, "param:0", r.pointer_hash()));
  const pb::DecompiledFunction after = Decompile(walk);
  for (const char *field : {"->field_0xc", "->field_0x18"})
    EXPECT_NE(after.text().find(field), std::string::npos) << field << "\n" << after.text();
  EXPECT_NE(after.text().find("astruct *it"), std::string::npos) << after.text();
  EXPECT_NE(Decompile(functions_.at("main")).text().find("astruct"), std::string::npos)
      << Decompile(functions_.at("main")).text();
  Undo(done);
  EXPECT_EQ(Decompile(walk).text(), before.text());
  Undo(locked);
}

// A temporary (a unique-space local, which Ghidra maps by a hash of its
// p-code): committed by that hash, it is typed in the body too, and keeps
// its key.
TEST_F(AutoStructTest, RetypedTemporariesAreTypedInTheBody) {
  const std::uint64_t push = functions_.at("push");
  const pb::DecompiledFunction before = Decompile(push);
  std::string key;
  for (const auto &v : before.variables())
    if (v.kind() == pb::VARIABLE_KIND_LOCAL && v.storage_key().starts_with("unique:")) key = v.storage_key();
  ASSERT_FALSE(key.empty()) << before.text();
  pb::AutoStructureResponse r;
  ASSERT_TRUE(Auto(push, key, pb::AUTO_STRUCTURE_MODE_CREATE, r, 0).ok());
  ASSERT_TRUE(ByOffset(r).contains(0xe)) << r.c_definition();
  auto done = Apply(r, RetypeLocal(push, key, r.pointer_hash()));
  pb::DecompiledFunction after = Decompile(push);
  EXPECT_NE(after.text().find("->field_0xe"), std::string::npos) << after.text();
  bool kept = false;
  for (const auto &v : after.variables()) kept |= v.storage_key() == key && v.type().hash() == r.pointer_hash();
  EXPECT_TRUE(kept) << after.text();
  Undo(done);
  EXPECT_EQ(Decompile(push).text(), before.text());
}

// A stack local, unoptimized: the slot is committed with the type, so the
// loads and stores through it read the fields.
TEST_F(AutoStructTest, RetypedStackLocalsAreTypedInTheBody) {
  if (!compiled0_) GTEST_SKIP() << "no -O0 build";
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path(exe0_.string());
  pb::ImportProgramResponse resp;
  ASSERT_TRUE(backend_->ImportProgram(ctx_, req, resp).ok());
  id_ = resp.program().program_id();
  pb::ListFunctionsRequest fr;
  fr.set_program_id(id_);
  pb::ListFunctionsResponse fs;
  ASSERT_TRUE(backend_->ListFunctions(ctx_, fr, fs).ok());
  std::uint64_t chain = 0;
  for (const auto &f : fs.functions())
    if (f.name() == "chain") chain = f.entry().offset();
  ASSERT_NE(chain, 0u);

  const pb::DecompiledFunction before = Decompile(chain);
  const pb::Variable *n = nullptr;
  for (const auto &v : before.variables())
    if (v.kind() == pb::VARIABLE_KIND_LOCAL && v.storage_key().starts_with("stack:") && v.storage_size() == 1 &&
        v.storage(0).size() == 8) {
      pb::AutoStructureResponse made;
      if (Auto(chain, v.storage_key(), pb::AUTO_STRUCTURE_MODE_CREATE, made, 0).ok() && ByOffset(made).contains(0x18)) n = &v;
    }
  ASSERT_NE(n, nullptr) << before.text();
  pb::AutoStructureResponse r;
  ASSERT_TRUE(Auto(chain, n->storage_key(), pb::AUTO_STRUCTURE_MODE_CREATE, r, 0).ok());
  auto done = Apply(r, RetypeLocal(chain, n->storage_key(), r.pointer_hash()));
  pb::DecompiledFunction after = Decompile(chain);
  for (const char *field : {"->field_0xc", "->field_0x18"})
    EXPECT_NE(after.text().find(field), std::string::npos) << field << "\n" << after.text();
  bool kept = false;
  for (const auto &v : after.variables()) kept |= v.storage_key() == n->storage_key() && v.type().hash() == r.pointer_hash();
  EXPECT_TRUE(kept) << after.text();
  Undo(done);
  EXPECT_EQ(Decompile(chain).text(), before.text());
}

TEST_F(AutoStructTest, FillsInTheStructureAVariablePointsTo) {
  const std::uint64_t walk = functions_.at("walk"), bump = functions_.at("bump");
  pb::AutoStructureResponse first;
  ASSERT_TRUE(Auto(walk, "param:0", pb::AUTO_STRUCTURE_MODE_CREATE, first, 0).ok());
  auto made = Apply(first, RetypeLocal(walk, "param:0", first.pointer_hash()));

  // FILL needs a struct pointer.
  pb::AutoStructureResponse refused;
  EXPECT_EQ(Auto(bump, "param:0", pb::AUTO_STRUCTURE_MODE_FILL, refused).code, StatusCode::kFailedPrecondition);

  // bump's parameter typed as the same struct: filling in adds count and
  // weight and keeps the rest.
  auto typed = Apply(pb::AutoStructureResponse(), RetypeLocal(bump, "param:0", first.pointer_hash()));
  pb::AutoStructureResponse fill;
  ASSERT_TRUE(Auto(bump, "param:0", pb::AUTO_STRUCTURE_MODE_FILL, fill).ok());
  EXPECT_EQ(fill.existing_hash(), first.struct_hash());
  EXPECT_EQ(fill.named_key(), "struct astruct");
  EXPECT_FALSE(fill.unchanged());
  auto f = ByOffset(fill);
  ASSERT_TRUE(f.contains(8) && f.contains(0x10)) << fill.c_definition();
  EXPECT_EQ(f[8]->source(), pb::AUTO_STRUCTURE_FIELD_SOURCE_ACCESS);
  ASSERT_TRUE(f.contains(0));
  EXPECT_EQ(f[0]->source(), pb::AUTO_STRUCTURE_FIELD_SOURCE_EXISTING);
  EXPECT_EQ(fill.fields_size(), first.fields_size() + 2);
  EXPECT_EQ(fill.size(), first.size());

  // Applied: the name is bound to the filled-in definition, so walk's
  // variable (typed by the first hash) shows it too.
  auto filled = Apply(fill, RetypeLocal(bump, "param:0", fill.pointer_hash()));
  pb::GetTypesRequest gt;
  gt.set_program_id(id_);
  gt.add_hashes(fill.struct_hash());
  pb::GetTypesResponse types;
  ASSERT_TRUE(backend_->GetTypes(ctx_, gt, types).ok());
  ASSERT_EQ(types.types_size(), 1);
  EXPECT_TRUE(types.types(0).bound());

  // Again: nothing new.
  pb::AutoStructureResponse same;
  ASSERT_TRUE(Auto(bump, "param:0", pb::AUTO_STRUCTURE_MODE_FILL, same).ok());
  EXPECT_TRUE(same.unchanged());
  Undo(filled);
  Undo(typed);
  Undo(made);
}

TEST_F(AutoStructTest, CreatesAStructureFromTheDataInARangeAndDefinesIt) {
  pb::ListSymbolsRequest sr;
  sr.set_program_id(id_);
  sr.set_name_equals("config");
  pb::ListSymbolsResponse syms;
  ASSERT_TRUE(backend_->ListSymbols(ctx_, sr, syms).ok());
  ASSERT_EQ(syms.symbols_size(), 1);
  const std::uint64_t config = syms.symbols(0).address().offset();

  // An int and a short defined in it; the rest stays undefined.
  pb::AppendAssertionsRequest dr;
  dr.set_program_id(id_);
  dr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  for (auto [at, type] : {std::pair<std::uint64_t, const char *>{config, "int"}, {config + 4, "short"}}) {
    auto *b = dr.add_assertions()->mutable_body()->mutable_listing_edit();
    b->mutable_address()->set_offset(at);
    b->mutable_data()->mutable_type()->set_c_declaration(type);
  }
  pb::AppendAssertionsResponse defined;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, dr, defined).ok());

  pb::AutoStructureRequest req;
  req.set_program_id(id_);
  req.mutable_range()->mutable_first()->set_offset(config);
  req.mutable_range()->mutable_last()->set_offset(config + 15);
  req.set_name("conf_t");
  pb::AutoStructureResponse r;
  auto st = backend_->AutoStructure(ctx_, req, r);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(r.size(), 16u);
  auto f = ByOffset(r);
  ASSERT_EQ(r.fields_size(), 2) << r.c_definition();
  EXPECT_EQ(f[0]->type_display(), "int");
  EXPECT_EQ(f[4]->type_display(), "short");
  EXPECT_EQ(f[4]->source(), pb::AUTO_STRUCTURE_FIELD_SOURCE_DATA);

  pb::AssertionBody data;
  data.mutable_listing_edit()->mutable_address()->set_offset(config);
  data.mutable_listing_edit()->mutable_data()->mutable_type()->set_type_hash(r.struct_hash());
  auto done = Apply(r, data);
  pb::GetListingRequest lr;
  lr.set_program_id(id_);
  lr.mutable_addresses()->mutable_start()->set_offset(config);
  lr.mutable_addresses()->set_max_rows(2);
  pb::GetListingResponse rows;
  ASSERT_TRUE(backend_->GetListing(ctx_, lr, rows).ok());
  ASSERT_GE(rows.rows_size(), 1);
  EXPECT_EQ(rows.rows(0).data_type(), "struct conf_t");
  EXPECT_EQ(rows.rows(0).data_components(), 2u);

  Undo(done);
  pb::GetListingResponse undone;
  ASSERT_TRUE(backend_->GetListing(ctx_, lr, undone).ok());
  EXPECT_EQ(undone.rows(0).data_type(), "int");

  // FILL and an empty name are for variables.
  req.set_mode(pb::AUTO_STRUCTURE_MODE_FILL);
  EXPECT_EQ(backend_->AutoStructure(ctx_, req, r).code, StatusCode::kInvalidArgument);
}

TEST_F(AutoStructTest, RefusesWhatIsntThere) {
  pb::AutoStructureResponse r;
  EXPECT_EQ(Auto(functions_.at("walk") + 1, "param:0", pb::AUTO_STRUCTURE_MODE_CREATE, r).code, StatusCode::kNotFound);
  EXPECT_EQ(Auto(functions_.at("walk"), "stack:-0x9999", pb::AUTO_STRUCTURE_MODE_CREATE, r).code, StatusCode::kNotFound);
  EXPECT_EQ(Auto(functions_.at("walk"), "param:0", pb::AUTO_STRUCTURE_MODE_CREATE, r, 9).code, StatusCode::kInvalidArgument);
  pb::AutoStructureRequest none;
  none.set_program_id(id_);
  EXPECT_EQ(backend_->AutoStructure(ctx_, none, r).code, StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace revkit::backend
