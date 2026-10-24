// The image backend on the fact store: what an edit recomputes, what a
// reopened project keeps, DWARF prototypes reaching the decompiler, and the
// revert rule. Counters come from the fact engine (QueryCounters).
#include "builders.hh"
#include "type_record.h"

#include "revkit/backend/image_backend.h"
#include "revkit/debuginfo/dwarf.h"
#include "revkit/debuginfo/pdb.h"
#include "revkit/facts/engine.h"
#include "revkit/facts/storage.h"
#include "revkit/loader/load.hh"
#include "revkit/types/print.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <chrono>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;

constexpr const char *kProgram = R"(
#include <stdio.h>
int counter;
struct buffer { const unsigned char *data; long length; };
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return h;
}
__attribute__((noinline)) unsigned buffer_checksum(const struct buffer *b) { return checksum(b->data, (int)b->length); }
__attribute__((noinline)) int twice(int x) { return checksum((const unsigned char *)&x, 4) * 2; }
__attribute__((noinline)) int lonely(int x) { return x * 7 + counter; }
int main(int argc, char **argv) {
  struct buffer b = {(const unsigned char *)argv[0], argc};
  printf("%u %d %u %d\n", checksum(b.data, argc), twice(argc), buffer_checksum(&b), lonely(argc));
  return 0;
}
)";

// Two functions discovery can't find on its own once the binary is
// stripped: no symbol, no unwind entry (no CFI), and only a pointer that
// main stores reaches cb_outer. They sit in a 256-byte span of their own.
constexpr const char *kHidden = R"(
#include <stdio.h>
__asm__(".text\n"
        ".p2align 8\n"
        ".globl cb_outer\n"
        ".type cb_outer, @function\n"
        "cb_outer:\n"
        "  call cb_inner\n"
        "  add $1, %eax\n"
        "  ret\n"
        ".p2align 4\n"
        ".globl cb_inner\n"
        ".type cb_inner, @function\n"
        "cb_inner:\n"
        "  lea 7(%rdi), %eax\n"
        "  ret\n"
        ".p2align 8\n");
int cb_outer(int);
int (*volatile hook)(int);
__attribute__((noinline)) void set_hook(int (*f)(int)) { hook = f; }
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  return h;
}
__attribute__((noinline)) int twice(int x) { return checksum((const unsigned char *)&x, 4) * 2; }
int main(int argc, char **argv) {
  set_hook(cb_outer);
  printf("%d %u %d\n", hook(argc), checksum((const unsigned char *)argv[0], argc), twice(argc));
  return 0;
}
)";

class Sink : public api::EventSink {
 public:
  void Send(pb::SubscribeResponse event) override {
    std::lock_guard lock(mu_);
    if (event.has_revision()) revisions_.push_back(event.revision());
  }
  void End(api::Status) override {}
  std::vector<pb::RevisionEvent> revisions() {
    std::lock_guard lock(mu_);
    return revisions_;
  }

 private:
  std::mutex mu_;
  std::vector<pb::RevisionEvent> revisions_;
};

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

// Ghidra's default name for a function.
std::string FormatName(std::uint64_t entry) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "FUN_%08llx", static_cast<unsigned long long>(entry));
  return buf;
}

std::string NoSpace(std::string s) {
  std::erase_if(s, [](unsigned char c) { return std::isspace(c); });
  return s;
}

class FactStoreTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("fact-store");
    plain_ = dir / "prog";
    debug_ = dir / "prog-g";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1", plain_) &&
                testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g", debug_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
  }

  static std::unique_ptr<api::Backend> Make(const std::string &project_dir = {}) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir;
    return MakeImageBackend(o);
  }

  std::string Import(api::Backend &b, const fs::path &path) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    pb::ImportProgramResponse resp;
    auto st = b.ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::map<std::string, std::uint64_t> Functions(api::Backend &b, const std::string &program) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(b.ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  pb::DecompiledFunction Decompile(api::Backend &b, const std::string &program, std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(program);
    req.mutable_function()->set_offset(entry);
    pb::DecompileResponse resp;
    auto st = b.Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  pb::AppendAssertionsResponse Append(api::Backend &b, const std::string &program, const pb::AssertionBody &body,
                                      const std::string &actor = "alice",
                                      pb::ProvenanceKind kind = pb::PROVENANCE_KIND_USER) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.mutable_provenance()->set_kind(kind);
    req.mutable_provenance()->set_id(actor);
    *req.add_assertions()->mutable_body() = body;
    pb::AppendAssertionsResponse resp;
    auto st = b.AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static pb::AssertionBody Rename(std::uint64_t addr, const std::string &name) {
    pb::AssertionBody body;
    body.mutable_rename()->mutable_target()->mutable_address()->set_offset(addr);
    body.mutable_rename()->set_name(name);
    return body;
  }

  // Decompiles every function, recording which ones the fact engine
  // computed afresh rather than validating a memo.
  std::set<std::uint64_t> Recomputed(api::Backend &b, const std::string &program, const std::vector<std::uint64_t> &fns) {
    std::set<std::uint64_t> out;
    for (std::uint64_t f : fns) {
      ResetQueryCounters(b, "default");
      Decompile(b, program, f);
      if (QueryCounters(b, "default").at("decompile.ghidra").executions > 0) out.insert(f);
    }
    return out;
  }

  // Functions whose decompilation names `target` (a call or a reference).
  static bool Names(const pb::DecompiledFunction &f, std::uint64_t target) {
    for (const auto &line : f.lines())
      for (const auto &t : line.tokens())
        if (t.has_target() && t.target().offset() == target) return true;
    return false;
  }

  static inline fs::path plain_, debug_;
  static inline bool compiled_ = false;
  // Until nothing is queued or running in the background for the program.
  pb::GetAnalysisStatusResponse Settle(api::Backend &b, const std::string &program) {
    pb::GetAnalysisStatusRequest req;
    req.set_program_id(program);
    pb::GetAnalysisStatusResponse resp;
    const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(3);
    do {
      resp.Clear();
      EXPECT_TRUE(b.GetAnalysisStatus(ctx_, req, resp).ok());
      if (resp.idle()) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    } while (std::chrono::steady_clock::now() < until);
    EXPECT_TRUE(resp.idle());
    return resp;
  }

  CallContext ctx_;
};

// A rename re-decompiles exactly the functions whose decompilation looked
// the name up: the function itself and the ones that print it. Nothing
// else is recomputed: no discovery, rows, xrefs or other decompilations.
TEST_F(FactStoreTest, RenameRecomputesExactlyTheFunctionsThatReadTheName) {
  auto b = Make();
  std::string id = Import(*b, plain_);
  auto fns = Functions(*b, id);
  std::vector<std::uint64_t> all;
  for (const auto &[name, entry] : fns) all.push_back(entry);
  const std::uint64_t checksum = fns.at("checksum");

  std::set<std::uint64_t> expected{checksum};
  for (std::uint64_t f : all)
    if (Names(Decompile(*b, id, f), checksum)) expected.insert(f);
  ASSERT_TRUE(expected.contains(fns.at("main")) && expected.contains(fns.at("twice")) &&
              expected.contains(fns.at("buffer_checksum")));
  EXPECT_TRUE(Recomputed(*b, id, all).empty());  // all cached

  ResetQueryCounters(*b, "default");
  Append(*b, id, Rename(checksum, "fnv1a"));
  EXPECT_EQ(Recomputed(*b, id, all), expected);
  auto c = QueryCounters(*b, "default");
  for (const char *rule : {"analysis.functions", "analysis.flow", "listing.code", "listing.rows", "xrefs.function",
                           "xrefs.static", "names.default"})
    EXPECT_EQ(c.at(rule).executions, 0u) << rule;
  EXPECT_NE(Text(Decompile(*b, id, fns.at("main"))).find("fnv1a("), std::string::npos);

  // A function only main calls: itself and main, nothing else.
  const std::uint64_t lonely = fns.at("lonely");
  std::set<std::uint64_t> readers{lonely};
  for (std::uint64_t f : all)
    if (Names(Decompile(*b, id, f), lonely)) readers.insert(f);
  EXPECT_EQ(readers, (std::set<std::uint64_t>{lonely, fns.at("main")}));
  Append(*b, id, Rename(lonely, "solitary"));
  EXPECT_EQ(Recomputed(*b, id, all), readers);
}

// Comments and flow overrides reach only the function they are in; local
// names, local types and C-text prototypes are overlays and re-decompile
// nothing.
TEST_F(FactStoreTest, OtherEditsRecomputeOnlyWhatTheyAffect) {
  auto b = Make();
  std::string id = Import(*b, plain_);
  auto fns = Functions(*b, id);
  std::vector<std::uint64_t> all;
  for (const auto &[name, entry] : fns) all.push_back(entry);
  for (std::uint64_t f : all) Decompile(*b, id, f);
  const std::uint64_t twice = fns.at("twice");

  pb::AssertionBody comment;
  comment.mutable_comment()->mutable_address()->set_offset(twice);
  comment.mutable_comment()->set_kind(pb::COMMENT_KIND_PLATE);
  comment.mutable_comment()->set_text("doubles a checksum");
  Append(*b, id, comment);
  EXPECT_EQ(Recomputed(*b, id, all), std::set<std::uint64_t>{twice});
  EXPECT_NE(Text(Decompile(*b, id, twice)).find("doubles a checksum"), std::string::npos);

  // An end-of-line comment isn't shown by the decompiler: nothing reruns.
  comment.mutable_comment()->set_kind(pb::COMMENT_KIND_EOL);
  Append(*b, id, comment);
  EXPECT_TRUE(Recomputed(*b, id, all).empty());

  pb::AssertionBody local;
  local.mutable_rename()->mutable_target()->mutable_local()->mutable_function()->set_offset(twice);
  local.mutable_rename()->mutable_target()->mutable_local()->set_storage_key("param:0");
  local.mutable_rename()->set_name("value");
  Append(*b, id, local);
  EXPECT_TRUE(Recomputed(*b, id, all).empty());
  // C text the parser can't read stays an overlay (as all C text did
  // before revkit::cparse).
  pb::AssertionBody proto;
  proto.mutable_retype()->mutable_target()->mutable_address()->set_offset(twice);
  proto.mutable_retype()->mutable_type()->set_c_declaration("int twice(int value");
  Append(*b, id, proto);
  EXPECT_TRUE(Recomputed(*b, id, all).empty());
  pb::DecompiledFunction f = Decompile(*b, id, twice);
  EXPECT_EQ(f.prototype().c_declaration(), "int twice(int value");
  // One it reads is a hashed prototype: the function and those that
  // consulted it rerun, as for any h: prototype.
  proto.mutable_retype()->mutable_type()->set_c_declaration("int twice(int value)");
  Append(*b, id, proto);
  std::set<std::uint64_t> rerun = Recomputed(*b, id, all);
  EXPECT_TRUE(rerun.contains(twice));
  for (std::uint64_t g : rerun) EXPECT_TRUE(g == twice || Names(Decompile(*b, id, g), twice)) << std::hex << g;
  EXPECT_NE(Text(Decompile(*b, id, twice)).find("int value"), std::string::npos);
  EXPECT_NE(Text(f).find("value"), std::string::npos);
}

// Debug builds decompile with DWARF's signatures: names, parameter names
// and types as Ghidra's own DWARF import spells them.
// With ImageBackendOptions::infer_prototypes, functions nothing asserts a
// prototype for decompile with revkit::infer's: the same as infer gives
// them, in their own decompilation and at the calls to them. Inference
// runs after the import, in the background, as an analysis job; its
// prototypes reach the decompiler when it publishes them.
TEST_F(FactStoreTest, InferredPrototypesReachTheDecompiler) {
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;  // prog: x86-64 without debug info
  auto with = MakeImageBackend(o);
  auto without = Make();
  const std::string a = Import(*with, plain_), b = Import(*without, plain_);
  auto fns = Functions(*with, a);
  pb::GetAnalysisStatusResponse status = Settle(*with, a);
  const pb::AnalysisJob *job = nullptr;
  for (const pb::AnalysisJob &j : status.jobs())
    if (!j.analyzers().empty() && j.analyzers(0) == "infer.prototypes") job = &j;
  ASSERT_NE(job, nullptr);
  EXPECT_EQ(job->state(), pb::ANALYSIS_STATE_SUCCEEDED) << job->message();
  EXPECT_EQ(job->progress(), 1.0f);
  EXPECT_GT(job->last_revision(), job->first_revision());  // published in a revision of its own
  {
    // The function's prototype says where it came from.
    pb::GetFunctionRequest req;
    req.set_program_id(a);
    req.mutable_address()->set_offset(fns.at("checksum"));
    pb::GetFunctionResponse resp;
    ASSERT_TRUE(with->GetFunction(ctx_, req, resp).ok());
    EXPECT_EQ(NoSpace(resp.function().prototype()), "uintchecksum(uchar*param_1,intparam_2)");
    EXPECT_EQ(resp.function().prototype_origin().derived().rule(), "infer.prototypes");
  }
  const std::string inferred = NoSpace(Decompile(*with, a, fns.at("checksum")).prototype().c_declaration());
  const std::string local = NoSpace(Decompile(*without, b, fns.at("checksum")).prototype().c_declaration());
  // The decompiler alone sees a byte pointer; inference, from the callers
  // and the signature priors, the C type: the source's `unsigned char *`,
  // its loads typed by their movzx as the daemon's decompiler types them
  // (docs/infer.md, "Load types"; with Ghidra's use-based types, `char *`).
  EXPECT_EQ(local, "uintchecksum(byte*param_1,intparam_2)");
  EXPECT_EQ(inferred, "uintchecksum(uchar*param_1,intparam_2)");
  EXPECT_FALSE(Decompile(*with, a, fns.at("checksum")).prototype().origin().has_asserted());
  // Its caller passes what the inferred prototype says.
  const std::string twice = Text(Decompile(*with, a, fns.at("twice")));
  EXPECT_NE(twice.find("checksum((uchar *)"), std::string::npos) << twice;
}

// Inference's structures (docs/infer.md, "Structures"): a pointer passed
// on between functions points to one inferred structure, published as a
// program type in the analysis's revision (analysis:infer.prototypes,
// filed under /inferred), which the decompiler lays the pointer's
// accesses on (p->field_0x10). It is a program type like any other: an
// edit of it (a field renamed) reaches the decompilation, and reverting
// the analysis's assertions takes it away.
TEST_F(FactStoreTest, InferredStructuresArePublishedAsProgramTypes) {
  const fs::path exe = testing::scratch_dir("fact-store-structs") / "nodes";
  ASSERT_TRUE(testing::compile(REVKIT_TEST_CC, R"(
#include <stdio.h>
#include <stdlib.h>
struct node { int val; double w; struct node *next; unsigned char flag; };
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
int main(int argc, char **argv) {
  struct node *n = calloc(1, sizeof *n);
  node_mark(n, argc);
  printf("%f\n", node_sum(n));
  return 0;
}
)", "-O1", exe));
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;
  auto b = MakeImageBackend(o);
  const std::string id = Import(*b, exe);
  const auto fns = Functions(*b, id);
  Settle(*b, id);
  auto prototype = [&](const char *name) {
    pb::GetFunctionRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(fns.at(name));
    pb::GetFunctionResponse resp;
    EXPECT_TRUE(b->GetFunction(ctx_, req, resp).ok());
    return resp.function();
  };
  const std::string sum = prototype("node_sum").prototype();
  EXPECT_NE(sum.find("astruct_1 *"), std::string::npos) << sum;
  EXPECT_EQ(prototype("node_sum").prototype_origin().derived().rule(), "infer.prototypes");
  EXPECT_NE(prototype("node_mark").prototype().find("astruct_1 *"), std::string::npos);
  // The decompiler reads the fields.
  std::string c = Text(Decompile(*b, id, fns.at("node_sum")));
  EXPECT_NE(c.find("->field_0x10"), std::string::npos) << c;
  EXPECT_NE(c.find("->field_0x0"), std::string::npos) << c;
  // A program type, the analysis's, filed under /inferred.
  auto find = [&] {
    pb::FindTypesRequest req;
    req.set_program_id(id);
    req.set_name_contains("astruct_1");
    pb::FindTypesResponse resp;
    EXPECT_TRUE(b->FindTypes(ctx_, req, resp).ok());
    pb::TypeDefinition out;
    for (const auto &t : resp.types())
      if (t.name() == "astruct_1" && t.kind() == pb::TYPE_KIND_STRUCT && t.bound()) out = t;
    return out;
  };
  const pb::TypeDefinition def = find();
  ASSERT_FALSE(def.hash().empty());
  EXPECT_EQ(def.category(), "/inferred");
  EXPECT_EQ(def.origin().asserted().provenance().kind(), pb::PROVENANCE_KIND_ANALYSIS);
  EXPECT_EQ(def.origin().asserted().provenance().id(), "infer.prototypes");
  EXPECT_GE(def.size(), 0x19u);
  // The user renames field_0x0 (the struct's next version, bound to its
  // name): the decompilation shows it.
  {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    pb::TypeNode *t = req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
    t->set_kind(pb::TYPE_KIND_STRUCT);
    t->set_name("astruct_1");
    t->set_size(def.size());
    for (const auto &f : def.composite().fields()) {
      auto *nf = t->add_fields();
      nf->set_name(f.offset() == 0 ? "val" : f.name());
      nf->set_offset(f.offset());
      nf->mutable_type()->set_hash(f.type_hash());
    }
    req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(0);
    pb::AppendAssertionsResponse resp;
    auto st = b->AppendAssertions(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
  }
  c = Text(Decompile(*b, id, fns.at("node_sum")));
  EXPECT_NE(c.find("->val"), std::string::npos) << c;
  auto revert = [&](pb::ProvenanceKind kind, const char *who) {
    pb::RevertByProvenanceRequest req;
    req.set_program_id(id);
    req.mutable_filter()->set_kind(kind);
    req.mutable_filter()->set_id(who);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    pb::RevertByProvenanceResponse resp;
    auto st = b->RevertByProvenance(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  };
  // Undoing the edit brings the analysis's back; reverting the analysis's
  // assertions takes the structure away: the parameter points to undefined
  // bytes again.
  revert(pb::PROVENANCE_KIND_USER, "alice");
  c = Text(Decompile(*b, id, fns.at("node_sum")));
  EXPECT_EQ(c.find("->val"), std::string::npos) << c;
  EXPECT_NE(c.find("->field_0x0"), std::string::npos) << c;
  revert(pb::PROVENANCE_KIND_ANALYSIS, "infer.prototypes");
  c = Text(Decompile(*b, id, fns.at("node_mark")));
  EXPECT_EQ(c.find("astruct_1"), std::string::npos) << c;
  EXPECT_NE(c.find("undefined1 *param_1"), std::string::npos) << c;
}

// Readers and a writer while inference publishes its structures in the
// background (bug scrub part 3, for TSan): prototypes, the program's types
// and decompilations read from three threads, renames from a fourth, from
// the import until the analysis settles.
TEST_F(FactStoreTest, ReadersAndAWriterWhileInferencePublishes) {
  const fs::path exe = testing::scratch_dir("fact-store-publish") / "nodes";
  ASSERT_TRUE(testing::compile(REVKIT_TEST_CC, R"(
#include <stdio.h>
#include <stdlib.h>
struct node { int val; double w; struct node *next; unsigned char flag; };
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
int main(int argc, char **argv) {
  struct node *n = calloc(1, sizeof *n);
  node_mark(n, argc);
  printf("%f\n", node_sum(n));
  return 0;
}
)", "-O1", exe));
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;
  auto b = MakeImageBackend(o);
  const std::string id = Import(*b, exe);
  const auto fns = Functions(*b, id);
  ASSERT_TRUE(fns.contains("node_sum") && fns.contains("node_mark"));
  std::atomic<bool> stop{false};
  std::atomic<int> reads{0};
  std::vector<std::thread> threads;
  for (int k = 0; k < 3; ++k)
    threads.emplace_back([&, k] {
      CallContext ctx;
      while (!stop) {
        pb::GetFunctionRequest fr;
        fr.set_program_id(id);
        fr.mutable_address()->set_offset(fns.at(k == 0 ? "node_sum" : "node_mark"));
        pb::GetFunctionResponse fresp;
        EXPECT_TRUE(b->GetFunction(ctx, fr, fresp).ok());
        pb::FindTypesRequest tr;
        tr.set_program_id(id);
        tr.set_name_contains("astruct");
        pb::FindTypesResponse tresp;
        EXPECT_TRUE(b->FindTypes(ctx, tr, tresp).ok());
        pb::DecompileRequest dr;
        dr.set_program_id(id);
        dr.mutable_function()->set_offset(fns.at(k == 1 ? "node_sum" : "node_mark"));
        pb::DecompileResponse dresp;
        EXPECT_TRUE(b->Decompile(ctx, dr, dresp).ok());
        ++reads;
      }
    });
  threads.emplace_back([&] {
    for (int i = 0; !stop; ++i) {
      pb::AppendAssertionsRequest req;
      req.set_program_id(id);
      req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
      req.mutable_provenance()->set_id("alice");
      *req.add_assertions()->mutable_body() = Rename(fns.at("main"), "main_" + std::to_string(i % 4));
      pb::AppendAssertionsResponse resp;
      CallContext ctx;
      EXPECT_TRUE(b->AppendAssertions(ctx, req, resp).ok());
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  });
  Settle(*b, id);
  const int settled = reads;
  while (reads < settled + 6) std::this_thread::sleep_for(std::chrono::milliseconds(20));
  stop = true;
  for (std::thread &t : threads) t.join();
  pb::GetFunctionRequest fr;
  fr.set_program_id(id);
  fr.mutable_address()->set_offset(fns.at("node_sum"));
  pb::GetFunctionResponse fresp;
  ASSERT_TRUE(b->GetFunction(ctx_, fr, fresp).ok());
  EXPECT_NE(fresp.function().prototype().find("astruct_1 *"), std::string::npos) << fresp.function().prototype();
}

// Inference reads the memory map (docs/memory-map.md): a constant a
// function returns is an address once a region maps it, and inference,
// run again after the edit, makes the return a pointer; undoing the region
// takes it back.
TEST_F(FactStoreTest, InferenceReadsTheMemoryMap) {
  const fs::path exe = testing::scratch_dir("fact-store-mmio") / "mmio";
  ASSERT_TRUE(testing::compile(REVKIT_TEST_CC, R"(
#include <stdio.h>
__attribute__((noinline)) unsigned long mmio_base(void) { return 0x50000000UL; }
int main(void) {
  printf("%lx\n", mmio_base());
  return 0;
}
)", "-O1", exe));
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.infer_prototypes = InferMode::automatic;
  auto b = MakeImageBackend(o);
  const std::string id = Import(*b, exe);
  const std::uint64_t entry = Functions(*b, id).at("mmio_base");
  auto prototype = [&] {
    Settle(*b, id);
    pb::GetFunctionRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(entry);
    pb::GetFunctionResponse resp;
    EXPECT_TRUE(b->GetFunction(ctx_, req, resp).ok());
    EXPECT_EQ(resp.function().prototype_origin().derived().rule(), "infer.prototypes");
    return NoSpace(resp.function().prototype());
  };
  const std::string before = prototype();
  EXPECT_EQ(before.find('*'), std::string::npos) << before;

  pb::AddMemoryRegionRequest add;
  add.set_program_id(id);
  add.mutable_region()->set_name("mmio");
  add.mutable_region()->set_start(0x50000000);
  add.mutable_region()->set_size(0x1000);
  add.mutable_region()->set_read(true);
  add.mutable_region()->set_write(true);
  add.mutable_region()->set_is_volatile(true);
  add.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  add.mutable_provenance()->set_id("alice");
  pb::AddMemoryRegionResponse added;
  auto st = b->AddMemoryRegion(ctx_, add, added);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string after = prototype();
  EXPECT_NE(after.find("*mmio_base("), std::string::npos) << after;

  pb::RetractAssertionsRequest undo;
  undo.set_program_id(id);
  undo.add_seqs(added.assertion().seq());
  *undo.mutable_provenance() = add.provenance();
  pb::RetractAssertionsResponse undone;
  ASSERT_TRUE(b->RetractAssertions(ctx_, undo, undone).ok());
  EXPECT_EQ(prototype(), before);
}

TEST_F(FactStoreTest, DwarfPrototypesReachTheDecompiler) {
  auto b = Make();
  std::string id = Import(*b, debug_);
  auto fns = Functions(*b, id);

  // The truth, straight from the DWARF reader.
  std::ifstream in(debug_, std::ios::binary);
  std::string file((std::istreambuf_iterator<char>(in)), {});
  auto bytes = std::make_shared<loader::Bytes>(file.size());
  std::memcpy(bytes->data(), file.data(), file.size());
  loader::Image image = loader::parse(bytes, {});
  debuginfo::Sections sections;
  for (const auto &s : image.sections)
    if (s.name.starts_with(".debug_"))
      sections.by_name.emplace(s.name, std::span(reinterpret_cast<const std::uint8_t *>(file.data()) + s.offset, s.file_size));
  types::TypeStore store;
  debuginfo::DebugInfo info = debuginfo::import_dwarf(sections, store);
  types::PrintOptions ghidra_style;
  ghidra_style.style = types::Style::Ghidra;

  int compared = 0;
  for (const char *name : {"checksum", "buffer_checksum", "twice", "lonely"}) {
    const debuginfo::Function *truth = nullptr;
    for (const auto &f : info.functions)
      if (f.name == name) truth = &f;
    ASSERT_NE(truth, nullptr) << name;
    pb::DecompiledFunction f = Decompile(*b, id, fns.at(name));
    EXPECT_EQ(NoSpace(f.prototype().c_declaration()), NoSpace(types::prototype(store, truth->prototype, name, ghidra_style)))
        << name << "\n" << Text(f);
    EXPECT_TRUE(f.prototype().origin().has_asserted()) << name;
    ++compared;
  }
  EXPECT_EQ(compared, 4);
  // The struct came along: buffer_checksum reads b->data by field name.
  EXPECT_NE(Text(Decompile(*b, id, fns.at("buffer_checksum"))).find("->data"), std::string::npos);

  // The DWARF facts are import:dwarf assertions, outranked by a user.
  pb::BlameRequest blame;
  blame.mutable_key()->set_program_id(id);
  blame.mutable_key()->set_kind(pb::FACT_KIND_TYPE);
  blame.mutable_key()->mutable_address()->set_offset(fns.at("checksum"));
  pb::BlameResponse br;
  ASSERT_TRUE(b->Blame(ctx_, blame, br).ok());
  ASSERT_EQ(br.candidates_size(), 1);
  EXPECT_EQ(br.candidates(0).provenance().id(), "dwarf");
  EXPECT_EQ(br.candidates(0).body().retype().type().type_hash().size(), 32u);
  pb::GetTypesRequest types_req;
  types_req.set_program_id(id);
  types_req.add_hashes(br.candidates(0).body().retype().type().type_hash());
  pb::GetTypesResponse types_resp;
  ASSERT_TRUE(b->GetTypes(ctx_, types_req, types_resp).ok());
  ASSERT_EQ(types_resp.types_size(), 1);
  EXPECT_EQ(NoSpace(types_resp.types(0).display()), "unsignedint(constunsignedchar*p,intn)");
}

// On Lua's debug build, every function DWARF describes (and whose ABI the
// compiler kept) decompiles with its DWARF signature, compared the way
// rk-dwarf's references are: parameter count and names.
TEST_F(FactStoreTest, LuaDecompilesWithDwarfSignatures) {
  fs::path lua = fs::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/debug/lua";
  if (!fs::exists(lua)) GTEST_SKIP() << "corpus not built";
  auto b = Make();
  std::string id = Import(*b, lua);
  auto fns = Functions(*b, id);
  int total = 0, exact = 0;
  for (const char *name : {"luaL_checkinteger", "luaL_newstate", "lua_settop", "luaH_getshortstr", "luaS_newlstr",
                           "luaL_tolstring", "lua_pushvalue", "luaD_call", "luaV_concat", "luaO_pushfstring"}) {
    if (!fns.contains(name)) continue;
    pb::DecompiledFunction f = Decompile(*b, id, fns.at(name));
    ++total;
    const std::string decl = f.prototype().c_declaration();
    // Parameters are named as declared, not param_N.
    if (decl.find("param_") == std::string::npos && decl.find(std::string(name) + "(") != std::string::npos) ++exact;
    else ADD_FAILURE() << decl;
  }
  EXPECT_GT(total, 5);
  EXPECT_EQ(exact, total);
}

// A PE's PDB is found beside it and imported as import:pdb; its functions
// decompile with the PDB's signatures.
TEST_F(FactStoreTest, PePdbPrototypesReachTheDecompiler) {
  fs::path exe = fs::path(REVKIT_CORPUS) / "pe-x86_64/clang-O2/debug/features.exe";
  if (!fs::exists(exe) || !fs::exists(exe.parent_path() / "features.pdb")) GTEST_SKIP() << "corpus not built";
  auto b = Make();
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path(exe.string());
  pb::ImportProgramResponse resp;
  ASSERT_TRUE(b->ImportProgram(ctx_, req, resp).ok());
  const std::string id = resp.program().program_id();
  bool pdb = false;
  for (const auto &w : resp.warnings()) pdb |= w.starts_with("imported pdb");
  EXPECT_TRUE(pdb);

  std::ifstream in(exe.parent_path() / "features.pdb", std::ios::binary);
  std::vector<std::uint8_t> file((std::istreambuf_iterator<char>(in)), {});
  types::TypeStore store;
  debuginfo::PdbOptions popt;
  popt.image_base = loader::load_file(exe).image_base;
  debuginfo::PdbDebugInfo info = debuginfo::read_pdb(file, store, popt);
  types::PrintOptions ghidra_style;
  ghidra_style.style = types::Style::Ghidra;
  auto fns = Functions(*b, id);
  int compared = 0, matched = 0;
  for (const auto &f : info.functions) {
    if (!f.prototype.valid() || !fns.contains(f.name) || fns.at(f.name) != f.entry) continue;
    pb::DecompiledFunction d = Decompile(*b, id, f.entry);
    if (d.warnings_size() && d.warnings(0).starts_with("decompilation failed")) continue;
    ++compared;
    std::string truth = types::prototype(store, f.prototype, f.name, ghidra_style);
    if (NoSpace(d.prototype().c_declaration()) == NoSpace(truth)) ++matched;
    else std::cout << "  differs: " << d.prototype().c_declaration() << "  vs PDB " << truth << "\n";
    if (compared == 40) break;
  }
  std::cout << matched << " of " << compared << " prototypes match the PDB\n";
  EXPECT_GE(compared, 20);
  EXPECT_GE(matched * 10, compared * 9);
}

// Discovery's results reach the decompiler where Ghidra's Java side would
// supply them: a function's no-return flag with its symbol, and jump
// tables where the decompiler can't recover them. With gp tracked (as
// Ghidra's analysis sets it) the decompiler resolves RISC-V run_vm's table
// itself and, as Ghidra does, folds the one-destination switch it finds.
TEST_F(FactStoreTest, NoReturnAndJumpTablesReachTheDecompiler) {
  fs::path bin = fs::path(REVKIT_CORPUS) / "elf-riscv64/gcc-O2/debug/features";
  if (!fs::exists(bin)) GTEST_SKIP() << "corpus not built";
  auto b = Make();
  std::string id = Import(*b, bin);
  auto fns = Functions(*b, id);
  ASSERT_TRUE(fns.contains("run_vm"));
  pb::DecompiledFunction vm = Decompile(*b, id, fns.at("run_vm"));
  for (const auto &w : vm.warnings()) EXPECT_EQ(w.find("Treating indirect jump"), std::string::npos) << w;
  EXPECT_NE(Text(vm).find("Switch with 1 destination removed"), std::string::npos) << Text(vm);

  // die() never returns (discovery infers it: it ends in exit), and the
  // decompiler is told so with its symbol, as Ghidra's analysis tells it.
  constexpr const char *kDies = R"(
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) void die(const char *m) { puts(m); exit(3); }
__attribute__((noinline)) int pick(int x) { if (x < 0) die("negative"); return x * 3; }
int main(int argc, char **argv) { (void)argv; return pick(argc - 2); }
)";
  fs::path dies = testing::scratch_dir("fact-store-noreturn") / "dies";
  if (!testing::compile(REVKIT_TEST_CC, kDies, "-O1", dies)) GTEST_SKIP() << "no C compiler";
  auto d = Make();
  std::string did = Import(*d, dies);
  auto dfns = Functions(*d, did);
  ASSERT_TRUE(dfns.contains("die") && dfns.contains("pick"));
  auto function = [&](std::uint64_t entry) {
    pb::GetFunctionRequest req;
    req.set_program_id(did);
    req.mutable_address()->set_offset(entry);
    pb::GetFunctionResponse resp;
    EXPECT_TRUE(d->GetFunction(ctx_, req, resp).ok());
    return resp.function();
  };
  EXPECT_TRUE(function(dfns.at("die")).no_return());
  EXPECT_FALSE(function(dfns.at("pick")).no_return());
  EXPECT_TRUE(Decompile(*d, did, dfns.at("die")).prototype().no_return());
  EXPECT_FALSE(Decompile(*d, did, dfns.at("pick")).prototype().no_return());
}

// Revert follows the fact store: everything the author did is retracted,
// their retractions included, live or not, so a full revert reads as if
// they never acted. Skipping ops that were already retracted (what the
// backend did before) would undo the agent's own undo and revive its
// first rename.
TEST_F(FactStoreTest, FullRevertReadsAsIfTheAuthorNeverActed) {
  auto b = Make();
  std::string id = Import(*b, plain_);
  auto fns = Functions(*b, id);
  auto name_of = [&](std::uint64_t f) {
    pb::GetFunctionRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(f);
    pb::GetFunctionResponse resp;
    EXPECT_TRUE(b->GetFunction(ctx_, req, resp).ok());
    return resp.function().name();
  };
  auto agent_retracts = [&](std::uint64_t seq) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_AGENT);
    req.mutable_provenance()->set_id("model");
    req.add_seqs(seq);
    pb::RetractAssertionsResponse resp;
    EXPECT_TRUE(b->RetractAssertions(ctx_, req, resp).ok());
  };
  const std::uint64_t checksum = fns.at("checksum"), twice = fns.at("twice"), lonely = fns.at("lonely");
  // The agent renames checksum and undoes it, renames twice, and retracts
  // bob's rename of lonely.
  agent_retracts(Append(*b, id, Rename(checksum, "agent_first"), "model", pb::PROVENANCE_KIND_AGENT).assertions(0).seq());
  Append(*b, id, Rename(twice, "agent_twice"), "model", pb::PROVENANCE_KIND_AGENT);
  agent_retracts(Append(*b, id, Rename(lonely, "bobs_name"), "bob").assertions(0).seq());
  EXPECT_EQ(name_of(checksum), "checksum");
  EXPECT_EQ(name_of(twice), "agent_twice");
  EXPECT_EQ(name_of(lonely), "lonely");

  pb::RevertByProvenanceRequest rv;
  rv.set_program_id(id);
  rv.mutable_filter()->set_kind(pb::PROVENANCE_KIND_AGENT);
  rv.mutable_filter()->set_id("model");
  rv.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  rv.mutable_provenance()->set_id("reviewer");
  rv.set_dry_run(true);
  pb::RevertByProvenanceResponse reverted;
  ASSERT_TRUE(b->RevertByProvenance(ctx_, rv, reverted).ok());
  EXPECT_EQ(reverted.retracted_seqs_size(), 4);  // two renames, two retractions
  EXPECT_EQ(reverted.retractions_size(), 0);
  rv.set_dry_run(false);
  ASSERT_TRUE(b->RevertByProvenance(ctx_, rv, reverted).ok());
  EXPECT_EQ(reverted.retractions_size(), 4);
  EXPECT_EQ(name_of(checksum), "checksum");  // not revived
  EXPECT_EQ(name_of(twice), "twice");
  EXPECT_EQ(name_of(lonely), "bobs_name");  // what the agent removed is back
}

// A user-asserted entry point is a discovery seed. On a stripped binary
// whose cb_outer only a data pointer reaches, asserting it a function
// discovers it and its callee, turns their rows from data into
// instructions, and re-runs exactly the affected discovery (the two new
// flows, the whole-program fixpoint once, their references) and the
// affected decompilations: the two new functions and main, which passes
// cb_outer's address and so looked it up. A flow override then feeds back
// the same way.
TEST_F(FactStoreTest, AssertedEntryRerunsExactlyTheAffectedDiscovery) {
  const fs::path dir = testing::scratch_dir("fact-store-entry");
  if (!testing::compile(REVKIT_TEST_CC, kHidden, "-O1", dir / "named") ||
      !testing::compile(REVKIT_TEST_CC, kHidden, "-O1 -s", dir / "stripped"))
    GTEST_SKIP() << "no C compiler";
  loader::Image named = loader::load_file(dir / "named", {.image_base = std::nullopt, .ghidra_image_base = true, .macho_slice = {}});
  if (named.machine != 62) GTEST_SKIP() << "host isn't x86-64";
  std::map<std::string, std::uint64_t> sym;
  for (const loader::Symbol &s : named.symbols)
    if (s.defined) sym[s.name] = s.value;
  const std::uint64_t outer = sym.at("cb_outer"), inner = sym.at("cb_inner"), main_fn = sym.at("main");

  auto b = Make();
  const std::string id = Import(*b, dir / "stripped");
  auto row_at = [&](std::uint64_t a) {
    pb::GetListingRequest req;
    req.set_program_id(id);
    req.mutable_addresses()->mutable_start()->set_offset(a);
    req.mutable_addresses()->set_max_rows(1);
    pb::GetListingResponse resp;
    EXPECT_TRUE(b->GetListing(ctx_, req, resp).ok());
    return resp;
  };
  std::vector<std::uint64_t> all;
  for (const auto &[name, entry] : Functions(*b, id)) all.push_back(entry);
  ASSERT_TRUE(std::find(all.begin(), all.end(), main_fn) != all.end());
  ASSERT_TRUE(std::find(all.begin(), all.end(), outer) == all.end());
  const pb::GetListingResponse data = row_at(outer);
  EXPECT_EQ(data.rows(0).kind(), pb::LISTING_ROW_KIND_UNDEFINED);
  for (std::uint64_t f : all) Decompile(*b, id, f);

  auto sink = std::make_shared<Sink>();
  std::unique_ptr<api::Subscription> sub;
  pb::SubscribeRequest sreq;
  sreq.set_project_id("default");
  ASSERT_TRUE(b->Subscribe(ctx_, sreq, sink, sub).ok());

  ResetQueryCounters(*b, "default");
  pb::AssertionBody entry;
  entry.mutable_function_bounds()->mutable_entry()->set_offset(outer);
  Append(*b, id, entry);
  // The commit worked out its effects, so discovery has run again: two new
  // flows and thunk checks, one fixpoint, two functions' references.
  auto c = QueryCounters(*b, "default");
  EXPECT_EQ(c.at("analysis.flow").executions, 2u);
  EXPECT_EQ(c.at("analysis.thunk").executions, 2u);
  EXPECT_EQ(c.at("analysis.functions").executions, 1u);
  EXPECT_EQ(c.at("xrefs.function").executions, 2u);
  EXPECT_EQ(c.at("listing.code").executions, 1u);
  EXPECT_EQ(c.at("decompile.ghidra").executions, 0u);

  auto fns = Functions(*b, id);
  ASSERT_EQ(fns.size(), all.size() + 2);
  ASSERT_TRUE(fns.contains(FormatName(outer)) && fns.contains(FormatName(inner)));
  all.push_back(outer);
  all.push_back(inner);
  EXPECT_EQ(Recomputed(*b, id, all), (std::set<std::uint64_t>{main_fn, outer, inner}));
  EXPECT_NE(Text(Decompile(*b, id, outer)).find(FormatName(inner) + "("), std::string::npos);

  // The rows are instructions now, and the event says which rows were
  // rebuilt, with their windows on both sides.
  const pb::GetListingResponse code = row_at(outer);
  EXPECT_EQ(code.rows(0).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_TRUE(code.rows(0).function_entry());
  EXPECT_EQ(row_at(inner).rows(0).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  auto events = sink->revisions();
  ASSERT_EQ(events.size(), 1u);
  std::int64_t shift = 0;
  bool rebuilt = false;
  std::set<std::uint64_t> functions, decompiles;
  for (const auto &q : events[0].invalidated()) {
    if (q.kind() == pb::QUERY_KIND_FUNCTION) functions.insert(q.address().offset());
    if (q.kind() == pb::QUERY_KIND_DECOMPILE) decompiles.insert(q.address().offset());
    if (q.kind() != pb::QUERY_KIND_LISTING || !q.has_rows()) continue;
    shift += static_cast<std::int64_t>(q.rows().row_count()) - q.previous_rows().row_count();
    if (q.range().first().offset() <= outer && q.range().last().offset() >= inner) {
      rebuilt = true;
      EXPECT_EQ(q.rows().first_row(), code.first_row() - (code.rows(0).row() - q.rows().first_row()));
      EXPECT_EQ(q.previous_rows().first_row(), q.rows().first_row());  // nothing before it moved
      EXPECT_GE(q.rows().row_count(), 5u);                               // five instructions, then padding
    }
  }
  EXPECT_TRUE(rebuilt);
  EXPECT_EQ(code.total_rows() - data.total_rows(), shift);
  EXPECT_TRUE(functions.contains(outer) && functions.contains(inner));
  EXPECT_TRUE(decompiles.contains(outer) && decompiles.contains(main_fn));

  // A flow override reads cb_outer's call as a branch: cb_inner isn't
  // called any more, so its code joins cb_outer's body, and what followed
  // the call isn't reached: those rows become data. Only cb_outer's flow
  // and decompilation re-run.
  sink = std::make_shared<Sink>();
  ASSERT_TRUE(b->Subscribe(ctx_, sreq, sink, sub).ok());
  ResetQueryCounters(*b, "default");
  pb::AssertionBody branch;
  branch.mutable_flow_override()->mutable_address()->set_offset(outer);
  branch.mutable_flow_override()->set_kind(pb::FLOW_OVERRIDE_KIND_BRANCH);
  Append(*b, id, branch);
  c = QueryCounters(*b, "default");
  EXPECT_EQ(c.at("analysis.flow").executions, 1u);
  EXPECT_EQ(c.at("analysis.functions").executions, 1u);
  fns = Functions(*b, id);
  EXPECT_FALSE(fns.contains(FormatName(inner)));
  pb::GetFunctionRequest freq;
  freq.set_program_id(id);
  freq.mutable_address()->set_offset(inner);
  freq.set_containing(true);
  pb::GetFunctionResponse fresp;
  ASSERT_TRUE(b->GetFunction(ctx_, freq, fresp).ok());
  EXPECT_EQ(fresp.function().entry().offset(), outer);
  all.pop_back();
  EXPECT_EQ(Recomputed(*b, id, all), std::set<std::uint64_t>{outer});
  const std::uint64_t after_call = outer + 5;  // add $1, %eax
  EXPECT_EQ(row_at(after_call).rows(0).kind(), pb::LISTING_ROW_KIND_UNDEFINED);
  events = sink->revisions();
  ASSERT_EQ(events.size(), 1u);
  rebuilt = false;
  for (const auto &q : events[0].invalidated())
    if (q.kind() == pb::QUERY_KIND_LISTING && q.has_rows())
      rebuilt |= q.range().first().offset() <= after_call && q.range().last().offset() >= after_call;
  EXPECT_TRUE(rebuilt);
}

// A project directory keeps assertions and derived facts: the reopened
// backend serves the same answers without rediscovering or re-decompiling.
TEST_F(FactStoreTest, ProjectsReopenWithAssertionsAndDerivedFacts) {
  fs::path dir = testing::scratch_dir("fact-store-projects") / ::testing::UnitTest::GetInstance()->current_test_info()->name();
  fs::remove_all(dir);
  std::map<std::string, std::uint64_t> fns;
  std::string id, main_text;
  pb::ListAssertionsResponse before;
  {
    auto b = Make(dir.string());
    id = Import(*b, debug_);
    fns = Functions(*b, id);
    Append(*b, id, Rename(fns.at("checksum"), "fnv1a"));
    main_text = Text(Decompile(*b, id, fns.at("main")));
    pb::ListAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_filter()->set_include_inactive(true);
    req.mutable_page()->set_page_size(5000);
    ASSERT_TRUE(b->ListAssertions(ctx_, req, before).ok());
    EXPECT_GT(before.assertions_size(), 10);  // the DWARF import and the rename
  }
  auto b = Make(dir.string());
  ResetQueryCounters(*b, "default");
  auto again = Functions(*b, id);
  EXPECT_EQ(again.size(), fns.size());
  EXPECT_TRUE(again.contains("fnv1a"));
  EXPECT_EQ(Text(Decompile(*b, id, fns.at("main"))), main_text);
  pb::ListAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_filter()->set_include_inactive(true);
  req.mutable_page()->set_page_size(5000);
  pb::ListAssertionsResponse after;
  ASSERT_TRUE(b->ListAssertions(ctx_, req, after).ok());
  ASSERT_EQ(after.assertions_size(), before.assertions_size());
  for (int i = 0; i < after.assertions_size(); ++i) {
    pb::Assertion x = after.assertions(i), y = before.assertions(i);
    EXPECT_EQ(x.SerializeAsString(), y.SerializeAsString()) << x.DebugString() << y.DebugString();
  }
  auto c = QueryCounters(*b, "default");
  for (const char *rule : {"analysis.functions", "listing.code", "names.default", "functions.table", "decompile.ghidra"}) {
    EXPECT_EQ(c.at(rule).executions, 0u) << rule;
    EXPECT_GT(c.at(rule).loads, 0u) << rule;
  }

  // Edits keep working after the reopen and land at new revisions.
  auto appended = Append(*b, id, Rename(fns.at("checksum"), "fnv1a_32"));
  EXPECT_GT(appended.snapshot().revision(), 0u);
  EXPECT_NE(Text(Decompile(*b, id, fns.at("main"))).find("fnv1a_32("), std::string::npos);
}

// Reopening after a rule's version changed recomputes that rule only: its
// value comes out the same, so everything that read it validates by
// fingerprint instead of recomputing.
TEST_F(FactStoreTest, RuleVersionBumpRecomputesOnlyThatRule) {
  fs::path dir = testing::scratch_dir("fact-store-projects") / ::testing::UnitTest::GetInstance()->current_test_info()->name();
  fs::remove_all(dir);
  std::string id;
  std::map<std::string, std::uint64_t> fns;
  {
    auto b = Make(dir.string());
    id = Import(*b, plain_);
    fns = Functions(*b, id);
    for (const auto &[name, entry] : fns) Decompile(*b, id, entry);
  }
  // Stamp analysis.functions' stored memos with another version: what a
  // build with that rule's version bumped sees on reopen.
  {
    auto storage = facts::open_lmdb_storage(dir / "default");
    facts::Encoder prefix;
    prefix.u32be(facts::query_id("analysis.functions"));
    facts::WriteBatch batch;
    storage->scan(facts::Table::Derived, prefix.str(), [&](std::string_view k, std::string_view v) {
      facts::Decoder d(v);
      d.varint();  // the stored rule version
      facts::Encoder e;
      e.varint(1000);
      e.raw(v.substr(v.size() - d.remaining()));
      batch.put(facts::Table::Derived, std::string(k), std::move(e).str());
      return true;
    });
    ASSERT_FALSE(batch.empty());
    storage->write(batch);
  }
  auto b = Make(dir.string());
  ResetQueryCounters(*b, "default");
  for (const auto &[name, entry] : fns) Decompile(*b, id, entry);
  pb::GetListingRequest lr;
  lr.set_program_id(id);
  lr.mutable_rows()->set_row_count(100);
  pb::GetListingResponse listing;
  ASSERT_TRUE(b->GetListing(ctx_, lr, listing).ok());
  auto c = QueryCounters(*b, "default");
  EXPECT_EQ(c.at("analysis.functions").executions, 1u);
  for (const char *rule : {"analysis.flow", "names.loader", "names.default", "listing.code", "listing.rows", "xrefs.static",
                           "functions.table", "symbols.effective", "decompile.inputs", "decompile.ghidra"})
    EXPECT_EQ(c.at(rule).executions, 0u) << rule;
  EXPECT_GT(c.at("decompile.ghidra").loads, 0u);
  EXPECT_GT(c.at("listing.rows").validations, 0u);
}

}  // namespace
}  // namespace revkit::backend
