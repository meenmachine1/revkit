// Handler-level tests: the fake backend through the Backend interface, the
// same calls the transports make.
#include "revkit/api/fake_backend.h"

#include <gtest/gtest.h>

#include <deque>
#include <mutex>

namespace revkit::api {
namespace {

using namespace fake;

struct RecordingSink : EventSink {
  std::mutex mu;
  std::deque<pb::SubscribeResponse> events;
  std::optional<Status> ended;
  void Send(pb::SubscribeResponse e) override {
    std::lock_guard lock(mu);
    events.push_back(std::move(e));
  }
  void End(Status s) override {
    std::lock_guard lock(mu);
    ended = std::move(s);
  }
  std::vector<pb::RevisionEvent> revisions() {
    std::lock_guard lock(mu);
    std::vector<pb::RevisionEvent> out;
    for (auto &e : events)
      if (e.has_revision()) out.push_back(e.revision());
    return out;
  }
};

pb::Address Addr(std::uint64_t offset) {
  pb::Address a;
  a.set_offset(offset);
  return a;
}

pb::Provenance Prov(pb::ProvenanceKind kind, std::string id, std::string session = {}) {
  pb::Provenance p;
  p.set_kind(kind);
  p.set_id(std::move(id));
  p.set_session(std::move(session));
  return p;
}

pb::FactKey NameKey(std::uint64_t addr) {
  pb::FactKey k;
  k.set_program_id(kProgramId);
  k.set_kind(pb::FACT_KIND_NAME);
  *k.mutable_address() = Addr(addr);
  return k;
}

class FakeBackendTest : public ::testing::Test {
 protected:
  std::unique_ptr<Backend> backend = MakeFakeBackend();
  CallContext ctx;

  pb::AppendAssertionsResponse Rename(std::uint64_t addr, const std::string &name,
                                      pb::Provenance prov = Prov(pb::PROVENANCE_KIND_USER, "alice")) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(kProgramId);
    *req.mutable_provenance() = prov;
    auto *r = req.add_assertions()->mutable_body()->mutable_rename();
    *r->mutable_target()->mutable_address() = Addr(addr);
    r->set_name(name);
    pb::AppendAssertionsResponse resp;
    Status st = backend->AppendAssertions(ctx, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::string FunctionName(std::uint64_t entry, std::uint64_t revision = 0) {
    pb::GetFunctionRequest req;
    req.set_program_id(kProgramId);
    *req.mutable_address() = Addr(entry);
    req.mutable_read()->set_revision(revision);
    pb::GetFunctionResponse resp;
    Status st = backend->GetFunction(ctx, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function().name();
  }

  pb::DecompiledFunction Decompile(std::uint64_t entry) {
    pb::DecompileRequest req;
    req.set_program_id(kProgramId);
    *req.mutable_function() = Addr(entry);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    Status st = backend->Decompile(ctx, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  std::uint64_t Head() {
    pb::ListProjectsResponse resp;
    EXPECT_TRUE(backend->ListProjects(ctx, {}, resp).ok());
    return resp.projects(0).head_revision();
  }
};

TEST_F(FakeBackendTest, ServerInfoAndProjects) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend->GetServerInfo(ctx, {}, info).ok());
  EXPECT_EQ(info.api_major(), "v1");
  EXPECT_GE(info.api_minor(), 1u);

  pb::OpenProjectRequest open;
  open.set_project_id(kProjectId);
  pb::OpenProjectResponse opened;
  ASSERT_TRUE(backend->OpenProject(ctx, open, opened).ok());
  ASSERT_EQ(opened.programs_size(), 1);
  EXPECT_EQ(opened.programs(0).program_id(), kProgramId);
  EXPECT_EQ(opened.programs(0).sha256().size(), 64u);
  EXPECT_EQ(opened.project().head_revision(), 1u);  // the import

  pb::GetProgramSummaryRequest sreq;
  sreq.set_program_id(kProgramId);
  pb::GetProgramSummaryResponse summary;
  ASSERT_TRUE(backend->GetProgramSummary(ctx, sreq, summary).ok());
  EXPECT_EQ(summary.summary().language().language_id(), "x86:LE:64:default");
  EXPECT_EQ(summary.summary().image_base().offset(), 0x400000u);
  EXPECT_EQ(summary.summary().memory_size(), 4);
  EXPECT_EQ(summary.summary().function_count(), 4u);
  EXPECT_EQ(summary.snapshot().revision(), 1u);
}

TEST_F(FakeBackendTest, ListFunctionsPaginatesWithinOneSnapshot) {
  pb::ListFunctionsRequest req;
  req.set_program_id(kProgramId);
  req.mutable_page()->set_page_size(3);
  pb::ListFunctionsResponse first;
  ASSERT_TRUE(backend->ListFunctions(ctx, req, first).ok());
  ASSERT_EQ(first.functions_size(), 3);
  EXPECT_EQ(first.functions(0).name(), "entry");
  EXPECT_EQ(first.functions(1).name(), "main");
  EXPECT_EQ(first.functions(2).name(), "FUN_00401040");
  EXPECT_EQ(first.page().total_count(), 4);
  ASSERT_FALSE(first.page().next_page_token().empty());

  // A rename between pages must not leak into page two.
  Rename(kHelper, "double_it");
  req.mutable_page()->set_page_token(first.page().next_page_token());
  pb::ListFunctionsResponse second;
  ASSERT_TRUE(backend->ListFunctions(ctx, req, second).ok());
  ASSERT_EQ(second.functions_size(), 1);
  EXPECT_EQ(second.functions(0).name(), "FUN_00401070");
  EXPECT_EQ(second.snapshot().revision(), first.snapshot().revision());
  EXPECT_EQ(second.snapshot().head_revision(), first.snapshot().revision() + 1);
  EXPECT_TRUE(second.page().next_page_token().empty());
}

TEST_F(FakeBackendTest, ListSymbolsFindsFunctionsLabelsAndRenames) {
  pb::ListSymbolsRequest req;
  req.set_program_id(kProgramId);
  pb::ListSymbolsResponse all;
  ASSERT_TRUE(backend->ListSymbols(ctx, req, all).ok());
  std::map<std::string, std::pair<std::uint64_t, pb::SymbolKind>> by_name;
  std::uint64_t last = 0;
  for (const auto &s : all.symbols()) {
    EXPECT_GE(s.address().offset(), last);  // address order
    last = s.address().offset();
    by_name[s.name()] = {s.address().offset(), s.kind()};
  }
  EXPECT_EQ(by_name["main"], std::make_pair(kMain, pb::SYMBOL_KIND_FUNCTION));
  ASSERT_TRUE(by_name.count("s_hello_00402000"));
  EXPECT_EQ(by_name["s_hello_00402000"].second, pb::SYMBOL_KIND_LABEL);
  EXPECT_EQ(all.page().total_count(), all.symbols_size());

  req.set_name_contains("HELLO");
  pb::ListSymbolsResponse sub;
  ASSERT_TRUE(backend->ListSymbols(ctx, req, sub).ok());
  ASSERT_EQ(sub.symbols_size(), 1);
  EXPECT_EQ(sub.symbols(0).name(), "s_hello_00402000");

  req.clear_name_contains();
  req.add_kinds(pb::SYMBOL_KIND_FUNCTION);
  pb::ListSymbolsResponse fns;
  ASSERT_TRUE(backend->ListSymbols(ctx, req, fns).ok());
  EXPECT_EQ(fns.symbols_size(), 4);

  // Renames are found by their new name, with the assertion as origin;
  // name_equals is exact.
  Rename(kHelper, "double_it");
  pb::ListSymbolsRequest exact;
  exact.set_program_id(kProgramId);
  exact.set_name_equals("double_it");
  pb::ListSymbolsResponse found;
  ASSERT_TRUE(backend->ListSymbols(ctx, exact, found).ok());
  ASSERT_EQ(found.symbols_size(), 1);
  EXPECT_EQ(found.symbols(0).address().offset(), kHelper);
  EXPECT_TRUE(found.symbols(0).origin().has_asserted());
  exact.set_name_equals("Double_it");
  pb::ListSymbolsResponse none;
  ASSERT_TRUE(backend->ListSymbols(ctx, exact, none).ok());
  EXPECT_EQ(none.symbols_size(), 0);
}

TEST_F(FakeBackendTest, ListingWindowsAndTokens) {
  pb::GetListingRequest req;
  req.set_program_id(kProgramId);
  req.mutable_addresses()->mutable_start()->set_offset(0x401020);
  req.mutable_addresses()->set_max_rows(2);
  req.mutable_addresses()->set_rows_before(1);
  pb::GetListingResponse resp;
  ASSERT_TRUE(backend->GetListing(ctx, req, resp).ok());
  ASSERT_EQ(resp.rows_size(), 2);
  EXPECT_EQ(resp.rows(0).address().offset(), 0x40101bu);
  const auto &call = resp.rows(1);
  EXPECT_EQ(call.address().offset(), 0x401020u);
  EXPECT_EQ(call.kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_EQ(call.bytes(), std::string("\xe8\x1b\x00\x00\x00", 5));
  EXPECT_EQ(call.function().offset(), kMain);
  ASSERT_GE(call.tokens_size(), 3);
  EXPECT_EQ(call.tokens(0).text(), "CALL");
  const auto &sym = call.tokens(call.tokens_size() - 1);
  EXPECT_EQ(sym.kind(), pb::LISTING_TOKEN_KIND_SYMBOL);
  EXPECT_EQ(sym.text(), "FUN_00401040");
  EXPECT_EQ(sym.target().offset(), kChecksum);

  // Row windows address the same rows by index.
  pb::GetListingRequest rows;
  rows.set_program_id(kProgramId);
  rows.mutable_rows()->set_first_row(resp.first_row());
  rows.mutable_rows()->set_row_count(2);
  pb::GetListingResponse by_row;
  ASSERT_TRUE(backend->GetListing(ctx, rows, by_row).ok());
  ASSERT_EQ(by_row.rows_size(), 2);
  EXPECT_EQ(by_row.rows(1).address().offset(), 0x401020u);
  EXPECT_EQ(by_row.total_rows(), resp.total_rows());
}

TEST_F(FakeBackendTest, InstructionDetailHasPcode) {
  pb::GetInstructionRequest req;
  req.set_program_id(kProgramId);
  *req.mutable_address() = Addr(0x401020);
  pb::GetInstructionResponse resp;
  ASSERT_TRUE(backend->GetInstruction(ctx, req, resp).ok());
  const auto &i = resp.instruction();
  EXPECT_EQ(i.mnemonic(), "CALL");
  EXPECT_EQ(i.flow(), pb::FLOW_KIND_CALL);
  ASSERT_EQ(i.flow_targets_size(), 1);
  EXPECT_EQ(i.flow_targets(0).offset(), kChecksum);
  ASSERT_FALSE(i.pcode().empty());
  EXPECT_EQ(i.pcode().rbegin()->opcode(), pb::PCODE_OPCODE_CALL);
  EXPECT_EQ(i.pcode().rbegin()->mnemonic(), "CALL");
  EXPECT_EQ(i.pcode(0).output().register_name(), "RSP");

  *req.mutable_address() = Addr(0x401021);  // mid-instruction
  EXPECT_EQ(backend->GetInstruction(ctx, req, resp).code, StatusCode::kNotFound);
}

TEST_F(FakeBackendTest, XrefsToAndFrom) {
  pb::GetXrefsRequest req;
  req.set_program_id(kProgramId);
  *req.mutable_address() = Addr(kChecksum);
  pb::GetXrefsResponse resp;
  ASSERT_TRUE(backend->GetXrefs(ctx, req, resp).ok());
  ASSERT_EQ(resp.xrefs_size(), 1);
  EXPECT_EQ(resp.xrefs(0).from_address().offset(), 0x401020u);
  EXPECT_EQ(resp.xrefs(0).kind(), pb::XREF_KIND_CALL);
  EXPECT_EQ(resp.xrefs(0).from_function_name(), "main");

  pb::GetXrefsRequest from;
  from.set_program_id(kProgramId);
  *from.mutable_range()->mutable_first() = Addr(kMain);
  *from.mutable_range()->mutable_last() = Addr(0x40102e);
  from.set_direction(pb::XREF_DIRECTION_FROM);
  pb::GetXrefsResponse out;
  ASSERT_TRUE(backend->GetXrefs(ctx, from, out).ok());
  EXPECT_EQ(out.xrefs_size(), 3);  // string, checksum, global
}

TEST_F(FakeBackendTest, DecompileMapsTokensToVarnodesAndAddresses) {
  auto fn = Decompile(kChecksum);
  EXPECT_EQ(fn.prototype().c_declaration(), "uint FUN_00401040(byte *param_1,long param_2)");
  ASSERT_EQ(fn.variables_size(), 4);
  EXPECT_EQ(fn.prototype().parameter_indices_size(), 2);
  EXPECT_NE(fn.text().find("0x1000193"), std::string::npos);
  EXPECT_NE(fn.text().find("while (pbVar1 != param_1 + param_2);"), std::string::npos) << fn.text();

  bool found_multiply = false;
  for (const auto &line : fn.lines())
    for (const auto &t : line.tokens())
      if (t.kind() == pb::CODE_TOKEN_KIND_CONSTANT && t.text() == "0x1000193") {
        found_multiply = true;
        EXPECT_EQ(t.address().offset(), 0x401055u);
        ASSERT_EQ(t.varnode_indices_size(), 1);
        EXPECT_EQ(fn.varnodes(t.varnode_indices(0)).varnode().space(), "const");
      }
  EXPECT_TRUE(found_multiply);

  // Every variable reference points at a declared variable.
  for (const auto &line : fn.lines())
    for (const auto &t : line.tokens())
      if (t.has_variable_index()) {
        EXPECT_LT(t.variable_index(), static_cast<std::uint32_t>(fn.variables_size()));
      }
}

TEST_F(FakeBackendTest, RenameChangesQueriesAndPinnedReadsStillSeeTheOldName) {
  std::uint64_t before = Head();
  auto resp = Rename(kChecksum, "checksum");
  EXPECT_EQ(resp.snapshot().revision(), before + 1);
  ASSERT_EQ(resp.assertions_size(), 1);
  EXPECT_EQ(resp.assertions(0).status(), pb::ASSERTION_STATUS_EFFECTIVE);
  EXPECT_EQ(resp.assertions(0).key().kind(), pb::FACT_KIND_NAME);
  ASSERT_EQ(resp.changed_keys_size(), 1);

  EXPECT_EQ(FunctionName(kChecksum), "checksum");
  EXPECT_EQ(FunctionName(kChecksum, before), "FUN_00401040");
  // Callers render the new name.
  EXPECT_NE(Decompile(kMain).text().find("uVar1 = checksum(s_hello_00402000,5);"), std::string::npos)
      << Decompile(kMain).text();
}

TEST_F(FakeBackendTest, PrecedenceBlameHistoryAndBulkRevert) {
  auto agent = Prov(pb::PROVENANCE_KIND_AGENT, "claude", "run-1");
  Rename(kChecksum, "fnv1a_hash", agent);
  Rename(kHelper, "times_two", agent);
  EXPECT_EQ(FunctionName(kChecksum), "fnv1a_hash");

  Rename(kChecksum, "checksum");  // user outranks agent
  EXPECT_EQ(FunctionName(kChecksum), "checksum");
  Rename(kChecksum, "agent_wants_this", agent);  // newer, but still outranked
  EXPECT_EQ(FunctionName(kChecksum), "checksum");

  pb::BlameRequest breq;
  *breq.mutable_key() = NameKey(kChecksum);
  pb::BlameResponse blame;
  ASSERT_TRUE(backend->Blame(ctx, breq, blame).ok());
  EXPECT_EQ(blame.value_text(), "checksum");
  ASSERT_TRUE(blame.origin().has_asserted());
  EXPECT_EQ(blame.origin().asserted().provenance().kind(), pb::PROVENANCE_KIND_USER);
  ASSERT_EQ(blame.candidates_size(), 3);
  EXPECT_EQ(blame.candidates(0).status(), pb::ASSERTION_STATUS_EFFECTIVE);
  EXPECT_EQ(blame.candidates(1).status(), pb::ASSERTION_STATUS_SHADOWED);

  // Revert the agent session: its live assertions are retracted together.
  pb::RevertByProvenanceRequest rreq;
  rreq.set_program_id(kProgramId);
  rreq.mutable_filter()->set_kind(pb::PROVENANCE_KIND_AGENT);
  rreq.mutable_filter()->set_session("run-1");
  *rreq.mutable_provenance() = Prov(pb::PROVENANCE_KIND_USER, "alice");
  rreq.set_dry_run(true);
  pb::RevertByProvenanceResponse dry;
  ASSERT_TRUE(backend->RevertByProvenance(ctx, rreq, dry).ok());
  EXPECT_EQ(dry.retracted_seqs_size(), 3);
  EXPECT_EQ(dry.retractions_size(), 0);
  rreq.set_dry_run(false);
  pb::RevertByProvenanceResponse reverted;
  ASSERT_TRUE(backend->RevertByProvenance(ctx, rreq, reverted).ok());
  EXPECT_EQ(reverted.retractions_size(), 3);
  EXPECT_EQ(FunctionName(kHelper), "FUN_00401070");
  EXPECT_EQ(FunctionName(kChecksum), "checksum");

  pb::GetHistoryRequest hreq;
  *hreq.mutable_key() = NameKey(kChecksum);
  pb::GetHistoryResponse history;
  ASSERT_TRUE(backend->GetHistory(ctx, hreq, history).ok());
  EXPECT_EQ(history.entries_size(), 5);  // 3 asserts + 2 retractions
  int retracted = 0;
  for (const auto &e : history.entries()) retracted += e.status() == pb::ASSERTION_STATUS_RETRACTED;
  EXPECT_EQ(retracted, 2);
}

TEST_F(FakeBackendTest, RetractingARetractionReinstates) {
  auto added = Rename(kHelper, "times_two");
  std::uint64_t seq = added.assertions(0).seq();
  pb::RetractAssertionsRequest req;
  req.set_program_id(kProgramId);
  req.add_seqs(seq);
  *req.mutable_provenance() = Prov(pb::PROVENANCE_KIND_USER, "alice");
  pb::RetractAssertionsResponse r1;
  ASSERT_TRUE(backend->RetractAssertions(ctx, req, r1).ok());
  EXPECT_EQ(FunctionName(kHelper), "FUN_00401070");
  EXPECT_EQ(backend->RetractAssertions(ctx, req, r1).code, StatusCode::kFailedPrecondition);

  req.set_seqs(0, r1.retractions(0).seq());
  pb::RetractAssertionsResponse r2;
  ASSERT_TRUE(backend->RetractAssertions(ctx, req, r2).ok());
  EXPECT_EQ(FunctionName(kHelper), "times_two");
}

TEST_F(FakeBackendTest, LocalsCommentsAndBounds) {
  pb::AppendAssertionsRequest req;
  req.set_program_id(kProgramId);
  *req.mutable_provenance() = Prov(pb::PROVENANCE_KIND_USER, "alice");
  auto *rn = req.add_assertions()->mutable_body()->mutable_rename();
  *rn->mutable_target()->mutable_local()->mutable_function() = Addr(kChecksum);
  rn->mutable_target()->mutable_local()->set_storage_key("register:EAX@0x40104b");
  rn->set_name("hash");
  auto *rt = req.add_assertions()->mutable_body()->mutable_retype();
  *rt->mutable_target()->mutable_local()->mutable_function() = Addr(kChecksum);
  rt->mutable_target()->mutable_local()->set_storage_key("param:1");
  rt->mutable_type()->set_c_declaration("size_t");
  auto *c = req.add_assertions()->mutable_body()->mutable_comment();
  *c->mutable_address() = Addr(0x401055);
  c->set_kind(pb::COMMENT_KIND_PRE);
  c->set_text("FNV prime");
  pb::AppendAssertionsResponse resp;
  ASSERT_TRUE(backend->AppendAssertions(ctx, req, resp).ok());
  EXPECT_EQ(resp.changed_keys_size(), 3);

  auto fn = Decompile(kChecksum);
  EXPECT_NE(fn.text().find("hash = (hash ^ *pbVar1) * 0x1000193;"), std::string::npos) << fn.text();
  EXPECT_NE(fn.text().find("size_t param_2"), std::string::npos) << fn.text();
  EXPECT_NE(fn.text().find("/* FNV prime */"), std::string::npos) << fn.text();

  pb::GetListingRequest lreq;
  lreq.set_program_id(kProgramId);
  lreq.mutable_addresses()->mutable_start()->set_offset(0x401055);
  lreq.mutable_addresses()->set_max_rows(1);
  pb::GetListingResponse listing;
  ASSERT_TRUE(backend->GetListing(ctx, lreq, listing).ok());
  ASSERT_EQ(listing.rows(0).comments_size(), 1);
  EXPECT_EQ(listing.rows(0).comments(0).text(), "FNV prime");
  EXPECT_TRUE(listing.rows(0).comments(0).origin().has_asserted());

  // Declare a function at the checksum's early-return block, then remove it.
  pb::AppendAssertionsRequest bounds;
  bounds.set_program_id(kProgramId);
  *bounds.mutable_provenance() = Prov(pb::PROVENANCE_KIND_USER, "alice");
  *bounds.add_assertions()->mutable_body()->mutable_function_bounds()->mutable_entry() = Addr(0x401065);
  ASSERT_TRUE(backend->AppendAssertions(ctx, bounds, resp).ok());
  EXPECT_EQ(FunctionName(0x401065), "FUN_00401065");
  pb::GetFunctionRequest freq;
  freq.set_program_id(kProgramId);
  *freq.mutable_address() = Addr(0x401065);
  pb::GetFunctionResponse f;
  ASSERT_TRUE(backend->GetFunction(ctx, freq, f).ok());
  ASSERT_EQ(f.function().body_size(), 1);
  EXPECT_EQ(f.function().body(0).last().offset(), 0x40106au);
}

TEST_F(FakeBackendTest, ValidationAndRevisionErrors) {
  pb::AppendAssertionsRequest req;
  req.set_program_id(kProgramId);
  *req.mutable_provenance() = Prov(pb::PROVENANCE_KIND_USER, "alice");
  auto *rn = req.add_assertions()->mutable_body()->mutable_rename();
  *rn->mutable_target()->mutable_address() = Addr(0x900000);
  rn->set_name("nowhere");
  pb::AppendAssertionsResponse resp;
  Status st = backend->AppendAssertions(ctx, req, resp);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("assertions[0]"), std::string::npos);

  req.clear_provenance();
  EXPECT_EQ(backend->AppendAssertions(ctx, req, resp).code, StatusCode::kInvalidArgument);

  pb::ListFunctionsRequest lreq;
  lreq.set_program_id("nope");
  pb::ListFunctionsResponse lresp;
  EXPECT_EQ(backend->ListFunctions(ctx, lreq, lresp).code, StatusCode::kNotFound);
  lreq.set_program_id(kProgramId);
  lreq.mutable_read()->set_revision(99);
  EXPECT_EQ(backend->ListFunctions(ctx, lreq, lresp).code, StatusCode::kOutOfRange);

  // Optimistic concurrency.
  pb::AppendAssertionsRequest stale;
  stale.set_program_id(kProgramId);
  *stale.mutable_provenance() = Prov(pb::PROVENANCE_KIND_USER, "alice");
  stale.set_expected_head_revision(Head() + 5);
  auto *ok_rn = stale.add_assertions()->mutable_body()->mutable_rename();
  *ok_rn->mutable_target()->mutable_address() = Addr(kHelper);
  ok_rn->set_name("x");
  EXPECT_EQ(backend->AppendAssertions(ctx, stale, resp).code, StatusCode::kAborted);
}

TEST(FakeBackendRetention, ExpiredRevisionsFailWithFailedPrecondition) {
  auto backend = MakeFakeBackend({.retained_revisions = 2});
  CallContext ctx;
  for (const char *name : {"a", "b", "c"}) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(fake::kProgramId);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    auto *rn = req.add_assertions()->mutable_body()->mutable_rename();
    rn->mutable_target()->mutable_address()->set_offset(fake::kHelper);
    rn->set_name(name);
    pb::AppendAssertionsResponse resp;
    ASSERT_TRUE(backend->AppendAssertions(ctx, req, resp).ok());
  }
  pb::ListFunctionsRequest req;
  req.set_program_id(fake::kProgramId);
  req.mutable_read()->set_revision(1);
  pb::ListFunctionsResponse resp;
  Status st = backend->ListFunctions(ctx, req, resp);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition);
  EXPECT_NE(st.message.find("REVISION_EXPIRED"), std::string::npos);
}

TEST_F(FakeBackendTest, SubscriptionsCarryInvalidationsAndReplay) {
  auto sink = std::make_shared<RecordingSink>();
  std::unique_ptr<Subscription> sub;
  pb::SubscribeRequest req;
  req.set_project_id(kProjectId);
  req.set_include_assertions(true);
  ASSERT_TRUE(backend->Subscribe(ctx, req, sink, sub).ok());
  ASSERT_EQ(sink->events.size(), 1u);
  ASSERT_TRUE(sink->events[0].has_hello());
  std::uint64_t start = sink->events[0].hello().head_revision();

  Rename(kChecksum, "checksum");
  auto revs = sink->revisions();
  ASSERT_EQ(revs.size(), 1u);
  const auto &ev = revs[0];
  EXPECT_EQ(ev.revision(), start + 1);
  EXPECT_EQ(ev.previous_revision(), start);
  EXPECT_EQ(ev.cause(), pb::CHANGE_CAUSE_ASSERTION);
  EXPECT_EQ(ev.assertions_size(), 1);
  ASSERT_EQ(ev.changed_keys_size(), 1);
  EXPECT_EQ(ev.changed_keys(0).address().offset(), kChecksum);
  bool main_decompile = false, function_list = false, call_row = false;
  for (const auto &q : ev.invalidated()) {
    main_decompile |= q.kind() == pb::QUERY_KIND_DECOMPILE && q.address().offset() == kMain;
    function_list |= q.kind() == pb::QUERY_KIND_FUNCTION_LIST;
    call_row |= q.kind() == pb::QUERY_KIND_LISTING && q.range().first().offset() == 0x401020;
  }
  EXPECT_TRUE(main_decompile);
  EXPECT_TRUE(function_list);
  EXPECT_TRUE(call_row);

  // Unsubscribing stops delivery.
  sub.reset();
  Rename(kHelper, "times_two");
  EXPECT_EQ(sink->revisions().size(), 1u);

  // A late subscriber replays from its resume point.
  auto late = std::make_shared<RecordingSink>();
  req.set_from_revision(start);
  ASSERT_TRUE(backend->Subscribe(ctx, req, late, sub).ok());
  auto replayed = late->revisions();
  ASSERT_EQ(replayed.size(), 2u);
  EXPECT_EQ(replayed[0].revision(), start + 1);
  EXPECT_EQ(replayed[1].revision(), start + 2);

  // Closing the project ends streams.
  pb::CloseProjectRequest close;
  close.set_project_id(kProjectId);
  pb::CloseProjectResponse closed;
  ASSERT_TRUE(backend->CloseProject(ctx, close, closed).ok());
  ASSERT_TRUE(late->ended.has_value());
  EXPECT_EQ(late->ended->code, StatusCode::kCancelled);
}

TEST_F(FakeBackendTest, TypesByHash) {
  auto fn = Decompile(kChecksum);
  std::string ptr_hash = fn.variables(0).type().hash();
  ASSERT_FALSE(ptr_hash.empty());
  pb::GetTypesRequest req;
  req.set_program_id(kProgramId);
  req.add_hashes(ptr_hash);
  req.add_hashes("0000000000000000");
  req.set_include_dependencies(true);
  pb::GetTypesResponse resp;
  ASSERT_TRUE(backend->GetTypes(ctx, req, resp).ok());
  ASSERT_EQ(resp.types_size(), 2);  // byte * and byte
  EXPECT_EQ(resp.types(0).kind(), pb::TYPE_KIND_POINTER);
  EXPECT_EQ(resp.types(1).name(), "byte");
  ASSERT_EQ(resp.missing_size(), 1);

  pb::FindTypesRequest find;
  find.set_program_id(kProgramId);
  find.set_name_contains("FNV");
  pb::FindTypesResponse found;
  ASSERT_TRUE(backend->FindTypes(ctx, find, found).ok());
  ASSERT_EQ(found.types_size(), 1);
  EXPECT_EQ(found.types(0).composite().fields_size(), 2);
}

}  // namespace
}  // namespace revkit::api
