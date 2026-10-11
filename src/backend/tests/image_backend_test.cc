// The image backend through the api::Backend interface, on a binary
// compiled at test time and (when built) the corpus.
#include "builders.hh"

#include "revkit/analysis/analysis.h"
#include "revkit/backend/image_backend.h"
#include "revkit/decompd/bundle.h"
#include "revkit/decompd/pool.h"
#include "revkit/facts/fact_db.h"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <thread>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
#include <stdio.h>
int counter;
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return h;
}
__attribute__((noinline)) int twice(int x) { return checksum((const unsigned char *)&x, 4) * 2; }
int main(int argc, char **argv) {
  unsigned r = checksum((const unsigned char *)argv[0], argc);
  printf("%u %d\n", r, twice(argc));
  return (int)r;
}
)";

class Sink : public api::EventSink {
 public:
  void Send(pb::SubscribeResponse event) override {
    std::lock_guard lock(mu_);
    events_.push_back(std::move(event));
  }
  void End(api::Status) override {}
  std::vector<pb::RevisionEvent> revisions() {
    std::lock_guard lock(mu_);
    std::vector<pb::RevisionEvent> out;
    for (const auto &e : events_)
      if (e.has_revision()) out.push_back(e.revision());
    return out;
  }

 private:
  std::mutex mu_;
  std::vector<pb::SubscribeResponse> events_;
};

std::string Text(const pb::DecompiledFunction &f) {
  std::string out;
  for (const auto &line : f.lines()) {
    for (const auto &t : line.tokens()) out += t.text();
    out += '\n';
  }
  return out;
}

class ImageBackendTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("image-backend");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1", exe_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  std::string Import(const std::filesystem::path &path, const std::string &name = {}) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = backend_->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::map<std::string, std::uint64_t> Functions(const std::string &program) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  pb::DecompiledFunction Decompile(const std::string &program, std::uint64_t entry, std::uint64_t revision = 0) {
    pb::DecompileRequest req;
    req.set_program_id(program);
    req.mutable_function()->set_offset(entry);
    req.mutable_read()->set_revision(revision);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse resp;
    auto st = backend_->Decompile(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  }

  api::Status Rename(const std::string &program, std::uint64_t addr, const std::string &name,
                     const std::string &actor = "alice", pb::AppendAssertionsResponse *out = nullptr) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id(actor);
    auto *r = req.add_assertions()->mutable_body()->mutable_rename();
    r->mutable_target()->mutable_address()->set_offset(addr);
    r->set_name(name);
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    if (out) *out = resp;
    return st;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
};

TEST_F(ImageBackendTest, ImportsFromPathAndBytes) {
  std::string by_path = Import(exe_);
  EXPECT_EQ(by_path, "default/prog");

  std::ifstream in(exe_, std::ios::binary);
  std::string bytes((std::istreambuf_iterator<char>(in)), {});
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_content(bytes);
  pb::ImportProgramResponse resp;
  ASSERT_TRUE(backend_->ImportProgram(ctx_, req, resp).ok());
  EXPECT_EQ(resp.program().program_id(), "default/upload");
  EXPECT_EQ(resp.program().format(), "elf");
  EXPECT_EQ(resp.program().language_id(), "x86:LE:64:default");
  EXPECT_EQ(resp.program().sha256().size(), 64u);
  EXPECT_EQ(resp.snapshot().revision(), 2u);

  pb::ImportProgramRequest junk;
  junk.set_project_id("default");
  junk.set_content("not an executable");
  EXPECT_EQ(backend_->ImportProgram(ctx_, junk, resp).code, StatusCode::kInvalidArgument);
  junk.set_project_id("nope");
  EXPECT_EQ(backend_->ImportProgram(ctx_, junk, resp).code, StatusCode::kNotFound);
}

TEST_F(ImageBackendTest, ListSymbolsByNameAndKind) {
  std::string prog = Import(exe_);
  auto fns = Functions(prog);
  ASSERT_TRUE(fns.count("checksum"));

  pb::ListSymbolsRequest req;
  req.set_program_id(prog);
  req.set_name_equals("checksum");
  pb::ListSymbolsResponse resp;
  resp.Clear();
  ASSERT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
  ASSERT_EQ(resp.symbols_size(), 1);
  EXPECT_EQ(resp.symbols(0).address().offset(), fns["checksum"]);
  EXPECT_EQ(resp.symbols(0).kind(), pb::SYMBOL_KIND_FUNCTION);
  EXPECT_TRUE(resp.symbols(0).origin().has_derived());  // the loader named it

  // The global is a label, found by substring regardless of case.
  req.clear_name_equals();
  req.set_name_contains("COUNTER");
  resp.Clear();
  ASSERT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
  ASSERT_GE(resp.symbols_size(), 1);
  EXPECT_EQ(resp.symbols(0).name(), "counter");
  EXPECT_EQ(resp.symbols(0).kind(), pb::SYMBOL_KIND_LABEL);

  // Only functions, in address order.
  req.clear_name_contains();
  req.add_kinds(pb::SYMBOL_KIND_FUNCTION);
  resp.Clear();
  ASSERT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
  EXPECT_EQ(static_cast<std::size_t>(resp.symbols_size()), fns.size());
  for (int i = 1; i < resp.symbols_size(); ++i)
    EXPECT_LT(resp.symbols(i - 1).address().offset(), resp.symbols(i).address().offset());

  // A renamed global is found under its new name only.
  const std::uint64_t counter = [&] {
    pb::ListSymbolsRequest q;
    q.set_program_id(prog);
    q.set_name_equals("counter");
    pb::ListSymbolsResponse r;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, q, r).ok());
    return r.symbols_size() ? r.symbols(0).address().offset() : 0;
  }();
  ASSERT_NE(counter, 0u);
  ASSERT_TRUE(Rename(prog, counter, "call_count").ok());
  pb::ListSymbolsRequest q;
  q.set_program_id(prog);
  q.set_name_equals("call_count");
  resp.Clear();
  ASSERT_TRUE(backend_->ListSymbols(ctx_, q, resp).ok());
  ASSERT_EQ(resp.symbols_size(), 1);
  EXPECT_EQ(resp.symbols(0).address().offset(), counter);
  EXPECT_TRUE(resp.symbols(0).origin().has_asserted());
  q.set_name_equals("counter");
  resp.Clear();
  ASSERT_TRUE(backend_->ListSymbols(ctx_, q, resp).ok());
  EXPECT_EQ(resp.symbols_size(), 0);
}

TEST_F(ImageBackendTest, SummaryMemoryAndReads) {
  std::string id = Import(exe_);
  pb::GetProgramSummaryRequest req;
  req.set_program_id(id);
  pb::GetProgramSummaryResponse resp;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, req, resp).ok());
  const auto &s = resp.summary();
  EXPECT_EQ(s.language().compiler_spec_id(), "gcc");
  EXPECT_EQ(s.language().pointer_size(), 8u);
  EXPECT_GT(s.function_count(), 2u);
  EXPECT_GT(s.instruction_count(), 10u);
  ASSERT_FALSE(s.entry_points().empty());
  EXPECT_EQ(s.entry_points(0).name(), "_start");

  const pb::MemoryBlock *text = nullptr;
  for (const auto &b : s.memory())
    if (b.name() == ".text") text = &b;
  ASSERT_NE(text, nullptr);
  EXPECT_TRUE(text->execute());
  pb::ReadMemoryRequest rm;
  rm.set_program_id(id);
  rm.mutable_address()->set_offset(text->range().first().offset());
  rm.set_length(16);
  pb::ReadMemoryResponse rr;
  ASSERT_TRUE(backend_->ReadMemory(ctx_, rm, rr).ok());
  EXPECT_EQ(rr.data().size(), 16u);
  rm.mutable_address()->set_offset(0x10);  // unmapped
  ASSERT_TRUE(backend_->ReadMemory(ctx_, rm, rr).ok());
  EXPECT_TRUE(rr.data().empty());
}

// Data analysis's string is a data row, named and shown as Ghidra's
// listing shows it; counter, which code writes, is undefined4.
TEST_F(ImageBackendTest, ListingShowsAnalysedData) {
  std::string id = Import(exe_);
  pb::GetListingRequest req;
  req.set_program_id(id);
  req.mutable_rows()->set_first_row(0);
  req.mutable_rows()->set_row_count(5000);
  pb::GetListingResponse resp;
  ASSERT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
  bool string = false, word = false;
  for (const auto &row : resp.rows()) {
    if (row.kind() != pb::LISTING_ROW_KIND_DATA) continue;
    ASSERT_GE(row.tokens_size(), 3);
    EXPECT_EQ(row.tokens(0).kind(), pb::LISTING_TOKEN_KIND_TYPE);
    if (row.data_type() == "string" && row.tokens(2).text() == "\"%u %d\\n\"") {
      string = true;
      EXPECT_EQ(row.tokens(0).text(), "ds");
      EXPECT_EQ(row.tokens(2).kind(), pb::LISTING_TOKEN_KIND_DATA_VALUE);
      EXPECT_EQ(row.length(), 7u);
      ASSERT_GT(row.labels_size(), 0);
      EXPECT_TRUE(row.labels(0).name().starts_with("s_%u_%d_")) << row.labels(0).name();
    }
    if (row.data_type() == "undefined4") word = true;
  }
  EXPECT_TRUE(string);
  EXPECT_TRUE(word);
}

TEST_F(ImageBackendTest, ListingWindowsAgree) {
  std::string id = Import(exe_);
  auto fns = Functions(id);
  const std::uint64_t main = fns.at("main");

  pb::GetListingRequest by_addr;
  by_addr.set_program_id(id);
  by_addr.mutable_addresses()->mutable_start()->set_offset(main);
  by_addr.mutable_addresses()->set_max_rows(30);
  by_addr.mutable_addresses()->set_rows_before(3);
  pb::GetListingResponse a;
  ASSERT_TRUE(backend_->GetListing(ctx_, by_addr, a).ok());
  ASSERT_EQ(a.rows_size(), 30);
  EXPECT_EQ(a.rows(3).address().offset(), main);
  EXPECT_TRUE(a.rows(3).function_entry());
  EXPECT_EQ(a.rows(3).labels(0).name(), "main");

  // The same rows through a row window, crossing a page boundary.
  pb::GetListingRequest by_row;
  by_row.set_program_id(id);
  by_row.mutable_rows()->set_first_row(a.first_row());
  by_row.mutable_rows()->set_row_count(30);
  pb::GetListingResponse b;
  ASSERT_TRUE(backend_->GetListing(ctx_, by_row, b).ok());
  ASSERT_EQ(b.rows_size(), 30);
  EXPECT_EQ(a.total_rows(), b.total_rows());
  for (int i = 0; i < 30; ++i) EXPECT_EQ(a.rows(i).SerializeAsString(), b.rows(i).SerializeAsString());

  bool symbol_call = false;
  for (const auto &row : a.rows()) {
    if (row.kind() != pb::LISTING_ROW_KIND_INSTRUCTION) continue;
    EXPECT_EQ(row.tokens(0).kind(), pb::LISTING_TOKEN_KIND_MNEMONIC);
    for (const auto &t : row.tokens())
      if (t.kind() == pb::LISTING_TOKEN_KIND_SYMBOL && t.text() == "checksum") {
        symbol_call = true;
        EXPECT_EQ(t.target().offset(), fns.at("checksum"));
        EXPECT_EQ(t.operand_index(), 0u);
      }
  }
  EXPECT_TRUE(symbol_call);

  // Every row of the program pages through without gaps.
  std::uint64_t prev_end = 0;
  std::int64_t seen = 0;
  for (std::int64_t first = 0; first < b.total_rows(); first += 2000) {
    by_row.mutable_rows()->set_first_row(first);
    by_row.mutable_rows()->set_row_count(2000);
    by_row.set_omit_bytes(true);
    b.Clear();
    ASSERT_TRUE(backend_->GetListing(ctx_, by_row, b).ok());
    for (const auto &row : b.rows()) {
      EXPECT_GE(row.address().offset(), prev_end);
      prev_end = row.address().offset() + row.length();
      ++seen;
    }
  }
  EXPECT_EQ(seen, b.total_rows());
}

TEST_F(ImageBackendTest, InstructionDetailAndXrefs) {
  std::string id = Import(exe_);
  auto fns = Functions(id);
  pb::GetXrefsRequest xr;
  xr.set_program_id(id);
  xr.mutable_address()->set_offset(fns.at("checksum"));
  pb::GetXrefsResponse xresp;
  ASSERT_TRUE(backend_->GetXrefs(ctx_, xr, xresp).ok());
  std::set<std::string> callers;
  std::uint64_t call_site = 0;
  for (const auto &x : xresp.xrefs()) {
    EXPECT_EQ(x.kind(), pb::XREF_KIND_CALL);
    EXPECT_EQ(x.to_name(), "checksum");
    callers.insert(x.from_function_name());
    call_site = x.from_address().offset();
  }
  EXPECT_EQ(callers, (std::set<std::string>{"main", "twice"}));

  pb::GetInstructionRequest ir;
  ir.set_program_id(id);
  ir.mutable_address()->set_offset(call_site);
  pb::GetInstructionResponse iresp;
  ASSERT_TRUE(backend_->GetInstruction(ctx_, ir, iresp).ok());
  const auto &insn = iresp.instruction();
  EXPECT_EQ(insn.mnemonic(), "CALL");
  EXPECT_EQ(insn.flow(), pb::FLOW_KIND_CALL);
  ASSERT_EQ(insn.flow_targets_size(), 1);
  EXPECT_EQ(insn.flow_targets(0).offset(), fns.at("checksum"));
  EXPECT_EQ(insn.fall_through().offset(), call_site + insn.length());
  ASSERT_EQ(insn.operands_size(), 1);
  EXPECT_EQ(insn.operands(0).references(0).offset(), fns.at("checksum"));
  bool call_op = false, rsp = false;
  for (const auto &op : insn.pcode()) {
    call_op |= op.opcode() == pb::PCODE_OPCODE_CALL && op.mnemonic() == "CALL";
    if (op.has_output() && op.output().register_name() == "RSP") rsp = true;
  }
  EXPECT_TRUE(call_op);
  EXPECT_TRUE(rsp);

  ir.mutable_address()->set_offset(0x10);
  EXPECT_EQ(backend_->GetInstruction(ctx_, ir, iresp).code, StatusCode::kNotFound);
}

// Batch reads for scripts (api_minor 29): DecompileMany streams every
// function at one pinned revision, FindBytes searches with a mask, and
// ListInstructions streams a function's instructions with p-code.
TEST_F(ImageBackendTest, ScriptBatchReads) {
  std::string id = Import(exe_);
  auto fns = Functions(id);
  const std::uint64_t checksum = fns.at("checksum");
  pb::AppendAssertionsResponse renamed;
  ASSERT_TRUE(Rename(id, checksum, "fnv1a", "alice", &renamed).ok());
  const std::uint64_t after = renamed.snapshot().revision();

  // Every function, once each, in completion order with its index.
  pb::DecompileManyRequest dm;
  dm.set_program_id(id);
  dm.set_all(true);
  dm.mutable_options()->set_include_text(true);
  std::mutex mu;
  std::vector<pb::DecompileManyResponse> got;
  auto collect = [&](const pb::DecompileManyResponse &m) {
    std::lock_guard lock(mu);
    got.push_back(m);
    return true;
  };
  ASSERT_TRUE(backend_->DecompileMany(ctx_, dm, collect).ok());
  ASSERT_EQ(got.size(), fns.size());
  std::set<std::uint32_t> indexes;
  bool saw = false;
  for (const auto &m : got) {
    EXPECT_EQ(m.total(), fns.size());
    EXPECT_EQ(m.snapshot().revision(), after);
    EXPECT_TRUE(m.error().empty()) << m.error();
    indexes.insert(m.index());
    if (m.entry().offset() == checksum) {
      saw = true;
      EXPECT_NE(m.function().text().find("fnv1a"), std::string::npos) << m.function().text();
    }
  }
  EXPECT_TRUE(saw);
  EXPECT_EQ(indexes.size(), fns.size());

  // Named entries at a pinned revision (before the rename); an address with
  // no function is a result with an error. Decompiled before: served first.
  got.clear();
  dm.clear_all();
  dm.add_functions()->set_offset(0x10);
  dm.add_functions()->set_offset(checksum);
  dm.mutable_read()->set_revision(after - 1);
  dm.set_parallelism(1);
  ASSERT_TRUE(backend_->DecompileMany(ctx_, dm, collect).ok());
  ASSERT_EQ(got.size(), 2u);
  for (const auto &m : got) {
    EXPECT_EQ(m.snapshot().revision(), after - 1);
    if (m.index() == 0) {
      EXPECT_NE(m.error().find("no function"), std::string::npos);
    } else {
      EXPECT_EQ(m.entry().offset(), checksum);
      EXPECT_TRUE(m.served_before());
      EXPECT_NE(m.function().text().find("checksum"), std::string::npos);
    }
  }
  dm.mutable_options()->set_escalate(true);
  EXPECT_EQ(backend_->DecompileMany(ctx_, dm, collect).code, StatusCode::kInvalidArgument);
  // A client that goes away stops it.
  dm.mutable_options()->set_escalate(false);
  dm.clear_functions();
  dm.clear_read();
  dm.set_all(true);
  int writes = 0;
  auto st = backend_->DecompileMany(ctx_, dm, [&](const pb::DecompileManyResponse &) { return ++writes < 1; });
  EXPECT_EQ(st.code, StatusCode::kCancelled);

  // FindBytes: the FNV offset basis inside checksum, exactly and masked.
  pb::FindBytesRequest fb;
  fb.set_program_id(id);
  fb.set_pattern(std::string("\xc5\x9d\x1c\x81", 4));
  pb::FindBytesResponse fr;
  fr.Clear();
  fr.Clear();
  ASSERT_TRUE(backend_->FindBytes(ctx_, fb, fr).ok());
  ASSERT_GE(fr.addresses_size(), 1);
  EXPECT_GE(fr.addresses(0).offset(), checksum);
  EXPECT_LT(fr.addresses(0).offset(), checksum + 0x40);
  EXPECT_GT(fr.bytes_searched(), 0u);
  const std::uint64_t hit = fr.addresses(0).offset();
  fb.set_pattern(std::string("\xc5\x9d\x00\x81", 4));
  fb.set_mask(std::string("\xff\xff\x00\xff", 4));
  fr.Clear();
  fr.Clear();
  ASSERT_TRUE(backend_->FindBytes(ctx_, fb, fr).ok());
  ASSERT_GE(fr.addresses_size(), 1);
  EXPECT_EQ(fr.addresses(0).offset(), hit);
  // Wildcards only (the ELF header, then truncated at one).
  fb.set_pattern(std::string("\x7f" "ELF", 4));
  fb.clear_mask();
  fb.set_max_results(1);
  fr.Clear();
  fr.Clear();
  ASSERT_TRUE(backend_->FindBytes(ctx_, fb, fr).ok());
  fb.set_pattern(std::string(2, '\0'));
  fb.set_mask(std::string(2, '\0'));
  fr.Clear();
  fr.Clear();
  ASSERT_TRUE(backend_->FindBytes(ctx_, fb, fr).ok());
  EXPECT_EQ(fr.addresses_size(), 1);
  EXPECT_TRUE(fr.truncated());
  fb.set_mask(std::string(3, '\xff'));
  EXPECT_EQ(backend_->FindBytes(ctx_, fb, fr).code, StatusCode::kInvalidArgument);
  // A range that excludes the hit.
  fb.set_pattern(std::string("\xc5\x9d\x1c\x81", 4));
  fb.clear_mask();
  fb.set_max_results(0);
  fb.mutable_range()->mutable_first()->set_offset(hit + 1);
  fb.mutable_range()->mutable_last()->set_offset(hit + 0x10);
  fr.Clear();
  fr.Clear();
  ASSERT_TRUE(backend_->FindBytes(ctx_, fb, fr).ok());
  EXPECT_EQ(fr.addresses_size(), 0);

  // ListInstructions over checksum's body, with p-code, in address order.
  pb::ListInstructionsRequest li;
  li.set_program_id(id);
  li.mutable_function()->set_offset(checksum);
  std::vector<pb::InstructionDetail> insns;
  bool truncated = false;
  auto take = [&](const pb::ListInstructionsResponse &m) {
    for (const auto &i : m.instructions()) insns.push_back(i);
    truncated = truncated || m.truncated();
    return true;
  };
  ASSERT_TRUE(backend_->ListInstructions(ctx_, li, take).ok());
  ASSERT_GT(insns.size(), 3u);
  EXPECT_EQ(insns.front().address().offset(), checksum);
  std::size_t with_pcode = 0;
  for (std::size_t i = 0; i < insns.size(); ++i) {
    if (i) EXPECT_GT(insns[i].address().offset(), insns[i - 1].address().offset());
    EXPECT_EQ(insns[i].function().offset(), checksum);
    with_pcode += insns[i].pcode_size() > 0;
  }
  EXPECT_GT(with_pcode, insns.size() / 2);
  const std::size_t n = insns.size();
  insns.clear();
  li.set_omit_pcode(true);
  li.set_limit(2);
  ASSERT_TRUE(backend_->ListInstructions(ctx_, li, take).ok());
  ASSERT_EQ(insns.size(), 2u);
  EXPECT_EQ(insns[0].pcode_size(), 0);
  EXPECT_TRUE(truncated);
  // A range: the same instructions as the body when it is contiguous.
  insns.clear();
  li.clear_limit();
  li.mutable_range()->mutable_first()->set_offset(checksum);
  li.mutable_range()->mutable_last()->set_offset(checksum + 0x1000);
  ASSERT_TRUE(backend_->ListInstructions(ctx_, li, take).ok());
  EXPECT_GE(insns.size(), n);
  li.mutable_function()->set_offset(0x10);
  EXPECT_EQ(backend_->ListInstructions(ctx_, li, take).code, StatusCode::kNotFound);
}

TEST_F(ImageBackendTest, RenameReachesDecompileListingAndEvents) {
  std::string id = Import(exe_);
  auto fns = Functions(id);
  const std::uint64_t main = fns.at("main"), checksum = fns.at("checksum"), twice = fns.at("twice");

  auto sink = std::make_shared<Sink>();
  std::unique_ptr<api::Subscription> sub;
  pb::SubscribeRequest sreq;
  sreq.set_project_id("default");
  ASSERT_TRUE(backend_->Subscribe(ctx_, sreq, sink, sub).ok());

  pb::DecompiledFunction before = Decompile(id, main);
  EXPECT_NE(Text(before).find("checksum("), std::string::npos);
  const std::uint64_t r0 = before.origin().computed_at_revision();

  pb::AppendAssertionsResponse appended;
  ASSERT_TRUE(Rename(id, checksum, "fnv1a", "alice", &appended).ok());
  const std::uint64_t r1 = appended.snapshot().revision();
  auto events = sink->revisions();
  ASSERT_EQ(events.size(), 1u);
  std::set<std::uint64_t> decompiles;
  for (const auto &q : events[0].invalidated())
    if (q.kind() == pb::QUERY_KIND_DECOMPILE) decompiles.insert(q.address().offset());
  EXPECT_TRUE(decompiles.contains(main) && decompiles.contains(twice) && decompiles.contains(checksum));

  EXPECT_NE(Text(Decompile(id, main)).find("fnv1a("), std::string::npos);
  EXPECT_NE(Text(Decompile(id, twice)).find("fnv1a("), std::string::npos);
  pb::DecompiledFunction self = Decompile(id, checksum);
  EXPECT_EQ(self.name(), "fnv1a");
  EXPECT_NE(self.prototype().c_declaration().find("fnv1a("), std::string::npos);
  // The old snapshot still decompiles with the old name.
  EXPECT_NE(Text(Decompile(id, main, r0)).find("checksum("), std::string::npos);

  pb::GetListingRequest lr;
  lr.set_program_id(id);
  lr.mutable_addresses()->mutable_start()->set_offset(checksum);
  lr.mutable_addresses()->set_max_rows(1);
  pb::GetListingResponse listing;
  ASSERT_TRUE(backend_->GetListing(ctx_, lr, listing).ok());
  EXPECT_EQ(listing.rows(0).labels(0).name(), "fnv1a");
  EXPECT_TRUE(listing.rows(0).labels(0).origin().has_asserted());

  // Retracting restores the default everywhere.
  pb::RetractAssertionsRequest rr;
  rr.set_program_id(id);
  rr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  rr.add_seqs(appended.assertions(0).seq());
  pb::RetractAssertionsResponse rresp;
  ASSERT_TRUE(backend_->RetractAssertions(ctx_, rr, rresp).ok());
  EXPECT_GT(rresp.snapshot().revision(), r1);
  EXPECT_NE(Text(Decompile(id, main)).find("checksum("), std::string::npos);
  EXPECT_EQ(sink->revisions().size(), 2u);
}

TEST_F(ImageBackendTest, LocalsCommentsAndValidation) {
  std::string id = Import(exe_);
  const std::uint64_t checksum = Functions(id).at("checksum");
  pb::DecompiledFunction f = Decompile(id, checksum);
  ASSERT_GE(f.prototype().parameter_indices_size(), 2);
  const pb::Variable &p0 = f.variables(static_cast<int>(f.prototype().parameter_indices(0)));
  EXPECT_EQ(p0.storage_key(), "param:0");

  pb::AppendAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_AGENT);
  req.mutable_provenance()->set_id("claude");
  auto *local = req.add_assertions()->mutable_body()->mutable_rename();
  local->mutable_target()->mutable_local()->mutable_function()->set_offset(checksum);
  local->mutable_target()->mutable_local()->set_storage_key("param:0");
  local->set_name("buf");
  auto *retype = req.add_assertions()->mutable_body()->mutable_retype();
  retype->mutable_target()->mutable_local()->mutable_function()->set_offset(checksum);
  retype->mutable_target()->mutable_local()->set_storage_key("param:0");
  retype->mutable_type()->set_c_declaration("const uint8_t *");
  auto *c = req.add_assertions()->mutable_body()->mutable_comment();
  c->mutable_address()->set_offset(checksum);
  c->set_kind(pb::COMMENT_KIND_PLATE);
  c->set_text("FNV-1a");
  pb::AppendAssertionsResponse resp;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, resp).ok());

  f = Decompile(id, checksum);
  std::string text = Text(f);
  EXPECT_NE(text.find("/* FNV-1a */"), std::string::npos) << text;
  EXPECT_NE(f.prototype().c_declaration().find("buf"), std::string::npos);
  const pb::Variable &renamed = f.variables(static_cast<int>(f.prototype().parameter_indices(0)));
  EXPECT_EQ(renamed.name(), "buf");
  EXPECT_TRUE(renamed.name_origin().has_asserted());
  EXPECT_EQ(renamed.type().display(), "const uint8_t *");
  for (const auto &line : f.lines())
    for (const auto &t : line.tokens())
      if (t.has_variable_index() && t.variable_index() == renamed.index()) {
        EXPECT_EQ(t.text(), "buf");
      }
  // The asserted type is printed where the parameter is declared.
  EXPECT_NE(text.find("const uint8_t *buf"), std::string::npos) << text;
  EXPECT_NE(f.prototype().c_declaration().find("const uint8_t *buf"), std::string::npos)
      << f.prototype().c_declaration();

  // A storage key the function doesn't have, and an unmapped address.
  local->mutable_target()->mutable_local()->set_storage_key("stack:-0x9999");
  EXPECT_EQ(backend_->AppendAssertions(ctx_, req, resp).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Rename(id, 0x10, "nowhere").code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Rename(id, checksum, "has space").code, StatusCode::kInvalidArgument);
}

// Code-unit rows in display order, with their display row numbers, from
// GetListing with header rows at a revision.
struct HeaderListing {
  std::int64_t total = 0;
  std::vector<std::pair<std::uint64_t, std::int64_t>> units;  // (address, display row)
  std::vector<pb::ListingRow> headers;
};

TEST_F(ImageBackendTest, HeaderRowsNumberingAndWindows) {
  std::string id = Import(exe_);
  auto fns = Functions(id);
  const std::uint64_t checksum = fns.at("checksum"), main = fns.at("main");

  auto read = [&](bool headers, std::uint64_t revision = 0) {
    HeaderListing out;
    pb::GetListingRequest req;
    req.set_program_id(id);
    req.set_header_rows(headers);
    req.set_omit_bytes(true);
    req.mutable_read()->set_revision(revision);
    for (std::int64_t first = 0;; first += 2000) {
      req.mutable_rows()->set_first_row(first);
      req.mutable_rows()->set_row_count(2000);
      pb::GetListingResponse resp;
      EXPECT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
      out.total = resp.total_rows();
      for (int i = 0; i < resp.rows_size(); ++i) {
        const pb::ListingRow &row = resp.rows(i);
        EXPECT_EQ(row.row(), first + i);
        if (row.kind() == pb::LISTING_ROW_KIND_HEADER) out.headers.push_back(row);
        else out.units.emplace_back(row.address().offset(), row.row());
      }
      if (first + 2000 >= resp.total_rows()) break;
    }
    return out;
  };

  // The same code units in the same order, with header lines between.
  HeaderListing plain = read(false), shown = read(true);
  ASSERT_EQ(plain.units.size(), shown.units.size());
  for (std::size_t i = 0; i < plain.units.size(); ++i) ASSERT_EQ(plain.units[i].first, shown.units[i].first);
  EXPECT_EQ(shown.total, plain.total + static_cast<std::int64_t>(shown.headers.size()));
  // Every function has a signature then its label above its entry.
  std::map<std::uint64_t, std::vector<pb::ListingHeaderKind>> above;
  for (const auto &h : shown.headers) above[h.address().offset()].push_back(h.header().kind());
  for (const auto &[name, entry] : fns)
    EXPECT_EQ(above[entry], (std::vector<pb::ListingHeaderKind>{pb::LISTING_HEADER_KIND_SIGNATURE,
                                                                pb::LISTING_HEADER_KIND_LABEL}))
        << name;
  for (const auto &h : shown.headers)
    if (h.address().offset() == checksum && h.header().kind() == pb::LISTING_HEADER_KIND_SIGNATURE)
      EXPECT_EQ(h.header().text(), "undefined checksum()");

  // An address window anchors on the code unit; rows_before shows its headers.
  pb::GetListingRequest at;
  at.set_program_id(id);
  at.set_header_rows(true);
  at.mutable_addresses()->mutable_start()->set_offset(checksum);
  at.mutable_addresses()->set_max_rows(4);
  at.mutable_addresses()->set_rows_before(2);
  pb::GetListingResponse ar;
  ASSERT_TRUE(backend_->GetListing(ctx_, at, ar).ok());
  ASSERT_EQ(ar.rows_size(), 4);
  EXPECT_EQ(ar.rows(0).header().kind(), pb::LISTING_HEADER_KIND_SIGNATURE);
  EXPECT_EQ(ar.rows(1).header().kind(), pb::LISTING_HEADER_KIND_LABEL);
  EXPECT_EQ(ar.rows(1).labels(0).name(), "checksum");
  EXPECT_EQ(ar.rows(2).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_EQ(ar.rows(2).address().offset(), checksum);
  EXPECT_TRUE(ar.rows(2).function_entry());

  auto sink = std::make_shared<Sink>();
  std::unique_ptr<api::Subscription> sub;
  pb::SubscribeRequest sreq;
  sreq.set_project_id("default");
  ASSERT_TRUE(backend_->Subscribe(ctx_, sreq, sink, sub).ok());

  // Every code unit moves by the windows before it: rows before a window
  // keep their numbers, rows after it shift by its size change.
  auto check = [&](const HeaderListing &before, const HeaderListing &after, const pb::RevisionEvent &ev) {
    std::vector<const pb::InvalidatedQuery *> windows;
    for (const auto &q : ev.invalidated())
      if (q.kind() == pb::QUERY_KIND_LISTING && q.has_header_rows()) windows.push_back(&q);
    EXPECT_FALSE(windows.empty());
    std::map<std::uint64_t, std::int64_t> now(after.units.begin(), after.units.end());
    for (const auto &[addr, row] : before.units) {
      std::int64_t moved = row;
      bool inside = false;
      for (const auto *q : windows) {
        const auto &p = q->previous_header_rows();
        if (row >= p.first_row() + static_cast<std::int64_t>(p.row_count())) moved += static_cast<std::int64_t>(q->header_rows().row_count()) - p.row_count();
        else if (row >= p.first_row()) inside = true;
      }
      if (!inside && now.contains(addr)) EXPECT_EQ(now[addr], moved) << std::hex << addr;
    }
    std::int64_t delta = 0;
    for (const auto *q : windows) delta += static_cast<std::int64_t>(q->header_rows().row_count()) - q->previous_header_rows().row_count();
    EXPECT_EQ(after.total, before.total + delta);
  };

  // A name on an unlabelled instruction adds a label line.
  const std::uint64_t inner = shown.units[std::find_if(shown.units.begin(), shown.units.end(),
                                                       [&](auto &u) { return u.first == checksum; }) - shown.units.begin() + 1].first;
  pb::AppendAssertionsResponse appended;
  ASSERT_TRUE(Rename(id, inner, "inner", "alice", &appended).ok());
  HeaderListing renamed = read(true);
  ASSERT_EQ(sink->revisions().size(), 1u);
  check(shown, renamed, sink->revisions().back());
  EXPECT_EQ(renamed.total, shown.total + 1);

  // A two-line plate comment adds two lines above main.
  pb::AppendAssertionsRequest creq;
  creq.set_program_id(id);
  creq.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  creq.mutable_provenance()->set_id("alice");
  auto *c = creq.add_assertions()->mutable_body()->mutable_comment();
  c->mutable_address()->set_offset(main);
  c->set_kind(pb::COMMENT_KIND_PLATE);
  c->set_text("entry point\nof the test");
  pb::AppendAssertionsResponse cresp;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, creq, cresp).ok());
  HeaderListing plated = read(true);
  check(renamed, plated, sink->revisions().back());
  EXPECT_EQ(plated.total, renamed.total + 2);
  at.mutable_addresses()->mutable_start()->set_offset(main);
  at.mutable_addresses()->set_rows_before(4);
  ar.Clear();
  ASSERT_TRUE(backend_->GetListing(ctx_, at, ar).ok());
  EXPECT_EQ(ar.rows(0).header().kind(), pb::LISTING_HEADER_KIND_PLATE);
  EXPECT_EQ(ar.rows(0).header().text(), "entry point");
  EXPECT_EQ(ar.rows(1).header().text(), "of the test");
  EXPECT_EQ(ar.rows(1).header().line(), 1u);
  EXPECT_TRUE(ar.rows(1).header().origin().has_asserted());

  // A function asserted at the labelled instruction: a signature line, and
  // checksum's body changes (rows rebuilt or not, the numbering holds).
  pb::AppendAssertionsRequest breq;
  breq.set_program_id(id);
  breq.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  breq.mutable_provenance()->set_id("alice");
  breq.add_assertions()->mutable_body()->mutable_function_bounds()->mutable_entry()->set_offset(inner);
  pb::AppendAssertionsResponse bresp;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, breq, bresp).ok());
  HeaderListing bounded = read(true);
  check(plated, bounded, sink->revisions().back());

  // Undo all three: back to the original numbering.
  pb::RetractAssertionsRequest rr;
  rr.set_program_id(id);
  rr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  rr.add_seqs(bresp.assertions(0).seq());
  rr.add_seqs(cresp.assertions(0).seq());
  rr.add_seqs(appended.assertions(0).seq());
  pb::RetractAssertionsResponse rresp;
  ASSERT_TRUE(backend_->RetractAssertions(ctx_, rr, rresp).ok());
  HeaderListing undone = read(true);
  check(bounded, undone, sink->revisions().back());
  EXPECT_EQ(undone.total, shown.total);
}

TEST_F(ImageBackendTest, ListingFlowAndOverrides) {
  std::string id = Import(exe_);
  auto fns = Functions(id);
  const std::uint64_t checksum = fns.at("checksum"), main = fns.at("main");
  auto rows = [&](std::uint64_t start, int n) {
    pb::GetListingRequest req;
    req.set_program_id(id);
    req.mutable_addresses()->mutable_start()->set_offset(start);
    req.mutable_addresses()->set_max_rows(static_cast<std::uint32_t>(n));
    pb::GetListingResponse resp;
    EXPECT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
    return resp;
  };
  // checksum's loop: a conditional branch inside the function.
  bool branch = false;
  const pb::GetListingResponse loop = rows(checksum, 20);
  for (const auto &r : loop.rows()) {
    if (r.function().offset() != checksum || r.flow() != pb::FLOW_KIND_CONDITIONAL_BRANCH) continue;
    ASSERT_EQ(r.flow_targets_size(), 1);
    EXPECT_GE(r.flow_targets(0).offset(), checksum);
    branch = true;
  }
  EXPECT_TRUE(branch);
  // main's call to checksum, then overridden as a tail call and as a branch.
  std::uint64_t call = 0;
  const pb::GetListingResponse calls = rows(main, 20);
  for (const auto &r : calls.rows())
    if (r.flow() == pb::FLOW_KIND_CALL && r.flow_targets_size() == 1 && r.flow_targets(0).offset() == checksum && !call)
      call = r.address().offset();
  ASSERT_NE(call, 0u);
  for (auto kind : {pb::FLOW_OVERRIDE_KIND_BRANCH, pb::FLOW_OVERRIDE_KIND_RETURN}) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    auto *f = req.add_assertions()->mutable_body()->mutable_flow_override();
    f->mutable_address()->set_offset(call);
    f->set_kind(kind);
    pb::AppendAssertionsResponse resp;
    ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, resp).ok());
    const pb::ListingRow r = rows(call, 1).rows(0);
    EXPECT_EQ(r.flow_override(), kind);
    EXPECT_TRUE(r.flow_override_origin().has_asserted());
    EXPECT_EQ(r.flow(), kind == pb::FLOW_OVERRIDE_KIND_BRANCH ? pb::FLOW_KIND_UNCONDITIONAL_BRANCH : pb::FLOW_KIND_RETURN);
  }

  // A global's asserted type shows on its row.
  pb::ListSymbolsRequest sr;
  sr.set_program_id(id);
  sr.set_name_equals("counter");
  pb::ListSymbolsResponse sresp;
  ASSERT_TRUE(backend_->ListSymbols(ctx_, sr, sresp).ok());
  ASSERT_EQ(sresp.symbols_size(), 1);
  const std::uint64_t counter = sresp.symbols(0).address().offset();
  pb::AppendAssertionsRequest tr;
  tr.set_program_id(id);
  tr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  tr.mutable_provenance()->set_id("alice");
  auto *t = tr.add_assertions()->mutable_body()->mutable_retype();
  t->mutable_target()->mutable_address()->set_offset(counter);
  t->mutable_type()->set_c_declaration("unsigned int");
  pb::AppendAssertionsResponse tresp;
  ASSERT_TRUE(backend_->AppendAssertions(ctx_, tr, tresp).ok());
  EXPECT_EQ(rows(counter, 1).rows(0).data_type(), "unsigned int");
}

TEST_F(ImageBackendTest, ListFunctionsByOffset) {
  std::string id = Import(exe_);
  pb::ListFunctionsRequest req;
  req.set_program_id(id);
  pb::ListFunctionsResponse all;
  ASSERT_TRUE(backend_->ListFunctions(ctx_, req, all).ok());
  ASSERT_GE(all.functions_size(), 4);
  EXPECT_EQ(all.page().total_count(), all.functions_size());
  for (std::uint64_t off : {std::uint64_t{1}, std::uint64_t{3}}) {
    req.set_offset(off);
    req.mutable_page()->set_page_size(2);
    pb::ListFunctionsResponse page;
    ASSERT_TRUE(backend_->ListFunctions(ctx_, req, page).ok());
    ASSERT_EQ(page.functions_size(), 2);
    EXPECT_EQ(page.functions(0).SerializeAsString(), all.functions(static_cast<int>(off)).SerializeAsString());
    EXPECT_EQ(page.page().total_count(), all.functions_size());
  }
  // Filtered by name, with an offset into the matches.
  req.set_name_contains("CHECK");
  req.set_offset(0);
  pb::ListFunctionsResponse named;
  ASSERT_TRUE(backend_->ListFunctions(ctx_, req, named).ok());
  ASSERT_EQ(named.functions_size(), 1);
  EXPECT_EQ(named.functions(0).name(), "checksum");
  req.set_offset(1);
  named.Clear();
  ASSERT_TRUE(backend_->ListFunctions(ctx_, req, named).ok());
  EXPECT_EQ(named.functions_size(), 0);
}

// DefineType (api_minor 4): a recursive struct, a pointer to it and a
// function type defined in one request, then the function retyped by the
// hash validate_only reported. The prototype reaches the decompiler and
// GetTypes describes the types field by field.
TEST_F(ImageBackendTest, DefinedTypesReachGetTypesAndThePrototype) {
  std::string id = Import(exe_);
  const std::uint64_t checksum = Functions(id).at("checksum");

  pb::AppendAssertionsRequest req;
  req.set_program_id(id);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_IMPORT);
  req.mutable_provenance()->set_id("ghidra");
  auto define = [&]() { return req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type(); };
  pb::TypeNode *node = define();  // 0: struct node { int value; struct node *next; }
  node->set_kind(pb::TYPE_KIND_STRUCT);
  node->set_name("node");
  node->set_size(16);
  auto *value = node->add_fields();
  value->set_name("value");
  value->mutable_type()->set_assertion_index(2);
  auto *next = node->add_fields();
  next->set_name("next");
  next->set_offset(8);
  next->mutable_type()->set_assertion_index(1);
  pb::TypeNode *ptr = define();  // 1: struct node *
  ptr->set_kind(pb::TYPE_KIND_POINTER);
  ptr->mutable_target()->set_assertion_index(0);
  pb::TypeNode *i32 = define();  // 2: int
  i32->set_kind(pb::TYPE_KIND_INT);
  i32->set_size(4);
  i32->set_rank(pb::INTEGER_RANK_INT);
  pb::TypeNode *u32 = define();  // 3: unsigned int
  u32->set_kind(pb::TYPE_KIND_UINT);
  u32->set_size(4);
  u32->set_rank(pb::INTEGER_RANK_INT);
  pb::TypeNode *fn = define();  // 4: unsigned (struct node *list, int n)
  fn->set_kind(pb::TYPE_KIND_FUNCTION);
  fn->mutable_target()->set_assertion_index(3);
  auto *p0 = fn->add_params();
  p0->set_name("list");
  p0->mutable_type()->set_assertion_index(1);
  auto *p1 = fn->add_params();
  p1->set_name("n");
  p1->mutable_type()->set_assertion_index(2);

  req.set_validate_only(true);
  pb::AppendAssertionsResponse checked;
  auto st = backend_->AppendAssertions(ctx_, req, checked);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(checked.assertions_size(), 5);
  std::vector<std::string> hashes;
  for (const auto &a : checked.assertions()) {
    EXPECT_EQ(a.key().kind(), pb::FACT_KIND_TYPE_DEF);
    EXPECT_EQ(a.key().sub().size(), 32u);
    hashes.push_back(a.key().sub());
  }
  // Stored bodies name what they reference by hash.
  EXPECT_EQ(checked.assertions(1).body().define_type().type().target().hash(), hashes[0]);

  req.set_validate_only(false);
  auto *retype = req.add_assertions()->mutable_body()->mutable_retype();
  retype->mutable_target()->mutable_address()->set_offset(checksum);
  retype->mutable_type()->set_type_hash(hashes[4]);
  pb::AppendAssertionsResponse appended;
  st = backend_->AppendAssertions(ctx_, req, appended);
  ASSERT_TRUE(st.ok()) << st.message;
  for (int i = 0; i < 5; ++i) EXPECT_EQ(appended.assertions(i).key().sub(), hashes[static_cast<std::size_t>(i)]);

  pb::DecompiledFunction f = Decompile(id, checksum);
  EXPECT_NE(f.prototype().c_declaration().find("node *list"), std::string::npos) << f.prototype().c_declaration();

  pb::GetTypesRequest treq;
  treq.set_program_id(id);
  treq.add_hashes(hashes[0]);
  treq.set_include_dependencies(true);
  pb::GetTypesResponse types;
  ASSERT_TRUE(backend_->GetTypes(ctx_, treq, types).ok());
  ASSERT_EQ(types.types_size(), 3);  // node, node *, int
  const pb::TypeDefinition &t = types.types(0);
  EXPECT_EQ(t.kind(), pb::TYPE_KIND_STRUCT);
  EXPECT_EQ(t.name(), "node");
  EXPECT_EQ(t.size(), 16u);
  EXPECT_TRUE(t.complete());
  ASSERT_EQ(t.composite().fields_size(), 2);
  EXPECT_EQ(t.composite().fields(1).offset(), 8u);
  EXPECT_EQ(t.composite().fields(1).type_hash(), hashes[1]);
  EXPECT_TRUE(t.origin().has_asserted());
  for (const auto &d : types.types())
    if (d.hash() == hashes[2]) {
      EXPECT_EQ(d.kind(), pb::TYPE_KIND_INT);
      EXPECT_EQ(d.rank(), pb::INTEGER_RANK_INT);
      EXPECT_EQ(d.display(), "int");
    }

  // The same types described again, in another order, hash the same.
  pb::AppendAssertionsRequest again;
  again.set_program_id(id);
  again.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  again.set_validate_only(true);
  pb::TypeNode *p = again.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  p->set_kind(pb::TYPE_KIND_POINTER);
  p->mutable_target()->set_assertion_index(1);
  pb::TypeNode *s = again.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
  *s = *node;
  s->mutable_fields(0)->mutable_type()->set_hash(hashes[2]);
  s->mutable_fields(1)->mutable_type()->set_assertion_index(0);
  pb::AppendAssertionsResponse same;
  st = backend_->AppendAssertions(ctx_, again, same);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(same.assertions(0).key().sub(), hashes[1]);
  EXPECT_EQ(same.assertions(1).key().sub(), hashes[0]);

  // References must name a define_type of the request or a known hash.
  s->mutable_fields(1)->mutable_type()->set_assertion_index(7);
  EXPECT_EQ(backend_->AppendAssertions(ctx_, again, same).code, StatusCode::kInvalidArgument);
  s->mutable_fields(1)->mutable_type()->set_hash(std::string(32, '0'));
  EXPECT_EQ(backend_->AppendAssertions(ctx_, again, same).code, StatusCode::kInvalidArgument);
}

// Types for tests, as DefineType nodes in one request: each returns its
// assertion index.
struct TypeNodes {
  pb::AppendAssertionsRequest req;
  int Add(const pb::TypeNode &n) {
    *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = n;
    return req.assertions_size() - 1;
  }
  int Int(std::uint32_t size, pb::IntegerRank rank) {
    pb::TypeNode n;
    n.set_kind(pb::TYPE_KIND_INT);
    n.set_size(size);
    n.set_rank(rank);
    return Add(n);
  }
  int Pointer(int to) {
    pb::TypeNode n;
    n.set_kind(pb::TYPE_KIND_POINTER);
    n.mutable_target()->set_assertion_index(static_cast<std::uint32_t>(to));
    return Add(n);
  }
  int Struct(const std::string &name, std::uint64_t size, const std::vector<std::tuple<std::string, std::uint64_t, int>> &fields) {
    pb::TypeNode n;
    n.set_kind(pb::TYPE_KIND_STRUCT);
    n.set_name(name);
    n.set_size(size);
    for (const auto &[fname, off, type] : fields) {
      auto *f = n.add_fields();
      f->set_name(fname);
      f->set_offset(off);
      f->mutable_type()->set_assertion_index(static_cast<std::uint32_t>(type));
    }
    return Add(n);
  }
  int Function(int ret, const std::vector<std::pair<std::string, int>> &params, const std::string &cc = {}) {
    pb::TypeNode n;
    n.set_kind(pb::TYPE_KIND_FUNCTION);
    n.mutable_target()->set_assertion_index(static_cast<std::uint32_t>(ret));
    n.set_calling_convention(cc);
    for (const auto &[pname, type] : params) {
      auto *p = n.add_params();
      p->set_name(pname);
      p->mutable_type()->set_assertion_index(static_cast<std::uint32_t>(type));
    }
    return Add(n);
  }
  // Applies type `fn` (an index of this request) to the function at `entry`.
  void Retype(std::uint64_t entry, int fn) { retypes.emplace_back(entry, fn); }
  std::vector<std::pair<std::uint64_t, int>> retypes;
  // Appends the request: its types (their hashes from a validate_only
  // pass), then the retypes by hash.
  api::Status Commit(api::Backend &backend, const CallContext &ctx, pb::AppendAssertionsResponse &resp) {
    if (!retypes.empty()) {
      pb::AppendAssertionsRequest check = req;
      check.set_validate_only(true);
      pb::AppendAssertionsResponse checked;
      if (auto st = backend.AppendAssertions(ctx, check, checked); !st.ok()) return st;
      for (const auto &[entry, fn] : retypes) {
        auto *r = req.add_assertions()->mutable_body()->mutable_retype();
        r->mutable_target()->mutable_address()->set_offset(entry);
        r->mutable_type()->set_type_hash(checked.assertions(fn).key().sub());
      }
    }
    return backend.AppendAssertions(ctx, req, resp);
  }
};

// Field tokens (api_minor 38, feature "field-tokens") carry their struct's
// hash and the field's offset, and follow an edit of the struct (a new
// definition bound to its name, as the type editor and Rename Field save).
TEST_F(ImageBackendTest, FieldTokensNameTheirStructAndOffset) {
  constexpr const char *kFields = R"(
struct pair { int a; int b; long c; };
__attribute__((noinline)) long sum(struct pair *p) { return p->a + p->b * 3 + p->c; }
int main(int argc, char **argv) {
  struct pair q = {argc, argc + 1, (long)argv};
  return (int)sum(&q);
}
)";
  auto exe = testing::scratch_dir("image-backend-fields") / "fields";
  if (!testing::compile(REVKIT_TEST_CC, kFields, "-O1", exe)) GTEST_SKIP() << "no C compiler";
  std::string id = Import(exe);
  const std::uint64_t sum = Functions(id).at("sum");

  auto define = [&](const std::string &b_name, bool bind) {
    TypeNodes t;
    t.req.set_program_id(id);
    t.req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    const int i32 = t.Int(4, pb::INTEGER_RANK_INT), i64 = t.Int(8, pb::INTEGER_RANK_LONG);
    const int pair = t.Struct("pair", 16, {{"a", 0, i32}, {b_name, 4, i32}, {"c", 8, i64}});
    if (bind) t.req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(
        static_cast<std::uint32_t>(pair));
    else t.Retype(sum, t.Function(i64, {{"p", t.Pointer(pair)}}));
    pb::AppendAssertionsResponse resp;
    auto st = t.Commit(*backend_, ctx_, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.assertions(pair).key().sub();
  };
  // Field tokens of `sum` by name: (parent hash, offset).
  auto fields = [&](const pb::DecompiledFunction &f) {
    std::map<std::string, std::pair<std::string, std::uint64_t>> out;
    for (const auto &line : f.lines())
      for (const auto &t : line.tokens())
        if (t.kind() == pb::CODE_TOKEN_KIND_FIELD) {
          EXPECT_TRUE(t.has_field_offset()) << t.text();
          out[t.text()] = {t.parent_type_hash(), t.field_offset()};
        }
    return out;
  };

  const std::string pair = define("b", false);
  pb::DecompiledFunction f = Decompile(id, sum);
  auto got = fields(f);
  ASSERT_EQ(got.size(), 3u) << f.text();
  EXPECT_EQ(got["a"], std::make_pair(pair, std::uint64_t{0}));
  EXPECT_EQ(got["b"], std::make_pair(pair, std::uint64_t{4}));
  EXPECT_EQ(got["c"], std::make_pair(pair, std::uint64_t{8}));
  // Other tokens carry neither.
  for (const auto &line : f.lines())
    for (const auto &t : line.tokens())
      if (t.kind() != pb::CODE_TOKEN_KIND_FIELD) EXPECT_TRUE(!t.has_field_offset() && t.parent_type_hash().empty()) << t.text();

  // b renamed: the new definition, bound to "struct pair".
  const std::string renamed = define("count", true);
  ASSERT_NE(renamed, pair);
  f = Decompile(id, sum);
  got = fields(f);
  EXPECT_NE(f.text().find("p->count"), std::string::npos) << f.text();
  EXPECT_EQ(got["count"], std::make_pair(renamed, std::uint64_t{4}));
  EXPECT_EQ(got["c"], std::make_pair(renamed, std::uint64_t{8}));
}

// A prototype's calling convention reaches the decompiler as the compiler
// spec's prototype model (32-bit Windows: __stdcall, the default,
// __cdecl, __fastcall, __thiscall): the callee's parameters come from its
// registers or stack, and callers pass them so. One the spec lacks is the
// default with a warning; no convention is the default as before.
TEST_F(ImageBackendTest, PrototypeCallingConventionsReachTheDecompiler) {
  constexpr const char *kConventions = R"(
__attribute__((noinline)) int __fastcall fmix(int a, int b, int c) { return a * 3 + b * 5 - c; }
__attribute__((noinline)) int __stdcall smix(int a, int b) { return a * 7 - b; }
volatile int sink;
int start(int n) {
  volatile int keep = n * 13;
  sink = fmix(n, n + 1, 9);
  sink = smix(n, 11);
  return keep;
}
)";
  if (std::string(REVKIT_TEST_CLANG).empty() || std::string(REVKIT_TEST_LLD).empty()) GTEST_SKIP() << "needs clang and lld";
  auto exe = testing::scratch_dir("image-backend-conventions") / "conv.exe";
  if (!testing::compile(REVKIT_TEST_CLANG, kConventions,
                        "--target=i686-w64-mingw32 -O1 -ffreestanding -nostdlib -fuse-ld=lld -Wl,-e,_start", exe))
    GTEST_SKIP() << "clang can't build an i386 PE";
  std::string id = Import(exe);
  // No symbols: fmix and smix come first in .text, then start (the entry).
  std::vector<std::uint64_t> entries;
  for (const auto &[name, entry] : Functions(id)) entries.push_back(entry);
  std::sort(entries.begin(), entries.end());
  ASSERT_EQ(entries.size(), 3u);
  const std::uint64_t fmix = entries[0], smix = entries[1], start = entries[2];
  ASSERT_EQ(Functions(id).at("entry"), start);
  auto call = [](std::uint64_t entry, const std::string &args) {
    char name[32];
    std::snprintf(name, sizeof name, "FUN_%08llx", static_cast<unsigned long long>(entry));
    return std::string(name) + "(" + args + ")";
  };

  auto set = [&](std::uint64_t entry, const std::string &name, int params, const std::string &cc) {
    TypeNodes t;
    t.req.set_program_id(id);
    t.req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    const int i32 = t.Int(4, pb::INTEGER_RANK_INT);
    std::vector<std::pair<std::string, int>> ps;
    for (int i = 0; i < params; ++i) ps.emplace_back(std::string(1, static_cast<char>('a' + i)), i32);
    t.Retype(entry, t.Function(i32, ps, cc));
    pb::AppendAssertionsResponse resp;
    auto st = t.Commit(*backend_, ctx_, resp);
    EXPECT_TRUE(st.ok()) << name << ": " << st.message;
    return resp.snapshot().revision();
  };

  // No convention: the spec's default (__stdcall here), all on the stack;
  // fmix's register parameters are read as unassigned registers.
  set(fmix, "fmix", 3, "");
  pb::DecompiledFunction f = Decompile(id, fmix);
  EXPECT_EQ(f.prototype().calling_convention(), "__stdcall");
  EXPECT_NE(f.text().find("in_ECX"), std::string::npos) << f.text();
  EXPECT_TRUE(f.warnings().empty()) << f.warnings(0);
  const std::string default_start = Decompile(id, start).text();

  // __fastcall: a and b in ECX and EDX, c on the stack, as the caller passes them.
  set(fmix, "fmix", 3, "__fastcall");
  f = Decompile(id, fmix);
  EXPECT_EQ(f.prototype().calling_convention(), "__fastcall");
  EXPECT_EQ(f.text().find("in_ECX"), std::string::npos) << f.text();
  EXPECT_EQ(f.text().find("in_EDX"), std::string::npos) << f.text();
  EXPECT_NE(f.prototype().c_declaration().find("__fastcall"), std::string::npos) << f.prototype().c_declaration();
  const std::string fast_start = Decompile(id, start).text();
  EXPECT_NE(fast_start, default_start);
  EXPECT_NE(fast_start.find(call(fmix, "param_1,param_1 + 1,9")), std::string::npos) << fast_start;

  // smix pops its 8 bytes (ret 8). As __stdcall the caller's stack after
  // the call is right (keep = n * 13 is read back); as __cdecl the caller is
  // told it cleans up, and reads the wrong slot (its argument n).
  set(smix, "smix", 2, "__stdcall");
  const std::string std_start = Decompile(id, start).text();
  EXPECT_NE(std_start.find(call(smix, "param_1,0xb")), std::string::npos) << std_start;
  EXPECT_NE(std_start.find("return param_1 * 0xd;"), std::string::npos) << std_start;
  set(smix, "smix", 2, "__cdecl");
  f = Decompile(id, smix);
  EXPECT_EQ(f.prototype().calling_convention(), "__cdecl");
  const std::string cdecl_start = Decompile(id, start).text();
  EXPECT_EQ(cdecl_start.find("return param_1 * 0xd;"), std::string::npos) << cdecl_start;

  // Set signature's C (a declaration the daemon parses for the program's
  // target, or ParseC's prototype applied by hash) keeps the convention,
  // as a keyword or a GNU attribute.
  auto set_c = [&](std::uint64_t entry, const std::string &decl) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    auto *r = req.add_assertions()->mutable_body()->mutable_retype();
    r->mutable_target()->mutable_address()->set_offset(entry);
    r->mutable_type()->set_c_declaration(decl);
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << decl << ": " << st.message;
  };
  set(fmix, "fmix", 3, "");
  set_c(fmix, "int __fastcall fmix(int a, int b, int c)");
  EXPECT_EQ(Decompile(id, fmix).prototype().calling_convention(), "__fastcall");
  set(fmix, "fmix", 3, "");
  set_c(fmix, "__attribute__((fastcall)) int fmix(int a, int b, int c)");
  EXPECT_EQ(Decompile(id, fmix).prototype().calling_convention(), "__fastcall");
  {
    pb::ParseCRequest req;
    req.set_program_id(id);
    auto *src = req.add_sources();
    src->set_text("int __fastcall fmix(int a, int b, int c);\n");
    src->set_name("retype.h");
    req.mutable_options()->set_prototypes(true);
    pb::ParseCResponse parsed;
    ASSERT_TRUE(backend_->ParseC(ctx_, req, parsed).ok());
    ASSERT_EQ(parsed.prototypes_size(), 1);
    pb::GetTypesRequest treq;
    treq.set_program_id(id);
    treq.add_hashes(parsed.prototypes(0).hash());
    pb::GetTypesResponse types;
    ASSERT_TRUE(backend_->GetTypes(ctx_, treq, types).ok());
    ASSERT_EQ(types.types_size(), 1);
    EXPECT_EQ(types.types(0).function().calling_convention(), "__fastcall");
  }

  // ListCallingConventions (feature calling-conventions): x86win.cspec's
  // models, __stdcall the default and first, each with its C spelling; a
  // C declaration in a listed spelling sets that convention.
  {
    pb::ListCallingConventionsRequest req;
    req.set_program_id(id);
    pb::ListCallingConventionsResponse cc;
    auto st = backend_->ListCallingConventions(ctx_, req, cc);
    ASSERT_TRUE(st.ok()) << st.message;
    EXPECT_EQ(cc.default_name(), "__stdcall");
    ASSERT_GT(cc.conventions_size(), 2);
    EXPECT_EQ(cc.conventions(0).name(), "__stdcall");
    EXPECT_TRUE(cc.conventions(0).is_default());
    std::map<std::string, std::string> spelled;
    for (const auto &c : cc.conventions()) spelled[c.name()] = c.c_spelling();
    for (const char *n : {"__cdecl", "__fastcall", "__thiscall"}) {
      ASSERT_TRUE(spelled.contains(n)) << n;
      EXPECT_EQ(spelled[n], n);
    }
    set(fmix, "fmix", 3, "");
    set_c(fmix, "int " + spelled["__fastcall"] + " fmix(int a, int b, int c)");
    EXPECT_EQ(Decompile(id, fmix).prototype().calling_convention(), "__fastcall");
  }

  // A convention the spec has no model for: the default, with a warning.
  set(smix, "smix", 2, "__vectorcall");
  f = Decompile(id, smix);
  EXPECT_EQ(f.prototype().calling_convention(), "__stdcall");
  ASSERT_EQ(f.warnings_size(), 1);
  EXPECT_NE(f.warnings(0).find("no __vectorcall calling convention"), std::string::npos) << f.warnings(0);
}

TEST_F(ImageBackendTest, DecompilationsStopAtTheirLimits) {
  const std::string id = Import(exe_);
  const std::uint64_t main = Functions(id).at("main");
  pb::DecompileRequest req;
  req.set_program_id(id);
  req.mutable_function()->set_offset(main);
  pb::DecompileResponse resp;

  // The client went away: cancelled, and the next request still decompiles.
  CallContext gone;
  gone.cancelled = [] { return true; };
  EXPECT_EQ(backend_->Decompile(gone, req, resp).code, api::StatusCode::kCancelled);
  EXPECT_GT(Decompile(id, main).lines_size(), 0);

  // Over the server's varnode bound: an OOM failure, the decompilation's
  // result for its bundle until the bundle or the decompiler changes; only
  // a timeout may be retried with a longer deadline.
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.decompile_max_varnodes = 1;
  backend_ = MakeImageBackend(o);
  const std::string small = Import(exe_);
  req.set_program_id(small);
  std::string hash;
  for (int i = 0; i < 2; ++i) {
    auto st = backend_->Decompile(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    ASSERT_TRUE(resp.has_failure());
    EXPECT_EQ(resp.failure().kind(), pb::DECOMPILE_FAILURE_KIND_OOM);
    EXPECT_NE(resp.failure().detail().find("too large"), std::string::npos) << resp.failure().detail();
    EXPECT_FALSE(resp.failure().can_escalate());
    EXPECT_TRUE(resp.failure().bundle().empty());
    if (i == 1) EXPECT_EQ(resp.failure().bundle_hash(), hash);
    hash = resp.failure().bundle_hash();
    ASSERT_EQ(resp.function().lines_size(), 1);
    EXPECT_EQ(resp.function().lines(0).tokens(0).kind(), pb::CODE_TOKEN_KIND_ERROR);
  }
  req.mutable_options()->set_escalate(true);
  EXPECT_EQ(backend_->Decompile(ctx_, req, resp).code, api::StatusCode::kFailedPrecondition);
}

// The decompiler runs in worker processes: a crash costs one function, comes
// back as a failure with the bundle that reproduces it, and the daemon goes
// on decompiling. REVKIT_DECOMPD_FAULT makes a worker fail on purpose.
TEST_F(ImageBackendTest, DecompilerCrashesAndHangsCostOneFunction) {
  const std::string id = Import(exe_);
  auto fns = Functions(id);
  const std::uint64_t main = fns.at("main"), checksum = fns.at("checksum");
  char spec[64];
  std::snprintf(spec, sizeof spec, "segv@%llx", static_cast<unsigned long long>(main));
  ::setenv("REVKIT_DECOMPD_FAULT", spec, 1);
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.decompile_timeout_seconds = 30;
  backend_ = MakeImageBackend(o);
  const std::string prog = Import(exe_);
  pb::DecompileRequest req;
  req.set_program_id(prog);
  req.mutable_function()->set_offset(main);
  req.mutable_options()->set_include_bundle(true);
  pb::DecompileResponse resp;
  ASSERT_TRUE(backend_->Decompile(ctx_, req, resp).ok());
  ASSERT_TRUE(resp.has_failure());
  EXPECT_EQ(resp.failure().kind(), pb::DECOMPILE_FAILURE_KIND_SEGV);
  EXPECT_NE(resp.failure().detail().find("SIGSEGV"), std::string::npos) << resp.failure().detail();
  EXPECT_FALSE(resp.failure().bundle().empty());
  EXPECT_EQ(resp.failure().bundle_hash(), decompd::bundle_hash(resp.failure().bundle()));
  EXPECT_EQ(resp.failure().decompiler_build(), decompd::decompiler_build());
  EXPECT_EQ(resp.function().name(), "main");
  // The daemon is fine, and so is every other function.
  EXPECT_GT(Decompile(prog, checksum).lines_size(), 3);
  // The bundle decodes alone: what rk-decompd --bundle reproduces.
  const decompd::Bundle b = decompd::decode_bundle(resp.failure().bundle());
  EXPECT_EQ(b.entry, main);
  EXPECT_EQ(b.mode, decompd::Mode::tokens);
  // Cached: the same failure again, until the bundle or the build changes.
  pb::DecompileResponse again;
  ASSERT_TRUE(backend_->Decompile(ctx_, req, again).ok());
  EXPECT_EQ(again.failure().bundle_hash(), resp.failure().bundle_hash());

  // A hang past the hard deadline: a timeout, which may be retried once
  // with a longer deadline.
  std::snprintf(spec, sizeof spec, "hang@%llx", static_cast<unsigned long long>(checksum));
  ::setenv("REVKIT_DECOMPD_FAULT", spec, 1);
  o.decompile_timeout_seconds = 0.2;
  backend_ = MakeImageBackend(o);
  const std::string slow = Import(exe_);
  req.set_program_id(slow);
  req.mutable_function()->set_offset(checksum);
  req.mutable_options()->set_include_bundle(false);
  ASSERT_TRUE(backend_->Decompile(ctx_, req, resp).ok());
  ASSERT_TRUE(resp.has_failure());
  EXPECT_EQ(resp.failure().kind(), pb::DECOMPILE_FAILURE_KIND_TIMEOUT);
  EXPECT_NE(resp.failure().detail().find("killed at"), std::string::npos) << resp.failure().detail();
  EXPECT_TRUE(resp.failure().can_escalate());
  // A run that only needs longer: killed at its 2.25 s deadline, then
  // escalated to 30 s, which it survives.
  std::snprintf(spec, sizeof spec, "sleep3000@%llx", static_cast<unsigned long long>(checksum));
  ::setenv("REVKIT_DECOMPD_FAULT", spec, 1);
  backend_ = MakeImageBackend(o);
  const std::string later = Import(exe_);
  req.set_program_id(later);
  pb::DecompileResponse timed_out;
  ASSERT_TRUE(backend_->Decompile(ctx_, req, timed_out).ok());
  ASSERT_TRUE(timed_out.has_failure());
  EXPECT_EQ(timed_out.failure().kind(), pb::DECOMPILE_FAILURE_KIND_TIMEOUT);
  req.mutable_options()->set_escalate(true);
  req.mutable_options()->set_timeout_ms(30000);
  pb::DecompileResponse escalated;
  ASSERT_TRUE(backend_->Decompile(ctx_, req, escalated).ok());
  EXPECT_FALSE(escalated.has_failure()) << escalated.failure().detail();
  EXPECT_GT(escalated.function().lines_size(), 3);
  // Later requests get the escalated result; a second escalation is refused.
  req.mutable_options()->set_escalate(false);
  pb::DecompileResponse after;
  ASSERT_TRUE(backend_->Decompile(ctx_, req, after).ok());
  EXPECT_FALSE(after.has_failure());
  EXPECT_EQ(after.function().lines_size(), escalated.function().lines_size());
  req.mutable_options()->set_escalate(true);
  EXPECT_EQ(backend_->Decompile(ctx_, req, after).code, api::StatusCode::kFailedPrecondition);
  ::unsetenv("REVKIT_DECOMPD_FAULT");
}

TEST_F(ImageBackendTest, PinnedReadsAndRevisionErrors) {
  std::string id = Import(exe_);
  const std::uint64_t checksum = Functions(id).at("checksum");
  ASSERT_TRUE(Rename(id, checksum, "a").ok());
  ASSERT_TRUE(Rename(id, checksum, "b").ok());
  pb::GetFunctionRequest req;
  req.set_program_id(id);
  req.mutable_address()->set_offset(checksum);
  pb::GetFunctionResponse resp;
  for (auto [rev, name] : {std::pair{1u, "checksum"}, std::pair{2u, "a"}, std::pair{3u, "b"}}) {
    req.mutable_read()->set_revision(rev);
    ASSERT_TRUE(backend_->GetFunction(ctx_, req, resp).ok());
    EXPECT_EQ(resp.function().name(), name);
    EXPECT_EQ(resp.snapshot().head_revision(), 3u);
  }
  req.mutable_read()->set_revision(99);
  EXPECT_EQ(backend_->GetFunction(ctx_, req, resp).code, StatusCode::kOutOfRange);
}

// Readers decompile, page and query while a writer renames; every result
// must be the one for the revision it reports. This is the TSan target.
TEST_F(ImageBackendTest, ConcurrentReadersAndWriter) {
  std::string id = Import(exe_);
  auto fns = Functions(id);
  const std::uint64_t main = fns.at("main"), checksum = fns.at("checksum");
  // The name checksum has at each revision: revision 1 (import) is the
  // default; the writer's n-th rename makes revision n + 1 "fn_<n>".
  auto name_at = [](std::uint64_t rev) { return rev <= 1 ? std::string("checksum") : "fn_" + std::to_string(rev - 1); };

  std::atomic<bool> stop = false;
  std::atomic<int> checked = 0, failures = 0;
  std::vector<std::thread> threads;
  for (int t = 0; t < 6; ++t) {
    threads.emplace_back([&, t] {
      CallContext ctx;
      std::mt19937 rng(static_cast<unsigned>(t));
      while (!stop) {
        switch (rng() % 3) {
          case 0: {
            pb::DecompileRequest req;
            req.set_program_id(id);
            req.mutable_function()->set_offset(main);
            req.mutable_options()->set_include_text(true);
            pb::DecompileResponse resp;
            if (!backend_->Decompile(ctx, req, resp).ok()) {
              ++failures;
            } else if (resp.function().text().find(name_at(resp.snapshot().revision()) + "(") == std::string::npos) {
              if (failures++ == 0) ADD_FAILURE() << "revision " << resp.snapshot().revision() << "\n" << resp.function().text();
            }
            break;
          }
          case 1: {
            pb::GetListingRequest req;
            req.set_program_id(id);
            req.mutable_rows()->set_first_row(static_cast<std::int64_t>(rng() % 250));
            req.mutable_rows()->set_row_count(300);
            pb::GetListingResponse resp;
            if (!backend_->GetListing(ctx, req, resp).ok() || resp.rows_size() == 0) ++failures;
            break;
          }
          default: {
            pb::GetFunctionRequest req;
            req.set_program_id(id);
            req.mutable_address()->set_offset(checksum);
            pb::GetFunctionResponse resp;
            if (!backend_->GetFunction(ctx, req, resp).ok() ||
                resp.function().name() != name_at(resp.snapshot().revision())) {
              if (failures++ == 0) ADD_FAILURE() << "function " << resp.function().name() << " at " << resp.snapshot().revision();
            }
          }
        }
        ++checked;
      }
    });
  }
  // Each rename waits for a few reads, so reads interleave with writes
  // however slow the build (sanitizers) is.
  for (int n = 1; n <= 12; ++n) {
    ASSERT_TRUE(Rename(id, checksum, "fn_" + std::to_string(n)).ok());
    const int target = checked.load() + 4;
    for (int wait = 0; wait < 2000 && checked.load() < target; ++wait)
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  stop = true;
  for (auto &t : threads) t.join();
  EXPECT_EQ(failures.load(), 0);
  EXPECT_GT(checked.load(), 12);
}

// Imports run in parallel (each building SLEIGH engines), then every
// program is decompiled and paged on several threads at once, so several
// decompiler instances of one language print concurrently.
TEST_F(ImageBackendTest, ParallelImportsAndDecompiles) {
  constexpr int kPrograms = 4;
  std::vector<std::string> ids(kPrograms);
  std::vector<std::thread> threads;
  for (int i = 0; i < kPrograms; ++i)
    threads.emplace_back([&, i] {
      CallContext ctx;
      pb::ImportProgramRequest req;
      req.set_project_id("default");
      req.set_path(exe_.string());
      req.set_name("copy" + std::to_string(i));
      pb::ImportProgramResponse resp;
      if (backend_->ImportProgram(ctx, req, resp).ok()) ids[static_cast<std::size_t>(i)] = resp.program().program_id();
    });
  for (auto &t : threads) t.join();
  threads.clear();
  for (const auto &id : ids) ASSERT_FALSE(id.empty());

  std::atomic<int> failures = 0;
  for (int t = 0; t < 8; ++t)
    threads.emplace_back([&, t] {
      CallContext ctx;
      const std::string &id = ids[static_cast<std::size_t>(t % kPrograms)];
      pb::ListFunctionsRequest lf;
      lf.set_program_id(id);
      pb::ListFunctionsResponse fns;
      if (!backend_->ListFunctions(ctx, lf, fns).ok()) ++failures;
      for (const auto &f : fns.functions()) {
        pb::DecompileRequest req;
        req.set_program_id(id);
        req.mutable_function()->set_offset(f.entry().offset());
        pb::DecompileResponse resp;
        if (!backend_->Decompile(ctx, req, resp).ok() || resp.function().lines_size() == 0) ++failures;
        pb::GetListingRequest lr;
        lr.set_program_id(id);
        *lr.mutable_addresses()->mutable_start() = f.entry();
        lr.mutable_addresses()->set_max_rows(64);
        pb::GetListingResponse listing;
        if (!backend_->GetListing(ctx, lr, listing).ok()) ++failures;
      }
    });
  for (auto &t : threads) t.join();
  EXPECT_EQ(failures.load(), 0);
}

// On a stripped binary the daemon's functions are function discovery's:
// the entries, names and bodies rk-lift --analyze reports, which runs the
// same analysis over a fact store of its own (sdk/python's
// test_discovery.py compares with the tool itself).
TEST_F(ImageBackendTest, StrippedFunctionsAreWhatDiscoveryFinds) {
  auto stripped = testing::scratch_dir("image-backend-stripped") / "prog";
  if (!testing::compile(REVKIT_TEST_CC, kProgram, "-O2 -s", stripped)) GTEST_SKIP() << "no C compiler";
  std::string id = Import(stripped);
  pb::ListFunctionsRequest req;
  req.set_program_id(id);
  req.mutable_page()->set_page_size(5000);
  pb::ListFunctionsResponse resp;
  ASSERT_TRUE(backend_->ListFunctions(ctx_, req, resp).ok());
  using Body = std::vector<std::pair<std::uint64_t, std::uint64_t>>;
  std::map<std::uint64_t, std::pair<std::string, Body>> served, found;
  for (const auto &f : resp.functions()) {
    Body body;
    for (const auto &r : f.body()) body.emplace_back(r.first().offset(), r.last().offset());
    served[f.entry().offset()] = {f.name(), body};
  }

  // What rk-lift --analyze computes.
  loader::Image image = loader::load_file(stripped, {.image_base = std::nullopt, .ghidra_image_base = true});
  facts::FactDb db;
  analysis::register_queries(db.engine());
  analysis::import_image(db, {}, image, analysis::describe(image, loader::guess_language(image)->id()));
  for (const analysis::FunctionInfo &f : db.snapshot().get<analysis::Functions>({})->functions) {
    Body body;
    for (const facts::AddressRange &r : f.body.ranges()) body.emplace_back(r.first.offset, r.last.offset);
    found[f.entry.offset] = {f.name, body};
  }
  EXPECT_EQ(served, found);
  EXPECT_GT(found.size(), 5u);
  // main has no symbol any more, but its unwind entry makes it a function,
  // and the PLT stub it calls carries the import's name.
  bool printf_stub = false;
  for (const auto &[entry, f] : served) printf_stub |= f.first.find("printf") != std::string::npos;
  EXPECT_TRUE(printf_stub);
}

TEST_F(ImageBackendTest, CorpusLua) {
  std::filesystem::path lua = std::filesystem::path(REVKIT_CORPUS) / "elf-x86_64/gcc-O2/debug/lua";
  if (!std::filesystem::exists(lua)) GTEST_SKIP() << "corpus not built";
  std::string id = Import(lua);
  auto fns = Functions(id);
  EXPECT_GT(fns.size(), 600u);
  // Field tokens name their struct (the debug info's) and offset: the
  // struct has a field of the token's name there (L->top).
  std::map<std::string, pb::TypeDefinition> parents;
  int fields = 0, named = 0;
  for (const char *name : {"main", "luaL_newstate", "luaV_execute", "luaH_resize", "lua_settop"}) {
    pb::DecompiledFunction f = Decompile(id, fns.at(name));
    EXPECT_GT(f.lines_size(), 3) << name << ": " << (f.warnings().empty() ? "" : f.warnings(0));
    for (const auto &line : f.lines())
      for (const auto &t : line.tokens()) {
        if (t.kind() != pb::CODE_TOKEN_KIND_FIELD) continue;
        ++fields;
        EXPECT_TRUE(t.has_field_offset()) << name << ": " << t.text();
        if (t.parent_type_hash().empty()) continue;
        if (!parents.contains(t.parent_type_hash())) {
          pb::GetTypesRequest req;
          req.set_program_id(id);
          req.add_hashes(t.parent_type_hash());
          pb::GetTypesResponse resp;
          ASSERT_TRUE(backend_->GetTypes(ctx_, req, resp).ok());
          ASSERT_EQ(resp.types_size(), 1) << t.parent_type_hash();
          parents[t.parent_type_hash()] = resp.types(0);
        }
        const pb::TypeDefinition &parent = parents[t.parent_type_hash()];
        bool found = false;
        for (const auto &fd : parent.composite().fields())
          found |= fd.name() == t.text() && fd.offset() == t.field_offset();
        EXPECT_TRUE(found) << name << ": " << t.text() << " at " << t.field_offset() << " in " << parent.name();
        named += found;
      }
  }
  EXPECT_GT(fields, 50);
  // Typedefs of anonymous structs and unions (StkIdRel's .p) included.
  EXPECT_EQ(named, fields);
  bool lua_state = false;
  for (const auto &[hash, t] : parents) lua_state |= t.name() == "lua_State";
  EXPECT_TRUE(lua_state);
}

// Every function of a small AArch64 binary decompiles. Soft-float helpers
// print annotation varnodes, which have no high-level variable.
TEST_F(ImageBackendTest, CorpusAArch64DecompilesEverything) {
  std::filesystem::path bin = std::filesystem::path(REVKIT_CORPUS) / "elf-aarch64/gcc-O2/debug/features";
  if (!std::filesystem::exists(bin)) GTEST_SKIP() << "corpus not built";
  std::string id = Import(bin);
  for (const auto &[name, entry] : Functions(id)) {
    pb::DecompiledFunction f = Decompile(id, entry);
    for (const auto &w : f.warnings()) EXPECT_FALSE(w.starts_with("decompilation failed")) << name << ": " << w;
  }
}

// Whether a function returns, as the user says (SetNoReturn, feature
// no-return): marking fail() no-return ends g()'s body, listing flow and
// decompilation at the call (sink = 2 is dead fallthrough); marking panic()
// (a known no-return name, here a function that returns) as returning gives
// h() back what follows its call (sink = 3). Retracted, analysis has its say
// again.
TEST_F(ImageBackendTest, NoReturnMarksEndOrResumeCallersFlow) {
  constexpr const char *kNoReturn = R"(
volatile int sink;
__attribute__((noinline, noipa)) void fail(int c) { sink = c; }
__attribute__((noinline, noipa)) void panic(void) { sink = 9; }
__attribute__((noinline)) void g(int x) { sink = 1; fail(x); sink = 2; }
__attribute__((noinline)) void h(void) { sink = 5; panic(); sink = 3; }
int main(int argc, char **argv) {
  (void)argv;
  g(argc);
  if (argc > 5) h();
  return 0;
}
)";
  auto exe = testing::scratch_dir("image-backend-noreturn") / "noret";
  if (!testing::compile(REVKIT_TEST_CC, kNoReturn, "-O1 -fno-inline -fno-pie -no-pie", exe)) GTEST_SKIP() << "no C compiler";
  const std::string id = Import(exe);
  auto fns = Functions(id);
  ASSERT_TRUE(fns.contains("fail") && fns.contains("panic") && fns.contains("g") && fns.contains("h"));
  auto function = [&](std::uint64_t entry) {
    pb::GetFunctionRequest req;
    req.set_program_id(id);
    req.mutable_address()->set_offset(entry);
    pb::GetFunctionResponse resp;
    auto st = backend_->GetFunction(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.function();
  };
  auto body_bytes = [&](std::uint64_t entry) {
    std::uint64_t n = 0;
    const pb::Function f = function(entry);
    for (const auto &r : f.body()) n += r.last().offset() - r.first().offset() + 1;
    return n;
  };
  auto mark = [&](std::uint64_t entry, bool no_return) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    auto *b = req.add_assertions()->mutable_body()->mutable_no_return();
    b->mutable_function()->set_offset(entry);
    b->set_no_return(no_return);
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  };
  auto retract = [&](const pb::AppendAssertionsResponse &done) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    for (const auto &a : done.assertions()) req.add_seqs(a.seq());
    pb::RetractAssertionsResponse resp;
    EXPECT_TRUE(backend_->RetractAssertions(ctx_, req, resp).ok());
  };
  const std::uint64_t fail = fns.at("fail"), die = fns.at("panic"), g = fns.at("g"), h = fns.at("h");

  // As analysis sees it: fail returns, panic (by its name) doesn't.
  const std::string g0 = Decompile(id, g).text(), h0 = Decompile(id, h).text();
  EXPECT_NE(g0.find("sink = 2"), std::string::npos) << g0;
  EXPECT_EQ(h0.find("sink = 3"), std::string::npos) << h0;
  EXPECT_FALSE(function(fail).no_return());
  EXPECT_TRUE(function(die).no_return());
  const std::uint64_t g_bytes = body_bytes(g), h_bytes = body_bytes(h);

  // fail marked no-return: g ends at the call.
  auto a1 = mark(fail, true);
  EXPECT_TRUE(function(fail).no_return());
  const std::string g1 = Decompile(id, g).text();
  EXPECT_EQ(g1.find("sink = 2"), std::string::npos) << g1;
  EXPECT_NE(g1.find("fail("), std::string::npos) << g1;
  EXPECT_LT(body_bytes(g), g_bytes);

  // panic marked as returning: h goes on after the call.
  auto a2 = mark(die, false);
  EXPECT_FALSE(function(die).no_return());
  const std::string h1 = Decompile(id, h).text();
  EXPECT_NE(h1.find("sink = 3"), std::string::npos) << h1;
  EXPECT_GT(body_bytes(h), h_bytes);

  // A function is required.
  pb::AppendAssertionsRequest bad;
  bad.set_program_id(id);
  bad.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  auto *b = bad.add_assertions()->mutable_body()->mutable_no_return();
  b->mutable_function()->set_offset(g + 1);
  b->set_no_return(true);
  pb::AppendAssertionsResponse bad_resp;
  EXPECT_FALSE(backend_->AppendAssertions(ctx_, bad, bad_resp).ok());

  // Retracted: as analysis has it.
  retract(a2);
  retract(a1);
  EXPECT_EQ(Decompile(id, g).text(), g0);
  EXPECT_EQ(Decompile(id, h).text(), h0);
  EXPECT_EQ(body_bytes(g), g_bytes);
  EXPECT_TRUE(function(die).no_return());
}

}  // namespace
}  // namespace revkit::backend
