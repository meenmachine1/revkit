// The byte viewer's read, the overview bars and next/previous by kind
// (QueryService.GetByteView, GetOverview, FindNext; api_minor 44) through
// the image backend, on a program compiled at test time: runs that match
// the listing's code units, patched bytes with what the file had, zeros
// for .bss, the overview's counts adding up with code where .text is,
// imports as external and entropy, and each navigation kind checked
// against the listing, the memory and the symbols.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <map>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr const char *kProgram = R"(
#include <stdio.h>
int counter;
char big[4096];
const char greeting[] = "hello, byte viewer";
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return h;
}
__attribute__((noinline)) int twice(int x) { return checksum((const unsigned char *)&x, 4) * 2; }
int main(int argc, char **argv) {
  unsigned r = checksum((const unsigned char *)argv[0], argc);
  big[argc] = 1;
  printf("%u %d %s\n", r, twice(argc), greeting);
  return (int)r;
}
)";

class ByteViewTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("byte-view");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1", exe_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    b_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(exe_.string());
    pb::ImportProgramResponse resp;
    auto st = b_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id_ = resp.program().program_id();
    pb::ListFunctionsRequest lf;
    lf.set_program_id(id_);
    lf.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse fr;
    ASSERT_TRUE(b_->ListFunctions(ctx_, lf, fr).ok());
    for (const auto &f : fr.functions()) fns_[f.name()] = f.entry().offset();
    pb::GetMemoryMapRequest mm;
    mm.set_program_id(id_);
    ASSERT_TRUE(b_->GetMemoryMap(ctx_, mm, map_).ok());
  }

  pb::GetByteViewResponse View(std::uint64_t at, std::uint32_t n) {
    pb::GetByteViewRequest req;
    req.set_program_id(id_);
    req.mutable_address()->set_offset(at);
    req.set_length(n);
    pb::GetByteViewResponse resp;
    auto st = b_->GetByteView(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }
  std::string Memory(std::uint64_t at, std::uint32_t n) {
    pb::ReadMemoryRequest req;
    req.set_program_id(id_);
    req.mutable_address()->set_offset(at);
    req.set_length(n);
    pb::ReadMemoryResponse resp;
    EXPECT_TRUE(b_->ReadMemory(ctx_, req, resp).ok());
    return resp.data();
  }
  std::vector<pb::ListingRow> Rows(std::uint64_t start, std::uint32_t n) {
    pb::GetListingRequest req;
    req.set_program_id(id_);
    req.mutable_addresses()->mutable_start()->set_offset(start);
    req.mutable_addresses()->set_max_rows(n);
    req.set_omit_bytes(true);
    pb::GetListingResponse resp;
    EXPECT_TRUE(b_->GetListing(ctx_, req, resp).ok());
    return {resp.rows().begin(), resp.rows().end()};
  }
  // The listing row containing `a`.
  pb::ListingRow RowAt(std::uint64_t a) { return Rows(a, 1).at(0); }
  std::optional<std::uint64_t> Next(std::uint64_t from, pb::NavigationKind kind, bool back = false) {
    pb::FindNextRequest req;
    req.set_program_id(id_);
    req.mutable_from()->set_offset(from);
    req.set_kind(kind);
    req.set_backward(back);
    pb::FindNextResponse resp;
    auto st = b_->FindNext(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    if (!resp.found()) return std::nullopt;
    return resp.address().offset();
  }
  const pb::MemoryBlock *Block(const std::string &name) {
    for (const auto &b : map_.blocks())
      if (b.name() == name) return &b;
    return nullptr;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> b_;
  std::string id_;
  std::map<std::string, std::uint64_t> fns_;
  pb::GetMemoryMapResponse map_;
};

TEST_F(ByteViewTest, BytesRunsAndPatches) {
  const std::uint64_t main = fns_.at("main");
  auto v = View(main, 64);
  ASSERT_EQ(v.data().size(), 64u);
  EXPECT_EQ(v.data(), Memory(main, 64));
  EXPECT_EQ(v.address().offset(), main);
  EXPECT_TRUE(v.patched().empty());
  // The runs tile the range, and each code run is a listing instruction.
  ASSERT_FALSE(v.runs().empty());
  EXPECT_LE(v.runs(0).start().offset(), main);
  for (int i = 1; i < v.runs_size(); ++i)
    EXPECT_EQ(v.runs(i).start().offset(), v.runs(i - 1).start().offset() + v.runs(i - 1).length()) << i;
  const auto &last = v.runs(v.runs_size() - 1);
  EXPECT_GE(last.start().offset() + last.length(), main + 64);
  int code = 0;
  for (const auto &r : v.runs()) {
    if (r.kind() != pb::BYTE_KIND_CODE) continue;
    ++code;
    const pb::ListingRow row = RowAt(r.start().offset());
    EXPECT_EQ(row.kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
    EXPECT_EQ(row.address().offset(), r.start().offset());
    EXPECT_EQ(row.length(), r.length());
  }
  EXPECT_GT(code, 3);

  // A byte patched: the new byte, and the file's beside it.
  const char was = v.data()[1];
  pb::PatchBytesRequest pr;
  pr.set_program_id(id_);
  pr.mutable_address()->set_offset(main + 1);
  pr.set_data(std::string(1, static_cast<char>(was ^ 0x5a)));
  pr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pr.mutable_provenance()->set_id("alice");
  pb::PatchBytesResponse presp;
  auto st = b_->PatchBytes(ctx_, pr, presp);
  ASSERT_TRUE(st.ok()) << st.message;
  v = View(main, 16);
  EXPECT_EQ(v.data()[1], static_cast<char>(was ^ 0x5a));
  ASSERT_EQ(v.patched_size(), 1);
  EXPECT_EQ(v.patched(0).start().offset(), main + 1);
  EXPECT_EQ(v.patched(0).original(), std::string(1, was));

  pb::GetByteViewRequest big;
  big.set_program_id(id_);
  big.mutable_address()->set_offset(main);
  big.set_length(65537);
  pb::GetByteViewResponse br;
  EXPECT_EQ(b_->GetByteView(ctx_, big, br).code, StatusCode::kInvalidArgument);
}

TEST_F(ByteViewTest, UninitializedAndOutsideBlocksAreZero) {
  const pb::MemoryBlock *bss = Block(".bss");
  ASSERT_NE(bss, nullptr);
  ASSERT_FALSE(bss->initialized());
  auto v = View(bss->range().first().offset(), 32);
  EXPECT_EQ(v.data(), std::string(32, '\0'));
  ASSERT_FALSE(v.runs().empty());
  // Analysis's data there (a global's undefinedN) is data; the rest has no bytes.
  bool uninit = false;
  for (const auto &r : v.runs()) {
    EXPECT_TRUE(r.kind() == pb::BYTE_KIND_UNINITIALIZED || r.kind() == pb::BYTE_KIND_DATA) << r.kind();
    uninit |= r.kind() == pb::BYTE_KIND_UNINITIALIZED;
  }
  v = View(bss->range().first().offset(), static_cast<std::uint32_t>(std::min<std::uint64_t>(
                                               65536, bss->range().last().offset() - bss->range().first().offset() + 1)));
  for (const auto &r : v.runs()) uninit |= r.kind() == pb::BYTE_KIND_UNINITIALIZED;
  EXPECT_TRUE(uninit);
  // Past the last block: zeros, uninitialized, as long as asked.
  std::uint64_t top = 0;
  for (const auto &b : map_.blocks()) top = std::max(top, b.range().last().offset());
  v = View(top + 0x1000, 16);
  EXPECT_EQ(v.data(), std::string(16, '\0'));
  ASSERT_EQ(v.runs_size(), 1);
  EXPECT_EQ(v.runs(0).kind(), pb::BYTE_KIND_UNINITIALIZED);
}

TEST_F(ByteViewTest, Overview) {
  pb::GetOverviewRequest req;
  req.set_program_id(id_);
  req.set_buckets(256);
  pb::GetOverviewResponse o;
  ASSERT_TRUE(b_->GetOverview(ctx_, req, o).ok());
  std::uint64_t total = 0;
  for (const auto &b : map_.blocks()) total += b.range().last().offset() - b.range().first().offset() + 1;
  EXPECT_EQ(o.total_bytes(), total);
  ASSERT_GE(o.buckets_size(), map_.blocks_size());
  std::uint64_t sum = 0, external = 0;
  bool text_code = false, bss_uninit = false;
  for (int i = 0; i < o.buckets_size(); ++i) {
    const auto &b = o.buckets(i);
    sum += b.length();
    EXPECT_EQ(b.code() + b.data() + b.undefined() + b.external() + b.uninitialized(), b.length()) << i;
    if (i > 0) EXPECT_GE(b.start().offset(), o.buckets(i - 1).start().offset() + o.buckets(i - 1).length());
    EXPECT_GE(b.entropy(), 0.0f);
    EXPECT_LE(b.entropy(), 8.0f);
    external += b.external();
    const std::uint64_t main = fns_.at("main");
    if (main >= b.start().offset() && main < b.start().offset() + b.length()) {
      EXPECT_EQ(b.block(), ".text");
      EXPECT_GT(b.code(), 0u);
      EXPECT_GT(b.entropy(), 2.0f);
      text_code = true;
    }
    if (b.block() == ".bss") {
      EXPECT_EQ(b.kind(), pb::BYTE_KIND_UNINITIALIZED);
      EXPECT_EQ(b.entropy(), 0.0f);
      bss_uninit = true;
    }
  }
  EXPECT_EQ(sum, total);
  EXPECT_TRUE(text_code);
  EXPECT_TRUE(bss_uninit);
  EXPECT_GT(external, 0u) << "printf's import";
  req.set_buckets(9000);
  EXPECT_EQ(b_->GetOverview(ctx_, req, o).code, StatusCode::kInvalidArgument);
}

TEST_F(ByteViewTest, FindNextFunctionsAndRuns) {
  std::vector<std::uint64_t> entries;
  for (const auto &[name, entry] : fns_) entries.push_back(entry);
  std::sort(entries.begin(), entries.end());
  const std::uint64_t checksum = fns_.at("checksum");
  auto pos = std::find(entries.begin(), entries.end(), checksum);
  ASSERT_NE(pos, entries.end());
  if (pos + 1 != entries.end()) EXPECT_EQ(Next(checksum, pb::NAVIGATION_KIND_FUNCTION), *(pos + 1));
  if (pos != entries.begin()) EXPECT_EQ(Next(checksum, pb::NAVIGATION_KIND_FUNCTION, true), *(pos - 1));
  EXPECT_EQ(Next(checksum + 1, pb::NAVIGATION_KIND_FUNCTION, true), checksum);
  EXPECT_FALSE(Next(entries.back(), pb::NAVIGATION_KIND_FUNCTION).has_value());

  // Next instruction skips the run of instructions it is in: between them
  // lies something else.
  const std::uint64_t main = fns_.at("main");
  auto next = Next(main, pb::NAVIGATION_KIND_INSTRUCTION);
  ASSERT_TRUE(next.has_value());
  EXPECT_EQ(RowAt(*next).kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_EQ(RowAt(*next).address().offset(), *next);
  // Bytes that aren't an instruction's lie between (here the gap before
  // .fini, which follows .text).
  auto between = View(main, static_cast<std::uint32_t>(*next - main));
  bool gap = false;
  for (const auto &r : between.runs()) gap |= r.kind() != pb::BYTE_KIND_CODE;
  EXPECT_TRUE(gap);
  // Previous instruction from there: the last one before that gap.
  auto prev = Next(*next, pb::NAVIGATION_KIND_INSTRUCTION, true);
  ASSERT_TRUE(prev.has_value());
  EXPECT_LT(*prev, *next);
  const auto pr = RowAt(*prev);
  EXPECT_EQ(pr.kind(), pb::LISTING_ROW_KIND_INSTRUCTION);
  EXPECT_EQ(pr.address().offset(), *prev);
  EXPECT_NE(View(*prev + pr.length(), 1).runs(0).kind(), pb::BYTE_KIND_CODE);

  // Next undefined from main: bytes nothing defines.
  auto undef = Next(main, pb::NAVIGATION_KIND_UNDEFINED);
  ASSERT_TRUE(undef.has_value());
  EXPECT_EQ(RowAt(*undef).kind(), pb::LISTING_ROW_KIND_UNDEFINED);
  // Next data from the start of the program, and back again.
  auto data = Next(0, pb::NAVIGATION_KIND_DATA);
  ASSERT_TRUE(data.has_value());
  EXPECT_EQ(RowAt(*data).kind(), pb::LISTING_ROW_KIND_DATA);
}

TEST_F(ByteViewTest, FindNextBytesLabelsAndNotes) {
  // A different byte: every byte before it is the one at `from`.
  const pb::MemoryBlock *text = Block(".text");
  ASSERT_NE(text, nullptr);
  const std::uint64_t from = text->range().first().offset();
  auto diff = Next(from, pb::NAVIGATION_KIND_DIFFERENT_BYTE);
  ASSERT_TRUE(diff.has_value());
  ASSERT_GT(*diff, from);
  const std::string bytes = Memory(from, static_cast<std::uint32_t>(*diff - from + 1));
  for (std::size_t i = 1; i + 1 < bytes.size(); ++i) EXPECT_EQ(bytes[i], bytes[0]) << i;
  EXPECT_NE(bytes.back(), bytes[0]);
  auto back = Next(*diff, pb::NAVIGATION_KIND_DIFFERENT_BYTE, true);
  ASSERT_TRUE(back.has_value());
  EXPECT_LT(*back, *diff);
  EXPECT_NE(Memory(*back, 1), Memory(*diff, 1));

  // Labels: the first symbol in address order, then the one after it.
  pb::ListSymbolsRequest ls;
  ls.set_program_id(id_);
  ls.mutable_page()->set_page_size(3);
  pb::ListSymbolsResponse sr;
  ASSERT_TRUE(b_->ListSymbols(ctx_, ls, sr).ok());
  ASSERT_GE(sr.symbols_size(), 2);
  EXPECT_EQ(Next(0, pb::NAVIGATION_KIND_LABEL), sr.symbols(0).address().offset());
  EXPECT_EQ(Next(sr.symbols(0).address().offset(), pb::NAVIGATION_KIND_LABEL), sr.symbols(1).address().offset());
  EXPECT_EQ(Next(sr.symbols(1).address().offset(), pb::NAVIGATION_KIND_LABEL, true), sr.symbols(0).address().offset());

  // Notes: none, then one at twice, found from either side.
  const std::uint64_t twice = fns_.at("twice");
  EXPECT_FALSE(Next(0, pb::NAVIGATION_KIND_NOTE).has_value());
  pb::AppendAssertionsRequest ar;
  ar.set_program_id(id_);
  ar.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  ar.mutable_provenance()->set_id("alice");
  auto *note = ar.add_assertions()->mutable_body()->mutable_note();
  note->mutable_address()->set_offset(twice);
  note->set_tag("todo");
  note->set_text("look here");
  pb::AppendAssertionsResponse aresp;
  auto st = b_->AppendAssertions(ctx_, ar, aresp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(Next(0, pb::NAVIGATION_KIND_NOTE), twice);
  EXPECT_EQ(Next(twice, pb::NAVIGATION_KIND_NOTE), std::nullopt);
  EXPECT_EQ(Next(UINT64_MAX - 1, pb::NAVIGATION_KIND_NOTE, true), twice);

  pb::FindNextRequest bad;
  bad.set_program_id(id_);
  pb::FindNextResponse br;
  EXPECT_EQ(b_->FindNext(ctx_, bad, br).code, StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace revkit::backend
