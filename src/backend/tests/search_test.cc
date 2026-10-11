// The searches (api_minor 41, feature "search"): what memory queries mean
// as bytes (search.cc), and SearchMemory, SearchText, SearchScalars and
// SearchDecompiled on corpus programs through the api::Backend interface.
#include "search.h"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <map>
#include <set>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;
using api::StatusCode;

// --- Queries as bytes ---------------------------------------------------------

std::string Compile(pb::SearchMemoryRequest req, bool big_endian, search::Compiled &out) {
  return search::CompileMemoryQuery(req, big_endian, out);
}

pb::SearchMemoryRequest Query(pb::SearchFormat f, const std::string &q) {
  pb::SearchMemoryRequest r;
  r.set_format(f);
  r.set_query(q);
  return r;
}

TEST(SearchQuery, Hex) {
  search::Compiled c;
  ASSERT_EQ(Compile(Query(pb::SEARCH_FORMAT_HEX, "48 8b ?? e8"), false, c), "");
  EXPECT_EQ(c.pattern.Display(), "48 8b ?? e8");
  ASSERT_EQ(Compile(Query(pb::SEARCH_FORMAT_HEX, "488b05"), false, c), "");
  EXPECT_EQ(c.pattern.Display(), "48 8b 05");
  ASSERT_EQ(Compile(Query(pb::SEARCH_FORMAT_HEX, "4? ?f .. 0x12"), false, c), "");
  EXPECT_EQ(c.pattern.Display(), "4? ?f ?? 12");
  EXPECT_EQ(static_cast<unsigned char>(c.pattern.mask[0]), 0xf0);
  EXPECT_EQ(static_cast<unsigned char>(c.pattern.mask[1]), 0x0f);
  ASSERT_EQ(Compile(Query(pb::SEARCH_FORMAT_HEX, "a 0b"), false, c), "");
  EXPECT_EQ(c.pattern.Display(), "0a 0b");
  EXPECT_NE(Compile(Query(pb::SEARCH_FORMAT_HEX, "4g"), false, c), "");
  EXPECT_NE(Compile(Query(pb::SEARCH_FORMAT_HEX, "?? ??"), false, c), "");
  EXPECT_NE(Compile(Query(pb::SEARCH_FORMAT_HEX, ""), false, c), "");
}

TEST(SearchQuery, Binary) {
  search::Compiled c;
  ASSERT_EQ(Compile(Query(pb::SEARCH_FORMAT_BINARY, "10xx0101 11110000"), false, c), "");
  ASSERT_EQ(c.pattern.size(), 2u);
  EXPECT_EQ(static_cast<unsigned char>(c.pattern.value[0]), 0x85);
  EXPECT_EQ(static_cast<unsigned char>(c.pattern.mask[0]), 0xcf);
  EXPECT_EQ(c.pattern.Display(), "[85/cf] f0");
  EXPECT_NE(Compile(Query(pb::SEARCH_FORMAT_BINARY, "1010"), false, c), "");
  EXPECT_NE(Compile(Query(pb::SEARCH_FORMAT_BINARY, "10102010"), false, c), "");
}

TEST(SearchQuery, Strings) {
  search::Compiled c;
  auto q = Query(pb::SEARCH_FORMAT_STRING, "Hi\\n");
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.value, "Hi\\n");
  q.set_escape_sequences(true);
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.value, "Hi\n");
  EXPECT_EQ(c.pattern.fold, std::string("\1\1\0", 3));  // insensitive by default: letters fold
  q.set_case_sensitive(true);
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.fold, std::string(3, '\0'));
  q.set_query("A\\x00\\u00e9");
  q.set_encoding(pb::SEARCH_ENCODING_UTF8);
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.value, std::string("A\0\xc3\xa9", 4));
  q.set_encoding(pb::SEARCH_ENCODING_UTF16);
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.value, std::string("A\0\0\0\xe9\0", 6));
  ASSERT_EQ(Compile(q, true, c), "");
  EXPECT_EQ(c.pattern.value, std::string("\0A\0\0\0\xe9", 6));
  q.set_byte_order(pb::ENDIANNESS_LITTLE);
  ASSERT_EQ(Compile(q, true, c), "");
  EXPECT_EQ(c.pattern.value, std::string("A\0\0\0\xe9\0", 6));
  // A character beyond Latin-1 isn't ASCII.
  q.set_encoding(pb::SEARCH_ENCODING_ASCII);
  q.set_query("\xe2\x82\xac");
  EXPECT_NE(Compile(q, false, c), "");
  q.set_query("bad \\q escape");
  EXPECT_NE(Compile(q, false, c), "");
}

TEST(SearchQuery, Numbers) {
  search::Compiled c;
  auto q = Query(pb::SEARCH_FORMAT_DECIMAL, "1000000 -1 0x10");
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.value, std::string("\x40\x42\x0f\x00\xff\xff\xff\xff\x10\x00\x00\x00", 12));
  ASSERT_EQ(Compile(q, true, c), "");
  EXPECT_EQ(c.pattern.value, std::string("\x00\x0f\x42\x40\xff\xff\xff\xff\x00\x00\x00\x10", 12));
  q.set_value_size(2);
  q.set_query("-32768 65535");
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.value, std::string("\x00\x80\xff\xff", 4));
  q.set_query("65536");
  EXPECT_NE(Compile(q, false, c), "");
  q.set_query("-32769");
  EXPECT_NE(Compile(q, false, c), "");
  q.set_unsigned_values(true);
  q.set_query("-1");
  EXPECT_NE(Compile(q, false, c), "");
  q.set_value_size(8);
  q.set_query("18446744073709551615");
  ASSERT_EQ(Compile(q, false, c), "");
  EXPECT_EQ(c.pattern.value, std::string(8, '\xff'));
  q.set_value_size(3);
  EXPECT_NE(Compile(q, false, c), "");

  auto f = Query(pb::SEARCH_FORMAT_FLOAT, "2.5");
  ASSERT_EQ(Compile(f, false, c), "");
  float fv = 2.5f;
  EXPECT_EQ(c.pattern.value, std::string(reinterpret_cast<const char *>(&fv), 4));
  auto d = Query(pb::SEARCH_FORMAT_DOUBLE, "-0.125");
  ASSERT_EQ(Compile(d, true, c), "");
  EXPECT_EQ(c.pattern.value, std::string("\xbf\xc0\0\0\0\0\0\0", 8));
  EXPECT_NE(Compile(Query(pb::SEARCH_FORMAT_FLOAT, "1e300"), false, c), "");
  EXPECT_NE(Compile(Query(pb::SEARCH_FORMAT_DOUBLE, "pi"), false, c), "");
}

std::vector<std::pair<std::size_t, std::size_t>> Scan(const search::Compiled &c, const std::string &data,
                                                      std::size_t starts = std::string::npos) {
  std::string err;
  auto m = search::MakeByteMatcher(c, err);
  EXPECT_TRUE(m) << err;
  std::vector<std::pair<std::size_t, std::size_t>> out;
  if (!m) return out;
  m->Scan(reinterpret_cast<const unsigned char *>(data.data()), data.size(), std::min(starts, data.size()),
          [&](std::size_t at, std::size_t len) {
            out.emplace_back(at, len);
            return true;
          });
  return out;
}

TEST(SearchMatch, PatternsAndRegex) {
  search::Compiled c;
  ASSERT_EQ(Compile(Query(pb::SEARCH_FORMAT_HEX, "4? 8b"), false, c), "");
  const std::string data("\x48\x8b\x00\x41\x8b\x48\x8c\x4f\x8b", 9);
  EXPECT_EQ(Scan(c, data), (std::vector<std::pair<std::size_t, std::size_t>>{{0, 2}, {3, 2}, {7, 2}}));
  // Matches start before `starts` but may read past it.
  EXPECT_EQ(Scan(c, data, 8), (std::vector<std::pair<std::size_t, std::size_t>>{{0, 2}, {3, 2}, {7, 2}}));
  EXPECT_EQ(Scan(c, data, 7), (std::vector<std::pair<std::size_t, std::size_t>>{{0, 2}, {3, 2}}));
  // Case-insensitive ASCII, overlapping matches.
  auto s = Query(pb::SEARCH_FORMAT_STRING, "aA");
  ASSERT_EQ(Compile(s, false, c), "");
  EXPECT_EQ(Scan(c, "xAaAa"), (std::vector<std::pair<std::size_t, std::size_t>>{{1, 2}, {2, 2}, {3, 2}}));
  // A regex over bytes: non-ASCII bytes, alternation, no match past `starts`.
  auto r = Query(pb::SEARCH_FORMAT_REGEX, "\\xff[\\x00-\\x02]+|PK\\x03\\x04");
  ASSERT_EQ(Compile(r, false, c), "");
  EXPECT_EQ(Scan(c, std::string("ab\xff\x01\x02\x03PK\x03\x04", 10)),
            (std::vector<std::pair<std::size_t, std::size_t>>{{2, 3}, {6, 4}}));
  std::string err;
  EXPECT_EQ(search::MakeByteMatcher(search::Compiled{.pattern = {}, .regex = "a*", .is_regex = true}, err), nullptr);
  EXPECT_EQ(search::MakeByteMatcher(search::Compiled{.pattern = {}, .regex = "(", .is_regex = true}, err), nullptr);
}

TEST(SearchMatch, Text) {
  std::string err;
  std::size_t at = 0, len = 0;
  auto plain = search::TextMatcher::Make("eax", false, false, false, err);
  ASSERT_TRUE(plain);
  EXPECT_TRUE(plain->Find("MOV EAX,0x1", at, len));
  EXPECT_EQ(at, 4u);
  EXPECT_EQ(len, 3u);
  auto exact = search::TextMatcher::Make("eax", false, true, false, err);
  EXPECT_FALSE(exact->Find("MOV EAX,0x1", at, len));
  auto word = search::TextMatcher::Make("lua_State", false, true, true, err);
  EXPECT_FALSE(word->Find("lua_State_t x", at, len));
  EXPECT_TRUE(word->Find("lua_State_t x; lua_State *L", at, len));
  EXPECT_EQ(at, 15u);
  auto re = search::TextMatcher::Make("CALL +lua[A-Z]_", true, false, false, err);
  ASSERT_TRUE(re) << err;
  EXPECT_TRUE(re->Find("call luaL_newstate", at, len));
  EXPECT_EQ(len, 10u);
  // Non-ASCII, case-insensitive: Unicode folding.
  auto uni = search::TextMatcher::Make("ÉTÉ", false, false, false, err);
  ASSERT_TRUE(uni);
  EXPECT_TRUE(uni->Find("un été", at, len));
  EXPECT_EQ(at, 3u);
  EXPECT_EQ(search::TextMatcher::Make("", false, false, false, err), nullptr);
  EXPECT_EQ(search::TextMatcher::Make("(", true, false, false, err), nullptr);
  EXPECT_EQ(search::TextMatcher::Make("x*", true, false, false, err), nullptr);
}

// --- The RPCs on corpus programs ---------------------------------------------------

class SearchTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    backend_ = MakeImageBackend(o);
  }

  std::string Import(const fs::path &path) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(path.string());
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

  std::string Read(const std::string &program, std::uint64_t at, std::uint32_t n) {
    pb::ReadMemoryRequest req;
    req.set_program_id(program);
    req.mutable_address()->set_offset(at);
    req.set_length(n);
    pb::ReadMemoryResponse resp;
    EXPECT_TRUE(backend_->ReadMemory(ctx_, req, resp).ok());
    return resp.data();
  }

  // Every message of a search: its matches gathered, and the last message.
  template <class Req, class Resp, class Match>
  api::Status Run(api::Status (api::Backend::*rpc)(const CallContext &, const Req &, const std::function<bool(const Resp &)> &),
                  const Req &req, std::vector<Match> &out, Resp *last = nullptr, const CallContext *ctx = nullptr) {
    out.clear();
    int dones = 0;
    auto st = (backend_.get()->*rpc)(ctx ? *ctx : ctx_, req, [&](const Resp &m) {
      for (const auto &x : m.matches()) out.push_back(x);
      dones += m.done();
      if (last) *last = m;
      return true;
    });
    if (st.ok()) {
      EXPECT_EQ(dones, 1);
    }
    return st;
  }

  std::vector<pb::MemoryMatch> Memory(pb::SearchMemoryRequest req, pb::SearchMemoryResponse *last = nullptr) {
    std::vector<pb::MemoryMatch> out;
    auto st = Run(&api::Backend::SearchMemory, req, out, last);
    EXPECT_TRUE(st.ok()) << st.message;
    return out;
  }
  std::vector<pb::TextMatch> Text(pb::SearchTextRequest req, pb::SearchTextResponse *last = nullptr) {
    std::vector<pb::TextMatch> out;
    auto st = Run(&api::Backend::SearchText, req, out, last);
    EXPECT_TRUE(st.ok()) << st.message;
    return out;
  }
  std::vector<pb::ScalarMatch> Scalars(pb::SearchScalarsRequest req, pb::SearchScalarsResponse *last = nullptr) {
    std::vector<pb::ScalarMatch> out;
    auto st = Run(&api::Backend::SearchScalars, req, out, last);
    EXPECT_TRUE(st.ok()) << st.message;
    return out;
  }
  std::vector<pb::DecompiledMatch> Decompiled(pb::SearchDecompiledRequest req, pb::SearchDecompiledResponse *last = nullptr) {
    std::vector<pb::DecompiledMatch> out;
    auto st = Run(&api::Backend::SearchDecompiled, req, out, last);
    EXPECT_TRUE(st.ok()) << st.message;
    return out;
  }

  api::Status Assert(const std::string &program, const std::function<void(pb::AssertionBody &)> &fill) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    fill(*req.add_assertions()->mutable_body());
    pb::AppendAssertionsResponse resp;
    return backend_->AppendAssertions(ctx_, req, resp);
  }

  static std::vector<std::uint64_t> Addresses(const auto &matches) {
    std::vector<std::uint64_t> out;
    for (const auto &m : matches) out.push_back(m.address().offset());
    return out;
  }

  fs::path Corpus(const std::string &rel) { return fs::path(REVKIT_CORPUS) / rel; }

  std::unique_ptr<api::Backend> backend_;
  CallContext ctx_;
};

TEST_F(SearchTest, MemoryOnLua) {
  const fs::path lua = Corpus("elf-x86_64/gcc-O2/debug/lua");
  if (!fs::exists(lua)) GTEST_SKIP() << "corpus not built";
  const std::string id = Import(lua);
  const auto fns = Functions(id);

  // A string, as ASCII: found in the data, with the listing's view of it.
  pb::SearchMemoryRequest req;
  req.set_program_id(id);
  req.set_format(pb::SEARCH_FORMAT_STRING);
  req.set_query("attempt to compare");
  req.set_case_sensitive(true);
  req.set_details(true);
  pb::SearchMemoryResponse last;
  auto hits = Memory(req, &last);
  ASSERT_GE(hits.size(), 2u);  // "...compare %s with %s", "...compare two %s values"
  EXPECT_FALSE(last.truncated());
  EXPECT_EQ(last.bytes_searched(), last.bytes_total());
  EXPECT_GT(last.bytes_total(), 100000u);
  for (const auto &m : hits) {
    EXPECT_EQ(m.bytes(), "attempt to compare");
    EXPECT_EQ(Read(id, m.address().offset(), 18), "attempt to compare");
    EXPECT_NE(m.preview(), "") << m.address().offset();
  }
  // Case-insensitive finds the same; a different case only that way.
  req.set_query("ATTEMPT TO COMPARE");
  EXPECT_TRUE(Memory(req).empty());
  req.set_case_sensitive(false);
  EXPECT_EQ(Addresses(Memory(req)), Addresses(hits));

  // Hex with wildcards: a function's first bytes with one byte masked.
  const std::uint64_t entry = fns.at("luaH_resize");
  const std::string head = Read(id, entry, 6);
  char hex[64];
  std::snprintf(hex, sizeof hex, "%02x ?? %02x%02x %02x%02x", static_cast<unsigned char>(head[0]), static_cast<unsigned char>(head[2]),
                static_cast<unsigned char>(head[3]), static_cast<unsigned char>(head[4]), static_cast<unsigned char>(head[5]));
  pb::SearchMemoryRequest hx;
  hx.set_program_id(id);
  hx.set_query(hex);
  hx.set_max_results(100000);
  auto hx_hits = Addresses(Memory(hx, &last));
  EXPECT_NE(std::find(hx_hits.begin(), hx_hits.end(), entry), hx_hits.end()) << hex;
  EXPECT_EQ(last.pattern().substr(3, 2), "??");

  // The same bytes as binary with masks, and as a regex.
  pb::SearchMemoryRequest bin = hx;
  bin.set_format(pb::SEARCH_FORMAT_BINARY);
  std::string bits;
  for (int k = 0; k < 6; ++k) {
    for (int b = 7; b >= 0; --b) bits += k == 1 ? 'x' : ((static_cast<unsigned char>(head[k]) >> b) & 1) ? '1' : '0';
    bits += ' ';
  }
  bin.set_query(bits);
  EXPECT_EQ(Addresses(Memory(bin)), hx_hits);
  pb::SearchMemoryRequest re = hx;
  re.set_format(pb::SEARCH_FORMAT_REGEX);
  std::string rx;
  for (int k = 0; k < 6; ++k) {
    std::snprintf(hex, sizeof hex, "\\x%02x", static_cast<unsigned char>(head[k]));
    rx += k == 1 ? std::string("(?s:.)") : std::string(hex);
  }
  re.set_query(rx);
  EXPECT_EQ(Addresses(Memory(re)), hx_hits);

  // A 4-byte value from memory, as a decimal in the program's byte order.
  std::uint32_t v32;
  std::memcpy(&v32, head.data(), 4);
  pb::SearchMemoryRequest dec = hx;
  dec.set_format(pb::SEARCH_FORMAT_DECIMAL);
  dec.set_query(std::to_string(v32));
  dec.set_unsigned_values(true);
  auto dec_hits = Addresses(Memory(dec));
  EXPECT_NE(std::find(dec_hits.begin(), dec_hits.end(), entry), dec_hits.end());
  // Big-endian finds it only where the bytes are reversed.
  dec.set_byte_order(pb::ENDIANNESS_BIG);
  auto be_hits = Addresses(Memory(dec));
  EXPECT_EQ(std::find(be_hits.begin(), be_hits.end(), entry), be_hits.end());

  // Code units: the string is data, so "instructions only" doesn't find it.
  req.set_query("attempt to compare");
  req.mutable_scope()->set_instructions(true);
  EXPECT_TRUE(Memory(req).empty());
  req.mutable_scope()->set_defined_data(true);
  req.mutable_scope()->set_undefined(true);
  EXPECT_EQ(Memory(req).size(), hits.size());
  // A function's bytes are instructions.
  hx.mutable_scope()->set_instructions(true);
  auto in_code = Addresses(Memory(hx));
  EXPECT_NE(std::find(in_code.begin(), in_code.end(), entry), in_code.end());
  hx.mutable_scope()->set_instructions(false);
  hx.mutable_scope()->set_defined_data(true);
  auto in_data = Addresses(Memory(hx));
  EXPECT_EQ(std::find(in_data.begin(), in_data.end(), entry), in_data.end());
  hx.clear_scope();

  // A selection: only matches starting in it.
  pb::SearchMemoryRequest sel = req;
  sel.clear_scope();
  auto *range = sel.mutable_scope()->add_ranges();
  range->mutable_first()->set_offset(hits[0].address().offset());
  range->mutable_last()->set_offset(hits[0].address().offset());
  EXPECT_EQ(Addresses(Memory(sel)), std::vector<std::uint64_t>{hits[0].address().offset()});

  // Next and previous from an address, wrapping, alignment, the limit.
  pb::SearchMemoryRequest inc = hx;
  inc.set_max_results(1);
  inc.mutable_start()->mutable_from()->set_offset(entry);
  auto next = Memory(inc);
  auto after = std::upper_bound(hx_hits.begin(), hx_hits.end(), entry);
  if (after != hx_hits.end()) {
    ASSERT_EQ(Addresses(next), std::vector<std::uint64_t>{*after});
  }
  inc.mutable_start()->set_backward(true);
  auto prev = Memory(inc);
  auto before = std::lower_bound(hx_hits.begin(), hx_hits.end(), entry);
  if (before != hx_hits.begin()) {
    ASSERT_EQ(Addresses(prev), std::vector<std::uint64_t>{*std::prev(before)});
  }
  inc.mutable_start()->set_backward(false);
  inc.mutable_start()->mutable_from()->set_offset(hx_hits.back());
  EXPECT_TRUE(Memory(inc).empty());
  inc.mutable_start()->set_wrap(true);
  auto wrapped = Memory(inc);
  ASSERT_EQ(wrapped.size(), 1u);
  EXPECT_EQ(wrapped[0].address().offset(), hx_hits.front());
  EXPECT_TRUE(wrapped[0].wrapped());
  pb::SearchMemoryRequest all_back = hx;
  all_back.mutable_start()->set_backward(true);
  auto rev = Addresses(Memory(all_back));
  std::reverse(rev.begin(), rev.end());
  EXPECT_EQ(rev, hx_hits);
  if (hx_hits.size() > 2) {
    pb::SearchMemoryRequest lim = hx;
    lim.set_max_results(2);
    auto two = Memory(lim, &last);
    EXPECT_EQ(two.size(), 2u);
    EXPECT_TRUE(last.truncated());
  }
  pb::SearchMemoryRequest al = hx;
  al.set_alignment(16);
  for (std::uint64_t a : Addresses(Memory(al))) EXPECT_EQ(a % 16, 0u);

  // Bad queries are refused; a cancelled call stops.
  pb::SearchMemoryRequest bad = hx;
  bad.set_query("zz");
  std::vector<pb::MemoryMatch> none;
  EXPECT_EQ(Run(&api::Backend::SearchMemory, bad, none).code, StatusCode::kInvalidArgument);
  CallContext cancelled;
  cancelled.cancelled = [] { return true; };
  EXPECT_EQ(Run(&api::Backend::SearchMemory, hx, none, static_cast<pb::SearchMemoryResponse *>(nullptr), &cancelled).code,
            StatusCode::kCancelled);
}

TEST_F(SearchTest, Utf16OnPe) {
  const fs::path exe = Corpus("pe-x86_64/clang-O2/debug/features.exe");
  if (!fs::exists(exe)) GTEST_SKIP() << "corpus not built";
  const std::string id = Import(exe);
  pb::SearchMemoryRequest req;
  req.set_program_id(id);
  req.set_format(pb::SEARCH_FORMAT_STRING);
  req.set_encoding(pb::SEARCH_ENCODING_UTF16);
  req.set_query("(NULL)");
  auto hits = Memory(req);
  ASSERT_FALSE(hits.empty());
  EXPECT_EQ(hits[0].bytes(), std::string("(\0n\0u\0l\0l\0)\0", 12));
}

TEST_F(SearchTest, BigEndianProgramOrder) {
  const fs::path elf = fs::path(REVKIT_CORPUS).parent_path() / "firmware-corpus/mips/uboot-malta.elf";
  if (!fs::exists(elf)) GTEST_SKIP() << "firmware corpus not built";
  const std::string id = Import(elf);
  const auto fns = Functions(id);
  ASSERT_FALSE(fns.empty());
  const std::uint64_t entry = fns.begin()->second;
  const std::string w = Read(id, entry, 4);
  ASSERT_EQ(w.size(), 4u);
  const std::uint32_t be = (std::uint32_t{static_cast<unsigned char>(w[0])} << 24) | (static_cast<unsigned char>(w[1]) << 16) |
                           (static_cast<unsigned char>(w[2]) << 8) | static_cast<unsigned char>(w[3]);
  pb::SearchMemoryRequest req;
  req.set_program_id(id);
  req.set_format(pb::SEARCH_FORMAT_DECIMAL);
  req.set_unsigned_values(true);
  req.set_query(std::to_string(be));
  req.set_max_results(100000);
  auto hits = Addresses(Memory(req));
  EXPECT_NE(std::find(hits.begin(), hits.end(), entry), hits.end());
}

TEST_F(SearchTest, TextOnLua) {
  const fs::path lua = Corpus("elf-x86_64/gcc-O2/debug/lua");
  if (!fs::exists(lua)) GTEST_SKIP() << "corpus not built";
  const std::string id = Import(lua);
  const auto fns = Functions(id);

  // Instructions as the listing shows them: a call names its target.
  pb::SearchTextRequest req;
  req.set_program_id(id);
  req.set_query("CALL luaH_resize");
  req.set_max_results(100000);
  pb::SearchTextResponse last;
  auto calls = Text(req, &last);
  ASSERT_FALSE(calls.empty());
  EXPECT_EQ(last.rows_searched(), last.rows_total());
  for (const auto &m : calls) {
    EXPECT_EQ(m.field(), pb::TEXT_FIELD_MNEMONICS);
    EXPECT_EQ(m.text().substr(m.match_start(), m.match_length()), "CALL luaH_resize");
    EXPECT_NE(m.function_name(), "");
  }
  // Operands only, case-sensitive, whole words, regex.
  req.add_fields(pb::TEXT_FIELD_OPERANDS);
  req.set_query("luaH_resize");
  auto ops = Text(req);
  EXPECT_GE(ops.size(), calls.size());
  for (const auto &m : ops) EXPECT_EQ(m.field(), pb::TEXT_FIELD_OPERANDS);
  req.clear_fields();
  req.set_case_sensitive(true);
  req.set_query("call luah_resize");
  EXPECT_TRUE(Text(req).empty());
  req.set_case_sensitive(false);
  req.set_query("CALL +luaH_re[s]ize");  // luaH_resizearray's calls too, as plain text
  req.set_regex(true);
  EXPECT_EQ(Addresses(Text(req)), Addresses(calls));
  req.set_regex(false);

  // Labels and signatures: the function itself.
  pb::SearchTextRequest lab;
  lab.set_program_id(id);
  lab.set_query("luaH_resize");
  lab.set_whole_word(true);
  lab.add_fields(pb::TEXT_FIELD_LABELS);
  lab.add_fields(pb::TEXT_FIELD_FUNCTIONS);
  auto labels = Text(lab);
  std::set<pb::TextField> kinds;
  for (const auto &m : labels)
    if (m.address().offset() == fns.at("luaH_resize")) kinds.insert(m.field());
  EXPECT_TRUE(kinds.contains(pb::TEXT_FIELD_LABELS));
  EXPECT_TRUE(kinds.contains(pb::TEXT_FIELD_FUNCTIONS));

  // Defined data: a string's value.
  pb::SearchTextRequest data;
  data.set_program_id(id);
  data.set_query("attempt to compare");
  data.add_fields(pb::TEXT_FIELD_DATA_VALUES);
  auto strings = Text(data);
  ASSERT_FALSE(strings.empty());
  for (const auto &m : strings) EXPECT_EQ(m.field(), pb::TEXT_FIELD_DATA_VALUES);

  // What the user sees: a rename reaches labels, signatures and operands,
  // and a comment is found by its text.
  ASSERT_TRUE(Assert(id, [&](pb::AssertionBody &b) {
                b.mutable_rename()->mutable_target()->mutable_address()->set_offset(fns.at("luaH_resize"));
                b.mutable_rename()->set_name("grow_table_xyzzy");
              }).ok());
  const std::uint64_t at = calls[0].address().offset();
  ASSERT_TRUE(Assert(id, [&](pb::AssertionBody &b) {
                b.mutable_comment()->mutable_address()->set_offset(at);
                b.mutable_comment()->set_kind(pb::COMMENT_KIND_EOL);
                b.mutable_comment()->set_text("first line\nthe needle_comment here");
              }).ok());
  req.set_query("CALL luaH_resize");
  req.set_whole_word(true);
  EXPECT_TRUE(Text(req).empty());
  req.set_whole_word(false);
  req.set_query("grow_table_xyzzy");
  auto renamed = Text(req);
  std::set<pb::TextField> fields;
  for (const auto &m : renamed) fields.insert(m.field());
  EXPECT_TRUE(fields.contains(pb::TEXT_FIELD_LABELS));
  EXPECT_TRUE(fields.contains(pb::TEXT_FIELD_FUNCTIONS));
  EXPECT_TRUE(fields.contains(pb::TEXT_FIELD_OPERANDS));  // in "CALL grow_table_xyzzy"
  EXPECT_GE(renamed.size(), calls.size() + 2);
  req.set_query("needle_comment");
  auto comments = Text(req);
  ASSERT_EQ(comments.size(), 1u);
  EXPECT_EQ(comments[0].field(), pb::TEXT_FIELD_COMMENTS);
  EXPECT_EQ(comments[0].comment_kind(), pb::COMMENT_KIND_EOL);
  EXPECT_EQ(comments[0].text(), "the needle_comment here");
  EXPECT_EQ(comments[0].address().offset(), at);

  // Next and previous; a selection; backward is the reverse.
  pb::SearchTextRequest all;
  all.set_program_id(id);
  all.set_query("xor eax,eax");
  all.set_max_results(100000);
  auto every = Addresses(Text(all));
  ASSERT_GT(every.size(), 10u);
  const std::uint64_t mid = every[every.size() / 2];
  pb::SearchTextRequest inc = all;
  inc.set_max_results(1);
  inc.mutable_start()->mutable_from()->set_offset(mid);
  EXPECT_EQ(Addresses(Text(inc)), std::vector<std::uint64_t>{*std::upper_bound(every.begin(), every.end(), mid)});
  inc.mutable_start()->set_backward(true);
  EXPECT_EQ(Addresses(Text(inc)), std::vector<std::uint64_t>{*std::prev(std::lower_bound(every.begin(), every.end(), mid))});
  pb::SearchTextRequest back = all;
  back.mutable_start()->set_backward(true);
  auto reversed = Addresses(Text(back));
  std::reverse(reversed.begin(), reversed.end());
  EXPECT_EQ(reversed, every);
  pb::SearchTextRequest sel = all;
  auto *r = sel.mutable_scope()->add_ranges();
  r->mutable_first()->set_offset(every[2]);
  r->mutable_last()->set_offset(every[5]);
  EXPECT_EQ(Addresses(Text(sel)), std::vector<std::uint64_t>(every.begin() + 2, every.begin() + 6));
  pb::SearchTextRequest lim = all;
  lim.set_max_results(3);
  EXPECT_EQ(Addresses(Text(lim, &last)), std::vector<std::uint64_t>(every.begin(), every.begin() + 3));
  EXPECT_TRUE(last.truncated());
}

TEST_F(SearchTest, ScalarsOnLua) {
  const fs::path lua = Corpus("elf-x86_64/gcc-O2/debug/lua");
  if (!fs::exists(lua)) GTEST_SKIP() << "corpus not built";
  const std::string id = Import(lua);
  // LUAI_MAXSTACK (1,000,000) bounds the stack in ldo.c.
  pb::SearchScalarsRequest req;
  req.set_program_id(id);
  req.set_min(1000000);
  req.set_max(1000000);
  auto hits = Scalars(req);
  ASSERT_FALSE(hits.empty());
  bool ldo = false;
  for (const auto &m : hits) {
    EXPECT_EQ(m.value(), 1000000);
    EXPECT_FALSE(m.data());
    EXPECT_GE(m.operand_index(), 0);
    EXPECT_NE(m.text().find("0xf4240"), std::string::npos) << m.text();
    ldo |= m.function_name().starts_with("luaD_");
  }
  EXPECT_TRUE(ldo);
  // An equate on it (feature "equates") is what the listing shows, so a
  // text search finds the name, and the scalar is still found by value.
  ASSERT_TRUE(Assert(id, [&](pb::AssertionBody &b) {
                b.mutable_operand_display()->mutable_address()->set_offset(hits[0].address().offset());
                b.mutable_operand_display()->set_value(1000000);
                b.mutable_operand_display()->mutable_equate()->set_name("LUAI_MAXSTACK_EQ");
              }).ok());
  pb::SearchTextRequest eq;
  eq.set_program_id(id);
  eq.set_query("LUAI_MAXSTACK_EQ");
  auto named = Text(eq);
  ASSERT_FALSE(named.empty());
  EXPECT_EQ(named[0].address().offset(), hits[0].address().offset());
  EXPECT_EQ(named[0].field(), pb::TEXT_FIELD_OPERANDS);
  auto again = Scalars(req);
  ASSERT_EQ(again.size(), hits.size());
  EXPECT_NE(again[0].text().find("LUAI_MAXSTACK_EQ"), std::string::npos) << again[0].text();
  // A range holds the exact value's matches; data only finds none of them.
  pb::SearchScalarsRequest range = req;
  range.set_min(999999);
  range.set_max(1000001);
  range.set_max_results(100000);
  auto in_range = Scalars(range);
  EXPECT_GE(in_range.size(), hits.size());
  range.mutable_scope()->set_defined_data(true);
  for (const auto &m : Scalars(range)) EXPECT_TRUE(m.data());
  // -1 matches as signed; a 32-bit 0xffffffff also as unsigned.
  pb::SearchScalarsRequest neg;
  neg.set_program_id(id);
  neg.set_min(-1);
  neg.set_max(-1);
  neg.set_max_results(10);
  auto minus = Scalars(neg);
  ASSERT_FALSE(minus.empty());
  for (const auto &m : minus) EXPECT_EQ(m.value(), -1);
  pb::SearchScalarsRequest bad = req;
  bad.set_min(2);
  bad.set_max(1);
  std::vector<pb::ScalarMatch> none;
  EXPECT_EQ(Run(&api::Backend::SearchScalars, bad, none).code, StatusCode::kInvalidArgument);
}

TEST_F(SearchTest, DecompiledOnLua) {
  const fs::path lua = Corpus("elf-x86_64/gcc-O2/debug/lua");
  if (!fs::exists(lua)) GTEST_SKIP() << "corpus not built";
  const std::string id = Import(lua);
  const auto fns = Functions(id);
  const std::uint64_t main = fns.at("main");
  pb::SearchDecompiledRequest req;
  req.set_program_id(id);
  req.set_query("luaL_newstate");
  req.set_whole_word(true);
  req.add_functions()->set_offset(main);
  pb::SearchDecompiledResponse last;
  auto hits = Decompiled(req, &last);
  ASSERT_EQ(hits.size(), 1u);
  EXPECT_EQ(last.functions_done(), 1u);
  EXPECT_EQ(last.functions_total(), 1u);
  EXPECT_EQ(hits[0].function().offset(), main);
  EXPECT_EQ(hits[0].function_name(), "main");
  EXPECT_EQ(hits[0].text().substr(hits[0].match_start(), hits[0].match_length()), "luaL_newstate");
  // The line is the decompiler's line of that index.
  pb::DecompileRequest d;
  d.set_program_id(id);
  d.mutable_function()->set_offset(main);
  pb::DecompileResponse dr;
  ASSERT_TRUE(backend_->Decompile(ctx_, d, dr).ok());
  ASSERT_LT(static_cast<int>(hits[0].line()), dr.function().lines_size());
  std::string text;
  for (const auto &t : dr.function().lines(static_cast<int>(hits[0].line())).tokens()) text += t.text();
  EXPECT_EQ(text, hits[0].text());
  // By range (a selection inside main searches main), regex, the limit.
  pb::SearchDecompiledRequest by_range;
  by_range.set_program_id(id);
  by_range.set_query("lua_[a-z]+\\(");
  by_range.set_regex(true);
  auto *r = by_range.add_ranges();
  r->mutable_first()->set_offset(main + 1);
  r->mutable_last()->set_offset(main + 1);
  auto calls = Decompiled(by_range);
  EXPECT_GT(calls.size(), 1u);
  for (const auto &m : calls) EXPECT_EQ(m.function().offset(), main);
  by_range.set_max_results(1);
  auto one = Decompiled(by_range, &last);
  EXPECT_EQ(one.size(), 1u);
  EXPECT_TRUE(last.truncated());
  // Every function, stopped by the limit.
  pb::SearchDecompiledRequest every;
  every.set_program_id(id);
  every.set_query("return");
  every.set_all(true);
  every.set_max_results(5);
  auto five = Decompiled(every, &last);
  EXPECT_EQ(five.size(), 5u);
  EXPECT_TRUE(last.truncated());
  pb::SearchDecompiledRequest neither;
  neither.set_program_id(id);
  neither.set_query("x");
  std::vector<pb::DecompiledMatch> none;
  EXPECT_EQ(Run(&api::Backend::SearchDecompiled, neither, none).code, StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace revkit::backend
