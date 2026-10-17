// Data settings (docs/listing-edit.md#data-settings): how a data item
// displays, per item, per struct field and per type, as NOTE assertions
// with reserved tags; the helpers that format values; and that settings
// survive undo, rebase and a project archive.
#include "builders.hh"
#include "data_settings.h"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <filesystem>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;
using F = DataSettings::Format;
using P = DataSettings::Padding;

// ---- the helpers --------------------------------------------------------

TEST(DataSettingsText, RoundTripsAndSkipsWhatALaterDaemonAdds) {
  DataSettings s;
  EXPECT_TRUE(s.empty());
  EXPECT_EQ(s.encode(), "");
  s.format = F::decimal;
  s.sign = DataSettings::Sign::is_signed;
  s.endian = DataSettings::Endian::big;
  s.charset = "ISO-8859-1";
  s.termination = DataSettings::Termination::all;
  s.pointer = DataSettings::Pointer::image_base;
  s.mask = 0xffff;
  s.shift = -2;
  EXPECT_EQ(s.encode(), "format=decimal;sign=signed;endian=big;charset=ISO-8859-1;term=all;pointer=image-base;mask=ffff;shift=-2");
  EXPECT_EQ(DataSettings::parse(s.encode()), s);
  EXPECT_EQ(DataSettings::parse(""), DataSettings{});
  auto later = DataSettings::parse("format=octal;colour=red");
  ASSERT_TRUE(later);
  EXPECT_EQ(later->format, F::octal);
  EXPECT_FALSE(DataSettings::parse("format=roman"));
  EXPECT_FALSE(DataSettings::parse("nonsense"));
  EXPECT_FALSE(DataSettings::parse("mask=0"));
  EXPECT_FALSE(DataSettings::parse("charset=EBCDIC"));

  // Each unset setting falls back.
  DataSettings type;
  type.format = F::hex;
  type.padding = P::padded;
  DataSettings own;
  own.format = F::binary;
  const DataSettings both = own.over(type);
  EXPECT_EQ(both.format, F::binary);
  EXPECT_EQ(both.padding, P::padded);
}

TEST(DataSettingsText, ValidatesTheApiMessage) {
  std::string err;
  pb::DataSettings p;
  p.set_charset("latin1");
  auto s = DataSettings::from_proto(p, &err);
  ASSERT_TRUE(s) << err;
  EXPECT_EQ(s->charset, "ISO-8859-1");
  EXPECT_EQ(DataSettings::from_proto(s->to_proto(), &err), s);
  p.set_charset("klingon");
  EXPECT_FALSE(DataSettings::from_proto(p, &err));
  EXPECT_NE(err.find("windows-1252"), std::string::npos) << err;
  pb::DataSettings m;
  m.set_pointer_mask(0);
  EXPECT_FALSE(DataSettings::from_proto(m, &err));
  pb::DataSettings sh;
  sh.set_pointer_shift(64);
  EXPECT_FALSE(DataSettings::from_proto(sh, &err));
  pb::DataSettings f;
  f.set_format(static_cast<pb::DataFormat>(9));
  EXPECT_FALSE(DataSettings::from_proto(f, &err));
}

TEST(DataSettingsFormat, IntegersInEveryFormat) {
  const std::string v("\x2a\x00\x00\x00", 4);  // 42, little endian
  EXPECT_EQ(FormatInteger(v, false, false, F::hex, P::unset), "0000002ah");
  EXPECT_EQ(FormatInteger(v, false, false, F::hex, P::unpadded), "2ah");
  EXPECT_EQ(FormatInteger(v, false, false, F::decimal, P::unset), "42");
  EXPECT_EQ(FormatInteger(v, false, false, F::octal, P::unset), "52o");
  EXPECT_EQ(FormatInteger(v, false, false, F::octal, P::padded), "00000000052o");
  EXPECT_EQ(FormatInteger(v, false, false, F::binary, P::unset), "101010b");
  EXPECT_EQ(FormatInteger(std::string("\x2a", 1), false, false, F::binary, P::padded), "00101010b");
  EXPECT_EQ(FormatInteger(v, true, false, F::hex, P::unset), "2a000000h");
  const std::string neg("\xfe\xff", 2);  // -2
  EXPECT_EQ(FormatInteger(neg, false, true, F::decimal, P::unset), "-2");
  EXPECT_EQ(FormatInteger(neg, false, false, F::decimal, P::unset), "65534");
  EXPECT_EQ(FormatInteger(neg, false, true, F::hex, P::unset), "-2h");
  EXPECT_EQ(FormatInteger(neg, false, true, F::hex, P::padded), "-0002h");
  EXPECT_EQ(FormatInteger(std::string("\x80\0\0\0\0\0\0\0", 8), true, true, F::decimal, P::unset), "-9223372036854775808");
  EXPECT_EQ(FormatInteger(std::string("ABCD", 4), true, false, F::character, P::unset), "'ABCD'");
  EXPECT_EQ(FormatInteger(std::string("\x01'", 2), true, false, F::character, P::unset), "'\\x01\\''");
  EXPECT_EQ(FormatInteger("", false, false, F::hex, P::unset), "??");
}

TEST(DataSettingsFormat, StringsInEveryCharset) {
  const std::string cafe("caf\xe9\0x", 6);
  EXPECT_EQ(QuoteChars(cafe, "ISO-8859-1", false, false, ""), "\"caf\xc3\xa9\"");
  EXPECT_EQ(QuoteChars(cafe, "US-ASCII", false, false, ""), "\"caf\\xe9\"");
  EXPECT_EQ(QuoteChars(cafe, "UTF-8", false, false, ""), "\"caf\\xe9\"");
  EXPECT_EQ(QuoteChars(cafe, "ISO-8859-1", false, true, ""), "\"caf\xc3\xa9\\0x\"");
  EXPECT_EQ(QuoteChars("\x80\x81", "windows-1252", false, false, ""), "\"\xe2\x82\xac\\x81\"");
  EXPECT_EQ(QuoteChars("caf\xc3\xa9\n", "UTF-8", false, false, ""), "\"caf\xc3\xa9\\n\"");
  const std::string hi("h\0i\0\0\0", 6);
  EXPECT_EQ(QuoteChars(hi, "UTF-16LE", true, false, "u"), "u\"hi\"");
  EXPECT_EQ(QuoteChars(hi, "UTF-16", false, false, "u"), "u\"hi\"");
  EXPECT_EQ(QuoteChars(std::string("\0h", 2), "UTF-16", true, false, "u"), "u\"h\"");
  EXPECT_EQ(QuoteChars(std::string("\x3d\xd8\x00\xde", 4), "UTF-16LE", false, false, "u"), "u\"\xf0\x9f\x98\x80\"");
  EXPECT_EQ(QuoteChars(std::string("\0\0\0A", 4), "UTF-32BE", false, false, "U"), "U\"A\"");
  EXPECT_EQ(CharsetPrefix("UTF-16BE"), "u");
  EXPECT_EQ(CharsetPrefix("windows-1252"), "");
  EXPECT_EQ(CanonicalCharset("utf_16le"), "UTF-16LE");
  EXPECT_EQ(CanonicalCharset("Latin1"), "ISO-8859-1");
  EXPECT_FALSE(CanonicalCharset("shift-jis"));
}

// ---- on a program --------------------------------------------------------

constexpr const char *kProgram = R"(
struct conf { int magic; short port; short flags; const char *name; };
__attribute__((used)) struct conf config = {0x1234, 80, 3, "server"};
__attribute__((used)) int threshold = 0x12345678;
__attribute__((used)) unsigned counts[4] = {10, 20, 30, 40};
__attribute__((used)) const unsigned char latin[] = {'c', 'a', 'f', 0xe9, 0};
__attribute__((used)) const char padded[8] = "ab";
__attribute__((used)) const unsigned short wide[] = {'h', 'i', 0};
__attribute__((used)) const char *greeting = "greetings";
__attribute__((noinline)) int get(int i) { return config.port + threshold + (int)counts[i & 3] + latin[i & 3] + padded[i & 7] + wide[i & 1] + greeting[0]; }
int main(int argc, char **argv) { (void)argv; return get(argc); }
)";

class DataSettingsTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("data-settings");
    exe_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -fno-pie -no-pie", exe_);
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
  }

  std::uint64_t Symbol(const std::string &name, const std::string &program = "") {
    pb::ListSymbolsRequest req;
    req.set_program_id(program.empty() ? id_ : program);
    req.set_name_equals(name);
    pb::ListSymbolsResponse resp;
    EXPECT_TRUE(backend_->ListSymbols(ctx_, req, resp).ok());
    EXPECT_EQ(resp.symbols_size(), 1) << name;
    return resp.symbols_size() ? resp.symbols(0).address().offset() : 0;
  }

  std::vector<pb::ListingRow> Rows(std::uint64_t a, std::uint32_t n = 8, const std::string &program = "") {
    pb::GetListingRequest req;
    req.set_program_id(program.empty() ? id_ : program);
    req.mutable_addresses()->mutable_start()->set_offset(a);
    req.mutable_addresses()->set_max_rows(n);
    pb::GetListingResponse resp;
    EXPECT_TRUE(backend_->GetListing(ctx_, req, resp).ok());
    return {resp.rows().begin(), resp.rows().end()};
  }
  pb::ListingRow Row(std::uint64_t a, const std::string &field = "", const std::string &program = "") {
    for (const auto &r : Rows(a, 12, program))
      if ((field.empty() ? r.address().offset() == a && !r.has_data_parent() : r.data_field() == field)) return r;
    return {};
  }
  static std::string Value(const pb::ListingRow &r) {
    std::string out;
    for (const auto &t : r.tokens())
      if (t.kind() == pb::LISTING_TOKEN_KIND_DATA_VALUE) out += t.text();
    return out;
  }
  static std::uint64_t Target(const pb::ListingRow &r) {
    for (const auto &t : r.tokens())
      if (t.has_target()) return t.target().offset();
    return 0;
  }

  api::Status Edit(const std::vector<pb::AssertionBody> &bodies, pb::AppendAssertionsResponse *out = nullptr) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    for (const auto &b : bodies) *req.add_assertions()->mutable_body() = b;
    pb::AppendAssertionsResponse resp;
    auto st = backend_->AppendAssertions(ctx_, req, resp);
    if (out) *out = resp;
    return st;
  }
  pb::AppendAssertionsResponse MustEdit(const pb::AssertionBody &body) {
    pb::AppendAssertionsResponse resp;
    auto st = Edit({body}, &resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
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

  static pb::AssertionBody Data(std::uint64_t a, const std::string &type, std::uint64_t count = 0) {
    pb::AssertionBody b;
    b.mutable_listing_edit()->mutable_address()->set_offset(a);
    b.mutable_listing_edit()->mutable_data()->mutable_type()->set_c_declaration(type);
    b.mutable_listing_edit()->mutable_data()->set_count(count);
    return b;
  }
  static pb::AssertionBody String(std::uint64_t a, pb::StringEncoding e = pb::STRING_ENCODING_UTF8) {
    pb::AssertionBody b;
    b.mutable_listing_edit()->mutable_address()->set_offset(a);
    b.mutable_listing_edit()->mutable_data()->set_string(e);
    return b;
  }
  static pb::AssertionBody Settings(std::uint64_t a, const pb::DataSettings &s, const std::string &field = "") {
    pb::AssertionBody b;
    b.mutable_data_settings()->mutable_address()->set_offset(a);
    b.mutable_data_settings()->set_field(field);
    *b.mutable_data_settings()->mutable_settings() = s;
    return b;
  }
  static pb::AssertionBody TypeSettings(const std::string &type, const pb::DataSettings &s) {
    pb::AssertionBody b;
    b.mutable_data_settings()->set_type_name(type);
    *b.mutable_data_settings()->mutable_settings() = s;
    return b;
  }
  static pb::DataSettings Format(pb::DataFormat f) {
    pb::DataSettings s;
    s.set_format(f);
    return s;
  }

  static inline std::filesystem::path exe_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
  std::string id_;
};

TEST_F(DataSettingsTest, AnItemShowsAsItsSettingsSayAndUndoGivesTheOldDisplayBack) {
  const std::uint64_t threshold = Symbol("threshold");
  MustEdit(Data(threshold, "int"));
  const pb::ListingRow before = Row(threshold);
  EXPECT_EQ(Value(before), "12345678h");
  EXPECT_EQ(before.data_settings_type(), "int");
  EXPECT_FALSE(before.has_data_settings());

  // Settings with nothing set change nothing.
  auto none = MustEdit(Settings(threshold, pb::DataSettings{}));
  EXPECT_EQ(Value(Row(threshold)), "12345678h");
  Undo(none);

  auto dec = MustEdit(Settings(threshold, Format(pb::DATA_FORMAT_DECIMAL)));
  ASSERT_EQ(dec.assertions_size(), 1);
  // Stored as a NOTE an older daemon reads as a note (docs/listing-edit.md).
  EXPECT_EQ(dec.assertions(0).key().kind(), pb::FACT_KIND_NOTE);
  EXPECT_EQ(dec.assertions(0).key().sub(), "revkit:data-settings");
  EXPECT_TRUE(dec.assertions(0).body().has_data_settings());
  pb::ListingRow r = Row(threshold);
  EXPECT_EQ(Value(r), "305419896");
  EXPECT_EQ(r.data_settings().format(), pb::DATA_FORMAT_DECIMAL);
  EXPECT_EQ(r.data_settings_origin().asserted().provenance().id(), "alice");

  pb::DataSettings big;
  big.set_endian(pb::DATA_ENDIAN_BIG);
  big.set_padding(pb::DATA_PADDING_PADDED);
  auto swapped = MustEdit(Settings(threshold, big));
  EXPECT_EQ(Value(Row(threshold)), "78563412h");
  pb::DataSettings bin = Format(pb::DATA_FORMAT_BINARY);
  bin.set_signedness(pb::DATA_SIGNEDNESS_UNSIGNED);
  auto binary = MustEdit(Settings(threshold, bin));
  EXPECT_EQ(Value(Row(threshold)), "10010001101000101011001111000b");

  Undo(binary);
  EXPECT_EQ(Value(Row(threshold)), "78563412h");
  Undo(swapped);
  Undo(dec);
  EXPECT_EQ(Value(Row(threshold)), "12345678h");
  EXPECT_FALSE(Row(threshold).has_data_settings());
}

TEST_F(DataSettingsTest, ATypesDefaultsApplyWhereAnItemsOwnDont) {
  const std::uint64_t threshold = Symbol("threshold"), config = Symbol("config");
  MustEdit(Data(threshold, "int"));
  MustEdit(Data(config, "struct conf { int magic; short port; short flags; const char *name; }"));
  EXPECT_EQ(Value(Row(config, "magic")), "1234h");

  auto ints = MustEdit(TypeSettings("int", Format(pb::DATA_FORMAT_DECIMAL)));
  EXPECT_EQ(ints.assertions(0).key().kind(), pb::FACT_KIND_NOTE);
  EXPECT_EQ(Value(Row(threshold)), "305419896");
  const pb::ListingRow magic = Row(config, "magic");
  EXPECT_EQ(Value(magic), "4660");  // a struct field of the type follows too
  EXPECT_EQ(magic.data_settings_type(), "int");
  EXPECT_EQ(magic.data_type_settings().format(), pb::DATA_FORMAT_DECIMAL);
  EXPECT_EQ(Value(Row(config, "port")), "50h");  // a short isn't an int

  // The item's own setting wins; the rest still come from the type.
  auto hex = MustEdit(Settings(threshold, Format(pb::DATA_FORMAT_HEX)));
  EXPECT_EQ(Value(Row(threshold)), "12345678h");
  EXPECT_EQ(Value(Row(config, "magic")), "4660");

  // A struct field's own settings.
  auto port = MustEdit(Settings(config, Format(pb::DATA_FORMAT_DECIMAL), "port"));
  EXPECT_EQ(Value(Row(config, "port")), "80");
  EXPECT_EQ(Row(config, "port").data_settings().format(), pb::DATA_FORMAT_DECIMAL);
  EXPECT_EQ(Value(Row(config, "flags")), "3h");

  Undo(port);
  Undo(hex);
  Undo(ints);
  EXPECT_EQ(Value(Row(threshold)), "12345678h");
  EXPECT_EQ(Value(Row(config, "magic")), "1234h");
}

TEST_F(DataSettingsTest, ArraysStringsAndPointers) {
  const std::uint64_t counts = Symbol("counts"), latin = Symbol("latin"), padded = Symbol("padded"),
                      wide = Symbol("wide"), greeting = Symbol("greeting");
  // An array's elements take the item's settings.
  MustEdit(Data(counts, "unsigned int", 4));
  EXPECT_EQ(Value(Row(counts)), "{0000000ah, 00000014h, 0000001eh, 00000028h}");
  MustEdit(Settings(counts, Format(pb::DATA_FORMAT_DECIMAL)));
  EXPECT_EQ(Value(Row(counts)), "{10, 20, 30, 40}");
  EXPECT_EQ(Row(counts).data_settings_type(), "unsigned int");

  // A string in another charset.
  MustEdit(String(latin));
  EXPECT_EQ(Value(Row(latin)), "\"caf\\xe9\"");  // not UTF-8: escaped (a protobuf string must be UTF-8)
  pb::DataSettings l1;
  l1.set_charset("ISO-8859-1");
  MustEdit(Settings(latin, l1));
  EXPECT_EQ(Value(Row(latin)), "\"caf\xc3\xa9\"");
  EXPECT_EQ(Row(latin).data_settings_type(), "string");

  // A char array to its end.
  MustEdit(Data(padded, "char", 8));
  EXPECT_EQ(Value(Row(padded)), "\"ab\"");
  pb::DataSettings all;
  all.set_termination(pb::STRING_TERMINATION_ALL);
  MustEdit(Settings(padded, all));
  EXPECT_EQ(Value(Row(padded)), "\"ab\\0\\0\\0\\0\\0\\0\"");

  // UTF-16 read big endian.
  MustEdit(String(wide, pb::STRING_ENCODING_UTF16));
  EXPECT_EQ(Value(Row(wide)), "u\"hi\"");
  pb::DataSettings be;
  be.set_charset("UTF-16BE");
  MustEdit(Settings(wide, be));
  EXPECT_EQ(Value(Row(wide)), "u\"\xe6\xa0\x80\xe6\xa4\x80\"");  // U+6800 U+6900

  // A pointer as an image-base offset, and masked.
  MustEdit(Data(greeting, "char *"));
  const std::uint64_t target = Target(Row(greeting));
  ASSERT_NE(target, 0u);
  pb::GetProgramSummaryRequest sr;
  sr.set_program_id(id_);
  pb::GetProgramSummaryResponse summary;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, sr, summary).ok());
  const std::uint64_t base = summary.summary().image_base().offset();
  pb::DataSettings ibo;
  ibo.set_pointer_kind(pb::POINTER_KIND_IMAGE_BASE_OFFSET);
  auto as_ibo = MustEdit(Settings(greeting, ibo));
  EXPECT_EQ(Target(Row(greeting)), target + base);
  Undo(as_ibo);
  pb::DataSettings masked;
  masked.set_pointer_mask(0xffff);
  masked.set_pointer_kind(pb::POINTER_KIND_RELATIVE);
  MustEdit(Settings(greeting, masked));
  EXPECT_EQ(Target(Row(greeting)), (target & 0xffff) + greeting);
}

TEST_F(DataSettingsTest, RefusesWhatItCantKeepAndReservesItsTags) {
  const std::uint64_t threshold = Symbol("threshold");
  pb::DataSettings bad;
  bad.set_charset("EBCDIC");
  EXPECT_EQ(Edit({Settings(threshold, bad)}).code, StatusCode::kInvalidArgument);
  pb::AssertionBody both = TypeSettings("int", Format(pb::DATA_FORMAT_DECIMAL));
  both.mutable_data_settings()->mutable_address()->set_offset(threshold);
  EXPECT_EQ(Edit({both}).code, StatusCode::kInvalidArgument);
  pb::AssertionBody neither;
  neither.mutable_data_settings();
  EXPECT_EQ(Edit({neither}).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Edit({Settings(threshold, Format(pb::DATA_FORMAT_DECIMAL), "[2]")}).code, StatusCode::kInvalidArgument);
  EXPECT_EQ(Edit({Settings(0x10, Format(pb::DATA_FORMAT_DECIMAL))}).code, StatusCode::kInvalidArgument);  // not in memory
  pb::AssertionBody note;
  note.mutable_note()->mutable_address()->set_offset(threshold);
  note.mutable_note()->set_tag("revkit:data-settings");
  note.mutable_note()->set_text("format=decimal");
  EXPECT_EQ(Edit({note}).code, StatusCode::kInvalidArgument);

  // Settings aren't bookmarks: next-note navigation passes them.
  MustEdit(Settings(threshold, Format(pb::DATA_FORMAT_DECIMAL)));
  pb::FindNextRequest fn;
  fn.set_program_id(id_);
  fn.mutable_from()->set_offset(0);
  fn.set_kind(pb::NAVIGATION_KIND_NOTE);
  pb::FindNextResponse found;
  ASSERT_TRUE(backend_->FindNext(ctx_, fn, found).ok());
  EXPECT_FALSE(found.found());
}

TEST_F(DataSettingsTest, SettingsFollowARebaseAndAProjectArchive) {
  const std::uint64_t threshold = Symbol("threshold"), counts = Symbol("counts");
  MustEdit(Data(threshold, "int"));
  MustEdit(Data(counts, "unsigned int", 4));
  MustEdit(Settings(threshold, Format(pb::DATA_FORMAT_DECIMAL)));
  MustEdit(TypeSettings("unsigned int", Format(pb::DATA_FORMAT_OCTAL)));
  EXPECT_EQ(Value(Row(counts)), "{12o, 24o, 36o, 50o}");

  // Rebased: the item's settings move with it; the type's stay the type's.
  pb::GetProgramSummaryRequest sr;
  sr.set_program_id(id_);
  pb::GetProgramSummaryResponse summary;
  ASSERT_TRUE(backend_->GetProgramSummary(ctx_, sr, summary).ok());
  const std::uint64_t base = summary.summary().image_base().offset();
  pb::SetImageBaseRequest rb;
  rb.set_program_id(id_);
  rb.set_image_base(base + 0x10000000);
  rb.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pb::SetImageBaseResponse rebased;
  auto st = backend_->SetImageBase(ctx_, rb, rebased);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(Value(Row(threshold + 0x10000000)), "305419896");
  EXPECT_EQ(Value(Row(counts + 0x10000000)), "{12o, 24o, 36o, 50o}");

  // Exported and imported as a new project.
  pb::ExportProjectRequest ex;
  ex.set_project_id("default");
  std::string bytes;
  bool first = true;
  auto est = backend_->ExportProject(ctx_, ex, [&](const pb::ExportProjectResponse &r) {
    if (!first) bytes += r.data();
    first = false;
    return true;
  });
  ASSERT_TRUE(est.ok()) << est.message;
  pb::ImportProjectArchiveRequest imp;
  imp.mutable_archive()->set_content(bytes);
  imp.set_new_project_name("copied");
  imp.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pb::ImportProjectArchiveResponse imported;
  auto ist = backend_->ImportProjectArchive(ctx_, imp, imported);
  ASSERT_TRUE(ist.ok()) << ist.message;
  ASSERT_EQ(imported.programs_size(), 1);
  const std::string copy = imported.programs(0).program().program_id();
  EXPECT_EQ(Value(Row(threshold + 0x10000000, "", copy)), "305419896");
  EXPECT_EQ(Value(Row(counts + 0x10000000, "", copy)), "{12o, 24o, 36o, 50o}");
}

}  // namespace
}  // namespace revkit::backend
