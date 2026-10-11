// Rebase (docs/memory-map.md, "Rebase: setting the image base") through the
// API: a corpus program with a user's work (renames, a struct and a
// prototype using it, comments, a patch, a listing edit, a memory region),
// moved by +0x10000 and back. At the moved base the function list, the
// listing, the decompiled C, the history and the memory read as before at
// the shifted addresses; moving back (and undoing the rebase) gives
// exactly what was there; it persists. And the case it is for: a raw
// firmware imported at a wrong base, fixed without losing the work.
#include "builders.hh"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

constexpr std::uint64_t kDelta = 0x10000;

fs::path Corpus(const std::string &rel) { return fs::path(REVKIT_CORPUS) / rel; }

pb::Provenance User(const std::string &who = "alice") {
  pb::Provenance p;
  p.set_kind(pb::PROVENANCE_KIND_USER);
  p.set_id(who);
  return p;
}

// What the gate compares, of one program.
struct Answers {
  std::vector<std::string> functions;                // entry, name, prototype
  std::map<std::uint64_t, std::string> decompiled;   // a sample, by entry
  std::map<std::uint64_t, std::string> listing;      // rows from each sampled entry
  std::vector<std::string> history;                  // every op but the rebases', in order
  std::vector<std::string> effective;                // what is in force
  std::vector<std::string> memory;                   // the map
  std::map<std::uint64_t, std::string> bytes;        // the first bytes of each block, by start
  std::string types;
};

// `text` with every address in [lo, hi] it spells moved by `delta`:
// hexadecimal (0x1234, FUN_00101234: the same digits, zero-padded as
// before) and the decimal offsets of debug strings ("offset: 1052672").
std::string Shifted(const std::string &text, std::uint64_t lo, std::uint64_t hi, std::uint64_t delta, bool debug = false) {
  static const std::regex hex("(0x)?([0-9a-f]{5,16})(?![0-9a-zA-Z])");
  if (debug) {
    // Debug strings spell numbers in decimal ("offset: 1052672"), and
    // subs in hex with 0x ("block:0x109060").
    std::string hexed;
    std::size_t at0 = 0;
    static const std::regex prefixed("0x([0-9a-f]{1,16})");
    for (std::sregex_iterator it(text.begin(), text.end(), prefixed), end; it != end; ++it) {
      const std::smatch &m = *it;
      const std::uint64_t v = std::stoull(m[1].str(), nullptr, 16);
      if (v < lo || v > hi) continue;
      std::ostringstream o;
      o << std::hex << v + delta;
      hexed += text.substr(at0, static_cast<std::size_t>(m.position(1)) - at0) + o.str();
      at0 = static_cast<std::size_t>(m.position(1) + m.length(1));
    }
    const std::string src = hexed + text.substr(at0);
    static const std::regex dec("((?:^|[^_a-z])(?:offset|start): )([0-9]+)");
    std::string result;
    std::size_t last = 0;
    for (std::sregex_iterator it(src.begin(), src.end(), dec), end; it != end; ++it) {
      const std::smatch &m = *it;
      const std::uint64_t v = std::stoull(m[2].str());
      const auto at = static_cast<std::size_t>(m.position(2));
      if (v < lo || v > hi) continue;
      result += src.substr(last, at - last) + std::to_string(v + delta);
      last = at + static_cast<std::size_t>(m.length(2));
    }
    return result + src.substr(last);
  }
  std::string out;
  std::sregex_iterator end;
  std::size_t last = 0;
  for (std::sregex_iterator it(text.begin(), text.end(), hex); it != end; ++it) {
    const std::smatch &m = *it;
    // Inside an identifier only after '_' (FUN_00101234), not mid-word.
    const auto at = static_cast<std::size_t>(m.position(0));
    if (at > 0 && !m[1].matched) {
      const char before = text[at - 1];
      if (std::isalnum(static_cast<unsigned char>(before))) continue;
    }
    const std::uint64_t v = std::stoull(m[2].str(), nullptr, 16);
    if (v < lo || v > hi) continue;
    std::ostringstream s;
    s << std::hex << std::setfill('0') << std::setw(static_cast<int>(m[2].length())) << v + delta;
    out += text.substr(last, at - last) + m[1].str() + s.str();
    last = at + static_cast<std::size_t>(m.length(0));
  }
  out += text.substr(last);
  return out;
}

// Little-endian pointer-sized words in [lo, hi] moved by `delta` (a PIE's
// relocated pointers follow the base).
std::string ShiftedWords(std::string bytes, std::uint64_t lo, std::uint64_t hi, std::uint64_t delta) {
  for (std::size_t i = 0; i + 8 <= bytes.size(); i += 8) {
    std::uint64_t v = 0;
    for (int k = 7; k >= 0; --k) v = v << 8 | static_cast<unsigned char>(bytes[i + static_cast<std::size_t>(k)]);
    if (v < lo || v > hi) continue;
    v += delta;
    for (int k = 0; k < 8; ++k) bytes[i + static_cast<std::size_t>(k)] = static_cast<char>((v >> (8 * k)) & 0xff);
  }
  return bytes;
}

class RebaseTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!fs::exists(Corpus("elf-x86_64/gcc-O2/debug/cjson"))) GTEST_SKIP() << "no corpus";
  }

  std::unique_ptr<api::Backend> Make(const fs::path &project_dir = {}) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir.string();
    o.param_id = inputs::ParamIdMode::off;
    return MakeImageBackend(o);
  }

  std::string Import(api::Backend &b, const fs::path &file, const std::string &name) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(file.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = b.ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::uint64_t Entry(api::Backend &b, const std::string &program, const std::string &name) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.set_name_contains(name);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(b.ListFunctions(ctx_, req, resp).ok());
    for (const auto &f : resp.functions())
      if (f.name() == name) return f.entry().offset();
    ADD_FAILURE() << "no function " << name;
    return 0;
  }

  pb::AppendAssertionsResponse Append(api::Backend &b, const std::string &program, std::vector<pb::AssertionBody> bodies) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    *req.mutable_provenance() = User();
    for (auto &body : bodies) *req.add_assertions()->mutable_body() = body;
    pb::AppendAssertionsResponse resp;
    auto st = b.AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static pb::AssertionBody Rename(std::uint64_t at, const std::string &name) {
    pb::AssertionBody body;
    body.mutable_rename()->mutable_target()->mutable_address()->set_offset(at);
    body.mutable_rename()->set_name(name);
    return body;
  }

  pb::SetImageBaseResponse SetBase(api::Backend &b, const std::string &program, std::uint64_t base,
                                   api::Status *status = nullptr) {
    pb::SetImageBaseRequest req;
    req.set_program_id(program);
    req.set_image_base(base);
    *req.mutable_provenance() = User();
    pb::SetImageBaseResponse resp;
    auto st = b.SetImageBase(ctx_, req, resp);
    if (status) *status = st;
    else EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::uint64_t Base(api::Backend &b, const std::string &program, std::uint64_t *imported = nullptr) {
    pb::GetProgramSummaryRequest req;
    req.set_program_id(program);
    pb::GetProgramSummaryResponse resp;
    EXPECT_TRUE(b.GetProgramSummary(ctx_, req, resp).ok());
    if (imported) *imported = resp.summary().import_image_base().offset();
    return resp.summary().image_base().offset();
  }

  void Retract(api::Backend &b, const std::string &program, std::uint64_t seq) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(program);
    req.add_seqs(seq);
    *req.mutable_provenance() = User();
    pb::RetractAssertionsResponse resp;
    auto st = b.RetractAssertions(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
  }

  // The user's work on cjson.
  void Work(api::Backend &b, const std::string &cjson) {
    const std::uint64_t get_string = Entry(b, cjson, "cJSON_GetStringValue");
    const std::uint64_t array_size = Entry(b, cjson, "cJSON_GetArraySize");
    const std::uint64_t version = Entry(b, cjson, "cJSON_Version");
    const std::uint64_t is_null = Entry(b, cjson, "cJSON_IsNull");
    Append(b, cjson, {Rename(get_string, "get_string")});
    // A struct, from C, and a prototype that uses it.
    pb::ParseCRequest parse;
    parse.set_program_id(cjson);
    auto *src = parse.add_sources();
    src->set_name("mine.h");
    src->set_text("struct point { int x; int y; long weight; };\n");
    pb::ParseCResponse parsed;
    ASSERT_TRUE(b.ParseC(ctx_, parse, parsed).ok());
    {
      pb::AppendAssertionsRequest req;
      req.set_program_id(cjson);
      *req.mutable_provenance() = User();
      for (const auto &n : parsed.nodes()) *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = n;
      for (const auto &n : parsed.named())
        req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(n.index());
      pb::AppendAssertionsResponse resp;
      auto st = b.AppendAssertions(ctx_, req, resp);
      ASSERT_TRUE(st.ok()) << st.message;
    }
    pb::AssertionBody retype;
    retype.mutable_retype()->mutable_target()->mutable_address()->set_offset(array_size);
    retype.mutable_retype()->mutable_type()->set_c_declaration("int cJSON_GetArraySize(const struct point *array)");
    Append(b, cjson, {retype});
    // Comments.
    pb::AssertionBody plate, eol;
    plate.mutable_comment()->mutable_address()->set_offset(version);
    plate.mutable_comment()->set_kind(pb::COMMENT_KIND_PLATE);
    plate.mutable_comment()->set_text("The library's version string.");
    eol.mutable_comment()->mutable_address()->set_offset(get_string);
    eol.mutable_comment()->set_kind(pb::COMMENT_KIND_EOL);
    eol.mutable_comment()->set_text("checked by callers");
    Append(b, cjson, {plate, eol});
    // A patch.
    pb::PatchBytesRequest patch;
    patch.set_program_id(cjson);
    patch.mutable_address()->set_offset(is_null);
    patch.set_data(std::string("\x31\xc0\xc3", 3));  // xor eax, eax; ret
    *patch.mutable_provenance() = User();
    pb::PatchBytesResponse patched;
    auto st = b.PatchBytes(ctx_, patch, patched);
    ASSERT_TRUE(st.ok()) << st.message;
    // A listing edit: an int where .data starts.
    pb::GetMemoryMapRequest mm;
    mm.set_program_id(cjson);
    pb::GetMemoryMapResponse map;
    ASSERT_TRUE(b.GetMemoryMap(ctx_, mm, map).ok());
    std::uint64_t data = 0;
    for (const auto &blk : map.blocks())
      if (blk.name() == ".data") data = blk.range().first().offset();
    ASSERT_NE(data, 0u);
    pb::AssertionBody unit;
    unit.mutable_listing_edit()->mutable_address()->set_offset(data + 8);
    unit.mutable_listing_edit()->mutable_data()->mutable_type()->set_c_declaration("int");
    Append(b, cjson, {unit});
    // A memory region with bytes from another file, and an image block's edit.
    pb::AddMemoryRegionRequest add;
    add.set_program_id(cjson);
    add.mutable_region()->set_name("blob");
    add.mutable_region()->set_start(0x7000000);
    add.mutable_region()->set_read(true);
    add.set_content(std::string(200, '\x5a') + "tail of another file");
    add.set_file_name("blob.bin");
    *add.mutable_provenance() = User();
    pb::AddMemoryRegionResponse added;
    st = b.AddMemoryRegion(ctx_, add, added);
    ASSERT_TRUE(st.ok()) << st.message;
    pb::UpdateMemoryRegionRequest upd;
    upd.set_program_id(cjson);
    upd.mutable_block_start()->set_offset(data);
    upd.mutable_region()->set_start(data);
    upd.mutable_region()->set_initialized(true);
    upd.mutable_region()->set_name("data_renamed");
    upd.mutable_region()->set_read(true);
    upd.mutable_region()->set_write(true);
    *upd.mutable_provenance() = User();
    pb::UpdateMemoryRegionResponse updated;
    st = b.UpdateMemoryRegion(ctx_, upd, updated);
    ASSERT_TRUE(st.ok()) << st.message;
    // A note, and an undone rename.
    pb::AssertionBody note;
    note.mutable_note()->mutable_address()->set_offset(version);
    note.mutable_note()->set_text("look here");
    Append(b, cjson, {note});
    auto undone = Append(b, cjson, {Rename(version, "version_undone")});
    Retract(b, cjson, undone.assertions(0).seq());
  }

  Answers Ask(api::Backend &b, const std::string &program) {
    Answers a;
    pb::ListFunctionsRequest lf;
    lf.set_program_id(program);
    lf.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse fs;
    EXPECT_TRUE(b.ListFunctions(ctx_, lf, fs).ok());
    std::vector<std::uint64_t> sample;
    for (const auto &f : fs.functions()) {
      a.functions.push_back(std::to_string(f.entry().offset()) + " " + f.name() + " " + f.prototype());
      if (sample.size() < 10 || f.name() == "get_string" || f.name() == "cJSON_GetArraySize" ||
          f.name() == "cJSON_IsNull" || f.name() == "cJSON_Version" || f.name() == "cJSON_Parse")
        sample.push_back(f.entry().offset());
    }
    for (std::uint64_t e : sample) {
      pb::DecompileRequest d;
      d.set_program_id(program);
      d.mutable_function()->set_offset(e);
      d.mutable_options()->set_include_text(true);
      pb::DecompileResponse dr;
      EXPECT_TRUE(b.Decompile(ctx_, d, dr).ok());
      a.decompiled[e] = dr.function().text();
      pb::GetListingRequest gl;
      gl.set_program_id(program);
      gl.set_header_rows(true);
      gl.mutable_addresses()->mutable_start()->set_offset(e);
      gl.mutable_addresses()->set_rows_before(4);
      gl.mutable_addresses()->set_max_rows(40);
      gl.set_omit_bytes(true);
      pb::GetListingResponse listing;
      EXPECT_TRUE(b.GetListing(ctx_, gl, listing).ok());
      std::string rows;
      for (const auto &row : listing.rows()) {
        rows += std::to_string(row.address().offset()) + " " + std::to_string(row.kind()) + " " + row.header().text();
        for (const auto &l : row.labels()) rows += " [" + l.name() + "]";
        for (const auto &t : row.tokens()) rows += t.text();
        for (const auto &c : row.comments()) rows += " ;" + c.text();
        rows += "\n";
      }
      a.listing[e] = rows;
    }
    for (bool inactive : {true, false}) {
      pb::ListAssertionsRequest la;
      la.set_program_id(program);
      la.mutable_filter()->set_include_inactive(inactive);
      la.mutable_page()->set_page_size(5000);
      pb::ListAssertionsResponse all;
      EXPECT_TRUE(b.ListAssertions(ctx_, la, all).ok());
      for (const auto &x : all.assertions()) {
        if (x.key().kind() == pb::FACT_KIND_REBASE) continue;
        if (x.op() == pb::ASSERTION_OP_RETRACT && x.body().has_image_base()) continue;
        pb::Assertion n = x;
        n.clear_seq();
        n.clear_revision();
        n.clear_id();
        n.clear_retracts_id();
        n.clear_retracts_seq();
        n.clear_retracted_by();
        n.clear_retracted_by_ids();
        n.clear_depends_on_id();
        n.clear_depends_on_seq();
        n.clear_supersedes();
        n.clear_stamp();
        n.clear_time();
        (inactive ? a.history : a.effective).push_back(n.ShortDebugString());
      }
    }
    pb::GetMemoryMapRequest mm;
    mm.set_program_id(program);
    pb::GetMemoryMapResponse map;
    EXPECT_TRUE(b.GetMemoryMap(ctx_, mm, map).ok());
    for (const auto &blk : map.blocks()) {
      pb::MemoryBlock n = blk;
      n.clear_origin();
      a.memory.push_back(n.ShortDebugString());
      pb::ReadMemoryRequest rm;
      rm.set_program_id(program);
      *rm.mutable_address() = blk.range().first();
      rm.set_length(static_cast<std::uint32_t>(std::min<std::uint64_t>(256, blk.range().last().offset() - blk.range().first().offset() + 1)));
      pb::ReadMemoryResponse rr;
      if (b.ReadMemory(ctx_, rm, rr).ok()) a.bytes[blk.range().first().offset()] = rr.data();
    }
    pb::FindTypesRequest ft;
    ft.set_program_id(program);
    ft.set_name_prefix("point");
    pb::FindTypesResponse found;
    EXPECT_TRUE(b.FindTypes(ctx_, ft, found).ok());
    for (const auto &t : found.types()) a.types += t.name() + "=" + t.hash() + ";";
    return a;
  }

  // `x` (at the import base) moved by kDelta must read as `y`.
  void ExpectMoved(const Answers &x, const Answers &y, std::uint64_t lo, std::uint64_t hi) {
    ASSERT_EQ(x.functions.size(), y.functions.size());
    for (std::size_t i = 0; i < x.functions.size(); ++i) {
      const std::string &f = x.functions[i];
      const std::uint64_t entry = std::stoull(f.substr(0, f.find(' ')));
      EXPECT_EQ(std::to_string(entry + kDelta) + Shifted(f.substr(f.find(' ')), lo, hi, kDelta), y.functions[i]) << "function " << i;
    }
    for (const auto &[e, text] : x.decompiled) {
      ASSERT_TRUE(y.decompiled.contains(e + kDelta)) << "no decompilation at 0x" << std::hex << e + kDelta;
      EXPECT_EQ(Shifted(text, lo, hi, kDelta), y.decompiled.at(e + kDelta)) << "decompiled at 0x" << std::hex << e;
    }
    for (const auto &[e, rows] : x.listing) {
      std::istringstream in(rows);
      std::string moved, line;
      while (std::getline(in, line)) {
        const std::uint64_t at = std::stoull(line.substr(0, line.find(' ')));
        moved += std::to_string(at + kDelta) + Shifted(line.substr(line.find(' ')), lo, hi, kDelta) + "\n";
      }
      EXPECT_EQ(moved, y.listing.at(e + kDelta)) << "listing at 0x" << std::hex << e;
    }
    ASSERT_EQ(x.history.size(), y.history.size());
    for (std::size_t i = 0; i < x.history.size(); ++i) EXPECT_EQ(Shifted(x.history[i], lo, hi, kDelta, true), y.history[i]);
    ASSERT_EQ(x.effective.size(), y.effective.size());
    for (std::size_t i = 0; i < x.effective.size(); ++i) EXPECT_EQ(Shifted(x.effective[i], lo, hi, kDelta, true), y.effective[i]);
    ASSERT_EQ(x.memory.size(), y.memory.size());
    for (std::size_t i = 0; i < x.memory.size(); ++i) EXPECT_EQ(Shifted(x.memory[i], lo, hi, kDelta, true), y.memory[i]);
    for (const auto &[start, bytes] : x.bytes) {
      ASSERT_TRUE(y.bytes.contains(start + kDelta));
      EXPECT_EQ(ShiftedWords(bytes, lo, hi, kDelta), y.bytes.at(start + kDelta)) << "bytes at 0x" << std::hex << start;
    }
    EXPECT_EQ(x.types, y.types);
  }

  void ExpectSame(const Answers &x, const Answers &y, const std::string &what) {
    EXPECT_EQ(x.functions, y.functions) << what;
    EXPECT_EQ(x.decompiled, y.decompiled) << what;
    EXPECT_EQ(x.listing, y.listing) << what;
    EXPECT_EQ(x.history, y.history) << what;
    EXPECT_EQ(x.effective, y.effective) << what;
    EXPECT_EQ(x.memory, y.memory) << what;
    EXPECT_EQ(x.bytes, y.bytes) << what;
    EXPECT_EQ(x.types, y.types) << what;
  }

  CallContext ctx_;
};

TEST_F(RebaseTest, ACorpusProgramMovesWithItsWorkAndBack) {
  auto b = Make();
  const std::string cjson = Import(*b, Corpus("elf-x86_64/gcc-O2/debug/cjson"), "cjson");
  Work(*b, cjson);
  std::uint64_t imported = 0;
  const std::uint64_t base = Base(*b, cjson, &imported);
  EXPECT_EQ(base, imported);
  const Answers before = Ask(*b, cjson);
  EXPECT_GT(before.history.size(), 100u);  // DWARF's and the user's
  const std::uint64_t get_string = Entry(*b, cjson, "get_string");
  // Everything at or above the image (the blob region at 0x7000000 too).
  const std::uint64_t lo = base, hi = 0x7ffffff;

  // +0x10000: one assertion, at the moved base.
  pb::SetImageBaseResponse moved = SetBase(*b, cjson, base + kDelta);
  EXPECT_EQ(moved.previous_image_base(), base);
  EXPECT_EQ(moved.import_image_base(), base);
  ASSERT_TRUE(moved.has_assertion());
  EXPECT_EQ(moved.assertion().key().kind(), pb::FACT_KIND_REBASE);
  EXPECT_EQ(moved.assertion().body().image_base().image_base(), base + kDelta);
  EXPECT_EQ(Base(*b, cjson, &imported), base + kDelta);
  EXPECT_EQ(imported, base);
  const Answers there = Ask(*b, cjson);
  ExpectMoved(before, there, lo, hi);
  EXPECT_EQ(Entry(*b, cjson, "get_string"), get_string + kDelta);

  // An edit made at the moved base goes back with the program.
  const std::uint64_t parse = Entry(*b, cjson, "cJSON_Parse");
  auto late = Append(*b, cjson, {Rename(parse, "parse_late")});
  // ...and back: by asserting the import base, the round trip is exact.
  SetBase(*b, cjson, base);
  EXPECT_EQ(Base(*b, cjson), base);
  EXPECT_EQ(Entry(*b, cjson, "parse_late"), parse - kDelta);
  Retract(*b, cjson, late.assertions(0).seq());
  const Answers back = Ask(*b, cjson);
  // As before, but for the late rename and its undo, which are history now.
  EXPECT_EQ(back.functions, before.functions);
  EXPECT_EQ(back.decompiled, before.decompiled);
  EXPECT_EQ(back.listing, before.listing);
  EXPECT_EQ(back.effective, before.effective);
  EXPECT_EQ(back.memory, before.memory);
  EXPECT_EQ(back.bytes, before.bytes);
  EXPECT_EQ(back.types, before.types);
  ASSERT_EQ(back.history.size(), before.history.size() + 2);
  EXPECT_EQ(std::vector<std::string>(back.history.begin(), back.history.begin() + static_cast<std::ptrdiff_t>(before.history.size())),
            before.history);
  EXPECT_NE(back.history[before.history.size()].find("parse_late"), std::string::npos);

  // Undoing a rebase is moving back too.
  pb::SetImageBaseResponse again = SetBase(*b, cjson, base + kDelta);
  ExpectMoved(back, Ask(*b, cjson), lo, hi);
  Retract(*b, cjson, again.assertion().seq());
  EXPECT_EQ(Base(*b, cjson), base);
  const Answers undone = Ask(*b, cjson);
  EXPECT_EQ(undone.functions, before.functions);
  EXPECT_EQ(undone.decompiled, before.decompiled);
  EXPECT_EQ(undone.memory, before.memory);
}

TEST_F(RebaseTest, ItPersistsAndRefusesWhatCantBe) {
  const fs::path dir = testing::scratch_dir("rebase-persist");
  std::string cjson;
  std::uint64_t base = 0;
  Answers there;
  {
    auto b = Make(dir);
    cjson = Import(*b, Corpus("elf-x86_64/gcc-O2/debug/cjson"), "cjson");
    base = Base(*b, cjson);
    const std::uint64_t entry = Entry(*b, cjson, "cJSON_Parse");
    Append(*b, cjson, {Rename(entry, "parse")});
    // Refused: a base the image wouldn't fit at.
    api::Status st;
    SetBase(*b, cjson, ~std::uint64_t{0} - 0x100, &st);
    EXPECT_EQ(st.code, StatusCode::kInvalidArgument) << st.message;
    SetBase(*b, cjson, base + kDelta);
    there = Ask(*b, cjson);
    EXPECT_EQ(Entry(*b, cjson, "parse"), entry + kDelta);
  }
  // Reopened: at the moved base, as it was.
  auto b = Make(dir);
  EXPECT_EQ(Base(*b, cjson), base + kDelta);
  const Answers reopened = Ask(*b, cjson);
  EXPECT_EQ(reopened.functions, there.functions);
  EXPECT_EQ(reopened.decompiled, there.decompiled);
  EXPECT_EQ(reopened.listing, there.listing);
  EXPECT_EQ(reopened.history, there.history);
  EXPECT_EQ(reopened.memory, there.memory);
  // AppendAssertions can't make one.
  pb::AppendAssertionsRequest req;
  req.set_program_id(cjson);
  *req.mutable_provenance() = User();
  req.add_assertions()->mutable_body()->mutable_image_base()->set_image_base(0);
  pb::AppendAssertionsResponse resp;
  EXPECT_EQ(b->AppendAssertions(ctx_, req, resp).code, StatusCode::kInvalidArgument);
}

// The case it is for: a raw firmware imported at a wrong base, worked on,
// then moved where it belongs: the work comes along and analysis now
// finds what the right base reaches.
class RawRebaseTest : public RebaseTest {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_TEST_CLANG).empty() ||
        std::string(REVKIT_TEST_LLD).empty() || std::string(REVKIT_TEST_OBJCOPY).empty())
      return;
    dir_ = testing::scratch_dir("raw-rebase");
    const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                            REVKIT_TEST_LLD + " " + REVKIT_TEST_OBJCOPY + " " + dir_.string() + " >/dev/null 2>&1";
    built_ = std::system(cmd.c_str()) == 0 && fs::exists(dir_ / "fw.bin");
  }
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
  }
  static inline fs::path dir_;
  static inline bool built_ = false;
};

TEST_F(RawRebaseTest, AWrongGuessIsFixedWithoutLosingTheWork) {
  auto b = Make();
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path((dir_ / "fw.bin").string());
  pb::ImportOptions *o = req.mutable_options();
  o->set_format("raw");
  o->set_language_id("ARM:LE:32:v4t");
  o->set_compiler_spec_id("default");
  o->set_has_image_base(true);
  o->set_image_base(0x10000);  // linked at 0: a wrong guess
  pb::ImportProgramResponse imported;
  auto st = b->ImportProgram(ctx_, req, imported);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string fw = imported.program().program_id();
  // Hours of work at the wrong base: the reset handler renamed, a comment.
  pb::ListFunctionsRequest lf;
  lf.set_program_id(fw);
  lf.mutable_page()->set_page_size(5000);
  pb::ListFunctionsResponse wrong;
  ASSERT_TRUE(b->ListFunctions(ctx_, lf, wrong).ok());
  // (The processor's vectors are at 0: at 0x10000 nothing seeds discovery.)
  const std::uint64_t reset = 0x10000;  // the reset vector, at the image's start
  Append(*b, fw, {Rename(reset, "reset_vectors")});
  pb::AssertionBody comment;
  comment.mutable_comment()->mutable_address()->set_offset(reset);
  comment.mutable_comment()->set_kind(pb::COMMENT_KIND_PLATE);
  comment.mutable_comment()->set_text("the vectors");
  Append(*b, fw, {comment});

  SetBase(*b, fw, 0);
  EXPECT_EQ(Base(*b, fw), 0u);
  pb::ListFunctionsResponse right;
  ASSERT_TRUE(b->ListFunctions(ctx_, lf, right).ok());
  // The work moved with the image...
  EXPECT_EQ(Entry(*b, fw, "reset_vectors"), 0u);
  pb::GetListingRequest gl;
  gl.set_program_id(fw);
  gl.set_header_rows(true);
  gl.mutable_addresses()->mutable_start()->set_offset(0);
  gl.mutable_addresses()->set_rows_before(4);
  gl.mutable_addresses()->set_max_rows(8);
  pb::GetListingResponse listing;
  ASSERT_TRUE(b->GetListing(ctx_, gl, listing).ok());
  bool plate = false;
  for (const auto &row : listing.rows()) plate |= row.header().text() == "the vectors";
  EXPECT_TRUE(plate);
  // ...and analysis follows the right base: the literal pools' code
  // pointers now point at code, so discovery finds more functions.
  EXPECT_GT(right.functions_size(), wrong.functions_size());
}

// Changing the language (docs/api.md, "Changing a program's language"):
// a raw ARM image imported as v4, which has no Thumb, moves to v4t in
// place. The work stays, the program reads as v4t, CompareLanguages ranks
// the variants, and undoing the change goes back to v4.
TEST_F(RawRebaseTest, TheLanguageChangesInPlaceAndBack) {
  auto b = Make();
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path((dir_ / "fw.bin").string());
  pb::ImportOptions *o = req.mutable_options();
  o->set_format("raw");
  o->set_language_id("ARM:LE:32:v4");
  o->set_compiler_spec_id("default");
  o->set_has_image_base(true);
  o->set_image_base(0);
  pb::ImportProgramResponse imported;
  auto st = b->ImportProgram(ctx_, req, imported);
  ASSERT_TRUE(st.ok()) << st.message;
  const std::string fw = imported.program().program_id();
  Append(*b, fw, {Rename(0, "reset_vectors")});
  auto language = [&] {
    pb::GetProgramSummaryRequest r;
    r.set_program_id(fw);
    pb::GetProgramSummaryResponse s;
    EXPECT_TRUE(b->GetProgramSummary(ctx_, r, s).ok());
    return s.summary().language().language_id() + ":" + s.summary().language().compiler_spec_id();
  };
  EXPECT_EQ(language(), "ARM:LE:32:v4:default");

  // The variants, compared on the program's code.
  pb::CompareLanguagesRequest cl;
  cl.set_program_id(fw);
  pb::CompareLanguagesResponse fits;
  st = b->CompareLanguages(ctx_, cl, fits);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_GT(fits.fits_size(), 2);
  EXPECT_GT(fits.bytes(), 0u);
  int recommended = 0;
  bool current = false, v4t = false;
  for (const pb::LanguageFit &f : fits.fits()) {
    recommended += f.recommended();
    current |= f.current() && f.language_id() == "ARM:LE:32:v4";
    v4t |= f.language_id() == "ARM:LE:32:v4t" && f.compatible();
    EXPECT_GE(f.decoded(), 0.0);
    EXPECT_LE(f.decoded(), 1.0);
  }
  EXPECT_EQ(recommended, 1);
  for (const pb::LanguageFit &f : fits.fits())
    if (f.recommended()) EXPECT_TRUE(f.language_id().starts_with("ARM:LE:32:")) << f.language_id();  // the image is little-endian
  EXPECT_TRUE(current);
  EXPECT_TRUE(v4t);

  // Refused: an unknown language, and one that lays memory out otherwise.
  pb::SetProgramLanguageRequest bad;
  bad.set_program_id(fw);
  *bad.mutable_provenance() = User();
  bad.set_language_id("ARM:LE:32:nonsense");
  pb::SetProgramLanguageResponse refused;
  EXPECT_EQ(b->SetProgramLanguage(ctx_, bad, refused).code, StatusCode::kInvalidArgument);
  bad.set_language_id("avr8:LE:16:default");
  EXPECT_EQ(b->SetProgramLanguage(ctx_, bad, refused).code, StatusCode::kFailedPrecondition);
  EXPECT_EQ(language(), "ARM:LE:32:v4:default");

  // v4 -> v4t, in place.
  pb::SetProgramLanguageRequest set;
  set.set_program_id(fw);
  *set.mutable_provenance() = User();
  set.set_language_id("ARM:LE:32:v4t");
  pb::SetProgramLanguageResponse changed;
  st = b->SetProgramLanguage(ctx_, set, changed);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(changed.previous_language_id(), "ARM:LE:32:v4");
  EXPECT_EQ(changed.language_id(), "ARM:LE:32:v4t");
  EXPECT_EQ(changed.compiler_spec_id(), "default");
  ASSERT_TRUE(changed.has_assertion());
  EXPECT_EQ(changed.assertion().key().kind(), pb::FACT_KIND_LANGUAGE);
  EXPECT_EQ(language(), "ARM:LE:32:v4t:default");
  EXPECT_EQ(Entry(*b, fw, "reset_vectors"), 0u);  // the work stayed
  // Asking again for the language it is in changes nothing.
  pb::SetProgramLanguageResponse again;
  ASSERT_TRUE(b->SetProgramLanguage(ctx_, set, again).ok());
  EXPECT_FALSE(again.has_assertion());

  // Undone: back to the imported language, the work still there.
  Retract(*b, fw, changed.assertion().seq());
  EXPECT_EQ(language(), "ARM:LE:32:v4:default");
  EXPECT_EQ(Entry(*b, fw, "reset_vectors"), 0u);
}

// A language change and a rebase together persist, and neither undoes the
// other: OnRebase keeps the language, OnLanguage keeps the base.
TEST_F(RawRebaseTest, TheLanguageAndBasePersistTogether) {
  const fs::path dir = testing::scratch_dir("language-persist");
  std::string fw;
  {
    auto b = Make(dir);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path((dir_ / "fw.bin").string());
    pb::ImportOptions *o = req.mutable_options();
    o->set_format("raw");
    o->set_language_id("ARM:LE:32:v4");
    o->set_compiler_spec_id("default");
    o->set_has_image_base(true);
    o->set_image_base(0);
    pb::ImportProgramResponse imported;
    auto st = b->ImportProgram(ctx_, req, imported);
    ASSERT_TRUE(st.ok()) << st.message;
    fw = imported.program().program_id();
    Append(*b, fw, {Rename(0, "reset_vectors")});
    pb::SetProgramLanguageRequest set;
    set.set_program_id(fw);
    *set.mutable_provenance() = User();
    set.set_language_id("ARM:LE:32:v4t");
    pb::SetProgramLanguageResponse changed;
    ASSERT_TRUE(b->SetProgramLanguage(ctx_, set, changed).ok());
    SetBase(*b, fw, 0x20000);  // after the language change: it must stay v4t
    if (std::getenv("RK_SHOW_FITS")) {
      pb::CompareLanguagesRequest cl;
      cl.set_program_id(fw);
      pb::CompareLanguagesResponse fits;
      ASSERT_TRUE(b->CompareLanguages(ctx_, cl, fits).ok());
      for (const pb::LanguageFit &f : fits.fits())
        std::printf("%-22s %-6s decoded %.3f invalid %5llu unimpl %4llu reached %6llu cut %4llu%s%s %s\n",
                    f.language_id().c_str(), f.mode().c_str(), f.decoded(), (unsigned long long)f.invalid(),
                    (unsigned long long)f.unimplemented(), (unsigned long long)f.reached(),
                    (unsigned long long)f.reached_invalid(), f.current() ? " CURRENT" : "",
                    f.recommended() ? " PICK" : "", f.note().c_str());
    }
  }
  auto b = Make(dir);
  pb::GetProgramSummaryRequest r;
  r.set_program_id(fw);
  pb::GetProgramSummaryResponse s;
  ASSERT_TRUE(b->GetProgramSummary(ctx_, r, s).ok());
  EXPECT_EQ(s.summary().language().language_id(), "ARM:LE:32:v4t");
  EXPECT_EQ(Base(*b, fw), 0x20000u);
}

}  // namespace
}  // namespace revkit::backend
