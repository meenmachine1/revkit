// PatchService through the image backend (docs/patching.md): the
// synthetic ARM firmware (src/analysis/tests/fixtures/armfw) behind a
// header. Assembling, patching an immediate and a call, what every view
// then shows (listing, instruction, memory, decompilation, discovery, the
// emulator), undo and revert, what a patch recomputes, and export with a
// checksum in the file name, verified.
#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/loader/load.hh"
#include "revkit/asm/assembler.hh"
#include "revkit/patch/checksum.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

class PatchApi : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_TEST_CLANG).empty() ||
        std::string(REVKIT_TEST_LLD).empty() || std::string(REVKIT_TEST_OBJCOPY).empty())
      return;
    dir_ = testing::scratch_dir("patch-api");
    const std::string cmd = std::string("sh ") + REVKIT_ARMFW_DIR + "/build.sh " + REVKIT_TEST_CLANG + " " +
                            REVKIT_TEST_LLD + " " + REVKIT_TEST_OBJCOPY + " " + dir_.string() + " >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) return;
    auto image = testing::read_file(dir_ / "fw.bin");
    std::ofstream out(dir_ / "fw.bin.hdr", std::ios::binary);
    std::string header(0x40, 'H');
    out.write(header.data(), static_cast<std::streamsize>(header.size()));
    out.write(reinterpret_cast<const char *>(image.data()), static_cast<std::streamsize>(image.size()));
    built_ = out.good();
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!built_) GTEST_SKIP() << "no clang, ld.lld and llvm-objcopy for armv4t";
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    b_ = MakeImageBackend(o);
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path((dir_ / "fw.bin.hdr").string());
    pb::ImportOptions *io = req.mutable_options();
    io->set_format("raw");
    io->set_language_id("ARM:LE:32:v4t");
    io->set_compiler_spec_id("default");
    io->set_raw_offset(0x40);
    pb::MemoryRegion *r = io->add_regions();
    r->set_name("sysctrl");
    r->set_start(0xd0000000);
    r->set_size(0x1000);
    r->set_read(true);
    r->set_write(true);
    r->set_is_volatile(true);
    pb::ImportProgramResponse resp;
    auto st = b_->ImportProgram(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    id_ = resp.program().program_id();
    // The raw image has no symbols: names from its ELF (linked at 0).
    const loader::Image elf = loader::load_file(dir_ / "fw.elf");
    for (const loader::Symbol &sym : elf.symbols)
      if (sym.defined && sym.type == loader::SymbolType::func) fns_[sym.name] = sym.value & ~std::uint64_t{1};
  }

  static pb::Provenance User() {
    pb::Provenance p;
    p.set_kind(pb::PROVENANCE_KIND_USER);
    p.set_id("alice");
    return p;
  }

  // The instruction rows of a function's body, in order.
  std::vector<pb::ListingRow> Rows(std::uint64_t start, std::uint32_t n) {
    pb::GetListingRequest req;
    req.set_program_id(id_);
    req.mutable_addresses()->mutable_start()->set_offset(start);
    req.mutable_addresses()->set_max_rows(n);
    pb::GetListingResponse resp;
    EXPECT_TRUE(b_->GetListing(ctx_, req, resp).ok());
    return {resp.rows().begin(), resp.rows().end()};
  }
  static std::string Text(const pb::ListingRow &r) {
    std::string s;
    for (const auto &t : r.tokens()) s += t.text();
    return s;
  }
  // The first instruction of `fn` with an immediate operand.
  std::optional<pb::ListingRow> FirstImmediate(std::uint64_t fn) {
    for (const auto &r : Rows(fn, 40))
      if (r.kind() == pb::LISTING_ROW_KIND_INSTRUCTION && Text(r).find("#0x") != std::string::npos) return r;
    return std::nullopt;
  }
  std::string Decompiled(std::uint64_t fn) {
    pb::DecompileRequest req;
    req.set_program_id(id_);
    req.mutable_function()->set_offset(fn);
    req.mutable_options()->set_include_text(true);
    pb::DecompileResponse d;
    auto st = b_->Decompile(ctx_, req, d);
    EXPECT_TRUE(st.ok()) << "0x" << std::hex << fn << ": " << st.message;
    return d.function().text();
  }
  pb::PatchInstructionResponse Patch(std::uint64_t at, const std::string &text) {
    pb::PatchInstructionRequest req;
    req.set_program_id(id_);
    req.mutable_address()->set_offset(at);
    req.set_text(text);
    *req.mutable_provenance() = User();
    pb::PatchInstructionResponse resp;
    auto st = b_->PatchInstruction(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static inline fs::path dir_;
  static inline bool built_ = false;
  std::unique_ptr<api::Backend> b_;
  std::string id_;
  std::map<std::string, std::uint64_t> fns_;
  CallContext ctx_;
};

TEST_F(PatchApi, AssemblesWithCompletionAndErrors) {
  const std::uint64_t h1 = fns_.at("h1");
  pb::AssembleRequest req;
  req.set_program_id(id_);
  req.mutable_address()->set_offset(h1);
  req.set_text("mov r0,#0x7");
  pb::AssembleResponse resp;
  ASSERT_TRUE(b_->Assemble(ctx_, req, resp).ok());
  ASSERT_FALSE(resp.candidates().empty()) << resp.error();
  EXPECT_EQ(resp.candidates(0).bytes(), std::string("\x07\x00\xa0\xe3", 4));
  EXPECT_FALSE(resp.current_text().empty());
  EXPECT_EQ(resp.current_bytes().size(), 4u);

  req.set_text("mo");
  req.set_complete(true);
  req.set_cursor(2);
  resp.Clear();
  ASSERT_TRUE(b_->Assemble(ctx_, req, resp).ok());
  EXPECT_NE(std::find(resp.completions().begin(), resp.completions().end(), "mov"), resp.completions().end());

  req.set_text("mov r0,#");
  req.set_complete(false);
  resp.Clear();
  ASSERT_TRUE(b_->Assemble(ctx_, req, resp).ok());
  EXPECT_TRUE(resp.candidates().empty());
  EXPECT_EQ(resp.error(), "incomplete instruction");

  // Labels resolve to the program's names (a raw image's are defaults).
  char label[32];
  std::snprintf(label, sizeof label, "bl FUN_%08llx", static_cast<unsigned long long>(fns_.at("h2")));
  req.set_text(label);
  resp.Clear();
  ASSERT_TRUE(b_->Assemble(ctx_, req, resp).ok());
  ASSERT_FALSE(resp.candidates().empty()) << label << ": " << resp.error() << " at " << resp.error_column();
  EXPECT_NE(resp.candidates(0).text().find("bl "), std::string::npos);
}

TEST_F(PatchApi, AnImmediateShowsEverywhereAndUndoes) {
  const std::uint64_t fn = fns_.at("dispatch");
  auto row = FirstImmediate(fn);
  ASSERT_TRUE(row);
  const std::uint64_t at = row->address().offset();
  const std::string before_text = Text(*row), before_bytes = row->bytes(), before_c = Decompiled(fn);
  // The same instruction with another immediate.
  std::string text = before_text;
  const auto hash = text.find("#0x");
  text = text.substr(0, hash) + "#0x5d";
  auto resp = Patch(at, text);
  ASSERT_EQ(resp.seqs_size(), 1);

  auto rows = Rows(at, 1);
  ASSERT_EQ(rows.size(), 1u);
  EXPECT_TRUE(rows[0].patched());
  EXPECT_EQ(rows[0].original_bytes(), before_bytes);
  EXPECT_TRUE(revkit::assembler::Assembler::same_text(Text(rows[0]), text)) << Text(rows[0]);
  // GetInstruction and ReadMemory read it as patched.
  pb::GetInstructionRequest gi;
  gi.set_program_id(id_);
  gi.mutable_address()->set_offset(at);
  pb::GetInstructionResponse ir;
  ASSERT_TRUE(b_->GetInstruction(ctx_, gi, ir).ok());
  EXPECT_EQ(ir.instruction().bytes(), resp.bytes());
  pb::ReadMemoryRequest rm;
  rm.set_program_id(id_);
  rm.mutable_address()->set_offset(at);
  rm.set_length(4);
  pb::ReadMemoryResponse mr;
  ASSERT_TRUE(b_->ReadMemory(ctx_, rm, mr).ok());
  EXPECT_EQ(mr.data(), resp.bytes());
  // The decompiler sees it.
  const std::string after_c = Decompiled(fn);
  EXPECT_NE(after_c, before_c) << after_c;
  // The patches list.
  pb::ListPatchesRequest lp;
  lp.set_program_id(id_);
  pb::ListPatchesResponse lr;
  ASSERT_TRUE(b_->ListPatches(ctx_, lp, lr).ok());
  ASSERT_EQ(lr.patches_size(), 1);
  EXPECT_EQ(lr.patches(0).original(), before_bytes);
  EXPECT_EQ(lr.patches(0).typed_text(), text);
  EXPECT_EQ(lr.patches(0).original_text(), before_text);
  EXPECT_EQ(lr.patches(0).function().offset(), fn);
  EXPECT_EQ(lr.patches(0).provenance().id(), "alice");

  // Undo (a retraction) restores every view; redo brings it back.
  pb::RetractAssertionsRequest undo;
  undo.set_program_id(id_);
  undo.add_seqs(resp.seqs(0));
  *undo.mutable_provenance() = User();
  pb::RetractAssertionsResponse ur;
  ASSERT_TRUE(b_->RetractAssertions(ctx_, undo, ur).ok());
  rows = Rows(at, 1);
  EXPECT_FALSE(rows[0].patched());
  EXPECT_EQ(rows[0].bytes(), before_bytes);
  EXPECT_EQ(Decompiled(fn), before_c);
  pb::RetractAssertionsRequest redo = undo;
  redo.clear_seqs();
  redo.add_seqs(ur.retractions(0).seq());
  ASSERT_TRUE(b_->RetractAssertions(ctx_, redo, ur).ok());
  EXPECT_TRUE(Rows(at, 1)[0].patched());
  EXPECT_EQ(Decompiled(fn), after_c);

  // RevertPatches by range: back to the file's bytes.
  pb::RevertPatchesRequest rv;
  rv.set_program_id(id_);
  *rv.mutable_range()->mutable_first() = row->address();
  *rv.mutable_range()->mutable_last() = row->address();
  *rv.mutable_provenance() = User();
  pb::RevertPatchesResponse rr;
  ASSERT_TRUE(b_->RevertPatches(ctx_, rv, rr).ok());
  EXPECT_EQ(Rows(at, 1)[0].bytes(), before_bytes);
  lr.Clear();
  ASSERT_TRUE(b_->ListPatches(ctx_, lp, lr).ok());
  EXPECT_EQ(lr.patches_size(), 0);
}

TEST_F(PatchApi, ACallToNewCodeIsDiscovered) {
  // `unreferenced` has no callers; a bl to it from h0 makes one.
  const std::uint64_t h0 = fns_.at("h0"), target = fns_.at("unreferenced");
  auto rows = Rows(h0, 3);
  ASSERT_GE(rows.size(), 2u);
  const std::uint64_t at = rows[0].address().offset();
  char text[64];
  std::snprintf(text, sizeof text, "bl 0x%llx", static_cast<unsigned long long>(target));
  Patch(at, text);
  pb::GetXrefsRequest xr;
  xr.set_program_id(id_);
  xr.mutable_address()->set_offset(target);
  xr.set_direction(pb::XREF_DIRECTION_TO);
  pb::GetXrefsResponse xs;
  ASSERT_TRUE(b_->GetXrefs(ctx_, xr, xs).ok());
  bool found = false;
  for (const auto &x : xs.xrefs()) found |= x.from_address().offset() == at;
  EXPECT_TRUE(found);
}

TEST_F(PatchApi, RefusesBytesTheFileDoesntHold) {
  pb::PatchBytesRequest req;
  req.set_program_id(id_);
  req.mutable_address()->set_offset(0xd0000010);
  req.set_data("\x01");
  *req.mutable_provenance() = User();
  pb::PatchBytesResponse resp;
  auto st = b_->PatchBytes(ctx_, req, resp);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition);
}

TEST_F(PatchApi, ExportsWithASumInTheNameAndVerifies) {
  const std::uint64_t fn = fns_.at("h2");
  auto row = FirstImmediate(fn);
  ASSERT_TRUE(row);
  std::string text = Text(*row);
  text = text.substr(0, text.find("#0x")) + "#0x9";
  auto patched = Patch(row->address().offset(), text);
  pb::PatchBytesRequest pbr;  // and a byte patch in data
  pbr.set_program_id(id_);
  pbr.mutable_address()->set_offset(fns_.at("h0") - 4);
  pbr.set_data("\xde\xad");
  *pbr.mutable_provenance() = User();
  pb::PatchBytesResponse pbs;
  ASSERT_TRUE(b_->PatchBytes(ctx_, pbr, pbs).ok());

  pb::ExportProgramRequest req;
  req.set_program_id(id_);
  pb::ExportFixup *fx = req.mutable_settings()->add_fixups();
  fx->mutable_checksum()->set_algorithm(pb::CHECKSUM_ALGORITHM_SUM32);
  fx->mutable_checksum()->set_name(true);
  req.mutable_settings()->set_file_name_template("FW_{SUM:08X}.bin");
  pb::ExportProgramResponse resp;
  auto st = b_->ExportProgram(ctx_, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(resp.verification().ok()) << resp.verification().detail();
  auto file = testing::read_file(dir_ / "fw.bin.hdr");
  ASSERT_EQ(resp.data().size(), file.size());
  std::size_t differ = 0;
  for (std::size_t i = 0; i < file.size(); ++i) differ += static_cast<std::uint8_t>(resp.data()[i]) != file[i];
  EXPECT_GE(differ, 2u);
  EXPECT_LE(differ, 6u);
  EXPECT_EQ(resp.data().substr(0x40 + row->address().offset(), 4), patched.bytes());
  std::vector<std::uint8_t> out(resp.data().begin(), resp.data().end());
  char want[32];
  std::snprintf(want, sizeof want, "FW_%08llX.bin",
                static_cast<unsigned long long>(patch::compute(patch::Algorithm::sum32, out)));
  EXPECT_EQ(resp.file_name(), want);

  // The detector finds the name rule from the value in a name.
  pb::DetectChecksumRequest dr;
  dr.set_program_id(id_);
  dr.set_patched(true);
  dr.set_file_name(resp.file_name());
  pb::DetectChecksumResponse ds;
  ASSERT_TRUE(b_->DetectChecksum(ctx_, dr, ds).ok());
  ASSERT_FALSE(ds.hits().empty());
  EXPECT_TRUE(ds.hits(0).spec().name());
  EXPECT_EQ(ds.hits(0).spec().algorithm(), pb::CHECKSUM_ALGORITHM_SUM32);
  EXPECT_EQ(ds.hits(0).file_name_template(), "FW_{SUM:08X}.bin");

  // Stored settings are what an export uses by default.
  pb::SetExportSettingsRequest set;
  set.set_program_id(id_);
  *set.mutable_settings() = req.settings();
  *set.mutable_provenance() = User();
  pb::SetExportSettingsResponse sr;
  ASSERT_TRUE(b_->SetExportSettings(ctx_, set, sr).ok());
  pb::GetExportSettingsRequest get;
  get.set_program_id(id_);
  pb::GetExportSettingsResponse gr;
  ASSERT_TRUE(b_->GetExportSettings(ctx_, get, gr).ok());
  EXPECT_TRUE(gr.stored());
  EXPECT_EQ(gr.settings().file_name_template(), "FW_{SUM:08X}.bin");
  pb::ExportProgramRequest again;
  again.set_program_id(id_);
  pb::ExportProgramResponse ar;
  ASSERT_TRUE(b_->ExportProgram(ctx_, again, ar).ok());
  EXPECT_EQ(ar.file_name(), resp.file_name());
}

TEST_F(PatchApi, TheEmulatorRunsThePatchedProgram) {
  pb::PatchBytesRequest req;
  req.set_program_id(id_);
  req.mutable_address()->set_offset(0x100);
  req.set_data("\x11\x22\x33\x44");
  *req.mutable_provenance() = User();
  pb::PatchBytesResponse resp;
  ASSERT_TRUE(b_->PatchBytes(ctx_, req, resp).ok());
  pb::CreateEmulatorSessionRequest cr;
  cr.set_program_id(id_);
  cr.mutable_entry()->set_offset(0);
  cr.set_mode(pb::EMULATOR_START_MODE_BARE);
  pb::CreateEmulatorSessionResponse cs;
  auto st = b_->CreateEmulatorSession(ctx_, cr, cs);
  ASSERT_TRUE(st.ok()) << st.message;
  pb::ReadEmulatorMemoryRequest rm;
  rm.set_session_id(cs.session_id());
  rm.mutable_address()->set_offset(0x100);
  rm.set_length(4);
  pb::ReadEmulatorMemoryResponse mr;
  ASSERT_TRUE(b_->ReadEmulatorMemory(ctx_, rm, mr).ok());
  EXPECT_EQ(mr.data(), "\x11\x22\x33\x44");
}

}  // namespace
}  // namespace revkit::backend

namespace revkit::backend {
namespace {

// What one patch costs on a real firmware: set RK_PATCH_FIRMWARE to a raw
// ARMv4T image with a 0x200-byte header (RK_PATCH_AT, RK_PATCH_TEXT: the
// patch). Prints the commit's time and the rules it re-ran.
TEST(PatchCost, OnALocalFirmware) {
  const char *path = std::getenv("RK_PATCH_FIRMWARE");
  if (!path || std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "RK_PATCH_FIRMWARE not set";
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  auto b = MakeImageBackend(o);
  CallContext ctx;
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path(path);
  req.mutable_options()->set_format("raw");
  req.mutable_options()->set_language_id("ARM:LE:32:v4t");
  req.mutable_options()->set_raw_offset(0x200);
  pb::ImportProgramResponse resp;
  ASSERT_TRUE(b->ImportProgram(ctx, req, resp).ok());
  pb::GetListingRequest lr;
  lr.set_program_id(resp.program().program_id());
  lr.mutable_rows()->set_row_count(100);
  pb::GetListingResponse ls;
  ASSERT_TRUE(b->GetListing(ctx, lr, ls).ok());
  ResetQueryCounters(*b, "default");
  pb::PatchInstructionRequest pr;
  pr.set_program_id(resp.program().program_id());
  pr.mutable_address()->set_offset(std::stoull(std::getenv("RK_PATCH_AT") ? std::getenv("RK_PATCH_AT") : "0x8010", nullptr, 0));
  pr.set_text(std::getenv("RK_PATCH_TEXT") ? std::getenv("RK_PATCH_TEXT") : "cmp r0,#0x9");
  pr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pr.mutable_provenance()->set_id("me");
  pb::PatchInstructionResponse ps;
  const auto t0 = std::chrono::steady_clock::now();
  auto st = b->PatchInstruction(ctx, pr, ps);
  const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
  ASSERT_TRUE(st.ok()) << st.message;
  std::fprintf(stderr, "patch committed in %.1f ms\n", ms);
  for (const auto &[rule, c] : QueryCounters(*b, "default"))
    if (c.executions) std::fprintf(stderr, "  %-28s executions %llu, validations %llu\n", rule.c_str(),
                                   static_cast<unsigned long long>(c.executions), static_cast<unsigned long long>(c.validations));
}

}  // namespace
}  // namespace revkit::backend

namespace revkit::backend {
namespace {

// A patch re-runs what read its bytes and what depends on that, nothing
// else: functions a page apart (x86-64, the host compiler), one patched
// immediate. Its flow and its decompilation recompute, and its caller's
// (which consulted it); no other flow or decompilation does.
TEST(PatchPrecision, OnlyWhatReadsThePatchedBytesRecomputes) {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  const fs::path dir = testing::scratch_dir("patch-precision");
  std::string src = "#define F(n) __attribute__((noinline, aligned(4096))) int f##n(int x) { return x * (n + 3) + 0x40 + n; }\n"
                    "F(0) F(1) F(2) F(3) F(4) F(5)\n"
                    "int main(int c, char **v) { (void)v; return f0(c) + f1(c) + f2(c) + f3(c) + f4(c) + f5(c); }\n";
  if (!testing::compile(REVKIT_TEST_CC, src, "-O1", dir / "prog")) GTEST_SKIP() << "no C compiler";
  ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  auto b = MakeImageBackend(o);
  CallContext ctx;
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path((dir / "prog").string());
  pb::ImportProgramResponse resp;
  ASSERT_TRUE(b->ImportProgram(ctx, req, resp).ok());
  const std::string id = resp.program().program_id();
  pb::ListFunctionsRequest lf;
  lf.set_program_id(id);
  pb::ListFunctionsResponse fr;
  ASSERT_TRUE(b->ListFunctions(ctx, lf, fr).ok());
  std::map<std::string, std::uint64_t> fns;
  for (const auto &f : fr.functions()) fns[f.name()] = f.entry().offset();
  ASSERT_TRUE(fns.contains("f3"));
  auto decompile = [&](std::uint64_t f) {
    pb::DecompileRequest d;
    d.set_program_id(id);
    d.mutable_function()->set_offset(f);
    d.mutable_options()->set_include_text(true);
    pb::DecompileResponse r;
    EXPECT_TRUE(b->Decompile(ctx, d, r).ok());
    return r.function().text();
  };
  for (const auto &[name, f] : fns) decompile(f);
  // f3's instruction with an immediate.
  pb::GetListingRequest lr;
  lr.set_program_id(id);
  lr.mutable_addresses()->mutable_start()->set_offset(fns.at("f3"));
  lr.mutable_addresses()->set_max_rows(6);
  pb::GetListingResponse ls;
  ASSERT_TRUE(b->GetListing(ctx, lr, ls).ok());
  std::optional<std::pair<std::uint64_t, std::string>> target;
  for (const auto &row : ls.rows()) {
    std::string t;
    for (const auto &tok : row.tokens()) t += tok.text();
    // The constant 0x43 (0x40 + 3), wherever the compiler put it.
    if (auto x = t.find("0x43"); x != std::string::npos && !target) target = {row.address().offset(), t.substr(0, x) + "0x77" + t.substr(x + 4)};
  }
  ASSERT_TRUE(target);
  const std::string before = decompile(fns.at("f3"));
  ResetQueryCounters(*b, "default");
  pb::PatchInstructionRequest pr;
  pr.set_program_id(id);
  pr.mutable_address()->set_offset(target->first);
  pr.set_text(target->second);
  pr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  pr.mutable_provenance()->set_id("me");
  pb::PatchInstructionResponse ps;
  auto st = b->PatchInstruction(ctx, pr, ps);
  ASSERT_TRUE(st.ok()) << target->second << ": " << st.message;
  auto c = QueryCounters(*b, "default");
  EXPECT_EQ(c.at("analysis.flow").executions, 1u);  // f3's only: the other functions are pages away
  std::set<std::string> recomputed;
  for (const auto &[name, f] : fns) {
    ResetQueryCounters(*b, "default");
    const std::string text = decompile(f);
    if (QueryCounters(*b, "default").at("decompile.ghidra").executions > 0) recomputed.insert(name);
    if (name == "f3") EXPECT_NE(text, before);
  }
  // f3, and main, whose decompilation consulted f3 (its callee): no other.
  EXPECT_EQ(recomputed, (std::set<std::string>{"f3", "main"}));
}

}  // namespace
}  // namespace revkit::backend

namespace revkit::backend {
namespace {

TEST_F(PatchApi, ComparesWithTheOriginal) {
  const std::uint64_t fn = fns_.at("h1");
  auto row = FirstImmediate(fn);
  ASSERT_TRUE(row);
  std::string text = Text(*row);
  text = text.substr(0, text.find("#0x")) + "#0x6";
  Patch(row->address().offset(), text);

  pb::OpenOriginalRequest oq;
  oq.set_program_id(id_);
  *oq.mutable_provenance() = User();
  pb::OpenOriginalResponse orig;
  auto st = b_->OpenOriginal(ctx_, oq, orig);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(orig.created());
  pb::OpenOriginalResponse again;
  ASSERT_TRUE(b_->OpenOriginal(ctx_, oq, again).ok());
  EXPECT_FALSE(again.created());
  EXPECT_EQ(again.program_id(), orig.program_id());
  // The original has the file's bytes.
  pb::ReadMemoryRequest rm;
  rm.set_program_id(orig.program_id());
  rm.mutable_address()->set_offset(row->address().offset());
  rm.set_length(4);
  pb::ReadMemoryResponse mr;
  ASSERT_TRUE(b_->ReadMemory(ctx_, rm, mr).ok());
  EXPECT_EQ(mr.data(), row->bytes());

  // Diffing them: the patched function is the one modified.
  pb::CreateDiffSessionRequest cq;
  cq.set_project_id("default");
  cq.set_program_a(orig.program_id());
  cq.set_program_b(id_);
  *cq.mutable_provenance() = User();
  pb::CreateDiffSessionResponse cs;
  ASSERT_TRUE(b_->CreateDiffSession(ctx_, cq, cs).ok());
  pb::ListMatchesRequest lm;
  lm.set_project_id("default");
  lm.set_session_id(cs.session().session_id());
  lm.mutable_page()->set_page_size(1000);
  pb::ListMatchesResponse ms;
  ASSERT_TRUE(b_->ListMatches(ctx_, lm, ms).ok());
  std::set<std::uint64_t> modified;
  std::size_t unchanged = 0;
  for (const auto &m : ms.matches()) {
    if (m.change_kind() == pb::DIFF_CHANGE_KIND_MODIFIED) modified.insert(m.b().entry().offset());
    unchanged += m.change_kind() == pb::DIFF_CHANGE_KIND_UNCHANGED;
  }
  EXPECT_EQ(modified, (std::set<std::uint64_t>{fn}));
  EXPECT_GE(unchanged, 10u);
}

}  // namespace
}  // namespace revkit::backend
