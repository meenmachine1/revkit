// Function ID: databases (.fidbf and .rkfid, hostile input), Ghidra's hash
// bit for bit on corpus binaries, matching and naming (docs/fid.md).
#include "json.hh"

#include "revkit/fid/create.h"
#include "revkit/fid/db.h"
#include "revkit/fid/hash.h"
#include "revkit/fid/match.h"
#include "revkit/fid/program.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#include <unistd.h>

namespace fs = std::filesystem;
using namespace revkit::fid;

namespace {

std::string slurp(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

fs::path builtin(const std::string &name) {
  return fs::path(REVKIT_GHIDRA_ROOT) / "Ghidra/Features/FunctionID/data" / (name + ".fidbf");
}

ProgramHashes hash_file(const fs::path &path) {
  revkit::lift::initialize(REVKIT_GHIDRA_ROOT);
  revkit::loader::LoadOptions opts;
  opts.ghidra_image_base = true;
  auto image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_file(path, opts));
  auto lang = revkit::loader::guess_language(*image);
  auto an = revkit::inputs::analyze(*image, lang->language + ":" + lang->compiler, 2);
  ProgramSource src;
  src.language = lang->language;
  src.info = &an->info();
  src.functions = &an->functions();
  src.flow = [&](std::uint64_t k) { return an->flow_shared(k); };
  src.read = [&](std::uint64_t a, std::span<std::byte> out) { return image->memory.read(a, out); };
  image_relocations(*image, src);
  src.no_return = revkit::inputs::ghidra_no_return(an->functions(), an->no_return_evidence());
  src.scalar_references = image->format != revkit::loader::Format::elf;
  return hash_program(src);
}

std::string hex16(std::uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "%016llx", static_cast<unsigned long long>(v));
  return b;
}

}  // namespace

TEST(FidHash, Fnv1a64) {
  Fnv1a64 h;
  EXPECT_EQ(h.value(), 0xcbf29ce484222325ULL);
  const std::uint8_t a = 'a';
  h.update(std::span(&a, 1));
  EXPECT_EQ(h.value(), 0xaf63dc4c8601ec8cULL);  // FNV-1a("a")
}

TEST(FidHash, X86Skipper) {
  const std::uint8_t nop[] = {0x90}, mov[] = {0x8b, 0xff}, long_nop[] = {0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0};
  const std::uint8_t ret[] = {0xc3};
  EXPECT_TRUE(x86_skipped(nop));
  EXPECT_TRUE(x86_skipped(mov));
  EXPECT_TRUE(x86_skipped(long_nop));
  EXPECT_FALSE(x86_skipped(ret));
}

TEST(FidHash, TooShortHashesToNothing) {
  std::vector<HashUnit> units(3);
  for (auto &u : units) {
    u.bytes = {0xc3};
    u.insn.length = 1;
    u.insn.masks = true;
    u.insn.mask = {0xff};
  }
  EXPECT_FALSE(hash_function(units, {}).has_value());
  units.push_back(units[0]);
  auto q = hash_function(units, {});
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(q->code_units, 4);
  EXPECT_EQ(q->full, q->specific);  // no operands: the same bytes in both
}

// Ghidra's own hashes (src/fid/tests/data/ghidra_hashes.json) for corpus
// binaries: every function both find, bit for bit.
TEST(FidHash, MatchesGhidraOnTheCorpus) {
  const fs::path corpus = REVKIT_CORPUS_DIR;
  const auto doc = rklift::Json::parse(slurp(fs::path(REVKIT_FID_TEST_DATA) / "ghidra_hashes.json"));
  int checked = 0;
  for (const auto &[rel, want] : doc["programs"].object()) {
    const fs::path bin = corpus / rel;
    if (!fs::exists(bin)) continue;
    const ProgramHashes got = hash_file(bin);
    std::size_t same = 0, total = 0;
    std::vector<std::string> diffs;
    for (const auto &[entry, quad] : want.object()) {
      const ProgramFunction *f = got.find(std::stoull(entry, nullptr, 16));
      if (f == nullptr) continue;  // a function discovery doesn't make
      ++total;
      const auto &q = quad.array();
      const bool ok = f->hash && f->hash->code_units == q[0].int64() && hex16(f->hash->full) == q[1].str() &&
                      f->hash->specific_extra == q[2].int64() && hex16(f->hash->specific) == q[3].str();
      if (ok) ++same;
      else diffs.push_back(entry);
    }
    // AArch64's PLT header jumps to the resolver through a register Ghidra
    // makes a call; revkit can't tell (one function).
    const std::size_t allowed = rel.starts_with("elf-aarch64") ? 1 : 0;
    EXPECT_GE(same + allowed, total) << rel << ": " << same << "/" << total << " first diff "
                                     << (diffs.empty() ? "" : diffs.front());
    EXPECT_GT(total, 100u) << rel;
    ++checked;
  }
  if (checked == 0) GTEST_SKIP() << "no corpus binaries under " << corpus;
}

TEST(FidDb, ReadsGhidrasShippedDatabase) {
  const fs::path p = builtin("vs2019_x64");
  if (!fs::exists(p)) GTEST_SKIP() << "no " << p;
  const Database db = Database::open(p);
  EXPECT_EQ(db.name(), "vs2019_x64");
  EXPECT_EQ(db.format(), Database::Format::fidbf);
  EXPECT_EQ(db.functions().size(), 57785u);
  EXPECT_EQ(db.superior_count(), 102025u);
  EXPECT_EQ(db.inferior_count(), 94009u);
  ASSERT_EQ(db.libraries().size(), 2u);
  EXPECT_EQ(db.libraries()[0].family, "Visual Studio");
  EXPECT_TRUE(db.has_language("x86:LE:64:default"));
  EXPECT_FALSE(db.has_language("x86:LE:32:default"));
  // The first record Ghidra's tables hold.
  const auto fns = db.by_full(5220612664417371843ULL);
  ASSERT_FALSE(fns.empty());
  EXPECT_EQ(fns[0].name, "archive_acl_count");
  EXPECT_EQ(fns[0].hash.code_units, 34);
  EXPECT_EQ(fns[0].hash.specific_extra, 19);
  EXPECT_EQ(fns[0].entry, 10896u);
  EXPECT_NE(db.library(fns[0].library), nullptr);
  EXPECT_TRUE(db.path(fns[0]).ends_with("archive_acl.c.obj"));
  // The libraries and the count alone, without the functions.
  const Database::Peek peek = Database::peek(p);
  EXPECT_EQ(peek.format, Database::Format::fidbf);
  EXPECT_EQ(peek.functions, 57785u);
  ASSERT_EQ(peek.libraries.size(), 2u);
  EXPECT_EQ(peek.libraries[1].language, "x86:LE:64:default");
}

TEST(FidDb, RkfidRoundTrip) {
  Database db;
  db.set_name("t");
  Library lib;
  lib.family = "acc";
  lib.version = "1";
  lib.language = "x86:LE:64:default";
  const auto lid = db.add_library(lib);
  Function a, b;
  a.name = "acc_add";
  a.library = lid;
  a.hash = {20, 0x1111, 3, 0x2222};
  b.name = "summarize";
  b.library = lid;
  b.hash = {40, 0x3333, 7, 0x4444};
  a.path = b.path = db.intern_path("libacc.a(lib.o)");
  const auto ida = db.add_function(a), idb = db.add_function(b);
  db.add_superior(idb, 0x1111);
  db.add_inferior(ida, 0x3333);
  db.index();
  const std::string bytes = db.serialize();
  const Database back = Database::parse(std::as_bytes(std::span(bytes.data(), bytes.size())), "t");
  EXPECT_EQ(back.format(), Database::Format::rkfid);
  ASSERT_EQ(back.functions().size(), 2u);
  EXPECT_EQ(back.by_full(0x3333)[0].name, "summarize");
  EXPECT_TRUE(back.superior(idb, 0x1111));
  EXPECT_TRUE(back.inferior(0x3333, ida));
  EXPECT_FALSE(back.superior(ida, 0x3333));
  EXPECT_EQ(back.serialize(), bytes);  // deterministic
  EXPECT_EQ(back.path(back.by_full(0x1111)[0]), "libacc.a(lib.o)");
  const fs::path file = fs::temp_directory_path() / ("rk-fid-test-" + std::to_string(::getpid()) + ".rkfid");
  back.write(file);
  const Database::Peek peek = Database::peek(file);
  fs::remove(file);
  EXPECT_EQ(peek.functions, 2u);
  ASSERT_EQ(peek.libraries.size(), 1u);
  EXPECT_EQ(peek.libraries[0].family, "acc");
}

// Hostile files: every truncation and random corruption is a FidError or a
// database, never a crash.
TEST(FidDb, RkfidFunctionsWithoutNames) {
  // A function's smallest record is 52 bytes; the count check wanted 60
  // each, so a database of unnamed functions didn't read back.
  Database db;
  Library lib;
  lib.family = "x";
  db.add_library(lib);
  for (int i = 0; i < 50; ++i) {
    Function f;
    f.hash = {static_cast<std::uint16_t>(i), static_cast<std::uint64_t>(i) * 7, 1, 9};
    db.add_function(f);
  }
  db.index();
  const std::string s = db.serialize();
  EXPECT_EQ(Database::parse(std::as_bytes(std::span(s.data(), s.size())), "x").functions().size(), 50u);
}

TEST(FidDb, HostileInput) {
  Database db;
  Library lib;
  lib.family = "x";
  db.add_library(lib);
  for (int i = 0; i < 50; ++i) {
    Function f;
    f.name = "f" + std::to_string(i);
    f.hash = {static_cast<std::uint16_t>(i), static_cast<std::uint64_t>(i) * 7, 1, 9};
    db.add_superior(db.add_function(f), 3);
  }
  db.index();
  const std::string good = db.serialize();
  std::mt19937 rng(7);
  auto attempt = [](const std::string &s) {
    try {
      Database::parse(std::as_bytes(std::span(s.data(), s.size())), "x");
    } catch (const FidError &) {
    }
  };
  for (std::size_t n = 0; n < good.size(); n += 7) attempt(good.substr(0, n));
  for (int i = 0; i < 2000; ++i) {
    std::string s = good;
    for (int k = 0; k < 4; ++k) s[rng() % s.size()] = static_cast<char>(rng());
    attempt(s);
  }
  // A Ghidra file, cut and corrupted.
  const fs::path p = builtin("vs2017_x64");
  if (fs::exists(p)) {
    const std::string fidbf = slurp(p);
    attempt(fidbf.substr(0, 16384 * 3));
    for (int i = 0; i < 8; ++i) {
      std::string s = fidbf;
      for (int k = 0; k < 64; ++k) s[rng() % s.size()] = static_cast<char>(rng());
      attempt(s);
    }
  }
  std::string not_one = "not a database at all";
  EXPECT_THROW(Database::parse(std::as_bytes(std::span(not_one.data(), not_one.size())), "x"), FidError);
}

TEST(FidDb, AliasedRecordsAreBudgeted) {
  // A .fidbf whose master table node has 2500 entries all pointing at one
  // 30000-byte record: each was decoded (and a Strings Table kept them),
  // 160 GB from a 4 MB node at full size. Decoding stops at four times the
  // file.
  constexpr std::size_t kBlock = 65536;
  std::string f(3 * kBlock, '\0');
  auto be = [&](std::size_t off, std::uint64_t v, int n) {
    for (int i = 0; i < n; ++i) f[off + i] = static_cast<char>(v >> (8 * (n - 1 - i)));
  };
  be(0, 0x2f30312c34292c2aULL, 8);  // magic
  be(16, 1, 4);                     // version
  be(20, kBlock, 4);                // block size
  // Buffer 0: DBParms, a one-buffer chained buffer: version 1, master root 1.
  std::size_t b0 = kBlock;
  be(b0 + 1, 0, 4);
  f[b0 + 5] = 9;
  be(b0 + 6, 5, 4);
  f[b0 + 10] = 1;
  be(b0 + 11, 1, 4);
  // Buffer 1: the master table, a var-record leaf.
  std::size_t b1 = 2 * kBlock, p = b1 + 5;
  be(b1 + 1, 1, 4);
  const std::size_t n = 2500, rec = 13 + n * 13 + 16;
  f[p] = 1;
  be(p + 1, n, 4);
  for (std::size_t i = 0; i < n; ++i) {
    be(p + 13 + i * 13, i, 8);
    be(p + 13 + i * 13 + 8, rec, 4);
  }
  // The record: a 30000-byte name, then the master schema's other fields.
  std::size_t r = p + rec;
  be(r, 30000, 4);
  r += 4 + 30000;
  be(r + 4 + 4 + 1, 0xffffffffu, 4);  // ints, the key type, a null schema
  be(r + 13, 0xffffffffu, 4);         // a null string
  try {
    Database::parse(std::as_bytes(std::span(f.data(), f.size())), "x");
    ADD_FAILURE() << "parsed";
  } catch (const FidError &e) {
    EXPECT_NE(std::string(e.what()).find("decode to more"), std::string::npos) << e.what();
  }
}

// FidProgramSeeker's scoring and ApplyFidEntriesCommand's naming over a
// made-up database and program.
TEST(FidMatch, ScoresRelationsAndNames) {
  Database db;
  Library lib;
  lib.family = "acc";
  lib.version = "1";
  lib.variant = "O2";
  lib.language = "x86:LE:64:default";
  const auto lid = db.add_library(lib);
  auto fn = [&](std::string name, HashQuad h, std::uint8_t flags = 0) {
    Function f;
    f.name = std::move(name);
    f.hash = h;
    f.library = lid;
    f.flags = flags;
    return db.add_function(f);
  };
  const auto big = fn("big", {30, 0xb1, 2, 0xb2});
  const auto small = fn("small", {8, 0x51, 1, 0x52});
  fn("_twin", {16, 0x71, 0, 0x72});
  fn("twin", {16, 0x71, 0, 0x73});
  fn("left", {20, 0x81, 0, 0x82});
  fn("right", {20, 0x81, 0, 0x83});
  fn("never", {50, 0x91, 0, 0x92}, kAutoFail);
  db.add_superior(small, 0xb1);  // small calls big
  db.add_inferior(big, 0x51);
  db.index();

  ProgramHashes p;
  p.language = "x86:LE:64:default";
  auto add = [&](std::uint64_t entry, HashQuad h) {
    ProgramFunction f;
    f.entry = entry;
    f.name = "FUN";
    f.hash = h;
    p.functions.push_back(f);
    return p.functions.size() - 1;
  };
  const auto pb = add(0x100, {30, 0xb1, 2, 0xb2});
  const auto ps = add(0x200, {8, 0x51, 1, 0x52});
  add(0x300, {16, 0x71, 0, 0x72});
  add(0x400, {20, 0x81, 0, 0x99});
  add(0x500, {50, 0x91, 0, 0x92});
  add(0x600, {8, 0x51, 1, 0x52});  // small, but nothing it calls matches
  p.functions[ps].callees = {pb};
  p.functions[pb].callers = {ps};

  const std::vector<Match> ms = search(p, {&db});
  std::map<std::uint64_t, const Match *> by;
  for (const Match &m : ms) by[m.entry] = &m;
  ASSERT_TRUE(by.contains(0x100));
  EXPECT_EQ(by[0x100]->name, "big");
  EXPECT_FLOAT_EQ(by[0x100]->candidates[0].primary, 30 + static_cast<float>(0.67 * 2));
  EXPECT_FLOAT_EQ(by[0x100]->candidates[0].parents, 8);
  ASSERT_TRUE(by.contains(0x200));  // 8 units + 0.67 + big's 30 as a callee
  EXPECT_EQ(by[0x200]->name, "small");
  EXPECT_FLOAT_EQ(by[0x200]->candidates[0].children, 30);
  EXPECT_FALSE(by.contains(0x600));  // 8.67 is under 14.6
  ASSERT_TRUE(by.contains(0x300));   // "_twin" and "twin": one name, leading underscores aside
  EXPECT_EQ(by[0x300]->verdict, Verdict::single);
  EXPECT_EQ(by[0x300]->name, "_twin");
  EXPECT_EQ(by[0x300]->candidates.size(), 2u);
  ASSERT_TRUE(by.contains(0x400));  // two base names scoring 20 < 30: not named
  EXPECT_EQ(by[0x400]->verdict, Verdict::below_threshold);
  EXPECT_TRUE(by[0x400]->name.empty());
  EXPECT_FALSE(by.contains(0x500));  // auto-fail
  EXPECT_EQ(by[0x100]->libraries, std::vector<std::string>{"acc 1 O2"});
  EXPECT_EQ(by[0x100]->comment(), "Library Function - Single Match\n big\n\nLibrary: acc 1 O2");
}

// LibraryBuilder (FidServiceLibraryIngest): records, relations, duplicates.
TEST(FidCreate, BuildsRelationsAndSkipsDuplicates) {
  ProgramHashes p;
  auto add = [&](std::uint64_t entry, std::string name, std::optional<HashQuad> h) {
    ProgramFunction f;
    f.entry = entry;
    f.name = std::move(name);
    f.hash = h;
    p.functions.push_back(f);
    return p.functions.size() - 1;
  };
  const auto a = add(0x10, "caller", HashQuad{20, 0xa1, 0, 0xa2});
  const auto b = add(0x20, "callee", HashQuad{20, 0xb1, 0, 0xb2});
  add(0x30, "FUN_00000030", HashQuad{20, 0xc1, 0, 0xc2});
  add(0x40, "tiny", std::nullopt);
  p.functions[a].callees = {b};
  p.functions[a].external_callees = {"malloc"};
  Database db;
  LibraryBuilder lb(db, {"lib", "1", "", "x86:LE:64:default", "gcc"});
  auto is_default = [](const std::string &n) { return n.starts_with("FUN_"); };
  lb.add_program(p, "one", is_default);
  lb.add_program(p, "two", is_default);  // the same functions again: duplicates
  const IngestReport r = lb.finish();
  EXPECT_EQ(db.functions().size(), 2u);
  EXPECT_EQ(r.counts.at(Disposition::included), 2u);
  EXPECT_EQ(r.counts.at(Disposition::duplicate), 2u);
  EXPECT_EQ(r.counts.at(Disposition::no_symbol), 2u);
  EXPECT_EQ(r.counts.at(Disposition::too_short), 2u);
  EXPECT_TRUE(r.unresolved.contains("malloc"));
  const auto caller = db.by_full(0xa1)[0].id, callee = db.by_full(0xb1)[0].id;
  EXPECT_TRUE(db.superior(caller, 0xb1));
  EXPECT_TRUE(db.inferior(0xa1, callee));
}
