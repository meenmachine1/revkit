#include "revkit/detect/detect.hh"

#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <map>
#include <random>

namespace revkit::detect {
namespace {

std::vector<std::byte> fill(std::size_t n, std::uint8_t v) { return std::vector<std::byte>(n, std::byte{v}); }

std::vector<std::byte> noise(std::size_t n) {
  std::mt19937 gen(7);
  std::vector<std::byte> out(n);
  for (std::byte &b : out) b = static_cast<std::byte>(gen() & 0xff);
  return out;
}

TEST(Segments, CoverTheFileAndNameWhatEachStretchIs) {
  std::vector<std::byte> file = fill(4096, 0xff);
  const std::vector<std::byte> dense = noise(8192);
  file.insert(file.end(), dense.begin(), dense.end());
  for (int i = 0; i < 4096; ++i) file.push_back(static_cast<std::byte>("log line: sensor ok\r\n"[i % 21]));
  const std::vector<Segment> s = segments(file);
  ASSERT_EQ(s.size(), 3u);
  EXPECT_EQ(s[0], (Segment{0, 4096, Segment::Kind::padding}));
  EXPECT_EQ(s[1], (Segment{4096, 8192, Segment::Kind::high_entropy}));
  EXPECT_EQ(s[2], (Segment{12288, 4096, Segment::Kind::text}));
}

TEST(Detect, RefusesWhatIsNoProgram) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  EXPECT_EQ(detect(noise(1 << 16)).refusal.value().reason, "high-entropy");
  EXPECT_EQ(detect(fill(1 << 16, 0xff)).refusal.value().reason, "not-code");
  EXPECT_EQ(detect(fill(16, 0x12)).refusal.value().reason, "too-small");
}

// This program's own code, as a blob with no header: what the compiler made
// for the machine the tests run on.
std::vector<std::byte> own_code() {
  const loader::Image image = loader::load_file("/proc/self/exe");
  const loader::Section *text = loader::find_section(image, ".text");
  if (text == nullptr) return {};
  const std::span<const std::byte> bytes = loader::section_bytes(image, *text);
  return {bytes.begin(), bytes.end()};
}

TEST(Detect, NamesTheProcessorOfThisProgramsOwnCode) {
#if defined(__x86_64__)
  const std::string expect = "x86:LE:64:";
#elif defined(__aarch64__)
  const std::string expect = "AARCH64:LE:64:";
#else
  const std::string expect;
#endif
  const std::vector<std::byte> code = own_code();
  if (expect.empty() || code.size() < (64 << 10)) GTEST_SKIP() << "no code of a known processor to read";
  lift::initialize(REVKIT_GHIDRA_ROOT);
  Options options;
  options.threads = 4;
  // A handful of processors, to keep it quick under the sanitizers: enough
  // for wrong ones to be in the running.
  options.processors = {"x86", "AARCH64", "ARM", "MIPS", "PowerPC", "z80", "68000"};
  const Report r = detect(code, options);
  EXPECT_FALSE(r.refusal) << r.refusal->reason;
  ASSERT_FALSE(r.suggestions.empty());
  const Suggestion &top = r.suggestions.front();
  EXPECT_TRUE(top.language.starts_with(expect)) << top.language;
  EXPECT_EQ(top.processor, Confidence::high);
  ASSERT_FALSE(top.evidence.empty());
  EXPECT_NE(top.evidence.front().text.find("relative calls go to a function called more than once"), std::string::npos)
      << top.evidence.front().text;
  // Nothing else comes close.
  if (r.suggestions.size() > 1) EXPECT_GT(top.score, 5 * r.suggestions[1].score);

  // The same bytes shuffled are no program.
  std::vector<std::byte> shuffled = code;
  std::mt19937 gen(11);
  std::shuffle(shuffled.begin(), shuffled.end(), gen);
  const Report none = detect(shuffled, options);
  ASSERT_TRUE(none.refusal);
  for (const Suggestion &s : none.suggestions) EXPECT_NE(s.processor, Confidence::high);
}

// What tells code from bytes that merely decode is counted against chance.
TEST(Quality, CountsOnlyWhatChanceDoesNotExplain) {
  Features code;
  code.instructions = 10000, code.bytes = code.valid_bytes = 40000;
  code.branches = 1000, code.branch_near = 900, code.branch_start = 890;
  Features noise = code;
  // Where the shuffled bytes' branches land nearby as often, that says nothing...
  EXPECT_LT(quality(code, noise).total(), 0.005);
  // ...and where they almost never do, it says a lot.
  noise.branch_near = 30, noise.branch_start = 10;
  const Quality q = quality(code, noise);
  EXPECT_GT(q.branches, 0.2);
  EXPECT_EQ(q.kinds(), 1);
  // What code seldom does counts against it.
  code.unimplemented = 2500;
  EXPECT_LT(quality(code, noise).total(), 0.6 * q.total());
  // Too little decoded says nothing.
  Features few;
  few.instructions = 100;
  EXPECT_EQ(quality(few, noise).total(), 0);
}

// Z80 code of absolute jumps, each to `target(place)`, between loads of A.
std::vector<std::byte> z80_jumps(const std::function<std::uint16_t(std::size_t)> &target) {
  std::vector<std::byte> out;
  while (out.size() + 7 <= 4096) {
    for (std::uint8_t b : {0x3e, 0x01, 0x3e, 0x02}) out.push_back(std::byte{b});  // ld a,1; ld a,2
    const std::uint16_t t = target(out.size());
    for (std::uint8_t b : {std::uint8_t{0xc3}, static_cast<std::uint8_t>(t), static_cast<std::uint8_t>(t >> 8)})
      out.push_back(std::byte{b});  // jp t
  }
  return out;
}

// Fill is no code, and absolute jumps going near themselves are code
// whatever the base.
TEST(Sweep, SkipsFillAndCountsJumpsGoingNearThemselves) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  Candidate z80;
  z80.language = "z80:LE:16:default";
  z80.languages = {z80.language};
  Sweeper sweeper(z80);
  ASSERT_TRUE(sweeper.ok());
  const std::vector<std::pair<std::uint64_t, std::uint64_t>> window = {{0, 4096}};

  // Jumps within a few dozen bytes of themselves, at a base of 0x4000.
  std::mt19937 gen(5);
  const std::vector<std::byte> near =
      z80_jumps([&](std::size_t at) { return static_cast<std::uint16_t>(0x4000 + at - 30 + gen() % 80); });
  const Features f = sweeper.sweep(near, window);
  EXPECT_GT(f.abs_pairs, 500u);
  EXPECT_GT(f.abs_pairs_near, f.abs_pairs * 9 / 10);
  // Jumps anywhere.
  const std::vector<std::byte> anywhere = z80_jumps([&](std::size_t) { return static_cast<std::uint16_t>(gen()); });
  const Features g = sweeper.sweep(anywhere, window);
  EXPECT_GT(g.abs_pairs, 500u);
  EXPECT_LT(g.abs_pairs_near, g.abs_pairs / 10);
  // A table of jumps, one after another, says nothing either way.
  std::vector<std::byte> table;
  for (std::uint16_t i = 0; table.size() + 3 <= 4096; ++i)
    for (std::uint8_t b : {std::uint8_t{0xc3}, static_cast<std::uint8_t>(i * 3), static_cast<std::uint8_t>(0x40 + (i * 3 >> 8))})
      table.push_back(std::byte{b});
  table.resize(4096, std::byte{0});
  EXPECT_EQ(sweeper.sweep(table, window).abs_pairs, 0u);

  // Fill in the middle is skipped, not decoded.
  std::vector<std::byte> filled = near;
  std::fill(filled.begin() + 1024, filled.begin() + 2048, std::byte{0xff});
  const Features h = sweeper.sweep(filled, window);
  EXPECT_GE(h.fill_bytes, 1000u);
  EXPECT_LT(h.instructions, f.instructions);
}

// An image for the layout tests: `header` bytes of a vendor header (text,
// then fill), then noise standing for code, with strings
// in its second half, at uneven distances (evenly spaced strings would
// fit their pointers at every shift alike). Returns the strings' offsets
// in the file.
std::vector<std::uint64_t> image_with_strings(std::vector<std::byte> &file, std::size_t header) {
  file.clear();
  for (std::size_t i = 0; i < header; ++i) file.push_back(i < 24 ? static_cast<std::byte>("FWIMAGE v1.2 build 77 \n"[i % 23]) : std::byte{0xff});
  const std::vector<std::byte> code = noise(32 << 10);
  file.insert(file.end(), code.begin(), code.end());
  std::vector<std::uint64_t> strings;
  std::mt19937 gap(3);
  for (std::size_t at = header + (16 << 10); at + 64 <= file.size(); at += 40 + gap() % 90) {
    const std::string text = "message " + std::to_string(at) + " ok";
    file[at - 1] = std::byte{0};
    for (std::size_t k = 0; k < text.size(); ++k) file[at + k] = static_cast<std::byte>(text[k]);
    file[at + text.size()] = std::byte{0};
    strings.push_back(at);
  }
  return strings;
}

TEST(Layout, FindsTheBaseFromAddressesThatAreStrings) {
  std::vector<std::byte> file;
  const std::vector<std::uint64_t> strings = image_with_strings(file, 0);
  const std::vector<std::uint64_t> found = string_offsets(file);
  for (std::uint64_t s : strings) EXPECT_TRUE(std::binary_search(found.begin(), found.end(), s)) << s;

  Trace trace;
  for (std::uint64_t s : strings) trace.pointers.push_back(0x08000000 + s);
  for (std::uint64_t junk = 0x100; junk < 0x4000; junk += 0x1c) trace.pointers.push_back(junk);  // numbers that aren't addresses
  std::sort(trace.pointers.begin(), trace.pointers.end());
  const Layout l = layout(file, segments(file), trace, 32, false, false);
  ASSERT_TRUE(l.delta);
  EXPECT_EQ(l.base, 0x08000000u);
  EXPECT_EQ(l.offset, 0u);
  EXPECT_EQ(l.base_confidence, Confidence::high);
  EXPECT_EQ(l.string_hits, strings.size());

  // Nothing agrees: no base, not a guess.
  Trace none;
  for (std::uint64_t junk = 0x100; junk < 0x40000; junk += 0x137) none.pointers.push_back(junk * 0x9e3779b1 & 0xffffffff);
  std::sort(none.pointers.begin(), none.pointers.end());
  EXPECT_FALSE(layout(file, segments(file), none, 32, false, false).delta);
}

TEST(Layout, SplitsAHeaderOffTheBase) {
  // 0x200 bytes of header: the pointers say base - offset; a round base
  // says which part is the header.
  std::vector<std::byte> file;
  const std::vector<std::uint64_t> strings = image_with_strings(file, 0x200);
  Trace trace;
  for (std::uint64_t s : strings) trace.pointers.push_back(0xbfc00000 + (s - 0x200));
  const Layout l = layout(file, segments(file), trace, 32, true, false);
  ASSERT_TRUE(l.delta);
  EXPECT_EQ(l.base, 0xbfc00000u);
  EXPECT_EQ(l.offset, 0x200u);
  ASSERT_EQ(l.evidence.size(), 2u);
  EXPECT_NE(l.evidence[1].text.find("0x200"), std::string::npos) << l.evidence[1].text;

  // An image that can't fit under the top of the address space at offset 0
  // isn't put there.
  Trace high;
  for (std::uint64_t s : strings) high.pointers.push_back((0xfffffe00 + s) & 0xffffffff);
  std::sort(high.pointers.begin(), high.pointers.end());
  const Layout h = layout(file, segments(file), high, 32, true, false);
  ASSERT_TRUE(h.delta);
  EXPECT_EQ(h.base, 0u);
  EXPECT_EQ(h.offset, 0x200u);
}

// Pointers say only base - offset. A round base that would need a "header"
// holding code and the very strings the pointers name is no answer: the
// image starts at the file's start, at the base that isn't round.
TEST(Layout, NoHeaderThatCutsOffWhatThePointersName) {
  std::vector<std::byte> file;
  image_with_strings(file, 0);
  // Strings throughout the image, from its first kilobytes.
  std::vector<std::uint64_t> early;
  std::mt19937 gap(5);
  for (std::size_t at = 0x400; at + 64 < (16u << 10); at += 40 + gap() % 90) {
    const std::string text = "early " + std::to_string(at);
    file[at - 1] = std::byte{0};
    for (std::size_t k = 0; k < text.size(); ++k) file[at + k] = static_cast<std::byte>(text[k]);
    file[at + text.size()] = std::byte{0};
    early.push_back(at);
  }
  Trace trace;
  for (std::uint64_t s : string_offsets(file)) trace.pointers.push_back(0x15e0 + s);
  std::sort(trace.pointers.begin(), trace.pointers.end());
  const Layout l = layout(file, segments(file), trace, 32, false, false);
  ASSERT_TRUE(l.delta);
  EXPECT_EQ(*l.delta, 0x15e0u);
  EXPECT_EQ(l.offset, 0u) << "a split at " << l.offset << " leaves named strings in its header";
  EXPECT_EQ(l.base, 0x15e0u);
}

// Position-independent code names no addresses; its tables do.
TEST(Layout, ReadsPointerTablesInData) {
  std::vector<std::byte> file;
  const std::vector<std::uint64_t> strings = image_with_strings(file, 0);
  // A table of the strings' addresses, big-endian, over the first quarter.
  std::size_t at = 0x400;
  for (std::uint64_t s : strings) {
    const std::uint32_t p = 0x00ff0000 + static_cast<std::uint32_t>(s);
    for (int k = 0; k < 4; ++k) file[at++] = static_cast<std::byte>(p >> (24 - 8 * k));
  }
  const Layout l = layout(file, segments(file), Trace{}, 32, true, false);
  ASSERT_TRUE(l.delta);
  EXPECT_EQ(l.base, 0x00ff0000u);
}

// A position-independent image's own relocations (ELF RELA records:
// slot, type, addend) at the end of the file, the slots left zero: the
// addends are pointers, the type between them isn't.
TEST(Layout, ReadsRelocationsAtTheEndOfTheFile) {
  std::vector<std::byte> file;
  const std::vector<std::uint64_t> strings = image_with_strings(file, 0);
  constexpr std::uint64_t kBase = 0x40280000;
  auto put64 = [&](std::uint64_t v) {
    for (int k = 0; k < 8; ++k) file.push_back(static_cast<std::byte>(v >> (8 * k)));
  };
  for (std::size_t i = 0; i < strings.size(); ++i) {
    put64(kBase + 0x100 + 8 * i);  // the slot
    put64(0x403);                  // R_AARCH64_RELATIVE
    put64(kBase + strings[i]);     // what it points to
  }
  const Layout l = layout(file, segments(file), Trace{}, 64, false, false);
  ASSERT_TRUE(l.delta);
  EXPECT_EQ(l.base, kBase);
  EXPECT_EQ(l.string_hits, strings.size());
}

// Structures with a pointer among small fields: a run of pointers all the same.
TEST(Layout, ReadsPointersBetweenSmallFields) {
  std::vector<std::byte> file;
  const std::vector<std::uint64_t> strings = image_with_strings(file, 0);
  std::size_t at = 0x400;
  for (std::uint64_t s : strings) {
    const std::uint32_t fields[] = {0x20000000 + static_cast<std::uint32_t>(s), 7, 0};
    for (std::uint32_t f : fields)
      for (int k = 0; k < 4; ++k) file[at++] = static_cast<std::byte>(f >> (8 * k));
  }
  const Layout l = layout(file, segments(file), Trace{}, 32, false, false);
  ASSERT_TRUE(l.delta);
  EXPECT_EQ(l.base, 0x20000000u);
}

// AArch64's adrp makes an address from the program counter's 4 KiB page:
// relative, though it moves only when the code moves a whole page. Not a
// pointer, which a file offset taken for an address would be.
TEST(Trace, AdrpIsRelativeToTheProgramCounter) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  std::vector<std::byte> file;
  auto put32 = [&](std::uint32_t v) {
    for (int k = 0; k < 4; ++k) file.push_back(static_cast<std::byte>(v >> (8 * k)));
  };
  for (int i = 0; i < 256; ++i) {
    put32(0xb0000000);  // adrp x0, the next page
    put32(0x91004000);  // add x0, x0, #0x10
    put32(0x94000004);  // bl . + 16
    put32(0xd65f03c0);  // ret
  }
  Candidate c;
  c.language = "AARCH64:LE:64:v8A";
  Sweeper sweeper(c);
  ASSERT_TRUE(sweeper.ok());
  const Trace t = sweeper.trace(file, {{0, file.size()}});
  EXPECT_GT(t.instructions, 1000u);
  EXPECT_TRUE(t.pointers.empty()) << t.pointers.size() << " pointers, the first " << t.pointers.front();
}

// The fit of a language's whole instruction set, on made-up censuses.
TEST(Fit, RunsCutShortAndRareInstructionsTellADerivedProcessor) {
  constexpr std::pair<std::string_view, std::uint32_t> kMnemonics[] = {
      {"addiu", 3000}, {"beq", 1000}, {"jal", 1000}, {"lui", 1000}, {"lw", 3000}, {"sw", 1000}, {"syscall", 2}};
  const Profile real{"MIPS", 32, "", 10002, kMnemonics};
  EXPECT_EQ(real.count("lw"), 3000u);
  EXPECT_EQ(real.count("cache"), 0u);
  Features code, noise;
  code.reached = 5000, code.reached_invalid = 3;
  code.reached_forms = {{{"lw", 4}, 2000}, {{"addiu", 4}, 1500}, {{"jal", 4}, 1000}, {{"syscall", 4}, 100}, {{"lwc2", 4}, 50}};
  noise.reached = 300, noise.reached_invalid = 90;
  noise.reached_forms = {{{"lw", 4}, 100}, {{"cache", 4}, 100}, {{"lwc2", 4}, 100}};
  const Fit ok = fit(code, noise, &real);
  EXPECT_TRUE(ok.profiled);
  EXPECT_EQ(ok.rare, 150u);  // syscall: 2 in 10002 is rare; lwc2: none
  EXPECT_NEAR(ok.noise_rare_share(), 2.0 / 3, 1e-9);
  EXPECT_FALSE(ok.near_miss());

  // Many instructions real MIPS code rarely has: a near miss.
  Features derived = code;
  derived.reached_forms[{"lwc2", 4}] = 1500;
  derived.reached_forms[{"cache", 4}] = 600;
  EXPECT_TRUE(fit(derived, noise, &real).unusual());
  // Runs of reached code cut short by bytes that don't decode: a near
  // miss too, profile or not.
  Features cut = code;
  cut.reached_invalid = 200;
  EXPECT_TRUE(fit(cut, noise, nullptr).cut_short());
  EXPECT_FALSE(fit(derived, noise, nullptr).near_miss());  // no profile: only the cut runs count

  // The generated profiles cover the kit's processors, not others.
  EXPECT_NE(profile("MIPS", 32, ""), nullptr);
  EXPECT_NE(profile("ARM", 32, "thumb"), nullptr);
  EXPECT_EQ(profile("ARM", 32, ""), nullptr);
  EXPECT_EQ(profile("M16C/60", 16, ""), nullptr);
}

// Thumb-2 from the instructions control flow reaches, against chance.
TEST(Variant, ThumbTwoFromItsInstructions) {
  Features thumb, thumb2, noise;
  thumb.reached_forms = {{{"ldr", 2}, 3000}, {{"bl", 4}, 400}, {{"push", 2}, 300}, {{"ldr.w", 4}, 2}};
  thumb2.reached_forms = {{{"ldr", 2}, 2000}, {{"bl", 4}, 400}, {{"ldr.w", 4}, 600}, {{"ite", 2}, 40}, {{"cbz", 2}, 60}};
  noise.reached_forms = {{{"ldr", 2}, 900}, {{"mcr2", 4}, 60}, {{"cbnz", 2}, 20}, {{"itt", 2}, 5}, {{"bl", 4}, 15}};
  const Thumb2 n = thumb2_census(noise);
  EXPECT_EQ(n.used(), 85u);
  const Thumb2 t2 = thumb2_census(thumb2);
  EXPECT_EQ(t2.wide, 600u);
  EXPECT_EQ(t2.it, 40u);
  EXPECT_EQ(t2.cbz, 60u);
  EXPECT_TRUE(uses_thumb2(t2, n));
  EXPECT_FALSE(uses_thumb2(thumb2_census(thumb), n));
}

// Region inference (regions.cc) on traces made up here: what the code
// says about memory outside the image, without decoding anything.
Trace::Access access(std::uint64_t address, std::uint64_t at, bool write, std::optional<std::uint64_t> value = {},
                     std::uint32_t size = 4, std::uint64_t base = 0) {
  return {address, at, size, write, value, base == 0 ? address : base};
}

const RegionSuggestion *find_region(const Regions &r, RegionSuggestion::Kind kind) {
  for (const RegionSuggestion &g : r.regions)
    if (g.kind == kind) return &g;
  return nullptr;
}

TEST(Regions, APolledDeviceWrittenWithConstants) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  // A 68k image at 0 (no architectural map): a device at 0xf00000 whose
  // status register is polled and whose control registers are set, from
  // several functions.
  const std::vector<std::byte> file = fill(64 << 10, 0x4e);
  Trace t;
  for (std::uint64_t f = 0x1000; f < 0x6000; f += 0x1000) {
    t.memory.push_back(access(0xf00004, f + 4, false));  // in the loop below
    t.back_jumps.emplace_back(f, f + 12);
    t.memory.push_back(access(0xf00000, f + 0x20, true, 0x41));
    t.memory.push_back(access(0xf00008, f + 0x24, true, 0x3));
  }
  const Regions r = regions(file, t, 0, 0, "68000:BE:32:default");
  ASSERT_EQ(r.regions.size(), 1u);
  const RegionSuggestion &g = r.regions[0];
  EXPECT_EQ(g.kind, RegionSuggestion::Kind::mmio);
  EXPECT_EQ(g.spec, "mmio:f00000:1000:rw-:volatile");
  EXPECT_EQ(g.confidence, Confidence::high);
  const std::string why = ::testing::PrintToString(g.evidence);
  EXPECT_NE(why.find("polling"), std::string::npos) << why;
  EXPECT_NE(why.find("stores write constants"), std::string::npos) << why;
  EXPECT_NE(why.find("rounded out to pages of 4 KiB"), std::string::npos) << why;
}

TEST(Regions, NothingFromAFewStrayAccesses) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::vector<std::byte> file = fill(64 << 10, 0);
  Trace t;
  // Bytes that aren't code name addresses from one stretch of the file;
  // small numbers are offsets, not addresses.
  for (std::uint64_t k = 0; k < 6; ++k) t.memory.push_back(access(0x61626364 + 4 * k, 0x2000 + 2 * k, k % 2 != 0));
  for (std::uint64_t k = 0; k < 6; ++k) t.memory.push_back(access(0x200 + 4 * k, 0x1000 * k, true, 1));
  const Regions r = regions(file, t, 0x08000000, 0, "ARM:LE:32:v8");
  EXPECT_TRUE(r.regions.empty());
  ASSERT_FALSE(r.evidence.empty());
  EXPECT_EQ(r.evidence.back().about, "regions");
}

// ARM instruction words read as literals (mov r0, #0 is 0xe3a00000) are
// no device: the same polled, written device made only from such words,
// read from code that control flow runs through, makes no region.
TEST(Regions, NothingFromInstructionsReadAsWords) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::vector<std::byte> file = fill(64 << 10, 0x4e);
  Trace t;
  for (std::uint64_t f = 0x1000; f < 0x6000; f += 0x1000) {
    t.memory.push_back(access(0xe3a00004, f + 4, false, {}, 4, 0xe3a00000));
    t.back_jumps.emplace_back(f, f + 12);
    t.memory.push_back(access(0xe3a00000, f + 0x20, true, 0x41));
    t.memory.push_back(access(0xe3a00008, f + 0x24, true, 0x3, 4, 0xe3a00000));
  }
  EXPECT_FALSE(regions(file, t, 0x10000, 0, "ARM:LE:32:v7").regions.empty());
  t.code_words = {0xe3a00000};
  const Regions r = regions(file, t, 0x10000, 0, "ARM:LE:32:v7");
  EXPECT_TRUE(r.regions.empty());
  EXPECT_TRUE(std::any_of(r.evidence.begin(), r.evidence.end(), [](const Evidence &e) {
    return e.text.find("instructions of the code read as words") != std::string::npos;
  })) << ::testing::PrintToString(r.evidence.size());
}

// Which words the trace reads as literals are instructions: those in code
// a branch lands in and runs through, not those in a pool past a return.
TEST(Trace, LiteralsFromCodeAreInstructions) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  std::vector<std::byte> file;
  auto put32 = [&](std::uint32_t v) {
    for (int k = 0; k < 4; ++k) file.push_back(static_cast<std::byte>(v >> (8 * k)));
  };
  auto at = [&] { return static_cast<std::uint32_t>(file.size()); };
  put32(0xea00003e);                        // 0x000: b 0x100
  while (at() < 0x100) put32(0xe1a00000);   // nop
  for (int i = 0; i < 8; ++i) put32(0xe3a00000);  // 0x100: mov r0, #0: code a branch lands in
  put32(0xe12fff1e);                        // bx lr
  while (at() < 0x200) put32(0xe1a00000);
  put32(0xe51f1108);                        // 0x200: ldr r1, [pc, #-0x108]: reads 0x100, an instruction
  put32(0xe5912000);                        // ldr r2, [r1]
  put32(0xe59f3004);                        // ldr r3, [pc, #4]: reads 0x214, a pool
  put32(0xe5932000);                        // ldr r2, [r3]
  put32(0xe12fff1e);                        // bx lr
  put32(0x40001000);                        // 0x214: the pool's word
  while (at() < 0x400) put32(0xe1a00000);
  Candidate c;
  c.language = "ARM:LE:32:v7";
  Sweeper sweeper(c);
  ASSERT_TRUE(sweeper.ok());
  const Trace t = sweeper.trace(file, {{0, file.size()}});
  EXPECT_EQ(t.code_words, std::vector<std::uint64_t>{0xe3a00000});
  EXPECT_TRUE(std::any_of(t.memory.begin(), t.memory.end(), [](const Trace::Access &a) { return a.address == 0x40001000; }));
}

// A small processor's code with its base unknown: accesses scattered over
// the 64 KiB space are no device spanning it (they had made
// mmio:0:10000), and nothing may cover 0, where an import without a base
// puts the image. A device block of a few registers is still one, in pages
// sized for the space.
TEST(Regions, SmallSpacesScatteredAccessesAndTheImageAtZero) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::vector<std::byte> file = fill(6730, 0xea);
  Trace t;
  for (std::uint64_t k = 0; k < 16; ++k) {
    const std::uint64_t a = 0x100 + k * 0xf00 + (k * 37 % 0x40);
    for (std::uint64_t f = 0; f < 5; ++f) t.memory.push_back(access(a, 0x100 * f + 0x10 * k, f % 2 == 1, 0x10, 1));
    t.back_jumps.emplace_back(0x10 * k, 0x10 * k + 8);
  }
  const Regions scattered = regions(file, t, std::nullopt, 0, "6502:LE:16:default");
  for (const RegionSuggestion &g : scattered.regions) {
    EXPECT_LE(g.size, 0x4000u) << g.spec;
    EXPECT_GE(g.start, 6730u) << g.spec;
  }
  // A device: registers at 0xd000-0xd00f, polled and set, from several places.
  Trace d;
  for (std::uint64_t f = 0x200; f < 0x1400; f += 0x200) {
    d.memory.push_back(access(0xd004, f + 4, false, {}, 1));
    d.back_jumps.emplace_back(f, f + 8);
    d.memory.push_back(access(0xd000, f + 0x20, true, 0x41, 1));
    d.memory.push_back(access(0xd00f, f + 0x24, true, 0x3, 1));
  }
  const Regions r = regions(file, d, std::nullopt, 0, "6502:LE:16:default");
  ASSERT_EQ(r.regions.size(), 1u);
  EXPECT_EQ(r.regions[0].spec, "mmio:d000:100:rw-:volatile");
  const std::string why = ::testing::PrintToString(r.regions[0].evidence);
  EXPECT_NE(why.find("rounded out to pages of 256 bytes"), std::string::npos) << why;
  EXPECT_NE(why.find("medium: where the image loads is unknown"), std::string::npos) << why;
}

TEST(Regions, TheStackAloneIsTheTopOfRam) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  // MIPS startup code setting the stack (la sp, 0x80400000), and nothing
  // else: RAM below it, at medium confidence.
  const std::vector<std::byte> file = fill(64 << 10, 0);
  Trace t;
  t.stack_values = {{0x80400000, 0x40}, {0x803fffe0, 0x48}};
  const Regions r = regions(file, t, 0xbfc00000, 0, "MIPS:BE:32:default");
  ASSERT_EQ(r.regions.size(), 1u);
  EXPECT_EQ(r.regions[0].spec, "ram:803f0000:10000");
  EXPECT_EQ(r.regions[0].confidence, Confidence::medium);
  // Constants put in the stack pointer far from the image's ends are
  // something else.
  t.stack_values = {{0x80400000, 0x80000}};
  const std::vector<std::byte> big = fill(1 << 20, 0);
  EXPECT_TRUE(regions(big, t, 0xbfc00000, 0, "MIPS:BE:32:default").regions.empty());
}

TEST(Regions, TheImageThroughItsOtherWindowIsNoRegion) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  // A MIPS image at 0xbfc00000 (kseg1) reading itself through kseg0.
  const std::vector<std::byte> file = fill(64 << 10, 0);
  Trace t;
  for (std::uint64_t k = 0; k < 8; ++k) t.memory.push_back(access(0x9fc01000 + 16 * k, 0x400 * k, false));
  const Regions r = regions(file, t, 0xbfc00000, 0, "MIPS:BE:32:default");
  EXPECT_TRUE(r.regions.empty());
  ASSERT_FALSE(r.evidence.empty());
  EXPECT_NE(r.evidence.front().text.find("the image itself"), std::string::npos) << r.evidence.front().text;
}

TEST(Regions, RamEndsAtTheStackAndTheWindow) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  // ESP32-like: variables from 0x3ffb0000, the stack at 0x40000000 where
  // the data bus ends. 320 KiB isn't a size RAM comes in, but the window
  // ends there.
  const std::vector<std::byte> file = fill(64 << 10, 0);
  Trace t;
  for (std::uint64_t k = 0; k < 60; ++k)
    t.memory.push_back(access(0x3ffb0000 + 8 * k, 0x100 * k, k % 3 == 0, std::nullopt, k % 5 == 0 ? 1 : 4));
  t.stack_values = {{0x40000000, 0x20}};
  const Regions r = regions(file, t, 0x400d0000, 0, "Xtensa:LE:32:default");
  const RegionSuggestion *ram = find_region(r, RegionSuggestion::Kind::ram);
  ASSERT_NE(ram, nullptr);
  EXPECT_EQ(ram->spec, "ram:3ffb0000:50000");
  EXPECT_EQ(ram->confidence, Confidence::high);  // the stack and many variables
  const std::string why = ::testing::PrintToString(ram->evidence);
  EXPECT_NE(why.find("the initial stack pointer is 0x40000000"), std::string::npos) << why;
  EXPECT_NE(why.find("up to the end of the window at 0x40000000"), std::string::npos) << why;
}

TEST(Regions, SmallProcessorsDeclareTheirRegisters) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const Regions r = regions(fill(4096, 0), Trace{}, 0, 0, "avr8:LE:16:default");
  ASSERT_FALSE(r.evidence.empty());
  EXPECT_NE(r.evidence.front().text.find("mem:0x20-0x57"), std::string::npos) << r.evidence.front().text;
}

// A small Thumb assembler for the generated Cortex-M image below:
// halfwords, labels, and literal loads resolved at the end.
struct Thumb {
  std::vector<std::byte> &image;
  std::size_t at;
  std::map<std::string, std::size_t> labels;
  std::vector<std::pair<std::size_t, std::string>> branches;      // (place, label)
  std::vector<std::pair<std::size_t, std::uint32_t>> literals;  // (ldr's place, value)

  void half(std::uint16_t h) {
    image[at] = static_cast<std::byte>(h & 0xff);
    image[at + 1] = static_cast<std::byte>(h >> 8);
    at += 2;
  }
  void label(const std::string &name) { labels[name] = at; }
  void ldr_literal(int rd, std::uint32_t value) { literals.emplace_back(at, value), half(static_cast<std::uint16_t>(0x4800 | rd << 8)); }
  void branch(std::uint16_t op, const std::string &to) { branches.emplace_back(at, to), half(op); }  // 0xd000|cond<<8, or 0xe000
  void ldr(int rt, int rn, int off) { half(static_cast<std::uint16_t>(0x6800 | (off / 4) << 6 | rn << 3 | rt)); }
  void str(int rt, int rn, int off) { half(static_cast<std::uint16_t>(0x6000 | (off / 4) << 6 | rn << 3 | rt)); }
  void strb(int rt, int rn, int off) { half(static_cast<std::uint16_t>(0x7000 | off << 6 | rn << 3 | rt)); }
  void movs(int rd, int imm) { half(static_cast<std::uint16_t>(0x2000 | rd << 8 | imm)); }
  // The literal pool, after the code; branches resolved.
  void finish() {
    if (at % 4) half(0x46c0);  // nop
    for (const auto &[place, value] : literals) {
      const std::size_t pool = at;
      for (int k = 0; k < 4; ++k) image[at++] = static_cast<std::byte>(value >> (8 * k));
      image[place] = static_cast<std::byte>(static_cast<std::uint8_t>(image[place]) | ((pool - ((place + 4) & ~std::size_t{3})) / 4));
    }
    for (const auto &[place, name] : branches) {
      const std::ptrdiff_t d = (static_cast<std::ptrdiff_t>(labels.at(name)) - static_cast<std::ptrdiff_t>(place + 4)) / 2;
      const bool conditional = (static_cast<std::uint8_t>(image[place + 1]) & 0xf0) == 0xd0;
      const std::uint16_t bits = conditional ? (d & 0xff) : (d & 0x7ff);
      image[place] = static_cast<std::byte>(bits & 0xff);
      image[place + 1] = static_cast<std::byte>(static_cast<std::uint8_t>(image[place + 1]) | (bits >> 8));
    }
    literals.clear(), branches.clear();
  }
};

// A Cortex-M image: a vector table, a reset handler copying its initial
// data from the image's end to RAM and clearing what follows, a UART
// driver polling its status register, and functions using variables.
std::vector<std::byte> cortex_m_image(std::uint32_t base) {
  std::vector<std::byte> image(0x1000, std::byte{0});
  auto word = [&](std::size_t at, std::uint32_t v) {
    for (int k = 0; k < 4; ++k) image[at + k] = static_cast<std::byte>(v >> (8 * k));
  };
  word(0, 0x20008000);  // the initial stack
  for (std::size_t v = 4; v < 0x40; v += 4) word(v, base + 0x41);
  for (std::size_t k = 0xff0; k < 0x1000; ++k) image[k] = std::byte{0x11};  // the initial data
  constexpr std::uint16_t kB = 0xe000, kBcs = 0xd200, kBeq = 0xd000, kBxLr = 0x4770;
  Thumb a{image, 0x40, {}, {}, {}};
  a.ldr_literal(0, base + 0xff0);  // __data_load
  a.ldr_literal(1, 0x20000000);    // __data_start
  a.ldr_literal(2, 0x20000010);    // __data_end
  a.label("copy");
  a.half(0x4291);  // cmp r1, r2
  a.branch(kBcs, "copied");
  a.half(0xc808);  // ldmia r0!, {r3}
  a.half(0xc108);  // stmia r1!, {r3}
  a.branch(kB, "copy");
  a.label("copied");
  a.ldr_literal(1, 0x20000010);  // __bss_start
  a.ldr_literal(2, 0x20000100);  // __bss_end
  a.movs(3, 0);
  a.label("clear");
  a.half(0x4291);
  a.branch(kBcs, "cleared");
  a.half(0xc108);
  a.branch(kB, "clear");
  a.label("cleared");
  a.branch(kB, "cleared");
  a.finish();
  // The UART at 0x40013800: putc polls its status.
  a.at = 0x100;
  a.ldr_literal(4, 0x40013800);
  a.label("poll");
  a.ldr(0, 4, 0x1c);
  a.movs(1, 0x80);
  a.half(0x4208);  // tst r0, r1
  a.branch(kBeq, "poll");
  a.movs(0, 0x41);
  a.str(0, 4, 0x28);
  a.half(kBxLr);
  a.finish();
  a.at = 0x200;  // its set-up
  a.ldr_literal(4, 0x40013800);
  for (int reg : {0x0c, 0x08, 0x10, 0x14, 0x18, 0x0c, 0x20, 0x24}) a.movs(0, reg * 2 + 1), a.str(0, 4, reg);
  a.half(kBxLr);
  a.finish();
  a.at = 0x500;  // getc
  a.ldr_literal(4, 0x40013800);
  a.ldr(0, 4, 0x1c);
  a.ldr(0, 4, 0x24);
  a.half(kBxLr);
  a.finish();
  // Variables.
  a.at = 0x300;
  a.ldr_literal(5, 0x20000000);
  a.ldr(6, 5, 0);
  a.half(0x3601);  // adds r6, #1
  a.str(6, 5, 0);
  a.ldr(6, 5, 4);
  a.str(6, 5, 8);
  a.strb(6, 5, 12);
  a.half(kBxLr);
  a.finish();
  a.at = 0x400;
  a.ldr_literal(5, 0x20000040);
  a.ldr(6, 5, 0);
  a.str(6, 5, 4);
  a.half(kBxLr);
  a.finish();
  return image;
}

TEST(Regions, ACortexMImageWithAStartupCopyAndAPolledUart) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  constexpr std::uint32_t kBase = 0x08000000;
  const std::vector<std::byte> image = cortex_m_image(kBase);
  Candidate thumb;
  thumb.language = "ARM:LE:32:v8";
  thumb.mode = "thumb";
  thumb.context = {{"TMode", 1}};
  Sweeper sweeper(thumb);
  ASSERT_TRUE(sweeper.ok());
  const Trace t = sweeper.trace(image, {{0, image.size()}});
  const Regions r = regions(image, t, kBase, 0, thumb.language);

  const RegionSuggestion *ram = find_region(r, RegionSuggestion::Kind::ram);
  ASSERT_NE(ram, nullptr) << ::testing::PrintToString(r.evidence);
  EXPECT_EQ(ram->spec, "ram:20000000:8000");  // from the copy's destination to the stack's top
  EXPECT_EQ(ram->confidence, Confidence::high);
  const std::string ram_why = ::testing::PrintToString(ram->evidence);
  EXPECT_NE(ram_why.find("vector table"), std::string::npos) << ram_why;
  EXPECT_NE(ram_why.find("code copies 16 bytes from the image (0x8000ff0) to 0x20000000"), std::string::npos) << ram_why;
  EXPECT_NE(ram_why.find("code clears 0x20000010-0x200000ff"), std::string::npos) << ram_why;

  const RegionSuggestion *mmio = find_region(r, RegionSuggestion::Kind::mmio);
  ASSERT_NE(mmio, nullptr);
  EXPECT_EQ(mmio->spec, "mmio:40013000:1000:rw-:volatile");
  EXPECT_EQ(mmio->confidence, Confidence::high);
  const std::string mmio_why = ::testing::PrintToString(mmio->evidence);
  EXPECT_NE(mmio_why.find("polling"), std::string::npos) << mmio_why;
  EXPECT_NE(mmio_why.find("reached from 1 base address"), std::string::npos) << mmio_why;
  EXPECT_NE(mmio_why.find("peripheral window"), std::string::npos) << mmio_why;
  EXPECT_EQ(r.regions.size(), 2u) << ::testing::PrintToString(r.regions.size());
}

TEST(Candidates, OnePerProcessorByteOrderAndSizeWithArmInBothModes) {
  lift::initialize(REVKIT_GHIDRA_ROOT);
  const std::vector<Candidate> all = candidates();
  auto has = [&](std::string_view label) {
    return std::any_of(all.begin(), all.end(), [&](const Candidate &c) { return c.label() == label; });
  };
  EXPECT_TRUE(has("ARM:LE:32:v8"));
  EXPECT_TRUE(has("ARM:LE:32:v8 (thumb)"));
  EXPECT_TRUE(has("ARM:BE:32:v8 (thumb)"));
  EXPECT_TRUE(has("x86:LE:64:default"));
  EXPECT_TRUE(has("MIPS:BE:32:default"));
  for (const Candidate &c : all) {
    EXPECT_EQ(c.language.find("Dalvik"), std::string::npos);
    EXPECT_NE(std::find(c.languages.begin(), c.languages.end(), c.language), c.languages.end());
  }
}

}  // namespace
}  // namespace revkit::detect
