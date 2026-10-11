// Auto-detection for a binary with no header that says what it is (raw
// firmware, a dump): which language decodes it, where it loads, and where
// in the file the image starts. docs/autodetect.md has the design and the
// measurements behind it.
//
// Everything here works on the file's bytes alone: no program exists yet.
// lift::initialize() must have been called.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace revkit::detect {

enum class Confidence : std::uint8_t { low, medium, high };
std::string_view name(Confidence c);

// What a stretch of the file looks like, before any language is tried.
struct Segment {
  enum class Kind : std::uint8_t {
    padding,       // one byte value repeated (erased flash, alignment)
    high_entropy,  // compressed or encrypted
    text,
    code,          // could be code (or binary data: only a decoder can tell)
  };
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
  Kind kind = Kind::code;

  friend bool operator==(const Segment &, const Segment &) = default;
};
std::string_view name(Segment::Kind k);

// The file as segments, in order, covering it exactly.
std::vector<Segment> segments(std::span<const std::byte> file);

// One way of decoding: the language that stands for the languages sharing
// its processor, byte order and address size, in one decoding mode.
struct Candidate {
  std::string language;  // "ARM:LE:32:v8", without the compiler
  std::string mode;      // "" or the mode's name ("thumb")
  std::vector<std::pair<std::string, std::uint32_t>> context;  // the mode's context variables
  std::vector<std::string> languages;  // every language of the group, `language` among them

  std::string label() const { return mode.empty() ? language : language + " (" + mode + ")"; }
};

// Every candidate the install's languages give, in a fixed order. Languages
// that aren't machine code (bytecode, the data-only language) are left out.
std::vector<Candidate> candidates();

// What a linear sweep of sampled windows under one candidate found. Counts
// are over all the windows.
struct Features {
  std::uint64_t bytes = 0;         // bytes swept
  std::uint64_t valid_bytes = 0;   // of them, in decoded instructions
  std::uint64_t instructions = 0;
  std::uint64_t invalid = 0;       // places nothing decoded
  std::uint64_t unimplemented = 0; // decoded, but the language has no semantics for it
  std::uint64_t callother = 0;     // instructions with a user-defined operation
  std::uint64_t rare = 0;          // instructions doing what code seldom does (floating point, division)
  std::uint64_t branches = 0;      // relative jumps, conditional or not
  std::uint64_t branch_near = 0;   // of them, to within the same window
  std::uint64_t branch_start = 0;  // of those, to the start of a swept instruction
  std::uint64_t calls = 0;         // relative calls
  std::uint64_t call_in_file = 0;  // of them, to an offset inside the file
  std::uint64_t call_shared = 0;   // of the calls, to a target another call of the sample has too
  std::uint64_t absolute = 0;      // jumps and calls to a fixed address
  std::uint64_t absolute_swept = 0;  // their distinct targets inside a swept window, were the file loaded at 0
  std::uint64_t absolute_start = 0;  // of those, the start of a swept instruction
  // What absolute jumps say whatever the base: a jump goes near itself, so
  // two absolute jumps in a row, in code, lie about as far from their
  // targets (target - place is base - offset wherever the image loads,
  // give or take a function's size); by chance they agree as often as
  // random addresses do.
  std::uint64_t abs_pairs = 0;        // consecutive absolute jumps in a window
  std::uint64_t abs_pairs_near = 0;   // of them, whose target - place agree within kNear
  std::uint64_t fill_bytes = 0;       // bytes skipped as fill (runs of one value), not swept
  std::uint64_t returns = 0;
  std::uint64_t return_then_start = 0;  // returns followed by fill or by a jump or call target
  std::uint64_t indirect = 0;      // computed jumps and calls
  std::uint64_t sp_reads = 0;      // instructions reading the stack pointer
  std::uint64_t sp_writes = 0;     // instructions writing it
  // Code that control flow vouches for: the instructions where a relative
  // branch or call lands on an instruction start, and those after it up to
  // the next transfer (at most kReach). Data between functions is seldom
  // reached, so this is the code itself, without the tables and pools a
  // linear sweep also decodes.
  std::uint64_t reached = 0;
  std::uint64_t reached_odd = 0;      // of them, unimplemented, user-defined operations, floating point, division
  std::uint64_t reached_invalid = 0;  // reached runs cut short by bytes that don't decode
  // How often each instruction form (mnemonic, length in bytes without
  // delay slots) was decoded, over everything swept and over what was
  // reached. Only from a sweep that asks for them.
  std::map<std::pair<std::string, std::uint32_t>, std::uint32_t> forms, reached_forms;
  double seconds = 0;              // building the decoder and sweeping

  friend bool operator==(const Features &, const Features &) = default;
};

// The windows a sweep samples: at most `count` of `size` bytes, spread
// evenly over the file's code-like segments. (offset, size) pairs.
std::vector<std::pair<std::uint64_t, std::uint64_t>> sample_windows(std::span<const std::byte> file,
                                                                    const std::vector<Segment> &segments,
                                                                    std::size_t count = 16, std::uint64_t size = 4096);

// What the code says about addresses, from a linear decode with constants
// followed through straight-line code (an address built in two
// instructions, a word loaded from a literal pool). Addresses are absolute:
// what the program uses when it runs where it was linked. Offsets are
// places in the file. Each list is sorted and without duplicates.
struct Trace {
  std::vector<std::uint64_t> pointers;       // addresses the code builds or loads, of pointer size
  std::vector<std::uint64_t> jump_targets;   // absolute jumps' and calls' targets
  // Targets of jumps that hold only the low `region_bits` bits (MIPS j and
  // jal: the rest is the jump's own address): those bits.
  std::vector<std::uint64_t> region_targets;
  unsigned region_bits = 0;
  std::vector<std::uint64_t> accesses;       // addresses read or written directly
  std::vector<std::uint64_t> function_offsets;  // relative calls' targets, and what follows a return or a tail call
  // base - offset as code that relocates itself says it: an address made
  // from the program counter (a file offset here) compared with, or
  // subtracted from, a constant (where it was linked). One per instruction,
  // in file order.
  std::vector<std::uint64_t> anchors;
  // Words read as literals from inside code control flow runs through:
  // instructions, read by an instruction of data decoded as a load from
  // the program counter. No addresses (regions.cc). Sorted.
  std::vector<std::uint64_t> code_words;
  std::uint64_t instructions = 0;

  // What the memory regions beyond the image are inferred from
  // (regions.cc). In file order, duplicates kept.
  struct Access {
    std::uint64_t address = 0;  // absolute
    std::uint64_t at = 0;       // the instruction's file offset
    std::uint32_t size = 0;     // bytes
    bool write = false;
    std::optional<std::uint64_t> value;  // a store's value, where it is a known constant
    // The constant the address was made from by adding a small offset (a
    // device's base, a structure's): the address itself where there was none.
    std::uint64_t base = 0;
  };
  std::vector<Access> memory;  // loads and stores at addresses the code names
  // Constants the code puts in the stack pointer (startup code setting a
  // stack): (value, the instruction's file offset), in file order.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> stack_values;
  // Relative jumps back a short way (a loop): (target, jump) file offsets.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> back_jumps;
  // What registers hold where control leaves straight-line code (a call,
  // a jump): constants of pointer size, as a loop or a call is set up
  // (copy and clear loops: source, destination, end or length).
  struct Setup {
    std::uint64_t at = 0;  // the transfer's file offset
    bool call = false;
    std::vector<std::uint64_t> values;  // sorted, without duplicates
  };
  std::vector<Setup> setups;  // those with two or more values, one of them 0x100 or more
};

// A decoder for one candidate, kept across sweeps (building it costs more
// than sweeping with it).
class Sweeper {
 public:
  explicit Sweeper(const Candidate &candidate);
  ~Sweeper();
  Sweeper(const Sweeper &) = delete;
  Sweeper &operator=(const Sweeper &) = delete;

  // False if the language couldn't be built (a broken spec): sweeps find
  // nothing.
  bool ok() const { return impl_ != nullptr; }
  double build_seconds() const { return seconds_; }
  // Where instructions may start, in bytes (1 where any byte may).
  unsigned alignment() const;

  // Decodes the windows of `file` linearly and counts; with `forms`, also
  // which instruction forms (Features::forms, reached_forms), which costs a
  // little more. `image_size`: the size of the file the windows stand for,
  // where `file` is not it (shuffled windows stand for the whole file:
  // whether absolute targets can be file offsets depends on its size).
  Features sweep(std::span<const std::byte> file, const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows,
                 bool forms = false, std::uint64_t image_size = 0);

  // Decodes the windows linearly and collects what tells where the image
  // loads: the addresses its code names, and the places in the file such
  // addresses would point to.
  Trace trace(std::span<const std::byte> file, const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  double seconds_ = 0;
};

// The evidence that a sweep is of code, in nats per instruction: the log
// likelihood ratio of what its control flow does, between code and what
// the candidate makes of the same bytes shuffled (`noise`). Each kind of
// event counts by how unlikely it is by chance: a branch landing nearby
// says nothing where every branch is short, and everything where a branch
// can go megabytes away.
struct Quality {
  double branches = 0;   // relative jumps landing nearby, on an instruction
  double calls = 0;      // relative calls sharing targets
  double returns = 0;    // returns followed by a function
  double absolute = 0;   // absolute jumps and calls landing on instructions, were the file loaded at 0
  double jumps = 0;      // absolute jumps going about as far as the one before (Features::abs_pairs)
  double plain = 1;      // 0 to 1: less for what code seldom does (unknown instructions, floating point)
  // Evidence against (a kind's rate below chance) doesn't cancel evidence
  // for: kinds an instruction set lacks would be held against it.
  double total() const {
    auto up = [](double v) { return v > 0 ? v : 0; };
    return plain * (up(branches) + up(calls) + up(returns) + up(absolute) + up(jumps));
  }
  // How many kinds speak for it, and the most any one says.
  int kinds() const {
    return (branches > 0.005) + (calls > 0.005) + (returns > 0.005) + (absolute > 0.005) + (jumps > 0.005);
  }
  double strongest() const { return plain * std::max({branches, calls, returns, absolute, jumps, 0.0}); }
};
Quality quality(const Features &f, const Features &noise);

// How often real code of one instruction set uses each mnemonic: what the
// code that control flow reaches decodes to (Features::reached_forms) in
// the kit's images and the corpus's programs, generated into profiles.inc
// by scripts/detect_profiles.py.
struct Profile {
  std::string_view processor;  // "MIPS", a language id's first field
  int bits = 0;                // its address size
  std::string_view mode;       // "" or the decoding mode ("thumb")
  std::uint64_t total = 0;     // instructions counted
  std::span<const std::pair<std::string_view, std::uint32_t>> mnemonics;  // sorted by mnemonic
  std::uint32_t count(std::string_view mnemonic) const;
};
// The profile of a processor at an address size in a mode; nullptr if there
// is no real code of it to have measured.
const Profile *profile(std::string_view processor, int bits, std::string_view mode);

// Whether a language's whole instruction set fits the code, beyond its
// decoding and its branches landing: of the code control flow reaches
// (Features::reached), how often a run of it ends in bytes the language
// can't decode, and how much of it uses mnemonics real code of the
// language rarely has (under one in kRare of its instructions in the
// profile). Code of a processor derived from the language's (another
// vendor's variant, a successor with a reworked encoding) shares the
// branches and much else, but not that.
struct Fit {
  static constexpr double kRare = 1e-3;
  std::uint64_t reached = 0;   // instructions control flow reaches
  std::uint64_t cut = 0;       // runs of them ending in bytes that don't decode
  bool profiled = false;       // there is a profile to compare with
  std::uint64_t counted = 0;   // reached instructions with a mnemonic (a census sweep)
  std::uint64_t rare = 0;      // of them, rare in the profile
  std::uint64_t noise_counted = 0, noise_rare = 0;  // the same of the shuffled bytes
  double cut_share() const { return reached == 0 ? 0 : static_cast<double>(cut) / static_cast<double>(reached); }
  double rare_share() const { return counted == 0 ? 0 : static_cast<double>(rare) / static_cast<double>(counted); }
  double noise_rare_share() const {
    return noise_counted == 0 ? 0 : static_cast<double>(noise_rare) / static_cast<double>(noise_counted);
  }
  // Thresholds from the kit, the corpus and derived processors made from
  // the kit's (docs/autodetect.md): real code reaches undecodable bytes in
  // at most 0.6% of its runs and has at most 10% rare mnemonics, wherever
  // it was compiled; derived processors' code 0.7-28% and 24-66%.
  static constexpr double kCut = 0.02, kRareShare = 0.2;
  bool cut_short() const { return cut >= 10 && cut_share() >= kCut; }
  bool unusual() const { return profiled && rare >= 20 && rare_share() >= kRareShare; }
  bool near_miss() const { return cut_short() || unusual(); }
};
// `code` and `noise` from sweeps with forms, for the share of rare
// mnemonics (else only the cut runs count); `profile` may be nullptr.
Fit fit(const Features &code, const Features &noise, const Profile *profile);

// One candidate's result: its sweep, and the same sweep over the windows'
// bytes shuffled, which is what the candidate makes of bytes that are no
// code at all: how often its branches land nearby and on an instruction by
// chance (always, for an instruction set with short branches and
// instructions at every other byte).
struct Sweep {
  Candidate candidate;
  Features features;
  Features noise;
  // The same windows a byte or a halfword along (half the candidate's
  // alignment), for a candidate whose instructions are aligned: what it
  // makes of the same bytes, with all their structure, off its alignment.
  // Its own code there is no code; another processor's byte-oriented code
  // and data are what they were. Empty where instructions may start
  // anywhere.
  Features shifted;
  // Of `features` against `noise`, less what `shifted` shows against it
  // (kind by kind): evidence that the bytes are structured, not that they
  // are this candidate's code, a permissive instruction set (one that
  // makes calls and jumps of a quarter of all words) finds in anything.
  Quality quality;
  double score() const { return quality.total(); }
};

struct Evidence {
  std::string about;  // "processor", "variant", "base", "offset", "regions"
  std::string text;
};

// The variant of a processor the code needs (variants.cc).
struct Variant {
  std::string language;                 // without the compiler
  std::vector<std::string> sufficient;  // larger variants that decode it as fully
  Confidence confidence = Confidence::low;
  std::vector<Evidence> evidence;
};
// Of `pool` (languages of `chosen`'s processor), the least capable that
// decodes the windows as fully as any, in `chosen`'s mode. M-profile ARM
// variants are tried only for Thumb code that starts with a Cortex-M vector
// table (`cortex_vectors`).
Variant choose_variant(const Candidate &chosen, const std::vector<std::string> &pool, std::span<const std::byte> file,
                       const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows,
                       std::span<const std::byte> noise,
                       const std::vector<std::pair<std::uint64_t, std::uint64_t>> &noise_windows, bool cortex_vectors,
                       unsigned threads);
// The Thumb-2 instructions among the code control flow reaches in a sweep
// in Thumb mode with forms (Features::reached_forms): 32-bit instructions
// other than bl and blx (which Thumb has had since ARMv4T, as two halves),
// and the 16-bit IT and cbz/cbnz, which came with Thumb-2 (ARMv6T2).
struct Thumb2 {
  std::uint64_t reached = 0;  // instructions counted
  std::uint64_t wide = 0, it = 0, cbz = 0;
  std::uint64_t used() const { return wide + it + cbz; }
  double share() const { return reached == 0 ? 0 : static_cast<double>(used()) / static_cast<double>(reached); }
};
Thumb2 thumb2_census(const Features &f);
// Whether code uses Thumb-2: its reached code has Thumb-2 instructions at
// least half as often as the same bytes shuffled do (Thumb-2 code: 2-3
// times as often; Thumb code: almost never, only where a branch of data
// lands in data).
bool uses_thumb2(const Thumb2 &code, const Thumb2 &noise);

// Whether the image at `offset` starts with a Cortex-M vector table: an
// initial stack pointer, then Thumb handler addresses (in the image, at
// `base`, when it is known).
bool cortex_m_vectors(std::span<const std::byte> file, std::uint64_t offset, std::optional<std::uint64_t> base,
                      bool big_endian);

// Where string-like text starts in the file: runs of printable characters
// that end in a zero and don't continue something printable. Sorted.
std::vector<std::uint64_t> string_offsets(std::span<const std::byte> file);

// Where the image loads, from pointers and what they would point to. A
// pointer p to the thing at file offset t says base - offset = p - t; the
// difference most of them agree on is the answer.
struct Layout {
  std::optional<std::uint64_t> delta;   // base - offset (mod the address size); nullopt: nothing agreed
  std::uint64_t base = 0;
  std::uint64_t offset = 0;
  Confidence base_confidence = Confidence::low;
  Confidence offset_confidence = Confidence::low;
  std::uint64_t string_hits = 0, string_next = 0;      // pointers on strings at `delta`, and at the next best
  std::uint64_t function_hits = 0, function_next = 0;  // on function starts
  std::uint64_t anchors = 0;  // Trace::anchors agreeing with `delta`
  std::vector<Evidence> evidence;
};
Layout layout(std::span<const std::byte> file, const std::vector<Segment> &segments, const Trace &trace,
              unsigned address_bits, bool big_endian, bool odd_function_pointers);

// What the code says about memory outside the image, with the image placed:
// what region inference works from.
struct MemoryUse {
  std::uint64_t address = 0;
  std::uint32_t reads = 0, writes = 0;  // instructions doing each
  std::uint32_t widths = 0;             // bit set of access sizes: 1 << bytes
  std::uint32_t polled = 0;    // loads in a loop of a few instructions that stores nothing
  std::uint32_t modified = 0;  // stores shortly after a load of the same address
  std::uint32_t flags = 0;     // stores of a constant with one bit set, or all bits
  std::uint32_t values = 0;    // stores of a known constant
  std::vector<std::uint64_t> bases;  // what the address was made from (Trace::Access::base), sorted
  std::vector<std::uint64_t> sites;  // the accessing instructions' file offsets, sorted
};
struct MemoryFill {
  std::uint64_t start = 0, end = 0;     // [start, end) written
  std::optional<std::uint64_t> source;  // a copy's source in the image; nullopt: cleared
};
struct MemoryFacts {
  std::optional<std::uint64_t> image_start, image_end;  // the image's addresses, if placed
  std::vector<MemoryUse> uses;                   // by address, outside the image
  // Initial stack pointers: constants put in the stack pointer near the
  // image's start or end (startup code), and a vector table's word 0.
  std::vector<std::uint64_t> stack_tops;
  std::optional<std::uint64_t> vector_table_stack;  // one of them, a vector table's word 0
  std::vector<MemoryFill> fills;                 // copies from the image and clears, sorted
  std::vector<std::uint64_t> pointers;           // addresses outside the image the code builds, sorted
};
// Where startup code may hide from a sweep of the code-like segments: in
// stretches the segment map calls padding (vectors spread out with fill
// between them) near either end of the image. (offset, size) pairs.
std::vector<std::pair<std::uint64_t, std::uint64_t>> startup_windows(std::span<const std::byte> file,
                                                                     const std::vector<Segment> &segments,
                                                                     std::uint64_t offset);
// `from`'s memory accesses, stack values, loops and set-ups added to `to`'s.
void add_memory(Trace &to, const Trace &from);
MemoryFacts memory_facts(std::span<const std::byte> file, const Trace &trace, std::optional<std::uint64_t> base,
                         std::uint64_t offset, unsigned address_bits, bool big_endian, bool vector_table);

// A memory region beyond the image, as --region takes it, with why.
struct RegionSuggestion {
  enum class Kind : std::uint8_t {
    ram,      // read and written, not volatile
    mmio,     // devices' registers: volatile
    unknown,  // accessed, but nothing says which (never high confidence)
  };
  Kind kind = Kind::unknown;
  std::uint64_t start = 0, size = 0;
  std::string spec;  // "ram:20000000:40000", "mmio:40010000:1000:rw-:volatile"
  Confidence confidence = Confidence::low;
  std::vector<std::string> evidence;
};
std::string_view name(RegionSuggestion::Kind k);

struct Regions {
  std::vector<RegionSuggestion> regions;  // by address
  std::vector<Evidence> evidence;         // about "regions" as a whole (none seen, aliases dropped, ...)
};
// The RAM and MMIO an image's code uses beyond its own bytes (regions.cc):
// from a trace of the code, the image placed at `base` (nullopt: not
// placed), under `language` ("ARM:LE:32:v8").
Regions regions(std::span<const std::byte> file, const Trace &trace, std::optional<std::uint64_t> base,
                std::uint64_t offset, const std::string &language);

struct Suggestion {
  std::string language;                 // with the compiler: ready for a raw import
  std::vector<std::string> tie_group;   // languages the evidence can't tell from `language`
  std::optional<std::uint64_t> base;    // nullopt: undetermined
  std::uint64_t offset = 0;
  std::vector<std::string> regions;     // "name:start:size[:perms]" as the raw loader takes them
  // Each of `regions` with its kind, confidence and evidence, and regions
  // seen but not classified (kind unknown), which `regions` leaves out.
  std::vector<RegionSuggestion> region_details;
  Confidence processor = Confidence::low;
  Confidence variant = Confidence::low;
  Confidence base_confidence = Confidence::low;
  Confidence offset_confidence = Confidence::low;
  double score = 0;
  std::vector<Evidence> evidence;
};

struct Refusal {
  std::string reason;  // "high-entropy", "not-code", "unknown-processor", "too-small"
  std::string detail;
};

struct Report {
  std::optional<Refusal> refusal;       // set: nothing here should be applied without the user
  std::vector<Suggestion> suggestions;  // best first, at most three
  std::vector<Segment> segments;
  // Every candidate's sweep, best first: for tuning and for --detect-features.
  std::vector<Sweep> sweeps;
};

// How far a detection has got (Options::progress).
struct Progress {
  enum class Stage : std::uint8_t {
    segments,  // mapping the file
    sweep,     // decoding samples as each candidate: `done` of `total` candidates
    layout,    // working out where the best answer's image loads, and its variant
  };
  Stage stage = Stage::segments;
  std::size_t done = 0, total = 0;  // 0 of 0 where a stage doesn't count
};

struct Options {
  unsigned threads = 1;
  // Only these processors' candidates ("ARM", "x86": a language id's first
  // field); empty for all. What the user already knows narrows the search.
  std::vector<std::string> processors;
  // Told as each stage starts and as each candidate's sweep ends, from
  // whichever thread did the work (several at once with `threads` > 1): it
  // must be safe to call so, and quick.
  std::function<void(const Progress &)> progress;
  // Asked between stages and between candidates. Once it answers true the
  // detection stops early and what it returns is incomplete: the caller,
  // who asked for that, drops it.
  std::function<bool()> cancel;
};

Report detect(std::span<const std::byte> file, const Options &options = {});

}  // namespace revkit::detect
