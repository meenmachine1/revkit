// Detection: the segment map, a sweep of every candidate against its own
// chance level, and what the sweeps say.
#include "revkit/detect/detect.hh"

#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <thread>
#include <tuple>

namespace revkit::detect {

namespace {

double ratio(std::uint64_t a, std::uint64_t b) { return b == 0 ? 0.0 : static_cast<double>(a) / static_cast<double>(b); }

std::string percent(double v) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "%.0f%%", 100 * v);
  return buf;
}

// The windows' bytes one after the other, shuffled within each window, and
// where each window now is: the same bytes with nothing of their layout.
std::vector<std::byte> shuffled(std::span<const std::byte> file,
                                const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows,
                                std::vector<std::pair<std::uint64_t, std::uint64_t>> &placed) {
  std::vector<std::byte> out;
  placed.clear();
  std::uint64_t state = 0x9e3779b97f4a7c15;  // fixed: the same file gives the same answer
  for (const auto &[offset, size] : windows) {
    const std::size_t at = out.size();
    out.insert(out.end(), file.begin() + offset, file.begin() + offset + size);
    for (std::size_t i = size; i > 1; --i) {
      state ^= state << 13, state ^= state >> 7, state ^= state << 17;  // xorshift
      std::swap(out[at + i - 1], out[at + state % i]);
    }
    placed.emplace_back(at, size);
  }
  return out;
}

// The windows' bytes `shift` bytes along, one after the other, each where
// a window of the same size would be: the same bytes and the same
// structure, at another alignment.
std::vector<std::byte> moved(std::span<const std::byte> file,
                             const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows, std::uint64_t shift,
                             std::vector<std::pair<std::uint64_t, std::uint64_t>> &placed) {
  std::vector<std::byte> out;
  placed.clear();
  for (const auto &[offset, size] : windows) {
    const std::size_t at = out.size();
    const std::uint64_t from = std::min<std::uint64_t>(offset + shift, file.size());
    const std::uint64_t n = std::min<std::uint64_t>(size, file.size() - from);
    out.insert(out.end(), file.begin() + from, file.begin() + from + n);
    out.resize(at + size, std::byte{0});  // (the file's last window: what is past its end is nothing)
    placed.emplace_back(at, size);
  }
  return out;
}

// The family a language belongs to, for telling a runner-up that is another
// processor from one that is the same processor differently.
std::string family(const std::string &language) {
  std::size_t colon = language.find(':');
  colon = colon == std::string::npos ? colon : language.find(':', colon + 1);
  return language.substr(0, colon);  // "ARM:LE"
}

std::string processor(const std::string &language) { return language.substr(0, language.find(':')); }

// The processors whose instruction sets are subsets of a processor's: its
// predecessors, whose code it runs unchanged. (The Z80 and Z180 run the
// 8080's, which with RIM and SIM is the 8085's; the 65C02 the 6502's; the
// HD6309 the 6809's; the HCS08 the HC08's, and the HC08 the 6805's; the
// HCS12 and HCS12X the HC12's; the 80251 and DS80C390 the 8051's.)
std::vector<std::string_view> subsets(const std::string &processor) {
  if (processor == "z180") return {"z80", "8085"};
  if (processor == "z80") return {"8085"};
  if (processor == "65C02") return {"6502"};
  if (processor == "H6309") return {"6809"};
  if (processor == "HCS08") return {"HC08", "6805"};
  if (processor == "HC08") return {"6805"};
  if (processor == "HCS-12X") return {"HCS-12", "HC-12"};
  if (processor == "HCS-12") return {"HC-12"};
  if (processor == "80251" || processor == "80390") return {"8051"};
  return {};
}

int bits(const std::string &language) {
  const std::size_t a = language.find(':'), b = a == std::string::npos ? a : language.find(':', a + 1);
  return b == std::string::npos ? 0 : std::atoi(language.c_str() + b + 1);
}

std::string with_compiler(const std::string &language) {
  for (const lift::LanguageSummary &l : lift::list_languages())
    if (l.id == language && !l.compilers.empty()) return language + ":" + l.compilers.front();
  return language + ":default";
}

}  // namespace

namespace {

// The total log likelihood ratio of `n` events of which `hits` came out
// the way code makes them, between code and chance. By chance one does
// with probability `q` (as in the shuffled bytes, of which `noise_n` events
// had `noise_hits`; `prior` where there were none). In code, a share
// `lift` of those that wouldn't by chance do as well; but the windows
// swept are code mixed with data in a share nobody knows (an 8-bit game is
// mostly graphics), and data does what chance does: the best of `lift`,
// half and a quarter of it, less what choosing among three costs.
double evidence(std::uint64_t hits, std::uint64_t n, std::uint64_t noise_hits, std::uint64_t noise_n, double prior,
                double lift) {
  if (n == 0) return 0;
  const double q = std::clamp((static_cast<double>(noise_hits) + 2 * prior) / (static_cast<double>(noise_n) + 2), 0.01, 0.99);
  double best = -std::numeric_limits<double>::infinity();
  for (const double share : {1.0, 0.5, 0.25}) {
    const double p = q + (1 - q) * lift * share;
    best = std::max(best, static_cast<double>(hits) * std::log(p / q) +
                              static_cast<double>(n - hits) * std::log((1 - p) / (1 - q)));
  }
  return best > 0 ? std::max(0.0, best - std::log(3.0)) : best;
}

// RISC-V registers saved and restored on the stack, by the size of the
// slot: what control flow reaches, decoded as RV64 (`rv64`), counted by
// the compressed forms that address the stack pointer (c.sdsp and c.ldsp:
// 64 bits; c.swsp and c.lwsp: 32; RV32 reads the 64-bit ones as c.fswsp
// and c.flwsp, which only code saving floating-point registers has). Code
// without compressed instructions counts nothing: RV32 can't decode its
// sd and ld, which the variant shows.
struct Census {
  std::uint64_t wide = 0, narrow = 0;
};
Census register_saves(const Candidate &rv64, std::span<const std::byte> file,
                      const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows) {
  Census c;
  Sweeper sweeper(rv64);
  if (!sweeper.ok()) return c;
  const Features f = sweeper.sweep(file, windows, true);
  for (const auto &[form, n] : f.reached_forms) {
    const std::string &m = form.first;
    if (m == "c.sdsp" || m == "c.ldsp") c.wide += n;
    else if (m == "c.swsp" || m == "c.lwsp") c.narrow += n;
  }
  return c;
}

}  // namespace

Quality quality(const Features &f, const Features &noise) {
  // Of absolute jumps in code, the share beyond chance that go about as far
  // as the jump before: code is mixed with data, so modestly.
  constexpr double kAbsLift = 0.4;
  Quality out;
  // Too little decoded to say anything.
  if (f.instructions < 300) {
    out.plain = 0;
    return out;
  }
  const double n = static_cast<double>(f.instructions);
  out.branches = (evidence(f.branch_near, f.branches, noise.branch_near, noise.branches, 0.5, 0.85) +
                  evidence(f.branch_start, f.branch_near, noise.branch_start, noise.branch_near, 0.5, 0.95)) / n;
  out.calls = evidence(f.call_shared, f.calls, noise.call_shared, noise.calls, 0.05, 0.7) / n;
  out.returns = evidence(f.return_then_start, f.returns, noise.return_then_start, noise.returns, 0.2, 0.4) / n;
  out.absolute = evidence(f.absolute_start, f.absolute_swept, noise.absolute_start, noise.absolute_swept, 0.5, 0.9) / n;
  out.jumps = evidence(f.abs_pairs_near, f.abs_pairs, noise.abs_pairs_near, noise.abs_pairs, 0.05, kAbsLift) / n;
  // Code is made of instructions the language knows, and rarely of
  // floating point, division or operations outside p-code.
  out.plain = ratio(f.valid_bytes, f.bytes) * (1 - std::min(1.0, 2 * ratio(f.unimplemented, f.instructions))) *
              (1 - std::min(1.0, 3 * ratio(f.rare, f.instructions))) *
              (1 - std::min(1.0, ratio(f.callother, f.instructions)));
  return out;
}

Report detect(std::span<const std::byte> file, const Options &options) {
  Report r;
  auto tell = [&](Progress::Stage stage, std::size_t done = 0, std::size_t total = 0) {
    if (options.progress) options.progress(Progress{stage, done, total});
  };
  auto cancelled = [&] { return options.cancel && options.cancel(); };
  tell(Progress::Stage::segments);
  r.segments = segments(file);
  if (cancelled()) return r;
  std::uint64_t code = 0, dense = 0, text = 0;
  for (const Segment &s : r.segments) {
    if (s.kind == Segment::Kind::code) code += s.size;
    if (s.kind == Segment::Kind::high_entropy) dense += s.size;
    if (s.kind == Segment::Kind::text) text += s.size;
  }
  if (code < 256) {
    if (dense > code && dense >= text)
      r.refusal = Refusal{"high-entropy", "the file is compressed or encrypted: nothing in it can be decoded as it is"};
    else if (file.size() < 256)
      r.refusal = Refusal{"too-small", "too few bytes to tell a processor from"};
    else
      r.refusal = Refusal{"not-code", "the file is text or fill: no stretch of it could be code"};
    return r;
  }

  std::vector<Candidate> all = candidates();
  if (!options.processors.empty())
    std::erase_if(all, [&](const Candidate &c) {
      return std::find(options.processors.begin(), options.processors.end(), processor(c.language)) ==
             options.processors.end();
    });
  const auto windows = sample_windows(file, r.segments);
  std::vector<std::pair<std::uint64_t, std::uint64_t>> noise_windows;
  const std::vector<std::byte> noise = shuffled(file, windows, noise_windows);
  // The windows a byte and a halfword along, for candidates aligned to 2
  // and to 4 or more.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> moved_windows;
  const std::vector<std::byte> moved_1 = moved(file, windows, 1, moved_windows);
  const std::vector<std::byte> moved_2 = moved(file, windows, 2, moved_windows);

  std::vector<Sweep> swept(all.size());
  std::atomic<std::size_t> next{0}, done{0};
  tell(Progress::Stage::sweep, 0, all.size());
  auto work = [&] {
    for (std::size_t i; !cancelled() && (i = next.fetch_add(1)) < all.size();) {
      Sweep &s = swept[i];
      s.candidate = all[i];
      Sweeper sweeper(all[i]);
      if (sweeper.ok()) {
        s.features = sweeper.sweep(file, windows);
        s.features.seconds += sweeper.build_seconds();
        s.noise = sweeper.sweep(noise, noise_windows, false, file.size());
        s.quality = quality(s.features, s.noise);
        if (const unsigned align = sweeper.alignment(); align > 1) {
          s.shifted = sweeper.sweep(align == 2 ? moved_1 : moved_2, moved_windows, false, file.size());
          const Quality off = quality(s.shifted, s.noise);
          s.quality.branches -= std::max(0.0, off.branches);
          s.quality.calls -= std::max(0.0, off.calls);
          s.quality.returns -= std::max(0.0, off.returns);
          s.quality.absolute -= std::max(0.0, off.absolute);
          s.quality.jumps -= std::max(0.0, off.jumps);
        }
      }
      tell(Progress::Stage::sweep, done.fetch_add(1) + 1, all.size());
    }
  };
  std::vector<std::thread> threads;
  for (unsigned t = 1; t < std::max(1u, options.threads); ++t) threads.emplace_back(work);
  work();
  for (std::thread &t : threads) t.join();
  if (cancelled()) return r;
  std::stable_sort(swept.begin(), swept.end(), [](const Sweep &a, const Sweep &b) { return a.score() > b.score(); });
  r.sweeps = std::move(swept);

  // One answer per processor and byte order, best first. Its other
  // candidates that score about the same (within kSame) decode the same
  // code: sizes of one processor, which differ in a few instructions. They
  // are not alternatives but a group the sweep can't tell apart, and the
  // smallest stands for it (a program for the larger would use what only
  // the larger has). The other byte order joins the group where the
  // instructions read the same in both (AArch64).
  constexpr double kSame = 0.1;
  struct Answer {
    const Sweep *sweep;
    std::vector<const Sweep *> same;
  };
  std::vector<Answer> answers;
  auto same_decoding = [](const Sweep &a, const Sweep &b) {
    return a.features.instructions == b.features.instructions && a.features.valid_bytes == b.features.valid_bytes &&
           a.score() == b.score();
  };
  for (const Sweep &s : r.sweeps) {
    if (s.score() <= 0) break;
    Answer *of = nullptr;
    for (Answer &a : answers) {
      const bool family_same = family(a.sweep->candidate.language) == family(s.candidate.language);
      const bool processor_same = processor(a.sweep->candidate.language) == processor(s.candidate.language);
      if (family_same || (processor_same && same_decoding(*a.sweep, s))) of = &a;
    }
    if (of == nullptr) {
      answers.push_back({&s, {}});
    } else if (s.score() >= (1 - kSame) * of->sweep->score() && s.candidate.mode == of->sweep->candidate.mode) {
      of->same.push_back(&s);
      // Little-endian and the smaller size first; "ilp32" is AArch64 run
      // with 32-bit pointers, which is rare.
      auto rank = [](const Sweep &x) {
        const std::string &l = x.candidate.language;
        return std::tuple(l.find("ilp32") != std::string::npos, l.find(":BE:") != std::string::npos, bits(l));
      };
      if (rank(s) < rank(*of->sweep)) std::swap(of->sweep, of->same.back());
    }
  }

  // Thresholds from the firmware corpus and labelled code of other
  // processors (docs/autodetect.md), in nats of evidence per instruction.
  // An answer needs two kinds of evidence, or one that is strong by
  // itself: one weak kind is what another processor's code, or data with
  // some regularity, gives by accident.
  constexpr double kAnswer = 0.01, kAlone = 0.05, kConfident = 0.04, kClear = 5, kNoFit = 0.1;
  auto answered = [&](const Sweep &s) {
    return s.score() >= kAnswer && (s.quality.kinds() >= 2 || s.quality.strongest() >= kAlone);
  };
  if (answers.empty() || !answered(*answers.front().sweep)) {
    r.refusal = Refusal{"unknown-processor",
                        "no language decodes this as code: either it is no program, or it is for a processor "
                        "there is no language for"};
  }
  // What follows is worked out for the best answer even where it is
  // refused: the user, who may know the processor, sees where its image
  // would load (no more certain than the processor, below).
  const bool refused = r.refusal.has_value();
  // Where the best answer's image loads: a decode of the code-like part of
  // the file (all of it up to kTraced bytes, then evenly spread blocks).
  Layout placed;
  Regions memory;  // beyond the image
  auto place = [&](const Candidate &c) {
    constexpr std::uint64_t kTraced = 8u << 20, kBlock = 64u << 10;
    const auto blocks = sample_windows(file, r.segments, kTraced / kBlock, kBlock);
    Sweeper sweeper(c);
    if (!sweeper.ok()) return;
    Trace trace = sweeper.trace(file, blocks);
    const bool big = c.language.find(":BE:") != std::string::npos;
    placed = layout(file, r.segments, trace, static_cast<unsigned>(bits(c.language)), big, processor(c.language) == "ARM");
    const std::uint64_t offset = placed.delta ? placed.offset : 0;
    add_memory(trace, sweeper.trace(file, startup_windows(file, r.segments, offset)));
    memory = regions(file, trace, placed.delta ? std::optional(placed.base) : std::nullopt, offset, c.language);
  };
  // RISC-V's word size, which the decoding hardly shows: RV32 and RV64
  // share the 32-bit instructions but for a few, and their compressed
  // ones differ where it doesn't stop the other decoding them (RV32's
  // c.jal is RV64's c.addiw, its c.flw and c.fsw RV64's c.ld and c.sd).
  // What does show it is the stack: functions save and restore registers
  // as words of the register size.
  std::optional<int> xlen;
  std::string xlen_evidence;
  if (!answers.empty() && processor(answers.front().sweep->candidate.language) == "RISCV") {
    Answer &a = answers.front();
    const Sweep *of[2] = {nullptr, nullptr};  // RV32, RV64
    for (const Sweep &s : r.sweeps)
      if (family(s.candidate.language) == family(a.sweep->candidate.language) && s.candidate.mode == a.sweep->candidate.mode &&
          (bits(s.candidate.language) == 32 || bits(s.candidate.language) == 64) && s.score() > 0) {
        const Sweep *&slot = of[bits(s.candidate.language) == 64];
        if (slot == nullptr) slot = &s;
      }
    if (of[0] && of[1]) {
      const Census c = register_saves(of[1]->candidate, file, windows);
      if (c.wide + c.narrow >= 20 && (c.wide >= 2 * c.narrow || c.narrow >= 2 * c.wide)) {
        xlen = c.wide > c.narrow ? 64 : 32;
        const Sweep *chosen = of[*xlen == 64];
        xlen_evidence = std::to_string(c.wide) + " registers saved or restored on the stack as 64-bit words (c.sdsp, c.ldsp) "
                        "and " + std::to_string(c.narrow) + " as 32-bit (c.swsp, c.lwsp), in the code control flow reaches: RV" +
                        std::to_string(*xlen);
        if (chosen != a.sweep) {
          std::erase(a.same, chosen);
          a.same.push_back(a.sweep);
          a.sweep = chosen;
        }
      }
    }
  }
  if (!answers.empty()) {
    tell(Progress::Stage::layout);
    place(answers.front().sweep->candidate);
  }
  // Which variant the best answer's code needs, among its group's (and the
  // groups that decoded it the same).
  std::optional<Variant> variant;
  if (cancelled()) return r;
  if (!answers.empty()) {
    const Answer &a = answers.front();
    std::vector<std::string> pool = a.sweep->candidate.languages;
    for (const Sweep *other : a.same)
      if (other->candidate.mode == a.sweep->candidate.mode)
        pool.insert(pool.end(), other->candidate.languages.begin(), other->candidate.languages.end());
    if (xlen) std::erase_if(pool, [&](const std::string &l) { return bits(l) != *xlen; });
    // Processors whose instruction set is a subset of the answer's: code
    // that uses nothing of the larger is the smaller's (Z80 runs 8080
    // code, of which the 8085 is the language here).
    for (const std::string_view sub : subsets(processor(a.sweep->candidate.language)))
      for (const Candidate &c : all)
        if (processor(c.language) == sub && c.mode == a.sweep->candidate.mode)
          pool.insert(pool.end(), c.languages.begin(), c.languages.end());
    const bool vectors = cortex_m_vectors(file, placed.delta ? placed.offset : 0,
                                          placed.delta ? std::optional(placed.base) : std::nullopt,
                                          a.sweep->candidate.language.find(":BE:") != std::string::npos);
    variant = choose_variant(a.sweep->candidate, pool, file, windows, noise, noise_windows, vectors, options.threads);
  }
  // The answer: the best candidate in the variant its code needs.
  Candidate answer;
  if (!answers.empty()) {
    answer = answers.front().sweep->candidate;
    if (variant) answer.language = variant->language;
    // The variant's address size is not the candidate's (a group of both
    // sizes stands for one answer, the smaller first): where the image
    // loads again, with pointers of the answer's size (RV64's tables).
    if (bits(answer.language) != bits(answers.front().sweep->candidate.language)) {
      placed = {}, memory = {};
      place(answer);
    }
  }
  // Whether the answer's whole instruction set fits: its sweep, with the
  // mnemonics of what control flow reaches, against the profile of real
  // code of the language.
  std::optional<Fit> fitted;
  if (cancelled()) return r;
  if (!answers.empty()) {
    Sweep &top = r.sweeps[static_cast<std::size_t>(answers.front().sweep - r.sweeps.data())];
    Sweeper sweeper(answer);
    if (sweeper.ok()) {
      Features code = sweeper.sweep(file, windows, true), shuffled = sweeper.sweep(noise, noise_windows, true, file.size());
      fitted = fit(code, shuffled, profile(processor(answer.language), bits(answer.language), answer.mode));
      top.features.forms = std::move(code.forms);
      top.features.reached_forms = std::move(code.reached_forms);
      top.noise.forms = std::move(shuffled.forms);
      top.noise.reached_forms = std::move(shuffled.reached_forms);
      // Where one run in ten of what control flow reaches ends in bytes the
      // language can't decode (real code: under one in a hundred), it is
      // not this language's code at all.
      if (!refused && fitted->cut >= 50 && fitted->cut_share() >= kNoFit)
        r.refusal = Refusal{"unknown-processor",
                            "the best language, " + answer.label() + ", decodes much of this, but " +
                                percent(fitted->cut_share()) +
                                " of the runs of code its control flow reaches end in bytes it can't decode: likely "
                                "code of a processor there is no language for"};
    }
  }
  // The answer's variant may be another answer's language (a subset
  // processor's): that one is no alternative to it.
  if (variant && !answers.empty())
    answers.erase(std::remove_if(answers.begin() + 1, answers.end(),
                                 [&](const Answer &a) {
                                   const std::vector<std::string> &l = a.sweep->candidate.languages;
                                   return a.sweep->candidate.mode == answers.front().sweep->candidate.mode &&
                                          std::find(l.begin(), l.end(), variant->language) != l.end();
                                 }),
                  answers.end());
  for (std::size_t i = 0; i < answers.size() && i < 3; ++i) {
    const Sweep &s = *answers[i].sweep;
    const Features &f = s.features;
    Suggestion out;
    out.language = with_compiler(i == 0 && variant ? variant->language : s.candidate.language);
    if (i == 0 && variant) {
      for (const std::string &l : variant->sufficient) out.tie_group.push_back(with_compiler(l));
      out.variant = variant->confidence;
    } else {
      for (const std::string &l : s.candidate.languages)
        if (l != s.candidate.language) out.tie_group.push_back(with_compiler(l));
      for (const Sweep *other : answers[i].same)
        for (const std::string &l : other->candidate.languages) out.tie_group.push_back(with_compiler(l));
    }
    out.score = s.score();
    const double next = i + 1 < answers.size() ? answers[i + 1].sweep->score() : 0;
    // High: plenty of evidence, of more than one kind, and nothing else
    // comes close.
    if (i == 0 && !r.refusal)
      out.processor = s.score() >= kConfident && s.score() >= kClear * next && s.quality.kinds() >= 2 ? Confidence::high
                      : s.score() >= 2 * next                                                        ? Confidence::medium
                                                                                                      : Confidence::low;
    std::string text = std::to_string(f.instructions) + " instructions decode (" + percent(ratio(f.valid_bytes, f.bytes)) +
                       " of the sampled bytes)";
    if (!s.candidate.mode.empty()) text += " as " + s.candidate.mode;
    auto chance = [](std::uint64_t hits, std::uint64_t n) { return n == 0 ? std::string("no such") : percent(ratio(hits, n)); };
    if (s.quality.branches > 0.005)
      text += "; " + percent(ratio(f.branch_start, f.branches)) + " of " + std::to_string(f.branches) +
              " relative branches land on an instruction nearby (" + chance(s.noise.branch_start, s.noise.branches) +
              " of the same bytes shuffled)";
    if (s.quality.calls > 0.005)
      text += "; " + percent(ratio(f.call_shared, f.calls)) + " of " + std::to_string(f.calls) +
              " relative calls go to a function called more than once (" + chance(s.noise.call_shared, s.noise.calls) +
              " shuffled)";
    if (s.quality.returns > 0.005)
      text += "; " + percent(ratio(f.return_then_start, f.returns)) + " of " + std::to_string(f.returns) +
              " returns are followed by a function (" + chance(s.noise.return_then_start, s.noise.returns) + " shuffled)";
    if (s.quality.jumps > 0.005)
      text += "; " + percent(ratio(f.abs_pairs_near, f.abs_pairs)) + " of " + std::to_string(f.abs_pairs) +
              " absolute jumps go about as far as the one before, as jumps within a function do (" +
              chance(s.noise.abs_pairs_near, s.noise.abs_pairs) + " shuffled)";
    if (s.quality.absolute > 0.005)
      text += "; " + percent(ratio(f.absolute_start, f.absolute_swept)) + " of " + std::to_string(f.absolute_swept) +
              " absolute jump and call targets are instructions if the file loads at 0 (" +
              chance(s.noise.absolute_start, s.noise.absolute_swept) + " shuffled)";
    out.evidence.push_back({"processor", std::move(text)});
    if (i == 0 && fitted && fitted->near_miss()) {
      // Decodes, and its branches land, but the rest of the instruction
      // set doesn't fit: code of a processor derived from this one, which
      // has no language here, looks so. Not confident, whatever else.
      if (out.processor == Confidence::high) out.processor = Confidence::medium;
      const std::string name = processor(out.language);
      std::string why = "decodes like " + name + ", but";
      if (fitted->unusual())
        why += " " + percent(fitted->rare_share()) + " of the code control flow reaches uses instructions real " + name +
               " code rarely has (" + percent(fitted->noise_rare_share()) + " of the same bytes shuffled, under 10% of " +
               "real code)";
      if (fitted->cut_short())
        why += std::string(fitted->unusual() ? " and" : "") + " " + percent(fitted->cut_share()) +
               " of the runs of code control flow reaches end in bytes " + name + " can't decode (under 1% in real code)";
      why += ": it may be code of a processor derived from " + name + ", which has no language here";
      out.evidence.push_back({"processor", std::move(why)});
    }
    if (i == 0 && variant) out.evidence.insert(out.evidence.end(), variant->evidence.begin(), variant->evidence.end());
    if (i == 0 && !xlen_evidence.empty()) out.evidence.push_back({"variant", xlen_evidence});
    if (i == 0 && placed.delta) {
      out.base = placed.base;
      out.offset = placed.offset;
      out.base_confidence = placed.base_confidence;
      out.offset_confidence = placed.offset_confidence;
      out.evidence.insert(out.evidence.end(), placed.evidence.begin(), placed.evidence.end());
      // Pointers that fit are evidence of another kind for the processor
      // too: another processor's decoding wouldn't name these addresses.
      // (A derived processor's code names the same addresses: not when the
      // instruction set doesn't fit.)
      if (out.processor == Confidence::medium && placed.base_confidence == Confidence::high && s.score() >= kConfident &&
          s.score() >= kClear * next && !(fitted && fitted->near_miss()))
        out.processor = Confidence::high;
    } else if (i == 0) {
      out.evidence.push_back({"base", "too few addresses in the code agree on where it loads: the code may run anywhere "
                                      "(position-independent), or name nothing in the file"});
    }
    if (i == 0) {
      for (const RegionSuggestion &g : memory.regions)
        if (g.kind != RegionSuggestion::Kind::unknown) out.regions.push_back(g.spec);
      out.region_details = memory.regions;
      out.evidence.insert(out.evidence.end(), memory.evidence.begin(), memory.evidence.end());
    }
    // A refused answer's variant, layout and regions are what they would be
    // if it were the processor: no more certain than that.
    if (i == 0 && r.refusal) {
      auto cap = [](Confidence &c) { c = std::min(c, Confidence::medium); };
      cap(out.variant), cap(out.base_confidence), cap(out.offset_confidence);
      for (RegionSuggestion &g : out.region_details) cap(g.confidence);
    }
    r.suggestions.push_back(std::move(out));
  }
  return r;
}

}  // namespace revkit::detect
