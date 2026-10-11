// Which variant of a processor the code needs: of the variants that decode
// it as fully as any, the least capable one (what decodes the fewest of the
// same bytes shuffled). A program for a larger variant would use something
// only the larger one has; one that doesn't can't be told from the smaller.
#include "revkit/detect/detect.hh"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <tuple>
#include <thread>

namespace revkit::detect {

namespace {

double ratio(std::uint64_t a, std::uint64_t b) { return b == 0 ? 0.0 : static_cast<double>(a) / static_cast<double>(b); }

std::string variant_of(const std::string &language) {
  std::size_t at = 0;
  for (int i = 0; i < 3 && at != std::string::npos; ++i) at = language.find(':', at + 1);
  return at == std::string::npos ? language : language.substr(at + 1);
}

int bits_of(const std::string &language) {
  const std::size_t a = language.find(':'), b = a == std::string::npos ? a : language.find(':', a + 1);
  return b == std::string::npos ? 0 : std::atoi(language.c_str() + b + 1);
}

bool m_profile(const std::string &language) {
  const std::string v = variant_of(language);
  return v == "Cortex" || v == "v8-m";
}

// An ARM variant's architecture version, which is what orders ARM's
// variants: each has what the one before had, and more. 0: not ARM.
int arm_version(const std::string &language) {
  if (!language.starts_with("ARM:")) return 0;
  const std::string v = variant_of(language);
  if (v == "Cortex") return 7;  // ARMv7-M
  if (v == "v8-m" || v == "v8T") return 8;
  return v.size() >= 2 && v[0] == 'v' ? std::atoi(v.c_str() + 1) : 0;
}

}  // namespace

Thumb2 thumb2_census(const Features &f) {
  Thumb2 out;
  for (const auto &[form, n] : f.reached_forms) {
    const std::string &m = form.first;
    out.reached += n;
    if (m.starts_with("it")) out.it += n;
    else if (m == "cbz" || m == "cbnz") out.cbz += n;
    else if (form.second == 4 && m != "bl" && m != "blx") out.wide += n;
  }
  return out;
}

bool uses_thumb2(const Thumb2 &code, const Thumb2 &noise) {
  // Too few to tell (a sample of a few hundred instructions has dozens).
  if (code.used() < 20) return false;
  return code.share() >= 0.5 * noise.share();
}

bool cortex_m_vectors(std::span<const std::byte> file, std::uint64_t offset, std::optional<std::uint64_t> base,
                      bool big_endian) {
  if (offset + 64 > file.size()) return false;
  auto word = [&](std::uint64_t at) {
    std::uint32_t w = 0;
    for (int k = 0; k < 4; ++k) w = w << 8 | static_cast<std::uint8_t>(file[offset + at + (big_endian ? k : 3 - k)]);
    return w;
  };
  // Word 0 is the initial stack pointer: word-aligned, not in the image's
  // first bytes. Words 1-15 are handlers: Thumb addresses (odd) in the
  // image, or zero for reserved ones; reset (word 1) is never zero.
  const std::uint32_t sp = word(0), reset = word(4);
  if (sp == 0 || sp % 4 != 0 || !(reset & 1)) return false;
  const std::uint64_t size = file.size() - offset;
  int handlers = 0;
  std::uint64_t low = ~std::uint64_t{0}, high = 0;
  for (std::uint64_t i = 1; i < 16; ++i) {
    const std::uint32_t h = word(4 * i);
    if (h == 0 && i != 1) continue;
    if (!(h & 1)) return false;
    ++handlers;
    low = std::min<std::uint64_t>(low, h), high = std::max<std::uint64_t>(high, h);
    if (base && (h - 1 < *base || h - 1 >= *base + size)) return false;
  }
  return handlers >= 4 && high - low < size;
}

Variant choose_variant(const Candidate &chosen, const std::vector<std::string> &pool,
                       std::span<const std::byte> file,
                       const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows,
                       std::span<const std::byte> noise,
                       const std::vector<std::pair<std::uint64_t, std::uint64_t>> &noise_windows, bool cortex_vectors,
                       unsigned threads) {
  struct Tried {
    std::string language;
    bool ok = false;
    Features code, shuffled;
  };
  std::vector<Tried> tried;
  for (const std::string &l : pool) {
    // M-profile cores run only Thumb, from a vector table of Thumb
    // addresses; without one, or for ARM code, they are not candidates.
    if (m_profile(l) && (chosen.mode != "thumb" || !cortex_vectors)) continue;
    // ARM v4 and v5 (without T) have no Thumb state, and revkit's ARM
    // analysis assumes one: they can't be imported, so they are no answer.
    if (l.starts_with("ARM:") && (variant_of(l) == "v4" || variant_of(l) == "v5")) continue;
    tried.push_back({l, false, {}, {}});
  }
  // ARM's Thumb code: which instructions it uses tells whether it needs
  // Thumb-2, where the bytes decoded tell little: a variant without
  // Thumb-2 decodes a Thumb-2 instruction's halves as two others.
  const bool census = chosen.language.starts_with("ARM:") && chosen.mode == "thumb";
  std::atomic<std::size_t> next{0};
  auto work = [&] {
    for (std::size_t i; (i = next.fetch_add(1)) < tried.size();) {
      Candidate c = chosen;
      c.language = tried[i].language;
      Sweeper sweeper(c);
      if (!sweeper.ok()) continue;
      tried[i].ok = true;
      tried[i].code = sweeper.sweep(file, windows, census);
      tried[i].shuffled = sweeper.sweep(noise, noise_windows, census);
    }
  };
  std::vector<std::thread> pool_threads;
  for (unsigned t = 1; t < std::max(1u, std::min<unsigned>(threads, tried.size())); ++t) pool_threads.emplace_back(work);
  work();
  for (std::thread &t : pool_threads) t.join();
  std::erase_if(tried, [](const Tried &t) { return !t.ok; });

  Variant out;
  out.language = chosen.language;
  if (tried.empty()) return out;
  const Tried *best = &tried.front();
  for (const Tried &t : tried)
    if (t.code.valid_bytes > best->code.valid_bytes) best = &t;
  const std::uint64_t most = best->code.valid_bytes;
  // Suffices: decodes as much of the code as the variant that decodes the
  // most, but for what that variant's extra instructions make of the data
  // between the code (literal pools, tables). Those are as likely to decode
  // as shuffled bytes are, so a variant falls short only where the code
  // gains more than half what shuffled bytes gain: a program that needs
  // the larger variant uses its instructions far more than data hits them
  // by chance.
  auto gain = [](std::uint64_t more, std::uint64_t less, std::uint64_t of) {
    return of == 0 || more <= less ? 0.0 : static_cast<double>(more - less) / static_cast<double>(of);
  };
  // How much of the windows is data: what the best variant can't decode,
  // against what it can't decode of shuffled bytes. The more data, the more
  // a larger variant gains on it by chance.
  const double undecoded = 1 - ratio(best->code.valid_bytes, best->code.bytes);
  const double undecoded_shuffled = 1 - ratio(best->shuffled.valid_bytes, best->shuffled.bytes);
  const double data = undecoded_shuffled <= 0 ? 0.5 : std::clamp(1.5 * undecoded / undecoded_shuffled, 0.5, 1.0);
  std::vector<const Tried *> enough, short_of;
  for (const Tried &t : tried) {
    const double code = gain(most, t.code.valid_bytes, best->code.bytes);
    const double chance = gain(best->shuffled.valid_bytes, t.shuffled.valid_bytes, best->shuffled.bytes);
    (code <= std::max(0.001, data * chance) ? enough : short_of).push_back(&t);
  }
  // Thumb code that uses Thumb-2 needs ARMv6T2 or later, however fully
  // older variants decode its bytes.
  std::optional<Thumb2> t2_code, t2_noise;
  bool thumb2 = false;
  if (census) {
    t2_code = thumb2_census(best->code), t2_noise = thumb2_census(best->shuffled);
    thumb2 = uses_thumb2(*t2_code, *t2_noise);
    if (thumb2 && std::any_of(enough.begin(), enough.end(), [](const Tried *t) { return arm_version(t->language) >= 6; })) {
      for (auto it = enough.begin(); it != enough.end();) {
        if (arm_version((*it)->language) < 6) short_of.push_back(*it), it = enough.erase(it);
        else ++it;
      }
    }
  }
  auto capability = [](const Tried *t) { return ratio(t->shuffled.valid_bytes, t->shuffled.bytes); };
  // The order among those that suffice: the smaller address size; then the
  // language's conventional variant ("default", Cortex for M-profile ARM),
  // since variants that aren't nested (PowerPC e500 vs 4xx) can't be ranked
  // by what they decode; then the smallest that suffices: for ARM by its
  // architecture version (ARM v4t < v5t < v6 < v7, which a variant's
  // decoding doesn't follow in Thumb: v4t decodes a Thumb-2 instruction's
  // halves as instructions of their own), for others the least capable
  // (what decodes the fewest of the same bytes shuffled). Thumb-2 code is
  // ARMv7's rather than ARMv6's: Ghidra's v6 has ARMv6T2's Thumb-2, but of
  // the ARMv6 cores only the ARM1156T2 does.
  auto rank = [&](const Tried *t) {
    const std::string v = variant_of(t->language);
    // AArch64 ilp32 and PowerPC's 64-bit variants with 32-bit addresses
    // decode the 64-bit instruction set: not the smaller one.
    const int bits = v.find("ilp32") != std::string::npos || v.find("32addr") != std::string::npos ? 64 : bits_of(t->language);
    const int version = arm_version(t->language);
    return std::tuple(bits, v == "default" || v == "v8A" ? 0 : v == "Cortex" ? 1 : 2, thumb2 && version == 6, version,
                      capability(t));
  };
  std::stable_sort(enough.begin(), enough.end(), [&](const Tried *a, const Tried *b) { return rank(a) < rank(b); });
  std::stable_sort(short_of.begin(), short_of.end(), [&](const Tried *a, const Tried *b) {
    return a->code.valid_bytes > b->code.valid_bytes;
  });
  out.language = enough.front()->language;
  for (std::size_t i = 1; i < enough.size(); ++i) out.sufficient.push_back(enough[i]->language);
  // High: the next smaller variants fall short, and no other variant is as
  // small. Medium: it is the smallest that suffices, but larger ones do too
  // (the code may just not use what they add). Low: nothing told them apart.
  const bool smaller_fail = !short_of.empty();
  const bool alone = enough.size() == 1 || rank(enough[1]) > rank(enough[0]);
  out.confidence = enough.size() == 1 ? Confidence::high
                   : alone && smaller_fail ? Confidence::medium
                                           : Confidence::low;
  if (m_profile(out.language)) {
    // The vector table is evidence of its own.
    if (out.confidence == Confidence::medium) out.confidence = Confidence::high;
  }

  // Variants by name; with the processor where they are of several (a
  // subset processor's among them).
  const std::string processor = out.language.substr(0, out.language.find(':'));
  const bool several = std::any_of(tried.begin(), tried.end(), [&](const Tried &t) { return !t.language.starts_with(processor + ":"); });
  auto label = [&](const std::string &language) {
    return several ? language.substr(0, language.find(':')) + " " + variant_of(language) : variant_of(language);
  };
  char buf[256];
  std::string text = label(out.language) + " decodes the sampled code as fully as any variant";
  if (!short_of.empty()) {
    text += "; ";
    for (std::size_t i = 0; i < short_of.size() && i < 3; ++i) {
      const std::uint64_t lost = most - short_of[i]->code.valid_bytes;
      if (thumb2 && arm_version(short_of[i]->language) < 6)
        std::snprintf(buf, sizeof buf, "%s%s has no Thumb-2", i ? ", " : "", label(short_of[i]->language).c_str());
      else
        std::snprintf(buf, sizeof buf, "%s%s leaves %llu bytes undecoded", i ? ", " : "",
                      label(short_of[i]->language).c_str(), static_cast<unsigned long long>(lost));
      text += buf;
    }
  }
  if (enough.size() > 1) {
    text += "; ";
    for (std::size_t i = 1; i < enough.size() && i < 4; ++i)
      text += (i > 1 ? ", " : "") + label(enough[i]->language);
    text += enough.size() == 2 ? " decodes it too, and more besides" : " decode it too, and more besides";
  }
  if (t2_code) {
    std::snprintf(buf, sizeof buf, "%.0f%% of the code control flow reaches is Thumb-2 (32-bit instructions, IT, cbz), "
                                   "%.0f%% of the same bytes shuffled",
                  100 * t2_code->share(), 100 * t2_noise->share());
    text += thumb2 ? "; uses Thumb-2: " + std::string(buf) + ", which ARMv4T and v5T don't have"
                   : "; uses no Thumb-2: " + std::string(buf);
    if (thumb2 && arm_version(out.language) > 6 &&
        std::any_of(enough.begin(), enough.end(), [](const Tried *t) { return arm_version(t->language) == 6; }))
      text += "; Ghidra's v6 decodes Thumb-2 too (ARMv6T2), but of the ARMv6 cores only the ARM1156T2 has it";
  }
  if (m_profile(out.language)) text += "; the image starts with a Cortex-M vector table (a stack top, then Thumb handlers)";
  out.evidence.push_back({"variant", std::move(text)});
  return out;
}

}  // namespace revkit::detect
