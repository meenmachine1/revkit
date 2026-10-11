// Where the image loads: the difference between addresses the code names
// and the file offsets of the things they would name, by vote; then that
// difference split into a base and the image's offset in the file.
#include "revkit/detect/detect.hh"

#include <algorithm>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>

namespace revkit::detect {

namespace {

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

bool printable(std::byte b) {
  const auto c = static_cast<std::uint8_t>(b);
  return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r';
}

// At most `count` of `v`, spread evenly.
std::vector<std::uint64_t> thinned(const std::vector<std::uint64_t> &v, std::size_t count) {
  if (v.size() <= count) return v;
  std::vector<std::uint64_t> out;
  for (std::size_t i = 0; i < count; ++i) out.push_back(v[i * v.size() / count]);
  return out;
}

// How many pointers land on a target at each difference: pointer - target
// (mod the address size) -> count. Only differences that are multiples of
// `align` are tried, which is what makes it affordable: a pointer can only
// meet the targets that agree with it below `align`.
std::unordered_map<std::uint64_t, std::uint32_t> votes(const std::vector<std::uint64_t> &pointers,
                                                       const std::vector<std::uint64_t> &targets, std::uint64_t align,
                                                       std::uint64_t mask) {
  std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> by_low;
  for (std::uint64_t t : targets) by_low[t & (align - 1)].push_back(t);
  std::unordered_map<std::uint64_t, std::uint32_t> out;
  for (std::uint64_t p : pointers) {
    const auto it = by_low.find(p & (align - 1));
    if (it == by_low.end()) continue;
    for (std::uint64_t t : it->second) ++out[(p - t) & mask];
  }
  return out;
}

}  // namespace

std::vector<std::uint64_t> string_offsets(std::span<const std::byte> file) {
  std::vector<std::uint64_t> out;
  constexpr std::size_t kShortest = 6;
  for (std::size_t i = 0; i < file.size();) {
    if (!printable(file[i])) {
      ++i;
      continue;
    }
    std::size_t end = i;
    while (end < file.size() && printable(file[end])) ++end;
    // Text that ends in a zero, as C strings do; its start is where
    // something else ended.
    if (end - i >= kShortest && end < file.size() && file[end] == std::byte{0}) out.push_back(i);
    i = end + 1;
  }
  return out;
}

Layout layout(std::span<const std::byte> file, const std::vector<Segment> &segments, const Trace &trace,
              unsigned address_bits, bool big_endian, bool odd_function_pointers) {
  Layout out;
  if (address_bits < 16) return out;
  const std::uint64_t mask = address_bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << address_bits) - 1;

  const std::vector<std::uint64_t> strings = string_offsets(file);
  // Pointers kept as data: tables of them (a global offset table, vectors,
  // arrays of strings and of structures, the relocations a
  // position-independent image applies to itself), which
  // position-independent code uses instead of naming addresses. Any word
  // could be one, but an instruction's word could match a string by its
  // immediate alone; so only runs of words that could all point into one
  // image: four or more, within the file's size of each other, not all the
  // same. Small numbers between them (a structure's other fields, a
  // relocation's type, zeros) don't end a run unless three come in a row,
  // and aren't pointers.
  std::vector<std::uint64_t> tabled;
  {
    const std::size_t size = address_bits / 8;
    const std::uint64_t span = std::max<std::uint64_t>(file.size(), 1u << 16);
    constexpr std::uint64_t kSmall = 0x10000;
    auto word = [&](std::size_t at) {
      std::uint64_t w = 0;
      for (std::size_t k = 0; k < size; ++k) w = w << 8 | static_cast<std::uint8_t>(file[at + (big_endian ? k : size - 1 - k)]);
      return w;
    };
    std::vector<std::uint64_t> run;  // the pointer-like words of the run so far
    std::uint64_t low = 0, high = 0;
    int smalls = 0;  // small words in a row just before
    auto flush = [&] {
      if (run.size() >= 4 && low != high) tabled.insert(tabled.end(), run.begin(), run.end());
      run.clear(), smalls = 0;
    };
    for (std::size_t at = 0; size != 0 && at + size <= file.size(); at += size) {
      const std::uint64_t w = word(at);
      if (w < kSmall) {
        if (++smalls == 3) flush();
        continue;
      }
      if (!run.empty() && std::max(high, w) - std::min(low, w) >= span) flush();
      if (run.empty()) low = high = w;
      low = std::min(low, w), high = std::max(high, w);
      run.push_back(w);
      smalls = 0;
    }
    flush();
    std::sort(tabled.begin(), tabled.end());
    tabled.erase(std::unique(tabled.begin(), tabled.end()), tabled.end());
  }
  std::vector<std::uint64_t> to_data = trace.pointers;
  to_data.insert(to_data.end(), tabled.begin(), tabled.end());
  std::sort(to_data.begin(), to_data.end());
  to_data.erase(std::unique(to_data.begin(), to_data.end()), to_data.end());
  // What may point at a function: the addresses the code builds, and where
  // its absolute jumps and calls go. Thumb function pointers are odd.
  std::vector<std::uint64_t> to_code = trace.jump_targets;
  to_code.insert(to_code.end(), to_data.begin(), to_data.end());
  if (odd_function_pointers)
    for (std::uint64_t &p : to_code) p &= ~std::uint64_t{1};
  std::sort(to_code.begin(), to_code.end());
  to_code.erase(std::unique(to_code.begin(), to_code.end()), to_code.end());

  // Coarse differences first (an image at a round address with no header
  // is the common case and costs nothing), then finer ones on fewer
  // pointers and targets, until some difference stands out.
  struct Pass {
    std::uint64_t align;
    std::size_t pointers, targets;
    std::size_t functions;  // function starts: dense (every return and tail call is followed by one), fewer at fine passes
  };
  constexpr Pass kPasses[] = {
      {0x1000, 60000, 200000, 200000}, {0x10, 6000, 30000, 30000}, {4, 3000, 20000, 4000}, {1, 2000, 10000, 2500}};
  // A kind's votes: the best difference and the best count anywhere else.
  struct Kind {
    std::uint64_t delta = 0;
    std::uint32_t hits = 0, next = 0;
    // Enough pointers agree, and three times what agrees on anything else:
    // pointers and targets that are dense meet often by chance, at every
    // difference alike.
    bool stands_out() const { return hits >= 8 && hits >= 3 * next; }
    // Ahead of the rest, if not by enough alone.
    bool leads() const { return hits >= 4 && hits >= 2 * next; }
  };
  auto best_of = [](const std::unordered_map<std::uint64_t, std::uint32_t> &v) {
    Kind k;
    for (const auto &[delta, n] : v)
      if (n > k.hits || (n == k.hits && delta < k.delta)) k.next = k.hits, k.hits = n, k.delta = delta;
      else if (n > k.next) k.next = n;
    return k;
  };
  const std::uint64_t region_mask = trace.region_bits == 0 ? 0 : (std::uint64_t{1} << trace.region_bits) - 1;
  std::optional<std::uint64_t> delta;
  std::uint32_t next = 0;
  std::optional<std::uint64_t> alias;  // where the strings say the image is, where the functions say otherwise
  std::uint32_t alias_hits = 0;
  for (const Pass &pass : kPasses) {
    const auto s = votes(thinned(to_data, pass.pointers), thinned(strings, pass.targets), pass.align, mask);
    auto f = votes(thinned(to_code, pass.pointers), thinned(trace.function_offsets, pass.functions), pass.align, mask);
    // Jumps that hold only low bits vote on those bits.
    const auto low = region_mask == 0 ? std::unordered_map<std::uint64_t, std::uint32_t>{}
                                      : votes(thinned(trace.region_targets, pass.pointers),
                                              thinned(trace.function_offsets, pass.functions), pass.align, region_mask);
    const Kind ks = best_of(s), kl = best_of(low);
    // The whole difference has to come from somewhere whole: strings, or
    // whole pointers to functions; low bits then join whichever they fit.
    for (const auto &[d, n] : low)
      if (ks.stands_out() && d == (ks.delta & region_mask)) f[ks.delta] += n;
    const Kind kf = best_of(f);
    if (std::getenv("RK_DETECT_DEBUG"))
      std::fprintf(stderr, "pass %llx: data %zu code %zu strings %zu functions %zu | s %llx %u/%u | f %llx %u/%u\n",
                   (unsigned long long)pass.align, to_data.size(), to_code.size(), strings.size(), trace.function_offsets.size(),
                   (unsigned long long)ks.delta, ks.hits, ks.next, (unsigned long long)kf.delta, kf.hits, kf.next);
    auto at = [](const std::unordered_map<std::uint64_t, std::uint32_t> &v, std::uint64_t d) {
      const auto it = v.find(d);
      return it == v.end() ? 0u : it->second;
    };
    // Two independent kinds of target, strings and function starts, ahead
    // at the same difference: by chance each kind's best is any of many.
    // (Small programs, and 8-bit ones, name few of either.)
    if (!ks.stands_out() && !kf.stands_out() && ks.leads() && kf.leads() && ks.delta == kf.delta &&
        ks.hits + kf.hits >= 12) {
      delta = ks.delta;
      out.string_hits = ks.hits, out.function_hits = kf.hits;
      out.string_next = ks.next, out.function_next = kf.next;
      next = ks.next + kf.next;
      out.base_confidence = Confidence::medium;
      break;
    }
    if (ks.stands_out() || kf.stands_out()) {
      // Where both stand out and disagree, the image is seen at two
      // addresses: chips that map their flash or ROM once for fetching
      // instructions and once for reading data (the ESP chips' instruction
      // and data buses) have code name its strings at the data bus's
      // address and its functions at the instruction bus's. The image runs
      // where its functions are; which is which isn't certain, so not
      // with high confidence.
      const bool aliased = ks.stands_out() && kf.stands_out() && ks.delta != kf.delta;
      const bool by_strings = ks.stands_out() && !kf.stands_out();
      delta = by_strings ? ks.delta : kf.delta;
      out.string_hits = at(s, *delta);
      out.function_hits = at(f, *delta);
      out.string_next = ks.delta == *delta ? ks.next : ks.hits;
      out.function_next = kf.delta == *delta ? kf.next : kf.hits;
      next = by_strings ? ks.next : kf.next;
      const bool both = ks.stands_out() && kf.stands_out() && ks.delta == kf.delta;
      const Kind &k = by_strings ? ks : kf;
      out.base_confidence = both || (k.hits >= 30 && k.hits >= 10 * std::max(k.next, 1u)) ? Confidence::high : Confidence::medium;
      if (aliased) {
        out.base_confidence = Confidence::medium;
        alias = ks.delta;
        alias_hits = ks.hits;
      }
      break;
    }
  }
  // Code that relocates itself compares where it runs (an address made
  // from the program counter) with where it was linked to: such a
  // comparison that agrees with the votes is evidence of another kind.
  // Alone it says little: code also compares where it is with where a
  // copy or a table ends.
  if (delta) {
    out.anchors = static_cast<std::uint64_t>(std::count(trace.anchors.begin(), trace.anchors.end(), *delta));
    if (out.anchors != 0 && !alias) out.base_confidence = Confidence::high;
  }
  if (!delta) return out;
  out.delta = delta;

  // base - offset is known; which of the two a header would account for
  // isn't in the pointers. Candidates for the offset, and what speaks for
  // each: a base at a round address, the place where padding or text ends
  // and code begins, a field before it holding the size of what follows.
  struct Split {
    std::uint64_t offset = 0;
    int support = 0;
    std::string why;
  };
  std::vector<Split> splits;
  // How many of the targets the pointers name at `delta` (strings and
  // function starts, as file offsets) lie before `limit`.
  std::vector<std::uint64_t> named;
  {
    auto named_by = [&](const std::vector<std::uint64_t> &pointers, const std::vector<std::uint64_t> &targets) {
      for (std::uint64_t t : targets)
        if (std::binary_search(pointers.begin(), pointers.end(), (*delta + t) & mask)) named.push_back(t);
    };
    named_by(to_data, strings);
    named_by(to_code, trace.function_offsets);
    std::sort(named.begin(), named.end());
  }
  auto matched_before = [&](std::uint64_t limit) {
    return static_cast<std::uint64_t>(std::lower_bound(named.begin(), named.end(), limit) - named.begin());
  };
  auto consider = [&](std::uint64_t offset) {
    if (offset >= file.size()) return;
    if (std::any_of(splits.begin(), splits.end(), [&](const Split &s) { return s.offset == offset; })) return;
    const std::uint64_t base = (*delta + offset) & mask;
    // The image has to fit below the top of the address space.
    if (mask != ~std::uint64_t{0} && base + (file.size() - offset) > mask + 1) return;
    Split s;
    s.offset = offset;
    const int zeros = base == 0 ? 64 : std::countr_zero(base);
    if (zeros >= 16) s.support += 2, s.why += "the base is a multiple of 64 KiB; ";
    else if (zeros >= 12) s.support += 1, s.why += "the base is a multiple of 4 KiB; ";
    if (offset != 0) {
      // Nothing before it could be code, and something before it is more
      // than fill: an image may well begin with erased flash, which is
      // part of it, not a header.
      // A header is small, and text and fields: compressed data before the
      // code is a payload, not a header.
      bool header_like = offset <= (64u << 10), content = false;
      for (const Segment &g : segments) {
        if (g.offset >= offset) continue;
        // What of the segment lies before the split (a segment may run on
        // past it: code that starts before a "header" ends isn't one).
        const std::uint64_t before = std::min(g.offset + g.size, offset) - g.offset;
        if (g.kind == Segment::Kind::code && before >= 2048) header_like = false;
        if (g.kind == Segment::Kind::high_entropy) header_like = false;
        if (g.kind != Segment::Kind::padding) content = true;
      }
      for (const Segment &g : segments)
        if (g.offset == offset && g.kind == Segment::Kind::code && header_like && content)
          s.support += 2, s.why += "a header's text and padding end and code begins there; ";
      // A size field: the bytes that follow, or the whole file.
      const std::uint64_t rest = file.size() - offset;
      for (std::uint64_t at = 0; at + 4 <= std::min<std::uint64_t>(offset, 4096); at += 4) {
        std::uint64_t word = 0;
        for (int k = 0; k < 4; ++k)
          word = word << 8 | static_cast<std::uint8_t>(file[at + (big_endian ? k : 3 - k)]);
        if (word == rest && rest > 0x100) {
          s.support += 2, s.why += "the word at " + hex(at) + " holds the size of what follows; ";
          break;
        }
      }
      if (!header_like) s.support -= 2;
      // The things the pointers name are in the image: a split that leaves
      // some of them out, in what it calls a header, is no split. (A few
      // may fall there by chance; more than one in fifty is no chance.)
      const std::uint64_t named = matched_before(offset), all = matched_before(file.size());
      if (all != 0 && named * 50 > all) return;
    }
    splits.push_back(std::move(s));
  };
  consider(0);
  if (const std::uint64_t round = (0 - *delta) & 0xfff; round != 0) consider(round);
  if (const std::uint64_t round = (0 - *delta) & 0xffff; round != 0) consider(round);
  for (const Segment &g : segments)
    if (g.kind == Segment::Kind::code && g.offset != 0 && g.offset <= (1u << 20)) {
      consider(g.offset);
      break;  // the first code after something else
    }
  if (splits.empty()) {
    out.delta.reset();
    return out;
  }
  std::stable_sort(splits.begin(), splits.end(), [](const Split &a, const Split &b) {
    return a.support != b.support ? a.support > b.support : a.offset < b.offset;
  });
  const Split &best = splits[0];
  out.offset = best.offset;
  out.base = (*delta + best.offset) & mask;
  const int margin = best.support - (splits.size() > 1 ? splits[1].support : -1);
  // High only when nothing else is nearly as good: two round bases a
  // stretch of fill apart are both right about where the code lands.
  out.offset_confidence = best.support >= 2 && margin >= 3 ? Confidence::high
                          : best.support >= 1 && margin >= 1 ? Confidence::medium
                                                              : Confidence::low;

  std::string text;
  if (out.anchors != 0)
    text += std::to_string(out.anchors) + (out.anchors == 1 ? " place" : " places") +
            " where the code compares where it runs with where it was linked to run" +
            (out.anchors == 1 ? " agrees; " : " agree; ");
  if (out.string_hits != 0)
    text += std::to_string(out.string_hits) + " addresses in the code and in tables are the starts of strings";
  if (out.function_hits != 0)
    text += std::string(text.empty() ? "" : " and ") + std::to_string(out.function_hits) + " are where functions start";
  text += " if the image is at " + hex(out.base);
  if (out.offset != 0) text += " from file offset " + hex(out.offset);
  text += "; the next best placement explains " + std::to_string(next);
  if (alias)
    text += "; but " + std::to_string(alias_hits) + " addresses name strings as if the image were at " +
            hex((*alias + out.offset) & mask) +
            ": the image is seen at two addresses (as through a chip's instruction and data buses), and runs where "
            "its functions are";
  out.evidence.push_back({"base", std::move(text)});
  std::string why = best.why.empty() ? "nothing says otherwise" : best.why.substr(0, best.why.size() - 2);
  out.evidence.push_back({"offset", (out.offset == 0 ? "the image starts at the start of the file: " : "the image starts at " + hex(out.offset) + ": ") + why});
  return out;
}

}  // namespace revkit::detect
