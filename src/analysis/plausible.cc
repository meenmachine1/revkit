// What isn't code, whatever it decodes to: text, fill, random bytes, zeroed
// words. On a raw image nothing marks data, and nearly every byte sequence
// decodes on ARM and Thumb, so a candidate that only a pattern, a pointer
// or other unproven code vouches for is checked against what its bytes are
// (Discovery::credible, find_code).

#include "internal.h"

#include <algorithm>
#include <array>
#include <cmath>

namespace revkit::analysis::detail {

Known::Known(const SearchInput &in) : data(in.data), insns_(&in.code) {
  std::vector<Range> ranges;
  ranges.reserve(in.code.size());
  for (const SearchInput::Insn &i : in.code)
    if (i.length != 0) ranges.push_back({i.address, i.address + i.length - 1});
  code = Ranges(std::move(ranges));
}

const SearchInput::Insn *Known::covering(std::uint64_t a) const {
  auto it = std::upper_bound(insns_->begin(), insns_->end(), a,
                             [](std::uint64_t x, const SearchInput::Insn &i) { return x < i.address; });
  // Instructions of different flows can overlap: look a few back.
  for (int n = 0; n < 4 && it != insns_->begin(); ++n) {
    --it;
    if (a - it->address < it->length) return &*it;
  }
  return nullptr;
}

const SearchInput::Insn *Known::at(std::uint64_t a) const {
  auto it = std::lower_bound(insns_->begin(), insns_->end(), a,
                             [](const SearchInput::Insn &i, std::uint64_t x) { return i.address < x; });
  return it != insns_->end() && it->address == a ? &*it : nullptr;
}

std::optional<bool> Known::thumb_before(std::uint64_t a) const {
  auto it = std::lower_bound(insns_->begin(), insns_->end(), a,
                             [](const SearchInput::Insn &i, std::uint64_t x) { return i.address < x; });
  if (it == insns_->begin()) return std::nullopt;
  return std::prev(it)->thumb;
}

namespace {

bool printable(std::uint8_t c) { return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r'; }

constexpr std::size_t kMinString = 4;
// How far around the bytes asked about a string is followed.
constexpr std::uint64_t kStringReach = 64;

}  // namespace

TextBytes text_bytes(ByteReader &bytes, std::uint64_t first, std::uint64_t last) {
  TextBytes out;
  if (last < first) return out;
  const std::uint64_t lo = first >= kStringReach ? first - kStringReach : 0;
  const std::uint64_t want = last - lo + 1 + kStringReach;
  if (want > (std::uint64_t{1} << 20)) return out;
  auto b = bytes.read(lo, static_cast<std::size_t>(want));
  auto at = [&](std::size_t i) { return std::to_integer<std::uint8_t>(b[i]); };
  std::vector<std::uint8_t> text(b.size(), 0);
  for (std::size_t i = 0; i < b.size();) {
    if (!printable(at(i))) {
      ++i;
      continue;
    }
    std::size_t end = i;
    while (end < b.size() && printable(at(end))) ++end;
    // A string: terminated, or cut off by the window after a long run.
    const bool terminated = end < b.size() ? at(end) == 0 : end - i >= 4 * kMinString;
    if (end - i >= kMinString && terminated) {
      // Its terminator and the padding to the next word count too.
      std::size_t stop = end;
      while (stop < b.size() && at(stop) == 0 && stop - end < 4) ++stop;
      std::fill(text.begin() + static_cast<std::ptrdiff_t>(i), text.begin() + static_cast<std::ptrdiff_t>(stop), 1);
      i = stop;
    } else {
      i = end;
    }
  }
  std::size_t run = 0;
  for (std::uint64_t a = first; a <= last && a - lo < b.size(); ++a) {
    if (text[static_cast<std::size_t>(a - lo)]) {
      ++out.total;
      out.longest = std::max(out.longest, ++run);
    } else {
      run = 0;
    }
    if (a == ~std::uint64_t{0}) break;
  }
  return out;
}

bool starts_in_text(ByteReader &bytes, std::uint64_t a) {
  constexpr std::uint64_t kWindow = 32;
  if (a > ~std::uint64_t{0} - kWindow) return false;
  if (text_bytes(bytes, a, a + 7).total != 8) return false;
  const TextBytes t = text_bytes(bytes, a, a + kWindow - 1);
  return 4 * t.total >= 3 * kWindow;
}

bool high_entropy(ByteReader &bytes, std::uint64_t a) {
  constexpr std::size_t kWindow = 256;
  auto b = bytes.read(a, kWindow);
  if (b.size() < kWindow) return false;
  std::array<unsigned, 256> count{};
  for (std::byte x : b) ++count[std::to_integer<std::uint8_t>(x)];
  double h = 0;
  for (unsigned c : count)
    if (c != 0) {
      const double p = static_cast<double>(c) / kWindow;
      h -= p * std::log2(p);
    }
  // 256 random bytes have about 7.17 bits a byte (never 8: there are only
  // 256 samples); machine code stays below 6.7 in a window this size.
  return h > 7.0;
}

bool zero_instruction(const lift::Instruction &insn, ByteReader &bytes) {
  if (insn.pcode.empty() || insn.length == 0) return false;
  auto b = bytes.read(insn.address, insn.length);
  return b.size() == insn.length && std::all_of(b.begin(), b.end(), [](std::byte x) { return x == std::byte{0}; });
}

}  // namespace revkit::analysis::detail
