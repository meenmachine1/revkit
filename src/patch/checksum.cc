// Checksum algorithms and the rule detector.

#include "revkit/patch/checksum.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>

namespace revkit::patch {

namespace {

struct CrcParams {
  unsigned width;
  std::uint32_t poly, init, xorout;
  bool reflect;
};

std::uint32_t reflect_bits(std::uint32_t v, unsigned width) {
  std::uint32_t r = 0;
  for (unsigned i = 0; i < width; ++i)
    if (v & (1u << i)) r |= 1u << (width - 1 - i);
  return r;
}

// Table-driven CRC (Rocksoft model) for widths 16 and 32.
class Crc {
 public:
  explicit Crc(const CrcParams &p) : p_(p) {
    const std::uint32_t top = 1u << (p.width - 1);
    const std::uint32_t mask = p.width == 32 ? 0xffffffffu : (1u << p.width) - 1;
    for (std::uint32_t b = 0; b < 256; ++b) {
      if (p.reflect) {
        const std::uint32_t poly = reflect_bits(p.poly, p.width);
        std::uint32_t c = b;
        for (int k = 0; k < 8; ++k) c = (c & 1) ? (c >> 1) ^ poly : c >> 1;
        table_[b] = c & mask;
      } else {
        std::uint32_t c = b << (p.width - 8);
        for (int k = 0; k < 8; ++k) c = (c & top) ? (c << 1) ^ p.poly : c << 1;
        table_[b] = c & mask;
      }
    }
  }
  std::uint32_t operator()(std::span<const std::uint8_t> data) const {
    const std::uint32_t mask = p_.width == 32 ? 0xffffffffu : (1u << p_.width) - 1;
    std::uint32_t c = p_.init;
    if (p_.reflect) {
      for (std::uint8_t b : data) c = (c >> 8) ^ table_[(c ^ b) & 0xff];
    } else {
      const unsigned sh = p_.width - 8;
      for (std::uint8_t b : data) c = ((c << 8) ^ table_[((c >> sh) ^ b) & 0xff]) & mask;
    }
    return (c ^ p_.xorout) & mask;
  }

 private:
  CrcParams p_;
  std::array<std::uint32_t, 256> table_{};
};

const Crc &crc_for(Algorithm a) {
  static const std::map<Algorithm, Crc> crcs = [] {
    std::map<Algorithm, Crc> m;
    m.emplace(Algorithm::crc16_ccitt_false, Crc({16, 0x1021, 0xffff, 0, false}));
    m.emplace(Algorithm::crc16_xmodem, Crc({16, 0x1021, 0, 0, false}));
    m.emplace(Algorithm::crc16_kermit, Crc({16, 0x1021, 0, 0, true}));
    m.emplace(Algorithm::crc16_modbus, Crc({16, 0x8005, 0xffff, 0, true}));
    m.emplace(Algorithm::crc16_arc, Crc({16, 0x8005, 0, 0, true}));
    m.emplace(Algorithm::crc32, Crc({32, 0x04c11db7, 0xffffffff, 0xffffffff, true}));
    m.emplace(Algorithm::crc32_bzip2, Crc({32, 0x04c11db7, 0xffffffff, 0xffffffff, false}));
    m.emplace(Algorithm::crc32_mpeg2, Crc({32, 0x04c11db7, 0xffffffff, 0, false}));
    m.emplace(Algorithm::crc32_posix, Crc({32, 0x04c11db7, 0, 0xffffffff, false}));
    m.emplace(Algorithm::crc32_jamcrc, Crc({32, 0x04c11db7, 0xffffffff, 0, true}));
    m.emplace(Algorithm::crc32c, Crc({32, 0x1edc6f41, 0xffffffff, 0xffffffff, true}));
    return m;
  }();
  return crcs.at(a);
}

const std::vector<std::pair<Algorithm, std::string_view>> &names() {
  static const std::vector<std::pair<Algorithm, std::string_view>> n = {
      {Algorithm::sum8, "sum8"},
      {Algorithm::sum16, "sum16"},
      {Algorithm::sum32, "sum32"},
      {Algorithm::sum16_words_le, "sum16-words-le"},
      {Algorithm::sum16_words_be, "sum16-words-be"},
      {Algorithm::sum32_words_le, "sum32-words-le"},
      {Algorithm::sum32_words_be, "sum32-words-be"},
      {Algorithm::sum8_neg, "sum8-neg"},
      {Algorithm::sum32_neg, "sum32-neg"},
      {Algorithm::xor8, "xor8"},
      {Algorithm::fletcher16, "fletcher16"},
      {Algorithm::fletcher32, "fletcher32"},
      {Algorithm::adler32, "adler32"},
      {Algorithm::crc16_ccitt_false, "crc16-ccitt-false"},
      {Algorithm::crc16_xmodem, "crc16-xmodem"},
      {Algorithm::crc16_kermit, "crc16-kermit"},
      {Algorithm::crc16_modbus, "crc16-modbus"},
      {Algorithm::crc16_arc, "crc16-arc"},
      {Algorithm::crc32, "crc32"},
      {Algorithm::crc32_bzip2, "crc32-bzip2"},
      {Algorithm::crc32_mpeg2, "crc32-mpeg2"},
      {Algorithm::crc32_posix, "crc32-posix"},
      {Algorithm::crc32_jamcrc, "crc32-jamcrc"},
      {Algorithm::crc32c, "crc32c"},
      {Algorithm::pe, "pe"},
  };
  return n;
}

std::string hex(std::uint64_t v, unsigned digits) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%0*llX", static_cast<int>(digits), static_cast<unsigned long long>(v));
  return buf;
}

std::string off(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::uint64_t mask_of(unsigned bits) { return bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << bits) - 1; }

}  // namespace

std::string_view name(Algorithm a) {
  for (const auto &[k, n] : names())
    if (k == a) return n;
  return "none";
}

std::optional<Algorithm> parse_algorithm(std::string_view n) {
  for (const auto &[k, v] : names())
    if (v == n) return k;
  return std::nullopt;
}

unsigned width_bits(Algorithm a) {
  switch (a) {
    case Algorithm::sum8:
    case Algorithm::sum8_neg:
    case Algorithm::xor8: return 8;
    case Algorithm::sum16:
    case Algorithm::sum16_words_le:
    case Algorithm::sum16_words_be:
    case Algorithm::fletcher16:
    case Algorithm::crc16_ccitt_false:
    case Algorithm::crc16_xmodem:
    case Algorithm::crc16_kermit:
    case Algorithm::crc16_modbus:
    case Algorithm::crc16_arc: return 16;
    default: return 32;
  }
}

const std::vector<Algorithm> &all_algorithms() {
  static const std::vector<Algorithm> all = [] {
    std::vector<Algorithm> v;
    for (const auto &[k, n] : names())
      if (k != Algorithm::pe) v.push_back(k);
    return v;
  }();
  return all;
}

std::uint64_t compute(Algorithm a, std::span<const std::uint8_t> b) {
  switch (a) {
    case Algorithm::none: return 0;
    case Algorithm::sum8:
    case Algorithm::sum16:
    case Algorithm::sum32:
    case Algorithm::sum8_neg:
    case Algorithm::sum32_neg: {
      std::uint64_t s = 0;
      for (std::uint8_t x : b) s += x;
      if (a == Algorithm::sum8_neg) return (~s + 1) & 0xff;
      if (a == Algorithm::sum32_neg) return (~s + 1) & 0xffffffff;
      return s & mask_of(width_bits(a));
    }
    case Algorithm::sum16_words_le:
    case Algorithm::sum16_words_be: {
      std::uint64_t s = 0;
      const bool be = a == Algorithm::sum16_words_be;
      for (std::size_t i = 0; i < b.size(); i += 2) {
        const std::uint64_t lo = b[i], hi = i + 1 < b.size() ? b[i + 1] : 0;
        s += be ? (lo << 8) | hi : (hi << 8) | lo;
      }
      return s & 0xffff;
    }
    case Algorithm::sum32_words_le:
    case Algorithm::sum32_words_be: {
      std::uint64_t s = 0;
      const bool be = a == Algorithm::sum32_words_be;
      for (std::size_t i = 0; i < b.size(); i += 4) {
        std::uint64_t w = 0;
        for (std::size_t k = 0; k < 4; ++k) {
          const std::uint64_t x = i + k < b.size() ? b[i + k] : 0;
          w |= be ? x << (8 * (3 - k)) : x << (8 * k);
        }
        s += w;
      }
      return s & 0xffffffff;
    }
    case Algorithm::xor8: {
      std::uint8_t x = 0;
      for (std::uint8_t y : b) x ^= y;
      return x;
    }
    case Algorithm::fletcher16: {
      std::uint32_t s1 = 0, s2 = 0;
      for (std::uint8_t x : b) {
        s1 = (s1 + x) % 255;
        s2 = (s2 + s1) % 255;
      }
      return (s2 << 8) | s1;
    }
    case Algorithm::fletcher32: {
      std::uint64_t s1 = 0, s2 = 0;
      for (std::size_t i = 0; i < b.size(); i += 2) {
        const std::uint64_t w = b[i] | (i + 1 < b.size() ? std::uint64_t{b[i + 1]} << 8 : 0);
        s1 = (s1 + w) % 65535;
        s2 = (s2 + s1) % 65535;
      }
      return (s2 << 16) | s1;
    }
    case Algorithm::adler32: {
      std::uint64_t s1 = 1, s2 = 0;
      for (std::uint8_t x : b) {
        s1 = (s1 + x) % 65521;
        s2 = (s2 + s1) % 65521;
      }
      return (s2 << 16) | s1;
    }
    case Algorithm::pe: return pe_checksum(b).value_or(0);
    default: return crc_for(a)(b);
  }
}

std::optional<std::pair<std::uint64_t, std::uint64_t>> resolve_range(const Spec &s, std::span<const std::uint8_t> file) {
  const std::uint64_t n = file.size();
  std::uint64_t end = n;
  if (s.end > 0) end = static_cast<std::uint64_t>(s.end);
  else if (s.end < 0) end = static_cast<std::uint64_t>(-s.end) <= n ? n - static_cast<std::uint64_t>(-s.end) : 0;
  if (end > n || s.start > end) return std::nullopt;
  if (s.skip_padding) {
    const std::uint8_t pad = end > s.start ? file[end - 1] : 0;
    if (pad == 0xff || pad == 0x00)
      while (end > s.start && file[end - 1] == pad) --end;
  }
  return std::pair{s.start, end};
}

std::optional<std::uint64_t> evaluate(const Spec &s, std::span<const std::uint8_t> file) {
  if (s.algorithm == Algorithm::pe) return pe_checksum(file);
  auto r = resolve_range(s, file);
  if (!r) return std::nullopt;
  std::span<const std::uint8_t> range = file.subspan(r->first, r->second - r->first);
  if (s.field && s.field_offset < r->second && s.field_offset + s.field_width > r->first) {
    std::vector<std::uint8_t> copy(range.begin(), range.end());
    for (unsigned i = 0; i < s.field_width; ++i) {
      const std::uint64_t at = s.field_offset + i;
      if (at >= r->first && at < r->second) copy[at - r->first] = 0;
    }
    return compute(s.algorithm, copy);
  }
  return compute(s.algorithm, range);
}

bool write_field(const Spec &s, std::uint64_t value, std::span<std::uint8_t> file) {
  if (!s.field || s.field_width == 0 || s.field_width > 8 || s.field_offset + s.field_width > file.size()) return false;
  for (unsigned i = 0; i < s.field_width; ++i) {
    const unsigned sh = s.field_big_endian ? 8 * (s.field_width - 1 - i) : 8 * i;
    file[s.field_offset + i] = static_cast<std::uint8_t>(value >> sh);
  }
  return true;
}

std::string describe(const Spec &s) {
  if (s.algorithm == Algorithm::pe) return "PE optional header CheckSum";
  std::string out(name(s.algorithm));
  out += " over " + off(s.start) + "..";
  if (s.end == 0) out += "EOF";
  else if (s.end < 0) out += "EOF-" + off(static_cast<std::uint64_t>(-s.end));
  else out += off(static_cast<std::uint64_t>(s.end));
  if (s.skip_padding) out += " (without trailing padding)";
  if (s.field)
    out += " into " + off(s.field_offset) + " (" + std::to_string(s.field_width) + " bytes, " +
           (s.field_big_endian ? "big" : "little") + "-endian)";
  if (s.name) out += " into the file name";
  return out;
}

std::optional<std::uint64_t> pe_checksum_offset(std::span<const std::uint8_t> file) {
  if (file.size() < 0x40 || file[0] != 'M' || file[1] != 'Z') return std::nullopt;
  const std::uint32_t lfanew = file[0x3c] | file[0x3d] << 8 | file[0x3e] << 16 | static_cast<std::uint32_t>(file[0x3f]) << 24;
  if (lfanew > file.size() || file.size() - lfanew < 24 + 68) return std::nullopt;
  if (file[lfanew] != 'P' || file[lfanew + 1] != 'E' || file[lfanew + 2] || file[lfanew + 3]) return std::nullopt;
  return std::uint64_t{lfanew} + 24 + 64;  // optional header + 64: CheckSum, for PE32 and PE32+
}

std::optional<std::uint32_t> pe_checksum(std::span<const std::uint8_t> file) {
  auto at = pe_checksum_offset(file);
  if (!at) return std::nullopt;
  std::uint64_t sum = 0;
  for (std::size_t i = 0; i < file.size(); i += 2) {
    if (i >= *at && i < *at + 4) continue;
    const std::uint64_t w = file[i] | (i + 1 < file.size() ? std::uint64_t{file[i + 1]} << 8 : 0);
    sum += w;
    sum = (sum & 0xffff) + (sum >> 16);
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<std::uint32_t>((sum & 0xffff) + file.size());
}

std::vector<std::pair<std::uint64_t, std::string>> values_in_name(std::string_view file_name) {
  std::vector<std::pair<std::uint64_t, std::string>> out;
  // Only the name: no directories.
  if (auto slash = file_name.find_last_of("/\\"); slash != std::string_view::npos) file_name.remove_prefix(slash + 1);
  std::size_t i = 0;
  while (i < file_name.size()) {
    if (!std::isxdigit(static_cast<unsigned char>(file_name[i]))) {
      ++i;
      continue;
    }
    std::size_t j = i;
    while (j < file_name.size() && std::isxdigit(static_cast<unsigned char>(file_name[j]))) ++j;
    const bool word_before = i > 0 && std::isalnum(static_cast<unsigned char>(file_name[i - 1]));
    const bool word_after = j < file_name.size() && std::isalnum(static_cast<unsigned char>(file_name[j]));
    const std::size_t len = j - i;
    if (!word_before && !word_after && (len == 8 || len == 4)) {
      const std::string run(file_name.substr(i, len));
      out.emplace_back(std::stoull(run, nullptr, 16), "the file name's \"" + run + "\"");
    }
    i = j;
  }
  return out;
}

DetectResult detect(std::span<const std::uint8_t> file, const DetectOptions &o) {
  DetectResult result;
  const std::uint64_t n = file.size();
  if (n == 0) return result;
  // Candidate ranges.
  std::set<std::pair<std::uint64_t, std::uint64_t>> ranges;
  auto trimmed = [&](std::uint64_t a, std::uint64_t b) {
    std::uint64_t e = b;
    const std::uint8_t pad = file[b - 1];
    if (pad == 0xff || pad == 0x00)
      while (e > a && file[e - 1] == pad) --e;
    return e;
  };
  std::vector<std::uint64_t> starts{0};
  if (o.image_offset > 0 && o.image_offset < n) starts.push_back(o.image_offset);
  for (std::uint64_t s : starts) {
    ranges.insert({s, n});
    if (std::uint64_t e = trimmed(s, n); e > s && e < n) ranges.insert({s, e});
    for (unsigned w : {2u, 4u})
      if (n - s > w) ranges.insert({s, n - w});  // a trailing checksum
  }
  // Lengths a header declares.
  const std::uint64_t header = std::min(o.header_bytes, n);
  std::set<std::uint64_t> lengths;
  for (std::uint64_t at = 0; at + 4 <= header; at += 4) {
    const std::uint64_t le = file[at] | file[at + 1] << 8 | file[at + 2] << 16 | std::uint64_t{file[at + 3]} << 24;
    const std::uint64_t be = std::uint64_t{file[at]} << 24 | file[at + 1] << 16 | file[at + 2] << 8 | file[at + 3];
    for (std::uint64_t v : {le, be})
      if (v >= n / 2 && v <= n) lengths.insert(v);
  }
  for (std::uint64_t len : lengths)
    for (std::uint64_t s : starts)
      if (s + len <= n && lengths.size() <= 16) ranges.insert({s, s + len});

  // Header words as stored values: (width bits, value) -> (offset, big-endian).
  std::unordered_map<std::uint64_t, std::vector<std::pair<std::uint64_t, bool>>> words16, words32;
  auto word = [&](std::uint64_t at, unsigned w, bool be) {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < w; ++i) v |= std::uint64_t{file[at + i]} << (be ? 8 * (w - 1 - i) : 8 * i);
    return v;
  };
  auto add_word = [&](std::uint64_t at) {
    for (bool be : {false, true}) {
      if (at + 2 <= n && at % 2 == 0) {
        const std::uint64_t v = word(at, 2, be);
        if (v != 0 && v != 0xffff) words16[v].emplace_back(at, be);
      }
      if (at + 4 <= n && at % 4 == 0) {
        const std::uint64_t v = word(at, 4, be);
        if (v != 0 && v != 0xffffffff) words32[v].emplace_back(at, be);
      }
    }
  };
  for (std::uint64_t at = 0; at + 2 <= header; at += 2) add_word(at);
  for (unsigned w : {2u, 4u})
    if (n >= w) add_word(n - w);

  auto add_hit = [&](Spec spec, std::uint64_t value, std::string evidence) {
    for (const Hit &h : result.hits)
      if (h.spec == spec) return;
    if (result.hits.size() < o.max_hits) result.hits.push_back({spec, value, std::move(evidence)});
  };
  // Ranges that end where trailing padding starts are "to EOF, skipping
  // padding", so the rule survives a file of another length.
  std::set<std::pair<std::uint64_t, std::uint64_t>> padded;
  for (std::uint64_t s : starts)
    if (std::uint64_t e = trimmed(s, n); e > s && e < n) padded.insert({s, e});
  for (const auto &[a, b] : ranges) {
    const std::span<const std::uint8_t> data = file.subspan(a, b - a);
    for (Algorithm alg : all_algorithms()) {
      const std::uint64_t v = compute(alg, data);
      ++result.tried;
      const unsigned bits = width_bits(alg);
      Spec spec;
      spec.algorithm = alg;
      spec.start = a;
      spec.end = b == n ? 0 : static_cast<std::int64_t>(b);
      if (padded.contains({a, b})) {
        spec.end = 0;
        spec.skip_padding = true;
      } else if (b < n && b >= n - 4 && file.size() - b <= 4) {
        spec.end = -static_cast<std::int64_t>(n - b);
      }
      for (const auto &[value, where] : o.expected) {
        if ((value & mask_of(bits)) != v || (bits < 32 && value > mask_of(bits))) continue;
        Spec s = spec;
        s.name = true;
        add_hit(s, v, describe(spec) + " = " + hex(v, bits / 4) + ", " + where);
      }
      // A stored value outside the range.
      const auto &words = bits == 32 ? words32 : bits == 16 ? words16 : words16;
      if (bits == 8) continue;  // too many chance matches
      auto it = words.find(v);
      if (it == words.end()) continue;
      for (const auto &[at, be] : it->second) {
        const unsigned w = bits / 8;
        if (at < b && at + w > a) continue;  // inside the range: see below
        Spec s = spec;
        s.field = true;
        s.field_offset = at;
        s.field_width = w;
        s.field_big_endian = be;
        add_hit(s, v, describe(s) + " = " + hex(v, bits / 4) + ", stored there");
      }
    }
    // Additive byte sums with the stored field inside the range (read as zero).
    std::uint64_t total = 0;
    for (std::uint8_t x : data) total += x;
    for (const auto &[w, words] : {std::pair{4u, &words32}, std::pair{2u, &words16}}) {
      for (const auto &[value, places] : *words)
        for (const auto &[at, be] : places) {
          if (at < a || at + w > b) continue;
          std::uint64_t field = 0;
          for (unsigned i = 0; i < w; ++i) field += file[at + i];
          const std::uint64_t s = total - field;
          for (Algorithm alg : {Algorithm::sum32, Algorithm::sum16, Algorithm::sum32_neg}) {
            if ((alg == Algorithm::sum16) != (w == 2)) continue;
            const std::uint64_t v = alg == Algorithm::sum32_neg ? (~s + 1) & 0xffffffff : s & mask_of(width_bits(alg));
            if (v != value) continue;
            Spec sp;
            sp.algorithm = alg;
            sp.start = a;
            sp.end = b == n ? 0 : static_cast<std::int64_t>(b);
            sp.field = true;
            sp.field_offset = at;
            sp.field_width = w;
            sp.field_big_endian = be;
            add_hit(sp, v, describe(sp) + " = " + hex(v, width_bits(alg) / 4) + ", stored there");
          }
        }
    }
  }
  // Name rules (what the caller expected) first, then 32-bit fields, then
  // the rest; within each, the simplest range: the whole file before a
  // slice, to EOF before a fixed end, without skipping padding before with.
  std::stable_sort(result.hits.begin(), result.hits.end(), [](const Hit &x, const Hit &y) {
    auto rank = [](const Hit &h) {
      return std::tuple{h.spec.name ? 0 : width_bits(h.spec.algorithm) == 32 ? 1 : 2, h.spec.end != 0, h.spec.start != 0,
                        h.spec.skip_padding};
    };
    return rank(x) < rank(y);
  });
  return result;
}

}  // namespace revkit::patch
