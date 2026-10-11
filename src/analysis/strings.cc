// Ghidra's ASCII Strings analyzer (StringsAnalyzer, StringSearcher,
// MultiByteCharMatcher, NGramUtils), and its string labels.

#include "data_internal.h"

#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <array>
#include <tuple>
#include <cmath>
#include <fstream>
#include <memory>
#include <mutex>

namespace revkit::analysis {

namespace {

// ---- the n-gram model ----

constexpr int kChars = 128;

// NGramUtils.NG_THRESHOLDS: by scored length; 100 and up use -6.3.
constexpr double kThresholds[] = {
    10.0,  10.0,  10.0,  10.0,  -2.71, -3.26, -3.52, -3.84, -4.23, -4.49, -4.55, -4.74, -4.88, -5.03, -5.06,
    -5.2,  -5.24, -5.29, -5.29, -5.42, -5.51, -5.52, -5.53, -5.6,  -5.6,  -5.62, -5.7,  -5.7,  -5.78, -5.79,
    -5.81, -5.81, -5.84, -5.85, -5.86, -5.88, -5.92, -5.92, -5.93, -5.95, -5.99, -6.0,  -6.0,  -6.0,  -6.02,
    -6.02, -6.02, -6.05, -6.06, -6.07, -6.08, -6.1,  -6.12, -6.12, -6.13, -6.13, -6.13, -6.13, -6.13, -6.13,
    -6.13, -6.15, -6.15, -6.16, -6.16, -6.16, -6.17, -6.19, -6.19, -6.21, -6.21, -6.21, -6.21, -6.21, -6.21,
    -6.25, -6.25, -6.25, -6.25, -6.25, -6.25, -6.25, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26,
    -6.26, -6.29, -6.29, -6.3,  -6.3,  -6.3,  -6.3,  -6.3,  -6.3,  -6.3,  -6.3};
constexpr double kMaxThreshold = -6.3;
// StringsAnalyzer.ABSOLUTE_MIN_STR_LENGTH, read before any model loads.
constexpr std::size_t kMinScored = 3;

struct Model {
  bool lowercase = false;
  std::vector<double> begin, end, tri;  // [a][b], [a][b], [a][b][c] log10 probabilities

  double b(int x, int y) const { return begin[x * kChars + y]; }
  double e(int x, int y) const { return end[x * kChars + y]; }
  double t(int x, int y, int z) const { return tri[(x * kChars + y) * kChars + z]; }
};

int char_code(const std::string &s) {
  static const std::pair<const char *, int> kNames[] = {
      {"[NUL]", 0},  {"[SOH]", 1},  {"[STX]", 2},  {"[ETX]", 3},  {"[EOT]", 4},  {"[ENQ]", 5},  {"[ACK]", 6},
      {"[BEL]", 7},  {"[BS]", 8},   {"[HT]", 9},   {"[LF]", 10},  {"[VT]", 11},  {"[FF]", 12},  {"[CR]", 13},
      {"[SO]", 14},  {"[SI]", 15},  {"[DLE]", 16}, {"[DC1]", 17}, {"[DC2]", 18}, {"[DC3]", 19}, {"[DC4]", 20},
      {"[NAK]", 21}, {"[SYN]", 22}, {"[ETB]", 23}, {"[CAN]", 24}, {"[EM]", 25},  {"[SUB]", 26}, {"[ESC]", 27},
      {"[FS]", 28},  {"[GS]", 29},  {"[RS]", 30},  {"[US]", 31},  {"[SP]", 32},  {"[DEL]", 127}};
  if (s.size() == 1) return static_cast<unsigned char>(s[0]) < kChars ? static_cast<unsigned char>(s[0]) : -1;
  if (s == "[^]") return -2;
  if (s == "[$]") return -3;
  for (const auto &[name, code] : kNames)
    if (s == name) return code;
  return -1;
}

std::unique_ptr<Model> load_model() {
  auto root = lift::ghidra_root();
  if (!root) return nullptr;
  std::ifstream in(*root / "Ghidra/Features/Base/data/stringngrams/StringModel.sng");
  if (!in) return nullptr;
  std::vector<std::int64_t> begin(kChars * kChars), end(kChars * kChars), tri(kChars * kChars * kChars);
  std::int64_t total = 0;
  bool typed = false, lowercase = false;
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.starts_with("#")) {
      constexpr std::string_view kType = "Model Type: ";
      if (auto p = line.find(kType); p != std::string::npos) {
        typed = true;
        std::string t = line.substr(kType.size() + 2);  // as NGramUtils cuts it
        for (char &c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        lowercase = t == "lowercase";
      }
      continue;
    }
    bool blank = true;
    for (char c : line) blank = blank && static_cast<unsigned char>(c) <= 0x20;
    if (blank) continue;
    std::vector<std::string> parts;
    std::size_t s = 0;
    for (std::size_t p; (p = line.find('\t', s)) != std::string::npos; s = p + 1) parts.push_back(line.substr(s, p - s));
    parts.push_back(line.substr(s));
    if (parts.size() != 4) return nullptr;
    const std::int64_t count = std::stoll(parts[3]);
    const int a = char_code(parts[0]), b = char_code(parts[1]), c = char_code(parts[2]);
    if (a == -2) {
      if (c != -3) {
        if (b < 0 || c < 0) return nullptr;
        begin[b * kChars + c] += count;
      }
    } else if (c == -3) {
      if (a < 0 || b < 0) return nullptr;
      end[a * kChars + b] += count;
    } else {
      if (a < 0 || b < 0 || c < 0) return nullptr;
      tri[(a * kChars + b) * kChars + c] += count;
    }
    total += count;
  }
  if (!typed) return nullptr;
  // Smoothing: unseen n-grams count once.
  for (auto *v : {&begin, &end, &tri})
    for (std::int64_t &x : *v)
      if (x == 0) {
        x = 1;
        ++total;
      }
  auto m = std::make_unique<Model>();
  m->lowercase = lowercase;
  auto logs = [&](const std::vector<std::int64_t> &v) {
    std::vector<double> out(v.size());
    for (std::size_t i = 0; i < v.size(); ++i)
      out[i] = std::log10(static_cast<double>(v[i]) / static_cast<double>(total));
    return out;
  };
  m->begin = logs(begin);
  m->end = logs(end);
  m->tri = logs(tri);
  return m;
}

const Model *model() {
  static std::once_flag once;
  static std::unique_ptr<Model> m;
  std::call_once(once, [] {
    try {
      m = load_model();
    } catch (const std::exception &) {
      m = nullptr;
    }
  });
  return m.get();
}

// StringAndScores: lower-cased (for a lower-case model), non-ASCII as
// spaces, trimmed (Java's trim: everything up to ' '), runs of spaces and
// of tabs collapsed.
std::string scored(std::string_view text, bool lowercase) {
  std::string s;
  s.reserve(text.size());
  for (char ch : text) {
    auto c = static_cast<unsigned char>(ch);
    if (c > 127) c = ' ';
    if (lowercase && c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
    s.push_back(static_cast<char>(c));
  }
  std::size_t a = 0, b = s.size();
  while (a < b && static_cast<unsigned char>(s[a]) <= 0x20) ++a;
  while (b > a && static_cast<unsigned char>(s[b - 1]) <= 0x20) --b;
  std::string out;
  out.reserve(b - a);
  for (std::size_t i = a; i < b; ++i) {
    if ((s[i] == ' ' || s[i] == '\t') && !out.empty() && out.back() == s[i] && i > a && s[i - 1] == s[i]) continue;
    out.push_back(s[i]);
  }
  return out;
}

}  // namespace

bool ngram_model_available() { return model() != nullptr; }

bool ngram_valid_string(std::string_view text) {
  const Model *m = model();
  if (m == nullptr) return false;
  const std::string s = scored(text, m->lowercase);
  const std::size_t n = s.size();
  if (n < kMinScored) return false;
  double score = -20.0;
  if (n >= 3) {
    auto c = [&](std::size_t i) { return static_cast<int>(static_cast<unsigned char>(s[i])); };
    double sum = m->b(c(0), c(1));
    std::size_t i = 1;
    for (; i + 2 < n; ++i) sum += m->t(c(i), c(i + 1), c(i + 2));
    sum += m->e(c(i), c(i + 1));
    score = sum / static_cast<double>(n);
  }
  const double threshold = n >= std::size(kThresholds) ? kMaxThreshold : kThresholds[n];
  return score > threshold;
}

std::string string_label(std::string_view prefix, std::string_view utf8) {
  std::string out(prefix);
  std::string buf;
  bool underscore = false;
  for (std::size_t i = 0; i < utf8.size() && buf.size() < 32;) {
    const auto c = static_cast<unsigned char>(utf8[i]);
    // One code point: an ASCII byte, or a UTF-8 sequence (never displayable).
    std::size_t n = 1;
    if (c >= 0xc0) n = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : 2;
    if (n == 1 && c > 0x20 && c < 0x7f) {
      if (underscore && !buf.empty()) buf.push_back('_');
      underscore = false;
      buf.push_back(static_cast<char>(c));
    } else {
      underscore = true;
    }
    i += n;
  }
  return out + buf;
}

namespace detail {

namespace {

// AsciiCharSetRecognizer.
constexpr std::array<bool, 256> kAscii = [] {
  std::array<bool, 256> t{};
  for (int c = 0x20; c <= 0x7e; ++c) t[c] = true;
  t[0x09] = t[0x0a] = t[0x0d] = true;
  return t;
}();

// MinLengthCharSequenceMatcher over one MultiByteCharMatcher's characters.
struct Matcher {
  unsigned width = 1;  // bytes per character
  unsigned offset = 0;
  unsigned skip = 0;   // bytes still to skip before the first unit (= offset)
  unsigned phase = 0;  // bytes of the current unit read
  std::array<std::uint8_t, 4> unit{};
  // The character sequence.
  std::int64_t current = -1, start = -1;
  bool in = false;
  // The last sequence found: character indexes, terminated.
  std::int64_t seq_start = 0, seq_end = 0;
  bool seq_terminated = false;

  static bool ascii(std::int64_t c) { return (c >= ' ' && c <= '~') || c == 0x0d || c == 0x0a || c == 0x09; }

  bool check(std::int64_t s, std::int64_t e, bool terminated) {
    if (!in) return false;
    in = false;
    std::int64_t length = e - s + 1;
    if (terminated) --length;
    if (length < 5) return false;
    seq_start = s;
    seq_end = e;
    seq_terminated = terminated;
    return true;
  }
  bool add_char(std::int64_t c) {
    ++current;
    if (ascii(c)) {
      if (!in) {
        start = current;
        in = true;
      }
      return false;
    }
    if (c == 0) return check(start, current, true);
    return check(start, current - 1, false);
  }
  bool end_sequence() { return check(start, current, false); }
  // Byte offsets of the last sequence in the range.
  std::uint64_t first_byte() const { return static_cast<std::uint64_t>(seq_start) * width + (width == 1 ? 0 : offset); }
  std::uint64_t last_byte() const {
    return static_cast<std::uint64_t>(seq_end) * width + (width == 1 ? 0 : width - 1 + offset);
  }
};


// A terminated sequence a matcher found, by the byte that ended it.
struct Event {
  std::uint64_t pos;
  std::size_t matcher;
  Matcher m;
};

// Runs one matcher over `n` bytes (the range's from `base` on).
void run_matcher(Matcher &m, std::size_t k, const std::uint8_t *chunk, std::size_t n, std::uint64_t base, bool be,
                 std::vector<Event> &events) {
  if (m.width == 1) {
    // MinLengthCharSequenceMatcher on bytes, inline.
    for (std::size_t i = 0; i < n; ++i) {
      const std::uint8_t c = chunk[i];
      ++m.current;
      if (kAscii[c]) {
        if (!m.in) {
          m.start = m.current;
          m.in = true;
        }
      } else if (c == 0) {
        if (m.in) {
          m.in = false;
          if (m.current - m.start >= 5) {
            m.seq_start = m.start;
            m.seq_end = m.current;
            m.seq_terminated = true;
            events.push_back({base + i, k, m});
          }
        }
      } else {
        m.in = false;
      }
    }
    return;
  }
  // Wide characters: MultiByteCharMatcher.add without a division per byte
  // (`skip` bytes before the offset, `phase` into the unit).
  auto unit_value = [&](const std::uint8_t *p) {
    std::int64_t c = 0;
    for (unsigned b = 0; b < m.width; ++b) c |= static_cast<std::int64_t>(p[b]) << (be ? 8 * (m.width - 1 - b) : 8 * b);
    if (m.width == 2 && c >= 0x8000) c -= 0x10000;  // DataConverter.getShort/getInt are signed
    if (m.width == 4 && c >= 0x80000000LL) c -= 0x100000000LL;
    return c;
  };
  for (std::size_t i = 0; i < n; ++i) {
    if (m.skip != 0) {
      --m.skip;
      continue;
    }
    if (m.phase == 0) {  // whole units at once
      while (i + m.width <= n) {
        i += m.width;
        if (m.add_char(unit_value(chunk + i - m.width)) && m.seq_terminated) events.push_back({base + i - 1, k, m});
      }
      if (i >= n) break;
    }
    m.unit[m.phase] = chunk[i];
    if (++m.phase < m.width) continue;
    m.phase = 0;
    if (m.add_char(unit_value(m.unit.data())) && m.seq_terminated) events.push_back({base + i, k, m});
  }
}

}  // namespace

void search_strings(const ProgramInfo &info, const DataProgramInfo &data, ByteReader &bytes,
                    const std::function<bool(std::uint64_t, std::uint64_t)> &undefined_range,
                    const std::function<bool(std::uint64_t, std::uint64_t)> &pad_free,
                    const std::function<const DataItem *(std::uint64_t)> &item_containing,
                    const std::function<void(DataItem)> &put, const Parallel &parallel) {
  if (!ngram_model_available()) return;
  // The searched set: loaded, initialized, accessible blocks; adjacent ones
  // make one range, as an AddressSet does.
  std::vector<Range> ranges;
  for (const DataBlock &b : data.blocks) {
    if (!b.initialized || !(b.read || b.write || b.exec)) continue;
    if (!ranges.empty() && ranges.back().last + 1 == b.range.first) ranges.back().last = b.range.last;
    else ranges.push_back(b.range);
  }
  std::vector<Matcher> proto;
  proto.push_back({1, 0, 0});
  if (data.wide_char == 2) {
    proto.push_back({2, 0, 0});
    proto.push_back({2, 1, 1});
  } else if (data.wide_char == 4) {
    for (unsigned off : {0u, 2u, 1u, 3u}) proto.push_back({4, off, off});
  }
  const bool be = info.big_endian;

  auto found = [&](const Matcher &m, std::uint64_t base) {
    if (!m.seq_terminated) return;  // "require null termination"
    const std::uint64_t first = base + m.first_byte(), last = base + m.last_byte();
    // The characters before the terminator.
    std::string text;
    const std::uint64_t chars = (last - first + 1) / m.width - 1;
    auto raw = bytes.read(first, static_cast<std::size_t>(chars * m.width));
    if (raw.size() != chars * m.width) return;
    for (std::uint64_t i = 0; i < chars; ++i) {
      std::uint64_t c = 0;
      for (unsigned k = 0; k < m.width; ++k) {
        const unsigned shift = be ? 8 * (m.width - 1 - k) : 8 * k;
        c |= std::uint64_t{std::to_integer<std::uint8_t>(raw[i * m.width + k])} << shift;
      }
      text.push_back(static_cast<char>(c));  // ASCII by the matcher's character set
    }
    if (!ngram_valid_string(text)) return;
    const DataKind kind = m.width == 1 ? DataKind::string : m.width == 2 ? DataKind::unicode : DataKind::unicode32;
    if (!undefined_range(first, last)) {
      // An equal-typed string ending in the same place, starting later,
      // may be consumed.
      const DataItem *d = item_containing(last);
      if (d == nullptr || d->address <= first || d->kind != kind || !undefined_range(first, d->address - 1)) return;
    }
    std::uint64_t length = last - first + 1;
    // End alignment 4: zero bytes after the terminator, up to alignment,
    // if nothing is there.
    const std::uint64_t next = last + 1;
    if (next != 0 && next % 4 != 0) {
      const std::uint64_t pad = 4 - next % 4;
      auto p = bytes.read(next, static_cast<std::size_t>(pad));
      bool zero = p.size() == pad;
      for (std::byte x : p) zero = zero && x == std::byte{0};
      // (Data can't run into the next block.)
      const DataBlock *blk = data.block(next + pad - 1);
      if (zero && blk != nullptr && blk == data.block(first) && pad_free(next, next + pad - 1)) length += pad;
    }
    put({first, static_cast<std::uint32_t>(length), kind, kDataSearch, std::move(text), 0});
  };

  // Each matcher runs on its own (they don't interact), in parallel,
  // recording the terminated sequences it ends with the byte that ended
  // them; they are offered in Ghidra's order (by that byte, then matcher).
  // A sequence the range's end cuts off is never terminated, so it never
  // makes a string.
  constexpr std::size_t kChunk = std::size_t{16} << 20;
  std::vector<std::uint8_t> chunk;
  for (const Range &r : ranges) {
    std::vector<Matcher> ms = proto;
    std::vector<std::vector<Event>> found_by(ms.size());
    for (std::uint64_t at = r.first;; at += kChunk) {
      const std::uint64_t left = r.last - at;
      const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(left, kChunk - 1) + 1);
      chunk.assign(n, 0xff);  // unreadable bytes read as -1
      for (std::size_t done = 0; done < n;) {
        const std::size_t step = std::min<std::size_t>(n - done, 1 << 16);
        auto got = bytes.read(at + done, step);
        for (std::size_t i = 0; i < got.size(); ++i) chunk[done + i] = std::to_integer<std::uint8_t>(got[i]);
        done += step;
      }
      parallel(ms.size(), [&](std::size_t k) { run_matcher(ms[k], k, chunk.data(), n, at - r.first, be, found_by[k]); });
      if (left < kChunk) break;
    }
    std::vector<Event> events;
    for (auto &f : found_by) events.insert(events.end(), f.begin(), f.end());
    std::sort(events.begin(), events.end(),
              [](const Event &a, const Event &b) { return std::tie(a.pos, a.matcher) < std::tie(b.pos, b.matcher); });
    for (const Event &e : events) found(e.m, r.first);
  }
}

}  // namespace detail

}  // namespace revkit::analysis
