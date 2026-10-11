// The segment map: what each stretch of the file looks like before any
// language is tried, from byte statistics of fixed windows.
#include "revkit/detect/detect.hh"

#include <algorithm>
#include <array>
#include <cmath>

namespace revkit::detect {

std::string_view name(Confidence c) {
  switch (c) {
    case Confidence::low: return "low";
    case Confidence::medium: return "medium";
    case Confidence::high: return "high";
  }
  return "low";
}

std::string_view name(Segment::Kind k) {
  switch (k) {
    case Segment::Kind::padding: return "padding";
    case Segment::Kind::high_entropy: return "high-entropy";
    case Segment::Kind::text: return "text";
    case Segment::Kind::code: return "code";
  }
  return "code";
}

namespace {

constexpr std::uint64_t kWindow = 1024;

Segment::Kind classify(std::span<const std::byte> w) {
  std::array<std::uint32_t, 256> count{};
  for (std::byte b : w) ++count[static_cast<std::uint8_t>(b)];
  const double n = static_cast<double>(w.size());
  std::uint32_t most = 0, printable = 0;
  double entropy = 0;
  for (unsigned v = 0; v < 256; ++v) {
    const std::uint32_t c = count[v];
    if (c == 0) continue;
    most = std::max(most, c);
    if ((v >= 0x20 && v < 0x7f) || v == '\n' || v == '\r' || v == '\t') printable += c;
    const double p = c / n;
    entropy -= p * std::log2(p);
  }
  if (most >= 0.9 * n) return Segment::Kind::padding;
  if (printable >= 0.9 * n) return Segment::Kind::text;
  // The most a window of this size can show is log2(size); compressed data
  // comes within a few percent of it, code and tables stay well below.
  if (entropy >= 0.955 * std::min(8.0, std::log2(n))) return Segment::Kind::high_entropy;
  return Segment::Kind::code;
}

}  // namespace

std::vector<Segment> segments(std::span<const std::byte> file) {
  std::vector<Segment> out;
  for (std::uint64_t at = 0; at < file.size(); at += kWindow) {
    const std::uint64_t size = std::min<std::uint64_t>(kWindow, file.size() - at);
    const Segment::Kind kind = classify(file.subspan(at, size));
    if (!out.empty() && out.back().kind == kind)
      out.back().size += size;
    else
      out.push_back({at, size, kind});
  }
  // A lone window that differs from equal neighbours is noise in the
  // statistics (a table inside code, a dense stretch of code): one segment.
  for (std::size_t i = 1; i + 1 < out.size();) {
    if (out[i].size <= kWindow && out[i - 1].kind == out[i + 1].kind && out[i].kind != Segment::Kind::padding) {
      out[i - 1].size += out[i].size + out[i + 1].size;
      out.erase(out.begin() + i, out.begin() + i + 2);
    } else {
      ++i;
    }
  }
  return out;
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> sample_windows(std::span<const std::byte> file,
                                                                    const std::vector<Segment> &segments,
                                                                    std::size_t count, std::uint64_t size) {
  // Every window of every code-like segment, then `count` of them evenly.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> all;
  for (const Segment &s : segments) {
    if (s.kind != Segment::Kind::code) continue;
    for (std::uint64_t at = s.offset; at < s.offset + s.size; at += size)
      all.emplace_back(at, std::min(size, s.offset + s.size - at));
  }
  (void)file;
  if (all.size() <= count) return all;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
  for (std::size_t i = 0; i < count; ++i) out.push_back(all[(2 * i + 1) * all.size() / (2 * count)]);
  return out;
}

}  // namespace revkit::detect
