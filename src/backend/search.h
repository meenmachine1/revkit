// The matching half of the searches (api_minor 41, feature "search";
// docs/api.md "Search"): what a memory search's query means as bytes, a
// fast scanner for byte patterns with masks and ASCII case folding, byte
// regular expressions, and text matching for the program text and
// decompiled-code searches. The program half (where to look, what the
// listing shows) is in image_backend.cc.
#pragma once

#include "revkit/v1/query.pb.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace re2 {
class RE2;
}

namespace revkit::backend::search {

namespace pb = ::revkit::v1;

// Bytes to find: per position a value and a bit mask; a folded position
// is an ASCII letter matched in either case.
struct Pattern {
  std::string value, mask;
  std::string fold;  // per position: 1 = ASCII case-insensitive
  std::size_t size() const { return value.size(); }
  // "48 8b ?? e8": hex with "?" for a masked nibble, "[v/m]" for a byte
  // masked inside a nibble.
  std::string Display() const;
};

// A memory query compiled: a byte pattern, or a regular expression.
struct Compiled {
  Pattern pattern;
  std::string regex;  // set for SEARCH_FORMAT_REGEX
  bool is_regex = false;
  std::string Display() const { return is_regex ? regex : pattern.Display(); }
};

// Reads a memory search's query as bytes; `big_endian` is the byte order
// to use when the request says the program's. Returns "" or the error.
std::string CompileMemoryQuery(const pb::SearchMemoryRequest &req, bool big_endian, Compiled &out);

// Finds matches in a buffer. Thread-compatible; one per search.
class ByteMatcher {
 public:
  virtual ~ByteMatcher() = default;
  // Matches starting at offsets [0, starts) of data[0, len), in order;
  // `fn(offset, length)` returns false to stop (then Scan returns false).
  virtual bool Scan(const unsigned char *data, std::size_t len, std::size_t starts,
                    const std::function<bool(std::size_t, std::size_t)> &fn) const = 0;
  // How far past the last start a match may reach: the bytes to read
  // beyond a chunk so a match crossing its end is found.
  virtual std::size_t reach() const = 0;
};

// A matcher for `c`, or null with `error` set (a bad regular expression).
std::unique_ptr<ByteMatcher> MakeByteMatcher(const Compiled &c, std::string &error);

// Text matching for SearchText and SearchDecompiled: plain text or a
// regular expression (RE2, UTF-8), optionally case-sensitive and whole
// word. Find is safe to call from several threads.
class TextMatcher {
 public:
  ~TextMatcher();
  // Null with `error` set when the query is empty or a bad regex.
  static std::unique_ptr<TextMatcher> Make(const std::string &query, bool regex, bool case_sensitive, bool whole_word,
                                           std::string &error);
  // The first match in `text`: its byte offset and length.
  bool Find(std::string_view text, std::size_t &start, std::size_t &length) const;

 private:
  TextMatcher() = default;
  bool FindPlain(std::string_view text, std::size_t from, std::size_t &start, std::size_t &length) const;
  bool FindRegex(std::string_view text, std::size_t from, std::size_t &start, std::size_t &length) const;

  std::string query_;  // folded to lower case when !case_sensitive_ (plain)
  bool case_sensitive_ = true;
  bool whole_word_ = false;
  std::unique_ptr<re2::RE2> re_;
};

}  // namespace revkit::backend::search
