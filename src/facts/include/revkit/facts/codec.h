// Deterministic binary encoding. Everything the fact store persists or
// fingerprints goes through Codec<T>, so encodings must be canonical: equal
// values encode to equal bytes (no unordered containers, no padding).
#pragma once

#include "revkit/facts/address.h"

#include <concepts>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace revkit::facts {

struct DecodeError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

class Encoder {
 public:
  void u8(std::uint8_t v) { buf_.push_back(static_cast<char>(v)); }
  void varint(std::uint64_t v) {
    while (v >= 0x80) {
      u8(static_cast<std::uint8_t>(v | 0x80));
      v >>= 7;
    }
    u8(static_cast<std::uint8_t>(v));
  }
  void svarint(std::int64_t v) {
    varint((static_cast<std::uint64_t>(v) << 1) ^ static_cast<std::uint64_t>(v >> 63));
  }
  // Big-endian so byte order matches numeric order in sorted key spaces.
  void u64be(std::uint64_t v) {
    for (int i = 7; i >= 0; --i) u8(static_cast<std::uint8_t>(v >> (8 * i)));
  }
  void u32be(std::uint32_t v) {
    for (int i = 3; i >= 0; --i) u8(static_cast<std::uint8_t>(v >> (8 * i)));
  }
  void raw(std::string_view bytes) { buf_.append(bytes); }
  void bytes(std::string_view b) {
    varint(b.size());
    raw(b);
  }

  const std::string &str() const & { return buf_; }
  std::string str() && { return std::move(buf_); }
  std::size_t size() const { return buf_.size(); }

 private:
  std::string buf_;
};

class Decoder {
 public:
  explicit Decoder(std::string_view in) : in_(in) {}

  std::uint8_t u8() {
    need(1);
    return static_cast<std::uint8_t>(in_[pos_++]);
  }
  std::uint64_t varint() {
    std::uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
      std::uint8_t b = u8();
      if (shift == 63 && b > 1) break;
      v |= std::uint64_t{b & 0x7fu} << shift;
      if (!(b & 0x80)) return v;
    }
    throw DecodeError("varint overflow");
  }
  std::int64_t svarint() {
    std::uint64_t z = varint();
    return static_cast<std::int64_t>((z >> 1) ^ (~(z & 1) + 1));
  }
  std::uint64_t u64be() {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | u8();
    return v;
  }
  std::uint32_t u32be() {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | u8();
    return v;
  }
  std::string_view raw(std::size_t n) {
    need(n);
    std::string_view v = in_.substr(pos_, n);
    pos_ += n;
    return v;
  }
  std::string_view bytes() {
    std::uint64_t n = varint();
    if (n > remaining()) throw DecodeError("length past end of input");
    return raw(static_cast<std::size_t>(n));
  }
  // Element counts are bounded by the bytes left, since every element
  // encodes to at least one byte; this stops hostile input from making
  // decoders reserve huge buffers.
  std::size_t count() {
    std::uint64_t n = varint();
    if (n > remaining()) throw DecodeError("count past end of input");
    return static_cast<std::size_t>(n);
  }

  std::size_t remaining() const { return in_.size() - pos_; }
  bool done() const { return pos_ == in_.size(); }
  void expect_done() const {
    if (!done()) throw DecodeError("trailing bytes");
  }

 private:
  void need(std::size_t n) const {
    if (n > in_.size() - pos_) throw DecodeError("unexpected end of input");
  }
  std::string_view in_;
  std::size_t pos_ = 0;
};

template <class T>
struct Codec;

// Types may carry their own encoding as members.
template <class T>
concept SelfEncoding = requires(const T &t, Encoder &e, Decoder &d) {
  t.encode(e);
  { T::decode(d) } -> std::same_as<T>;
};

template <class T>
concept Encodable = requires(const T &t, Encoder &e, Decoder &d) {
  Codec<T>::encode(e, t);
  { Codec<T>::decode(d) } -> std::same_as<T>;
};

template <class T>
void encode(Encoder &e, const T &v) {
  Codec<T>::encode(e, v);
}
template <class T>
T decode(Decoder &d) {
  return Codec<T>::decode(d);
}
template <class T>
std::string encode_to_string(const T &v) {
  Encoder e;
  encode(e, v);
  return std::move(e).str();
}
template <class T>
T decode_from_string(std::string_view s) {
  Decoder d(s);
  T v = decode<T>(d);
  d.expect_done();
  return v;
}

template <SelfEncoding T>
struct Codec<T> {
  static void encode(Encoder &e, const T &v) { v.encode(e); }
  static T decode(Decoder &d) { return T::decode(d); }
};

template <>
struct Codec<bool> {
  static void encode(Encoder &e, bool v) { e.u8(v ? 1 : 0); }
  static bool decode(Decoder &d) {
    std::uint8_t b = d.u8();
    if (b > 1) throw DecodeError("bad bool");
    return b == 1;
  }
};

template <std::unsigned_integral T>
  requires(!std::same_as<T, bool>)
struct Codec<T> {
  static void encode(Encoder &e, T v) { e.varint(v); }
  static T decode(Decoder &d) {
    std::uint64_t v = d.varint();
    if (v > std::numeric_limits<T>::max()) throw DecodeError("integer out of range");
    return static_cast<T>(v);
  }
};

template <std::signed_integral T>
struct Codec<T> {
  static void encode(Encoder &e, T v) { e.svarint(v); }
  static T decode(Decoder &d) {
    std::int64_t v = d.svarint();
    if (v < std::numeric_limits<T>::min() || v > std::numeric_limits<T>::max())
      throw DecodeError("integer out of range");
    return static_cast<T>(v);
  }
};

template <class T>
  requires std::is_enum_v<T>
struct Codec<T> {
  static void encode(Encoder &e, T v) {
    e.varint(static_cast<std::uint64_t>(static_cast<std::underlying_type_t<T>>(v)));
  }
  static T decode(Decoder &d) {
    return static_cast<T>(Codec<std::underlying_type_t<T>>::decode(d));
  }
};

template <>
struct Codec<std::string> {
  static void encode(Encoder &e, const std::string &v) { e.bytes(v); }
  static std::string decode(Decoder &d) { return std::string(d.bytes()); }
};

template <>
struct Codec<std::monostate> {
  static void encode(Encoder &, std::monostate) {}
  static std::monostate decode(Decoder &) { return {}; }
};

template <class T>
struct Codec<std::vector<T>> {
  static void encode(Encoder &e, const std::vector<T> &v) {
    e.varint(v.size());
    for (const auto &x : v) Codec<T>::encode(e, x);
  }
  static std::vector<T> decode(Decoder &d) {
    std::size_t n = d.count();
    std::vector<T> v;
    // n is at most the bytes left, but an element may be much larger than
    // its encoding (an AddressRange is 32 bytes from as few as 4): grow
    // past the first 4096 as elements actually decode.
    v.reserve(std::min<std::size_t>(n, 4096));
    for (std::size_t i = 0; i < n; ++i) v.push_back(Codec<T>::decode(d));
    return v;
  }
};

template <class K, class V>
struct Codec<std::map<K, V>> {
  static void encode(Encoder &e, const std::map<K, V> &m) {
    e.varint(m.size());
    for (const auto &[k, v] : m) {
      Codec<K>::encode(e, k);
      Codec<V>::encode(e, v);
    }
  }
  static std::map<K, V> decode(Decoder &d) {
    std::size_t n = d.count();
    std::map<K, V> m;
    for (std::size_t i = 0; i < n; ++i) {
      K k = Codec<K>::decode(d);
      m.emplace(std::move(k), Codec<V>::decode(d));
    }
    return m;
  }
};

template <class T>
struct Codec<std::optional<T>> {
  static void encode(Encoder &e, const std::optional<T> &v) {
    e.u8(v ? 1 : 0);
    if (v) Codec<T>::encode(e, *v);
  }
  static std::optional<T> decode(Decoder &d) {
    if (!Codec<bool>::decode(d)) return std::nullopt;
    return Codec<T>::decode(d);
  }
};

template <class A, class B>
struct Codec<std::pair<A, B>> {
  static void encode(Encoder &e, const std::pair<A, B> &v) {
    Codec<A>::encode(e, v.first);
    Codec<B>::encode(e, v.second);
  }
  static std::pair<A, B> decode(Decoder &d) {
    A a = Codec<A>::decode(d);
    return {std::move(a), Codec<B>::decode(d)};
  }
};

template <class... Ts>
struct Codec<std::variant<Ts...>> {
  using V = std::variant<Ts...>;
  static void encode(Encoder &e, const V &v) {
    e.varint(v.index());
    std::visit([&](const auto &x) { Codec<std::decay_t<decltype(x)>>::encode(e, x); }, v);
  }
  static V decode(Decoder &d) {
    std::uint64_t idx = d.varint();
    return decode_at<0>(d, idx);
  }

 private:
  template <std::size_t I>
  static V decode_at(Decoder &d, std::uint64_t idx) {
    if constexpr (I == sizeof...(Ts)) {
      throw DecodeError("bad variant index");
    } else {
      if (idx == I)
        return V(std::in_place_index<I>,
                 Codec<std::variant_alternative_t<I, V>>::decode(d));
      return decode_at<I + 1>(d, idx);
    }
  }
};

template <>
struct Codec<Address> {
  static void encode(Encoder &e, const Address &a) {
    e.varint(a.space);
    e.varint(a.offset);
  }
  static Address decode(Decoder &d) {
    Address a;
    a.space = Codec<SpaceId>::decode(d);
    a.offset = d.varint();
    return a;
  }
};

template <>
struct Codec<AddressRange> {
  static void encode(Encoder &e, const AddressRange &r) {
    Codec<Address>::encode(e, r.first);
    e.varint(r.span());
  }
  static AddressRange decode(Decoder &d) {
    Address first = Codec<Address>::decode(d);
    std::uint64_t span = d.varint();
    if (span > ~std::uint64_t{0} - first.offset) throw DecodeError("range wraps");
    return AddressRange{first, Address{first.space, first.offset + span}};
  }
};

template <>
struct Codec<AddressSet> {
  static void encode(Encoder &e, const AddressSet &s) {
    Codec<std::vector<AddressRange>>::encode(e, s.ranges());
  }
  static AddressSet decode(Decoder &d) {
    // Sorted first: add() inserts into a sorted vector, so ranges in
    // descending order (a hostile archive's or peer's) cost O(n^2).
    std::vector<AddressRange> ranges = Codec<std::vector<AddressRange>>::decode(d);
    std::sort(ranges.begin(), ranges.end(), [](const AddressRange &a, const AddressRange &b) {
      return a.first.space != b.first.space ? a.first.space < b.first.space : a.first.offset < b.first.offset;
    });
    AddressSet s;
    for (const auto &r : ranges) s.add(r);
    return s;
  }
};

}  // namespace revkit::facts
