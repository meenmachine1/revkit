// CPython's marshal format, from its documented type codes (Python/marshal.c,
// PSF licence: the format, not code): one type byte, FLAG_REF (0x80) adding
// the value to the reference table, 'r' naming one.
#include "marshal.hh"

#include "formats.hh"

namespace revkit::container::detail {

namespace {

class Reader {
 public:
  Reader(std::span<const std::byte> d, std::size_t p, int major, int minor, std::uint32_t depth, std::uint64_t values)
      : d_(d), p_(p), major_(major), minor_(minor), max_depth_(depth), max_values_(values) {}
  std::size_t pos() const { return p_; }

  std::shared_ptr<const Marshal> value(std::uint32_t depth) {
    if (depth > max_depth_) throw LimitError("marshalled data nests deeper than " + std::to_string(max_depth_));
    if (++values_ > max_values_) throw LimitError("marshalled data has too many values");
    const std::uint8_t code = byte();
    const bool flag = (code & 0x80) != 0;
    const char t = static_cast<char>(code & 0x7f);
    // A slot for FLAG_REF values, filled once the value is built (a
    // container referring to itself sees null and fails).
    std::size_t slot = SIZE_MAX;
    if (flag) {
      if (refs_.size() >= max_values_) throw LimitError("too many marshal references");
      slot = refs_.size();
      refs_.emplace_back();
    }
    auto m = std::make_shared<Marshal>();
    switch (t) {
      case '0':  // NULL: ends a dict
        m->type = Marshal::Type::other;
        m->s = "NULL";
        break;
      case 'N': break;
      case 'F': m->type = Marshal::Type::boolean; break;
      case 'T':
        m->type = Marshal::Type::boolean;
        m->b = true;
        break;
      case 'S': case '.': m->type = Marshal::Type::other; break;  // StopIteration, Ellipsis
      case 'i':
        m->type = Marshal::Type::integer;
        m->i = static_cast<std::int32_t>(u32());
        break;
      case 'I': {  // int64 (Python 2)
        m->type = Marshal::Type::integer;
        const std::uint64_t lo = u32(), hi = u32();
        m->i = static_cast<std::int64_t>(lo | hi << 32);
        break;
      }
      case 'l': {  // long: digit count (signed), 15-bit digits
        const std::int32_t n = static_cast<std::int32_t>(u32());
        const std::uint64_t k = n < 0 ? -static_cast<std::int64_t>(n) : n;
        need(k * 2);
        std::uint64_t v = 0;
        bool fits = k <= 4;
        for (std::uint64_t j = 0; j < k; ++j) {
          const std::uint8_t lo = u8(), hi = u8();
          const std::uint16_t dgt = static_cast<std::uint16_t>(lo | hi << 8);
          if (fits && j < 4) v |= std::uint64_t{dgt} << (15 * j);
        }
        m->type = fits && v < (1ull << 62) ? Marshal::Type::integer : Marshal::Type::other;
        m->i = n < 0 ? -static_cast<std::int64_t>(v) : static_cast<std::int64_t>(v);
        break;
      }
      case 'g': skip(8); m->type = Marshal::Type::floating; break;   // binary float
      case 'y': skip(16); m->type = Marshal::Type::floating; break;  // binary complex
      case 'f': skip(u8()); m->type = Marshal::Type::floating; break;
      case 'x': skip(u8()); skip(u8()); m->type = Marshal::Type::floating; break;
      case 's': case 't': case 'u': case 'a': case 'A': {  // bytes, interned, unicode, ascii
        const std::uint32_t n = u32();
        m->type = t == 's' ? Marshal::Type::bytes : Marshal::Type::str;
        m->s = text(n);
        break;
      }
      case 'z': case 'Z': {  // short ascii
        const std::uint8_t n = u8();
        m->type = Marshal::Type::str;
        m->s = text(n);
        break;
      }
      case 'R': {  // Python 2's string reference
        const std::uint32_t n = u32();
        if (n >= strings_.size()) throw Error("a marshal string reference out of range");
        return strings_[n];
      }
      case '(': case '[': case '<': case '>': case ')': {
        const std::uint64_t n = t == ')' ? u8() : u32();
        if (n > d_.size() - p_) throw Error("a marshal sequence longer than its data");
        m->type = t == '[' ? Marshal::Type::list : (t == '<' || t == '>') ? Marshal::Type::set : Marshal::Type::tuple;
        for (std::uint64_t j = 0; j < n; ++j) m->items.push_back(value(depth + 1));
        break;
      }
      case '{': {
        m->type = Marshal::Type::dict;
        for (;;) {
          auto k = value(depth + 1);
          if (k->type == Marshal::Type::other && k->s == "NULL") break;
          m->items.push_back(k);
          m->items.push_back(value(depth + 1));
        }
        break;
      }
      case ':':  // slice (3.14): start, stop, step
        m->type = Marshal::Type::other;
        for (int j = 0; j < 3; ++j) m->items.push_back(value(depth + 1));
        break;
      case 'c': skip_code(depth); m->type = Marshal::Type::code; break;
      case 'r': {
        const std::uint32_t n = u32();
        if (n >= refs_.size() || !refs_[n]) throw Error("a marshal reference out of range");
        return refs_[n];
      }
      default:
        throw Error("unknown marshal type " + std::to_string(code));
    }
    if (t == 't' && major_ == 2) strings_.push_back(m);
    if (slot != SIZE_MAX) refs_[slot] = m;
    return m;
  }

 private:
  void need(std::uint64_t n) const {
    if (n > d_.size() - p_) throw Error("truncated marshal data");
  }
  std::uint8_t u8() {
    need(1);
    return static_cast<std::uint8_t>(d_[p_++]);
  }
  std::uint8_t byte() { return u8(); }
  std::uint32_t u32() {
    need(4);
    const std::uint32_t v = le32(d_.data() + p_);
    p_ += 4;
    return v;
  }
  void skip(std::uint64_t n) {
    need(n);
    p_ += static_cast<std::size_t>(n);
  }
  std::string text(std::uint64_t n) {
    need(n);
    std::string s(reinterpret_cast<const char *>(d_.data() + p_), static_cast<std::size_t>(n));
    p_ += static_cast<std::size_t>(n);
    return s;
  }
  // A code object, by the writing version's field list: 32-bit fields,
  // then objects, the first line number, and the tables after it.
  void skip_code(std::uint32_t depth) {
    int ints = 5, objects = 8, tail = 1;
    if (major_ == 2) ints = 4;
    else if (major_ == 3 && minor_ >= 11) ints = 5, objects = 8, tail = 2;  // stacksize..; qualname; linetable, exceptiontable
    else if (major_ == 3 && minor_ >= 8) ints = 6;                         // posonlyargcount
    for (int j = 0; j < ints; ++j) u32();
    for (int j = 0; j < objects; ++j) value(depth + 1);
    u32();  // firstlineno
    for (int j = 0; j < tail; ++j) value(depth + 1);
  }

  std::span<const std::byte> d_;
  std::size_t p_;
  int major_, minor_;
  std::uint32_t max_depth_;
  std::uint64_t max_values_;
  std::uint64_t values_ = 0;
  std::vector<std::shared_ptr<const Marshal>> refs_;
  std::vector<std::shared_ptr<const Marshal>> strings_;
};

}  // namespace

std::shared_ptr<const Marshal> read_marshal(std::span<const std::byte> data, std::size_t &pos, int major, int minor,
                                            std::uint32_t max_depth, std::uint64_t max_values) {
  if (pos > data.size()) throw Error("marshal data past its end");
  Reader r(data, pos, major, minor, max_depth, max_values);
  auto v = r.value(0);
  pos = r.pos();
  return v;
}

}  // namespace revkit::container::detail
