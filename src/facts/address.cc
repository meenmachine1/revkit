#include "revkit/facts/address.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <stdexcept>

namespace revkit::facts {

std::string_view to_string(SpaceKind kind) {
  switch (kind) {
    case SpaceKind::Constant: return "const";
    case SpaceKind::Ram: return "ram";
    case SpaceKind::Register: return "register";
    case SpaceKind::Stack: return "stack";
    case SpaceKind::Unique: return "unique";
    case SpaceKind::Overlay: return "overlay";
    case SpaceKind::Other: return "other";
  }
  return "?";
}

std::optional<AddressRange> AddressRange::make(Address first, Address last) {
  if (first.space != last.space || first.offset > last.offset) return std::nullopt;
  return AddressRange{first, last};
}

std::optional<AddressRange> AddressRange::sized(Address start, std::uint64_t length) {
  if (length == 0) return std::nullopt;
  std::uint64_t end = start.offset + (length - 1);
  if (end < start.offset) return std::nullopt;
  return AddressRange{start, Address{start.space, end}};
}

namespace {

// True if b starts at or before one past a's end, so the two can merge.
bool touches(const AddressRange &a, const AddressRange &b) {
  if (a.first.space != b.first.space) return false;
  return a.last.offset == ~std::uint64_t{0} || b.first.offset <= a.last.offset + 1;
}

}  // namespace

void AddressSet::add(AddressRange r) {
  // First range that could merge with r: the first whose end is not entirely
  // before r's start.
  auto it = std::lower_bound(ranges_.begin(), ranges_.end(), r,
                             [](const AddressRange &x, const AddressRange &key) {
                               if (x.first.space != key.first.space)
                                 return x.first.space < key.first.space;
                               return !touches(x, key);
                             });
  auto last = it;
  while (last != ranges_.end() && last->first.space == r.first.space &&
         touches(r, *last)) {
    r.first.offset = std::min(r.first.offset, last->first.offset);
    r.last.offset = std::max(r.last.offset, last->last.offset);
    ++last;
  }
  it = ranges_.erase(it, last);
  ranges_.insert(it, r);
}

void AddressSet::add(const AddressSet &other) {
  for (const auto &r : other.ranges_) add(r);
}

void AddressSet::subtract(AddressRange r) {
  std::vector<AddressRange> out;
  out.reserve(ranges_.size() + 1);
  for (const auto &x : ranges_) {
    if (x.first.space != r.first.space || x.last.offset < r.first.offset ||
        x.first.offset > r.last.offset) {
      out.push_back(x);
      continue;
    }
    if (x.first.offset < r.first.offset)
      out.push_back({x.first, Address{x.first.space, r.first.offset - 1}});
    if (x.last.offset > r.last.offset)
      out.push_back({Address{x.first.space, r.last.offset + 1}, x.last});
  }
  ranges_ = std::move(out);
}

AddressSet AddressSet::intersect(const AddressSet &other) const {
  AddressSet out;
  auto a = ranges_.begin();
  auto b = other.ranges_.begin();
  while (a != ranges_.end() && b != other.ranges_.end()) {
    if (a->first.space != b->first.space) {
      (a->first.space < b->first.space) ? ++a : ++b;
      continue;
    }
    std::uint64_t lo = std::max(a->first.offset, b->first.offset);
    std::uint64_t hi = std::min(a->last.offset, b->last.offset);
    if (lo <= hi) out.ranges_.push_back({{a->first.space, lo}, {a->first.space, hi}});
    (a->last.offset < b->last.offset) ? ++a : ++b;
  }
  return out;
}

bool AddressSet::contains(Address a) const {
  auto it = std::upper_bound(ranges_.begin(), ranges_.end(), a,
                             [](Address key, const AddressRange &x) { return key < x.first; });
  if (it == ranges_.begin()) return false;
  return std::prev(it)->contains(a);
}

bool AddressSet::intersects(AddressRange r) const {
  return !intersect(AddressSet(r)).empty();
}

std::optional<Address> AddressSet::min() const {
  if (ranges_.empty()) return std::nullopt;
  return ranges_.front().first;
}

std::optional<Address> AddressSet::max() const {
  if (ranges_.empty()) return std::nullopt;
  return ranges_.back().last;
}

SpaceTable SpaceTable::standard(std::uint8_t ram_size) {
  SpaceTable t;
  t.add("const", SpaceKind::Constant, 8);
  t.add("ram", SpaceKind::Ram, ram_size);
  t.add("register", SpaceKind::Register, 4);
  t.add("stack", SpaceKind::Stack, ram_size);
  t.add("unique", SpaceKind::Unique, 4);
  return t;
}

SpaceId SpaceTable::add(std::string name, SpaceKind kind, std::uint8_t size,
                        std::uint8_t word_size, bool big_endian) {
  if (find(name)) throw std::invalid_argument("duplicate address space: " + name);
  if (size == 0 || size > 8) throw std::invalid_argument("bad address size for " + name);
  if (spaces_.size() > 0xffff) throw std::length_error("too many address spaces");
  AddressSpace s;
  s.id = static_cast<SpaceId>(spaces_.size());
  s.name = std::move(name);
  s.kind = kind;
  s.size = size;
  s.word_size = word_size;
  s.big_endian = big_endian;
  spaces_.push_back(std::move(s));
  return spaces_.back().id;
}

SpaceId SpaceTable::add_overlay(std::string name, SpaceId base) {
  const AddressSpace *b = find(base);
  if (!b) throw std::invalid_argument("overlay of unknown space");
  AddressSpace copy = *b;
  SpaceId id = add(std::move(name), SpaceKind::Overlay, copy.size, copy.word_size,
                   copy.big_endian);
  spaces_[id].overlay_base = base;
  return id;
}

const AddressSpace *SpaceTable::find(SpaceId id) const {
  return id < spaces_.size() ? &spaces_[id] : nullptr;
}

const AddressSpace *SpaceTable::find(std::string_view name) const {
  for (const auto &s : spaces_)
    if (s.name == name) return &s;
  return nullptr;
}

std::optional<Address> SpaceTable::advance(Address a, std::uint64_t delta) const {
  const AddressSpace *s = find(a.space);
  if (!s) return std::nullopt;
  std::uint64_t max = s->max_offset();
  if (a.offset > max || delta > max - a.offset) return std::nullopt;
  return Address{a.space, a.offset + delta};
}

std::string SpaceTable::format(Address a) const {
  const AddressSpace *s = find(a.space);
  char buf[32];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(a.offset));
  return (s ? s->name : "space" + std::to_string(a.space)) + ":" + buf;
}

std::optional<Address> SpaceTable::parse(std::string_view text) const {
  auto colon = text.find(':');
  if (colon == std::string_view::npos) return std::nullopt;
  const AddressSpace *s = find(text.substr(0, colon));
  if (!s) return std::nullopt;
  std::string_view num = text.substr(colon + 1);
  if (num.starts_with("0x") || num.starts_with("0X")) num.remove_prefix(2);
  if (num.empty()) return std::nullopt;
  std::uint64_t off = 0;
  auto [p, ec] = std::from_chars(num.data(), num.data() + num.size(), off, 16);
  if (ec != std::errc{} || p != num.data() + num.size() || off > s->max_offset())
    return std::nullopt;
  return Address{s->id, off};
}

}  // namespace revkit::facts
