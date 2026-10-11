#include "sigdb.h"

#include <memory>
#include <mutex>

extern const char kSigdbGlibcLp64[];
extern const char kSigdbWin64[];

namespace revkit::infer {

SigDb::SigDb(std::string_view text) {
  while (!text.empty()) {
    std::size_t nl = text.find('\n');
    std::string_view line = text.substr(0, nl);
    text = nl == std::string_view::npos ? std::string_view() : text.substr(nl + 1);
    if (line.empty() || line.front() == '#') continue;
    std::vector<std::string> fields;
    while (true) {
      std::size_t tab = line.find('\t');
      fields.emplace_back(line.substr(0, tab));
      if (tab == std::string_view::npos) break;
      line = line.substr(tab + 1);
    }
    if (fields.size() < 2) continue;
    std::string name = std::move(fields.front());
    fields.erase(fields.begin());
    entries_[std::move(name)] = std::move(fields);
  }
}

const std::vector<std::string> *SigDb::lookup(std::string_view name) const {
  auto try_name = [&](std::string_view n) -> const std::vector<std::string> * {
    auto it = entries_.find(std::string(n));
    return it == entries_.end() ? nullptr : &it->second;
  };
  if (auto at = name.find('@'); at != std::string_view::npos && at > 0) name = name.substr(0, at);
  if (const auto *f = try_name(name)) return f;
  for (std::string_view prefix : {"__isoc99_", "__isoc23_", "__imp_", "__GI_"})
    if (name.starts_with(prefix))
      if (const auto *f = try_name(name.substr(prefix.size()))) return f;
  return nullptr;
}

std::optional<Prototype> SigDb::find(std::string_view name, const DataOrg &org) const {
  const std::vector<std::string> *f = lookup(name);
  if (f == nullptr) return std::nullopt;
  Prototype p;
  p.source = "library";
  auto ret = parse_type((*f)[0], org);
  if (!ret) return std::nullopt;
  p.ret = *ret;
  for (std::size_t i = 1; i < f->size(); ++i) {
    if ((*f)[i].starts_with("cb")) break;
    if ((*f)[i] == "...") {
      p.varargs = true;
      break;
    }
    auto t = parse_type((*f)[i], org);
    if (!t) return std::nullopt;
    p.params.push_back(*t);
  }
  return p;
}

std::optional<Prototype> SigDb::callback(std::string_view name, std::size_t index, const DataOrg &org) const {
  const std::vector<std::string> *f = lookup(name);
  if (f == nullptr) return std::nullopt;
  const std::string key = "cb" + std::to_string(index);
  for (const std::string &field : *f) {
    if (!field.starts_with(key)) continue;
    std::string_view rest = std::string_view(field).substr(key.size());
    bool optional = false;
    if (rest.starts_with("~")) {
      optional = true;
      rest.remove_prefix(1);
    }
    if (!rest.starts_with("=")) continue;
    rest.remove_prefix(1);
    std::vector<std::string> parts;
    while (true) {
      std::size_t bar = rest.find('|');
      parts.emplace_back(rest.substr(0, bar));
      if (bar == std::string_view::npos) break;
      rest = rest.substr(bar + 1);
    }
    Prototype p;
    p.source = optional ? "callback-optional" : "callback";
    auto ret = parse_type(parts[0], org);
    if (!ret) return std::nullopt;
    p.ret = *ret;
    for (std::size_t i = 1; i < parts.size(); ++i) {
      if (parts[i] == "...") {
        p.varargs = true;
        break;
      }
      auto t = parse_type(parts[i], org);
      if (!t) return std::nullopt;
      p.params.push_back(*t);
    }
    return p;
  }
  return std::nullopt;
}

namespace {

VType pick(const std::map<std::uint8_t, VType> &m, std::uint8_t size, VType fallback) {
  auto it = m.find(size);
  return it == m.end() ? fallback : it->second;
}

}  // namespace

VType Priors::unknown_param(std::uint8_t size) const { return pick(params, size, VType::unknown(size)); }
VType Priors::unknown_return(std::uint8_t size) const {
  // A return register holds values narrower than itself (an int in RAX):
  // the commonest return of any size that fits.
  return pick(returns_upto, size, VType::unknown(size));
}
VType Priors::integer_param(std::uint8_t size) const {
  return pick(int_params, size, VType::integer(size, Sign::is_signed));
}
VType Priors::integer_return(std::uint8_t size) const {
  return pick(int_returns, size, VType::integer(size, Sign::is_signed));
}

const Priors &SigDb::priors(const DataOrg &org) {
  static std::mutex mu;
  static std::map<std::pair<int, int>, std::unique_ptr<Priors>> cache;
  std::lock_guard lock(mu);
  auto &slot = cache[{org.pointer_size, org.long_size}];
  if (slot) return *slot;
  slot = std::make_unique<Priors>();
  Priors &p = *slot;
  // Count spelled types by role and size.
  using Counts = std::map<std::uint8_t, std::map<std::string, std::pair<int, VType>>>;
  Counts params, returns, int_params, int_returns;
  std::map<std::string, std::pair<int, VType>> pointees;
  auto count = [&](Counts &c, const VType &t) {
    auto &e = c[t.size][print(t, org)];
    ++e.first;
    e.second = t;
  };
  // Parsed as LP64 C, which glibc is: an 8-byte integer then prints as the
  // target spells it (long long on LLP64).
  DataOrg lp64 = org;
  lp64.long_size = 8;
  const SigDb glibc(kSigdbGlibcLp64);
  for (const auto &[name, fields] : glibc.entries_) {
    for (std::size_t i = 0; i < fields.size(); ++i) {
      if (fields[i] == "...") continue;
      auto t = parse_type(fields[i], lp64);
      if (!t || t->size == 0) continue;
      const bool ret = i == 0;
      if (t->meta == Meta::int_ || t->meta == Meta::pointer || t->meta == Meta::char_ || t->meta == Meta::bool_)
        count(ret ? returns : params, *t);
      if (t->meta == Meta::int_) count(ret ? int_returns : int_params, *t);
      if (!ret && t->is_pointer() && t->depth() == 1) {
        auto &e = pointees[print(t->target(), org)];
        ++e.first;
        e.second = t->target();
      }
    }
  }
  auto best = [](const Counts &c, std::map<std::uint8_t, VType> &out) {
    for (const auto &[size, types] : c) {
      int n = -1;
      for (const auto &[name, e] : types)
        if (e.first > n) {
          n = e.first;
          out[size] = e.second;
        }
    }
  };
  best(params, p.params);
  best(returns, p.returns);
  {
    std::map<std::string, std::pair<int, VType>> upto;
    for (const auto &[size, types] : returns) {
      for (const auto &[name, e] : types) {
        auto &u = upto[name];
        u.first += e.first;
        u.second = e.second;
      }
      int n = -1;
      for (const auto &[name, e] : upto)
        if (e.first > n) {
          n = e.first;
          p.returns_upto[size] = e.second;
        }
    }
    // Sizes between the ones seen take the next smaller one's.
    for (std::uint8_t sz = 1; sz <= 16; ++sz)
      if (!p.returns_upto.contains(sz))
        if (auto it = p.returns_upto.lower_bound(sz); it != p.returns_upto.begin()) p.returns_upto[sz] = std::prev(it)->second;
  }
  best(int_params, p.int_params);
  best(int_returns, p.int_returns);
  int n = -1;
  for (const auto &[name, e] : pointees)
    if (e.first > n && e.second.meta != Meta::struct_) {
      n = e.first;
      p.pointee = e.second;
    }
  return p;
}

const SigDb &SigDb::for_image(const loader::Image &image) {
  static const SigDb glibc(kSigdbGlibcLp64);
  static const SigDb win64(kSigdbWin64);
  return image.format == loader::Format::pe ? win64 : glibc;
}

}  // namespace revkit::infer

#include "revkit/infer/library.h"

namespace revkit::infer {

std::optional<Prototype> library_prototype(const loader::Image &image, std::string_view name) {
  DataOrg org;
  org.pointer_size = static_cast<std::uint8_t>(image.bits / 8);
  org.long_size = image.format == loader::Format::pe ? 4 : org.pointer_size;
  return SigDb::for_image(image).find(name, org);
}

}  // namespace revkit::infer
