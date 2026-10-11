#include "revkit/lift/functions.hh"

#include "revkit/lift/context.hh"

#include <algorithm>
#include <map>

namespace revkit::lift {

namespace {

int bind_rank(loader::SymbolBind b) {
  switch (b) {
    case loader::SymbolBind::global: return 0;
    case loader::SymbolBind::weak: return 1;
    default: return 2;
  }
}

bool executable(const loader::Image &image, std::uint64_t addr) {
  const loader::Region *r = image.memory.find(addr);
  return r != nullptr && r->perms.exec;
}

}  // namespace

std::vector<FunctionSymbol> function_symbols(const loader::Image &image, bool sized_only) {
  struct Candidate {
    std::string name;
    std::uint64_t size;
    int rank;
  };
  std::map<std::uint64_t, Candidate> best;
  auto offer = [&](std::uint64_t addr, const std::string &name, std::uint64_t size, int rank) {
    if (name.empty() || !executable(image, addr)) return;
    auto [it, inserted] = best.emplace(addr, Candidate{name, size, rank});
    if (inserted) return;
    Candidate &c = it->second;
    if (rank < c.rank || (rank == c.rank && name < c.name)) c = {name, size, rank};
  };

  for (const loader::Symbol &s : image.symbols) {
    if (!s.defined || s.type != loader::SymbolType::func) continue;
    if (sized_only && s.size == 0) continue;
    offer(function_address(image, s), s.name, s.size, bind_rank(s.bind));
  }
  if (image.format == loader::Format::pe && image.entry && !best.contains(*image.entry))
    offer(*image.entry, "entry", 0, 3);

  std::vector<FunctionSymbol> out;
  out.reserve(best.size());
  for (auto &[addr, c] : best) out.push_back({addr, std::move(c.name), c.size});
  return out;
}

std::vector<Function> seed_functions(const loader::Image &image, Lifter &lifter) {
  std::vector<Function> out;
  const bool pe = image.format == loader::Format::pe;
  for (FunctionSymbol &f : function_symbols(image, !pe)) {
    Function fn{f.entry, std::move(f.name), {}};
    if (f.size != 0) {
      fn.body.emplace_back(f.entry, f.entry + (f.size - 1));
    } else if (pe) {
      // .pdata is sorted by start; use the entry that begins here.
      auto it = std::lower_bound(image.function_ranges.begin(), image.function_ranges.end(), f.entry,
                                 [](const loader::FunctionRange &r, std::uint64_t a) { return r.start < a; });
      if (it != image.function_ranges.end() && it->start == f.entry && it->end > it->start)
        fn.body.emplace_back(it->start, it->end - 1);
      else
        fn.body = lifter.flow_body(f.entry);
    }
    if (!fn.body.empty()) out.push_back(std::move(fn));
  }

  // Every unwind entry (PE .pdata, ELF .eh_frame) is a function the file
  // describes; name it the way Ghidra names unnamed functions. Entries that
  // start inside a known body are chained records for part of a function.
  if (!image.function_ranges.empty()) {
    std::vector<AddressRange> known;
    for (const Function &f : out) known.insert(known.end(), f.body.begin(), f.body.end());
    std::sort(known.begin(), known.end());
    // Ranges may nest; track the furthest end seen so far for each prefix.
    std::vector<std::uint64_t> reach(known.size());
    for (std::size_t i = 0; i < known.size(); ++i)
      reach[i] = i == 0 ? known[i].second : std::max(reach[i - 1], known[i].second);
    auto inside = [&](std::uint64_t a) {
      auto it = std::upper_bound(known.begin(), known.end(), AddressRange{a, UINT64_MAX});
      if (it == known.begin()) return false;
      return reach[static_cast<std::size_t>(it - known.begin()) - 1] >= a;
    };
    std::vector<Function> extra;
    for (const loader::FunctionRange &r : image.function_ranges) {
      if (r.end <= r.start || inside(r.start)) continue;
      const loader::Region *region = image.memory.find(r.start);
      if (region == nullptr || !region->perms.exec) continue;
      std::string hex;
      for (std::uint64_t v = r.start; v != 0 || hex.empty(); v >>= 4) hex.insert(hex.begin(), "0123456789abcdef"[v & 0xf]);
      if (hex.size() < 8) hex.insert(0, 8 - hex.size(), '0');
      extra.push_back({r.start, "FUN_" + hex, {{r.start, r.end - 1}}});
    }
    for (Function &f : extra) out.push_back(std::move(f));
    std::sort(out.begin(), out.end(), [](const Function &a, const Function &b) { return a.entry < b.entry; });
  }
  return out;
}

std::optional<FunctionSymbol> find_function(const loader::Image &image, const std::string &name) {
  for (FunctionSymbol &f : function_symbols(image))
    if (f.name == name) return std::move(f);
  // The chosen name at an address may hide an alias; look at raw symbols too.
  for (const loader::Symbol &s : image.symbols)
    if (s.defined && s.type == loader::SymbolType::func && s.name == name)
      return FunctionSymbol{function_address(image, s), s.name, s.size};
  return std::nullopt;
}

}  // namespace revkit::lift
