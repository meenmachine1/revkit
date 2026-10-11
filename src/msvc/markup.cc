// analyze(): the passes over one image, merged.

#include "markup_internal.h"

#include <algorithm>

namespace revkit::msvc {

namespace detail {

bool Builder::claim(std::uint64_t address, std::uint64_t size) {
  const std::uint64_t last = address + (size - 1);
  if (last < address) return false;
  auto it = std::lower_bound(claimed_.begin(), claimed_.end(), std::make_pair(address, std::uint64_t{0}));
  if (it != claimed_.end() && it->first <= last) return false;
  if (it != claimed_.begin() && std::prev(it)->second >= address) return false;
  claimed_.insert(it, {address, last});
  return true;
}

}  // namespace detail

std::string count_pass(const std::string &what) {
  for (const char *m : {"rtti_classes", "vftables", "virtual_functions", "typed_this", "eh_functions", "eh_handlers"})
    if (what == m) return "msvc";
  return "pe";
}

Markup analyze(const loader::Image &image, const MarkupOptions &options) {
  Markup out;
  if (image.format != loader::Format::pe) return out;
  detail::Builder b(image, out);
  if (options.rtti) detail::rtti_markup(b, scan_rtti(image), options);
  if (options.pe) detail::pe_markup(b, options);
  std::sort(out.data.begin(), out.data.end(), [](const DataDef &x, const DataDef &y) { return x.address < y.address; });
  std::stable_sort(out.labels.begin(), out.labels.end(),
                   [](const LabelDef &x, const LabelDef &y) { return x.address < y.address; });
  out.labels.erase(std::unique(out.labels.begin(), out.labels.end(),
                               [](const LabelDef &x, const LabelDef &y) { return x.address == y.address; }),
                   out.labels.end());
  // One function per entry: the first pass's name and type, any pass's
  // request to make it.
  std::stable_sort(out.functions.begin(), out.functions.end(),
                   [](const FunctionDef &x, const FunctionDef &y) { return x.entry < y.entry; });
  std::vector<FunctionDef> merged;
  for (FunctionDef &f : out.functions) {
    if (!merged.empty() && merged.back().entry == f.entry) {
      FunctionDef &m = merged.back();
      m.create = m.create || f.create;
      if (m.name.empty()) m.name = std::move(f.name);
      if (!m.prototype.valid()) {
        m.prototype = f.prototype;
        m.this_type = f.this_type;
      }
      continue;
    }
    merged.push_back(std::move(f));
  }
  out.functions = std::move(merged);
  return out;
}

}  // namespace revkit::msvc
