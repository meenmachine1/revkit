// libFuzzer target for the C parser: the preprocessor, the declaration
// parser, layout, linking and printing.
//
// Input: one flags byte (the target, C++, constants as enums, a single
// declaration, a second linked unit), then up to
// three files separated by NUL bytes: the source, and "a.h" and "b.h",
// which it may #include (as may they each other). make_seeds.py makes
// seeds from headers.
#include "revkit/cparse/cparse.h"
#include "revkit/types/print.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace {

class MemoryFiles final : public revkit::cparse::FileSystem {
 public:
  std::map<std::string, std::string> files;
  std::optional<std::string> resolve(const std::string &path) override {
    std::string p = path;
    // Normalize "dir/./x" and "dir/../x" the way canonical paths would.
    for (std::size_t i; (i = p.find("/./")) != std::string::npos;) p.erase(i, 2);
    for (std::size_t i; (i = p.find("/../")) != std::string::npos;) {
      std::size_t s = i == 0 ? 0 : p.rfind('/', i - 1);
      p.erase(s == std::string::npos ? 0 : s, i + 3 - (s == std::string::npos ? 0 : s));
    }
    if (files.contains(p)) return p;
    return std::nullopt;
  }
  std::optional<std::string> read(const std::string &canonical, std::size_t max) override {
    auto it = files.find(canonical);
    if (it == files.end() || it->second.size() > max) return std::nullopt;
    return it->second;
  }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  if (size < 1) return 0;
  const std::uint8_t flags = data[0];
  std::vector<std::string> parts(1);
  for (std::size_t i = 1; i < size; ++i) {
    if (data[i] == 0 && parts.size() < 3) parts.emplace_back();
    else parts.back() += char(data[i]);
  }
  MemoryFiles fs;
  fs.files["/fuzz/main.h"] = parts[0];
  if (parts.size() > 1) fs.files["/fuzz/a.h"] = parts[1];
  if (parts.size() > 2) fs.files["/fuzz/b.h"] = parts[2];

  static const std::vector<std::string> targets = cparse::profile_names();
  cparse::Options o;
  o.profile = *cparse::profile_named(targets[flags % targets.size()]);
  o.cplusplus = flags & 0x40;
  o.defines_as_enums = flags & 0x80;
  o.fs = &fs;
  o.include_dirs = {"/fuzz"};
  o.limits.max_bytes = 1 << 20;
  o.limits.max_expansion_tokens = 200'000;
  o.limits.max_tokens = 400'000;
  o.limits.max_types = 100'000;
  o.limits.max_nesting = 100;
  o.limits.wall_time = std::chrono::milliseconds(3000);
  types::TypeStore store;
  if (flags & 0x10) {
    // One declaration, as a retype's C text.
    std::optional<cparse::Declaration> d = cparse::parse_declaration(store, parts[0], o);
    return d && d->function ? types::prototype(store, d->type, d->name).empty() : 0;
  }
  std::vector<cparse::Source> sources = {{"/fuzz/main.h", {}, true}};
  std::vector<cparse::Result> units;
  units.push_back(cparse::parse(store, sources, o));
  if (flags & 0x20) {
    // A second unit, linked with the first.
    std::vector<cparse::Source> second = {{"/fuzz/a.h", {}, true}};
    units.push_back(cparse::parse(store, second, o));
    cparse::link(store, units);
  }
  std::size_t chars = 0;
  for (const auto &u : units) {
    for (const auto &n : u.named) chars += types::definition(store, n.id).size();
    for (const auto &p : u.prototypes) chars += types::prototype(store, p.type, p.name).size();
  }
  return chars == 0xffffffff;  // keep the printing from being optimized away
}
