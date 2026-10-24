// A .nds image: the header, overlay tables, NitroFS, the module parameters,
// BLZ and the autoload split (revkit::nds::parse_nds).
#include "revkit/nds/rom.hh"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  std::span<const std::uint8_t> d(data, size);
  std::string e;
  revkit::nds::NdsLimits limits;
  limits.max_module = 4u << 20;
  limits.max_total = 16u << 20;
  limits.max_files = 4096;
  if (auto r = revkit::nds::parse_nds(d, &e, true, limits)) {
    std::size_t n = 0;
    for (const auto &m : r->modules) n += m.data.size() + m.name.size();
    for (const auto &f : r->files) n += f.path.size();
    (void)n;
  }
  // The pieces alone, on the same bytes.
  (void)revkit::nds::find_module_params(d, 0x02000000);
  std::vector<revkit::nds::NdsFile> files;
  std::vector<revkit::nds::NdsDirectory> dirs;
  std::vector<std::string> warnings;
  const std::size_t half = size / 2;
  revkit::nds::parse_nitrofs(d.subspan(0, half), d.subspan(half), files, dirs, warnings, 4096);
  revkit::nds::NdsModule main;
  main.address = 0x02000000;
  main.data.assign(data, data + size);
  if (auto p = revkit::nds::find_module_params(d, main.address)) {
    std::vector<revkit::nds::NdsAutoload> lists;
    std::vector<revkit::nds::NdsModule> out;
    revkit::nds::split_autoloads(*p, main, lists, out, limits);
  }
  return 0;
}
