// MSVC and PE markup (revkit::msvc::analyze) over a hostile PE: RTTI
// (complete object locators, class hierarchies, base class arrays,
// vftables), .pdata and UNWIND_INFO, C scope tables, C++ EH FuncInfo, TLS,
// Control Flow Guard and the imports' thunks. fuzz_pe stops at the loader;
// this runs what an import of the PE does next.
#include "revkit/loader/load.hh"
#include "revkit/msvc/msvc.h"

#include <cstddef>
#include <cstdint>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  auto bytes = std::make_shared<loader::Bytes>(size);
  for (std::size_t i = 0; i < size; ++i) (*bytes)[i] = std::byte{data[i]};
  loader::Image img;
  try {
    img = loader::parse_pe(std::move(bytes));
  } catch (const loader::LoadError &) {
    return 0;
  }
  msvc::MarkupOptions o;
  o.this_extent = [](std::uint64_t entry) { return entry & 0xff; };
  try {
    const msvc::Markup m = msvc::analyze(img, o);
    for (const auto &[what, n] : m.counts) (void)msvc::count_pass(what);
  } catch (const loader::LoadError &) {
    // analyze reports problems as warnings; anything else it throws is a
    // finding.
  }
  return 0;
}
