// The data program (analysis::describe_data): what the loader says about a
// hostile ELF or PE's data before analysis runs: its blocks, relocated
// pointer slots and their targets, the .got entries, the PE headers,
// exception table and import slots it marks defined. The first byte picks
// the format.
#include "revkit/analysis/data.h"
#include "revkit/loader/load.hh"

#include <cstddef>
#include <cstdint>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  if (size < 1) return 0;
  auto bytes = std::make_shared<loader::Bytes>(size - 1);
  for (std::size_t i = 1; i < size; ++i) (*bytes)[i - 1] = std::byte{data[i]};
  loader::Image img;
  try {
    img = (data[0] & 1) ? loader::parse_pe(std::move(bytes)) : loader::parse_elf(std::move(bytes));
  } catch (const loader::LoadError &) {
    return 0;
  }
  const analysis::DataProgramInfo info = analysis::describe_data(img);
  for (const auto &[slot, target] : info.pointers) {
    (void)info.block(slot);
    (void)info.has_relocation(target);
  }
  return 0;
}
