// Facts the image itself gives about how to decode its code: ARM/Thumb state
// and data embedded in code (literal pools), from ELF mapping symbols ($a,
// $t, $x, $d) and the Thumb bit of ARM function symbols.
#pragma once

#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"

#include <optional>
#include <string>
#include <vector>

namespace revkit::lift {

struct ContextRegion {
  std::string name;  // context variable, e.g. "TMode"
  std::uint32_t value = 0;
  std::uint64_t start = 0;
  std::uint64_t end = 0;  // exclusive
};

// Context to paint over the language defaults. Empty for most machines.
std::vector<ContextRegion> image_context(const loader::Image &image);

// Inclusive ranges of data inside code, marked by $d mapping symbols in
// ARM and AArch64 code sections. Sorted.
std::vector<AddressRange> embedded_data(const loader::Image &image);

// A function's entry address: the symbol value without the ARM Thumb bit.
std::uint64_t function_address(const loader::Image &image, const loader::Symbol &symbol);

// True if the symbol is an ARM function in Thumb state.
bool is_thumb_function(const loader::Image &image, const loader::Symbol &symbol);

}  // namespace revkit::lift
