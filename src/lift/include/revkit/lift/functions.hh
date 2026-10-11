// Functions known from file metadata, used until revkit has its own
// function discovery.
#pragma once

#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"

#include <string>
#include <vector>

namespace revkit::lift {

struct FunctionSymbol {
  std::uint64_t entry = 0;
  std::string name;
  std::uint64_t size = 0;  // 0 when the file doesn't say
};

// One entry per address, sorted, over defined function symbols that land in
// executable memory: ELF STT_FUNC (Thumb bit cleared), PE exports, and the PE
// entry point as "entry". Where several symbols share an address the name is
// global over weak over local, then lexically smallest. With `sized_only`,
// only ELF symbols with a size are considered.
std::vector<FunctionSymbol> function_symbols(const loader::Image &image, bool sized_only = false);

struct Function {
  std::uint64_t entry = 0;
  std::string name;
  std::vector<AddressRange> body;  // inclusive ranges, sorted
};

// The function list rk-lift reports, sorted by entry. ELF: STT_FUNC symbols
// with a size, body [value, value + size). PE: exports and the entry point,
// bodies from .pdata when it covers the entry, else from following control
// flow with `lifter`. Then every unwind-table function (.pdata, .eh_frame)
// not inside one of those, as "FUN_<addr>".
std::vector<Function> seed_functions(const loader::Image &image, Lifter &lifter);

// Find a function symbol by exact name.
std::optional<FunctionSymbol> find_function(const loader::Image &image, const std::string &name);

}  // namespace revkit::lift
