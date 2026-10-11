// Data analysis results (analysis::Data) as decompiler data facts, named
// and typed as Ghidra's database has them.
#pragma once

#include "revkit/analysis/data.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/loader/image.hh"

#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <unordered_map>

namespace revkit::inputs {

// The program's bytes as patched (Program::read); empty: the image's.
using ByteRead = std::function<void(std::uint64_t addr, std::span<std::byte> out)>;

// Adds `list`'s strings (s_<text>_<address>, u_...) and accessed data
// (DAT_<address>) to `in.data`, named and typed as Ghidra's database has
// them. Where the loader already has data (an ELF object symbol), a string
// takes its type and keeps its name. `names` gets the new labels. Returns
// the items added, by address with their names (for drop_overlapped).
std::map<std::uint64_t, std::string> add_analyzed_values(const analysis::DataList &list, const loader::Image &image,
                                                         const std::string &prefix, lift::DecompilerInputs &in,
                                                         std::unordered_map<std::uint64_t, std::string> &names,
                                                         const ByteRead &read = {});

// Then the pointers, named by pointer_name.
std::map<std::uint64_t, std::string> add_analyzed_pointers(const analysis::DataList &list, const loader::Image &image,
                                                           const SlotNames &names, lift::DecompilerInputs &in,
                                                           const ByteRead &read = {});

// Drops the data that lies inside a variable the debug info added since
// (a DWARF or PDB variable, which carries its source_name): Ghidra lays the
// debug info's typed variables over what the loader marked (relocated
// pointer slots) and its analysis never lays data inside them.
void drop_overlapped(lift::DecompilerInputs &in);

}  // namespace revkit::inputs
