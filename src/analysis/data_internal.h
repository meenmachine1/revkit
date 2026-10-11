// Shared by data.cc and strings.cc.
#pragma once

#include "internal.h"
#include "revkit/analysis/data.h"

#include <functional>

namespace revkit::analysis::detail {

// Runs fn(0..n-1), perhaps in parallel.
using Parallel = std::function<void(std::size_t, const std::function<void(std::size_t)> &)>;

// Ghidra's StringsAnalyzer over the program's loaded, initialized and
// accessible memory: each string it would make is offered to `put`, in the
// order Ghidra makes them. `undefined_range(first, last)`: only undefined
// bytes and undefinedN data there; `pad_free(first, last)`: no code unit
// at all there; `item_containing(a)`: analysis data around an address.
void search_strings(const ProgramInfo &info, const DataProgramInfo &data, ByteReader &bytes,
                    const std::function<bool(std::uint64_t, std::uint64_t)> &undefined_range,
                    const std::function<bool(std::uint64_t, std::uint64_t)> &pad_free,
                    const std::function<const DataItem *(std::uint64_t)> &item_containing,
                    const std::function<void(DataItem)> &put, const Parallel &parallel);

// FlowGraph::data_refs of the `count` instructions one flow decoded, from
// `start`; `at` finds one decoded instruction (nulls if none).
struct DecodedAt {
  const lift::Instruction *insn = nullptr;
  const FlowInsn *flow = nullptr;
};
void collect_data_refs(const ProgramInfo &info, ByteReader &bytes, std::uint64_t start, std::size_t count,
                       const std::function<DecodedAt(std::uint64_t)> &at, std::vector<DataRef> &out);

}  // namespace revkit::analysis::detail
