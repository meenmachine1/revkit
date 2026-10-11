// Graph helpers shared by the store and the printer (internal).
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace revkit::types::detail {

constexpr std::uint32_t kNone = 0xffffffffu;
using Adjacency = std::vector<std::vector<std::uint32_t>>;

struct Components {
  std::vector<std::uint32_t> comp;                  // node -> component index
  std::vector<std::vector<std::uint32_t>> members;  // in reverse topological order (sinks first)
};

// Tarjan's algorithm, iterative so deep graphs can't overflow the stack.
Components tarjan(const Adjacency &adj);

// Component id for each node on a cycle (a component with more than one
// node, or a self-loop), kNone for the rest. Empty if the graph is acyclic.
std::vector<std::uint32_t> cyclic_nodes(const Adjacency &adj);

struct VecHash {
  std::size_t operator()(const std::vector<std::uint32_t> &v) const noexcept {
    std::uint64_t h = 1469598103934665603ull;
    for (std::uint32_t x : v) h = (h ^ x) * 1099511628211ull;
    return std::size_t(h ^ (h >> 29));
  }
};

}  // namespace revkit::types::detail
