#include "graph_util.h"

#include <algorithm>

namespace revkit::types::detail {

Components tarjan(const Adjacency &adj) {
  const std::size_t n = adj.size();
  Components out;
  out.comp.assign(n, kNone);
  std::vector<std::uint32_t> index(n, kNone), low(n, 0);
  std::vector<bool> on_stack(n, false);
  std::vector<std::uint32_t> stack;
  struct Frame { std::uint32_t v; std::size_t next; };
  std::vector<Frame> calls;
  std::uint32_t counter = 0;

  auto visit = [&](std::uint32_t v) {
    index[v] = low[v] = counter++;
    stack.push_back(v);
    on_stack[v] = true;
    calls.push_back({v, 0});
  };
  for (std::uint32_t s = 0; s < n; ++s) {
    if (index[s] != kNone) continue;
    visit(s);
    while (!calls.empty()) {
      std::uint32_t v = calls.back().v;
      if (calls.back().next < adj[v].size()) {
        std::uint32_t w = adj[v][calls.back().next++];
        if (index[w] == kNone) visit(w);
        else if (on_stack[w]) low[v] = std::min(low[v], index[w]);
        continue;
      }
      calls.pop_back();
      if (!calls.empty()) low[calls.back().v] = std::min(low[calls.back().v], low[v]);
      if (low[v] != index[v]) continue;
      std::vector<std::uint32_t> members;
      std::uint32_t w;
      do {
        w = stack.back();
        stack.pop_back();
        on_stack[w] = false;
        out.comp[w] = std::uint32_t(out.members.size());
        members.push_back(w);
      } while (w != v);
      std::sort(members.begin(), members.end());
      out.members.push_back(std::move(members));
    }
  }
  return out;
}

std::vector<std::uint32_t> cyclic_nodes(const Adjacency &adj) {
  Components c = tarjan(adj);
  std::vector<std::uint32_t> out;
  for (std::size_t ci = 0; ci < c.members.size(); ++ci) {
    const auto &m = c.members[ci];
    bool cyclic = m.size() > 1 || std::find(adj[m[0]].begin(), adj[m[0]].end(), m[0]) != adj[m[0]].end();
    if (!cyclic) continue;
    if (out.empty()) out.assign(adj.size(), kNone);
    for (std::uint32_t v : m) out[v] = std::uint32_t(ci);
  }
  return out;
}

}  // namespace revkit::types::detail
