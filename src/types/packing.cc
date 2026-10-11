#include "revkit/types/packing.h"

#include <algorithm>
#include <utility>

namespace revkit::types {

void infer_packing(TypeGraph &g, const TypeStore &store, std::vector<std::pair<TypeId, std::uint32_t>> aggs) {
  std::sort(aggs.begin(), aggs.end());
  // Packing a struct changes its alignment, which can make an enclosing
  // struct look packed; a few passes reach the fixed point in practice.
  for (int pass = 0; pass < 4; ++pass) {
    std::vector<TypeId> packed;
    for (auto [id, cap] : aggs) {
      const auto *a = std::as_const(g).at(id).as<AggregateType>();
      if (!a || a->packed || a->alignment || !a->complete) continue;
      std::uint32_t max_align = 1;
      bool misaligned = false;
      for (const Field &f : a->fields) {
        std::uint32_t al = std::max<std::uint32_t>(1, std::min(g.align_of(f.type, store), cap));
        max_align = std::max(max_align, al);
        if (!f.bit_size && (f.bit_offset % 8 || (f.bit_offset / 8) % al)) misaligned = true;
      }
      if (misaligned || (a->kind != AggregateKind::Union && a->size % max_align)) packed.push_back(id);
    }
    if (packed.empty()) break;
    for (TypeId id : packed) g.at(id).as<AggregateType>()->packed = true;
  }
}

}  // namespace revkit::types
