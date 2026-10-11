// DefineType assertions: types described through the API (TypeNode), interned
// into revkit's type model and stored as TYPE_DEF records like the debug-info
// importers' (type_record.h). Also the reverse, a stored type as the API's
// TypeDefinition.
#pragma once

#include "api_util.h"

#include "revkit/types/store.h"
#include "revkit/v1/assertion.pb.h"
#include "revkit/v1/types.pb.h"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace revkit::backend {

// What a request's define_type bodies define, by request index.
struct DefinedTypes {
  // Content hash per assertion index; empty for other bodies.
  std::vector<std::string> hash;
  // Encoded TYPE_DEF record per assertion index (define_type only).
  std::vector<std::string> record;
  // The define_type bodies as stored: assertion_index references replaced
  // by the hashes they resolve to.
  std::vector<pb::AssertionBody> stored;
  bool any() const {
    for (const auto &h : hash)
      if (!h.empty()) return true;
    return false;
  }
};

// The records of a stored type and every type it reaches (q::Types), empty
// when the program doesn't define `hash`.
using ClosureFn = std::function<std::vector<std::pair<std::string, std::string>>(const std::string &hash)>;

// Interns every define_type of `assertions` as one batch. `pointer_size` is
// the program's, for POINTER nodes of size 0. Returns "" or an error that
// starts with "assertions[i]: ".
std::string DefineTypes(const google::protobuf::RepeatedPtrField<pb::AssertionInput> &assertions,
                        std::uint32_t pointer_size, const ClosureFn &closure, DefinedTypes &out);

// `id` (of `store`) as a DefineType node, its references made by `ref`; a
// DefineType of it interns to the same type (and hash).
pb::TypeNode TypeNodeOf(const types::TypeStore &store, types::TypeId id,
                        const std::function<pb::TypeNodeRef(types::TypeId)> &ref);

// "__stdcall" and so on: TypeNode.calling_convention's spelling.
std::string CallingConventionName(types::CallConv cc);

// `id` (of `store`) as the API describes it: kind, size, names and the hashes
// of what it references.
void DescribeType(const types::TypeStore &store, types::TypeId id, pb::TypeDefinition &out);

}  // namespace revkit::backend
