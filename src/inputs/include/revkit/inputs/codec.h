// Canonical encodings of decompiler inputs (lift::DecompilerInputs and its
// parts), for fact-store memos: facts::encode / facts::decode work on them.
#pragma once

#include "revkit/facts/codec.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/param_id.hh"

namespace revkit::facts {

#define REVKIT_INPUTS_CODEC(T)                     \
  template <>                                      \
  struct Codec<T> {                                \
    static void encode(Encoder &e, const T &v);    \
    static T decode(Decoder &d);                   \
  };

REVKIT_INPUTS_CODEC(lift::DecompElement)
REVKIT_INPUTS_CODEC(lift::StorageVarnode)
REVKIT_INPUTS_CODEC(lift::ParamFacts)
REVKIT_INPUTS_CODEC(lift::LocalFacts)
REVKIT_INPUTS_CODEC(lift::FunctionFacts)
REVKIT_INPUTS_CODEC(lift::DataFacts)
REVKIT_INPUTS_CODEC(lift::ExternalRefFacts)
REVKIT_INPUTS_CODEC(lift::LabelFacts)
REVKIT_INPUTS_CODEC(lift::CommentFacts)
REVKIT_INPUTS_CODEC(lift::TrackedFacts)
REVKIT_INPUTS_CODEC(lift::EquateFacts)
REVKIT_INPUTS_CODEC(lift::BlockFacts)
REVKIT_INPUTS_CODEC(lift::Mutability)
REVKIT_INPUTS_CODEC(lift::DecompilerInputs)
REVKIT_INPUTS_CODEC(inputs::FunctionInputs)
REVKIT_INPUTS_CODEC(lift::CommittedSignature)

#undef REVKIT_INPUTS_CODEC

}  // namespace revkit::facts
