// Rebase (docs/memory-map.md, "Rebase: setting the image base"): the image
// backend's rules for what moves with a program's image base, on top of
// the fact store's (facts::Shift, facts::Relocator).
#pragma once

#include "revkit/facts/fact_db.h"

#include <google/protobuf/message.h>

#include <memory>

namespace revkit::backend {

// The backend's relocator: a key's address moves unless it is a type
// definition, a memory-map edit (its address 0 is a container) or the
// Rebase key itself; a user reference's target (its sub), an image block's
// start (a memory-map edit's sub) and a region's start (its value) move;
// and so do the request bodies kept in op metadata.
std::shared_ptr<const facts::Relocator> Relocator();

// The Rebase key of a program space, and the Shift live there at a
// snapshot (identity when the program is at its import base).
facts::FactKey RebaseKey(facts::SpaceId space);

// A program's language set after import (FactKind::Language, docs/api.md
// "Changing a program's language"): its key, and the (language, compiler)
// the value says; ("", "") for the imported language.
facts::FactKey LanguageKey(facts::SpaceId space);
std::pair<std::string, std::string> LanguageOf(const facts::FactValue &v);
facts::Shift ShiftAt(const facts::Snapshot &snap, facts::SpaceId space);

// Every Address of the default space (an empty space name) in `m`, and a
// memory-map edit's region start, moved by `shift`.
void ShiftAddresses(google::protobuf::Message &m, const facts::Shift &shift);

// An op's key, value and request body as read with `shift` (the log keeps
// them image-relative).
facts::Op ShiftedOp(facts::Op op, const facts::Shift &shift);

}  // namespace revkit::backend
