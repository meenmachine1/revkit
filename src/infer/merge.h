// Combining what is known about one function into its prototype.
#pragma once

#include "abi.h"
#include "sigdb.h"
#include "revkit/infer/decompiler.h"
#include "revkit/infer/vtype.h"

#include <functional>
#include <optional>
#include <vector>

namespace revkit::infer {

struct Evidence {
  // The function's own decompilation in round 0, where its callees were
  // unlocked (imports aside): its parameter and return storage. Later
  // rounds lock callees, and a callee with a parameter too many makes its
  // callers pass a register through, which then looks like their own
  // parameter, so storage is taken from round 0 only.
  const Observation *self0 = nullptr;
  // Its decompilation at this round: the types its values have now.
  const Observation *self = nullptr;
  // Calls to it in its callers' round-0 decompilations, where nothing about
  // it was known: what callers pass and read without being told.
  std::vector<const CallSite *> unlocked;
  // Calls to it in its callers' decompilations at this round, which were
  // told its previous prototype: the types the callers' values have.
  std::vector<const CallSite *> current;
  bool interprocedural = true;
  // The current prototype of the function at an address (a callee, or a
  // function whose address is passed or returned), if known.
  std::function<std::optional<Prototype>(std::uint64_t)> proto_of;
  // The prototype shared by the functions of the function-pointer table
  // holding a data address, if known.
  std::function<std::optional<Prototype>(std::uint64_t)> table_proto;
  // Whether the function at an address reads argument `index` itself
  // (in a register, `arg`): its round-0 decompilation, where its callees
  // weren't locked, has a parameter there that its own code reads (not
  // only passes on, nor a register save area's), and its current
  // prototype has the position among its named parameters.
  std::function<bool(std::uint64_t, std::size_t, const Slot &)> callee_reads;
  // The return type of a function it tail-calls (a jump to another
  // function's entry), when that one returns a value.
  std::optional<VType> tail_ret;
};

// The prototype the evidence supports. `abi` may be null (unknown
// convention): then only the function's own view is used.
Prototype merge(const Abi *abi, const Evidence &ev, const DataOrg &org);

// Round k's prototype from round k-1's and round k's merged evidence: the
// same shape, each type the join of both, so a type only ever becomes
// more specific and the iteration is monotone.
Prototype join(const Prototype &prev, const Prototype &next);

// What the members of a function-pointer table agree on: the commonest
// arity, return presence and varargs, and per position the commonest
// informative type. `own` fills what no member says. Nullopt when the
// members disagree on arity too much to be one C type.
std::optional<Prototype> family_vote(const Prototype &own, const std::vector<Prototype> &members);

// The prototype as shown: types still unknown are spelled as the C type a
// value of that size and kind most often has in the system headers
// (Priors), and parameter integers, whose signedness the decompiler infers
// from comparisons compilers choose freely, take the headers' commonest
// integer of their size.
Prototype finalize(const Prototype &p, const DataOrg &org, bool keep_return_width = false);

}  // namespace revkit::infer
