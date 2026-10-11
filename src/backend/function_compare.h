// Comparing any two functions (docs/diff.md "Comparing two functions"):
// which variables of two decompilations correspond, so a name or a type can
// be ported from one to the other, and which names are the decompiler's own.
#pragma once

#include "revkit/v1/decompile.pb.h"

#include <cstdint>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// A name the decompiler made up (param_1, local_14, uVar2, pcVar3, pNVar4,
// in_RAX, unaff_RBX, extraout_EAX, auStack_28, local_res8, stack0x00000008)
// rather than one someone gave.
bool IsDefaultVariableName(std::string_view name);

struct VariablePairing {
  int a = -1, b = -1;  // indexes into each function's variables; -1: no partner
  std::uint32_t instructions = 0;  // corresponding instructions that print both
  std::uint32_t lines = 0;         // C lines that read the same with both in one place
  bool parameter = false;          // paired by position
};

// Pairs the parameters and locals (never globals) of two decompilations.
// Parameters pair by position. The rest by votes: each pair of
// corresponding instructions (`partner`: an instruction address of A to
// its partner in B, the instruction map's EQUAL and CHANGED pairs) whose
// tokens print as many variables on both sides votes for the variables in
// the same places; each pair of C lines (aligned by LCS) that read the same
// once variables and default names are abstracted votes likewise. A pair is
// kept when each is the other's strict best, repeatedly over what is left.
// Returns every variable of A in order (paired or alone), then B's alone.
// Deterministic.
std::vector<VariablePairing> PairVariables(const pb::DecompiledFunction &a, const pb::DecompiledFunction &b,
                                           const std::unordered_map<std::uint64_t, std::uint64_t> &partner);

}  // namespace revkit::backend
