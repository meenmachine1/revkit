// Reading decompiler inputs (src/lift decomp_inputs.hh) from JSON: Ghidra's
// export (tools/ghidra-export/ghidra_dbexport.py, docs/decompiler-inputs.md)
// or just the function list of a reference file.
#pragma once

#include "json.hh"

#include "revkit/lift/decomp_inputs.hh"

namespace rklift {

// A ghidra_dbexport.py document. Throws JsonError on malformed input.
revkit::lift::DecompilerInputs inputs_from_export(const Json &doc);

// Functions (entry, name, body) of a reference-format document, with
// nothing known about their signatures, as for a function Ghidra's analysis
// created without one.
revkit::lift::DecompilerInputs inputs_from_reference(const Json &doc);

// The inverse of inputs_from_export: `in` in the decompiler-inputs format,
// with "symbols_complete" telling rk-lift --inputs whether to synthesize
// Ghidra's default names where the document has no symbol (false for
// revkit's own inputs).
Json inputs_to_json(const revkit::lift::DecompilerInputs &in, bool synthesize_names);

}  // namespace rklift
