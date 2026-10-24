// What Export C and the decomp scratch write around decompiled C
// (QueryService.ExportC, ExportDecompScratch; docs/api.md "Export C"):
// Ghidra's built-in type names for the program's data model, in the C
// dialect asked for.
#pragma once

#include "revkit/cparse/archive.h"
#include "revkit/cparse/cparse.h"
#include "revkit/v1/decompile.pb.h"
#include "revkit/v1/query.pb.h"
#include "revkit/v1/types.pb.h"

#include <set>
#include <string>

namespace revkit::backend {

cparse::Dialect DialectOf(revkit::v1::CDialect d);

// Ghidra's built-in type names as the decompiler prints them (undefined4,
// uint, code, ...), as typedefs of the data model's integers of their
// sizes, once (in a REVKIT_GHIDRA_TYPES guard), in `dialect`: C11 includes
// <stdbool.h> where C has no bool, C89 makes bool an unsigned char.
std::string GhidraBuiltinTypedefs(const cparse::Profile &profile, cparse::Dialect dialect);

// The type names GhidraBuiltinTypedefs defines: a header after it never
// writes them again (cparse::ArchiveOptions::provided).
const std::set<std::string> &GhidraBuiltinNames();

// The name a DecompiledFunction.function_types typedef defines
// ("typedef int _func_int_char_ptr(char *);" -> "_func_int_char_ptr").
std::string FunctionTypeName(const std::string &typedef_text);

// `typedef struct astruct_1 astruct_1;` for each struct, union and enum of
// an archive whose tag no typedef (nor `names`) already names, as the
// decompiler names them by their tags alone. `names` gains them.
std::string TagTypedefs(const revkit::v1::TypeArchiveSidecar &archive, std::set<std::string> &names);

// Whether `name` is a C identifier (a demangled `Scene::Update` isn't:
// C can't declare it).
bool CIdentifier(const std::string &name);

// Whether every _func_ name in `text` is in `names`.
bool FunctionTypesNamed(const std::string &text, const std::set<std::string> &names);

// A global a decompilation reads or writes as C declares it, with its
// address: `extern undefined4 DAT_02000ca0; /* 0x02000ca0 */`, the bounds
// of an array after the name.
std::string GlobalDeclaration(const revkit::v1::Variable &global);

}  // namespace revkit::backend
