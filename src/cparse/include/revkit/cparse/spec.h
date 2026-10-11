// Profiles from Ghidra's compiler specs (needs revkit::lift and a Ghidra
// install: link revkit::cparse_spec).
#pragma once

#include "revkit/cparse/cparse.h"

#include <string>
#include <vector>

namespace revkit::cparse {

// The compiler spec's <data_organization>, as revkit::lift reads it.
DataOrganization read_data_organization(const std::string &language_id, const std::string &compiler_id);

// profile_for() with the language's compiler spec read from the Ghidra
// install (lift::initialize() must have been called). `format` is the
// program's ("elf", "pe", ...). Throws lift::LiftError for an unknown
// language.
Profile profile_for_language(const std::string &language_id, const std::string &compiler_id,
                             const std::string &format, std::vector<std::string> *notes = nullptr);

}  // namespace revkit::cparse
