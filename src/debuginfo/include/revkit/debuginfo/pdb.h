// PDB reader: MSF 7.00 container, PDB info, DBI, TPI/IPI and CodeView
// symbols, with types imported into a TypeStore.
//
// Everything is read from the file's bytes with bounds checks. A file that
// isn't an MSF 7.00 PDB, or whose stream directory or PDB info stream is
// unreadable, raises PdbError; damage past that (a bad module stream, type
// record or symbol) is reported in DebugInfo::diagnostics and skipped.
//
// Addresses: CodeView symbols say section:offset. The DBI section map and
// section headers (through OMAP, when the image was rewritten after
// linking) turn that into an RVA, and PdbOptions::image_base is added to
// give the virtual addresses in DebugInfo::functions and ::variables.
#pragma once

#include "revkit/debuginfo/dwarf.h"
#include "revkit/types/store.h"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace revkit::debuginfo {

class PdbError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

using PdbGuid = std::array<std::uint8_t, 16>;  // as stored (the PE's RSDS byte order)

// "{F04F0324-582A-FEB2-4C4C-44205044422E}" as Windows tools print a GUID.
std::string guid_string(const PdbGuid &guid);

// The PDB info stream plus the DBI header fields that identify the build.
struct PdbIdentity {
  std::uint32_t version = 0;    // 20000404 for VC7.0 and later
  std::uint32_t signature = 0;  // time stamp; what an NB10 record matches
  std::uint32_t age = 0;        // what the PE's RSDS record matches
  PdbGuid guid{};
  std::uint32_t dbi_age = 0;
  std::uint16_t machine = 0;  // IMAGE_FILE_MACHINE_*, from the DBI stream
  bool has_ipi = false;       // the IPI stream is present (VC140 feature)
  std::map<std::string, std::uint32_t> named_streams;  // "/names", "/LinkInfo", ...

  // True if this PDB was written for an image whose RSDS record has this
  // GUID and age (the linker gives both streams the image's age).
  bool matches(const PdbGuid &rsds_guid, std::uint32_t rsds_age) const {
    return guid == rsds_guid && (age == rsds_age || dbi_age == rsds_age);
  }
};

struct PdbSectionHeader {
  std::string name;
  std::uint32_t virtual_size = 0;
  std::uint32_t virtual_address = 0;
  std::uint32_t raw_size = 0;
  std::uint32_t characteristics = 0;
};

// A DBI section contribution: which module put which bytes in a section.
struct PdbContribution {
  std::uint16_t section = 0;  // 1-based
  std::uint32_t offset = 0;
  std::uint32_t size = 0;
  std::uint32_t characteristics = 0;
  std::uint16_t module = 0;  // index into PdbDebugInfo::modules
  std::uint64_t address = 0;  // image_base + RVA; 0 if the section is unknown
};

struct PdbModule {
  std::string name;    // object file, or "* Linker *"
  std::string object;  // object or library the module came from
  std::uint16_t stream = 0xffff;  // module symbol stream, 0xffff if none
  std::uint32_t symbol_bytes = 0;
  std::uint32_t c13_line_bytes = 0;
  std::uint16_t source_files = 0;
  std::string compiler;            // S_COMPILE2/3 version string, if any
  std::optional<std::uint8_t> language;  // CV_CFL_LANG: 0 C, 1 C++, 7 MASM, ...
};

// An S_PUB32 public symbol.
struct PdbPublic {
  std::string name;       // as stored (mangled for C++)
  std::string demangled;  // demangled, or `name` if it isn't mangled
  std::uint16_t segment = 0;
  std::uint32_t offset = 0;
  std::uint64_t address = 0;  // image_base + RVA; 0 if unmapped
  bool code = false;
  bool function = false;
};

// An S_UDT: a name the program gives a type (a typedef, or a tag name).
struct PdbTypeName {
  std::string name;
  types::TypeId type;
};

struct PdbDebugInfo : DebugInfo {
  PdbIdentity identity;
  std::vector<PdbSectionHeader> sections;
  std::vector<PdbModule> modules;
  std::vector<PdbContribution> contributions;
  std::vector<PdbPublic> publics;      // sorted by address, then name
  std::vector<PdbTypeName> type_names;  // S_UDT records with typedefs created for them
};

struct PdbOptions {
  // Added to every RVA. Pass the image's base to get virtual addresses.
  std::uint64_t image_base = 0;
  // Point forward references (struct foo; in CodeView, a record with the
  // fwdref property) at the PDB's definition when it has exactly one.
  bool resolve_forward_refs = true;
};

// Reads just enough of the file to identify it (MSF directory, PDB info
// stream, DBI header). Throws PdbError.
PdbIdentity read_pdb_identity(std::span<const std::uint8_t> file);

// Reads the whole PDB: types into `store`, then functions (with prototypes
// and parameter names from each procedure's own symbols), globals, publics,
// modules and section contributions. Throws PdbError for an unreadable
// container; everything else goes to diagnostics.
PdbDebugInfo read_pdb(std::span<const std::uint8_t> file, types::TypeStore &store,
                      const PdbOptions &options = {});

}  // namespace revkit::debuginfo
