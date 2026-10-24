// Type archives: TypeService.ExportTypeArchive, and the sidecar check of
// ParseC (docs/types.md#type-archives). An archive is a self-contained C
// header (revkit/cparse/archive.h) plus a JSON sidecar (TypeArchiveSidecar)
// of content hashes, categories, provenance and the data model; importing
// one is a header import with the sidecar, so both use ParseC.
#pragma once

#include "model.h"
#include "parse_c.h"
#include "program.h"

#include "revkit/api/backend.h"
#include "revkit/cparse/archive.h"
#include "revkit/cparse/cparse.h"
#include "revkit/v1/types.pb.h"

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>

namespace revkit::backend {

struct TypeArchiveContext {
  const Program &program;
  std::string program_name;
  const NamedTypes &names;
  const std::map<std::string, std::string> &categories;  // named key -> path
  // types.resolved: the types as their uses see them (bound names stand in
  // for the definitions they replace), so a header naming a type by name
  // means what the program means by it.
  ProgramTypes::Closure closure;
  // The provenance of a name's live BindTypeName, if it has one.
  std::function<std::optional<pb::Provenance>(const std::string &key)> binding;
};

// How a header for decompiled C is written (ExportC, ExportDecompScratch):
// the archive writer's dialect, decompiler view and provided names.
struct HeaderOptions {
  cparse::Dialect dialect = cparse::Dialect::C11;
  bool decompiler_view = false;
  std::set<std::string> provided;
};

api::Status ExportTypeArchive(const TypeArchiveContext &c, const pb::ExportTypeArchiveRequest &req,
                              pb::ExportTypeArchiveResponse &resp, const HeaderOptions *header = nullptr);

// The sidecar's JSON, read; nullopt (and `error`) when it isn't one.
std::optional<pb::TypeArchiveSidecar> ReadTypeArchiveSidecar(const std::string &json, std::string *error);

// A data model as the sidecar writes it, and back.
pb::TypeArchiveDataModel DataModelOf(const cparse::Profile &p);
cparse::Profile ProfileOf(const pb::TypeArchiveDataModel &m);

// The SHA-256 of `text`, as lowercase hex.
std::string Sha256Hex(std::string_view text);

// Where an archive import puts its provenance: kind IMPORT, id "archive",
// version the archive's origin.
inline constexpr const char *kArchiveImporter = "archive";

}  // namespace revkit::backend
