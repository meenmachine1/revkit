// Populating a Function ID database from programs with symbols, as
// Ghidra's FidServiceLibraryIngest does (docs/fid.md, "Creating databases").
#pragma once

#include "revkit/fid/db.h"
#include "revkit/fid/program.h"

#include <functional>
#include <map>
#include <unordered_map>
#include <set>
#include <string>
#include <vector>

namespace revkit::fid {

struct LibraryInfo {
  std::string family, version, variant;
  std::string language;  // "x86:LE:64:default"
  std::string compiler;  // "gcc"
};

// Why a function wasn't added (FidPopulateResult.Disposition).
enum class Disposition : std::uint8_t {
  included,
  no_symbol,      // only a default name (FUN_...)
  thunk,
  too_short,      // fewer than 4 instructions
  filtered,       // the caller's filter refused it
  duplicate,      // the same hash, name and callees as one already added
};

struct IngestReport {
  std::map<Disposition, std::size_t> counts;
  std::set<std::string> unresolved;  // callee names no function of the library has
};

class LibraryBuilder {
 public:
  // Adds the library's record to `db` (common: callee names too common to
  // relate by, Ghidra's "common symbols file").
  LibraryBuilder(Database &db, const LibraryInfo &info, std::set<std::string> common = {});

  // One program's functions. `is_default_name(name)` says a name is only a
  // default one (no symbol). `path` labels the program in the records.
  void add_program(const ProgramHashes &program, const std::string &path,
                   const std::function<bool(const std::string &)> &is_default_name);
  // Relations by callee name (resolveNamedRelations); then index the database.
  IngestReport finish();

 private:
  struct Pending {
    std::int64_t id;
    std::string name;
    std::uint64_t full;  // 0 with no hash known
    bool hashed;
  };
  Database &db_;
  std::int64_t library_ = 0;
  std::set<std::string> common_;
  std::set<std::uint64_t> unique_;
  std::vector<std::pair<std::int64_t, Pending>> unresolved_;  // (caller id, callee)
  struct Named {
    std::int64_t id;
    std::uint64_t full, specific;
  };
  std::map<std::string, std::vector<Named>> by_name_;
  std::unordered_map<std::int64_t, std::uint64_t> caller_full_;  // committed id -> full hash
  IngestReport report_;
};

}  // namespace revkit::fid
