// Function ID in the image backend (docs/fid.md, "In the daemon"): which
// databases a program is matched against, the databases opened once per
// file, and a program's hashes from a snapshot.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/facts/fact_db.h"
#include "revkit/fid/create.h"
#include "revkit/fid/db.h"
#include "revkit/fid/match.h"
#include "revkit/fid/program.h"
#include "revkit/loader/image.hh"

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace revkit::backend {

// The project NOTE (tag, at the project's own space) holding the project's
// attachments, and the program NOTE holding its rejected entries.
inline constexpr const char *kFidDatabasesTag = "revkit:fid.databases";
inline constexpr const char *kFidRejectedTag = "revkit:fid.rejected";
inline constexpr const char *kFidAnalyzer = "function-id";

// One scope's choices: files attached, builtin databases detached.
struct FidSettings {
  std::vector<std::string> attached;   // paths, in attach order
  std::set<std::string> detached;      // builtin ids ("builtin:vs2019_x64")
  friend bool operator==(const FidSettings &, const FidSettings &) = default;
};
std::string EncodeFidSettings(const FidSettings &s);
FidSettings DecodeFidSettings(const std::string &text);  // {} when it isn't one

// A program's rejected entries (program NOTE), sorted.
std::string EncodeFidRejected(const std::set<std::uint64_t> &entries);
std::set<std::uint64_t> DecodeFidRejected(const std::string &text);

// Databases by path, opened once while the file is unchanged (size, time),
// and the users' settings, kept in a JSON file when there is a place for
// it. Thread-safe.
class FidCatalog {
 public:
  // `ghidra_root`: where builtin databases are found; `user_store`: the
  // users' settings file ("" keeps them in memory).
  FidCatalog(std::string ghidra_root, std::string user_store);

  struct Opened {
    std::shared_ptr<const fid::Database> db;
    std::string error;
  };
  Opened Open(const std::string &path);
  // A file's libraries and function count, without reading its functions
  // (a database is opened only for a program of its language).
  struct Peeked {
    std::shared_ptr<const fid::Database::Peek> peek;
    std::string error;
    bool has_language(const std::string &language) const;
  };
  Peeked Peek(const std::string &path);
  // Ghidra's shipped databases: (id, path), by name.
  std::vector<std::pair<std::string, std::string>> Builtins() const;
  // The path behind an id ("builtin:<name>" or a path); "" if unknown.
  std::string PathOf(const std::string &id) const;

  FidSettings User(const std::string &caller);
  void SetUser(const std::string &caller, const FidSettings &settings);

 private:
  void LoadUsersLocked();
  void SaveUsersLocked();

  std::string ghidra_root_, user_store_;
  std::mutex mu_;
  struct Cached {
    std::uintmax_t size = 0;
    std::int64_t mtime = 0;
    Opened opened;
  };
  std::map<std::string, Cached> cache_;
  struct CachedPeek {
    std::uintmax_t size = 0;
    std::int64_t mtime = 0;
    Peeked peeked;
  };
  std::map<std::string, CachedPeek> peeks_;
  bool users_loaded_ = false;
  std::map<std::string, FidSettings> users_;
};

// A program's hashes from a snapshot: discovery's functions and flows,
// Ghidra's no-return evidence, the bytes as patched, the loaded image's
// relocations.
fid::ProgramHashes HashSnapshot(const facts::Snapshot &snap, const analysis::ProgramKey &key,
                                const loader::Image &image, facts::SpaceId space,
                                const std::atomic<bool> *cancel,
                                const std::function<void(std::size_t, std::size_t)> &progress,
                                int min_code_units = 4);

}  // namespace revkit::backend
