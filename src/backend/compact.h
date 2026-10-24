// Shrinking a project's store (docs/backend.md, "Compaction"): its derived
// memos pruned, then the LMDB file rewritten without its free pages, as
// `mdb_copy -c` does. LMDB keeps its file at its high-water mark, so
// replaced and deleted memos never give space back by themselves.
//
// What goes:
//   - always, the memos of rules this build doesn't have or whose version
//     changed: they can only be recomputed, never read again;
//   - with drop_caches, every memo (everything recomputes, as after an
//     import; the log, the program bytes and the meta table stay);
//   - with cache_limit, the memos beyond that many bytes, the ones last
//     used longest ago first (a memo's revision of last use).
// The log (every assertion and retraction, the project's history and what
// undo, blame and replication read) is never pruned.
//
// rk-daemon compact <project dir> (the daemon stopped: it takes the
// directory's lock) and ProjectService.CompactProject (a closed project)
// run it; --cache-limit-mb applies cache_limit to each project as it opens.
#pragma once

#include "revkit/facts/engine.h"
#include "revkit/facts/storage.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace revkit::backend {

struct CompactOptions {
  bool drop_caches = false;
  std::uint64_t cache_limit = 0;  // bytes of memos to keep; 0: no limit
  bool dry_run = false;           // plan and measure only
};

struct CompactReport {
  std::uint64_t file_before = 0, file_after = 0;  // data.mdb, bytes
  std::uint64_t log_records = 0, log_bytes = 0, file_bytes = 0;  // the log and the program bytes tables
  std::uint64_t memo_records = 0, memo_bytes = 0;  // derived, before
  std::uint64_t dropped_stale = 0, dropped_records = 0, dropped_bytes = 0;
  struct Rule {
    std::uint64_t records = 0, bytes = 0, dropped = 0;
  };
  std::map<std::string, Rule> rules;  // by rule name ("?<id>" for one this build lacks), before
};

// The rules a project's engine has (the fact store's and RegisterQueries'), for checking
// stored memos against.
std::vector<facts::Engine::RuleInfo> BackendRules();

// The derived keys to drop and the report's counts; nothing is changed.
std::vector<std::string> PlanCachePrune(const facts::Storage &storage, const std::vector<facts::Engine::RuleInfo> &rules,
                                        const CompactOptions &options, CompactReport &report);

// Prunes and rewrites `storage` (an LMDB store that nothing else uses
// meanwhile: a stopped daemon's, or a closed project's). False with
// `error` when the store can't be compacted (in memory).
bool CompactStore(facts::Storage &storage, const std::vector<facts::Engine::RuleInfo> &rules,
                  const CompactOptions &options, CompactReport &report, std::string *error);

// Only the pruning (no rewrite: LMDB reuses the freed pages, so the file
// stops growing): what --cache-limit-mb does as a project opens.
std::uint64_t PruneCaches(facts::Storage &storage, const std::vector<facts::Engine::RuleInfo> &rules,
                          const CompactOptions &options, CompactReport &report);

// One line per rule, largest first, and the totals: for the CLI and logs.
std::string FormatCompactReport(const CompactReport &report);

}  // namespace revkit::backend
