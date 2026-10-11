// Matching a program's functions against Function ID databases, scored and
// named as Ghidra's FidProgramSeeker and ApplyFidEntriesCommand do
// (docs/fid.md, "Matching").
#pragma once

#include "revkit/fid/db.h"
#include "revkit/fid/hash.h"
#include "revkit/fid/program.h"

#include <atomic>
#include <functional>
#include <string>
#include <vector>

namespace revkit::fid {

struct Candidate {
  const Database *db = nullptr;
  const Function *function = nullptr;
  const Library *library = nullptr;
  float primary = 0;   // code units, plus 0.67 per specific constant when the specific hash matches
  float children = 0;  // code units of callees the database relates to it
  float parents = 0;   // code units of callers the database relates to it
  bool specific = false;
  float score() const { return primary + children + parents; }
};

// The outcome for one function, after ApplyFidEntriesCommand's name analysis.
enum class Verdict : std::uint8_t {
  single,          // every match has one name (up to leading underscores)
  same_base,       // several names with one base name (demangled, template arguments aside)
  different,       // several base names: named FID_conflict:<first>
  below_threshold, // several base names, scored under the multi-name threshold: not named
};

struct Match {
  std::uint64_t entry = 0;
  std::size_t function = 0;  // index in ProgramHashes::functions
  HashQuad hash;
  std::vector<Candidate> candidates;  // the best-scoring ones (ties kept), best first
  Verdict verdict = Verdict::single;
  std::string name;                   // what to name it ("" for below_threshold)
  std::vector<std::string> names;     // the distinct names, sorted
  std::vector<std::string> libraries; // "Visual Studio 2019 Release", at most 5
  float score() const { return candidates.empty() ? 0 : candidates.front().score(); }
  // Ghidra's plate comment for it ("Library Function - Single Match\n name\n\nLibrary: ...").
  std::string comment() const;
};

struct SearchOptions {
  float threshold = kScoreThreshold;
  float multi_name_threshold = kMultiNameScoreThreshold;
  const std::atomic<bool> *cancel = nullptr;
  std::function<void(std::size_t done, std::size_t total)> progress;
};

// Every function with a match above the threshold (thunks never), by entry.
// The databases are searched as one (FidQueryService), in the given order.
std::vector<Match> search(const ProgramHashes &program, const std::vector<const Database *> &dbs,
                          const SearchOptions &options = {});

// Databases whose libraries are for the program's language.
std::vector<const Database *> for_language(const std::vector<const Database *> &dbs, const std::string &language);

}  // namespace revkit::fid
