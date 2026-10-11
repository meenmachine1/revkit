// BSim signature databases (docs/bsim.md): a persistent store of
// executables' functions and their BSim feature vectors, with an LSH index,
// for finding functions similar to a given one across every program
// ingested, as Ghidra's BSim databases do.
//
// A database is a directory (NAME.rkbsim):
//   database.json         what the database is: its weights table (BSim's
//                         64-bit, 32-bit or size-independent one: which
//                         signature settings every vector was made with),
//                         its LSH parameters, name and description; written
//                         once, at create
//   exe/<sha256>.rkbx     one executable: its metadata and functions (name,
//                         entry, prototype, size, flags, feature hashes and
//                         their LSH buckets), written whole to a temporary
//                         file and renamed, so a reader sees it whole or not
//                         at all; ingesting the same binary again replaces it
//   lock                  writers hold it (flock) while they write
// Readers load every executable at open (reload() picks up others' writes).
// Files are read as hostile: every count and length is checked against the
// file's size, and a bad file is a BsimError naming it, never a crash.
//
// Vectors are BSim's (src/diff/lsh.h: tf-idf weights, cosine,
// significance), bit for bit Ghidra's for the same hashes. The index is
// SimHash over those weighted vectors: `l` tables of `k` bits, each bit
// the sign of the vector's projection on a pseudo-random +-1 hyperplane
// derived from (seed, table, bit, feature hash); two functions of cosine c
// share a table's bucket with probability (1 - acos(c)/pi)^k. A search
// gathers the functions sharing a bucket in any table and scores each
// exactly (or every function: SearchOptions::exhaustive).
#pragma once

#include "revkit/diff/lsh.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::bsim {

struct BsimError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

inline constexpr std::uint32_t kFormatVersion = 1;

struct LshParams {
  std::uint32_t k = 10;   // bits per table (1..32)
  std::uint32_t l = 64;   // tables (1..512)
  std::uint64_t seed = 0x6273696d726b0001ull;
  friend bool operator==(const LshParams &, const LshParams &) = default;
};

// The database's weights table, as Ghidra's templates name them
// ("medium_64", "medium_32", "medium_nosize"): every function is signed with
// the table's settings (0x49 for 64 and 32, 0x4d for nosize).
enum class Template : std::uint8_t { w64 = 0, w32 = 1, nosize = 2 };
const char *template_name(Template t);                       // "64", "32", "nosize"
std::optional<Template> parse_template(std::string_view s);  // also "medium_64", ...
diff::Weights weights_of(Template t);
// The template for a program's language ("x86:LE:64:default"): 64 or 32 by
// its size, nosize otherwise.
Template template_for_language(std::string_view language);

struct DatabaseInfo {
  std::uint32_t format = kFormatVersion;
  std::string name;
  std::string description;
  Template weights = Template::w64;
  std::uint32_t settings = 0;  // the signature settings every vector has (the table's)
  LshParams lsh;
  std::int64_t created = 0;    // unix seconds
};

// One binary, by its file's sha256.
struct Executable {
  std::string id;          // lowercase hex sha256 of the file
  std::string name;
  std::string path;        // where it was ingested from (informational)
  std::string language;    // "x86:LE:64:default"
  std::string compiler;    // "gcc", "windows", "default"
  std::string md5;         // optional
  std::int64_t ingested = 0;
  std::string source;      // what ingested it: "rk-bsim", "daemon:<program id>"
  // Ghidra's executable categories: name -> value ("vendor" -> "acme").
  std::map<std::string, std::string> categories;
  std::uint32_t function_count = 0;  // filled on load
};

// FunctionRecord::flags.
enum FunctionFlags : std::uint32_t {
  kDefaultName = 1,  // an analysis name (FUN_..., sub_...), not from symbols or a user
  kThunk = 2,
  kHasPrototype = 4,  // the prototype came from somewhere other than the decompiler's default
};

struct FunctionRecord {
  std::string name;
  std::uint64_t entry = 0;
  std::string prototype;  // C, may be empty
  std::uint32_t size = 0; // body bytes
  std::uint32_t flags = 0;
  std::vector<std::uint32_t> features;  // sorted ascending, repeats adjacent
  std::vector<std::uint32_t> buckets;   // one per LSH table (filled by the database)
};

struct SearchOptions {
  double min_similarity = 0.7;  // cosine
  double min_confidence = 0.0;  // significance
  std::size_t max_matches = 100;
  // Filters: executables by id or name (any of them); languages by prefix
  // ("x86:LE:64"); a function name containing this (case-insensitive);
  // categories that must all match (name -> value).
  std::vector<std::string> executables;
  std::vector<std::string> exclude_executables;
  std::vector<std::string> languages;
  std::string name_contains;
  std::map<std::string, std::string> categories;
  bool exclude_default_names = false;
  // Score every function instead of the LSH candidates: always, or when the
  // database holds at most `exhaustive_below` functions (scoring one costs
  // about a microsecond; LSH misses pairs far below 0.7).
  bool exhaustive = false;
  std::size_t exhaustive_below = 50000;
};

struct Match {
  const Executable *executable = nullptr;
  const FunctionRecord *function = nullptr;
  double similarity = 0;
  double confidence = 0;
};

struct SearchStats {
  std::size_t candidates = 0;  // functions scored
  std::size_t total = 0;       // functions in the database
  bool exhaustive = false;     // every function was a candidate
};

class Database {
 public:
  // Creates the directory (it must not exist, or be empty). Throws BsimError.
  static Database create(const std::filesystem::path &dir, DatabaseInfo info);
  // Opens and loads every executable. Throws BsimError.
  static Database open(const std::filesystem::path &dir);
  // Reads database.json only.
  static DatabaseInfo peek(const std::filesystem::path &dir);
  static bool looks_like(const std::filesystem::path &dir);

  Database(Database &&) noexcept;
  Database &operator=(Database &&) noexcept;
  ~Database();

  const DatabaseInfo &info() const;
  const std::filesystem::path &path() const;
  const diff::WeightTable &weights() const;

  // The LSH buckets of a feature vector under this database's parameters.
  std::vector<std::uint32_t> buckets(std::span<const std::uint32_t> features) const;

  struct AddResult {
    bool replaced = false;      // the executable was there and is replaced
    std::size_t functions = 0;  // stored
    std::size_t empty = 0;      // left out: no features
  };
  // Adds the executable (exe.id required) with its functions, or replaces
  // the one with its id. Functions without features are left out.
  AddResult add(Executable exe, std::vector<FunctionRecord> functions);
  // Removes an executable; false when there is none with that id.
  bool remove(std::string_view id);
  // Changes an executable's categories (and name, when not empty).
  bool update(std::string_view id, const std::map<std::string, std::string> &categories,
              const std::string &name = {});
  // Re-reads the executables other processes wrote or removed.
  void reload();

  std::vector<const Executable *> executables() const;  // by name, then id
  const Executable *executable(std::string_view id) const;
  // An executable by id, unique id prefix (>= 6 hex digits) or unique name.
  const Executable *find_executable(std::string_view key) const;
  std::span<const FunctionRecord> functions(std::string_view id) const;
  std::size_t function_count() const;

  // Functions similar to `features` (sorted hashes), best first.
  std::vector<Match> search(std::span<const std::uint32_t> features, const SearchOptions &options,
                            SearchStats *stats = nullptr) const;
  // The vector's self-significance under the database's weights.
  double self_significance(std::span<const std::uint32_t> features) const;

 private:
  struct Impl;
  explicit Database(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

// The default-name test: FUN_xxx, sub_xxx, thunk_FUN_xxx, LAB_, entry
// points named by address.
bool is_default_name(std::string_view name);

// The .rkbx codec (exposed for tests and fuzzing): encodes one executable,
// decodes a file's bytes (throws BsimError).
std::string encode_executable(const Executable &exe, std::span<const FunctionRecord> functions, std::uint32_t tables);
std::pair<Executable, std::vector<FunctionRecord>> decode_executable(std::string_view bytes, std::uint32_t tables);

}  // namespace revkit::bsim
