// Function ID databases (docs/fid.md): libraries' functions by hash, with
// the caller/callee relations that disambiguate them.
//
// Two file formats hold the same model:
//   - Ghidra's .fidbf (a packed DBHandle / LocalBufferFile database with the
//     tables "Functions Table", "Libraries Table", "Strings Table",
//     "Superior Table" and "Inferior Table"), read-only: Ghidra ships them
//     for the MSVC runtimes (Ghidra/Features/FunctionID/data);
//   - revkit's .rkfid, which `rk-fid create` writes (layout in docs/fid.md).
// Both readers treat the file as hostile: every offset, count and link is
// checked, and a bad file is a FidError, never a crash or a huge
// allocation.
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace revkit::fid {

struct FidError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// FidHashQuad: what a function hashes to.
struct HashQuad {
  std::uint16_t code_units = 0;     // instructions hashed, less calls
  std::uint64_t full = 0;           // operands masked out
  std::uint8_t specific_extra = 0;  // constants the specific hash adds (at most 127)
  std::uint64_t specific = 0;       // small constants kept

  friend bool operator==(const HashQuad &, const HashQuad &) = default;
};

// FunctionRecord flags (Ghidra's values).
enum FunctionFlags : std::uint8_t {
  kHasTerminator = 1,
  kAutoPass = 2,       // a full-hash match always counts, even when short
  kAutoFail = 4,       // never matches
  kForceSpecific = 8,  // matches only when the specific hash does too
  kForceRelation = 16, // matches only when a callee matches too
};

struct Library {
  std::int64_t id = 0;
  std::string family, version, variant;
  std::string ghidra_version;
  std::string language;  // "x86:LE:64:default"
  std::int32_t language_version = 0, language_minor = 0;
  std::string compiler;  // "windows", "gcc"
};

struct Function {
  std::int64_t id = 0;
  HashQuad hash;
  std::int64_t library = 0;  // Library::id
  std::string name;
  std::uint64_t entry = 0;   // in the program it came from
  std::uint32_t path = 0;    // that program (Ghidra: its domain path), Database::path()
  std::uint8_t flags = 0;
};

// The relation keys (FidDBUtils): a caller's id smashed with a callee's
// full hash ("superior": the caller calls something with that hash), and a
// callee's id with a caller's full hash ("inferior").
std::uint64_t superior_key(std::int64_t caller_id, std::uint64_t callee_full);
std::uint64_t inferior_key(std::int64_t callee_id, std::uint64_t caller_full);

class Database {
 public:
  enum class Format { fidbf, rkfid };

  // Reads a .fidbf or .rkfid file (by its magic). Throws FidError.
  static Database open(const std::filesystem::path &path);
  // From bytes (fuzzing, tests): `name` labels it.
  static Database parse(std::span<const std::byte> bytes, std::string name);
  // Only a file's libraries (what languages it is for) and how many
  // functions it has, without reading them. Throws FidError.
  struct Peek {
    std::vector<Library> libraries;
    std::uint64_t functions = 0;
    Format format = Format::rkfid;
  };
  static Peek peek(const std::filesystem::path &path);
  // Builds one (rk-fid create); call index() when done adding.
  Database() = default;

  const std::string &name() const { return name_; }  // the file's stem: "vs2019_x64"
  Format format() const { return format_; }
  const std::vector<Library> &libraries() const { return libraries_; }
  const std::vector<Function> &functions() const { return functions_; }
  std::size_t superior_count() const { return superior_.size(); }
  const std::unordered_set<std::uint64_t> &superior_keys() const { return superior_; }
  const std::unordered_set<std::uint64_t> &inferior_keys() const { return inferior_; }
  std::size_t inferior_count() const { return inferior_.size(); }

  // The functions with this full hash, by id (signed), as Ghidra's index
  // lists them.
  std::span<const Function> by_full(std::uint64_t full) const;
  const Library *library(std::int64_t id) const;
  // The program a function came from.
  const std::string &path(const Function &f) const { return f.path < paths_.size() ? paths_[f.path] : paths_[0]; }
  std::uint32_t intern_path(const std::string &p);
  bool superior(std::int64_t caller_id, std::uint64_t callee_full) const {
    return superior_.contains(superior_key(caller_id, callee_full));
  }
  bool inferior(std::uint64_t caller_full, std::int64_t callee_id) const {
    return inferior_.contains(inferior_key(callee_id, caller_full));
  }
  // Whether any library is for this language ("x86:LE:64:default").
  bool has_language(std::string_view language) const;

  // Building.
  void set_name(std::string n) { name_ = std::move(n); }
  std::int64_t add_library(Library lib);
  std::int64_t add_function(Function f);
  void add_superior(std::int64_t caller_id, std::uint64_t callee_full) {
    superior_.insert(superior_key(caller_id, callee_full));
  }
  void add_inferior(std::int64_t callee_id, std::uint64_t caller_full) {
    inferior_.insert(inferior_key(callee_id, caller_full));
  }
  // Sorts the functions and builds the hash index.
  void index();
  // The functions of a library with a name (relations by name).
  std::vector<const Function *> by_name(std::int64_t library, std::string_view name) const;

  // Writes the .rkfid form.
  void write(const std::filesystem::path &path) const;
  std::string serialize() const;

 private:
  static Database parse_fidbf(std::span<const std::byte> bytes, bool libraries_only = false);
  static Database parse_rkfid(std::span<const std::byte> bytes, bool libraries_only = false);

  std::string name_;
  Format format_ = Format::rkfid;
  std::vector<Library> libraries_;
  std::vector<Function> functions_;  // sorted by (full hash, id)
  std::vector<std::string> paths_{std::string()};
  std::uint64_t peeked_functions_ = 0;  // libraries-only parses: the function count
  std::unordered_map<std::string, std::uint32_t> path_index_;
  std::unordered_set<std::uint64_t> superior_, inferior_;
  std::unordered_map<std::int64_t, std::size_t> library_index_;
  std::int64_t next_id_ = 1;
};

}  // namespace revkit::fid
