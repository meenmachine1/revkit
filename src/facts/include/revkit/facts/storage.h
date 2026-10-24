// Storage backends: an ordered key-value store split into a few fixed tables,
// with atomic batched writes. Snapshot isolation for queries is provided by
// the engine's revisions, not by the backend, so the interface stays small
// enough to sit on LMDB, RocksDB or a std::map.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::facts {

enum class Table : std::uint8_t {
  Meta,     // small bookkeeping values (schema version, last revision)
  Log,      // assertion log: big-endian seq -> encoded Op
  Bytes,    // program bytes: page key -> page contents
  Derived,  // spilled memos: query id + key -> encoded memo
};
inline constexpr int kTableCount = 4;

struct WriteBatch {
  struct Entry {
    Table table;
    std::string key;
    std::optional<std::string> value;  // nullopt deletes
  };
  std::vector<Entry> entries;

  void put(Table t, std::string key, std::string value) {
    entries.push_back({t, std::move(key), std::move(value)});
  }
  void erase(Table t, std::string key) { entries.push_back({t, std::move(key), std::nullopt}); }
  bool empty() const { return entries.empty(); }
};

struct StorageStats {
  std::uint64_t entries[kTableCount] = {};
  std::uint64_t bytes[kTableCount] = {};  // key + value bytes
  std::uint64_t file_bytes = 0;           // on-disk footprint, 0 for memory
};

class Storage {
 public:
  virtual ~Storage() = default;

  virtual std::optional<std::string> get(Table t, std::string_view key) const = 0;
  // Visits keys starting with prefix in key order until fn returns false.
  virtual void scan(Table t, std::string_view prefix,
                    const std::function<bool(std::string_view key, std::string_view value)>
                        &fn) const = 0;
  // Applies the whole batch atomically. Safe to call from several threads.
  virtual void write(const WriteBatch &batch) = 0;
  virtual StorageStats stats() const = 0;

  // Deletes `drop` (keys of `table`), then rewrites the store without its
  // free pages, as LMDB's `mdb_copy -c` does, so the file shrinks to what
  // it holds. Reads and writes wait while it runs. nullopt where the
  // backend has no file (memory).
  struct CompactResult {
    std::uint64_t file_before = 0, file_after = 0;  // bytes on disk
    std::uint64_t dropped = 0;                      // of `drop`, the keys there were
  };
  virtual std::optional<CompactResult> compact(Table table, const std::vector<std::string> &drop) {
    (void)table;
    (void)drop;
    return std::nullopt;
  }
};

std::unique_ptr<Storage> make_memory_storage();

struct LmdbOptions {
  // Upper bound on the database size; the file grows sparsely up to this.
  std::uint64_t map_size = std::uint64_t{64} << 30;
  // Skip fsync on commit. Derived facts are recomputable, so benchmarks and
  // caches can trade durability for speed.
  bool no_sync = false;
};
std::unique_ptr<Storage> open_lmdb_storage(const std::filesystem::path &dir,
                                           const LmdbOptions &opt = {});

struct StorageError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

}  // namespace revkit::facts
