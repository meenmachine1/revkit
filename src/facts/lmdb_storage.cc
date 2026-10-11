#include "revkit/facts/storage.h"

#include <lmdb.h>

#include <array>
#include <cerrno>
#include <string>

namespace revkit::facts {

namespace {

void check(int rc, const char *what) {
  if (rc != MDB_SUCCESS) throw StorageError(std::string(what) + ": " + mdb_strerror(rc));
}

MDB_val as_val(std::string_view s) {
  return MDB_val{s.size(), const_cast<char *>(s.data())};
}

std::string_view as_view(const MDB_val &v) {
  return {static_cast<const char *>(v.mv_data), v.mv_size};
}

// Owns an LMDB transaction; aborts unless committed.
class Txn {
 public:
  Txn(MDB_env *env, unsigned flags) { check(mdb_txn_begin(env, nullptr, flags, &txn_), "mdb_txn_begin"); }
  ~Txn() {
    if (txn_) mdb_txn_abort(txn_);
  }
  Txn(const Txn &) = delete;
  Txn &operator=(const Txn &) = delete;

  MDB_txn *get() const { return txn_; }
  void commit() {
    MDB_txn *t = txn_;
    txn_ = nullptr;
    check(mdb_txn_commit(t), "mdb_txn_commit");
  }

 private:
  MDB_txn *txn_ = nullptr;
};

class Cursor {
 public:
  Cursor(MDB_txn *txn, MDB_dbi dbi) { check(mdb_cursor_open(txn, dbi, &cur_), "mdb_cursor_open"); }
  ~Cursor() { mdb_cursor_close(cur_); }
  Cursor(const Cursor &) = delete;
  Cursor &operator=(const Cursor &) = delete;
  MDB_cursor *get() const { return cur_; }

 private:
  MDB_cursor *cur_ = nullptr;
};

constexpr std::array<const char *, kTableCount> kTableNames = {"meta", "log", "bytes", "derived"};

class LmdbStorage final : public Storage {
 public:
  LmdbStorage(const std::filesystem::path &dir, const LmdbOptions &opt) {
    std::filesystem::create_directories(dir);
    // The map reserves address space, not memory. Where there is less of
    // it than map_size (aarch64 kernels with 39-bit virtual addresses, an
    // emulator), mdb_env_open fails with ENOMEM: open again with half the
    // size, down to 1 GiB. An existing environment's own size, if larger,
    // is what LMDB maps anyway.
    std::uint64_t size = opt.map_size;
    for (;;) {
      check(mdb_env_create(&env_), "mdb_env_create");
      int rc = mdb_env_set_mapsize(env_, size);
      if (rc == MDB_SUCCESS) rc = mdb_env_set_maxdbs(env_, kTableCount);
      // Many engine threads hold short read transactions; NOTLS decouples
      // reader slots from OS threads so pool workers don't leak them.
      if (rc == MDB_SUCCESS) rc = mdb_env_set_maxreaders(env_, 1024);
      const unsigned flags = MDB_NOTLS | (opt.no_sync ? MDB_NOSYNC : 0u);
      if (rc == MDB_SUCCESS) rc = mdb_env_open(env_, dir.c_str(), flags, 0644);
      if (rc == MDB_SUCCESS) break;
      mdb_env_close(env_);
      env_ = nullptr;
      if (rc == ENOMEM && size / 2 >= (std::uint64_t{1} << 30)) {
        size /= 2;
        continue;
      }
      check(rc, "mdb_env_open");
    }
    try {
      Txn txn(env_, 0);
      for (int i = 0; i < kTableCount; ++i)
        check(mdb_dbi_open(txn.get(), kTableNames[i], MDB_CREATE, &dbi_[i]), "mdb_dbi_open");
      txn.commit();
    } catch (...) {
      mdb_env_close(env_);
      throw;
    }
  }

  ~LmdbStorage() override { mdb_env_close(env_); }

  std::optional<std::string> get(Table t, std::string_view key) const override {
    Txn txn(env_, MDB_RDONLY);
    MDB_val k = as_val(key), v;
    int rc = mdb_get(txn.get(), dbi(t), &k, &v);
    if (rc == MDB_NOTFOUND) return std::nullopt;
    check(rc, "mdb_get");
    return std::string(as_view(v));
  }

  void scan(Table t, std::string_view prefix,
            const std::function<bool(std::string_view, std::string_view)> &fn)
      const override {
    Txn txn(env_, MDB_RDONLY);
    Cursor cur(txn.get(), dbi(t));
    MDB_val k = as_val(prefix), v;
    int rc = mdb_cursor_get(cur.get(), &k, &v, prefix.empty() ? MDB_FIRST : MDB_SET_RANGE);
    while (rc == MDB_SUCCESS) {
      std::string_view key = as_view(k);
      if (!key.starts_with(prefix) || !fn(key, as_view(v))) return;
      rc = mdb_cursor_get(cur.get(), &k, &v, MDB_NEXT);
    }
    if (rc != MDB_NOTFOUND) check(rc, "mdb_cursor_get");
  }

  void write(const WriteBatch &batch) override {
    if (batch.empty()) return;
    Txn txn(env_, 0);
    for (const auto &e : batch.entries) {
      MDB_val k = as_val(e.key);
      if (e.value) {
        MDB_val v = as_val(*e.value);
        check(mdb_put(txn.get(), dbi(e.table), &k, &v, 0), "mdb_put");
      } else {
        int rc = mdb_del(txn.get(), dbi(e.table), &k, nullptr);
        if (rc != MDB_NOTFOUND) check(rc, "mdb_del");
      }
    }
    txn.commit();
  }

  StorageStats stats() const override {
    StorageStats s;
    Txn txn(env_, MDB_RDONLY);
    for (int i = 0; i < kTableCount; ++i) {
      MDB_stat st;
      check(mdb_stat(txn.get(), dbi_[i], &st), "mdb_stat");
      s.entries[i] = st.ms_entries;
      s.bytes[i] = std::uint64_t{st.ms_psize} *
                   (st.ms_branch_pages + st.ms_leaf_pages + st.ms_overflow_pages);
    }
    MDB_envinfo info;
    check(mdb_env_info(env_, &info), "mdb_env_info");
    MDB_stat env_stat;
    check(mdb_env_stat(env_, &env_stat), "mdb_env_stat");
    s.file_bytes = std::uint64_t{env_stat.ms_psize} * (info.me_last_pgno + 1);
    return s;
  }

 private:
  MDB_dbi dbi(Table t) const { return dbi_[static_cast<std::size_t>(t)]; }

  MDB_env *env_ = nullptr;
  std::array<MDB_dbi, kTableCount> dbi_{};
};

}  // namespace

std::unique_ptr<Storage> open_lmdb_storage(const std::filesystem::path &dir,
                                           const LmdbOptions &opt) {
  return std::make_unique<LmdbStorage>(dir, opt);
}

}  // namespace revkit::facts
