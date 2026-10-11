#include "revkit/facts/storage.h"

#include <array>
#include <map>
#include <mutex>
#include <shared_mutex>

namespace revkit::facts {

namespace {

class MemoryStorage final : public Storage {
 public:
  std::optional<std::string> get(Table t, std::string_view key) const override {
    std::shared_lock lock(mu_);
    const auto &m = table(t);
    auto it = m.find(key);
    if (it == m.end()) return std::nullopt;
    return it->second;
  }

  void scan(Table t, std::string_view prefix,
            const std::function<bool(std::string_view, std::string_view)> &fn)
      const override {
    std::shared_lock lock(mu_);
    const auto &m = table(t);
    for (auto it = m.lower_bound(prefix); it != m.end(); ++it) {
      if (!std::string_view(it->first).starts_with(prefix)) break;
      if (!fn(it->first, it->second)) break;
    }
  }

  void write(const WriteBatch &batch) override {
    std::unique_lock lock(mu_);
    for (const auto &e : batch.entries) {
      auto &m = table(e.table);
      if (e.value) {
        m.insert_or_assign(e.key, *e.value);
      } else {
        auto it = m.find(e.key);
        if (it != m.end()) m.erase(it);
      }
    }
  }

  StorageStats stats() const override {
    std::shared_lock lock(mu_);
    StorageStats s;
    for (int i = 0; i < kTableCount; ++i) {
      s.entries[i] = tables_[i].size();
      for (const auto &[k, v] : tables_[i]) s.bytes[i] += k.size() + v.size();
    }
    return s;
  }

 private:
  using Map = std::map<std::string, std::string, std::less<>>;
  Map &table(Table t) { return tables_[static_cast<std::size_t>(t)]; }
  const Map &table(Table t) const { return tables_[static_cast<std::size_t>(t)]; }

  mutable std::shared_mutex mu_;
  std::array<Map, kTableCount> tables_;
};

}  // namespace

std::unique_ptr<Storage> make_memory_storage() { return std::make_unique<MemoryStorage>(); }

}  // namespace revkit::facts
