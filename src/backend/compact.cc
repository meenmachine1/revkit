#include "compact.h"

#include "queries.h"

#include "revkit/backend/image_backend.h"

#include "revkit/facts/codec.h"
#include "revkit/facts/fact_db.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <unordered_map>

namespace revkit::backend {

std::vector<facts::Engine::RuleInfo> BackendRules() {
  // A fact store's own rules (fact.span, patch.page) and the backend's.
  facts::FactDb db;
  RegisterQueries(db.engine());
  return db.engine().rules();
}

namespace {

std::string Size(std::uint64_t n) {
  char b[32];
  if (n >= (std::uint64_t{1} << 30)) std::snprintf(b, sizeof b, "%.2f GB", static_cast<double>(n) / (1 << 30));
  else if (n >= (std::uint64_t{1} << 20)) std::snprintf(b, sizeof b, "%.1f MB", static_cast<double>(n) / (1 << 20));
  else std::snprintf(b, sizeof b, "%.1f KB", static_cast<double>(n) / 1024);
  return b;
}

}  // namespace

std::vector<std::string> PlanCachePrune(const facts::Storage &storage, const std::vector<facts::Engine::RuleInfo> &rules,
                                        const CompactOptions &options, CompactReport &report) {
  std::unordered_map<facts::QueryId, const facts::Engine::RuleInfo *> by_id;
  for (const auto &r : rules) by_id.emplace(r.id, &r);
  struct Memo {
    std::string key;
    std::uint64_t bytes, last_used;
    std::string rule;
  };
  std::vector<std::string> drop;
  std::vector<Memo> kept;
  storage.scan(facts::Table::Derived, "", [&](std::string_view k, std::string_view v) {
    const std::uint64_t bytes = k.size() + v.size();
    ++report.memo_records;
    report.memo_bytes += bytes;
    bool stale = k.size() < 4;
    std::string rule = "?";
    std::uint64_t last_used = 0;
    if (!stale) {
      facts::Decoder kd(k);
      const facts::QueryId id = kd.u32be();
      auto it = by_id.find(id);
      if (it == by_id.end() || !it->second->derived || !it->second->persistent) {
        char b[16];
        std::snprintf(b, sizeof b, "?%08x", id);
        rule = b;
        stale = true;
      } else {
        rule = it->second->name;
        try {
          facts::Decoder d(v);
          if (d.varint() != it->second->version) stale = true;
          (void)d.varint();      // lo
          last_used = d.varint();  // hi: the last revision it was valid at
        } catch (const facts::DecodeError &) {
          stale = true;
        }
      }
    }
    CompactReport::Rule &r = report.rules[rule];
    ++r.records;
    r.bytes += bytes;
    if (stale || options.drop_caches) {
      if (stale) ++report.dropped_stale;
      ++r.dropped;
      ++report.dropped_records;
      report.dropped_bytes += bytes;
      drop.emplace_back(k);
    } else {
      kept.push_back({std::string(k), bytes, last_used, std::move(rule)});
    }
    return true;
  });
  if (options.cache_limit && !options.drop_caches) {
    std::stable_sort(kept.begin(), kept.end(), [](const Memo &a, const Memo &b) { return a.last_used > b.last_used; });
    std::uint64_t total = 0;
    for (Memo &m : kept) {
      total += m.bytes;
      if (total <= options.cache_limit) continue;
      ++report.rules[m.rule].dropped;
      ++report.dropped_records;
      report.dropped_bytes += m.bytes;
      drop.push_back(std::move(m.key));
    }
  }
  const facts::StorageStats st = storage.stats();
  report.log_records = st.entries[static_cast<int>(facts::Table::Log)];
  report.log_bytes = st.bytes[static_cast<int>(facts::Table::Log)];
  report.file_bytes = st.bytes[static_cast<int>(facts::Table::Bytes)];
  report.file_before = report.file_after = st.file_bytes;
  return drop;
}

bool CompactStore(facts::Storage &storage, const std::vector<facts::Engine::RuleInfo> &rules,
                  const CompactOptions &options, CompactReport &report, std::string *error) {
  std::vector<std::string> drop = PlanCachePrune(storage, rules, options, report);
  if (options.dry_run) return true;
  std::optional<facts::Storage::CompactResult> r = storage.compact(facts::Table::Derived, drop);
  if (!r) {
    if (error) *error = "the project's store is in memory: nothing to compact";
    return false;
  }
  report.file_before = r->file_before;
  report.file_after = r->file_after;
  return true;
}

std::uint64_t PruneCaches(facts::Storage &storage, const std::vector<facts::Engine::RuleInfo> &rules,
                          const CompactOptions &options, CompactReport &report) {
  std::vector<std::string> drop = PlanCachePrune(storage, rules, options, report);
  if (options.dry_run || drop.empty()) return 0;
  for (std::size_t i = 0; i < drop.size();) {
    facts::WriteBatch b;
    for (std::size_t n = 0; i < drop.size() && n < 4096; ++i, ++n) b.erase(facts::Table::Derived, std::move(drop[i]));
    storage.write(b);
  }
  return report.dropped_records;
}

int CompactProjectDir(const std::string &project_dir, const std::string &project, const StoreCompaction &options,
                      std::ostream &out) {
  namespace fs = std::filesystem;
  const auto rules = BackendRules();
  int done = 0;
  std::vector<fs::path> stores;
  for (const fs::directory_entry &e : fs::directory_iterator(project_dir)) {
    if (!e.is_directory() || e.path().filename().string().starts_with(".")) continue;
    if (!project.empty() && e.path().filename() != project) continue;
    if (fs::exists(e.path() / "data.mdb")) stores.push_back(e.path());
  }
  std::sort(stores.begin(), stores.end());
  if (!project.empty() && stores.empty()) throw std::runtime_error("no project " + project + " in " + project_dir);
  for (const fs::path &dir : stores) {
    std::unique_ptr<facts::Storage> storage = facts::open_lmdb_storage(dir);
    CompactOptions o;
    o.drop_caches = options.drop_caches;
    o.cache_limit = options.cache_limit;
    o.dry_run = options.dry_run;
    CompactReport rep;
    std::string error;
    if (!CompactStore(*storage, rules, o, rep, &error)) throw std::runtime_error(dir.string() + ": " + error);
    out << dir.filename().string() << (options.dry_run ? " (dry run)" : "") << ":\n" << FormatCompactReport(rep);
    ++done;
  }
  return done;
}

std::string FormatCompactReport(const CompactReport &report) {
  std::vector<std::pair<std::string, CompactReport::Rule>> rules(report.rules.begin(), report.rules.end());
  std::sort(rules.begin(), rules.end(), [](const auto &a, const auto &b) { return a.second.bytes > b.second.bytes; });
  std::string out;
  out += "  file " + Size(report.file_before) + " -> " + Size(report.file_after) + "\n";
  out += "  log " + std::to_string(report.log_records) + " ops, " + Size(report.log_bytes) + "; program bytes " +
         Size(report.file_bytes) + "\n";
  out += "  memos " + std::to_string(report.memo_records) + ", " + Size(report.memo_bytes) + "; dropped " +
         std::to_string(report.dropped_records) + " (" + Size(report.dropped_bytes) + ", " +
         std::to_string(report.dropped_stale) + " stale)\n";
  std::size_t n = 0;
  for (const auto &[name, r] : rules) {
    // The largest, and every rule whose memos went.
    if (++n > 12 && r.dropped == 0) continue;
    out += "    " + name + ": " + std::to_string(r.records) + " memos, " + Size(r.bytes) +
           (r.dropped ? ", " + std::to_string(r.dropped) + " dropped" : std::string()) + "\n";
  }
  return out;
}

}  // namespace revkit::backend
