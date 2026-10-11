// FidServiceLibraryIngest, ported (Ghidra 12.1.4, Apache 2.0).

#include "revkit/fid/create.h"

#include <algorithm>

namespace revkit::fid {

namespace {

constexpr std::size_t kMaxNameRelations = 12;  // MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS

std::int32_t java_hash(const std::string &s) {
  std::uint32_t h = 0;
  for (unsigned char c : s) h = 31 * h + c;
  return static_cast<std::int32_t>(h);
}

struct Row {
  std::size_t function;
  std::string name;
  HashQuad hash;
  bool terminator = false;
  std::int64_t id = 0;  // 0 until committed
};

struct Child {
  const Row *row = nullptr;  // a function of the library
  std::string symbol;        // else the name called
  bool common = false;
};

}  // namespace

LibraryBuilder::LibraryBuilder(Database &db, const LibraryInfo &info, std::set<std::string> common)
    : db_(db), common_(std::move(common)) {
  Library lib;
  lib.family = info.family;
  lib.version = info.version;
  lib.variant = info.variant;
  lib.ghidra_version = "revkit";
  lib.language = info.language;
  lib.compiler = info.compiler;
  library_ = db_.add_library(std::move(lib));
}

void LibraryBuilder::add_program(const ProgramHashes &program, const std::string &path,
                                 const std::function<bool(const std::string &)> &is_default_name) {
  const std::size_t n = program.functions.size();
  std::vector<std::optional<Row>> rows(n);
  for (std::size_t i = 0; i < n; ++i) {
    const ProgramFunction &f = program.functions[i];
    const bool named = !f.name.empty() && !is_default_name(f.name);
    if (!named) {
      ++report_.counts[Disposition::no_symbol];
      continue;
    }
    if (f.thunk) {
      ++report_.counts[Disposition::thunk];
      continue;
    }
    if (!f.hash) {
      ++report_.counts[Disposition::too_short];
      continue;
    }
    rows[i] = Row{i, f.name, *f.hash, f.has_terminator, 0};
  }
  // Children, then the duplicate check (generateHash) and the records.
  std::vector<std::vector<Child>> children(n);
  for (std::size_t i = 0; i < n; ++i) {
    if (!rows[i]) continue;
    std::vector<Child> &kids = children[i];
    for (std::size_t c : program.functions[i].callees)
      if (rows[c]) kids.push_back({&*rows[c], {}, common_.contains(rows[c]->name)});
    for (const std::string &s : program.functions[i].external_callees) kids.push_back({nullptr, s, common_.contains(s)});
    std::stable_sort(kids.begin(), kids.end(), [](const Child &a, const Child &b) {
      if (a.row && b.row)
        return static_cast<std::int64_t>(a.row->hash.specific) < static_cast<std::int64_t>(b.row->hash.specific);
      if (a.row || b.row) return a.row != nullptr;
      return a.symbol < b.symbol;
    });
    std::int64_t h = static_cast<std::int64_t>(rows[i]->hash.specific);
    h = h * 31 + static_cast<std::int64_t>(rows[i]->hash.full);
    h = h * 31 + java_hash(rows[i]->name);
    for (const Child &k : kids) {
      h *= 31;
      h += k.row ? static_cast<std::int64_t>(k.row->hash.full) : java_hash(k.symbol);
    }
    if (!unique_.insert(static_cast<std::uint64_t>(h)).second) {
      ++report_.counts[Disposition::duplicate];
      continue;
    }
    Function fn;
    fn.hash = rows[i]->hash;
    fn.library = library_;
    fn.name = rows[i]->name;
    fn.entry = program.functions[i].entry;
    fn.path = db_.intern_path(path);
    fn.flags = rows[i]->terminator ? kHasTerminator : 0;
    rows[i]->id = db_.add_function(std::move(fn));
    by_name_[rows[i]->name].push_back({rows[i]->id, rows[i]->hash.full, rows[i]->hash.specific});
    ++report_.counts[Disposition::included];
  }
  for (std::size_t i = 0; i < n; ++i) {
    if (!rows[i] || rows[i]->id == 0) continue;
    for (const Child &k : children[i]) {
      if (k.common) continue;
      if (k.row == nullptr) {
        unresolved_.push_back({rows[i]->id, {0, k.symbol, 0, false}});
      } else if (k.row->id == 0) {  // a duplicate: relate by name
        unresolved_.push_back({rows[i]->id, {0, k.row->name, k.row->hash.full, true}});
      } else {
        db_.add_superior(rows[i]->id, k.row->hash.full);
        db_.add_inferior(k.row->id, rows[i]->hash.full);
      }
    }
  }
  caller_full_.reserve(caller_full_.size() + n);
  for (std::size_t i = 0; i < n; ++i)
    if (rows[i] && rows[i]->id != 0) caller_full_[rows[i]->id] = rows[i]->hash.full;
}

IngestReport LibraryBuilder::finish() {
  for (const auto &[caller, sym] : unresolved_) {
    auto it = by_name_.find(sym.name);
    if (it == by_name_.end()) {
      report_.unresolved.insert(sym.name);
      continue;
    }
    std::set<std::uint64_t> specifics;
    for (const Named &r : it->second)
      if (!sym.hashed || r.full == sym.full) specifics.insert(r.specific);
    if (specifics.empty() || specifics.size() > kMaxNameRelations) continue;
    const std::uint64_t caller_full = caller_full_.at(caller);
    for (const Named &r : it->second) {
      if (sym.hashed && r.full != sym.full) continue;
      db_.add_superior(caller, r.full);
      db_.add_inferior(r.id, caller_full);
    }
  }
  db_.index();
  return report_;
}

}  // namespace revkit::fid
