// Function ID in the image backend (fid.h).

#include "fid.h"

#include "revkit/inputs/inputs.h"
#include "revkit/analysis/no_return.h"

#include <algorithm>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace revkit::backend {

namespace fs = std::filesystem;

// Settings are text lines, "attach <path>" and "detach <id>": a NOTE's
// value, and the users' file with "<caller>\t" before each line.
std::string EncodeFidSettings(const FidSettings &s) {
  std::string out;
  for (const std::string &p : s.attached) out += "attach " + p + "\n";
  for (const std::string &d : s.detached) out += "detach " + d + "\n";
  return out;
}

FidSettings DecodeFidSettings(const std::string &text) {
  FidSettings s;
  std::istringstream in(text);
  for (std::string line; std::getline(in, line);) {
    if (line.starts_with("attach ") && line.size() > 7) {
      std::string p = line.substr(7);
      if (std::find(s.attached.begin(), s.attached.end(), p) == s.attached.end()) s.attached.push_back(std::move(p));
    } else if (line.starts_with("detach ") && line.size() > 7) {
      s.detached.insert(line.substr(7));
    }
  }
  return s;
}

std::string EncodeFidRejected(const std::set<std::uint64_t> &entries) {
  std::string out;
  char buf[24];
  for (std::uint64_t e : entries) {
    std::snprintf(buf, sizeof buf, "%llx\n", static_cast<unsigned long long>(e));
    out += buf;
  }
  return out;
}

std::set<std::uint64_t> DecodeFidRejected(const std::string &text) {
  std::set<std::uint64_t> out;
  std::istringstream in(text);
  for (std::string line; std::getline(in, line);) {
    if (line.empty() || line.size() > 16) continue;
    char *end = nullptr;
    const unsigned long long v = std::strtoull(line.c_str(), &end, 16);
    if (end != nullptr && *end == '\0') out.insert(v);
  }
  return out;
}

FidCatalog::FidCatalog(std::string ghidra_root, std::string user_store)
    : ghidra_root_(std::move(ghidra_root)), user_store_(std::move(user_store)) {}

std::vector<std::pair<std::string, std::string>> FidCatalog::Builtins() const {
  std::vector<std::pair<std::string, std::string>> out;
  if (ghidra_root_.empty()) return out;
  std::error_code ec;
  const fs::path dir = fs::path(ghidra_root_) / "Ghidra" / "Features" / "FunctionID" / "data";
  for (const auto &e : fs::directory_iterator(dir, ec)) {
    if (!e.is_regular_file(ec) || e.path().extension() != ".fidbf") continue;
    out.emplace_back("builtin:" + e.path().stem().string(), e.path().string());
  }
  std::sort(out.begin(), out.end());
  return out;
}

std::string FidCatalog::PathOf(const std::string &id) const {
  if (!id.starts_with("builtin:")) return id;
  for (const auto &[bid, path] : Builtins())
    if (bid == id) return path;
  return {};
}

FidCatalog::Opened FidCatalog::Open(const std::string &path) {
  std::error_code ec;
  const auto size = fs::file_size(path, ec);
  if (ec) return {nullptr, "cannot read " + path + ": " + ec.message()};
  const auto time = fs::last_write_time(path, ec);
  const std::int64_t mtime = ec ? 0 : static_cast<std::int64_t>(time.time_since_epoch().count());
  {
    std::lock_guard lock(mu_);
    auto it = cache_.find(path);
    if (it != cache_.end() && it->second.size == size && it->second.mtime == mtime) return it->second.opened;
  }
  Opened o;
  try {
    o.db = std::make_shared<const fid::Database>(fid::Database::open(path));
  } catch (const std::exception &e) {
    o.error = e.what();
  }
  std::lock_guard lock(mu_);
  cache_[path] = Cached{size, mtime, o};
  return o;
}

bool FidCatalog::Peeked::has_language(const std::string &language) const {
  if (!peek) return false;
  for (const fid::Library &l : peek->libraries)
    if (l.language == language) return true;
  return false;
}

FidCatalog::Peeked FidCatalog::Peek(const std::string &path) {
  std::error_code ec;
  const auto size = fs::file_size(path, ec);
  if (ec) return {nullptr, "cannot read " + path + ": " + ec.message()};
  const auto time = fs::last_write_time(path, ec);
  const std::int64_t mtime = ec ? 0 : static_cast<std::int64_t>(time.time_since_epoch().count());
  {
    std::lock_guard lock(mu_);
    auto it = peeks_.find(path);
    if (it != peeks_.end() && it->second.size == size && it->second.mtime == mtime) return it->second.peeked;
  }
  Peeked p;
  try {
    p.peek = std::make_shared<const fid::Database::Peek>(fid::Database::peek(path));
  } catch (const std::exception &e) {
    p.error = e.what();
  }
  std::lock_guard lock(mu_);
  peeks_[path] = CachedPeek{size, mtime, p};
  return p;
}

void FidCatalog::LoadUsersLocked() {
  if (users_loaded_) return;
  users_loaded_ = true;
  if (user_store_.empty()) return;
  std::ifstream in(user_store_);
  std::map<std::string, std::string> text;
  for (std::string line; std::getline(in, line);) {
    auto tab = line.find('\t');
    if (tab == std::string::npos) continue;
    text[line.substr(0, tab)] += line.substr(tab + 1) + "\n";
  }
  for (const auto &[caller, t] : text) users_[caller] = DecodeFidSettings(t);
}

void FidCatalog::SaveUsersLocked() {
  if (user_store_.empty()) return;
  std::string out;
  for (const auto &[caller, s] : users_) {
    std::istringstream in(EncodeFidSettings(s));
    for (std::string line; std::getline(in, line);) out += caller + "\t" + line + "\n";
  }
  const std::string tmp = user_store_ + ".tmp";
  {
    std::ofstream f(tmp, std::ios::trunc);
    f << out;
    if (!f) return;
  }
  std::error_code ec;
  fs::rename(tmp, user_store_, ec);
}

FidSettings FidCatalog::User(const std::string &caller) {
  std::lock_guard lock(mu_);
  LoadUsersLocked();
  auto it = users_.find(caller);
  return it == users_.end() ? FidSettings{} : it->second;
}

void FidCatalog::SetUser(const std::string &caller, const FidSettings &settings) {
  std::lock_guard lock(mu_);
  LoadUsersLocked();
  users_[caller] = settings;
  SaveUsersLocked();
}

fid::ProgramHashes HashSnapshot(const facts::Snapshot &snap, const analysis::ProgramKey &key,
                                const loader::Image &image, facts::SpaceId space, const std::atomic<bool> *cancel,
                                const std::function<void(std::size_t, std::size_t)> &progress, int min_code_units) {
  auto info = snap.get<analysis::Program>(key);
  auto list = snap.get<analysis::Functions>(key);
  auto evidence = snap.get<analysis::NoReturnEvidence>(key);
  fid::ProgramSource src;
  src.language = info->language;
  src.info = &*info;
  src.functions = &*list;
  src.flow = [&](std::uint64_t k) -> std::shared_ptr<const analysis::FlowGraph> {
    auto holder = std::make_shared<decltype(snap.get<analysis::Flow>(analysis::Location{key, k}))>(
        snap.get<analysis::Flow>(analysis::Location{key, k}));
    return std::shared_ptr<const analysis::FlowGraph>(holder, &**holder);
  };
  src.read = [&](std::uint64_t addr, std::span<std::byte> out) -> std::size_t {
    const std::size_t n = image.memory.read(addr, out);
    if (n == 0) return 0;
    std::string s(reinterpret_cast<const char *>(out.data()), n);
    facts::apply_patches(facts::patches_overlapping(snap, space, addr, addr + (n - 1)), addr, s);
    std::memcpy(out.data(), s.data(), n);
    return n;
  };
  fid::image_relocations(image, src);
  src.no_return = inputs::ghidra_no_return(*list, &*evidence);
  src.scalar_references = image.format != loader::Format::elf;
  src.cancel = cancel;
  src.progress = progress;
  src.min_code_units = min_code_units;
  return fid::hash_program(src);
}

}  // namespace revkit::backend
