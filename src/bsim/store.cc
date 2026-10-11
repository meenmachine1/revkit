// BSim signature databases: the directory format, the .rkbx codec, the LSH
// index and search (store.h, docs/bsim.md).
#include "revkit/bsim/store.h"

#include "json.hh"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <random>
#include <set>
#include <sstream>
#include <system_error>
#include <unordered_set>

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace revkit::bsim {

namespace fs = std::filesystem;
using rklift::Json;

// ---- templates ----------------------------------------------------------------

const char *template_name(Template t) {
  switch (t) {
    case Template::w64: return "64";
    case Template::w32: return "32";
    case Template::nosize: return "nosize";
  }
  return "64";
}

std::optional<Template> parse_template(std::string_view s) {
  if (s.starts_with("medium_")) s.remove_prefix(7);
  if (s == "64") return Template::w64;
  if (s == "32") return Template::w32;
  if (s == "nosize") return Template::nosize;
  return std::nullopt;
}

diff::Weights weights_of(Template t) {
  switch (t) {
    case Template::w64: return diff::Weights::w64;
    case Template::w32: return diff::Weights::w32;
    case Template::nosize: return diff::Weights::nosize;
  }
  return diff::Weights::w64;
}

Template template_for_language(std::string_view language) {
  // "proc:endian:size:variant[:compiler]"
  std::vector<std::string_view> parts;
  for (std::size_t i = 0; i <= language.size();) {
    std::size_t j = language.find(':', i);
    if (j == std::string_view::npos) j = language.size();
    parts.push_back(language.substr(i, j - i));
    i = j + 1;
  }
  if (parts.size() >= 3) {
    if (parts[2] == "64") return Template::w64;
    if (parts[2] == "32") return Template::w32;
  }
  return Template::nosize;
}

bool is_default_name(std::string_view n) {
  auto hex_after = [&](std::string_view prefix) {
    if (!n.starts_with(prefix) || n.size() == prefix.size()) return false;
    for (char c : n.substr(prefix.size()))
      if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
  };
  for (std::string_view p : {"FUN_", "sub_", "thunk_FUN_", "LAB_", "fcn.", "func_", "SUB_"})
    if (hex_after(p)) return true;
  return false;
}

namespace {

bool valid_id(std::string_view id) {
  if (id.size() < 8 || id.size() > 64) return false;
  for (char c : id)
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return true;
}

std::string read_file(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw BsimError("cannot read " + p.string());
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

// Writes `bytes` to `p` through a temporary file renamed over it.
void write_atomically(const fs::path &p, std::string_view bytes) {
  fs::path tmp = p;
  tmp += ".tmp" + std::to_string(::getpid());
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) throw BsimError("cannot write " + tmp.string());
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    out.flush();
    if (!out) {
      std::error_code ec;
      fs::remove(tmp, ec);
      throw BsimError("cannot write " + tmp.string());
    }
  }
  std::error_code ec;
  fs::rename(tmp, p, ec);
  if (ec) {
    fs::remove(tmp, ec);
    throw BsimError("cannot rename " + tmp.string() + " to " + p.string());
  }
}

// A writer's lock on the database (flock on DIR/lock), held while it lives.
class WriteLock {
 public:
  explicit WriteLock(const fs::path &dir) {
    fd_ = ::open((dir / "lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd_ < 0) throw BsimError("cannot open " + (dir / "lock").string());
    if (::flock(fd_, LOCK_EX) != 0) {
      ::close(fd_);
      throw BsimError("cannot lock " + (dir / "lock").string());
    }
  }
  ~WriteLock() {
    ::flock(fd_, LOCK_UN);
    ::close(fd_);
  }
  WriteLock(const WriteLock &) = delete;
  WriteLock &operator=(const WriteLock &) = delete;

 private:
  int fd_ = -1;
};

// ---- the .rkbx codec ------------------------------------------------------------

constexpr char kMagic[8] = {'R', 'K', 'B', 'S', 'I', 'M', 'X', '\0'};

void put_u32(std::string &out, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
}

void put_varint(std::string &out, std::uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<char>((v & 0x7f) | 0x80));
    v >>= 7;
  }
  out.push_back(static_cast<char>(v));
}

void put_bytes(std::string &out, std::string_view s) {
  put_varint(out, s.size());
  out.append(s);
}

class Reader {
 public:
  explicit Reader(std::string_view b) : b_(b) {}
  std::size_t left() const { return b_.size() - pos_; }
  void need(std::size_t n) const {
    if (n > left()) throw BsimError("truncated");
  }
  std::uint32_t u32() {
    need(4);
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(static_cast<unsigned char>(b_[pos_ + i])) << (8 * i);
    pos_ += 4;
    return v;
  }
  std::uint64_t varint() {
    std::uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
      need(1);
      const auto c = static_cast<unsigned char>(b_[pos_++]);
      v |= static_cast<std::uint64_t>(c & 0x7f) << shift;
      if (!(c & 0x80)) return v;
    }
    throw BsimError("bad varint");
  }
  std::string_view bytes(std::size_t n) {
    need(n);
    std::string_view s = b_.substr(pos_, n);
    pos_ += n;
    return s;
  }
  std::string_view counted(std::size_t max) {
    const std::uint64_t n = varint();
    if (n > max) throw BsimError("string too long");
    return bytes(static_cast<std::size_t>(n));
  }

 private:
  std::string_view b_;
  std::size_t pos_ = 0;
};

Json exe_header(const Executable &e) {
  Json::Object cats;
  for (const auto &[k, v] : e.categories) cats[k] = v;
  return Json::Object{{"id", e.id},
                      {"name", e.name},
                      {"path", e.path},
                      {"language", e.language},
                      {"compiler", e.compiler},
                      {"md5", e.md5},
                      {"ingested", e.ingested},
                      {"source", e.source},
                      {"categories", Json(std::move(cats))}};
}

std::string str_of(const Json &o, const char *key) {
  const Json *v = o.find(key);
  return v && v->is_string() ? v->str() : std::string();
}

Executable exe_from(const Json &o) {
  if (!o.is_object()) throw BsimError("bad executable header");
  Executable e;
  e.id = str_of(o, "id");
  e.name = str_of(o, "name");
  e.path = str_of(o, "path");
  e.language = str_of(o, "language");
  e.compiler = str_of(o, "compiler");
  e.md5 = str_of(o, "md5");
  e.source = str_of(o, "source");
  if (const Json *v = o.find("ingested"); v && v->is_number()) e.ingested = v->int64();
  if (const Json *c = o.find("categories"); c && c->is_object())
    for (const auto &[k, v] : c->object())
      if (v.is_string()) e.categories[k] = v.str();
  if (!valid_id(e.id)) throw BsimError("bad executable id");
  return e;
}

}  // namespace

std::string encode_executable(const Executable &exe, std::span<const FunctionRecord> functions, std::uint32_t tables) {
  std::string out(kMagic, sizeof kMagic);
  put_u32(out, kFormatVersion);
  put_u32(out, tables);
  const std::string header = exe_header(exe).compact();
  put_u32(out, static_cast<std::uint32_t>(header.size()));
  out += header;
  put_u32(out, static_cast<std::uint32_t>(functions.size()));
  for (const FunctionRecord &f : functions) {
    put_bytes(out, f.name);
    put_varint(out, f.entry);
    put_bytes(out, f.prototype);
    put_varint(out, f.size);
    put_varint(out, f.flags);
    put_varint(out, f.features.size());
    std::uint32_t prev = 0;
    for (std::uint32_t h : f.features) {
      put_varint(out, h - prev);  // sorted ascending: deltas
      prev = h;
    }
    if (f.buckets.size() != tables) throw BsimError("function " + f.name + " has no buckets");
    for (std::uint32_t b : f.buckets) put_u32(out, b);
  }
  return out;
}

std::pair<Executable, std::vector<FunctionRecord>> decode_executable(std::string_view bytes, std::uint32_t tables) {
  Reader r(bytes);
  if (r.bytes(sizeof kMagic) != std::string_view(kMagic, sizeof kMagic)) throw BsimError("not a BSim executable file");
  const std::uint32_t version = r.u32();
  if (version == 0 || version > kFormatVersion) throw BsimError("format version " + std::to_string(version));
  if (r.u32() != tables) throw BsimError("LSH tables differ from the database's");
  const std::uint32_t hlen = r.u32();
  Json h;
  try {
    h = Json::parse(r.bytes(hlen));
  } catch (const std::exception &e) {
    throw BsimError(std::string("bad executable header: ") + e.what());
  }
  Executable exe = exe_from(h);
  const std::uint32_t n = r.u32();
  // Each function takes at least 6 bytes plus its buckets.
  if (static_cast<std::uint64_t>(n) * (6 + 4ull * tables) > r.left()) throw BsimError("bad function count");
  std::vector<FunctionRecord> fns(n);
  for (FunctionRecord &f : fns) {
    f.name = std::string(r.counted(1 << 16));
    f.entry = r.varint();
    f.prototype = std::string(r.counted(1 << 16));
    f.size = static_cast<std::uint32_t>(std::min<std::uint64_t>(r.varint(), std::numeric_limits<std::uint32_t>::max()));
    f.flags = static_cast<std::uint32_t>(r.varint());
    const std::uint64_t nf = r.varint();
    if (nf > r.left()) throw BsimError("bad feature count");
    f.features.resize(static_cast<std::size_t>(nf));
    std::uint64_t prev = 0;
    for (std::uint32_t &x : f.features) {
      prev += r.varint();
      if (prev > std::numeric_limits<std::uint32_t>::max()) throw BsimError("bad feature");
      x = static_cast<std::uint32_t>(prev);
    }
    f.buckets.resize(tables);
    for (std::uint32_t &b : f.buckets) b = r.u32();
  }
  if (r.left() != 0) throw BsimError("trailing bytes");
  exe.function_count = n;
  return {std::move(exe), std::move(fns)};
}

// ---- the database -----------------------------------------------------------------

namespace {

struct ExeData {
  Executable exe;
  std::vector<FunctionRecord> functions;
  fs::file_time_type mtime;
  std::uintmax_t size = 0;
};

struct FnRef {
  const ExeData *exe;
  std::uint32_t index;
};

Json info_json(const DatabaseInfo &i) {
  char settings[16];
  std::snprintf(settings, sizeof settings, "0x%x", i.settings);
  return Json::Object{
      {"format", static_cast<std::uint64_t>(i.format)},
      {"name", i.name},
      {"description", i.description},
      {"template", std::string(template_name(i.weights))},
      {"settings", std::string(settings)},
      {"lsh", Json::Object{{"k", static_cast<std::uint64_t>(i.lsh.k)},
                           {"l", static_cast<std::uint64_t>(i.lsh.l)},
                           {"seed", static_cast<std::uint64_t>(i.lsh.seed)}}},
      {"created", i.created},
  };
}

DatabaseInfo info_from(const Json &o, const fs::path &file) {
  auto bad = [&](const std::string &why) { return BsimError(file.string() + ": " + why); };
  if (!o.is_object()) throw bad("not an object");
  DatabaseInfo i;
  const Json *fmt = o.find("format");
  if (!fmt || !fmt->is_number()) throw bad("no format");
  i.format = static_cast<std::uint32_t>(fmt->uint64());
  if (i.format == 0 || i.format > kFormatVersion) throw bad("format " + std::to_string(i.format) + " is newer");
  i.name = str_of(o, "name");
  i.description = str_of(o, "description");
  auto t = parse_template(str_of(o, "template"));
  if (!t) throw bad("unknown template");
  i.weights = *t;
  i.settings = diff::WeightTable::builtin(weights_of(i.weights)).settings();
  const Json *lsh = o.find("lsh");
  if (!lsh || !lsh->is_object()) throw bad("no lsh");
  const Json *k = lsh->find("k"), *l = lsh->find("l"), *seed = lsh->find("seed");
  if (!k || !l || !seed || !k->is_number() || !l->is_number() || !seed->is_number()) throw bad("bad lsh");
  i.lsh.k = static_cast<std::uint32_t>(k->uint64());
  i.lsh.l = static_cast<std::uint32_t>(l->uint64());
  i.lsh.seed = seed->uint64();
  if (i.lsh.k < 1 || i.lsh.k > 20 || i.lsh.l < 1 || i.lsh.l > 512) throw bad("lsh k or l out of range");
  if (const Json *c = o.find("created"); c && c->is_number()) i.created = c->int64();
  return i;
}

std::uint64_t mix64(std::uint64_t x) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ull;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebull;
  x ^= x >> 31;
  return x;
}

std::string lower(std::string_view s) {
  std::string o(s);
  for (char &c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return o;
}

}  // namespace

struct Database::Impl {
  fs::path dir;
  DatabaseInfo info;
  const diff::WeightTable *weights = nullptr;
  std::map<std::string, std::unique_ptr<ExeData>> exes;  // by id
  std::vector<FnRef> all;                                // every function
  // Per table: bucket -> indexes into `all`.
  std::vector<std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>> index;

  fs::path exe_path(std::string_view id) const { return dir / "exe" / (std::string(id) + ".rkbx"); }

  std::unique_ptr<ExeData> load_exe(const fs::path &p) const {
    auto d = std::make_unique<ExeData>();
    std::error_code ec;
    d->mtime = fs::last_write_time(p, ec);
    d->size = fs::file_size(p, ec);
    try {
      auto [exe, fns] = decode_executable(read_file(p), info.lsh.l);
      if (p.stem().string() != exe.id) throw BsimError("its id isn't its file name");
      d->exe = std::move(exe);
      d->functions = std::move(fns);
    } catch (const BsimError &e) {
      throw BsimError(p.string() + ": " + e.what());
    }
    return d;
  }

  void rebuild_index() {
    all.clear();
    index.assign(info.lsh.l, {});
    for (const auto &[id, d] : exes) add_to_index(*d);
  }

  void add_to_index(const ExeData &d) {
    for (std::uint32_t i = 0; i < d.functions.size(); ++i) {
      const auto ref = static_cast<std::uint32_t>(all.size());
      all.push_back({&d, i});
      const FunctionRecord &f = d.functions[i];
      for (std::uint32_t t = 0; t < info.lsh.l; ++t) index[t][f.buckets[t]].push_back(ref);
    }
  }

  // Loads (or re-loads) what is on disk; keeps unchanged executables, and
  // the index when nothing changed.
  void scan() {
    bool changed = false;
    std::map<std::string, std::unique_ptr<ExeData>> next;
    std::error_code ec;
    const fs::path exe_dir = dir / "exe";
    if (fs::is_directory(exe_dir, ec)) {
      for (const fs::directory_entry &e : fs::directory_iterator(exe_dir, ec)) {
        const fs::path &p = e.path();
        if (p.extension() != ".rkbx" || !e.is_regular_file(ec)) continue;
        const std::string id = p.stem().string();
        if (!valid_id(id)) continue;
        auto it = exes.find(id);
        if (it != exes.end()) {
          std::error_code ec2;
          if (fs::last_write_time(p, ec2) == it->second->mtime && fs::file_size(p, ec2) == it->second->size) {
            next.emplace(id, std::move(it->second));
            continue;
          }
        }
        next.emplace(id, load_exe(p));
        changed = true;
      }
    }
    changed = changed || next.size() != exes.size() || index.empty();
    exes = std::move(next);
    if (changed) rebuild_index();
  }

  std::vector<std::uint32_t> buckets(std::span<const std::uint32_t> features) const {
    const diff::LshVector v(features, *weights);
    std::vector<std::uint32_t> out(info.lsh.l, 0);
    if (v.empty()) return out;
    std::vector<double> acc(info.lsh.k);
    for (std::uint32_t t = 0; t < info.lsh.l; ++t) {
      std::fill(acc.begin(), acc.end(), 0.0);
      const std::uint64_t table_seed = mix64(info.lsh.seed ^ (0x9e3779b97f4a7c15ull * (t + 1)));
      for (const diff::HashEntry &e : v.entries()) {
        const std::uint64_t r = mix64(table_seed ^ (static_cast<std::uint64_t>(e.hash) * 0xd6e8feb86659fd93ull));
        for (std::uint32_t b = 0; b < info.lsh.k; ++b) acc[b] += ((r >> b) & 1) ? e.coeff : -e.coeff;
      }
      std::uint32_t bucket = 0;
      for (std::uint32_t b = 0; b < info.lsh.k; ++b)
        if (acc[b] >= 0) bucket |= 1u << b;
      out[t] = bucket;
    }
    return out;
  }
};

Database::Database(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Database::Database(Database &&) noexcept = default;
Database &Database::operator=(Database &&) noexcept = default;
Database::~Database() = default;

bool Database::looks_like(const fs::path &dir) {
  std::error_code ec;
  return fs::is_regular_file(dir / "database.json", ec);
}

DatabaseInfo Database::peek(const fs::path &dir) {
  const fs::path f = dir / "database.json";
  std::error_code ec;
  if (!fs::is_regular_file(f, ec)) throw BsimError(dir.string() + " is not a BSim database (no database.json)");
  try {
    return info_from(Json::parse(read_file(f)), f);
  } catch (const BsimError &) {
    throw;
  } catch (const std::exception &e) {
    throw BsimError(f.string() + ": " + e.what());
  }
}

Database Database::create(const fs::path &dir, DatabaseInfo info) {
  std::error_code ec;
  if (fs::exists(dir, ec) && !(fs::is_directory(dir, ec) && fs::is_empty(dir, ec)))
    throw BsimError(dir.string() + " exists and isn't an empty directory");
  if (info.lsh.k < 1 || info.lsh.k > 20 || info.lsh.l < 1 || info.lsh.l > 512)
    throw BsimError("lsh k is 1..20 and l 1..512");
  info.format = kFormatVersion;
  info.settings = diff::WeightTable::builtin(weights_of(info.weights)).settings();
  if (info.created == 0)
    info.created = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  if (info.name.empty()) info.name = dir.stem().string();
  fs::create_directories(dir / "exe", ec);
  if (ec) throw BsimError("cannot create " + (dir / "exe").string() + ": " + ec.message());
  std::ostringstream doc;
  info_json(info).write_document(doc);
  write_atomically(dir / "database.json", doc.str());
  return open(dir);
}

Database Database::open(const fs::path &dir) {
  auto impl = std::make_unique<Impl>();
  impl->dir = dir;
  impl->info = peek(dir);
  impl->weights = &diff::WeightTable::builtin(weights_of(impl->info.weights));
  impl->scan();
  return Database(std::move(impl));
}

const DatabaseInfo &Database::info() const { return impl_->info; }
const fs::path &Database::path() const { return impl_->dir; }
const diff::WeightTable &Database::weights() const { return *impl_->weights; }

std::vector<std::uint32_t> Database::buckets(std::span<const std::uint32_t> features) const {
  return impl_->buckets(features);
}

Database::AddResult Database::add(Executable exe, std::vector<FunctionRecord> functions) {
  if (!valid_id(exe.id)) throw BsimError("an executable's id is its sha256 in lowercase hex");
  AddResult r;
  std::vector<FunctionRecord> kept;
  kept.reserve(functions.size());
  for (FunctionRecord &f : functions) {
    if (f.features.empty()) {
      ++r.empty;
      continue;
    }
    if (!std::is_sorted(f.features.begin(), f.features.end())) std::sort(f.features.begin(), f.features.end());
    if (f.name.size() > (1 << 16) - 1) f.name.resize((1 << 16) - 1);
    if (f.prototype.size() > (1 << 16) - 1) f.prototype.clear();
    f.buckets = impl_->buckets(f.features);
    kept.push_back(std::move(f));
  }
  std::sort(kept.begin(), kept.end(), [](const FunctionRecord &a, const FunctionRecord &b) { return a.entry < b.entry; });
  if (exe.ingested == 0)
    exe.ingested = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  r.functions = kept.size();
  {
    WriteLock lock(impl_->dir);
    write_atomically(impl_->exe_path(exe.id), encode_executable(exe, kept, impl_->info.lsh.l));
  }
  r.replaced = impl_->exes.contains(exe.id);
  impl_->scan();
  return r;
}

bool Database::remove(std::string_view id) {
  if (!valid_id(id)) return false;
  bool removed = false;
  {
    WriteLock lock(impl_->dir);
    std::error_code ec;
    removed = fs::remove(impl_->exe_path(id), ec);
  }
  impl_->scan();
  return removed;
}

bool Database::update(std::string_view id, const std::map<std::string, std::string> &categories, const std::string &name) {
  if (!valid_id(id)) return false;
  WriteLock lock(impl_->dir);
  const fs::path p = impl_->exe_path(id);
  std::error_code ec;
  if (!fs::is_regular_file(p, ec)) return false;
  auto [exe, fns] = decode_executable(read_file(p), impl_->info.lsh.l);
  exe.categories = categories;
  if (!name.empty()) exe.name = name;
  write_atomically(p, encode_executable(exe, fns, impl_->info.lsh.l));
  impl_->scan();
  return true;
}

void Database::reload() { impl_->scan(); }

std::vector<const Executable *> Database::executables() const {
  std::vector<const Executable *> out;
  for (const auto &[id, d] : impl_->exes) out.push_back(&d->exe);
  std::sort(out.begin(), out.end(), [](const Executable *a, const Executable *b) {
    return std::tie(a->name, a->id) < std::tie(b->name, b->id);
  });
  return out;
}

const Executable *Database::executable(std::string_view id) const {
  auto it = impl_->exes.find(std::string(id));
  return it == impl_->exes.end() ? nullptr : &it->second->exe;
}

const Executable *Database::find_executable(std::string_view key) const {
  if (const Executable *e = executable(key)) return e;
  const Executable *found = nullptr;
  int hits = 0;
  const bool hex = key.size() >= 6 && key.size() <= 64 &&
                   std::all_of(key.begin(), key.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
  if (hex) {
    for (const auto &[id, d] : impl_->exes)
      if (id.starts_with(key)) {
        found = &d->exe;
        ++hits;
      }
    if (hits == 1) return found;
  }
  found = nullptr;
  hits = 0;
  for (const auto &[id, d] : impl_->exes)
    if (d->exe.name == key) {
      found = &d->exe;
      ++hits;
    }
  return hits == 1 ? found : nullptr;
}

std::span<const FunctionRecord> Database::functions(std::string_view id) const {
  auto it = impl_->exes.find(std::string(id));
  if (it == impl_->exes.end()) return {};
  return it->second->functions;
}

std::size_t Database::function_count() const { return impl_->all.size(); }

double Database::self_significance(std::span<const std::uint32_t> features) const {
  const diff::LshVector v(features, *impl_->weights);
  return diff::self_significance(*impl_->weights, v);
}

std::vector<Match> Database::search(std::span<const std::uint32_t> features, const SearchOptions &o,
                                    SearchStats *stats) const {
  const Impl &d = *impl_;
  std::vector<std::uint32_t> sorted(features.begin(), features.end());
  if (!std::is_sorted(sorted.begin(), sorted.end())) std::sort(sorted.begin(), sorted.end());
  const diff::LshVector q(sorted, *d.weights);
  if (stats) *stats = {0, d.all.size(), false};
  if (q.empty() || d.all.empty()) return {};

  // Filters, decided once per executable.
  const std::string needle = lower(o.name_contains);
  std::unordered_map<const ExeData *, bool> exe_ok;
  auto exe_passes = [&](const ExeData *x) {
    auto [it, fresh] = exe_ok.try_emplace(x, true);
    if (!fresh) return it->second;
    const Executable &e = x->exe;
    bool ok = true;
    auto names = [&](const std::vector<std::string> &keys) {
      for (const std::string &k : keys)
        if (k == e.id || k == e.name || (k.size() >= 6 && e.id.starts_with(k))) return true;
      return false;
    };
    if (!o.executables.empty() && !names(o.executables)) ok = false;
    if (ok && !o.exclude_executables.empty() && names(o.exclude_executables)) ok = false;
    if (ok && !o.languages.empty())
      ok = std::any_of(o.languages.begin(), o.languages.end(),
                       [&](const std::string &l) { return e.language.starts_with(l); });
    for (const auto &[k, v] : o.categories) {
      if (!ok) break;
      auto c = e.categories.find(k);
      ok = c != e.categories.end() && c->second == v;
    }
    it->second = ok;
    return ok;
  };
  auto fn_passes = [&](const FnRef &r) {
    if (!exe_passes(r.exe)) return false;
    const FunctionRecord &f = r.exe->functions[r.index];
    if (o.exclude_default_names && (f.flags & kDefaultName)) return false;
    if (!needle.empty() && lower(f.name).find(needle) == std::string::npos) return false;
    return true;
  };

  std::vector<std::uint32_t> candidates;
  const bool exhaustive = o.exhaustive || d.all.size() <= o.exhaustive_below;
  if (stats) stats->exhaustive = exhaustive;
  if (exhaustive) {
    candidates.resize(d.all.size());
    for (std::uint32_t i = 0; i < candidates.size(); ++i) candidates[i] = i;
  } else {
    const std::vector<std::uint32_t> qb = d.buckets(sorted);
    std::vector<bool> seen(d.all.size(), false);
    for (std::uint32_t t = 0; t < d.info.lsh.l; ++t) {
      auto it = d.index[t].find(qb[t]);
      if (it == d.index[t].end()) continue;
      for (std::uint32_t ref : it->second)
        if (!seen[ref]) {
          seen[ref] = true;
          candidates.push_back(ref);
        }
    }
  }

  std::vector<Match> out;
  std::size_t scored = 0;
  for (std::uint32_t ref : candidates) {
    const FnRef &r = d.all[ref];
    if (!fn_passes(r)) continue;
    const FunctionRecord &f = r.exe->functions[r.index];
    ++scored;
    const diff::LshVector v(f.features, *d.weights);
    diff::VectorCompare cmp;
    const double sim = diff::compare(q, v, &cmp);
    if (!(sim >= o.min_similarity)) continue;
    const double conf = diff::significance(*d.weights, cmp);
    if (!(conf >= o.min_confidence)) continue;
    out.push_back({&r.exe->exe, &f, sim, conf});
  }
  if (stats) stats->candidates = scored;
  auto better = [](const Match &a, const Match &b) {
    if (a.similarity != b.similarity) return a.similarity > b.similarity;
    if (a.confidence != b.confidence) return a.confidence > b.confidence;
    if (a.executable->name != b.executable->name) return a.executable->name < b.executable->name;
    if (a.executable->id != b.executable->id) return a.executable->id < b.executable->id;
    return a.function->entry < b.function->entry;
  };
  if (out.size() > o.max_matches) {
    std::partial_sort(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(o.max_matches), out.end(), better);
    out.resize(o.max_matches);
  } else {
    std::sort(out.begin(), out.end(), better);
  }
  return out;
}

}  // namespace revkit::bsim
