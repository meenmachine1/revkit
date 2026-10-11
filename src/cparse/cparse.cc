// parse() and the host file system.

#include "revkit/cparse/cparse.h"

#include "parser.h"
#include "preprocessor.h"

#include "revkit/types/describe.h"
#include "revkit/types/transform.h"

#include <filesystem>
#include <map>
#include <set>
#include <fstream>
#include <system_error>

namespace revkit::cparse {

namespace {

class HostFileSystem final : public FileSystem {
 public:
  explicit HostFileSystem(std::vector<std::string> roots) {
    for (const std::string &r : roots) {
      std::error_code ec;
      std::filesystem::path c = std::filesystem::weakly_canonical(r, ec);
      if (!ec) roots_.push_back(c.string());
    }
    restricted_ = !roots.empty();
  }

  std::optional<std::string> resolve(const std::string &path) override {
    std::error_code ec;
    std::filesystem::path c = std::filesystem::canonical(path, ec);
    if (ec) return std::nullopt;
    if (!std::filesystem::is_regular_file(c, ec) || ec) return std::nullopt;
    std::string s = c.string();
    if (restricted_ && !under_root(s)) return std::nullopt;
    return s;
  }

  std::optional<std::string> read(const std::string &canonical, std::size_t max) override {
    if (restricted_ && !under_root(canonical)) return std::nullopt;
    std::ifstream in(canonical, std::ios::binary);
    if (!in) return std::nullopt;
    std::string out;
    char buf[65536];
    while (in) {
      in.read(buf, sizeof buf);
      out.append(buf, static_cast<std::size_t>(in.gcount()));
      if (out.size() > max) return std::nullopt;
    }
    return out;
  }

 private:
  bool under_root(const std::string &s) const {
    for (const std::string &r : roots_) {
      if (s == r) return true;
      const std::string prefix = r.ends_with('/') ? r : r + "/";
      if (s.starts_with(prefix)) return true;
    }
    return false;
  }

  std::vector<std::string> roots_;
  bool restricted_ = false;
};

}  // namespace

std::unique_ptr<FileSystem> host_file_system(std::vector<std::string> roots) {
  return std::make_unique<HostFileSystem>(std::move(roots));
}

Result parse(types::TypeStore &store, std::span<const Source> sources, const Options &options) {
  Result result;
  detail::Context ctx(options, result);
  try {
    detail::Preprocessor pp(ctx);
    for (const Source &s : sources) pp.add_source(s);
    detail::Parser parser(ctx, pp, store);
    parser.run();
  } catch (const detail::LimitReached &l) {
    result.limit_hit = true;
    ctx.diag(Severity::Error, 0, 0, 0, "parse stopped: " + l.what);
  }
  return result;
}

std::optional<Declaration> parse_declaration(types::TypeStore &store, std::string_view text, const Options &options,
                                             Result *out) {
  Result result;
  std::optional<Declaration> decl;
  {
    detail::Context ctx(options, result);
    try {
      detail::Preprocessor pp(ctx);
      pp.add_source({"<declaration>", std::string(text), false});
      detail::Parser parser(ctx, pp, store);
      parser.set_single();
      parser.run();
      if (parser.single() && result.errors == 0 && !result.limit_hit)
        decl = Declaration{parser.single()->type, parser.single()->name, parser.single()->function};
    } catch (const detail::LimitReached &l) {
      result.limit_hit = true;
      ctx.diag(Severity::Error, 0, 0, 0, "parse stopped: " + l.what);
    }
  }
  if (decl && !decl->type.valid()) decl.reset();
  if (out) *out = std::move(result);
  return decl;
}

std::vector<std::string> link(types::TypeStore &store, std::span<Result> units) {
  // Definitions agree when their shapes do (size, member names and
  // positions; enumerators): their hashes can still differ, through what
  // each unit only declared. As the DWARF importer's def_signature.
  auto shape = [&](types::TypeId id) {
    std::string sig;
    const types::Type &t = store.get(id);
    if (const auto *a = t.as<types::AggregateType>()) {
      sig = std::to_string(int(a->kind)) + ":" + std::to_string(a->size);
      for (const types::Field &f : a->fields)
        sig += "," + f.name + "@" + std::to_string(f.bit_offset) + ":" + std::to_string(f.bit_size);
    } else if (const auto *e = t.as<types::EnumType>()) {
      sig = "e" + std::to_string(e->size);
      for (const types::Enumerator &v : e->values) sig += "," + v.name + "=" + std::to_string(v.value);
    }
    return sig;
  };
  std::map<std::string, types::TypeId> defs;
  std::map<std::string, std::string> shapes;
  std::set<std::string> ambiguous;
  for (const Result &r : units)
    for (const NamedType &n : r.named) {
      if (n.key.starts_with("typedef ")) continue;
      const types::Type &t = store.get(n.id);
      const auto *a = t.as<types::AggregateType>();
      const auto *e = t.as<types::EnumType>();
      if ((a && !a->complete) || (e && !e->complete) || (!a && !e)) continue;
      auto [it, fresh] = defs.emplace(n.key, n.id);
      if (fresh) shapes[n.key] = shape(n.id);
      else if (shapes[n.key] != shape(n.id)) ambiguous.insert(n.key);
    }
  for (const std::string &k : ambiguous) defs.erase(k);
  for (Result &r : units) {
    std::vector<types::TypeId> roots;
    for (const NamedType &n : r.named) roots.push_back(n.id);
    for (const Prototype &p : r.prototypes) roots.push_back(p.type);
    if (roots.empty()) continue;
    std::vector<types::TypeId> out = types::resolve_declarations(store, roots, defs);
    std::size_t i = 0;
    for (NamedType &n : r.named) n.id = out[i++];
    for (Prototype &p : r.prototypes) p.type = out[i++];
  }
  return {ambiguous.begin(), ambiguous.end()};
}

}  // namespace revkit::cparse
