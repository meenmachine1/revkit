#include "parse_c.h"

#include "define_type.h"
#include "type_archive.h"
#include "type_record.h"

#include "revkit/cparse/archive.h"
#include "revkit/cparse/spec.h"
#include "revkit/types/print.h"

#include <algorithm>
#include <filesystem>
#include <tuple>
#include <mutex>
#include <set>
#include <system_error>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;
using types::TypeId;

namespace {

const char *FormatName(loader::Format f) {
  switch (f) {
    case loader::Format::elf: return "elf";
    case loader::Format::pe: return "pe";
    case loader::Format::raw: return "raw";
    case loader::Format::macho: return "macho";
  }
  return "raw";
}

// Size, member offsets and widths; enumerator values: a definition's
// layout, without its members' names and types.
std::string Shape(const types::TypeStore &store, TypeId id) {
  const types::Type &t = store.get(store.strip_typedefs(id, false));
  std::string s;
  if (const auto *a = t.as<types::AggregateType>()) {
    s = "a" + std::to_string(int(a->kind)) + ":" + std::to_string(a->size) + (a->complete ? "" : "?");
    for (const auto &f : a->fields)
      s += "," + std::to_string(f.bit_offset) + ":" + std::to_string(f.bit_size);
  } else if (const auto *e = t.as<types::EnumType>()) {
    s = "e" + std::to_string(e->size) + (e->is_signed ? "s" : "u");
    for (const auto &v : e->values) s += "," + std::to_string(v.value);
  } else {
    s = "t" + std::to_string(store.size_of(id));
  }
  return s;
}

pb::ParseCSeverity SeverityOf(cparse::Severity s) {
  switch (s) {
    case cparse::Severity::Note: return pb::PARSE_C_SEVERITY_NOTE;
    case cparse::Severity::Warning: return pb::PARSE_C_SEVERITY_WARNING;
    case cparse::Severity::Error: return pb::PARSE_C_SEVERITY_ERROR;
  }
  return pb::PARSE_C_SEVERITY_UNSPECIFIED;
}

bool UnderRoot(const std::string &canonical, const std::vector<std::string> &roots) {
  for (const std::string &r : roots) {
    std::error_code ec;
    std::string root = std::filesystem::weakly_canonical(r, ec).string();
    if (ec) continue;
    if (canonical == root) return true;
    if (canonical.starts_with(root.ends_with('/') ? root : root + "/")) return true;
  }
  return false;
}

}  // namespace

cparse::Profile ProgramProfile(const Program &program, std::vector<std::string> *notes) {
  struct Cached {
    cparse::Profile profile;
    std::vector<std::string> notes;
  };
  static std::mutex mu;
  static std::map<std::string, Cached> cache;
  const auto &lang = program.language();
  const std::string format = FormatName(program.image().format);
  const std::string key = lang.language + "|" + lang.compiler + "|" + format;
  {
    std::lock_guard lock(mu);
    if (auto it = cache.find(key); it != cache.end()) {
      if (notes) *notes = it->second.notes;
      return it->second.profile;
    }
  }
  Cached c;
  try {
    c.profile = cparse::profile_for_language(lang.language, lang.compiler, format, &c.notes);
  } catch (const std::exception &e) {
    // No spec to read (a language Ghidra doesn't describe): the target's
    // own defaults.
    cparse::ProfileInputs in;
    in.language_id = lang.language;
    in.compiler_id = lang.compiler;
    in.format = format;
    c.profile = cparse::profile_for(in, &c.notes);
    c.notes.push_back(std::string("the compiler spec could not be read: ") + e.what());
  }
  std::lock_guard lock(mu);
  auto &slot = cache.emplace(key, std::move(c)).first->second;
  if (notes) *notes = slot.notes;
  return slot.profile;
}

ProgramTypes::ProgramTypes(const NamedTypes &names, Closure closure, types::TypeStore &store)
    : names_(names), closure_(std::move(closure)), store_(store) {
  sorted_ = std::is_sorted(names.types.begin(), names.types.end(),
                           [](const auto &a, const auto &b) { return std::tie(a.key, a.hash) < std::tie(b.key, b.hash); }) &&
            std::is_sorted(names.bindings.begin(), names.bindings.end(),
                           [](const auto &a, const auto &b) { return a.first < b.first; });
  if (sorted_) return;
  // The library's first, then the program's own over them, then bindings.
  for (const auto &e : names.types)
    if (e.library) definitions_.emplace(e.key, e.hash);
  for (const auto &e : names.types)
    if (!e.library && own_.insert(e.key).second) definitions_[e.key] = e.hash;
  for (const auto &[key, hash] : names.bindings) {
    definitions_[key] = hash;
    own_.insert(key);
  }
}

std::string ProgramTypes::definition(const std::string &key) const {
  if (!sorted_) {
    auto it = definitions_.find(key);
    return it == definitions_.end() ? std::string() : it->second;
  }
  // As the index picks: a binding, else the program's own first entry,
  // else the library's first.
  if (const std::string *b = names_.bound(key)) return *b;
  auto lo = std::lower_bound(names_.types.begin(), names_.types.end(), key,
                             [](const NamedTypes::Entry &e, const std::string &k) { return e.key < k; });
  const NamedTypes::Entry *library = nullptr;
  for (auto it = lo; it != names_.types.end() && it->key == key; ++it) {
    if (!it->library) return it->hash;
    if (!library) library = &*it;
  }
  return library ? library->hash : std::string();
}

bool ProgramTypes::own(const std::string &key) const {
  if (!sorted_) return own_.contains(key);
  if (names_.bound(key)) return true;
  auto lo = std::lower_bound(names_.types.begin(), names_.types.end(), key,
                             [](const NamedTypes::Entry &e, const std::string &k) { return e.key < k; });
  for (auto it = lo; it != names_.types.end() && it->key == key; ++it)
    if (!it->library) return true;
  return false;
}

std::optional<TypeId> ProgramTypes::intern(const std::string &hash) {
  if (auto it = by_hash_.find(hash); it != by_hash_.end()) return it->second;
  TypeClosure records = closure_(hash);
  if (records.empty()) return std::nullopt;
  std::map<std::string, std::string> map(records.begin(), records.end());
  for (const auto &[h, id] : InternRecords(map, store_)) {
    by_hash_.emplace(h, id);
    recorded_.emplace(id, h);
  }
  auto it = by_hash_.find(hash);
  if (it == by_hash_.end()) return std::nullopt;
  return it->second;
}

std::optional<TypeId> ProgramTypes::lookup(std::string_view key) {
  // A type by hash: "__revkit_type_<hash>" names the program's type with
  // that hash itself (no typedef), so a client can write a type it has by
  // hash where a type name goes (the type editor writes the fields it
  // didn't change that way, so they keep their exact types).
  constexpr std::string_view kByHash = "typedef __revkit_type_";
  if (key.starts_with(kByHash)) {
    const std::string_view h = key.substr(kByHash.size());
    if (h.empty() || h.size() > 128 || h.find_first_not_of("0123456789abcdef") != std::string_view::npos)
      return std::nullopt;
    return intern(std::string(h));
  }
  const std::string hash = definition(std::string(key));
  if (hash.empty()) return std::nullopt;
  return intern(hash);
}

const std::string *ProgramTypes::recorded(TypeId id) const {
  auto it = recorded_.find(id);
  return it == recorded_.end() ? nullptr : &it->second;
}

Status ParseC(const ParseCContext &c, const pb::ParseCRequest &req, pb::ParseCResponse &resp) {
  if (req.sources().empty()) return Error(StatusCode::kInvalidArgument, "sources is empty");
  if (req.sources_size() > 1024) return Error(StatusCode::kInvalidArgument, "more than 1024 sources");
  if (req.include_dirs_size() + req.system_include_dirs_size() > 256)
    return Error(StatusCode::kInvalidArgument, "more than 256 include directories");
  if (req.defines_size() + req.undefines_size() > 4096)
    return Error(StatusCode::kInvalidArgument, "more than 4096 defines");

  // Host files: only under --browse-root, every one checked (and every
  // #include, by the file system the parser reads through).
  bool host = !req.include_dirs().empty() || !req.system_include_dirs().empty();
  for (const auto &s : req.sources()) {
    if (s.kind_case() == pb::ParseCSource::KIND_NOT_SET)
      return Error(StatusCode::kInvalidArgument, "a source needs text or a path");
    host = host || s.has_path();
  }
  if (host && c.browse_roots.empty())
    return Error(StatusCode::kFailedPrecondition,
                 "reading the daemon's files needs rk-daemon --browse-root <dir>; send the text instead");
  auto fs = cparse::host_file_system(c.browse_roots);
  auto check_dir = [&](const std::string &d) -> Status {
    std::error_code ec;
    const std::string canon = std::filesystem::canonical(d, ec).string();
    if (ec || !std::filesystem::is_directory(canon, ec)) return Error(StatusCode::kNotFound, "no directory " + d);
    if (!UnderRoot(canon, c.browse_roots))
      return Error(StatusCode::kPermissionDenied, d + " is not under a --browse-root directory");
    return Status::Ok();
  };
  cparse::Options o;
  for (const std::string &d : req.include_dirs()) {
    if (Status st = check_dir(d); !st.ok()) return st;
    o.include_dirs.push_back(d);
  }
  for (const std::string &d : req.system_include_dirs()) {
    if (Status st = check_dir(d); !st.ok()) return st;
    o.system_include_dirs.push_back(d);
  }
  std::vector<cparse::Source> sources;
  for (const auto &s : req.sources()) {
    if (s.has_path()) {
      if (!fs->resolve(s.path()))
        return Error(StatusCode::kNotFound, s.path() + ": no such file, or not under a --browse-root directory");
      sources.push_back({s.path(), {}, true});
    } else {
      sources.push_back({s.name().empty() ? std::string("<input>") : s.name(), s.text(), false});
    }
  }
  std::vector<std::string> notes;
  std::optional<pb::TypeArchiveSidecar> archive;
  if (!req.archive_sidecar().empty()) {
    std::string err;
    archive = ReadTypeArchiveSidecar(req.archive_sidecar(), &err);
    if (!archive) return Error(StatusCode::kInvalidArgument, "archive_sidecar: " + err);
  }
  if (!req.profile().empty()) {
    auto p = cparse::profile_named(req.profile());
    if (!p) return Error(StatusCode::kInvalidArgument, "unknown profile " + req.profile());
    o.profile = *p;
  } else if (archive) {
    // The archive's data model: its types keep the layouts they were
    // exported with, whatever the program's target.
    o.profile = ProfileOf(archive->data_model());
    const cparse::Profile own = ProgramProfile(c.program);
    if (!(own.rules == o.profile.rules))
      notes.push_back("the archive was made for " + cparse::describe_profile(o.profile) + "; this program is " +
                      cparse::describe_profile(own) + ": the types keep the archive's layouts");
  } else {
    o.profile = ProgramProfile(c.program, &notes);
  }
  for (const std::string &d : req.defines()) {
    auto eq = d.find('=');
    if (d.empty() || eq == 0) return Error(StatusCode::kInvalidArgument, "empty define");
    if (eq == std::string::npos) o.defines.emplace_back(d, "1");
    else o.defines.emplace_back(d.substr(0, eq), d.substr(eq + 1));
  }
  for (const std::string &u : req.undefines()) o.undefines.push_back(u);
  o.cplusplus = req.options().cplusplus();
  o.defines_as_enums = req.options().defines_as_enum();
  o.fs = host ? fs.get() : nullptr;

  types::TypeStore store;
  ProgramTypes program(c.names, c.closure, store);
  // An archive is self-contained: what it only declares stays declared,
  // as it was exported.
  if (!archive) o.lookup = [&](std::string_view key) { return program.lookup(key); };
  cparse::Result r = cparse::parse(store, sources, o);

  // The roots, then every type they reach that the program lacks, as nodes.
  std::vector<TypeId> roots;
  for (const auto &n : r.named)
    if (!n.where.system || req.options().include_system()) roots.push_back(n.id);
  if (req.options().prototypes())
    for (const auto &p : r.prototypes) roots.push_back(p.type);
  for (const auto &e : r.constant_enums) roots.push_back(e.id);
  // Every root is a node (so each named type has an index), and so is
  // everything below one that the program doesn't have; the rest is
  // referenced by its hash.
  const std::set<TypeId> root_set(roots.begin(), roots.end());
  std::map<TypeId, std::uint32_t> index;
  std::vector<TypeId> order;
  std::vector<TypeId> stack(roots.rbegin(), roots.rend());
  while (!stack.empty()) {
    TypeId id = stack.back();
    stack.pop_back();
    if (index.contains(id) || (program.recorded(id) && !root_set.contains(id))) continue;
    index.emplace(id, static_cast<std::uint32_t>(order.size()));
    order.push_back(id);
    types::Type t = store.get(id);
    std::vector<TypeId> refs;
    types::for_each_ref(t, [&](TypeId &x, types::EdgeKind) { refs.push_back(x); });
    for (auto it = refs.rbegin(); it != refs.rend(); ++it) stack.push_back(*it);
  }
  auto ref = [&](TypeId id) {
    pb::TypeNodeRef out;
    if (auto it = index.find(id); it != index.end()) out.set_assertion_index(it->second);
    else out.set_hash(*program.recorded(id));
    return out;
  };
  for (TypeId id : order) {
    *resp.add_nodes() = TypeNodeOf(store, id, ref);
    resp.add_hashes(store.hash(id).hex());
    resp.add_displays(types::type_name(store, id));
  }
  auto node_index = [&](TypeId id) -> std::uint32_t {
    auto it = index.find(id);
    return it == index.end() ? 0 : it->second;
  };

  // Categories: the archive's, else the header's file name.
  std::map<std::string, std::string> archive_category;
  if (archive)
    for (const auto &t : archive->types()) archive_category.emplace(t.key(), t.category());
  auto category_for = [&](const cparse::NamedType &n) -> std::string {
    if (archive) {
      auto it = archive_category.find(n.key);
      return it == archive_category.end() ? std::string() : it->second;
    }
    if (n.where.file.empty() || n.where.file.starts_with("<")) return {};
    std::string base = std::filesystem::path(n.where.file).filename().string();
    auto path = NormalizeTypeCategory("/" + base);
    return path ? *path : std::string();
  };
  auto add_named = [&](const cparse::NamedType &n) {
    auto *out = resp.add_named();
    out->set_category(category_for(n));
    if (c.categories)
      if (auto it = c.categories->find(n.key); it != c.categories->end()) out->set_existing_category(it->second);
    out->set_existing_library(program.library_only(n.key));
    out->set_key(n.key);
    out->set_hash(store.hash(n.id).hex());
    out->set_index(node_index(n.id));
    out->set_file(n.where.file);
    out->set_line(n.where.line);
    out->set_system(n.where.system);
    const std::string existing = program.definition(n.key);
    out->set_existing_hash(existing);
    out->set_c_definition(types::definition(store, n.id));
    if (!existing.empty() && existing != out->hash()) {
      auto *cf = resp.add_conflicts();
      cf->set_named_key(n.key);
      cf->set_existing_hash(existing);
      cf->set_new_hash(out->hash());
      if (auto e = program.intern(existing)) cf->set_same_layout(Shape(store, *e) == Shape(store, n.id));
    }
  };
  for (const auto &n : r.named)
    if (!n.where.system || req.options().include_system()) add_named(n);
  for (const auto &n : r.constant_enums) add_named(n);
  if (req.options().prototypes())
    for (const auto &p : r.prototypes) {
      auto *out = resp.add_prototypes();
      out->set_name(p.name);
      out->set_index(node_index(p.type));
      out->set_hash(store.hash(p.type).hex());
      out->set_declaration(types::prototype(store, p.type, p.name));
      out->set_file(p.where.file);
      out->set_line(p.where.line);
      out->set_defined(p.defined);
    }
  for (const auto &k : r.constants) {
    auto *out = resp.add_constants();
    out->set_name(k.name);
    out->set_value(k.value);
    out->set_is_unsigned(k.is_unsigned);
    out->set_file(k.where.file);
    out->set_line(k.where.line);
  }
  // Each diagnostic's line, from the source text or the host file.
  std::map<std::string, std::optional<std::string>> texts;
  for (const cparse::Source &src : sources)
    if (!src.path) texts.emplace(src.name, src.text);
  auto line_of = [&](const std::string &file, std::uint32_t line) -> std::string {
    auto it = texts.find(file);
    if (it == texts.end()) {
      std::optional<std::string> text;
      if (host)
        if (auto canon = fs->resolve(file)) text = fs->read(*canon, o.limits.max_bytes);
      it = texts.emplace(file, std::move(text)).first;
    }
    if (!it->second || line == 0) return {};
    const std::string &t = *it->second;
    std::size_t at = 0;
    for (std::uint32_t l = 1; l < line && at != std::string::npos; ++l) {
      at = t.find('\n', at);
      if (at != std::string::npos) ++at;
    }
    if (at == std::string::npos || at > t.size()) return {};
    std::string out = t.substr(at, std::min<std::size_t>(t.find('\n', at) - at, 512));
    if (!out.empty() && out.back() == '\r') out.pop_back();
    return out;
  };
  for (const auto &d : r.diagnostics) {
    auto *out = resp.add_diagnostics();
    out->set_source_line(line_of(d.file, d.line));
    out->set_file(d.file);
    out->set_line(d.line);
    out->set_column(d.col);
    out->set_severity(SeverityOf(d.severity));
    out->set_text(d.text);
  }
  if (archive) {
    pb::ParseCArchiveCheck &check = *resp.mutable_archive();
    check.set_name(archive->name());
    check.set_origin(archive->provenance().origin());
    check.set_data_model(cparse::describe_profile(o.profile));
    check.set_types(static_cast<std::uint32_t>(archive->types_size()));
    std::map<std::string, std::string> parsed;
    for (const auto &n : r.named) parsed.emplace(n.key, store.hash(n.id).hex());
    // A library archive's prototypes (form "prototype", key "function <name>").
    for (const auto &p : r.prototypes) parsed.emplace("function " + p.name, store.hash(p.type).hex());
    std::uint32_t verified = 0;
    for (const auto &t : archive->types()) {
      auto it = parsed.find(t.key());
      if (it != parsed.end() && it->second == t.hash()) {
        ++verified;
        continue;
      }
      auto *m = check.add_mismatches();
      m->set_key(t.key());
      m->set_expected_hash(t.hash());
      if (it != parsed.end()) m->set_parsed_hash(it->second);
    }
    check.set_verified(verified);
    // The header as the sidecar's: one source, sent as text or read here.
    if (sources.size() == 1) {
      std::optional<std::string> text;
      if (!sources[0].path) text = sources[0].text;
      else if (auto canon = fs->resolve(sources[0].name)) text = fs->read(*canon, o.limits.max_bytes);
      check.set_header_changed(!text || Sha256Hex(*text) != archive->header_sha256());
    } else {
      check.set_header_changed(true);
    }
  }
  resp.set_profile(o.profile.name);
  for (const std::string &n : notes) resp.add_profile_notes(n);
  resp.set_errors(static_cast<std::uint32_t>(r.errors));
  resp.set_warnings(static_cast<std::uint32_t>(r.warnings));
  resp.set_limit_hit(r.limit_hit);
  for (const std::string &f : r.files) resp.add_files(f);
  return Status::Ok();
}

static ParsedRetype RetypeOf(types::TypeStore &store, const ProgramTypes &program, TypeId type);

std::optional<ParsedRetype> ParseRetype(const ParseCContext &c, const std::string &declaration, bool function) {
  if (declaration.size() > 65536) return std::nullopt;
  return RetypeParser(c).parse(declaration, function);
}

RetypeParser::RetypeParser(const ParseCContext &c) : program_(c.names, c.closure, store_) {
  options_.profile = ProgramProfile(c.program);
  options_.lookup = [this](std::string_view key) { return program_.lookup(key); };
  options_.limits.wall_time = std::chrono::milliseconds(2000);
}

std::optional<ParsedRetype> RetypeParser::parse(const std::string &declaration, bool function) {
  if (declaration.size() > 65536) return std::nullopt;
  std::optional<cparse::Declaration> d = cparse::parse_declaration(store_, declaration, options_);
  if (!d || d->function != function) return std::nullopt;
  return RetypeOf(store_, program_, d->type);
}

// The type and the records of what it reaches that the program lacks.
static ParsedRetype RetypeOf(types::TypeStore &store, const ProgramTypes &program, TypeId type) {
  ParsedRetype out;
  out.hash = store.hash(type).hex();
  std::vector<TypeId> stack{type};
  std::set<TypeId> seen;
  auto by_hash = [&](TypeId x) {
    pb::TypeNodeRef r;
    r.set_hash(store.hash(x).hex());
    return r;
  };
  while (!stack.empty()) {
    TypeId id = stack.back();
    stack.pop_back();
    if (!seen.insert(id).second || program.recorded(id)) continue;
    ParsedRetype::Def def;
    def.record = EncodeTypeRecord(store, id);
    *def.body.mutable_define_type()->mutable_type() = TypeNodeOf(store, id, by_hash);
    out.types.emplace(store.hash(id).hex(), std::move(def));
    types::Type t = store.get(id);
    types::for_each_ref(t, [&](TypeId &x, types::EdgeKind) { stack.push_back(x); });
  }
  return out;
}

std::optional<ParsedRetype> ParseSkeletonPrototype(const ParseCContext &c, const std::string &declaration,
                                                   std::vector<std::string> *placeholders, std::string *error) {
  auto fail = [&](std::string why) -> std::optional<ParsedRetype> {
    if (error) *error = std::move(why);
    return std::nullopt;
  };
  if (declaration.size() > 65536) return fail("the prototype is longer than 64 KiB");
  types::TypeStore store;
  ProgramTypes program(c.names, c.closure, store);
  // Type names the program lacks, found by parsing (the parser names each
  // it can't resolve), and their placeholders.
  std::set<std::string> unknown;
  std::map<std::string, TypeId> made;
  cparse::Options o;
  o.profile = ProgramProfile(c.program);
  o.limits.wall_time = std::chrono::milliseconds(2000);
  o.lookup = [&](std::string_view key) -> std::optional<TypeId> {
    if (auto t = program.lookup(key)) return t;
    constexpr std::string_view kTypedef = "typedef ";
    if (!key.starts_with(kTypedef)) return std::nullopt;
    const std::string name(key.substr(kTypedef.size()));
    if (!unknown.contains(name)) return std::nullopt;
    if (auto it = made.find(name); it != made.end()) return it->second;
    types::AggregateType a;
    a.kind = types::AggregateKind::Struct;
    a.name = name;
    a.complete = false;
    return made[name] = store.intern(types::Type(std::move(a)));
  };
  static constexpr std::string_view kUnknown = "unknown type name '";
  for (int round = 0; round < 32; ++round) {
    cparse::Result result;
    std::optional<cparse::Declaration> d = cparse::parse_declaration(store, declaration, o, &result);
    if (d && d->function) {
      ParsedRetype out = RetypeOf(store, program, d->type);
      if (placeholders)
        for (const auto &[hash, def] : out.types)
          if (const pb::TypeNode &n = def.body.define_type().type();
              (n.kind() == pb::TYPE_KIND_STRUCT || n.kind() == pb::TYPE_KIND_UNION) && n.incomplete())
            placeholders->push_back(n.name());
      return out;
    }
    if (d) return fail("not a function prototype");
    bool more = false;
    for (const cparse::Diagnostic &x : result.diagnostics)
      if (x.text.starts_with(kUnknown))
        if (std::size_t end = x.text.find('\'', kUnknown.size()); end != std::string::npos)
          more |= unknown.insert(x.text.substr(kUnknown.size(), end - kUnknown.size())).second;
    if (!more) {
      for (const cparse::Diagnostic &x : result.diagnostics)
        if (x.severity == cparse::Severity::Error) return fail(x.text);
      return fail("the prototype doesn't parse");
    }
  }
  return fail("too many unknown type names");
}

}  // namespace revkit::backend
