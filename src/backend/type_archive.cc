#include "type_archive.h"

#include "type_record.h"

#include "revkit/cparse/archive.h"
#include "revkit/types/describe.h"
#include "revkit/types/hash.h"

#include <google/protobuf/util/json_util.h>

#include <set>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;
using types::TypeId;

namespace {

const char *OsName(cparse::Os os) {
  switch (os) {
    case cparse::Os::None: return "none";
    case cparse::Os::Linux: return "linux";
    case cparse::Os::Windows: return "windows";
    case cparse::Os::Darwin: return "darwin";
  }
  return "none";
}

const char *CompilerName(cparse::Compiler c) {
  switch (c) {
    case cparse::Compiler::Gcc: return "gcc";
    case cparse::Compiler::Clang: return "clang";
    case cparse::Compiler::Msvc: return "msvc";
  }
  return "gcc";
}

}  // namespace

std::string Sha256Hex(std::string_view text) {
  types::Sha256 h;
  h.update(text);
  const auto d = h.finish();
  return types::to_hex(d);
}

pb::TypeArchiveDataModel DataModelOf(const cparse::Profile &p) {
  pb::TypeArchiveDataModel m;
  const cparse::LayoutRules &r = p.rules;
  m.set_profile(p.name);
  m.set_arch(p.arch);
  m.set_os(OsName(p.os));
  m.set_compiler(CompilerName(p.compiler));
  m.set_pointer_size(r.pointer_size);
  m.set_short_size(r.short_size);
  m.set_int_size(r.int_size);
  m.set_long_size(r.long_size);
  m.set_long_long_size(r.long_long_size);
  m.set_float_size(r.float_size);
  m.set_double_size(r.double_size);
  m.set_long_double_size(r.long_double_size);
  m.set_long_double_align(r.long_double_align);
  m.set_wchar_size(r.wchar_size);
  m.set_wchar_signed(r.wchar_signed);
  m.set_char_signed(r.char_signed);
  m.set_big_endian(r.big_endian);
  m.set_has_int128(r.has_int128);
  for (const auto &[size, align] : r.size_alignment)
    m.add_size_alignment(std::to_string(size) + ":" + std::to_string(align));
  m.set_max_alignment(r.max_alignment);
  m.set_bitfields(r.bitfields == cparse::BitfieldModel::Msvc ? "msvc" : "gcc");
  m.set_msvc_enums(r.msvc_enums);
  m.set_zero_width_bitfield_aligns(r.zero_width_bitfield_aligns);
  m.set_biggest_alignment(r.biggest_alignment);
  m.set_max_vector_alignment(r.max_vector_alignment);
  m.set_description(cparse::describe_profile(p));
  return m;
}

cparse::Profile ProfileOf(const pb::TypeArchiveDataModel &m) {
  cparse::Profile p = cparse::profile_named(m.profile()).value_or(cparse::Profile{});
  p.name = m.profile();
  if (!m.arch().empty()) p.arch = m.arch();
  if (m.os() == "linux") p.os = cparse::Os::Linux;
  else if (m.os() == "windows") p.os = cparse::Os::Windows;
  else if (m.os() == "darwin") p.os = cparse::Os::Darwin;
  else if (m.os() == "none") p.os = cparse::Os::None;
  if (m.compiler() == "gcc") p.compiler = cparse::Compiler::Gcc;
  else if (m.compiler() == "clang") p.compiler = cparse::Compiler::Clang;
  else if (m.compiler() == "msvc") p.compiler = cparse::Compiler::Msvc;
  cparse::LayoutRules &r = p.rules;
  // Sizes and alignments as the spec path takes them (1-64 bytes; a
  // sidecar is anyone's file): another value keeps the profile's.
  auto set = [](std::uint32_t &field, std::uint32_t v) {
    if (v > 0 && v <= 64) field = v;
  };
  set(r.pointer_size, m.pointer_size());
  set(r.short_size, m.short_size());
  set(r.int_size, m.int_size());
  set(r.long_size, m.long_size());
  set(r.long_long_size, m.long_long_size());
  set(r.float_size, m.float_size());
  set(r.double_size, m.double_size());
  set(r.long_double_size, m.long_double_size());
  set(r.long_double_align, m.long_double_align());
  set(r.wchar_size, m.wchar_size());
  r.wchar_signed = m.wchar_signed();
  r.char_signed = m.char_signed();
  r.big_endian = m.big_endian();
  r.has_int128 = m.has_int128();
  if (m.size_alignment_size() > 0) {
    r.size_alignment.clear();
    for (const std::string &sa : m.size_alignment()) {
      const auto colon = sa.find(':');
      if (colon == std::string::npos || r.size_alignment.size() >= 64) continue;
      try {
        const unsigned long size = std::stoul(sa.substr(0, colon)), align = std::stoul(sa.substr(colon + 1));
        if (size > 0 && size <= 64 && align > 0 && align <= 64)
          r.size_alignment.emplace_back(std::uint32_t(size), std::uint32_t(align));
      } catch (const std::exception &) {
      }
    }
  }
  if (m.max_alignment() <= 64) r.max_alignment = m.max_alignment();
  r.bitfields = m.bitfields() == "msvc" ? cparse::BitfieldModel::Msvc : cparse::BitfieldModel::Gcc;
  r.msvc_enums = m.msvc_enums();
  r.zero_width_bitfield_aligns = m.zero_width_bitfield_aligns();
  set(r.biggest_alignment, m.biggest_alignment());
  set(r.max_vector_alignment, m.max_vector_alignment());
  return p;
}

std::optional<pb::TypeArchiveSidecar> ReadTypeArchiveSidecar(const std::string &json, std::string *error) {
  auto fail = [&](std::string why) -> std::optional<pb::TypeArchiveSidecar> {
    if (error) *error = std::move(why);
    return std::nullopt;
  };
  if (json.size() > (64u << 20)) return fail("the sidecar is larger than 64 MiB");
  pb::TypeArchiveSidecar s;
  google::protobuf::util::JsonParseOptions o;
  o.ignore_unknown_fields = true;
  if (auto st = google::protobuf::util::JsonStringToMessage(json, &s, o); !st.ok())
    return fail("the sidecar isn't a type archive's JSON: " + std::string(st.message()));
  if (s.format() != "revkit-type-archive") return fail("the sidecar's format isn't \"revkit-type-archive\"");
  if (s.version() != 1) return fail("type archive version " + std::to_string(s.version()) + " is newer than this daemon reads (1)");
  if (s.data_model().profile().empty() || s.data_model().pointer_size() == 0)
    return fail("the sidecar has no data model");
  return s;
}

Status ExportTypeArchive(const TypeArchiveContext &c, const pb::ExportTypeArchiveRequest &req,
                         pb::ExportTypeArchiveResponse &resp) {
  pb::TypeArchiveScope scope = req.scope();
  if (scope == pb::TYPE_ARCHIVE_SCOPE_UNSPECIFIED)
    scope = !req.keys().empty() || !req.hashes().empty() ? pb::TYPE_ARCHIVE_SCOPE_SELECTED
            : !req.category().empty()                    ? pb::TYPE_ARCHIVE_SCOPE_CATEGORY
                                                         : pb::TYPE_ARCHIVE_SCOPE_USER;
  if (req.keys_size() + req.hashes_size() > 100000) return Error(StatusCode::kInvalidArgument, "more than 100000 types");

  types::TypeStore store;
  ProgramTypes program(c.names, c.closure, store);
  // The program's names (its own and bound; not the library archive's).
  std::set<std::string> keys;
  for (const auto &e : c.names.types)
    if (!e.library) keys.insert(e.key);
  for (const auto &[key, hash] : c.names.bindings) keys.insert(key);

  std::vector<TypeId> roots;
  auto add_key = [&](const std::string &key) -> Status {
    const std::string hash = program.definition(key);
    if (hash.empty()) return Error(StatusCode::kNotFound, "the program has no " + key);
    auto id = program.intern(hash);
    if (!id) return Error(StatusCode::kNotFound, "the program's " + key + " (" + hash + ") can't be read");
    roots.push_back(*id);
    return Status::Ok();
  };
  switch (scope) {
    case pb::TYPE_ARCHIVE_SCOPE_SELECTED:
      for (const std::string &key : req.keys()) {
        if (!IsNamedTypeKey(key))
          return Error(StatusCode::kInvalidArgument, "\"" + key.substr(0, 64) + "\" isn't a named type key (\"struct cJSON\")");
        if (Status st = add_key(key); !st.ok()) return st;
      }
      for (const std::string &hash : req.hashes()) {
        auto id = program.intern(hash);
        if (!id) return Error(StatusCode::kNotFound, "the program has no type " + hash.substr(0, 64));
        if (types::named_key(store, *id).empty())
          return Error(StatusCode::kInvalidArgument, "type " + hash + " isn't a named struct, union, enum or typedef");
        roots.push_back(*id);
      }
      break;
    case pb::TYPE_ARCHIVE_SCOPE_CATEGORY: {
      std::string err;
      auto want = NormalizeTypeCategory(req.category(), &err);
      if (!want) return Error(StatusCode::kInvalidArgument, "category: " + err);
      for (const std::string &key : keys) {
        auto it = c.categories.find(key);
        const std::string cat = it == c.categories.end() ? std::string() : it->second;
        if (want->empty() || cat == *want || cat.starts_with(*want + "/"))
          if (Status st = add_key(key); !st.ok()) return st;
      }
      if (roots.empty())
        return Error(StatusCode::kFailedPrecondition, "no type is filed under " + (want->empty() ? "/" : *want));
      break;
    }
    case pb::TYPE_ARCHIVE_SCOPE_USER:
      for (const auto &[key, hash] : c.names.bindings)
        if (Status st = add_key(key); !st.ok()) return st;
      if (roots.empty())
        return Error(StatusCode::kFailedPrecondition,
                     "no type of this program was made, edited or imported in revkit (scope ALL exports the debug "
                     "info's too)");
      break;
    case pb::TYPE_ARCHIVE_SCOPE_ALL:
      for (const std::string &key : keys)
        if (Status st = add_key(key); !st.ok()) return st;
      if (roots.empty()) return Error(StatusCode::kFailedPrecondition, "the program has no named types");
      break;
    default: return Error(StatusCode::kInvalidArgument, "unknown scope");
  }

  // The origin: an archive's import keeps the archive's (its provenance
  // version), so exporting what an archive brought gives the same files.
  cparse::ArchiveOptions ao;
  ao.profile = ProgramProfile(c.program);
  const bool any_binding = c.binding && !c.names.bindings.empty();
  ao.name = cparse::archive_stem(!req.name().empty() ? req.name() : any_binding ? "types" : c.program_name);
  cparse::Archive a = cparse::write_archive(store, roots, ao);
  std::optional<std::string> origin;
  bool mixed = false;
  for (const auto &e : a.entries) {
    if (!any_binding) break;
    const auto prov = c.binding(e.key);
    if (!prov) continue;
    if (prov->kind() != pb::PROVENANCE_KIND_IMPORT || prov->id() != kArchiveImporter || prov->version().empty() ||
        (origin && *origin != prov->version())) {
      mixed = true;
      break;
    }
    origin = prov->version();
  }
  const std::string from = origin && !mixed ? *origin : c.program_name;
  if (req.name().empty() && cparse::archive_stem(from) != ao.name) {
    ao.name = cparse::archive_stem(from);
    a = cparse::write_archive(store, roots, ao);
  }

  pb::TypeArchiveSidecar &s = *resp.mutable_archive();
  s.set_format("revkit-type-archive");
  s.set_version(1);
  s.set_name(ao.name);
  s.set_header(ao.name + ".h");
  s.set_header_sha256(Sha256Hex(a.header));
  *s.mutable_data_model() = DataModelOf(ao.profile);
  s.mutable_provenance()->set_generator("revkit");
  s.mutable_provenance()->set_origin(from);
  for (const auto &e : a.entries) {
    auto *t = s.add_types();
    t->set_key(e.key);
    t->set_hash(e.hash);
    t->set_size(e.size);
    t->set_line(e.line);
    if (auto it = c.categories.find(e.key); it != c.categories.end()) t->set_category(it->second);
    t->set_form(e.form);
    if (e.source_hash != e.hash) t->set_source_hash(e.source_hash);
  }
  google::protobuf::util::JsonPrintOptions o;
  o.add_whitespace = true;
  o.preserve_proto_field_names = true;
  std::string json;
  if (auto st = google::protobuf::util::MessageToJsonString(s, &json, o); !st.ok())
    return Error(StatusCode::kInternal, "sidecar: " + std::string(st.message()));
  if (!json.ends_with('\n')) json += '\n';
  resp.set_header(std::move(a.header));
  resp.set_sidecar(std::move(json));
  resp.set_header_name(ao.name + ".h");
  resp.set_sidecar_name(ao.name + ".json");
  for (std::string &n : a.notes) resp.add_notes(std::move(n));
  resp.set_mismatches(static_cast<std::uint32_t>(a.mismatches));
  return Status::Ok();
}

}  // namespace revkit::backend
