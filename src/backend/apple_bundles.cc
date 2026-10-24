#include "apple_bundles.h"

#include <algorithm>
#include <cmath>
#include <functional>
#include <map>
#include <set>

namespace revkit::backend {

namespace {

using api::Error;
using api::Status;
using api::StatusCode;
using container::Kind;
using container::Session;

constexpr std::uint64_t kMaxPlistBytes = 64ull << 20;
constexpr std::uint64_t kMaxInfoPlistBytes = 8ull << 20;
constexpr std::uint64_t kMaxPlistTotal = 64ull << 20;
constexpr std::uint64_t kMaxSignatureBytes = 64ull << 20;
constexpr std::uint64_t kMaxProfileBytes = 4ull << 20;
constexpr std::size_t kMaxNested = 256;
constexpr std::size_t kMaxInterfaceFiles = 2000;
constexpr std::size_t kMaxWalk = 50000;

void SetTime(double absolute, google::protobuf::Timestamp *out) {
  if (!std::isfinite(absolute)) return;
  const double unix_time = absolute + apple::kAbsoluteTimeEpoch;
  const double secs = std::floor(unix_time);
  if (secs < -62135596800.0 || secs > 253402300799.0) return;
  out->set_seconds(static_cast<std::int64_t>(secs));
  out->set_nanos(static_cast<std::int32_t>(std::min(999999999.0, (unix_time - secs) * 1e9)));
}

void FillCert(const apple::Certificate &c, pb::SigningCertificate *o) {
  o->set_subject(c.subject);
  o->set_common_name(c.common_name);
  o->set_organizational_unit(c.organizational_unit);
  o->set_issuer(c.issuer);
  o->set_not_before(c.not_before);
  o->set_not_after(c.not_after);
}

}  // namespace

void FillPlist(const apple::Value &v, pb::PlistValue *out, PlistBudget &budget) {
  using T = apple::Value::Type;
  switch (v.type) {
    case T::null: out->set_null_value(true); break;
    case T::boolean: out->set_bool_value(v.boolean); break;
    case T::integer:
      if (v.big) out->set_unsigned_value(v.unsigned_value);
      else out->set_integer_value(v.integer);
      break;
    case T::real: out->set_real_value(v.real); break;
    case T::date: SetTime(v.real, out->mutable_date_value()); break;
    case T::data:
      out->set_data_value(v.bytes.substr(0, budget.max_data));
      out->set_data_size(v.bytes.size());
      break;
    case T::string: out->set_string_value(v.bytes); break;
    case T::uid: out->set_uid_value(v.uid); break;
    case T::array: {
      auto *a = out->mutable_array_value();
      std::uint32_t omitted = 0;
      for (const apple::Value &x : v.array) {
        if (budget.values_left == 0) {
          ++omitted;
          continue;
        }
        --budget.values_left;
        FillPlist(x, a->add_items(), budget);
      }
      if (omitted) {
        out->set_omitted(omitted);
        budget.truncated = true;
      }
      break;
    }
    case T::dict: {
      auto *d = out->mutable_dict_value();
      std::uint32_t omitted = 0;
      for (const apple::DictEntry &e : v.dict) {
        if (budget.values_left == 0) {
          ++omitted;
          continue;
        }
        --budget.values_left;
        auto *entry = d->add_entries();
        entry->set_key(e.key);
        FillPlist(e.value, entry->mutable_value(), budget);
      }
      if (omitted) {
        out->set_omitted(omitted);
        budget.truncated = true;
      }
      break;
    }
  }
}

void FillCodeSignature(const apple::CodeSignature &sig, pb::CodeSignature *out) {
  for (const apple::CodeDirectory &cd : sig.code_directories) {
    pb::CodeDirectory *o = out->add_code_directories();
    o->set_version(cd.version);
    o->set_flags(cd.flags);
    for (const auto &f : cd.flag_names) o->add_flag_names(f);
    o->set_identifier(cd.identifier);
    o->set_team_id(cd.team_id);
    o->set_hash_type(cd.hash_name);
    o->set_hash_size(cd.hash_size);
    o->set_page_size(cd.page_size);
    o->set_code_slots(cd.code_slots);
    o->set_special_slots(cd.special_slots);
    o->set_code_limit(cd.code_limit);
    o->set_platform(cd.platform);
    for (const auto &h : cd.special_hashes) o->add_special_hashes(h);
    o->set_exec_seg_base(cd.exec_seg_base);
    o->set_exec_seg_limit(cd.exec_seg_limit);
    o->set_exec_seg_flags(cd.exec_seg_flags);
    for (const auto &f : cd.exec_seg_flag_names) o->add_exec_seg_flag_names(f);
    o->set_runtime_version(cd.runtime_version);
    o->set_cdhash(cd.cdhash);
    o->set_alternate(cd.alternate);
    o->set_slot(cd.slot);
  }
  if (const apple::Value *e = apple::entitlements_of(sig)) {
    PlistBudget b;
    FillPlist(*e, out->mutable_entitlements(), b);
  }
  out->set_entitlements_xml(sig.entitlements_xml.substr(0, 1u << 20));
  out->set_has_der_entitlements(sig.has_der_entitlements);
  for (const apple::Requirement &r : sig.requirements) {
    pb::CodeRequirement *o = out->add_requirements();
    o->set_type(r.type);
    o->set_type_name(r.type_name);
    o->set_text(r.text);
  }
  out->set_has_cms(sig.has_cms);
  out->set_cms_size(sig.cms_size);
  for (const apple::Certificate &c : sig.certificates) FillCert(c, out->add_certificates());
  out->set_adhoc(sig.adhoc);
  for (const auto &b : sig.blobs) {
    pb::CodeSignatureBlob *o = out->add_blobs();
    o->set_slot(b.slot);
    o->set_magic(b.magic);
    o->set_offset(b.offset);
    o->set_length(b.length);
  }
  for (const auto &w : sig.warnings) out->add_warnings(w);
}

void FillProvisioningProfile(const apple::ProvisioningProfile &p, pb::ProvisioningProfile *out) {
  out->set_name(p.name);
  out->set_uuid(p.uuid);
  out->set_app_id_name(p.app_id_name);
  out->set_application_identifier(p.application_identifier);
  for (const auto &t : p.team_identifiers) out->add_team_identifiers(t);
  out->set_team_name(p.team_name);
  for (const auto &x : p.platforms) out->add_platforms(x);
  if (p.creation_date) SetTime(*p.creation_date, out->mutable_creation_date());
  if (p.expiration_date) SetTime(*p.expiration_date, out->mutable_expiration_date());
  out->set_provisioned_devices(static_cast<std::uint32_t>(p.provisioned_devices));
  out->set_provisions_all_devices(p.provisions_all_devices);
  out->set_get_task_allow(p.get_task_allow);
  out->set_kind(p.kind);
  if (p.entitlements) {
    PlistBudget b;
    FillPlist(*p.entitlements, out->mutable_entitlements(), b);
  }
  out->set_developer_certificates(static_cast<std::uint32_t>(p.developer_certificates));
  for (const auto &c : p.signer_certificates) FillCert(c, out->add_signer_certificates());
  PlistBudget b;
  FillPlist(p.plist, out->mutable_plist(), b);
  for (const auto &w : p.warnings) out->add_warnings(w);
}

void FillBundleInfo(const apple::BundleInfo &b, pb::AppleBundleInfo *o) {
  o->set_identifier(b.identifier);
  o->set_name(b.name);
  o->set_display_name(b.display_name);
  o->set_executable(b.executable);
  o->set_version(b.version);
  o->set_short_version(b.short_version);
  o->set_package_type(b.package_type);
  o->set_minimum_os(b.minimum_os);
  for (const auto &x : b.supported_platforms) o->add_supported_platforms(x);
  for (const auto &x : b.device_families) o->add_device_families(x);
  for (const auto &x : b.url_schemes) o->add_url_schemes(x);
  for (const auto &x : b.queried_url_schemes) o->add_queried_url_schemes(x);
  for (const auto &d : b.document_types) {
    auto *t = o->add_document_types();
    t->set_name(d.name);
    t->set_role(d.role);
    t->set_handler_rank(d.handler_rank);
    for (const auto &x : d.content_types) t->add_content_types(x);
    for (const auto &x : d.extensions) t->add_extensions(x);
  }
  for (const auto &x : b.background_modes) o->add_background_modes(x);
  for (const auto &u : b.usage_descriptions) {
    auto *x = o->add_usage_descriptions();
    x->set_key(u.key);
    x->set_text(u.text);
  }
  for (const auto &[from, to] : {std::pair{&b.exported_types, o->mutable_exported_types()},
                                 std::pair{&b.imported_types, o->mutable_imported_types()}})
    for (const auto &d : *from) {
      auto *t = to->Add();
      t->set_identifier(d.identifier);
      t->set_description(d.description);
      for (const auto &x : d.conforms_to) t->add_conforms_to(x);
      for (const auto &x : d.extensions) t->add_extensions(x);
      for (const auto &x : d.mime_types) t->add_mime_types(x);
    }
  for (const auto &x : b.required_capabilities) o->add_required_capabilities(x);
  o->set_extension_point(b.extension_point);
  o->set_principal_class(b.principal_class);
  o->set_main_storyboard(b.main_storyboard);
  o->set_main_nib(b.main_nib);
  o->set_launch_storyboard(b.launch_storyboard);
  o->set_allows_arbitrary_loads(b.allows_arbitrary_loads);
  for (const auto &x : b.ats_exception_domains) o->add_ats_exception_domains(x);
  o->set_sdk(b.sdk);
  o->set_xcode(b.xcode);
  o->set_build_machine_os(b.build_machine_os);
}

namespace {

std::optional<std::uint32_t> ChildNamed(const container::FileSystem &fs, std::uint32_t dir, std::string_view name) {
  for (std::uint32_t c : fs.entry(dir).children)
    if (fs.entry(c).name == name) return c;
  return std::nullopt;
}

}  // namespace

std::string BundleKindOf(const container::FileSystem &fs, std::uint32_t entry) {
  const container::Entry &e = fs.entry(entry);
  if (e.kind != Kind::directory || entry == 0) return "";
  std::string kind = apple::bundle_kind(e.name);
  if (kind.empty()) return "";
  for (const char *marker : {"Info.plist", "Contents", "Versions", "Resources"})
    if (ChildNamed(fs, entry, marker)) return kind;
  // A compiled storyboard or a nib directory holds nibs.
  if (kind == "storyboardc") return kind;
  return "";
}

std::optional<apple::CodeSignature> ReadCodeSignature(
    const std::function<std::vector<std::byte>(std::uint64_t, std::size_t)> &read, std::uint64_t file_size,
    apple::SignatureRange *where) {
  auto range = apple::find_code_signature(read, file_size);
  if (!range || range->size == 0) return std::nullopt;
  if (where) *where = *range;
  apple::CodeSignature sig;
  if (range->size > kMaxSignatureBytes) {
    sig.warnings.push_back("the code signature is larger than 64 MiB: not read");
    return sig;
  }
  const std::vector<std::byte> blob = read(range->offset, range->size);
  try {
    return apple::parse_code_signature(blob);
  } catch (const apple::Error &e) {
    sig.warnings.push_back(e.what());
    return sig;
  }
}

namespace {

// One file system's view of a bundle being described.
struct Walker {
  Session &s;
  std::function<bool()> cancelled;
  // Info.plist bytes read for one request: a hostile bundle can nest 256
  // bundles with large plists.
  std::uint64_t plist_bytes = 0;

  Session::Node node(const Session::Node &in, std::uint32_t idx) const {
    return Session::Node{in.fs, idx, in.prefix + in.fs->path_of(idx), in.prefix, in.depth};
  }
  // `rel` below `dir`, links followed inside the layer.
  std::optional<Session::Node> at(const Session::Node &dir, std::initializer_list<std::string_view> rel) const {
    std::vector<std::string> comps = dir.fs->components_of(dir.entry);
    for (std::string_view r : rel) comps.emplace_back(r);
    try {
      if (auto f = dir.fs->find(comps, true)) return node(dir, *f);
    } catch (const container::Error &) {
    }
    return std::nullopt;
  }
  bool is_file(const std::optional<Session::Node> &n) const { return n && n->fs->entry(n->entry).kind == Kind::file; }
  bool is_dir(const std::optional<Session::Node> &n) const { return n && n->fs->entry(n->entry).kind == Kind::directory; }

  std::vector<std::byte> read_all(const Session::Node &n, std::uint64_t max, const char *what) {
    auto src = s.open_file(n.path, cancelled);
    if (src->size() > max)
      throw container::LimitError(std::string(what) + " is larger than " + std::to_string(max >> 20) + " MiB");
    return src->read_exact(0, src->size(), what);
  }

  std::optional<apple::Value> plist(const Session::Node &n, std::vector<std::string> &warnings) {
    try {
      const std::uint64_t size = n.fs->entry(n.entry).size;
      if (size != UINT64_MAX && plist_bytes + size > kMaxPlistTotal) {
        warnings.push_back(n.path + ": not read (the request's Info.plists pass 64 MiB)");
        return std::nullopt;
      }
      const auto bytes = read_all(n, kMaxInfoPlistBytes, "Info.plist");
      plist_bytes += bytes.size();
      if (plist_bytes > kMaxPlistTotal) {
        warnings.push_back(n.path + ": not read (the request's Info.plists pass 64 MiB)");
        return std::nullopt;
      }
      return apple::parse(bytes).root;
    } catch (const std::exception &e) {
      warnings.push_back(n.path + ": " + e.what());
      return std::nullopt;
    }
  }

  // A bundle directory's layout: its content directory and its Info.plist.
  struct Layout {
    std::string name;  // "shallow", "deep", "versioned"
    Session::Node content;
    std::optional<Session::Node> info;
  };
  Layout layout(const Session::Node &dir) {
    Layout l{"shallow", dir, std::nullopt};
    if (auto c = at(dir, {"Contents"}); is_dir(c)) {
      l.name = "deep";
      l.content = *c;
      l.info = at(*c, {"Info.plist"});
    } else if (auto v = at(dir, {"Versions"}); is_dir(v)) {
      l.name = "versioned";
      // Versions/Current, else the only version.
      std::optional<Session::Node> cur = at(*v, {"Current"});
      if (!is_dir(cur)) {
        cur.reset();
        for (std::uint32_t c : v->fs->entry(v->entry).children)
          if (v->fs->entry(c).kind == Kind::directory) {
            if (cur) {
              cur.reset();
              break;
            }
            cur = node(*v, c);
          }
      }
      if (cur) {
        l.content = *cur;
        l.info = at(*cur, {"Resources", "Info.plist"});
      }
    } else {
      l.info = at(dir, {"Info.plist"});
      if (!is_file(l.info)) l.info = at(dir, {"Resources", "Info.plist"});
    }
    if (!is_file(l.info)) l.info.reset();
    return l;
  }

  std::optional<Session::Node> executable(const Layout &l, const Session::Node &dir, const apple::BundleInfo &info) {
    std::string exe = info.executable;
    if (exe.empty()) {
      // A bundle without CFBundleExecutable: its name without the extension.
      const std::string &n = dir.fs->entry(dir.entry).name;
      exe = n.substr(0, n.rfind('.'));
    }
    if (exe.empty() || exe.find('/') != std::string::npos) return std::nullopt;
    std::optional<Session::Node> f = l.name == "deep" ? at(l.content, {"MacOS", exe}) : at(l.content, {exe});
    return is_file(f) ? f : std::nullopt;
  }

  // What a bundle is to its parent, by where it sits.
  static std::string role(const std::string &kind, const std::string &parent_dir, const std::string &grand) {
    if (kind == "framework") return "framework";
    if (kind == "appex") return "app-extension";
    if (kind == "xpc") return "xpc-service";
    if (kind == "app") {
      if (parent_dir == "Watch") return "watch-app";
      if (parent_dir == "LoginItems" && grand == "Library") return "login-item";
      if (parent_dir == "Helpers") return "helper-application";
      return "nested-application";
    }
    if (parent_dir == "PlugIns" || kind == "plugin") return "plug-in";
    if (parent_dir == "Resources" || kind == "bundle") return parent_dir == "Resources" ? "resource-bundle" : "bundle";
    return kind;
  }

  // The bundles and interface files below `content`, not into the bundles
  // found (nor into links: a versioned framework's links repeat it).
  void scan(const Session::Node &content, pb::AppleBundle &out, std::vector<Session::Node> &nested,
            std::size_t &visited) {
    struct Item {
      std::uint32_t entry;
      unsigned depth;
    };
    std::vector<Item> stack{{content.entry, 0}};
    const container::FileSystem &fs = *content.fs;
    while (!stack.empty()) {
      if (cancelled && cancelled()) throw container::Error("cancelled");
      const Item it = stack.back();
      stack.pop_back();
      const container::Entry &dir = fs.entry(it.entry);
      for (auto c = dir.children.rbegin(); c != dir.children.rend(); ++c) {
        if (++visited > kMaxWalk) {
          out.add_warnings("more than " + std::to_string(kMaxWalk) + " entries: the rest weren't looked at");
          return;
        }
        const container::Entry &e = fs.entry(*c);
        const bool nib = e.name.size() > 4 && e.name.ends_with(".nib");
        if (nib && (e.kind == Kind::file || e.kind == Kind::directory)) {
          if (out.interface_files_size() < static_cast<int>(kMaxInterfaceFiles))
            out.add_interface_files(content.prefix + fs.path_of(*c));
          continue;
        }
        if (e.kind != Kind::directory) continue;
        const std::string kind = BundleKindOf(fs, *c);
        if (kind == "storyboardc") {
          if (out.interface_files_size() < static_cast<int>(kMaxInterfaceFiles))
            out.add_interface_files(content.prefix + fs.path_of(*c));
          continue;
        }
        if (!kind.empty()) {
          if (nested.size() < kMaxNested) nested.push_back(node(content, *c));
          else if (nested.size() == kMaxNested) out.add_warnings("more than 256 nested bundles: the rest left out");
          continue;
        }
        if (it.depth < 12) stack.push_back({*c, it.depth + 1});
      }
    }
  }

  void describe(const Session::Node &dir, pb::AppleBundle &out, bool with_plist) {
    out.set_path(dir.path);
    out.set_container_path(s.container_path(dir.path));
    out.set_kind(apple::bundle_kind(dir.fs->entry(dir.entry).name));
    const Layout l = layout(dir);
    out.set_layout(l.name);
    std::vector<std::string> warnings;
    apple::BundleInfo info;
    if (l.info) {
      out.set_info_plist_path(l.info->path);
      if (auto v = plist(*l.info, warnings)) {
        info = apple::bundle_info(*v);
        FillBundleInfo(info, out.mutable_info());
        if (with_plist) {
          PlistBudget b;
          FillPlist(*v, out.mutable_info_plist(), b);
        }
      }
    } else {
      warnings.push_back("no Info.plist");
    }
    // The platform: the layout says macOS; a shallow bundle is iOS's
    // (watchOS, tvOS, visionOS: CFBundleSupportedPlatforms says which).
    std::string platform = l.name == "shallow" ? "ios" : "macos";
    if (!info.supported_platforms.empty()) {
      static const std::pair<const char *, const char *> kPlatforms[] = {
          {"iPhoneOS", "ios"},         {"iPhoneSimulator", "iossimulator"}, {"MacOSX", "macos"},
          {"AppleTVOS", "tvos"},       {"WatchOS", "watchos"},             {"XROS", "visionos"},
          {"AppleTVSimulator", "tvossimulator"}, {"WatchSimulator", "watchossimulator"}};
      for (const auto &[from, to] : kPlatforms)
        if (info.supported_platforms.front() == from) platform = to;
    }
    out.set_platform(platform);
    if (auto exe = executable(l, dir, info)) {
      out.set_executable_path(exe->path);
      try {
        out.set_executable_detected(s.describe(*exe, cancelled).description);
        auto src = s.open_file(exe->path, cancelled);
        auto read = [&](std::uint64_t off, std::size_t n) {
          if (off >= src->size()) return std::vector<std::byte>();
          return src->read_exact(off, std::min<std::uint64_t>(n, src->size() - off), "the executable");
        };
        apple::SignatureRange where;
        if (auto sig = ReadCodeSignature(read, src->size(), &where)) {
          FillCodeSignature(*sig, out.mutable_code_signature());
          out.mutable_code_signature()->set_offset(where.offset);
          out.mutable_code_signature()->set_size(where.size);
        }
      } catch (const container::Error &e) {
        warnings.push_back(exe->path + ": " + e.what());
      }
    } else if (out.kind() != "storyboardc" && out.kind() != "bundle") {
      warnings.push_back(info.executable.empty() ? "no CFBundleExecutable, and no executable named as the bundle"
                                                 : "its executable " + info.executable + " is missing");
    }
    for (const auto &rel : {std::initializer_list<std::string_view>{"embedded.mobileprovision"},
                            std::initializer_list<std::string_view>{"embedded.provisionprofile"}}) {
      auto p = at(l.content, rel);
      if (!is_file(p)) continue;
      out.set_provisioning_profile_path(p->path);
      try {
        FillProvisioningProfile(apple::parse_provisioning_profile(read_all(*p, kMaxProfileBytes, "the profile")),
                                out.mutable_provisioning_profile());
      } catch (const std::exception &e) {
        warnings.push_back(p->path + ": " + e.what());
      }
      break;
    }
    if (auto cr = at(l.content, {"_CodeSignature", "CodeResources"}); is_file(cr)) out.set_code_resources_path(cr->path);
    std::vector<Session::Node> nested;
    std::size_t visited = 0;
    scan(l.content, out, nested, visited);
    for (const Session::Node &n : nested) {
      pb::AppleBundleRef *r = out.add_nested();
      r->set_path(n.path);
      const container::Entry &e = n.fs->entry(n.entry);
      r->set_kind(BundleKindOf(*n.fs, n.entry));
      const container::Entry &parent = n.fs->entry(e.parent);
      const std::string grand = e.parent != 0 ? n.fs->entry(parent.parent).name : std::string();
      r->set_role(role(r->kind(), parent.name, grand));
      const Layout nl = layout(n);
      apple::BundleInfo ni;
      if (nl.info)
        if (auto v = plist(*nl.info, warnings)) ni = apple::bundle_info(*v);
      r->set_identifier(ni.identifier);
      r->set_extension_point(ni.extension_point);
      r->set_version(ni.short_version.empty() ? ni.version : ni.short_version);
      if (auto exe = executable(nl, n, ni)) r->set_executable_path(exe->path);
    }
    for (auto &w : warnings) out.add_warnings(std::move(w));
  }

  // The .app directories a container's root (or a directory) holds:
  // Payload/*.app (an .ipa), else *.app at the top.
  std::vector<Session::Node> apps_in(const Session::Node &root) {
    std::vector<Session::Node> out;
    auto apps = [&](const Session::Node &d) {
      for (std::uint32_t c : d.fs->entry(d.entry).children)
        if (BundleKindOf(*d.fs, c) == "app") out.push_back(node(d, c));
    };
    if (auto p = at(root, {"Payload"}); is_dir(p)) apps(*p);
    if (out.empty()) apps(root);
    return out;
  }
};

}  // namespace

Status GetAppleBundle(FsSession &fss, const api::CallContext &ctx, const pb::GetAppleBundleRequest &req,
                      pb::GetAppleBundleResponse &resp) {
  return FsGuard([&]() -> Status {
    Session &s = *fss.session;
    Walker w{s, ctx.cancelled};
    Session::Node n = s.locate(req.path().empty() ? "/" : req.path(), true, ctx.cancelled);
    std::optional<Session::Node> bundle;
    std::vector<Session::Node> apps;
    if (n.fs->entry(n.entry).kind == Kind::file) {
      if (auto sub = s.mount(n, ctx.cancelled)) {
        // An .ipa (or another container holding apps); else a file inside
        // a bundle (below).
        apps = w.apps_in(Session::Node{sub, 0, n.path + "!/", n.path + "!", n.depth + 1});
        if (!apps.empty()) bundle = apps.front();
      }
    } else if (!BundleKindOf(*n.fs, n.entry).empty()) {
      bundle = n;
    } else {
      apps = w.apps_in(n);
      if (!apps.empty()) bundle = apps.front();
    }
    // A file or directory inside a bundle: the nearest one around it.
    for (std::uint32_t at = n.entry; !bundle && at != 0;) {
      at = n.fs->entry(at).parent;
      const std::string kind = BundleKindOf(*n.fs, at);
      if (!kind.empty() && kind != "storyboardc") bundle = w.node(n, at);
    }
    if (!bundle) return Error(StatusCode::kNotFound, "not an Apple bundle, nor inside one: " + n.path);
    w.describe(*bundle, *resp.mutable_bundle(), !req.skip_info_plist());
    for (const Session::Node &a : apps) {
      pb::AppleBundleRef *r = resp.add_apps();
      r->set_path(a.path);
      r->set_kind("app");
      r->set_role("app");
      const auto l = w.layout(a);
      std::vector<std::string> ignored;
      apple::BundleInfo info;
      if (l.info)
        if (auto v = w.plist(*l.info, ignored)) info = apple::bundle_info(*v);
      r->set_identifier(info.identifier);
      r->set_version(info.short_version.empty() ? info.version : info.short_version);
      if (auto exe = w.executable(l, a, info)) r->set_executable_path(exe->path);
    }
    return Status::Ok();
  });
}

Status ReadPropertyList(FsSession &fss, const api::CallContext &ctx, const pb::ReadPropertyListRequest &req,
                        pb::ReadPropertyListResponse &resp) {
  return FsGuard([&]() -> Status {
    Session &s = *fss.session;
    auto src = s.open_file(req.path(), ctx.cancelled);
    if (src->size() > kMaxPlistBytes) return Error(StatusCode::kResourceExhausted, "a property list larger than 64 MiB");
    const std::vector<std::byte> bytes = src->read_exact(0, src->size(), "the property list");
    apple::Value root;
    std::uint64_t values = 0;
    try {
      if (apple::sniff(bytes)) {
        apple::Parsed p = apple::parse(bytes);
        resp.set_format(p.format == apple::Format::binary ? "binary" : "xml");
        root = std::move(p.root);
        values = p.values;
      } else if (!bytes.empty() && bytes[0] == std::byte{0x30}) {
        apple::ProvisioningProfile p = apple::parse_provisioning_profile(bytes);
        resp.set_format("mobileprovision");
        root = std::move(p.plist);
        for (auto &w : p.warnings) resp.add_warnings(std::move(w));
      } else {
        return Error(StatusCode::kInvalidArgument, "not a property list (XML, bplist00 or a provisioning profile)");
      }
    } catch (const apple::LimitError &e) {
      return Error(StatusCode::kResourceExhausted, e.what());
    } catch (const apple::Error &e) {
      return Error(StatusCode::kInvalidArgument, e.what());
    }
    resp.set_values(values);
    resp.set_keyed_archive(apple::KeyedArchive::is_keyed_archive(root));
    PlistBudget b;
    // A keyed archive's objects resolved (api_minor 101).
    if (resp.keyed_archive() && req.resolve_keyed_archive()) root = apple::KeyedArchive(root).resolve();
    b.values_left = req.max_values() == 0 ? 20000 : std::min<std::uint32_t>(req.max_values(), 200000);
    b.max_data = req.max_data_bytes() == 0 ? 4096 : std::min<std::uint32_t>(req.max_data_bytes(), 1u << 20);
    FillPlist(root, resp.mutable_root(), b);
    resp.set_truncated(b.truncated);
    return Status::Ok();
  });
}

// ---- Interface Builder (api_minor 101) ---------------------------------------------

namespace {

constexpr std::uint64_t kMaxNibBytes = 32ull << 20;
constexpr std::uint64_t kMaxNibTotal = 256ull << 20;
constexpr std::size_t kMaxDocs = 2000;

// The file a nib directory's runtime reads: runtime.nib, else the newest
// objects-<version>.nib, else the newest keyedobjects*.nib.
std::optional<std::uint32_t> NibFileIn(const container::FileSystem &fs, std::uint32_t dir) {
  std::optional<std::uint32_t> objects, keyed;
  std::string objects_name, keyed_name;
  for (std::uint32_t c : fs.entry(dir).children) {
    const container::Entry &e = fs.entry(c);
    if (e.kind != Kind::file) continue;
    if (e.name == "runtime.nib") return c;
    if (e.name.starts_with("objects") && e.name.ends_with(".nib") && e.name > objects_name) {
      objects = c;
      objects_name = e.name;
    }
    if (e.name.starts_with("keyedobjects") && e.name.ends_with(".nib") && e.name > keyed_name) {
      keyed = c;
      keyed_name = e.name;
    }
  }
  return objects ? objects : keyed;
}

std::string Stem(const std::string &name) { return name.ends_with(".nib") ? name.substr(0, name.size() - 4) : name; }

}  // namespace

Status CollectInterfaceDocs(FsSession &fss, const api::CallContext &ctx, const std::string &path, InterfaceDocs &out) {
  return FsGuard([&]() -> Status {
    Session &s = *fss.session;
    Walker w{s, ctx.cancelled};
    Session::Node n = s.locate(path.empty() ? "/" : path, true, ctx.cancelled);
    // What to read: a nib, a storyboard, or a bundle's (an .ipa's app's).
    std::vector<Session::Node> targets;
    std::optional<Session::Node> bundle;
    const container::Entry &e = n.fs->entry(n.entry);
    const bool nib = e.name.ends_with(".nib") && (e.kind == Kind::file || e.kind == Kind::directory);
    if (nib || BundleKindOf(*n.fs, n.entry) == "storyboardc") {
      targets.push_back(n);
    } else if (e.kind == Kind::file) {
      if (auto sub = s.mount(n, ctx.cancelled)) {
        auto apps = w.apps_in(Session::Node{sub, 0, n.path + "!/", n.path + "!", n.depth + 1});
        if (!apps.empty()) bundle = apps.front();
      }
      if (!bundle) return Error(StatusCode::kInvalidArgument, "not a nib, a storyboard or a bundle: " + n.path);
    } else if (!BundleKindOf(*n.fs, n.entry).empty()) {
      bundle = n;
    } else {
      auto apps = w.apps_in(n);
      if (apps.empty()) return Error(StatusCode::kNotFound, "no nib, storyboard or bundle at " + n.path);
      bundle = apps.front();
    }
    if (bundle) {
      pb::AppleBundle b;
      w.describe(*bundle, b, false);
      out.executable_path = b.executable_path();
      if (!out.executable_path.empty()) out.executable_container_path = s.container_path(out.executable_path);
      for (const std::string &f : b.interface_files()) targets.push_back(s.locate(f, true, ctx.cancelled));
    }
    std::uint64_t total = 0;
    auto read = [&](const Session::Node &file, const std::string &storyboard) {
      if (out.docs.size() >= kMaxDocs) {
        if (out.docs.size() == kMaxDocs) out.warnings.push_back("more than 2000 nibs: the rest weren't read");
        return;
      }
      Session::Node f = file;
      if (f.fs->entry(f.entry).kind == Kind::directory) {
        auto inner = NibFileIn(*f.fs, f.entry);
        if (!inner) {
          out.warnings.push_back(f.path + ": no runtime.nib, objects or keyedobjects nib in it");
          return;
        }
        f = w.node(f, *inner);
      }
      InterfaceDoc d;
      d.path = f.path;
      d.storyboard = storyboard;
      try {
        auto src = s.open_file(f.path, ctx.cancelled);
        if (src->size() > kMaxNibBytes || total + src->size() > kMaxNibTotal) {
          out.warnings.push_back(f.path + ": larger than the nibs' limits (32 MiB each, 256 MiB in all)");
          return;
        }
        total += src->size();
        d.doc = apple::read_interface_builder(src->read_exact(0, src->size(), "the nib"));
      } catch (const std::exception &x) {
        out.warnings.push_back(f.path + ": " + x.what());
        return;
      }
      // A keyed archive's File's Owner names its class.
      for (const apple::IbObject &o : d.doc.objects)
        if (o.placeholder == "files-owner" && d.doc.format == "nib:keyed" && o.custom_class != o.class_name) {
          d.owner_class = o.custom_class;
          d.owner_from = "archive";
        }
      out.docs.push_back(std::move(d));
    };
    for (const Session::Node &t : targets) {
      if (ctx.cancelled()) return Error(StatusCode::kCancelled, "cancelled");
      if (BundleKindOf(*t.fs, t.entry) == "storyboardc") {
        const std::size_t first = out.docs.size();
        for (std::uint32_t c : t.fs->entry(t.entry).children)
          if (t.fs->entry(c).name.ends_with(".nib")) read(w.node(t, c), t.path);
        // A scene's controller names its view's nib (UINibName): that
        // nib's File's Owner is the controller.
        std::map<std::string, std::string> owners;
        for (std::size_t i = first; i < out.docs.size(); ++i)
          for (const apple::IbObject &o : out.docs[i].doc.objects)
            if (!o.nib_name.empty()) owners.emplace(o.nib_name, o.custom_class);
        for (std::size_t i = first; i < out.docs.size(); ++i) {
          // The nib's name: the file, or its nib directory.
          std::string p = out.docs[i].path.substr(t.path.size() + 1);
          const std::string top = Stem(p.substr(0, p.find('/')));
          if (auto it = owners.find(top); it != owners.end()) {
            out.docs[i].owner_class = it->second;
            out.docs[i].owner_from = "storyboard";
          }
        }
      } else {
        read(t, "");
      }
    }
    return Status::Ok();
  });
}

namespace {

// An Objective-C program's instance methods by class and selector.
class MethodIndex {
 public:
  explicit MethodIndex(const objc::Metadata &md) {
    for (const objc::Class &c : md.classes) {
      classes_.emplace(c.name, &c);
      if (c.instance_methods)
        for (const objc::Method &m : c.instance_methods->methods) add(c.name, "", m);
    }
    for (const objc::Category &k : md.categories) {
      known_.insert(k.class_name);
      if (k.instance_methods)
        for (const objc::Method &m : k.instance_methods->methods) add(k.class_name, k.name, m);
    }
    for (const auto &[name, _] : classes_) known_.insert(name);
  }
  struct Hit {
    std::string cls, category;
    const objc::Method *method = nullptr;
  };
  bool known(const std::string &cls) const { return known_.contains(cls); }
  // `sel` from `cls` up its superclass chain (in the program).
  std::optional<Hit> find(std::string cls, const std::string &sel) const {
    for (int depth = 0; depth < 64 && !cls.empty(); ++depth) {
      auto range = by_selector_.equal_range(sel);
      for (auto it = range.first; it != range.second; ++it)
        if (it->second.cls == cls) return it->second;
      auto c = classes_.find(cls);
      if (c == classes_.end()) break;
      cls = c->second->superclass;
    }
    return std::nullopt;
  }
  std::vector<Hit> implementors(const std::string &sel) const {
    std::vector<Hit> out;
    auto range = by_selector_.equal_range(sel);
    for (auto it = range.first; it != range.second; ++it) out.push_back(it->second);
    return out;
  }

 private:
  void add(const std::string &cls, const std::string &category, const objc::Method &m) {
    if (!m.class_method) by_selector_.emplace(m.selector, Hit{cls, category, &m});
  }
  std::map<std::string, const objc::Class *> classes_;
  std::multimap<std::string, Hit> by_selector_;
  std::set<std::string> known_;
};

void FillDocument(const InterfaceDoc &d, bool full, pb::InterfaceDocument *o) {
  o->set_path(d.path);
  o->set_format(d.doc.format);
  o->set_storyboard(d.storyboard);
  o->set_owner_class(d.owner_class);
  o->set_owner_class_from(d.owner_from);
  for (const auto &w : d.doc.warnings) o->add_warnings(w);
  if (!full) return;
  for (const apple::IbObject &x : d.doc.objects) {
    pb::InterfaceObject *p = o->add_objects();
    p->set_id(x.id);
    p->set_class_name(x.class_name);
    p->set_custom_class(x.custom_class);
    p->set_original_class(x.original_class);
    p->set_placeholder(x.placeholder);
    p->set_label(x.label);
    if (x.parent) {
      p->set_parent(*x.parent);
      p->set_has_parent(true);
    }
    p->set_nib_name(x.nib_name);
    p->set_storyboard_identifier(x.storyboard_identifier);
  }
  for (const apple::IbConnection &c : d.doc.connections) {
    pb::InterfaceConnection *p = o->add_connections();
    p->set_kind(c.kind == apple::IbConnection::Kind::action ? "action" : "outlet");
    p->set_id(c.id);
    p->set_label(c.label);
    if (c.source) {
      p->set_source(*c.source);
      p->set_has_source(true);
    }
    if (c.destination) {
      p->set_destination(*c.destination);
      p->set_has_destination(true);
    }
    p->set_event_mask(c.event_mask);
    for (const auto &e : c.events) p->add_events(e);
  }
}

}  // namespace

void ResolveUiActions(InterfaceDocs &docs, const objc::Metadata *md, const std::function<pb::Address(std::uint64_t)> &address,
                      const std::function<std::string(std::uint64_t)> &name, bool include_documents,
                      pb::ListUiActionsResponse &resp) {
  std::optional<MethodIndex> index;
  if (md) index.emplace(*md);
  for (InterfaceDoc &d : docs.docs) {
    // A standalone nib named as a class of the program: UIKit's default
    // nib name for a view controller is its class's.
    if (d.owner_class.empty() && d.storyboard.empty() && index) {
      std::string p = d.path.substr(d.path.find_last_of('/') + 1);
      std::string stem = Stem(p);
      if (p == "runtime.nib" || p.starts_with("objects") || p.starts_with("keyedobjects")) {
        const std::string dir = d.path.substr(0, d.path.find_last_of('/'));
        stem = Stem(dir.substr(dir.find_last_of('/') + 1));
      }
      if (index->known(stem)) {
        d.owner_class = stem;
        d.owner_from = "nib-name";
      }
    }
    FillDocument(d, include_documents, resp.add_documents());
    auto obj = [&](std::optional<std::uint32_t> id) { return id ? d.doc.object(*id) : nullptr; };
    for (const apple::IbConnection &c : d.doc.connections) {
      const apple::IbObject *src = obj(c.source), *dst = obj(c.destination);
      if (c.kind == apple::IbConnection::Kind::outlet) {
        pb::UiOutlet *o = resp.add_outlets();
        o->set_document(d.path);
        o->set_source_class(src && src->placeholder == "files-owner" && !d.owner_class.empty() ? d.owner_class
                            : src                                                             ? src->custom_class
                                                                                              : "");
        o->set_name(c.label);
        if (dst) {
          o->set_destination_class(dst->custom_class);
          o->set_destination_label(dst->label);
        }
        continue;
      }
      pb::UiAction *a = resp.add_actions();
      a->set_document(d.path);
      a->set_storyboard(d.storyboard);
      if (src) {
        a->set_control(src->id);
        a->set_control_class(src->custom_class);
        a->set_control_label(src->label);
      }
      for (const auto &e : c.events) a->add_events(e);
      a->set_event_mask(c.event_mask);
      a->set_selector(c.label);
      std::string cls, from;
      if (!dst) {
        a->set_target("");
      } else if (dst->placeholder == "files-owner") {
        a->set_target("files-owner");
        cls = d.owner_class;
        from = d.owner_from;
      } else if (dst->placeholder == "first-responder") {
        a->set_target("first-responder");
      } else {
        a->set_target("object");
        cls = dst->custom_class;
        from = "object";
      }
      a->set_target_class(cls);
      a->set_target_class_from(from);
      if (!index) {
        a->set_resolution("no-program");
        continue;
      }
      auto take = [&](const MethodIndex::Hit &h, const char *resolution) {
        a->set_resolution(resolution);
        a->set_method(objc::method_name(h.cls, h.category, *h.method));
        a->set_implemented_by(h.cls);
        if (h.method->imp) {
          *a->mutable_implementation() = address(h.method->imp);
          a->set_function_name(name(h.method->imp));
        }
      };
      if (!cls.empty()) {
        if (auto h = index->find(cls, c.label)) take(*h, "resolved");
        else a->set_resolution(index->known(cls) ? "unresolved" : "external");
        continue;
      }
      const auto hits = index->implementors(c.label);
      if (hits.size() == 1) {
        take(hits[0], "resolved-by-selector");
      } else if (hits.empty()) {
        a->set_resolution("unresolved");
      } else {
        a->set_resolution("ambiguous");
        for (std::size_t i = 0; i < hits.size() && i < 16; ++i)
          a->add_candidates(objc::method_name(hits[i].cls, hits[i].category, *hits[i].method));
      }
    }
  }
  for (auto &w : docs.warnings) resp.add_warnings(std::move(w));
}

}  // namespace revkit::backend
