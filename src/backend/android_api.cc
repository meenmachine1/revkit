// FileSystemService's Android calls (api_minor 98, feature "android";
// docs/android.md): an APK in a file system session read through
// revkit::android, its members through the session (within its limits).
#include "android_api.h"

#include "revkit/android/apk_layer.hh"

#include <algorithm>
#include <cctype>
#include <set>

namespace revkit::backend {

namespace {

using api::Error;
using api::Status;
using api::StatusCode;
namespace an = ::revkit::android;

void FillManifest(const an::Manifest &m, pb::AndroidManifest *out) {
  out->set_package(m.package);
  if (m.version_code) out->set_version_code(*m.version_code);
  out->set_version_name(m.version_name);
  if (m.min_sdk) out->set_min_sdk(*m.min_sdk);
  if (m.target_sdk) out->set_target_sdk(*m.target_sdk);
  if (m.max_sdk) out->set_max_sdk(*m.max_sdk);
  if (m.compile_sdk) out->set_compile_sdk(*m.compile_sdk);
  out->set_compile_sdk_codename(m.compile_sdk_codename);
  if (m.platform_build_version_code) out->set_platform_build_version_code(*m.platform_build_version_code);
  out->set_platform_build_version_name(m.platform_build_version_name);
  out->set_install_location(m.install_location);
  out->set_shared_user_id(m.shared_user_id);
  for (const an::Permission &p : m.uses_permissions) {
    auto *x = out->add_uses_permissions();
    x->set_name(p.name);
    if (p.max_sdk) x->set_max_sdk(*p.max_sdk);
  }
  for (const an::Permission &p : m.permissions) {
    auto *x = out->add_permissions();
    x->set_name(p.name);
    x->set_protection_level(p.protection_level);
  }
  for (const std::string &s : m.uses_features) out->add_uses_features(s);
  for (const std::string &s : m.uses_libraries) out->add_uses_libraries(s);
  for (const std::string &s : m.queries_packages) out->add_queries_packages(s);
  out->set_application_class(m.application_class);
  out->set_label(m.label);
  out->set_icon(m.icon);
  out->set_theme(m.theme);
  out->set_process(m.process);
  out->set_app_component_factory(m.app_component_factory);
  if (m.debuggable) out->set_debuggable(*m.debuggable);
  if (m.allow_backup) out->set_allow_backup(*m.allow_backup);
  if (m.uses_cleartext_traffic) out->set_uses_cleartext_traffic(*m.uses_cleartext_traffic);
  if (m.extract_native_libs) out->set_extract_native_libs(*m.extract_native_libs);
  if (m.test_only) out->set_test_only(*m.test_only);
  if (m.large_heap) out->set_large_heap(*m.large_heap);
  if (m.has_code) out->set_has_code(*m.has_code);
  if (m.request_legacy_external_storage) out->set_request_legacy_external_storage(*m.request_legacy_external_storage);
  out->set_network_security_config(m.network_security_config);
  out->set_network_security_config_file(m.network_security_config_file);
  out->set_full_backup_content(m.full_backup_content);
  out->set_data_extraction_rules(m.data_extraction_rules);
  for (const an::Component &c : m.components) {
    auto *x = out->add_components();
    x->set_kind(c.kind);
    x->set_name(c.name);
    x->set_exported(c.exported);
    x->set_exported_explicit(c.exported_explicit);
    if (c.enabled) x->set_enabled(*c.enabled);
    x->set_permission(c.permission);
    x->set_process(c.process);
    x->set_authorities(c.authorities);
    x->set_read_permission(c.read_permission);
    x->set_write_permission(c.write_permission);
    x->set_grant_uri_permissions(c.grant_uri_permissions);
    x->set_target_activity(c.target_activity);
    x->set_launcher(c.launcher);
    for (const an::IntentFilter &f : c.intent_filters) {
      auto *y = x->add_intent_filters();
      for (const std::string &s : f.actions) y->add_actions(s);
      for (const std::string &s : f.categories) y->add_categories(s);
      for (const an::IntentData &d : f.data) {
        auto *z = y->add_data();
        z->set_scheme(d.scheme);
        z->set_host(d.host);
        z->set_port(d.port);
        z->set_path(d.path);
        z->set_path_prefix(d.path_prefix);
        z->set_path_pattern(d.path_pattern);
        z->set_mime_type(d.mime_type);
      }
      if (f.priority) y->set_priority(*f.priority);
      y->set_auto_verify(f.auto_verify);
    }
  }
  for (const auto &[k, v] : m.meta_data) (*out->mutable_meta_data())[k] = v;
}

void FillResources(const an::ResourceTable &t, pb::AndroidResourcesSummary *out) {
  out->set_present(true);
  out->set_strings(static_cast<std::uint32_t>(t.strings.strings.size()));
  out->set_values(static_cast<std::uint32_t>(t.entry_count()));
  for (const an::ResourcePackage &p : t.packages) {
    auto *x = out->add_packages();
    x->set_id(p.id);
    x->set_name(p.name);
    for (const an::ResourceType &ty : p.types) {
      auto *y = x->add_types();
      y->set_name(ty.name);
      y->set_id(ty.id);
      std::set<std::uint32_t> ids;
      for (const an::ResourceEntry &e : ty.entries) ids.insert(e.id);
      y->set_entries(static_cast<std::uint32_t>(ids.size()));
      y->set_values(static_cast<std::uint32_t>(ty.entries.size()));
      for (const std::string &c : ty.configs) y->add_configs(c);
    }
  }
  for (const std::string &w : t.warnings) out->add_warnings(w);
}

std::string Lower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

}  // namespace

Status GetAndroidPackage(FsSession &fss, const api::CallContext &ctx, const pb::GetAndroidPackageRequest &req,
                         pb::GetAndroidPackageResponse &resp) {
  return FsGuard([&]() -> Status {
    try {
      auto layer = an::ApkLayer::open(fss.session, req.path(), ctx.cancelled);
      an::ApkLimits limits;
      limits.native = !req.skip_native();
      limits.dex = !req.skip_dex();
      limits.max_file_bytes = std::min<std::uint64_t>(limits.max_file_bytes, fss.session->limits().max_file_bytes);
      const an::ApkInfo info = an::describe_apk(*layer, limits);
      pb::AndroidPackage *p = resp.mutable_package();
      p->set_path(layer->prefix());
      p->set_container_path(fss.session->container_path(layer->prefix().empty() ? "/" : layer->prefix()));
      p->set_manifest_present(info.has_manifest);
      if (info.has_manifest) {
        FillManifest(info.manifest, p->mutable_manifest());
        p->set_manifest_xml(info.manifest_xml.to_xml(false));
        p->set_manifest_xml_resolved(info.manifest_xml.to_xml(true));
      }
      if (info.has_resources) FillResources(info.resources, p->mutable_resources());
      for (const std::string &a : info.abis) p->add_abis(a);
      for (const an::NativeLibrary &l : info.libraries) {
        auto *x = p->add_native_libraries();
        x->set_abi(l.abi);
        x->set_path(layer->session_path(l.path));
        x->set_name(l.name);
        x->set_size(l.size);
        x->set_machine(l.machine);
        x->set_soname(l.soname);
        x->set_build_id(l.build_id);
        for (const std::string &n : l.needed) x->add_needed(n);
        x->set_exports(static_cast<std::uint32_t>(l.exports));
        for (const std::string &n : l.jni_exports) x->add_jni_exports(n);
        x->set_jni_onload(l.jni_onload);
        x->set_flutter(l.flutter);
        x->set_error(l.error);
      }
      for (const auto &[path, d] : info.dex) {
        auto *x = p->add_dex_files();
        x->set_path(layer->session_path(path));
        x->set_version(d.version);
        x->set_strings(d.strings);
        x->set_types(d.types);
        x->set_methods(d.methods);
        x->set_classes(d.classes);
        x->set_native_methods(static_cast<std::uint32_t>(std::count_if(
            info.native_methods.begin(), info.native_methods.end(), [&](const an::NativeMethodLink &n) { return n.dex == path; })));
      }
      for (const an::NativeMethodLink &n : info.native_methods) {
        auto *x = p->add_native_methods();
        x->set_class_name(n.method.class_name);
        x->set_method(n.method.name);
        x->set_signature(n.method.descriptor);
        x->set_is_static((n.method.access & 0x8) != 0);
        x->set_dex(layer->session_path(n.dex));
        x->set_jni_name(n.short_name);
        x->set_jni_long_name(n.long_name);
        for (const std::string &l : n.libraries) x->add_libraries(layer->session_path(l));
      }
      pb::AndroidFlutter *f = p->mutable_flutter();
      f->set_detected(info.flutter);
      f->set_snapshot_hash(info.snapshot_hash);
      for (const an::FlutterAbi &a : info.flutter_abis) {
        auto *x = f->add_abis();
        x->set_abi(a.abi);
        if (!a.libapp.empty()) x->set_libapp(layer->session_path(a.libapp));
        if (!a.libflutter.empty()) x->set_libflutter(layer->session_path(a.libflutter));
        x->set_snapshot_hash(a.app.snapshot_hash);
        for (const std::string &h : a.app.hash_candidates) x->add_hash_candidates(h);
        x->set_features(a.app.features);
        for (const an::DartSnapshot &s : a.app.snapshots) {
          auto *y = x->add_snapshots();
          y->set_symbol(s.symbol);
          y->set_file_offset(s.file_offset);
          y->set_size(s.size);
          y->set_header(s.header);
          y->set_length(s.length);
          y->set_kind(s.kind);
          y->set_kind_name(s.kind_name);
          y->set_hash(s.hash);
          y->set_features(s.features);
        }
        x->set_engine_build_id(a.engine.build_id);
        x->set_dart_version(a.engine.dart_version);
        for (const std::string &t : a.engine.toolchain) x->add_toolchain(t);
        for (const std::string &w : a.app.warnings) x->add_warnings(w);
      }
      for (const std::string &w : info.warnings) p->add_warnings(w);
      return Status::Ok();
    } catch (const an::Error &e) {
      return Error(StatusCode::kInvalidArgument, e.what());
    }
  });
}

Status DecodeAndroidXml(FsSession &fss, const api::CallContext &ctx, const pb::DecodeAndroidXmlRequest &req,
                        pb::DecodeAndroidXmlResponse &resp) {
  return FsGuard([&]() -> Status {
    try {
      auto src = fss.session->open_file(req.path(), ctx.cancelled);
      if (src->size() > (64u << 20)) return Error(StatusCode::kResourceExhausted, "the file is larger than 64 MiB");
      const std::vector<std::byte> bytes = src->read_exact(0, src->size(), req.path());
      if (!an::is_binary_xml(bytes)) return Error(StatusCode::kInvalidArgument, "not Android binary XML");
      // The package it is in, for its references.
      std::optional<an::ResourceTable> table;
      try {
        auto layer = an::ApkLayer::open(fss.session, req.path(), ctx.cancelled);
        table = an::read_apk_resources(*layer);
      } catch (const container::Error &) {
      } catch (const an::Error &e) {
        resp.add_warnings(std::string("resources.arsc: ") + e.what());
      }
      const an::XmlDocument doc = an::decode_xml(bytes, table ? &*table : nullptr);
      resp.set_xml(doc.to_xml(req.resolve()));
      resp.set_root(doc.root.name);
      for (const std::string &w : doc.warnings) resp.add_warnings(w);
      return Status::Ok();
    } catch (const an::Error &e) {
      return Error(StatusCode::kInvalidArgument, e.what());
    }
  });
}

Status ListAndroidResources(FsSession &fss, const api::CallContext &ctx, const pb::ListAndroidResourcesRequest &req,
                            pb::ListAndroidResourcesResponse &resp) {
  return FsGuard([&]() -> Status {
    try {
      auto layer = an::ApkLayer::open(fss.session, req.path(), ctx.cancelled);
      an::ApkLimits limits;
      limits.max_file_bytes = std::min<std::uint64_t>(limits.max_file_bytes, fss.session->limits().max_file_bytes);
      auto table = an::read_apk_resources(*layer, limits);
      if (!table) return Error(StatusCode::kNotFound, "the package has no resources.arsc");
      const std::uint32_t limit = req.limit() == 0 ? 500 : std::min<std::uint32_t>(req.limit(), 5000);
      const std::string query = Lower(req.query());
      std::set<std::string> types, configs;
      std::uint32_t total = 0;
      for (const an::ResourcePackage &p : table->packages)
        for (const an::ResourceType &t : p.types) {
          types.insert(t.name);
          if (!req.type().empty() && t.name != req.type()) continue;
          for (const std::string &c : t.configs) configs.insert(c);
          for (const an::ResourceEntry &e : t.entries) {
            if (req.config() != "*" && e.config != req.config()) continue;
            pb::AndroidResourceEntry x;
            x.set_id(e.id);
            x.set_name(table->name_of(e.id));
            x.set_type(t.name);
            x.set_key(e.name);
            x.set_config(e.config);
            if (e.complex) {
              x.set_value_type("bag");
              if (e.parent != 0) {
                std::string n = table->name_of(e.parent);
                if (n.empty()) n = an::format_value({0x01, e.parent});
                x.set_parent(n);
              }
              for (const auto &[attr, v] : e.items) {
                std::string an_name = table->name_of(attr);
                if (an_name.empty()) an_name = an::format_value({0x01, attr});
                std::string vn = v.type == 0x01 ? table->name_of(v.data) : std::string();
                std::string vs = vn.empty() ? table->resolve(v) : vn;
                x.add_items(an_name + " = " + vs);
              }
            } else {
              x.set_value_type(std::string(an::value_type_name(e.value.type)));
              std::string ref;
              x.set_value(table->resolve(e.value, &ref));
              x.set_reference(ref);
            }
            if (!query.empty()) {
              std::string hay = Lower(x.key() + "\n" + x.value() + "\n" + x.name());
              for (const std::string &i : x.items()) hay += "\n" + Lower(i);
              if (hay.find(query) == std::string::npos) continue;
            }
            if (total >= req.offset() && static_cast<std::uint32_t>(resp.entries_size()) < limit) *resp.add_entries() = std::move(x);
            ++total;
          }
        }
      resp.set_total(total);
      for (const std::string &t : types) resp.add_types(t);
      for (const std::string &c : configs) resp.add_configs(c);
      return Status::Ok();
    } catch (const an::Error &e) {
      return Error(StatusCode::kInvalidArgument, e.what());
    }
  });
}

}  // namespace revkit::backend
