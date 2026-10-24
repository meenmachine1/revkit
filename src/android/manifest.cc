// The fields of a decoded AndroidManifest.xml: the package, versions and
// SDK levels, permissions, the application and its components, with the
// defaults Android applies (an exported component without the attribute,
// relative class names). Written for revkit.
#include "reader.hh"

#include <algorithm>
#include <charconv>
#include <cstdio>

namespace revkit::android {

namespace {

struct Fields {
  const ResourceTable *table;
  Manifest &m;

  std::string str(const XmlAttribute *a) const {
    if (a == nullptr) return {};
    if (a->value.type == 0x03 || a->value.type == 0x00) return a->raw ? *a->raw : a->text;
    if (!a->resolved.empty()) return a->resolved;
    if (table != nullptr && (a->value.type == 0x01 || a->value.type == 0x07)) {
      std::string r = table->resolve(a->value);
      if (!r.empty()) return r;
    }
    return a->text;
  }
  // A reference's name ("@xml/network_security_config"), else the text.
  std::string ref(const XmlAttribute *a) const {
    if (a == nullptr) return {};
    if ((a->value.type == 0x01 || a->value.type == 0x07) && table != nullptr) {
      std::string n = table->name_of(a->value.data);
      if (!n.empty()) return n;
    }
    return a->text;
  }
  std::optional<std::int64_t> num(const XmlAttribute *a) const {
    if (a == nullptr) return std::nullopt;
    if (a->value.type >= 0x10 && a->value.type <= 0x1f) return static_cast<std::int32_t>(a->value.data);
    const std::string s = str(a);
    std::int64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec == std::errc() && p == s.data() + s.size() && !s.empty()) return v;
    return std::nullopt;
  }
  std::optional<std::int32_t> i32(const XmlAttribute *a) const {
    auto v = num(a);
    if (!v) return std::nullopt;
    return static_cast<std::int32_t>(*v);
  }
  std::optional<bool> flag(const XmlAttribute *a) const {
    if (a == nullptr) return std::nullopt;
    if (a->value.type == 0x12 || (a->value.type >= 0x10 && a->value.type <= 0x11)) return a->value.data != 0;
    const std::string s = str(a);
    if (s == "true") return true;
    if (s == "false") return false;
    return std::nullopt;
  }
  std::string cls(const XmlAttribute *a) const {
    std::string n = str(a);
    if (n.empty()) return n;
    if (n.front() == '.') return m.package + n;
    if (n.find('.') == std::string::npos && !m.package.empty()) return m.package + "." + n;
    return n;
  }
};

std::string protection(std::int64_t v) {
  static const char *base[] = {"normal", "dangerous", "signature", "signatureOrSystem", "internal"};
  std::string s = (v & 0xf) < 5 ? base[v & 0xf] : "level" + std::to_string(v & 0xf);
  static const std::pair<int, const char *> flags[] = {
      {0x10, "privileged"}, {0x20, "development"}, {0x40, "appop"}, {0x80, "pre23"}, {0x100, "installer"},
      {0x200, "verifier"}, {0x400, "preinstalled"}, {0x800, "setup"}, {0x1000, "instant"}, {0x2000, "runtime"},
      {0x4000, "oem"}, {0x8000, "vendorPrivileged"}, {0x10000, "textClassifier"}, {0x40000, "configurator"},
      {0x80000, "incidentReportApprover"}, {0x100000, "appPredictor"}, {0x400000, "companion"},
      {0x800000, "retailDemo"}, {0x1000000, "recents"}, {0x2000000, "role"}, {0x4000000, "knownSigner"}};
  for (const auto &[bit, name] : flags)
    if (v & bit) s += std::string("|") + name;
  return s;
}

}  // namespace

Manifest read_manifest(const XmlDocument &doc, const ResourceTable *table) {
  Manifest m;
  Fields f{table, m};
  const XmlElement &root = doc.root;
  if (root.name != "manifest") m.warnings.push_back("the root element is <" + root.name + ">, not <manifest>");
  m.package = f.str(root.attr("package"));
  if (auto v = f.num(root.android_attr("versionCode"))) {
    std::int64_t code = static_cast<std::uint32_t>(*v);
    if (auto major = f.num(root.android_attr("versionCodeMajor"))) code |= static_cast<std::int64_t>(static_cast<std::uint32_t>(*major)) << 32;
    m.version_code = code;
  }
  m.version_name = f.str(root.android_attr("versionName"));
  m.compile_sdk = f.i32(root.android_attr("compileSdkVersion"));
  m.compile_sdk_codename = f.str(root.android_attr("compileSdkVersionCodename"));
  m.platform_build_version_code = f.i32(root.attr("platformBuildVersionCode"));
  m.platform_build_version_name = f.str(root.attr("platformBuildVersionName"));
  if (auto v = f.num(root.android_attr("installLocation"))) {
    static const char *loc[] = {"auto", "internalOnly", "preferExternal"};
    m.install_location = *v >= 0 && *v < 3 ? loc[*v] : std::to_string(*v);
  }
  m.shared_user_id = f.str(root.android_attr("sharedUserId"));
  bool have_app = false;
  // The SDK levels first: a provider's default export depends on them.
  for (const XmlElement &e : root.children)
    if (e.name == "uses-sdk") {
      m.min_sdk = f.i32(e.android_attr("minSdkVersion"));
      m.target_sdk = f.i32(e.android_attr("targetSdkVersion"));
      m.max_sdk = f.i32(e.android_attr("maxSdkVersion"));
      break;
    }
  for (const XmlElement &e : root.children) {
    if (e.name == "uses-sdk") {
      continue;
    } else if (e.name == "uses-permission" || e.name == "uses-permission-sdk-23" || e.name == "uses-permission-sdk-m") {
      m.uses_permissions.push_back({f.str(e.android_attr("name")), f.i32(e.android_attr("maxSdkVersion")), {}});
    } else if (e.name == "permission") {
      Permission p{f.str(e.android_attr("name")), std::nullopt, "normal"};
      if (auto v = f.num(e.android_attr("protectionLevel"))) p.protection_level = protection(*v);
      m.permissions.push_back(std::move(p));
    } else if (e.name == "uses-feature") {
      std::string n = f.str(e.android_attr("name"));
      if (n.empty())
        if (auto gl = f.num(e.attr("glEsVersion"))) {
          char b[32];
          std::snprintf(b, sizeof b, "OpenGL ES %d.%d", static_cast<int>(*gl >> 16), static_cast<int>(*gl & 0xffff));
          n = b;
        }
      if (!n.empty()) m.uses_features.push_back(n);
    } else if (e.name == "queries") {
      for (const XmlElement &q : e.children)
        if (q.name == "package") m.queries_packages.push_back(f.str(q.android_attr("name")));
    } else if (e.name == "application" && !have_app) {
      have_app = true;
      m.application_class = f.cls(e.android_attr("name"));
      m.label = f.str(e.android_attr("label"));
      m.icon = f.ref(e.android_attr("icon"));
      m.theme = f.ref(e.android_attr("theme"));
      m.process = f.str(e.android_attr("process"));
      m.app_component_factory = f.cls(e.android_attr("appComponentFactory"));
      m.debuggable = f.flag(e.android_attr("debuggable"));
      m.allow_backup = f.flag(e.android_attr("allowBackup"));
      m.uses_cleartext_traffic = f.flag(e.android_attr("usesCleartextTraffic"));
      m.extract_native_libs = f.flag(e.android_attr("extractNativeLibs"));
      m.test_only = f.flag(e.android_attr("testOnly"));
      m.large_heap = f.flag(e.android_attr("largeHeap"));
      m.has_code = f.flag(e.android_attr("hasCode"));
      m.request_legacy_external_storage = f.flag(e.android_attr("requestLegacyExternalStorage"));
      if (const XmlAttribute *a = e.android_attr("networkSecurityConfig")) {
        m.network_security_config = f.ref(a);
        const std::string file = f.str(a);
        if (file.starts_with("res/")) m.network_security_config_file = file;
      }
      m.full_backup_content = f.ref(e.android_attr("fullBackupContent"));
      m.data_extraction_rules = f.ref(e.android_attr("dataExtractionRules"));
      for (const XmlElement &c : e.children) {
        if (c.name == "uses-library") {
          m.uses_libraries.push_back(f.str(c.android_attr("name")));
          continue;
        }
        if (c.name == "meta-data") {
          const XmlAttribute *v = c.android_attr("value");
          if (v == nullptr) v = c.android_attr("resource");
          m.meta_data.emplace_back(f.str(c.android_attr("name")), f.str(v));
          continue;
        }
        if (c.name != "activity" && c.name != "activity-alias" && c.name != "service" && c.name != "receiver" &&
            c.name != "provider")
          continue;
        Component k;
        k.kind = c.name;
        k.name = f.cls(c.android_attr("name"));
        k.enabled = f.flag(c.android_attr("enabled"));
        k.permission = f.str(c.android_attr("permission"));
        k.process = f.str(c.android_attr("process"));
        k.authorities = f.str(c.android_attr("authorities"));
        k.target_activity = f.cls(c.android_attr("targetActivity"));
        k.read_permission = f.str(c.android_attr("readPermission"));
        k.write_permission = f.str(c.android_attr("writePermission"));
        k.grant_uri_permissions = f.flag(c.android_attr("grantUriPermissions")).value_or(false);
        for (const XmlElement &i : c.children) {
          if (i.name != "intent-filter") continue;
          IntentFilter filter;
          filter.priority = f.i32(i.android_attr("priority"));
          filter.auto_verify = f.flag(i.android_attr("autoVerify")).value_or(false);
          for (const XmlElement &x : i.children) {
            if (x.name == "action") filter.actions.push_back(f.str(x.android_attr("name")));
            else if (x.name == "category") filter.categories.push_back(f.str(x.android_attr("name")));
            else if (x.name == "data")
              filter.data.push_back({f.str(x.android_attr("scheme")), f.str(x.android_attr("host")),
                                     f.str(x.android_attr("port")), f.str(x.android_attr("path")),
                                     f.str(x.android_attr("pathPrefix")), f.str(x.android_attr("pathPattern")),
                                     f.str(x.android_attr("mimeType"))});
          }
          auto has = [](const std::vector<std::string> &v, std::string_view s) {
            return std::find(v.begin(), v.end(), s) != v.end();
          };
          if (has(filter.actions, "android.intent.action.MAIN") && has(filter.categories, "android.intent.category.LAUNCHER"))
            k.launcher = true;
          k.intent_filters.push_back(std::move(filter));
        }
        if (auto ex = f.flag(c.android_attr("exported"))) {
          k.exported = *ex;
          k.exported_explicit = true;
        } else if (k.kind == "provider") {
          k.exported = m.target_sdk.value_or(m.min_sdk.value_or(1)) < 17;
        } else {
          k.exported = !k.intent_filters.empty();
        }
        m.components.push_back(std::move(k));
      }
    }
  }
  return m;
}

}  // namespace revkit::android
