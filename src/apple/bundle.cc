// Info.plist keys, as Apple's Information Property List reference names
// them.

#include "revkit/apple/bundle.hh"

#include <algorithm>
#include <cctype>

namespace revkit::apple {

namespace {

TypeDeclaration type_declaration(const Value &d) {
  TypeDeclaration t;
  t.identifier = d.string_at("UTTypeIdentifier");
  t.description = d.string_at("UTTypeDescription");
  t.conforms_to = d.strings_at("UTTypeConformsTo");
  if (const Value *tags = d.get("UTTypeTagSpecification"); tags && tags->is(Value::Type::dict)) {
    t.extensions = tags->strings_at("public.filename-extension");
    t.mime_types = tags->strings_at("public.mime-type");
  }
  return t;
}

}  // namespace

BundleInfo bundle_info(const Value &v) {
  BundleInfo b;
  if (!v.is(Value::Type::dict)) return b;
  b.identifier = v.string_at("CFBundleIdentifier");
  b.name = v.string_at("CFBundleName");
  b.display_name = v.string_at("CFBundleDisplayName");
  b.executable = v.string_at("CFBundleExecutable");
  b.version = v.string_at("CFBundleVersion");
  b.short_version = v.string_at("CFBundleShortVersionString");
  b.package_type = v.string_at("CFBundlePackageType");
  b.minimum_os = v.string_at("MinimumOSVersion");
  if (b.minimum_os.empty()) b.minimum_os = v.string_at("LSMinimumSystemVersion");
  b.supported_platforms = v.strings_at("CFBundleSupportedPlatforms");
  if (const Value *f = v.get("UIDeviceFamily"); f && f->is(Value::Type::array)) {
    static const char *kFamilies[] = {"", "iphone", "ipad", "tv", "watch", "carplay", "mac", "vision"};
    for (const Value &x : f->array)
      if (auto n = x.as_int(); n && *n >= 1 && *n < 8) b.device_families.push_back(kFamilies[*n]);
      else if (const std::string *s = x.as_string()) b.device_families.push_back(*s);
  }
  if (const Value *types = v.get("CFBundleURLTypes"); types && types->is(Value::Type::array))
    for (const Value &t : types->array)
      for (const std::string &s : t.strings_at("CFBundleURLSchemes"))
        if (std::find(b.url_schemes.begin(), b.url_schemes.end(), s) == b.url_schemes.end()) b.url_schemes.push_back(s);
  b.queried_url_schemes = v.strings_at("LSApplicationQueriesSchemes");
  if (const Value *docs = v.get("CFBundleDocumentTypes"); docs && docs->is(Value::Type::array))
    for (const Value &d : docs->array) {
      if (!d.is(Value::Type::dict)) continue;
      DocumentType t;
      t.name = d.string_at("CFBundleTypeName");
      t.role = d.string_at("CFBundleTypeRole");
      t.handler_rank = d.string_at("LSHandlerRank");
      t.content_types = d.strings_at("LSItemContentTypes");
      t.extensions = d.strings_at("CFBundleTypeExtensions");
      b.document_types.push_back(std::move(t));
    }
  b.background_modes = v.strings_at("UIBackgroundModes");
  for (const DictEntry &e : v.dict)
    if (e.key.ends_with("UsageDescription") && e.value.is(Value::Type::string))
      b.usage_descriptions.push_back({e.key, e.value.bytes});
  std::sort(b.usage_descriptions.begin(), b.usage_descriptions.end(),
            [](const UsageDescription &x, const UsageDescription &y) { return x.key < y.key; });
  for (const auto &[key, out] : {std::pair{"UTExportedTypeDeclarations", &b.exported_types},
                                 std::pair{"UTImportedTypeDeclarations", &b.imported_types}})
    if (const Value *list = v.get(key); list && list->is(Value::Type::array))
      for (const Value &d : list->array)
        if (d.is(Value::Type::dict)) out->push_back(type_declaration(d));
  if (const Value *caps = v.get("UIRequiredDeviceCapabilities")) {
    if (caps->is(Value::Type::array)) b.required_capabilities = v.strings_at("UIRequiredDeviceCapabilities");
    else if (caps->is(Value::Type::dict))
      for (const DictEntry &e : caps->dict)
        if (e.value.as_bool().value_or(false)) b.required_capabilities.push_back(e.key);
  }
  if (const Value *ext = v.get("NSExtension"); ext && ext->is(Value::Type::dict)) {
    b.extension_point = ext->string_at("NSExtensionPointIdentifier");
    b.principal_class = ext->string_at("NSExtensionPrincipalClass");
  }
  if (std::string p = v.string_at("NSPrincipalClass"); !p.empty()) b.principal_class = p;
  b.main_storyboard = v.string_at("UIMainStoryboardFile");
  if (b.main_storyboard.empty()) b.main_storyboard = v.string_at("NSMainStoryboardFile");
  b.main_nib = v.string_at("NSMainNibFile");
  b.launch_storyboard = v.string_at("UILaunchStoryboardName");
  if (const Value *ats = v.get("NSAppTransportSecurity"); ats && ats->is(Value::Type::dict)) {
    if (const Value *a = ats->get("NSAllowsArbitraryLoads")) b.allows_arbitrary_loads = a->as_bool().value_or(false);
    if (const Value *d = ats->get("NSExceptionDomains"); d && d->is(Value::Type::dict))
      for (const DictEntry &e : d->dict) b.ats_exception_domains.push_back(e.key);
  }
  b.sdk = v.string_at("DTSDKName");
  b.xcode = v.string_at("DTXcode");
  b.build_machine_os = v.string_at("BuildMachineOSBuild");
  if (const Value *r = v.get("LSRequiresIPhoneOS")) b.requires_iphone_os = r->as_bool().value_or(false);
  return b;
}

std::string bundle_kind(std::string_view name) {
  const std::size_t dot = name.rfind('.');
  if (dot == std::string_view::npos || dot == 0) return "";
  std::string ext;
  for (char c : name.substr(dot + 1)) ext += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  static const char *kKinds[] = {"app",         "framework",  "appex",    "bundle",   "xpc",
                                 "plugin",      "kext",       "systemextension", "dext", "qlgenerator",
                                 "mdimporter",  "prefpane",   "saver",    "storyboardc"};
  for (const char *k : kKinds)
    if (ext == k) return k;
  return "";
}

}  // namespace revkit::apple
