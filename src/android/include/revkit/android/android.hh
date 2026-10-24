// Android packages (docs/android.md): the binary XML that AndroidManifest.xml
// and the other compiled XML files of an APK are stored as, the resource
// table (resources.arsc), the manifest's fields, a minimal DEX reader (class
// and method names, which methods are native), the JNI names those methods
// bind to, the ELF facts of the native libraries (exports, the GNU build
// ID), and a Flutter app's Dart snapshot hash. Every parser takes hostile
// bytes: bounds-checked, with limits, never trusting a count or offset.
//
// No dependency on the rest of revkit: the image backend reads the APK's
// members through its container session and hands their bytes here.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::android {

using Bytes = std::span<const std::byte>;

// Malformed input the parser can't go on with.
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// --- Resource values (Res_value) ---

enum class ValueType : std::uint8_t {
  null = 0x00,
  reference = 0x01,
  attribute = 0x02,
  string = 0x03,
  floating = 0x04,
  dimension = 0x05,
  fraction = 0x06,
  dynamic_reference = 0x07,
  dynamic_attribute = 0x08,
  int_dec = 0x10,
  int_hex = 0x11,
  boolean = 0x12,
  color_argb8 = 0x1c,
  color_rgb8 = 0x1d,
  color_argb4 = 0x1e,
  color_rgb4 = 0x1f,
};

struct Value {
  std::uint8_t type = 0;  // ValueType, or another number as stored
  std::uint32_t data = 0;
};
// "TYPE_STRING" style names for the API: "reference", "string", "int", ...
std::string_view value_type_name(std::uint8_t type);
// A value as aapt2 dump prints it, without resolving references:
// "true", "0x7f040001", "16.0dip", "#ff336699", "@0x7f0c0012".
std::string format_value(const Value &v, std::string_view string_value = {});

// --- String pools ---

struct StringPool {
  std::vector<std::string> strings;  // UTF-8 (UTF-16 pools converted)
  bool utf8 = false;
  bool sorted = false;
  std::uint32_t styles = 0;
  const std::string *at(std::uint32_t i) const { return i < strings.size() ? &strings[i] : nullptr; }
};
// A ResStringPool chunk (its header first). Strings that don't decode are
// kept empty with a warning.
StringPool parse_string_pool(Bytes chunk, std::vector<std::string> *warnings = nullptr);

// --- The resource table (resources.arsc) ---

// ResTable_config as a qualifier string: "" for the default
// configuration, else aapt2's order ("en-rUS", "night", "xxhdpi", "v21",
// "sw600dp-land").
struct Config {
  std::string qualifiers;
  bool is_default() const { return qualifiers.empty(); }
};
std::string config_qualifiers(Bytes config);

struct ResourceEntry {
  std::uint32_t id = 0;  // 0xPPTTEEEE
  std::string name;      // the key ("app_name")
  std::string config;    // qualifiers, "" default
  bool complex = false;  // a bag (style, array, plurals, attr)
  bool is_public = false;
  Value value;           // a simple entry's value
  // A bag's parent and items (attribute id, value); a simple entry's none.
  std::uint32_t parent = 0;
  std::vector<std::pair<std::uint32_t, Value>> items;
};

struct ResourceType {
  std::uint8_t id = 0;
  std::string name;  // "string", "drawable", ...
  std::uint32_t entry_count = 0;  // from the type spec
  std::vector<std::string> configs;
  std::vector<ResourceEntry> entries;  // every config's
};

struct ResourcePackage {
  std::uint32_t id = 0;  // 0x7f for an app, 0x01 for android
  std::string name;
  std::vector<ResourceType> types;
  std::map<std::uint32_t, std::string> libraries;  // shared library packages: id -> name
};

struct ResourceLimits {
  std::size_t max_entries = 1u << 21;  // entries across all types and configs
  std::size_t max_strings = 1u << 21;  // in one string pool
};

struct ResourceTable {
  StringPool strings;  // the global value pool
  std::vector<ResourcePackage> packages;
  std::vector<std::string> warnings;

  const ResourcePackage *package(std::uint32_t id) const;
  // The entries of a resource id, one per configuration.
  std::vector<const ResourceEntry *> find(std::uint32_t id) const;
  // The entry for the default configuration, else the first one.
  const ResourceEntry *best(std::uint32_t id) const;
  // "@string/app_name", "@android:style/Theme" (ids of package 1 named
  // from the framework's attribute table only), or "" when unknown.
  std::string name_of(std::uint32_t id) const;
  // What a value means, references followed (at most 8 hops) to their
  // default-configuration value: a string's text, "true", "@xml/x" for a
  // file, a number. `ref_name`: the name of the first reference.
  std::string resolve(const Value &v, std::string *ref_name = nullptr) const;
  std::size_t entry_count() const;

  // Each id's entries as (package, type, entry) indexes, built by the parser.
  std::map<std::uint32_t, std::vector<std::array<std::uint32_t, 3>>> index;
};
ResourceTable parse_resource_table(Bytes data, const ResourceLimits &limits = {});

// --- Binary XML (AXML) ---

struct XmlAttribute {
  std::string ns;      // the namespace URI ("http://schemas.android.com/apk/res/android")
  std::string prefix;  // its prefix where declared ("android")
  std::string name;    // as stored, else from the resource map ("versionCode")
  std::uint32_t resource_id = 0;  // the attribute's id from the resource map (0x0101021b)
  std::optional<std::string> raw;  // the raw string value, when kept
  Value value;
  std::string text;      // the value as text (format_value, or the string)
  std::string resolved;  // with a resource table: what a reference resolves to
};

struct XmlElement {
  std::string ns, prefix, name;
  std::uint32_t line = 0;
  std::vector<XmlAttribute> attributes;
  std::vector<XmlElement> children;
  std::string text;  // character data inside it
  const XmlAttribute *attr(std::string_view name) const;  // by local name (any namespace)
  const XmlAttribute *android_attr(std::string_view name) const;  // in the android namespace, or by its framework id
};

struct XmlDocument {
  XmlElement root;
  std::vector<std::pair<std::string, std::string>> namespaces;  // prefix, uri (on the root)
  std::vector<std::string> warnings;
  // The document as XML text, two-space indented, with the attributes'
  // text values (resolved ones as `resolved` says, when asked).
  std::string to_xml(bool resolved_values = false) const;
};

struct XmlLimits {
  std::size_t max_depth = 256;
  std::size_t max_nodes = 1u << 20;
  std::size_t max_attributes = 4096;  // per element
};
// Binary XML (a RES_XML_TYPE chunk). `table`, when given, resolves
// references in attribute values (XmlAttribute::resolved).
XmlDocument decode_xml(Bytes data, const ResourceTable *table = nullptr, const XmlLimits &limits = {});
// Whether these bytes start like binary XML.
bool is_binary_xml(Bytes data);

// The framework attribute an id names ("versionCode" for 0x0101021b), or "".
std::string_view framework_attribute(std::uint32_t id);

// --- The manifest ---

struct IntentData {
  std::string scheme, host, port, path, path_prefix, path_pattern, mime_type;
};

struct IntentFilter {
  std::vector<std::string> actions, categories;
  std::vector<IntentData> data;
  std::optional<std::int32_t> priority;
  bool auto_verify = false;
};

struct Component {
  std::string kind;  // "activity", "activity-alias", "service", "receiver", "provider"
  std::string name;  // fully qualified ("com.example.MainActivity")
  // What Android decides: the attribute when it is there, else true when
  // the component has an intent filter (a provider: when targetSdk < 17).
  bool exported = false;
  bool exported_explicit = false;  // the manifest says
  std::optional<bool> enabled;
  std::string permission, process, authorities, target_activity, read_permission, write_permission;
  bool grant_uri_permissions = false;
  bool launcher = false;  // MAIN and LAUNCHER
  std::vector<IntentFilter> intent_filters;
};

struct Permission {
  std::string name;
  std::optional<std::int32_t> max_sdk;
  std::string protection_level;  // declared permissions
};

struct Manifest {
  std::string package;
  std::optional<std::int64_t> version_code;  // with versionCodeMajor in the high 32 bits
  std::string version_name;
  std::optional<std::int32_t> min_sdk, target_sdk, max_sdk, compile_sdk;
  std::string compile_sdk_codename, platform_build_version_name;
  std::optional<std::int32_t> platform_build_version_code;
  std::string install_location, shared_user_id;
  std::vector<Permission> uses_permissions;
  std::vector<Permission> permissions;  // declared
  std::vector<std::string> uses_features, uses_libraries, queries_packages;
  // <application>
  std::string application_class;  // fully qualified, "" when none
  std::string label, icon, theme, process, app_component_factory;
  std::optional<bool> debuggable, allow_backup, uses_cleartext_traffic, extract_native_libs, test_only, large_heap,
      has_code, request_legacy_external_storage;
  std::string network_security_config;       // "@xml/network_security_config"
  std::string network_security_config_file;  // "res/xml/network_security_config.xml", when the table says
  std::string full_backup_content, data_extraction_rules;
  std::vector<Component> components;
  std::vector<std::pair<std::string, std::string>> meta_data;  // application-level name, value
  std::vector<std::string> warnings;
};
// The fields of a decoded AndroidManifest.xml. `table` resolves label,
// icon, theme and the network security config's file.
Manifest read_manifest(const XmlDocument &doc, const ResourceTable *table = nullptr);

// --- DEX ---

struct DexMethod {
  std::string class_name;  // "com.example.Native" (from Lcom/example/Native;)
  std::string name;
  std::string descriptor;  // "(Ljava/lang/String;I)V"
  std::uint32_t access = 0;
  bool is_native() const { return (access & 0x100) != 0; }
};

struct DexFile {
  std::string version;  // "035" ... "041"
  std::uint32_t strings = 0, types = 0, methods = 0, classes = 0;
  std::vector<std::string> class_names;  // defined classes, dotted
  std::vector<DexMethod> native_methods;
  std::vector<std::string> warnings;
};

struct DexLimits {
  std::size_t max_ids = 1u << 22;
  std::size_t max_class_names = 1u << 18;  // kept (all are counted)
};
DexFile parse_dex(Bytes data, const DexLimits &limits = {});

// The JNI names a native method binds to: Java_<class>_<method>, and with
// its argument signature after "__" (for overloads).
std::string jni_short_name(std::string_view class_name, std::string_view method);
std::string jni_long_name(std::string_view class_name, std::string_view method, std::string_view descriptor);
// The Java method a Java_ export names (class dotted, method, signature
// or ""); nullopt when it isn't one.
struct JniName {
  std::string class_name, method, signature;
};
std::optional<JniName> parse_jni_name(std::string_view symbol);

// --- ELF (native libraries) ---

struct ElfSymbol {
  std::string name;
  std::uint64_t value = 0, size = 0;
  std::uint8_t type = 0;  // STT_*
  std::optional<std::uint64_t> file_offset;  // through PT_LOAD
};

struct ElfInfo {
  bool is64 = false, big_endian = false;
  std::uint16_t type = 0, machine = 0;
  std::string machine_name;  // "AArch64", "ARM", "x86-64", "x86", "RISC-V", "MIPS"
  std::string abi;           // what Android calls it: "arm64-v8a", "armeabi-v7a", "x86_64", "x86", "riscv64"
  std::string soname;
  std::vector<std::string> needed;
  std::vector<ElfSymbol> exports;  // defined dynamic symbols, global or weak
  std::string build_id;  // hex, the GNU build ID note
  std::vector<std::string> warnings;
};

struct ElfLimits {
  std::size_t max_symbols = 1u << 20;
};
ElfInfo parse_elf(Bytes data, const ElfLimits &limits = {});

// --- Flutter ---

struct DartSnapshot {
  std::string symbol;  // "_kDartVmSnapshotData"
  std::uint64_t file_offset = 0, size = 0;
  bool header = false;  // the f5f5dcdc magic is there
  std::uint64_t length = 0;
  std::uint64_t kind = 0;
  std::string kind_name;  // "full-aot" for 3, as the Dart releases since 2.x number it
  std::string hash;       // 32 hex characters
  std::string features;   // "product no-code_comments ... arm64 android compressed-pointers"
};

struct FlutterApp {
  std::vector<DartSnapshot> snapshots;  // the four _kDart*Snapshot* symbols that are there
  std::string snapshot_hash;            // the VM's and the isolate's, when they agree
  std::vector<std::string> hash_candidates;  // distinct hashes seen (more than one: they disagree)
  std::string features;
  std::vector<std::string> warnings;
};
// libapp.so: the snapshots from its dynamic symbols.
FlutterApp read_flutter_app(Bytes libapp);
// libflutter.so: the engine's build ID and the Dart version string it
// carries, when it does ("Dart VM version" lines are usually stripped).
struct FlutterEngine {
  std::string build_id;
  std::string dart_version;
  std::vector<std::string> toolchain;  // "Android (…) clang version …" lines
};
FlutterEngine read_flutter_engine(Bytes libflutter);

// --- A whole APK ---

// The package's files, as the caller reads them (the image backend: through
// its container session). Paths are relative to the APK's root, '/'
// separated ("lib/arm64-v8a/libfoo.so").
class ApkFiles {
 public:
  virtual ~ApkFiles() = default;
  virtual std::vector<std::string> list() = 0;
  virtual std::optional<std::uint64_t> size(const std::string &path) = 0;
  // The whole file; Error when it is larger than `max` or can't be read.
  virtual std::vector<std::byte> read(const std::string &path, std::uint64_t max) = 0;
};

struct ApkLimits {
  std::uint64_t max_file_bytes = 256ull << 20;   // one member read whole
  std::uint64_t max_total_bytes = 1ull << 30;    // all the native libraries and DEX files read
  std::size_t max_dex_files = 64;
  std::size_t max_libraries = 512;
  std::size_t max_jni_exports = 4096;            // per library
  bool native = true;                            // read the libraries (exports, Flutter)
  bool dex = true;                               // read the DEX files (native methods)
};

struct NativeLibrary {
  std::string abi;   // the directory: "arm64-v8a"
  std::string path;  // "lib/arm64-v8a/libfoo.so"
  std::string name;  // "libfoo.so"
  std::uint64_t size = 0;
  std::string machine, soname, build_id;
  std::string elf_abi;  // what its header says ("" when it isn't ELF)
  std::vector<std::string> needed;
  std::size_t exports = 0;
  std::vector<std::string> jni_exports;  // Java_* names
  bool jni_onload = false;
  std::string flutter;  // "engine" (libflutter.so), "app" (libapp.so), ""
  std::string error;    // why it couldn't be read
};

struct NativeMethodLink {
  DexMethod method;
  std::string dex;  // "classes.dex"
  std::string short_name, long_name;
  // The libraries that export it ("lib/arm64-v8a/libfoo.so"); none: it is
  // registered at run time (RegisterNatives, usually from JNI_OnLoad), or
  // its library is elsewhere.
  std::vector<std::string> libraries;
};

struct FlutterAbi {
  std::string abi, libapp, libflutter;
  FlutterApp app;
  FlutterEngine engine;
};

struct ApkInfo {
  bool has_manifest = false, has_resources = false;
  XmlDocument manifest_xml;
  Manifest manifest;
  ResourceTable resources;
  std::vector<std::string> abis;
  std::vector<NativeLibrary> libraries;
  std::vector<std::pair<std::string, DexFile>> dex;
  std::vector<NativeMethodLink> native_methods;
  bool flutter = false;
  std::vector<FlutterAbi> flutter_abis;
  std::string snapshot_hash;  // every ABI's, when they agree
  std::vector<std::string> warnings;
};
ApkInfo describe_apk(ApkFiles &files, const ApkLimits &limits = {});
// The resource table alone (resources.arsc), for references; nullopt when
// the package has none.
std::optional<ResourceTable> read_apk_resources(ApkFiles &files, const ApkLimits &limits = {});

}  // namespace revkit::android
