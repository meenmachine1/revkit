// revkit::android on APKs written by tests/data/android/make_apk.py (binary
// XML, resources.arsc, DEX and JNI libraries compiled here), checked by
// hand against jadx 1.5.6's decoding of the same files; on pieces built by
// the tests; and on hostile bytes (truncations, flipped bytes).
#include "revkit/android/android.hh"
#include "revkit/android/apk_layer.hh"
#include "revkit/container/session.hh"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>

namespace revkit::android {
namespace {

namespace fs = std::filesystem;

bool sh(const std::string &cmd) { return std::system(("set -e; { " + cmd + "; } >/dev/null 2>&1").c_str()) == 0; }
bool have(const std::string &tool) { return sh("command -v " + tool); }

std::vector<std::byte> slurp(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::string s((std::istreambuf_iterator<char>(in)), {});
  std::vector<std::byte> out(s.size());
  std::memcpy(out.data(), s.data(), s.size());
  return out;
}

class TempDir {
 public:
  TempDir() {
    std::string t = (fs::temp_directory_path() / "rk-android-test-XXXXXX").string();
    if (!mkdtemp(t.data())) throw std::runtime_error("mkdtemp");
    path_ = t;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  fs::path operator/(const std::string &s) const { return path_ / s; }

 private:
  fs::path path_;
};

const std::string kGen = std::string("python3 -I ") + REVKIT_SOURCE_DIR + "/tests/data/android/make_apk.py";

struct Apk {
  TempDir dir;
  fs::path apk;
  std::shared_ptr<container::Session> session;
  std::unique_ptr<ApkLayer> layer;
};

// The generated APK, with the host's libraries and (when the cross
// compiler is here) AArch64's.
std::unique_ptr<Apk> make(const std::string &flags, bool aarch64 = false) {
  auto a = std::make_unique<Apk>();
  a->apk = a->dir / "test.apk";
  std::string cc = " --cc cc:x86_64";
  if (aarch64) cc += " --cc aarch64-linux-gnu-gcc:arm64-v8a";
  if (!sh(kGen + " " + a->apk.string() + cc + " " + flags)) return nullptr;
  a->session = container::Session::open(container::open_host_file(a->apk.string()), "test.apk", container::Limits{});
  a->layer = ApkLayer::open(a->session, "");
  return a;
}

const Component *component(const Manifest &m, const std::string &name) {
  for (const Component &c : m.components)
    if (c.name == name) return &c;
  return nullptr;
}

void CheckManifest(const ApkInfo &info) {
  ASSERT_TRUE(info.has_manifest);
  const Manifest &m = info.manifest;
  EXPECT_EQ(m.package, "com.example.droid");
  EXPECT_EQ(m.version_code, 7);
  EXPECT_EQ(m.version_name, "1.2.3");
  EXPECT_EQ(m.min_sdk, 24);
  EXPECT_EQ(m.target_sdk, 34);
  EXPECT_EQ(m.compile_sdk, 34);
  EXPECT_EQ(m.compile_sdk_codename, "14");
  EXPECT_EQ(m.platform_build_version_code, 34);
  ASSERT_EQ(m.uses_permissions.size(), 2u);
  EXPECT_EQ(m.uses_permissions[0].name, "android.permission.INTERNET");
  EXPECT_EQ(m.uses_permissions[1].max_sdk, 28);
  ASSERT_EQ(m.permissions.size(), 1u);
  EXPECT_EQ(m.permissions[0].protection_level, "signature");
  EXPECT_EQ(m.uses_features, std::vector<std::string>{"android.hardware.camera"});
  EXPECT_EQ(m.application_class, "com.example.droid.DroidApp");
  EXPECT_EQ(m.label, "Droid Test");  // @string/app_name, the default configuration's
  EXPECT_EQ(m.icon, "@mipmap/ic_launcher");
  EXPECT_EQ(m.theme, "@style/AppTheme");
  EXPECT_EQ(m.debuggable, true);
  EXPECT_EQ(m.allow_backup, false);
  EXPECT_EQ(m.uses_cleartext_traffic, true);  // through @bool/cleartext
  EXPECT_EQ(m.extract_native_libs, true);
  EXPECT_EQ(m.network_security_config, "@xml/network_security_config");
  EXPECT_EQ(m.network_security_config_file, "res/xml/network_security_config.xml");
  ASSERT_EQ(m.components.size(), 7u);
  const Component *main = component(m, "com.example.droid.MainActivity");
  ASSERT_NE(main, nullptr);
  EXPECT_TRUE(main->exported && main->exported_explicit && main->launcher);
  const Component *deep = component(m, "com.example.droid.DeepLinkActivity");
  ASSERT_NE(deep, nullptr);
  EXPECT_TRUE(deep->exported);  // implied by its intent filter
  EXPECT_FALSE(deep->exported_explicit);
  ASSERT_EQ(deep->intent_filters.size(), 1u);
  ASSERT_EQ(deep->intent_filters[0].data.size(), 1u);
  EXPECT_EQ(deep->intent_filters[0].data[0].scheme, "https");
  EXPECT_EQ(deep->intent_filters[0].data[0].host, "example.com");
  EXPECT_EQ(deep->intent_filters[0].data[0].path_prefix, "/open");
  const Component *settings = component(m, "com.example.droid.SettingsActivity");
  ASSERT_NE(settings, nullptr);
  EXPECT_FALSE(settings->exported);
  const Component *alias = component(m, "com.example.droid.Launcher2");
  ASSERT_NE(alias, nullptr);
  EXPECT_EQ(alias->kind, "activity-alias");
  EXPECT_EQ(alias->target_activity, "com.example.droid.MainActivity");
  const Component *sync = component(m, "com.example.droid.SyncService");
  ASSERT_NE(sync, nullptr);
  EXPECT_EQ(sync->kind, "service");
  EXPECT_EQ(sync->permission, "com.example.droid.permission.SYNC");
  EXPECT_EQ(sync->process, ":sync");
  const Component *boot = component(m, "com.example.droid.BootReceiver");
  ASSERT_NE(boot, nullptr);
  EXPECT_EQ(boot->kind, "receiver");
  EXPECT_TRUE(boot->exported);
  EXPECT_EQ(boot->intent_filters.at(0).priority, 999);
  const Component *prov = component(m, "com.example.droid.DataProvider");
  ASSERT_NE(prov, nullptr);
  EXPECT_EQ(prov->authorities, "com.example.droid.data");
  EXPECT_FALSE(prov->exported);
  EXPECT_TRUE(prov->grant_uri_permissions);
  ASSERT_EQ(m.meta_data.size(), 1u);
  EXPECT_EQ(m.meta_data[0].second, "k-123");
}

TEST(Android, ManifestResourcesAndNativeLibraries) {
  auto a = make("");
  if (!a) GTEST_SKIP() << "make_apk.py needs python3 and cc";
  const ApkInfo info = describe_apk(*a->layer);
  CheckManifest(info);
  // The XML text, as jadx prints it (references by name).
  const std::string xml = info.manifest_xml.to_xml();
  EXPECT_NE(xml.find("<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\""), std::string::npos);
  EXPECT_NE(xml.find("android:label=\"@string/app_name\""), std::string::npos);
  EXPECT_NE(xml.find("android:debuggable=\"true\""), std::string::npos);
  EXPECT_NE(xml.find("package=\"com.example.droid\""), std::string::npos);
  EXPECT_NE(xml.find("<action android:name=\"android.intent.action.MAIN\" />"), std::string::npos);
  EXPECT_NE(info.manifest_xml.to_xml(true).find("android:label=\"Droid Test\""), std::string::npos);

  // resources.arsc
  ASSERT_TRUE(info.has_resources);
  const ResourceTable &t = info.resources;
  ASSERT_EQ(t.packages.size(), 1u);
  EXPECT_EQ(t.packages[0].id, 0x7fu);
  EXPECT_EQ(t.packages[0].name, "com.example.droid");
  const ResourceType *strings = nullptr;
  for (const ResourceType &ty : t.packages[0].types)
    if (ty.name == "string") strings = &ty;
  ASSERT_NE(strings, nullptr);
  EXPECT_EQ(strings->entry_count, 4u);
  std::vector<std::string> configs = strings->configs;
  std::sort(configs.begin(), configs.end());
  EXPECT_EQ(configs, (std::vector<std::string>{"", "en-rGB", "fr"}));
  std::map<std::string, std::string> fr, gb, def;
  for (const ResourceEntry &e : strings->entries) {
    const std::string v = t.resolve(e.value);
    (e.config == "fr" ? fr : e.config == "en-rGB" ? gb : def)[e.name] = v;
  }
  EXPECT_EQ(def["app_name"], "Droid Test");
  EXPECT_EQ(def["unused_label"], "日本語 \U0001F600");
  EXPECT_EQ(fr["app_name"], "Droïde d'essai");
  EXPECT_EQ(fr["hello"], "Bonjour, le monde !");
  EXPECT_EQ(gb.size(), 1u);  // a sparse type
  EXPECT_EQ(gb["app_name"], "Droid Test (UK)");
  // Ids, names, values of each kind.
  const std::uint32_t app_name = 0x7f020000;
  EXPECT_EQ(t.name_of(app_name), "@string/app_name");
  EXPECT_EQ(t.find(app_name).size(), 3u);
  bool saw_bool = false, saw_color = false, saw_dimen = false, saw_style = false, saw_night = false, saw_sw = false,
       saw_xxhdpi = false;
  for (const ResourceType &ty : t.packages[0].types)
    for (const ResourceEntry &e : ty.entries) {
      if (ty.name == "bool" && e.name == "cleartext") saw_bool = format_value(e.value) == "true";  // compact entries
      if (ty.name == "bool" && e.config == "sw600dp") saw_sw = format_value(e.value) == "true";
      if (ty.name == "color" && e.config.empty()) saw_color = format_value(e.value) == "#ff336699";
      if (ty.name == "color" && e.config == "night") saw_night = true;
      if (ty.name == "dimen" && e.name == "padding") saw_dimen = format_value(e.value) == "16.0dip";
      if (ty.name == "mipmap") saw_xxhdpi = e.config == "xxhdpi-v4";
      if (ty.name == "style") {
        saw_style = e.complex && e.parent == 0x01030005 && e.items.size() == 2;
        EXPECT_EQ(t.name_of(e.items.at(0).second.data), "@color/primary");
      }
    }
  EXPECT_TRUE(saw_bool && saw_color && saw_dimen && saw_style && saw_night && saw_sw && saw_xxhdpi);

  // Native libraries, by ABI, with their JNI exports.
  EXPECT_EQ(info.abis, std::vector<std::string>{"x86_64"});
  const NativeLibrary *native = nullptr, *helper = nullptr;
  for (const NativeLibrary &l : info.libraries) {
    if (l.name == "libnative.so") native = &l;
    if (l.name == "libhelper.so") helper = &l;
  }
  ASSERT_NE(native, nullptr);
  ASSERT_NE(helper, nullptr);
  EXPECT_EQ(native->path, "lib/x86_64/libnative.so");
  EXPECT_EQ(native->machine, "x86-64");
  EXPECT_EQ(native->elf_abi, "x86_64");
  EXPECT_EQ(native->soname, "libnative.so");
  EXPECT_EQ(native->needed.at(0), "libhelper.so");
  EXPECT_EQ(native->build_id.size(), 40u);
  EXPECT_TRUE(native->jni_onload);
  EXPECT_EQ(native->jni_exports,
            (std::vector<std::string>{"Java_com_example_droid_NativeLib_00024Inner_ping", "Java_com_example_droid_NativeLib_add__II",
                                      "Java_com_example_droid_NativeLib_add__JJ", "Java_com_example_droid_NativeLib_do_1it",
                                      "Java_com_example_droid_NativeLib_hello"}));
  EXPECT_TRUE(helper->jni_exports.empty());
  EXPECT_FALSE(info.flutter);

  // DEX: native methods linked to their exports.
  ASSERT_EQ(info.dex.size(), 1u);
  EXPECT_EQ(info.dex[0].first, "classes.dex");
  EXPECT_EQ(info.dex[0].second.version, "035");
  EXPECT_EQ(info.dex[0].second.classes, 3u);
  ASSERT_EQ(info.native_methods.size(), 6u);
  std::map<std::string, const NativeMethodLink *> by;
  for (const NativeMethodLink &l : info.native_methods) by[l.method.class_name + "." + l.method.name + l.method.descriptor] = &l;
  auto linked = [&](const std::string &k) {
    auto it = by.find(k);
    return it != by.end() && it->second->libraries == std::vector<std::string>{"lib/x86_64/libnative.so"};
  };
  EXPECT_TRUE(linked("com.example.droid.NativeLib.hello(Ljava/lang/String;)Ljava/lang/String;"));
  EXPECT_TRUE(linked("com.example.droid.NativeLib.add(II)I"));
  EXPECT_TRUE(linked("com.example.droid.NativeLib.add(JJ)J"));
  EXPECT_TRUE(linked("com.example.droid.NativeLib.do_it()V"));
  EXPECT_TRUE(linked("com.example.droid.NativeLib$Inner.ping()I"));
  ASSERT_TRUE(by.contains("com.example.droid.NativeLib.registered()V"));
  EXPECT_TRUE(by["com.example.droid.NativeLib.registered()V"]->libraries.empty());  // RegisterNatives
  EXPECT_EQ(by["com.example.droid.NativeLib.add(II)I"]->long_name, "Java_com_example_droid_NativeLib_add__II");
  for (const std::string &w : info.warnings) ADD_FAILURE() << "warning: " << w;
}

TEST(Android, Utf16PoolsAndPlainTables) {
  auto a = make("--utf16 --plain");
  if (!a) GTEST_SKIP() << "make_apk.py needs python3 and cc";
  const ApkInfo info = describe_apk(*a->layer);
  CheckManifest(info);
  EXPECT_EQ(info.manifest_xml.root.name, "manifest");
}

TEST(Android, CompiledXmlFiles) {
  auto a = make("");
  if (!a) GTEST_SKIP();
  auto table = read_apk_resources(*a->layer);
  ASSERT_TRUE(table);
  const XmlDocument doc = decode_xml(a->layer->read("res/layout/main.xml", 1 << 20), &*table);
  const std::string xml = doc.to_xml();
  EXPECT_NE(xml.find("<LinearLayout"), std::string::npos);
  EXPECT_NE(xml.find("android:text=\"@string/hello\""), std::string::npos);
  EXPECT_NE(xml.find("android:layout_width=\"120.0dip\""), std::string::npos);
  EXPECT_NE(xml.find("android:layout_height=\"-2\""), std::string::npos);
  EXPECT_NE(doc.to_xml(true).find("android:text=\"Hello, world!\""), std::string::npos);
  EXPECT_NE(doc.to_xml(true).find("android:textColor=\"#ff336699\""), std::string::npos);
  const XmlDocument nsc = decode_xml(a->layer->read("res/xml/network_security_config.xml", 1 << 20), &*table);
  EXPECT_NE(nsc.to_xml().find("cleartextTrafficPermitted=\"true\""), std::string::npos);
  EXPECT_FALSE(is_binary_xml(a->layer->read("classes.dex", 1 << 20)));
}

TEST(Android, Flutter) {
  const bool arm = have("aarch64-linux-gnu-gcc");
  auto a = make("--flutter", arm);
  if (!a) GTEST_SKIP();
  const ApkInfo info = describe_apk(*a->layer);
  EXPECT_TRUE(info.flutter);
  ASSERT_EQ(info.flutter_abis.size(), arm ? 2u : 1u);
  EXPECT_EQ(info.snapshot_hash, "90b56a561f70cd55e972cb49b79b3d8b");
  for (const FlutterAbi &f : info.flutter_abis) {
    EXPECT_EQ(f.libapp, "lib/" + f.abi + "/libapp.so");
    EXPECT_EQ(f.app.snapshot_hash, "90b56a561f70cd55e972cb49b79b3d8b");
    ASSERT_EQ(f.app.snapshots.size(), 4u);
    for (const DartSnapshot &s : f.app.snapshots)
      if (s.symbol.ends_with("Data")) {
        EXPECT_TRUE(s.header);
        EXPECT_EQ(s.kind, 3u);
        EXPECT_EQ(s.kind_name, "full-aot");
      }
    EXPECT_EQ(f.app.features, "product no-code_comments no-dwarf_stack_traces_mode arm64 android compressed-pointers");
    EXPECT_EQ(f.engine.build_id.size(), 40u);
    EXPECT_EQ(f.engine.dart_version.substr(0, 14), "3.4.0 (stable)");
    ASSERT_EQ(f.engine.toolchain.size(), 1u);
    EXPECT_TRUE(f.engine.toolchain[0].starts_with("Android (8490178, based on r450784d) clang version 14.0.6"));
    for (const std::string &w : f.app.warnings) ADD_FAILURE() << w;
  }
  if (arm) {
    EXPECT_EQ(info.abis, (std::vector<std::string>{"arm64-v8a", "x86_64"}));
  }
}

TEST(Android, StrippedSectionsUseTheDynamicTable) {
  // A library without section headers: the dynamic symbols through
  // PT_DYNAMIC and DT_GNU_HASH (or DT_HASH).
  TempDir d;
  const std::string so = (d / "lib.so").string();
  if (!sh("cc -shared -fPIC -O1 -Wl,--hash-style=gnu -o " + so + " " + REVKIT_SOURCE_DIR "/tests/data/android/native.c " +
          "-Wl,--unresolved-symbols=ignore-all"))
    GTEST_SKIP();
  std::vector<std::byte> b = slurp(so);
  const ElfInfo full = parse_elf(b);
  // Zero e_shoff, e_shnum and e_shstrndx.
  std::memset(b.data() + 40, 0, 8);
  std::memset(b.data() + 60, 0, 4);
  const ElfInfo stripped = parse_elf(b);
  auto names = [](const ElfInfo &e) {
    std::vector<std::string> n;
    for (const ElfSymbol &s : e.exports) n.push_back(s.name);
    std::sort(n.begin(), n.end());
    return n;
  };
  EXPECT_EQ(names(full), names(stripped));
  EXPECT_GE(full.exports.size(), 7u);
  if (sh("cc -shared -fPIC -O1 -Wl,--hash-style=sysv -o " + so + " " + REVKIT_SOURCE_DIR "/tests/data/android/native.c " +
         "-Wl,--unresolved-symbols=ignore-all")) {
    std::vector<std::byte> s = slurp(so);
    std::memset(s.data() + 40, 0, 8);
    std::memset(s.data() + 60, 0, 4);
    EXPECT_EQ(names(parse_elf(s)), names(full));
  }
}

TEST(Android, JniNames) {
  EXPECT_EQ(jni_short_name("com.example.Foo", "bar"), "Java_com_example_Foo_bar");
  EXPECT_EQ(jni_short_name("com.example.Foo$Bar", "do_it"), "Java_com_example_Foo_00024Bar_do_1it");
  EXPECT_EQ(jni_long_name("a.B", "m", "([ILjava/lang/String;J)V"), "Java_a_B_m___3ILjava_lang_String_2J");
  EXPECT_EQ(jni_short_name("p.été", "x"), "Java_p__000e9t_000e9_x");
  auto j = parse_jni_name("Java_com_example_Foo_00024Bar_do_1it");
  ASSERT_TRUE(j);
  EXPECT_EQ(j->class_name, "com.example.Foo$Bar");
  EXPECT_EQ(j->method, "do_it");
  auto k = parse_jni_name("Java_a_B_m___3ILjava_lang_String_2J");
  ASSERT_TRUE(k);
  EXPECT_EQ(k->class_name, "a.B");
  EXPECT_EQ(k->method, "m");
  EXPECT_EQ(k->signature, "([ILjava/lang/String;J)");
  EXPECT_FALSE(parse_jni_name("JNI_OnLoad"));
  EXPECT_FALSE(parse_jni_name("Java_x"));
}

TEST(Android, Values) {
  EXPECT_EQ(format_value({0x12, 1}), "true");
  EXPECT_EQ(format_value({0x10, 0xffffffffu}), "-1");
  EXPECT_EQ(format_value({0x11, 0x20}), "0x20");
  EXPECT_EQ(format_value({0x05, (16u << 8) | 1}), "16.0dip");
  EXPECT_EQ(format_value({0x05, (3u << 8) | 0x10 | 0}), "0.0234375px");  // radix 16p7: 3/128
  EXPECT_EQ(format_value({0x06, (1u << 8) | 0x30 | 1}), "1.19209e-05%p");
  EXPECT_EQ(format_value({0x1d, 0xff102030}), "#102030");
  EXPECT_EQ(format_value({0x01, 0}), "@null");
  EXPECT_EQ(format_value({0x01, 0x7f020000}), "@0x7f020000");
  EXPECT_EQ(format_value({0x02, 0x01010000}), "?0x01010000");
  float f = 1.5f;
  std::uint32_t bits;
  std::memcpy(&bits, &f, 4);
  EXPECT_EQ(format_value({0x04, bits}), "1.5");
  EXPECT_EQ(framework_attribute(0x0101021b), "versionCode");
  EXPECT_EQ(framework_attribute(0x01010003), "name");
  EXPECT_EQ(framework_attribute(0x7f010000), "");
}

TEST(Android, Configurations) {
  auto cfg = [](std::initializer_list<std::pair<int, int>> bytes) {
    std::vector<std::byte> c(64);
    c[0] = std::byte{64};
    for (auto [o, v] : bytes) c[o] = std::byte(v);
    return config_qualifiers(c);
  };
  EXPECT_EQ(cfg({}), "");
  EXPECT_EQ(cfg({{8, 'e'}, {9, 'n'}, {10, 'U'}, {11, 'S'}}), "en-rUS");
  EXPECT_EQ(cfg({{29, 0x20}, {14, 0xe0}, {15, 0x01}}), "night-xxhdpi");
  EXPECT_EQ(cfg({{12, 2}, {24, 21}}), "land-v21");
  EXPECT_EQ(cfg({{30, 0x58}, {31, 0x02}, {28, 0x80}}), "ldrtl-sw600dp");
  EXPECT_EQ(cfg({{4, 0x36}, {5, 0x01}, {6, 0x0a}}), "mcc310-mnc10");
  EXPECT_EQ(cfg({{8, 'z'}, {9, 'h'}, {36, 'H'}, {37, 'a'}, {38, 'n'}, {39, 's'}}), "b+zh+Hans");
  // A configuration that says it is shorter than its fields: the rest are zero.
  std::vector<std::byte> c(64, std::byte{0x7f});
  c[0] = std::byte{8};
  c[1] = c[2] = c[3] = std::byte{0};
  EXPECT_EQ(config_qualifiers(c), "mcc32639-mnc32639");
}

// Hostile bytes: every parser either throws Error or returns, on every
// truncation and on random byte flips of a real file.
template <class Fn>
void Hostile(const std::vector<std::byte> &good, Fn &&parse) {
  for (std::size_t n = 0; n < good.size(); n += std::max<std::size_t>(1, good.size() / 400)) {
    std::vector<std::byte> t(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(n));
    try {
      parse(t);
    } catch (const Error &) {
    }
  }
  std::mt19937 rng(1234);
  for (int i = 0; i < 400; ++i) {
    std::vector<std::byte> t = good;
    for (int k = 0; k < 1 + i % 8; ++k) t[rng() % t.size()] = std::byte(rng() & 0xff);
    try {
      parse(t);
    } catch (const Error &) {
    }
  }
}

TEST(Android, HostileInput) {
  auto a = make("", false);
  if (!a) GTEST_SKIP();
  auto table = read_apk_resources(*a->layer);
  ASSERT_TRUE(table);
  Hostile(a->layer->read("AndroidManifest.xml", 1 << 20), [&](const std::vector<std::byte> &b) {
    const XmlDocument d = decode_xml(b, &*table);
    read_manifest(d, &*table);
    (void)d.to_xml(true);
  });
  Hostile(a->layer->read("resources.arsc", 1 << 20), [](const std::vector<std::byte> &b) {
    const ResourceTable t = parse_resource_table(b);
    for (const auto &[id, _] : t.index) (void)t.resolve({0x01, id});
  });
  Hostile(a->layer->read("classes.dex", 1 << 20), [](const std::vector<std::byte> &b) { parse_dex(b); });
  Hostile(a->layer->read("lib/x86_64/libnative.so", 1 << 20), [](const std::vector<std::byte> &b) {
    parse_elf(b);
    read_flutter_app(b);
  });
  // A self-referencing reference doesn't loop.
  ResourceTable t = parse_resource_table(a->layer->read("resources.arsc", 1 << 20));
  t.packages[0].types[1].entries[0].value = {0x01, t.packages[0].types[1].entries[0].id};
  EXPECT_EQ(t.resolve({0x01, t.packages[0].types[1].entries[0].id}), "");
}

// Bug scrub part 3: a string pool's offsets, and a document's attributes,
// may all name one long string. What they decode and copy is budgeted, so
// a few hundred kilobytes don't expand to gigabytes.
namespace hostile {
void u16(std::vector<std::byte> &b, std::uint32_t v) {
  b.push_back(std::byte(v & 0xff));
  b.push_back(std::byte(v >> 8 & 0xff));
}
void u32(std::vector<std::byte> &b, std::uint32_t v) {
  u16(b, v & 0xffff);
  u16(b, v >> 16);
}
void put32(std::vector<std::byte> &b, std::size_t at, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) b[at + i] = std::byte(v >> (8 * i) & 0xff);
}
// A UTF-8 pool of `count` strings, every offset naming one string of `len` 'a's.
std::vector<std::byte> pool(std::uint32_t count, std::uint32_t len) {
  std::vector<std::byte> b;
  u16(b, 0x0001);
  u16(b, 28);
  u32(b, 0);  // size, below
  u32(b, count);
  u32(b, 0);
  u32(b, 0x100);  // UTF-8
  u32(b, 28 + 4 * count);
  u32(b, 0);
  for (std::uint32_t i = 0; i < count; ++i) u32(b, 0);
  for (int twice = 0; twice < 2; ++twice) {  // UTF-16 length, then UTF-8 length
    b.push_back(std::byte(0x80 | (len >> 8 & 0x7f)));
    b.push_back(std::byte(len & 0xff));
  }
  b.insert(b.end(), len, std::byte{'a'});
  b.push_back(std::byte{0});
  while (b.size() % 4) b.push_back(std::byte{0});
  put32(b, 4, static_cast<std::uint32_t>(b.size()));
  return b;
}
void element(std::vector<std::byte> &b, std::uint16_t attributes) {
  const std::size_t start = b.size();
  u16(b, 0x0102);
  u16(b, 16);
  u32(b, 0);
  u32(b, 1);
  u32(b, 0xffffffffu);
  u32(b, 0xffffffffu);  // ns
  u32(b, 0);            // name
  u16(b, 20);
  u16(b, 20);
  u16(b, attributes);
  u16(b, 0);
  u16(b, 0);
  u16(b, 0);
  for (std::uint16_t i = 0; i < attributes; ++i) {
    u32(b, 0xffffffffu);
    u32(b, 0);  // name
    u32(b, 0);  // raw value
    u16(b, 8);
    b.push_back(std::byte{0});
    b.push_back(std::byte{0x03});  // a string
    u32(b, 0);
  }
  put32(b, start + 4, static_cast<std::uint32_t>(b.size() - start));
}
void end_element(std::vector<std::byte> &b) {
  u16(b, 0x0103);
  u16(b, 16);
  u32(b, 24);
  u32(b, 1);
  u32(b, 0xffffffffu);
  u32(b, 0xffffffffu);
  u32(b, 0);
}
}  // namespace hostile

TEST(Android, AliasedStringsAreBudgeted) {
  // 50,000 offsets to one 30,000-byte string: 1.5 GB decoded in full.
  const std::vector<std::byte> p = hostile::pool(50000, 30000);
  std::vector<std::string> warnings;
  const StringPool sp = parse_string_pool(p, &warnings);
  std::uint64_t total = 0;
  for (const std::string &x : sp.strings) total += x.size();
  EXPECT_LE(total, 4ull * p.size() + (1u << 20) + 30000);
  EXPECT_EQ(sp.strings[0].size(), 30000u);
  EXPECT_FALSE(warnings.empty());
  // A document whose 4,096 attributes per element each copy one 30,000-byte
  // string three times: 370 MB an element.
  auto doc = [](std::uint16_t attributes) {
    std::vector<std::byte> x;
    hostile::u16(x, 0x0003);
    hostile::u16(x, 8);
    hostile::u32(x, 0);
    const std::vector<std::byte> one = hostile::pool(1, 30000);
    x.insert(x.end(), one.begin(), one.end());
    hostile::element(x, 0);
    for (int i = 0; i < 4; ++i) {
      hostile::element(x, attributes);
      hostile::end_element(x);
    }
    hostile::end_element(x);
    hostile::put32(x, 4, static_cast<std::uint32_t>(x.size()));
    return x;
  };
  const XmlDocument d = decode_xml(doc(1));  // the same shape, small: it reads
  EXPECT_EQ(d.to_xml().size() > 4 * 30000, true);
  EXPECT_THROW(decode_xml(doc(4096)), Error);
}

TEST(Android, NotAnApk) {
  TempDir d;
  if (!sh("cd " + (d / "").string() + " && echo hi > a.txt && zip -q x.zip a.txt")) GTEST_SKIP();
  auto s = container::Session::open(container::open_host_file((d / "x.zip").string()), "x.zip", container::Limits{});
  EXPECT_THROW(ApkLayer::open(s, ""), container::Error);
}

}  // namespace
}  // namespace revkit::android
