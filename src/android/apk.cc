// A whole APK: the manifest decoded against the package's resource table,
// the native libraries by ABI with their JNI exports, the DEX files' native
// methods linked to the libraries that export them, and Flutter's snapshot
// hash per ABI. Written for revkit.
#include "reader.hh"

#include <algorithm>
#include <set>
#include <unordered_map>

namespace revkit::android {

namespace {

const std::vector<std::byte> *read_into(ApkFiles &files, const std::string &path, std::uint64_t max,
                                        std::vector<std::byte> &buf, std::vector<std::string> &warnings) {
  try {
    buf = files.read(path, max);
    return &buf;
  } catch (const std::exception &e) {
    warnings.push_back(path + ": " + e.what());
    return nullptr;
  }
}

bool dex_name(const std::string &p) {
  // classes.dex, classes2.dex, ... at the root.
  if (p.find('/') != std::string::npos || !p.starts_with("classes") || !p.ends_with(".dex")) return false;
  const std::string mid = p.substr(7, p.size() - 11);
  return std::all_of(mid.begin(), mid.end(), [](char c) { return c >= '0' && c <= '9'; });
}

}  // namespace

std::optional<ResourceTable> read_apk_resources(ApkFiles &files, const ApkLimits &limits) {
  if (!files.size("resources.arsc")) return std::nullopt;
  const std::vector<std::byte> b = files.read("resources.arsc", limits.max_file_bytes);
  return parse_resource_table(b);
}

ApkInfo describe_apk(ApkFiles &files, const ApkLimits &limits) {
  ApkInfo info;
  std::vector<std::byte> buf;
  if (files.size("resources.arsc")) {
    if (read_into(files, "resources.arsc", limits.max_file_bytes, buf, info.warnings)) {
      try {
        info.resources = parse_resource_table(buf);
        info.has_resources = true;
        for (const std::string &w : info.resources.warnings) info.warnings.push_back("resources.arsc: " + w);
      } catch (const Error &e) {
        info.warnings.push_back(std::string("resources.arsc: ") + e.what());
      }
    }
  }
  if (files.size("AndroidManifest.xml")) {
    if (read_into(files, "AndroidManifest.xml", limits.max_file_bytes, buf, info.warnings)) {
      try {
        info.manifest_xml = decode_xml(buf, info.has_resources ? &info.resources : nullptr);
        info.has_manifest = true;
        info.manifest = read_manifest(info.manifest_xml, info.has_resources ? &info.resources : nullptr);
        for (const std::string &w : info.manifest_xml.warnings) info.warnings.push_back("AndroidManifest.xml: " + w);
        for (const std::string &w : info.manifest.warnings) info.warnings.push_back("AndroidManifest.xml: " + w);
      } catch (const Error &e) {
        info.warnings.push_back(std::string("AndroidManifest.xml: ") + e.what());
      }
    }
  } else {
    info.warnings.push_back("no AndroidManifest.xml at the package's root");
  }
  std::vector<std::string> names = files.list();
  std::sort(names.begin(), names.end());
  std::uint64_t read_total = 0;
  auto budget = [&](const std::string &path, std::uint64_t size) {
    if (size > limits.max_file_bytes) {
      info.warnings.push_back(path + ": larger than " + std::to_string(limits.max_file_bytes >> 20) + " MiB; not read");
      return false;
    }
    if (read_total + size > limits.max_total_bytes) {
      info.warnings.push_back(path + ": over the read budget; not read");
      return false;
    }
    read_total += size;
    return true;
  };
  // Native libraries: lib/<abi>/<name>.so.
  std::set<std::string> abis;
  for (const std::string &p : names) {
    if (!p.starts_with("lib/")) continue;
    const auto slash = p.find('/', 4);
    if (slash == std::string::npos || slash == 4 || p.find('/', slash + 1) != std::string::npos) continue;
    const std::string name = p.substr(slash + 1);
    if (name.empty() || !name.ends_with(".so")) continue;
    if (info.libraries.size() >= limits.max_libraries) {
      info.warnings.push_back("more than " + std::to_string(limits.max_libraries) + " native libraries; the rest are left out");
      break;
    }
    NativeLibrary lib;
    lib.abi = p.substr(4, slash - 4);
    lib.path = p;
    lib.name = name;
    lib.size = files.size(p).value_or(0);
    abis.insert(lib.abi);
    if (name == "libflutter.so") lib.flutter = "engine";
    else if (name == "libapp.so") lib.flutter = "app";
    if (limits.native && budget(p, lib.size)) {
      try {
        const std::vector<std::byte> b = files.read(p, limits.max_file_bytes);
        const ElfInfo elf = parse_elf(b);
        lib.machine = elf.machine_name;
        lib.elf_abi = elf.abi;
        lib.soname = elf.soname;
        lib.build_id = elf.build_id;
        lib.needed = elf.needed;
        lib.exports = elf.exports.size();
        for (const ElfSymbol &s : elf.exports) {
          if (s.name == "JNI_OnLoad") lib.jni_onload = true;
          if (s.name.starts_with("Java_")) {
            if (lib.jni_exports.size() < limits.max_jni_exports) lib.jni_exports.push_back(s.name);
          }
        }
        std::sort(lib.jni_exports.begin(), lib.jni_exports.end());
        if (!elf.abi.empty() && elf.abi != lib.abi && !(lib.abi == "armeabi" && elf.abi == "armeabi-v7a"))
          info.warnings.push_back(p + ": its header says " + elf.abi);
        if (lib.flutter == "app" || lib.flutter == "engine") {
          auto it = std::find_if(info.flutter_abis.begin(), info.flutter_abis.end(), [&](const FlutterAbi &f) { return f.abi == lib.abi; });
          if (it == info.flutter_abis.end()) {
            info.flutter_abis.push_back({});
            it = info.flutter_abis.end() - 1;
            it->abi = lib.abi;
          }
          if (lib.flutter == "app") {
            it->libapp = p;
            it->app = read_flutter_app(b);
          } else {
            it->libflutter = p;
            it->engine = read_flutter_engine(b);
          }
        }
      } catch (const std::exception &e) {
        lib.error = e.what();
      }
    }
    info.libraries.push_back(std::move(lib));
  }
  info.abis.assign(abis.begin(), abis.end());
  // Flutter: detected by its libraries; the hash where every ABI agrees.
  std::set<std::string> hashes;
  for (const NativeLibrary &l : info.libraries)
    if (!l.flutter.empty()) info.flutter = true;
  for (FlutterAbi &f : info.flutter_abis) {
    if (!f.app.snapshot_hash.empty()) hashes.insert(f.app.snapshot_hash);
    if (f.libapp.empty()) info.warnings.push_back("lib/" + f.abi + " has libflutter.so but no libapp.so");
    if (f.libflutter.empty()) info.warnings.push_back("lib/" + f.abi + " has libapp.so but no libflutter.so");
  }
  if (hashes.size() == 1) info.snapshot_hash = *hashes.begin();
  else if (hashes.size() > 1) info.warnings.push_back("the ABIs' Dart snapshot hashes differ");
  // DEX: native methods, linked to the libraries exporting their names.
  if (limits.dex) {
    std::unordered_map<std::string, std::vector<std::string>> exported;
    for (const NativeLibrary &l : info.libraries)
      for (const std::string &s : l.jni_exports) exported[s].push_back(l.path);
    for (const std::string &p : names) {
      if (!dex_name(p)) continue;
      if (info.dex.size() >= limits.max_dex_files) {
        info.warnings.push_back("more than " + std::to_string(limits.max_dex_files) + " DEX files; the rest are left out");
        break;
      }
      const std::uint64_t size = files.size(p).value_or(0);
      if (!budget(p, size)) continue;
      try {
        const std::vector<std::byte> b = files.read(p, limits.max_file_bytes);
        DexFile d = parse_dex(b);
        for (const DexMethod &m : d.native_methods) {
          NativeMethodLink link;
          link.method = m;
          link.dex = p;
          link.short_name = jni_short_name(m.class_name, m.name);
          link.long_name = jni_long_name(m.class_name, m.name, m.descriptor);
          for (const std::string *n : {&link.long_name, &link.short_name})
            if (auto it = exported.find(*n); it != exported.end())
              for (const std::string &lib : it->second)
                if (std::find(link.libraries.begin(), link.libraries.end(), lib) == link.libraries.end()) link.libraries.push_back(lib);
          info.native_methods.push_back(std::move(link));
        }
        for (const std::string &w : d.warnings) info.warnings.push_back(p + ": " + w);
        d.native_methods.clear();
        info.dex.emplace_back(p, std::move(d));
      } catch (const std::exception &e) {
        info.warnings.push_back(p + ": " + e.what());
      }
    }
  }
  return info;
}

}  // namespace revkit::android
