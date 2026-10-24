// libFuzzer harness for revkit::android, one target per parser
// (RK_FUZZ_FORMAT): binary XML (decoded, read as a manifest, printed),
// resources.arsc (parsed, every id resolved and named), DEX, and ELF (the
// exports, and Flutter's snapshot headers and engine strings).
#include "revkit/android/android.hh"

#include <cstring>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::android;
  const Bytes b(reinterpret_cast<const std::byte *>(data), size);
  constexpr std::string_view format = RK_FUZZ_FORMAT;
  try {
    if (format == "axml") {
      const XmlDocument d = decode_xml(b);
      const Manifest m = read_manifest(d);
      (void)d.to_xml(true);
      (void)m;
    } else if (format == "arsc") {
      const ResourceTable t = parse_resource_table(b);
      for (const auto &[id, _] : t.index) {
        (void)t.resolve({0x01, id});
        (void)t.name_of(id);
      }
      // The table resolving a document's references too.
      if (size > 64) {
        try {
          (void)decode_xml(b.subspan(size / 2), &t).to_xml(true);
        } catch (const Error &) {
        }
      }
    } else if (format == "dex") {
      const DexFile d = parse_dex(b);
      for (const DexMethod &m : d.native_methods) (void)parse_jni_name(jni_long_name(m.class_name, m.name, m.descriptor));
    } else if (format == "elf") {
      (void)parse_elf(b);
      try {
        (void)read_flutter_app(b);
      } catch (const Error &) {
      }
      (void)read_flutter_engine(b);
    } else if (format == "jni") {
      (void)parse_jni_name(std::string_view(reinterpret_cast<const char *>(data), size));
      (void)config_qualifiers(b);
    }
  } catch (const Error &) {
  }
  return 0;
}
