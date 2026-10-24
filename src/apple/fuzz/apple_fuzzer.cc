// libFuzzer target for one revkit::apple reader, named by RK_FUZZ_TARGET:
// "plist" (XML and binary property lists), "codesign" (an embedded code
// signature SuperBlob), "provision" (a provisioning profile's CMS), "nib"
// (a compiled nib, NIBArchive or keyed archive, as an object graph; a
// keyed archive's resolve()).
#include "revkit/apple/bundle.hh"
#include "revkit/apple/codesign.hh"
#include "revkit/apple/ib.hh"
#include "revkit/apple/plist.hh"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  const auto in = std::as_bytes(std::span(data, size));
  revkit::apple::Limits limits;
  limits.max_values = 1u << 16;
  limits.max_value_bytes = 16u << 20;
  try {
    if (std::strcmp(RK_FUZZ_TARGET, "plist") == 0) {
      const auto p = revkit::apple::parse(in, limits);
      (void)revkit::apple::bundle_info(p.root);
      (void)revkit::apple::to_xml(p.root);
    } else if (std::strcmp(RK_FUZZ_TARGET, "codesign") == 0) {
      (void)revkit::apple::parse_code_signature(in);
    } else if (std::strcmp(RK_FUZZ_TARGET, "provision") == 0) {
      (void)revkit::apple::parse_provisioning_profile(in, limits);
    } else if (std::strcmp(RK_FUZZ_TARGET, "nib") == 0) {
      (void)revkit::apple::read_interface_builder(in, limits);
      if (revkit::apple::sniff(in)) {
        const auto p = revkit::apple::parse(in, limits);
        if (revkit::apple::KeyedArchive::is_keyed_archive(p.root))
          (void)revkit::apple::KeyedArchive(p.root).resolve(1u << 16);
      }
    }
  } catch (const revkit::apple::Error &) {
  }
  return 0;
}
