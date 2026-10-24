// What a provider input is (revkit::providers::detect_kind): the container
// detector's content kind, a zip's central directory (jar or APK), and
// JavaScript by name and text. The first byte picks the name the file is
// given, so the name-dependent paths run on the same bytes; the rest is the
// file. Every kind answered must be one all_kinds() lists.
#include "revkit/providers/providers.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size == 0) return 0;
  static constexpr std::string_view kNames[] = {"a.bin", "a.js", "a.mjs", "a.jar", "a.apk", "a.pyc", "a.luac",
                                                "a.wasm", "a.dll", "a.dex", "a.class", "", "a.cjs", "A.JS"};
  const std::string_view name = kNames[data[0] % std::size(kNames)];
  const std::span<const std::byte> bytes(reinterpret_cast<const std::byte *>(data + 1), size - 1);
  const revkit::providers::InputKind k = revkit::providers::detect_kind(bytes, name);
  if (k) {
    const auto &all = revkit::providers::all_kinds();
    if (std::find(all.begin(), all.end(), k.kind) == all.end()) __builtin_trap();
  }
  // The content-kind mapping on the bytes as text.
  const std::string_view text(reinterpret_cast<const char *>(data + 1), std::min<std::size_t>(size - 1, 256));
  (void)revkit::providers::kind_from_format(text);
  return 0;
}
