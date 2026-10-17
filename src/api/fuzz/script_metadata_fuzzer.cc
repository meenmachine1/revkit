// A script's metadata comment block (ParseScriptMetadata: @name, @category,
// @arg lists with std::regex), read by ListScripts from every script in
// the shipped, user and project libraries. It had a stack-use-after-scope
// on any "@arg [a|b]" list (docs/bug-scrub.md).
#include "script_service.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size > (64u << 10)) return 0;  // ListScripts reads the header only
  const auto meta =
      revkit::api::ParseScriptMetadata(std::string_view(reinterpret_cast<const char *>(data), size), "fuzz");
  std::size_t n = meta.name.size();
  for (const auto &a : meta.args) n += a.name.size();
  return n == 0xffffffff;
}
