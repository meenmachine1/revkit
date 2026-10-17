// Assertion values decoded from project archives and peers (the archive
// only checks their framing; these decoders read the text): data settings
// (DataSettings::parse, a NOTE with a reserved tag) and register values
// (parse_register_value_sub and _text, a REGISTER_VALUE key and value).
// A parsed data setting must encode to text that parses back the same.
// Input: a selector byte, then the text.
#include "data_settings.h"

#include "revkit/analysis/register_values.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  if (size < 1) return 0;
  const std::string_view text(reinterpret_cast<const char *>(data + 1), size - 1);
  switch (data[0] % 3) {
    case 0: {
      (void)backend::IsDataSettingsTag(text);
      if (auto s = backend::DataSettings::parse(text)) {
        const std::string again = s->encode();
        auto back = backend::DataSettings::parse(again);
        if (!again.empty() && (!back || back->encode() != again)) std::abort();
      }
      break;
    }
    case 1: (void)analysis::parse_register_value_sub(text); break;
    case 2: (void)analysis::parse_register_value_text(text); break;
  }
  return 0;
}
