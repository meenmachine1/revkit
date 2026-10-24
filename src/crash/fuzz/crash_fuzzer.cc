// libFuzzer harness for revkit::crash (RK_FUZZ_FORMAT "elf-core" or
// "minidump"): the dump parsed, and every thread's stack and pc read back.
#include "revkit/crash/crash.hh"

#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::crash;
  const Bytes b(reinterpret_cast<const std::byte *>(data), size);
  constexpr std::string_view format = RK_FUZZ_FORMAT;
  try {
    const CrashDump d = format == "minidump" ? parse_minidump(b) : parse_elf_core(b);
    std::uint8_t buf[256];
    std::vector<std::pair<std::uint32_t, std::uint32_t>> missing;
    for (const Thread &t : d.threads)
      for (const Register &r : t.registers) {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < r.value.size() && i < 8; ++i) v |= std::uint64_t(r.value[i]) << (8 * i);
        missing.clear();
        d.read(b, v, buf, &missing);
        (void)d.module_at(v);
      }
  } catch (const Error &) {
  }
  return 0;
}
