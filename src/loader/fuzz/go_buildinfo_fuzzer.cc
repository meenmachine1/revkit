// Go build info (buildinfo.hh) on hostile bytes. The first byte picks the
// path: the header search and decode over the input as memory (both
// formats; pointers resolve inside the input), the module-text parser on
// the input as text, or an ELF or PE parsed and read whole
// (read_build_metadata: the Go and Rust readers, .comment, rustc paths).
#include "revkit/loader/buildinfo.hh"
#include "revkit/loader/load.hh"

#include <cstring>
#include <memory>

using namespace revkit::loader;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size == 0) return 0;
  const std::uint8_t mode = data[0] % 3;
  ++data;
  --size;
  if (mode == 0) {
    constexpr std::uint64_t kBase = 0x10000;
    ReadMemoryFn read = [&](std::uint64_t a, std::span<std::byte> out) -> std::size_t {
      std::memset(out.data(), 0, out.size());
      if (a < kBase || a - kBase >= size) return 0;
      const std::size_t off = std::size_t(a - kBase), n = std::min(out.size(), size - off);
      std::memcpy(out.data(), data + off, n);
      return n;
    };
    std::string error;
    auto g = find_go_buildinfo(read, kBase, size, {}, &error);
    if (g) (void)g->setting("GOOS");
  } else if (mode == 1) {
    GoBuildInfo g;
    parse_go_module_text(std::string_view(reinterpret_cast<const char *>(data), size), g);
  } else {
    auto bytes = std::make_shared<Bytes>(size);
    if (size) std::memcpy(bytes->data(), data, size);
    try {
      Image img = parse(bytes);
      BuildMetadata m = read_build_metadata(img);
      (void)m.empty();
    } catch (const LoadError &) {
    }
  }
  return 0;
}
