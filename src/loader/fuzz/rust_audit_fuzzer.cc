// cargo-auditable dependency lists (buildinfo.hh) on hostile bytes. An
// even first byte compresses the rest first, so the JSON reader sees the
// fuzzer's bytes; an odd one hands them to zlib as they are.
#include "revkit/loader/buildinfo.hh"

#include <zlib.h>

#include <vector>

using namespace revkit::loader;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size == 0) return 0;
  const bool raw = data[0] & 1;
  ++data;
  --size;
  std::vector<std::byte> in;
  if (raw) {
    in.assign(reinterpret_cast<const std::byte *>(data), reinterpret_cast<const std::byte *>(data) + size);
  } else {
    uLongf n = compressBound(static_cast<uLong>(size));
    in.resize(n);
    if (compress2(reinterpret_cast<Bytef *>(in.data()), &n, data, static_cast<uLong>(size), 1) != Z_OK) return 0;
    in.resize(n);
  }
  std::string error;
  auto r = parse_rust_audit(in, &error);
  if (r)
    for (const RustPackage &p : r->packages)
      for (std::uint32_t d : p.dependencies) (void)r->packages.at(d).name.size();
  return 0;
}
