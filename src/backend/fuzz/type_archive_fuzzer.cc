// Type archive sidecars (type_archive.cc): the JSON beside an archive's
// header (ReadTypeArchiveSidecar), its data model as the C parser's target
// (ProfileOf), and a header parsed under that hostile target, as ParseC
// does with archive_sidecar. Input: the sidecar JSON, a NUL, the header.
#include "type_archive.h"

#include "revkit/cparse/cparse.h"
#include "revkit/types/store.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  const std::string in(reinterpret_cast<const char *>(data), size);
  const std::size_t nul = in.find('\0');
  std::string err;
  auto sidecar = backend::ReadTypeArchiveSidecar(in.substr(0, nul), &err);
  if (!sidecar) return 0;
  cparse::Options o;
  o.profile = backend::ProfileOf(sidecar->data_model());
  o.limits.max_bytes = 1 << 20;
  o.limits.max_tokens = 200'000;
  o.limits.max_types = 50'000;
  o.limits.wall_time = std::chrono::milliseconds(2000);
  if (nul == std::string::npos) return 0;
  types::TypeStore store;
  cparse::Source src;
  src.name = "archive.h";
  src.text = in.substr(nul + 1);
  const std::vector<cparse::Source> sources = {src};
  (void)cparse::parse(store, sources, o);
  return 0;
}
