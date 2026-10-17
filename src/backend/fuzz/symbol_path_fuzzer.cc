// The symbol path (ParseSymbolPath: srv*cache*url;dir;cache*dir...) and the
// name handling of FindPdb: a CodeView record's PDB path, from the binary,
// reduced to a file name the stores and servers are asked for. The input
// is the path, a NUL, then the name. FindPdb gets an empty path, so it
// touches no file and no server.
#include "symbol_server.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit::backend;
  const std::string_view in(reinterpret_cast<const char *>(data), size);
  const std::size_t nul = in.find('\0');
  const std::string_view path = in.substr(0, nul), name = nul == std::string_view::npos ? "" : in.substr(nul + 1);
  std::string error;
  for (const SymbolPathEntry &e : ParseSymbolPath(path, &error)) (void)e.location.size();
  SymbolSettings s;
  s.path = "";
  s.downloads = false;
  std::vector<std::string> log;
  revkit::debuginfo::PdbGuid guid{};
  (void)FindPdb(s, name, guid, size, log);
  return 0;
}
