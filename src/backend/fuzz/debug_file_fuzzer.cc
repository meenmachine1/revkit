// External debug files (debug_files.cc) from untrusted bytes: a binary's
// .gnu_debuglink and GNU build ID as the loader reads them, a file found
// beside it, in a directory or downloaded from a debuginfod server checked
// against them (CheckDebugFile: an ELF with .debug_info whose build ID or
// CRC-32 is the program's), and a debuginfod URL as settings take it.
// Input: a flags byte, a URL up to the first NUL, then the ELF. The
// program's identity is the file's own (so the match path runs) or, with
// flag 1, a different one (the mismatch path).
#include "debug_files.h"

#include "revkit/loader/load.hh"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using namespace revkit;
  if (size < 1) return 0;
  const std::uint8_t flags = data[0];
  const std::string_view rest(reinterpret_cast<const char *>(data + 1), size - 1);
  const std::size_t nul = rest.find('\0');
  (void)backend::CheckDebuginfodUrl(rest.substr(0, nul), flags & 2);
  const std::string_view elf = nul == std::string_view::npos ? std::string_view() : rest.substr(nul + 1);
  auto bytes = std::make_shared<loader::Bytes>(elf.size());
  for (std::size_t i = 0; i < elf.size(); ++i) (*bytes)[i] = std::byte(static_cast<unsigned char>(elf[i]));
  backend::DebugFileQuery q;
  try {
    const loader::Image img = loader::parse_elf(bytes);
    q.build_id = img.build_id;
    q.link = backend::ReadDebugLink(img);
  } catch (const loader::LoadError &) {
  }
  if (flags & 1) {
    q.build_id = q.build_id.empty() ? "0123456789abcdef" : "";
    if (!q.link) q.link = backend::DebugLink{"x.debug", 0x12345678u};
  }
  (void)backend::CheckDebugFile(bytes, q);
  (void)backend::DebugLinkCrc(*bytes);
  return 0;
}
