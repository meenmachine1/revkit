// JavaScript packed into native executables (jsexe.cc). Internal.
#pragma once

#include "formats.hh"

namespace revkit::container::detail {

// Each true when the executable carries that packer's payload.
bool node_sea_payload(const Source &src);  // a NODE_SEA_BLOB note, resource or section
bool pkg_payload(const Source &src);       // pkg's prelude near the end
bool nexe_payload(const Source &src);      // "<nexe~~sentinel>" in the last 16000 bytes
bool bun_payload(const Source &src);       // "\n---- Bun! ----\n" ending its module graph

std::shared_ptr<FileSystem> open_node_sea(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx);
std::shared_ptr<FileSystem> open_pkg(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx);
std::shared_ptr<FileSystem> open_nexe(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx);
std::shared_ptr<FileSystem> open_bun(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx);

}  // namespace revkit::container::detail
