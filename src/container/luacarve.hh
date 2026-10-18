// Lua and LuaJIT chunks carved out of a file (luacarve.cc). Internal.
#pragma once

#include "formats.hh"

#include <functional>
#include <map>

namespace revkit::container::detail {

// At least one chunk that parses, in the file's first 256 MiB.
bool lua_chunks_payload(const Source &src, const std::function<bool()> &cancelled = {});
std::shared_ptr<FileSystem> open_lua_chunks(std::shared_ptr<const Source> src, std::string_view name,
                                            const Context &ctx);

}  // namespace revkit::container::detail
