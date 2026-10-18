// Bytecode and script formats (docs/bytecode-lifting.md): what their headers
// say, for identification (identify.cc) and for the packers' containers
// (pyinstaller.cc restores .pyc headers). Internal.
#pragma once

#include "revkit/container/container.hh"

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace revkit::container::detail {

// A CPython version, from a .pyc magic number (the two bytes before "\r\n").
struct PyVersion {
  int major = 0, minor = 0;
  std::string str() const { return std::to_string(major) + "." + std::to_string(minor); }
};
std::optional<PyVersion> pyc_version(std::uint16_t magic);
// The magic of a version's final release (3.12: 3531), for writing a .pyc
// header when only the version is known; 0 when there is none in the table.
std::uint16_t pyc_release_magic(PyVersion v);
// Bytes of a .pyc header: 8 (magic, mtime) before 3.3, 12 (and the source
// size) to 3.6, 16 (and the PEP 552 flags) from 3.7.
std::size_t pyc_header_size(PyVersion v);
// A .pyc header for marshalled code of that magic: zero flags, mtime and
// size (a header the interpreter's own loader accepts, unchecked).
std::vector<std::byte> pyc_header(std::uint16_t magic);

// A bytecode or compiled-script file named by its header: kind "bytecode",
// with its content kind ("pyc:3.12", "lua:5.4", "java-class:21", ...).
std::optional<Guess> bytecode_guess(std::span<const std::byte> head, std::uint64_t size);

// A PE's CLR header, when the head holds it: " .NET assembly (IL-only,
// metadata v4.0.30319)" to append to the PE's description, and the content
// kind ("dotnet:il" or "dotnet:mixed"). Empty when it has none.
struct DotNetHead {
  std::string description;
  std::string content_kind;
};
std::optional<DotNetHead> dotnet_head(std::span<const std::byte> head, std::uint32_t pe_offset);

// A zip's first members (the local headers the head holds): "apk" for an
// Android package, "jar" for a Java archive, "" otherwise.
std::string zip_content_kind(std::span<const std::byte> head);

// A Lua or LuaJIT chunk's header at `at` (docs/filesystems.md, the carver):
// the version and the sizes it declares. nullopt when the bytes there aren't
// a header this reader accepts.
struct LuaHeader {
  bool luajit = false;
  int version = 0;        // 0x51..0x55; LuaJIT: 1 (2.0) or 2 (2.1)
  std::size_t size = 0;   // header bytes (up to the main function)
  int int_size = 0, size_t_size = 0, instruction_size = 0, integer_size = 0, number_size = 0;
  bool integral = false;  // 5.1 and 5.2: lua_Number is an integer type
  bool big_endian = false;
  std::uint32_t luajit_flags = 0;  // BCDUMP_F_*: 1 BE, 2 STRIP, 4 FFI, 8 FR2
  std::string content_kind() const;  // "lua:5.4", "luajit:2.1"
  std::string description() const;   // "Lua 5.4 chunk", "LuaJIT 2.1 bytecode (stripped)"
};
std::optional<LuaHeader> lua_header(std::span<const std::byte> b, std::size_t at = 0);
// The length of the whole chunk whose header is `h` at `at` (its functions
// walked), or nullopt when it doesn't parse within `b`.
std::optional<std::size_t> lua_chunk_length(std::span<const std::byte> b, std::size_t at, const LuaHeader &h);

}  // namespace revkit::container::detail
