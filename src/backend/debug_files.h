// Separate debug files for ELF (docs/backend.md#debug-info, "External debug
// files"): the file a stripped binary's debug info went to, found by its
// GNU build ID (<dir>/.build-id/xx/yyyy.debug) or its .gnu_debuglink (a
// name and a CRC-32) in the binary's directory, the configured directories
// and the standard one, in a cache of files fetched or loaded before, and
// on debuginfod servers.
//
// debuginfod is network access the daemon does on its user's behalf: only
// when DebugFileSettings::debuginfod is set (off by default; the admin role
// sets it, docs/security.md), over https unless http is allowed too, never
// following a redirect to another host, at most max_bytes a file. What a
// server sends is untrusted: it must be an ELF with the program's build ID
// before it is kept, and the loader and the DWARF reader read it as they
// read any binary.
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::backend {

// A binary's .gnu_debuglink: the debug file's name and its CRC-32.
struct DebugLink {
  std::string name;
  std::uint32_t crc = 0;
};

// The image's .gnu_debuglink, if it has one (a bare file name; one with a
// directory or "..", or that doesn't fit its section, is ignored).
std::optional<DebugLink> ReadDebugLink(const loader::Image &image);

// The CRC-32 .gnu_debuglink uses (zlib's, of the whole file).
std::uint32_t DebugLinkCrc(std::span<const std::byte> bytes);

inline constexpr std::string_view kStandardDebugDir = "/usr/lib/debug";

struct DebugFileSettings {
  std::vector<std::string> dirs;  // searched like the standard directory
  // Searched too: kStandardDebugDir (Load debug file's search, not import's).
  bool standard_dirs = true;
  // Fetched and loaded files, by build ID: <cache>/<build id>/debuginfo.
  // "" (a daemon without a project directory): nothing is kept, and
  // nothing is downloaded.
  std::string cache_dir;
  std::uint64_t cache_max_bytes = std::uint64_t{4} << 30;
  bool debuginfod = false;  // may contact servers (off by default)
  std::vector<std::string> urls;
  bool allow_http = false;  // http:// servers too (default: https only)
  std::uint64_t max_bytes = std::uint64_t{1} << 30;  // one file, read or fetched
  int timeout_seconds = 60;
};

// The servers DEBUGINFOD_URLS names (whitespace-separated), for settings to
// suggest; never used unless an admin sets them.
std::vector<std::string> DebuginfodUrlsFromEnv();
// "" or why `url` can't be a server ("https://host[:port][/prefix]").
std::string CheckDebuginfodUrl(std::string_view url, bool allow_http);

struct DebugFileQuery {
  std::string build_id;             // the program's, lower-case hex ("" none)
  std::optional<DebugLink> link;    // its .gnu_debuglink
  std::filesystem::path binary;     // where it was imported from ("" unknown)
};

struct FoundDebugFile {
  std::filesystem::path file;
  std::string source;  // "beside the binary", "directory /x", "cache", "debuginfod https://..."
  bool downloaded = false;
  std::shared_ptr<loader::Bytes> bytes;  // its contents, as checked
};

// Why `bytes` aren't the query's debug file ("" when they are): an ELF
// whose build ID is the program's, or, for a program without one, whose
// CRC-32 is its debuglink's.
std::string CheckDebugFile(const std::shared_ptr<const loader::Bytes> &bytes, const DebugFileQuery &q);

// Where the debug file is looked for, in order: beside the binary (the
// debuglink in its directory and its .debug/), the configured directories
// and (with `standard`) the standard one (.build-id/xx/yyyy.debug, then the
// debuglink under <dir>/<binary's directory>/ and <dir>/), the cache, then,
// with `network` and settings.debuginfod, each server: GET
// <url>/buildid/<id>/debuginfo, kept in the cache. `log` gets a line per
// place tried. Throws nothing.
std::optional<FoundDebugFile> FindDebugFile(const DebugFileSettings &settings, const DebugFileQuery &q, bool standard,
                                            bool network, std::vector<std::string> &log);

// Keeps `bytes` (the debug file of `build_id`) in the cache, then trims the
// cache to its size, oldest first (never the file just kept). Returns the
// cached file, or nullopt (and why in `error`).
std::optional<std::filesystem::path> CacheDebugFile(const DebugFileSettings &settings, std::string_view build_id,
                                                    const loader::Bytes &bytes, std::string *error);

// Reads a local file of at most `max` bytes; null if it can't.
std::shared_ptr<loader::Bytes> ReadDebugFileBytes(const std::filesystem::path &p, std::uint64_t max);

}  // namespace revkit::backend
