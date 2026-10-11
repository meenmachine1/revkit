// Finding a PE's PDB on a symbol path (docs/pdb.md "Symbol servers"):
// _NT_SYMBOL_PATH's syntax, local symbol stores, HTTP(S) symbol servers
// (msdl.microsoft.com's protocol) with a download cache, and .pd_ files
// (cabinets, MSZIP or stored).
//
// Downloads are network access the daemon does on its user's behalf: they
// happen only when SymbolSettings::downloads is set (off by default; the
// admin role sets it, docs/security.md), and only for the entries of the
// path that name a server.
#pragma once

#include "revkit/debuginfo/pdb.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::backend {

// One element of a symbol path.
struct SymbolPathEntry {
  enum class Kind : std::uint8_t {
    directory,  // a plain directory: <dir>/<name>, and a store's <dir>/<name>/<key>/<name>
    server,     // srv*[cache*]url: an HTTP(S) server, files cached in `cache`
    store,      // srv*dir (a local or UNC store) or cache*dir
  };
  Kind kind = Kind::directory;
  std::string location;  // the directory, store or URL
  std::string cache;     // server: where downloads go ("" = the settings' default cache)

  friend bool operator==(const SymbolPathEntry &, const SymbolPathEntry &) = default;
};

// Parses _NT_SYMBOL_PATH syntax: entries separated by ';', each
// "srv*[cache*]location" (with "symsrv*symsrv.dll*" accepted as srv*),
// "cache*dir", or a directory. Empty entries are skipped. Errors (an
// srv* with nothing after it) set `error` and return what parsed.
std::vector<SymbolPathEntry> ParseSymbolPath(std::string_view path, std::string *error = nullptr);

struct SymbolSettings {
  std::string path;           // _NT_SYMBOL_PATH syntax
  bool downloads = false;     // may contact servers (off by default)
  std::string default_cache;  // a server entry without its own cache
  std::uint64_t max_bytes = std::uint64_t{2} << 30;  // the largest PDB fetched
  int timeout_seconds = 60;
};

// The symbol store key of a PDB: its GUID as 32 upper-case hex digits
// (Data1, Data2, Data3 as numbers, then Data4's bytes) and its age in hex,
// "F04F0324582AFEB24C4C44205044422E1".
std::string SymbolKey(const debuginfo::PdbGuid &guid, std::uint32_t age);

struct FoundPdb {
  std::filesystem::path file;  // a local file: a store's, or the cache's copy
  std::string source;          // "store D:\sym", "server https://..." (for messages)
  bool downloaded = false;
};

// Looks `name` (the CodeView record's file name, any directory dropped)
// with `guid` and `age` up along the path, in order: in each directory
// and store, then (with downloads on) on each server, through its cache.
// A .pd_ is expanded next to where it was found (or into the cache).
// `log` gets one line per place tried. Throws nothing; nullopt when
// nothing matched.
std::optional<FoundPdb> FindPdb(const SymbolSettings &settings, std::string_view name, const debuginfo::PdbGuid &guid,
                                std::uint32_t age, std::vector<std::string> &log);

// Expands a cabinet holding one file (a .pd_: stored or MSZIP-compressed
// folders; LZX and Quantum are refused) into `out`. Returns "" or the
// reason it can't.
std::string ExpandCabinet(std::string_view cab, std::string &out, std::uint64_t max_bytes = std::uint64_t{2} << 30);

}  // namespace revkit::backend
