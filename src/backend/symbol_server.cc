#include "symbol_server.h"

#include <httplib.h>
#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>

namespace revkit::backend {

namespace fs = std::filesystem;

namespace {

std::string Trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
  return std::string(s);
}

std::vector<std::string> Split(std::string_view s, char sep) {
  std::vector<std::string> out;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= s.size(); ++i)
    if (i == s.size() || s[i] == sep) {
      out.push_back(Trim(s.substr(start, i - start)));
      start = i + 1;
    }
  return out;
}

bool IsUrl(std::string_view s) { return s.starts_with("http://") || s.starts_with("https://"); }

std::optional<std::string> ReadFile(const fs::path &p, std::uint64_t max) {
  std::error_code ec;
  if (!fs::is_regular_file(p, ec)) return std::nullopt;
  const auto size = fs::file_size(p, ec);
  if (ec || size > max) return std::nullopt;
  std::ifstream in(p, std::ios::binary);
  if (!in) return std::nullopt;
  std::string out(static_cast<std::size_t>(size), '\0');
  in.read(out.data(), static_cast<std::streamsize>(size));
  if (!in) return std::nullopt;
  return out;
}

// Writes atomically (a temporary in the same directory, renamed).
bool WriteFile(const fs::path &p, std::string_view bytes) {
  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  if (ec) return false;
  std::random_device rd;
  const fs::path tmp = p.parent_path() / (p.filename().string() + ".tmp" + std::to_string(rd()));
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!out) {
      fs::remove(tmp, ec);
      return false;
    }
  }
  fs::rename(tmp, p, ec);
  if (ec) {
    fs::remove(tmp, ec);
    return false;
  }
  return true;
}

bool Matches(std::string_view bytes, const debuginfo::PdbGuid &guid, std::uint32_t age) {
  try {
    const debuginfo::PdbIdentity id = debuginfo::read_pdb_identity(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()));
    return id.matches(guid, age);
  } catch (const debuginfo::PdbError &) {
    return false;
  }
}

std::uint32_t U32(std::string_view b, std::size_t at) {
  std::uint32_t v = 0;
  for (int i = 3; i >= 0; --i) v = (v << 8) | static_cast<std::uint8_t>(b[at + static_cast<std::size_t>(i)]);
  return v;
}
std::uint16_t U16(std::string_view b, std::size_t at) {
  return static_cast<std::uint16_t>(static_cast<std::uint8_t>(b[at]) | (static_cast<std::uint8_t>(b[at + 1]) << 8));
}

// A file name the path may use: no directories, nothing odd.
bool SafeName(std::string_view n) {
  if (n.empty() || n.size() > 255 || n == "." || n == "..") return false;
  for (char c : n)
    if (c == '/' || c == '\\' || c == ':' || static_cast<unsigned char>(c) < 0x20) return false;
  return true;
}

}  // namespace

std::vector<SymbolPathEntry> ParseSymbolPath(std::string_view path, std::string *error) {
  std::vector<SymbolPathEntry> out;
  for (const std::string &raw : Split(path, ';')) {
    if (raw.empty()) continue;
    std::vector<std::string> parts = Split(raw, '*');
    std::string head = parts[0];
    std::transform(head.begin(), head.end(), head.begin(), [](unsigned char c) { return std::tolower(c); });
    if (head == "symsrv" && parts.size() >= 2) {  // symsrv*symsrv.dll*...
      parts.erase(parts.begin(), parts.begin() + 2);
      parts.insert(parts.begin(), "srv");
      head = "srv";
    }
    if (head == "srv" || head == "cache") {
      std::vector<std::string> rest(parts.begin() + 1, parts.end());
      rest.erase(std::remove(rest.begin(), rest.end(), std::string()), rest.end());
      if (rest.empty()) {
        if (head == "srv" && error) *error = "\"" + raw + "\" names no store or server";
        continue;
      }
      if (head == "srv" && IsUrl(rest.back())) {
        SymbolPathEntry e;
        e.kind = SymbolPathEntry::Kind::server;
        e.location = rest.back();
        while (!e.location.empty() && e.location.back() == '/') e.location.pop_back();
        if (rest.size() > 1) e.cache = rest.front();
        // The downstream stores are looked in first.
        for (std::size_t i = 0; i + 1 < rest.size(); ++i)
          out.push_back({SymbolPathEntry::Kind::store, rest[i], {}});
        out.push_back(std::move(e));
      } else {
        for (const std::string &r : rest) out.push_back({SymbolPathEntry::Kind::store, r, {}});
      }
      continue;
    }
    if (IsUrl(raw)) {
      out.push_back({SymbolPathEntry::Kind::server, raw, {}});
      continue;
    }
    out.push_back({SymbolPathEntry::Kind::directory, raw, {}});
  }
  // Each location once, in the first place it appears.
  std::vector<SymbolPathEntry> unique;
  for (SymbolPathEntry &e : out)
    if (std::none_of(unique.begin(), unique.end(), [&](const SymbolPathEntry &u) { return u == e; }))
      unique.push_back(std::move(e));
  return unique;
}

std::string SymbolKey(const debuginfo::PdbGuid &g, std::uint32_t age) {
  char buf[64];
  const std::uint32_t d1 = static_cast<std::uint32_t>(g[0]) | (static_cast<std::uint32_t>(g[1]) << 8) |
                           (static_cast<std::uint32_t>(g[2]) << 16) | (static_cast<std::uint32_t>(g[3]) << 24);
  const unsigned d2 = g[4] | (g[5] << 8), d3 = g[6] | (g[7] << 8);
  std::snprintf(buf, sizeof buf, "%08X%04X%04X", d1, d2, d3);
  std::string out = buf;
  for (int i = 8; i < 16; ++i) {
    std::snprintf(buf, sizeof buf, "%02X", g[static_cast<std::size_t>(i)]);
    out += buf;
  }
  std::snprintf(buf, sizeof buf, "%X", age);
  return out + buf;
}

std::string ExpandCabinet(std::string_view cab, std::string &out, std::uint64_t max_bytes) {
  out.clear();
  if (cab.size() < 36 || cab.substr(0, 4) != "MSCF") return "not a cabinet";
  const std::uint16_t folders = U16(cab, 26), files = U16(cab, 28), flags = U16(cab, 30);
  if (flags & 3) return "a cabinet split across several files";
  std::size_t at = 36;
  unsigned folder_reserve = 0, data_reserve = 0;
  if (flags & 4) {
    if (cab.size() < 40) return "truncated cabinet";
    const std::uint16_t header_reserve = U16(cab, 36);
    folder_reserve = static_cast<std::uint8_t>(cab[38]);
    data_reserve = static_cast<std::uint8_t>(cab[39]);
    at = 40 + header_reserve;
  }
  if (folders == 0 || files == 0) return "an empty cabinet";
  // The first folder holds the one file.
  if (at + 8 > cab.size()) return "truncated cabinet";
  std::uint32_t data_at = U32(cab, at);
  const std::uint16_t blocks = U16(cab, at + 4);
  const std::uint16_t compression = U16(cab, at + 6) & 0x0f;
  (void)folder_reserve;
  if (compression != 0 && compression != 1)
    return compression == 3 ? "LZX-compressed cabinets aren't supported (only stored and MSZIP)"
                            : "Quantum-compressed cabinets aren't supported (only stored and MSZIP)";
  std::uint32_t file_size = 0;
  {
    const std::uint32_t files_at = U32(cab, 16);
    if (std::uint64_t{files_at} + 16 > cab.size()) return "truncated cabinet";
    file_size = U32(cab, files_at);
    if (U32(cab, files_at + 4) != 0) return "the file doesn't start its folder";
  }
  if (file_size > max_bytes) return "the file is larger than allowed";
  z_stream z{};
  if (compression == 1 && inflateInit2(&z, -MAX_WBITS) != Z_OK) return "zlib";
  std::string window;  // MSZIP: each block may refer to the 32 KiB before it
  for (std::uint16_t b = 0; b < blocks; ++b) {
    if (std::uint64_t{data_at} + 8 + data_reserve > cab.size()) {
      if (compression == 1) inflateEnd(&z);
      return "truncated cabinet data";
    }
    const std::uint16_t packed = U16(cab, data_at + 4), unpacked = U16(cab, data_at + 6);
    const std::size_t payload = std::size_t{data_at} + 8 + data_reserve;
    if (payload + packed > cab.size()) {
      if (compression == 1) inflateEnd(&z);
      return "truncated cabinet data";
    }
    if (compression == 0) {
      out.append(cab.substr(payload, packed));
    } else {
      if (packed < 2 || cab[payload] != 'C' || cab[payload + 1] != 'K') {
        inflateEnd(&z);
        return "an MSZIP block without its CK signature";
      }
      inflateReset(&z);
      if (!window.empty())
        inflateSetDictionary(&z, reinterpret_cast<const Bytef *>(window.data()), static_cast<uInt>(window.size()));
      std::string block(unpacked, '\0');
      z.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(cab.data() + payload + 2));
      z.avail_in = packed - 2;
      z.next_out = reinterpret_cast<Bytef *>(block.data());
      z.avail_out = unpacked;
      const int r = inflate(&z, Z_FINISH);
      if ((r != Z_STREAM_END && r != Z_OK && r != Z_BUF_ERROR) || z.avail_out != 0) {
        inflateEnd(&z);
        return "a damaged MSZIP block";
      }
      out += block;
      window = out.size() > 32768 ? out.substr(out.size() - 32768) : out;
    }
    if (out.size() > max_bytes) {
      if (compression == 1) inflateEnd(&z);
      return "the file is larger than allowed";
    }
    data_at = static_cast<std::uint32_t>(payload + packed);
  }
  if (compression == 1) inflateEnd(&z);
  if (out.size() < file_size) return "truncated cabinet data";
  out.resize(file_size);
  return {};
}

std::optional<FoundPdb> FindPdb(const SymbolSettings &settings, std::string_view name_in, const debuginfo::PdbGuid &guid,
                                std::uint32_t age, std::vector<std::string> &log) {
  // The file name alone (a CodeView path may be a Windows one).
  std::string name(name_in);
  if (auto slash = name.find_last_of("/\\"); slash != std::string::npos) name = name.substr(slash + 1);
  if (!SafeName(name)) {
    log.push_back("\"" + name + "\" isn't a file name a symbol path can look up");
    return std::nullopt;
  }
  const std::string key = SymbolKey(guid, age);
  const std::string compressed = name.substr(0, name.size() - 1) + "_";
  std::string error;
  const std::vector<SymbolPathEntry> path = ParseSymbolPath(settings.path, &error);
  if (!error.empty()) log.push_back("symbol path: " + error);

  // A local candidate: the PDB itself, or a .pd_ expanded next to it.
  auto try_local = [&](const fs::path &pdb, const fs::path &pd_, const std::string &where) -> std::optional<FoundPdb> {
    if (auto bytes = ReadFile(pdb, settings.max_bytes)) {
      if (Matches(*bytes, guid, age)) return FoundPdb{pdb, where, false};
      log.push_back(pdb.string() + ": another build's PDB");
    }
    if (auto cab = ReadFile(pd_, settings.max_bytes)) {
      std::string expanded;
      if (std::string e = ExpandCabinet(*cab, expanded, settings.max_bytes); !e.empty()) {
        log.push_back(pd_.string() + ": " + e);
      } else if (!Matches(expanded, guid, age)) {
        log.push_back(pd_.string() + ": another build's PDB");
      } else if (WriteFile(pdb, expanded)) {
        return FoundPdb{pdb, where, false};
      } else {
        log.push_back(pd_.string() + ": can't write " + pdb.string());
      }
    }
    return std::nullopt;
  };

  for (const SymbolPathEntry &e : path) {
    if (e.kind == SymbolPathEntry::Kind::server) continue;
    const fs::path dir = e.location;
    if (auto f = try_local(dir / name / key / name, dir / name / key / compressed, "store " + e.location)) return f;
    if (e.kind == SymbolPathEntry::Kind::directory)
      if (auto f = try_local(dir / name, dir / compressed, "directory " + e.location)) return f;
    log.push_back("not in " + e.location);
  }
  for (const SymbolPathEntry &e : path) {
    if (e.kind != SymbolPathEntry::Kind::server) continue;
    const std::string cache_dir = e.cache.empty() ? settings.default_cache : e.cache;
    if (!cache_dir.empty()) {
      const fs::path c = cache_dir;
      if (auto f = try_local(c / name / key / name, c / name / key / compressed, "cache " + cache_dir)) return f;
    }
    if (!settings.downloads) {
      log.push_back(e.location + ": not contacted (symbol server downloads are off)");
      continue;
    }
    if (cache_dir.empty()) {
      log.push_back(e.location + ": no cache directory to download into");
      continue;
    }
    // scheme://host[:port][/prefix]
    const std::size_t scheme_end = e.location.find("://");
    const std::size_t path_at = e.location.find('/', scheme_end + 3);
    const std::string origin = path_at == std::string::npos ? e.location : e.location.substr(0, path_at);
    const std::string prefix = path_at == std::string::npos ? std::string() : e.location.substr(path_at);
    httplib::Client client(origin);
    client.set_follow_location(true);
    client.set_connection_timeout(settings.timeout_seconds, 0);
    client.set_read_timeout(settings.timeout_seconds, 0);
    client.set_default_headers({{"User-Agent", "Microsoft-Symbol-Server/10.0.0.0"}});
    for (const std::string &file : {name, compressed}) {
      const std::string url_path = prefix + "/" + name + "/" + key + "/" + file;
      std::string body;
      bool too_big = false;
      auto res = client.Get(url_path, [&](const char *data, std::size_t n) {
        if (body.size() + n > settings.max_bytes) {
          too_big = true;
          return false;
        }
        body.append(data, n);
        return true;
      });
      if (too_big) {
        log.push_back(e.location + url_path + ": larger than allowed");
        continue;
      }
      if (!res) {
        log.push_back(e.location + url_path + ": " + httplib::to_string(res.error()));
        break;  // the server can't be reached: the .pd_ won't be either
      }
      if (res->status != 200) {
        log.push_back(e.location + url_path + ": HTTP " + std::to_string(res->status));
        continue;
      }
      std::string pdb;  // not a copy of the body: both are up to max_bytes
      if (file == compressed) {
        if (std::string err = ExpandCabinet(body, pdb, settings.max_bytes); !err.empty()) {
          log.push_back(e.location + url_path + ": " + err);
          continue;
        }
        std::string().swap(body);
      } else {
        pdb = std::move(body);
      }
      if (!Matches(pdb, guid, age)) {
        log.push_back(e.location + url_path + ": not the PDB asked for");
        continue;
      }
      const fs::path dest = fs::path(cache_dir) / name / key / name;
      if (!WriteFile(dest, pdb)) {
        log.push_back("can't write " + dest.string());
        return std::nullopt;
      }
      return FoundPdb{dest, "server " + e.location, true};
    }
  }
  return std::nullopt;
}

}  // namespace revkit::backend
