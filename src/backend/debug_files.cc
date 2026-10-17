#include "debug_files.h"

#include "http_fetch.h"
#include "revkit/loader/load.hh"

#include <zlib.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <sstream>

namespace revkit::backend {

namespace fs = std::filesystem;

namespace {

// A bare file name: no directory, nothing odd.
bool SafeName(std::string_view n) {
  if (n.empty() || n.size() > 255 || n == "." || n == "..") return false;
  for (char c : n)
    if (c == '/' || c == '\\' || static_cast<unsigned char>(c) < 0x20) return false;
  return true;
}

bool IsHexId(std::string_view id) {
  if (id.size() < 4 || id.size() > 128 || id.size() % 2) return false;
  return std::all_of(id.begin(), id.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

// Writes atomically (a temporary in the same directory, renamed).
bool WriteFile(const fs::path &p, const loader::Bytes &bytes) {
  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  if (ec) return false;
  std::random_device rd;
  const fs::path tmp = p.parent_path() / (p.filename().string() + ".tmp" + std::to_string(rd()));
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
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

}  // namespace

std::optional<DebugLink> ReadDebugLink(const loader::Image &image) {
  if (image.format != loader::Format::elf) return std::nullopt;
  const loader::Section *s = loader::find_section(image, ".gnu_debuglink");
  if (!s) return std::nullopt;
  const std::span<const std::byte> b = loader::section_bytes(image, *s);
  // The name, NUL-terminated, padded to 4 bytes, then the CRC-32 in the
  // file's byte order.
  std::size_t n = 0;
  while (n < b.size() && b[n] != std::byte{0}) ++n;
  const std::size_t crc_at = (n + 4) & ~std::size_t{3};
  if (n == 0 || crc_at + 4 > b.size()) return std::nullopt;
  DebugLink out;
  out.name.assign(reinterpret_cast<const char *>(b.data()), n);
  if (!SafeName(out.name)) return std::nullopt;
  for (int i = 0; i < 4; ++i) {
    const auto byte = static_cast<std::uint32_t>(b[crc_at + static_cast<std::size_t>(image.endian == loader::Endian::big ? i : 3 - i)]);
    out.crc = out.crc << 8 | byte;
  }
  return out;
}

std::uint32_t DebugLinkCrc(std::span<const std::byte> bytes) {
  uLong crc = crc32(0L, Z_NULL, 0);
  std::size_t at = 0;
  while (at < bytes.size()) {
    const std::size_t n = std::min<std::size_t>(bytes.size() - at, std::size_t{1} << 30);
    crc = crc32(crc, reinterpret_cast<const Bytef *>(bytes.data() + at), static_cast<uInt>(n));
    at += n;
  }
  return static_cast<std::uint32_t>(crc);
}

std::vector<std::string> DebuginfodUrlsFromEnv() {
  std::vector<std::string> out;
  const char *env = std::getenv("DEBUGINFOD_URLS");
  if (!env) return out;
  std::istringstream in(env);
  for (std::string url; in >> url;)
    if (out.size() < 16 && url.size() <= 2048 && std::find(out.begin(), out.end(), url) == out.end()) out.push_back(url);
  return out;
}

std::string CheckDebuginfodUrl(std::string_view url, bool allow_http) {
  if (url.size() > 2048) return "longer than 2 KiB";
  const bool https = url.starts_with("https://"), http = url.starts_with("http://");
  if (!https && !http) return "not an https:// URL";
  if (http && !allow_http) return "http:// (plain text) isn't allowed: use https://, or allow http";
  const std::size_t host_at = url.find("://") + 3;
  const std::string_view rest = url.substr(host_at);
  const std::string_view host = rest.substr(0, rest.find('/'));
  if (host.empty()) return "names no host";
  if (host.find('@') != std::string_view::npos) return "has a user name or password in it";
  for (char c : url)
    if (static_cast<unsigned char>(c) <= 0x20 || c == 0x7f || c == '?' || c == '#') return "has a space, query or fragment in it";
  return {};
}

std::shared_ptr<loader::Bytes> ReadDebugFileBytes(const fs::path &p, std::uint64_t max) {
  std::error_code ec;
  if (!fs::is_regular_file(p, ec)) return nullptr;
  const auto size = fs::file_size(p, ec);
  if (ec || size > max || size < 64) return nullptr;
  std::ifstream in(p, std::ios::binary);
  if (!in) return nullptr;
  auto out = std::make_shared<loader::Bytes>(static_cast<std::size_t>(size));
  in.read(reinterpret_cast<char *>(out->data()), static_cast<std::streamsize>(size));
  if (!in) return nullptr;
  return out;
}

std::string CheckDebugFile(const std::shared_ptr<const loader::Bytes> &bytes, const DebugFileQuery &q) {
  if (!bytes || bytes->size() < 4 || std::memcmp(bytes->data(), "\x7f" "ELF", 4) != 0) return "not an ELF file";
  loader::Image image;
  try {
    image = loader::parse_elf(bytes);
  } catch (const std::exception &e) {
    return std::string("an ELF the loader can't read: ") + e.what();
  }
  if (!loader::find_section(image, ".debug_info") && !loader::find_section(image, ".zdebug_info"))
    return "no .debug_info in it";
  if (!q.build_id.empty()) {
    if (image.build_id != q.build_id)
      return image.build_id.empty() ? "it has no build ID (the program's is " + q.build_id + ")"
                                    : "another build's (build ID " + image.build_id + "; the program's is " + q.build_id + ")";
    return {};
  }
  if (q.link) {
    const std::uint32_t crc = DebugLinkCrc(*bytes);
    if (crc != q.link->crc) {
      char buf[64];
      std::snprintf(buf, sizeof buf, "its CRC-32 is %08x, the debuglink's %08x", crc, q.link->crc);
      return buf;
    }
    return {};
  }
  return "the program has neither a build ID nor a debuglink to match it by";
}

std::optional<fs::path> CacheDebugFile(const DebugFileSettings &settings, std::string_view build_id,
                                       const loader::Bytes &bytes, std::string *error) {
  if (settings.cache_dir.empty()) {
    if (error) *error = "the daemon has no cache directory (it has no project directory)";
    return std::nullopt;
  }
  if (!IsHexId(build_id)) {
    if (error) *error = "the build ID isn't hex";
    return std::nullopt;
  }
  if (bytes.size() > settings.cache_max_bytes) {
    if (error) *error = "larger than the cache";
    return std::nullopt;
  }
  const fs::path cache = settings.cache_dir;
  const fs::path dest = cache / std::string(build_id) / "debuginfo";
  if (!WriteFile(dest, bytes)) {
    if (error) *error = "can't write " + dest.string();
    return std::nullopt;
  }
  // The cache's size: the oldest go first.
  std::error_code ec;
  std::vector<std::pair<fs::file_time_type, std::pair<fs::path, std::uint64_t>>> files;
  std::uint64_t total = 0;
  for (auto it = fs::directory_iterator(cache, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
    const fs::path f = it->path() / "debuginfo";
    std::error_code e2;
    if (!fs::is_regular_file(f, e2)) continue;
    const std::uint64_t size = fs::file_size(f, e2);
    if (e2) continue;
    total += size;
    if (f != dest) files.push_back({fs::last_write_time(f, e2), {f, size}});
  }
  std::sort(files.begin(), files.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
  for (const auto &[when, f] : files) {
    if (total <= settings.cache_max_bytes) break;
    std::error_code e2;
    fs::remove(f.first, e2);
    fs::remove(f.first.parent_path(), e2);  // (only if empty)
    if (!e2) total -= f.second;
    else total -= std::min(total, f.second);
  }
  return dest;
}

std::optional<FoundDebugFile> FindDebugFile(const DebugFileSettings &settings, const DebugFileQuery &q, bool standard,
                                            bool network, std::vector<std::string> &log) {
  if (q.build_id.empty() && !q.link) {
    log.push_back("the program has neither a build ID nor a .gnu_debuglink");
    return std::nullopt;
  }
  if (!q.build_id.empty() && !IsHexId(q.build_id)) {
    log.push_back("the program's build ID isn't hex");
    return std::nullopt;
  }
  auto try_file = [&](const fs::path &p, const std::string &where) -> std::optional<FoundDebugFile> {
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) return std::nullopt;
    auto bytes = ReadDebugFileBytes(p, settings.max_bytes);
    if (!bytes) {
      log.push_back(p.string() + ": can't be read (or larger than allowed)");
      return std::nullopt;
    }
    if (std::string why = CheckDebugFile(bytes, q); !why.empty()) {
      log.push_back(p.string() + ": " + why);
      return std::nullopt;
    }
    return FoundDebugFile{p, where, false, std::move(bytes)};
  };
  const fs::path dir = q.binary.empty() ? fs::path() : q.binary.parent_path();
  // Beside the binary (gdb's order): <dir>/<link>, <dir>/.debug/<link>.
  if (q.link && !dir.empty()) {
    for (const fs::path &p : {dir / q.link->name, dir / ".debug" / q.link->name})
      if (p != q.binary)
        if (auto f = try_file(p, "beside the binary")) return f;
    log.push_back("not beside the binary");
  }
  std::vector<std::string> dirs = settings.dirs;
  if (standard && std::find(dirs.begin(), dirs.end(), std::string(kStandardDebugDir)) == dirs.end())
    dirs.emplace_back(kStandardDebugDir);
  for (const std::string &d : dirs) {
    if (d.empty()) continue;
    const fs::path root = d;
    if (!q.build_id.empty())
      if (auto f = try_file(root / ".build-id" / q.build_id.substr(0, 2) / (q.build_id.substr(2) + ".debug"), "directory " + d))
        return f;
    if (q.link) {
      if (!dir.empty())
        if (auto f = try_file(root / dir.relative_path() / q.link->name, "directory " + d)) return f;
      if (auto f = try_file(root / q.link->name, "directory " + d)) return f;
    }
    log.push_back("not in " + d);
  }
  if (!q.build_id.empty() && !settings.cache_dir.empty()) {
    if (auto f = try_file(fs::path(settings.cache_dir) / q.build_id / "debuginfo", "cache")) return f;
    log.push_back("not in the cache");
  }
  if (!network) return std::nullopt;
  if (!settings.debuginfod) {
    if (!settings.urls.empty()) log.push_back("debuginfod servers not contacted (downloads are off)");
    return std::nullopt;
  }
  if (q.build_id.empty()) {
    log.push_back("debuginfod needs a build ID; the program has none");
    return std::nullopt;
  }
  if (settings.cache_dir.empty()) {
    log.push_back("debuginfod: no cache directory to download into");
    return std::nullopt;
  }
  for (const std::string &url : settings.urls) {
    if (std::string why = CheckDebuginfodUrl(url, settings.allow_http); !why.empty()) {
      log.push_back(url + ": " + why);
      continue;
    }
    std::string base = url;
    while (!base.empty() && base.back() == '/') base.pop_back();
    const std::string origin = UrlOrigin(base);
    std::string path = base.substr(origin.size()) + "/buildid/" + q.build_id + "/debuginfo";
    // Redirects: within the same scheme, host and port only.
    HttpGetOptions get;
    get.user_agent = "revkit-debuginfod/1";
    get.timeout_seconds = settings.timeout_seconds;
    get.max_bytes = settings.max_bytes;
    auto body = std::make_shared<loader::Bytes>();
    const HttpGetResult res = HttpGetBounded(
        origin, path, get, [&] { loader::Bytes().swap(*body); },
        [&](const char *data, std::size_t n) {
          const auto *b = reinterpret_cast<const std::byte *>(data);
          body->insert(body->end(), b, b + n);
        });
    if (res.kind != HttpGetResult::Kind::kOk) {
      log.push_back(res.url + ": " + res.error);
      continue;
    }
    if (std::string why = CheckDebugFile(body, q); !why.empty()) {
      log.push_back(res.url + ": " + why);
      continue;
    }
    std::string error;
    auto kept = CacheDebugFile(settings, q.build_id, *body, &error);
    if (!kept) {
      log.push_back(res.url + ": fetched, but " + error);
      continue;
    }
    return FoundDebugFile{*kept, "debuginfod " + base, true, std::move(body)};
  }
  return std::nullopt;
}

}  // namespace revkit::backend
