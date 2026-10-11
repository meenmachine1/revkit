#include "revkit/api/host_files.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <system_error>

namespace revkit::api {
namespace {

namespace fs = std::filesystem;

// True when `p` is `root` or lies below it. Both are canonical, so this is
// a component-wise prefix test, not a string one ("/home/al" is not inside
// "/home/alice").
bool within(const fs::path &p, const fs::path &root) {
  auto r = root.begin(), q = p.begin();
  for (; r != root.end(); ++r, ++q) {
    if (q == p.end() || *q != *r) return false;
  }
  return true;
}

std::vector<fs::path> canonical_roots(const std::vector<std::string> &roots) {
  std::vector<fs::path> out;
  for (const auto &r : roots) {
    std::error_code ec;
    fs::path c = fs::canonical(r, ec);
    if (!ec && fs::is_directory(c, ec)) out.push_back(std::move(c));
  }
  return out;
}

void set_modified(const fs::directory_entry &e, pb::HostFileEntry &out) {
  std::error_code ec;
  auto t = e.last_write_time(ec);
  if (ec) return;
  auto sys = std::chrono::file_clock::to_sys(t);
  auto secs = std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count();
  out.mutable_modified()->set_seconds(secs);
}

}  // namespace

Status ListHostFiles(const HostFilesOptions &opt, const pb::ListHostFilesRequest &req,
                     pb::ListHostFilesResponse &resp) {
  auto roots = canonical_roots(opt.roots);
  if (roots.empty())
    return Error(StatusCode::kFailedPrecondition,
                 "browsing the daemon's host is off: start rk-daemon with --browse-root <dir>");
  for (const auto &r : roots) resp.add_roots(r.string());

  std::error_code ec;
  fs::path dir = req.path().empty() ? roots.front() : fs::canonical(req.path(), ec);
  if (ec) return Error(StatusCode::kNotFound, "no such directory: " + req.path());
  auto root = std::find_if(roots.begin(), roots.end(), [&](const fs::path &r) { return within(dir, r); });
  if (root == roots.end())
    return Error(StatusCode::kPermissionDenied, "outside the browsable roots: " + dir.string());
  if (!fs::is_directory(dir, ec)) return Error(StatusCode::kInvalidArgument, "not a directory: " + dir.string());

  resp.set_path(dir.string());
  if (dir != *root) resp.set_parent(dir.parent_path().string());

  std::vector<pb::HostFileEntry> dirs, files;
  fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
  if (ec) return Error(StatusCode::kPermissionDenied, "cannot list " + dir.string() + ": " + ec.message());
  for (; it != fs::directory_iterator(); it.increment(ec)) {
    if (ec) break;
    const auto &e = *it;
    std::string name = e.path().filename().string();
    if (!req.include_hidden() && !name.empty() && name.front() == '.') continue;
    pb::HostFileEntry out;
    out.set_name(name);
    out.set_path(e.path().string());
    std::error_code sec;
    // Follows symlinks: a link to a directory is listed as one, though
    // entering it is refused if its target lies outside the roots.
    if (e.is_directory(sec)) {
      out.set_directory(true);
    } else if (e.is_regular_file(sec)) {
      std::uintmax_t size = e.file_size(sec);
      if (!sec) out.set_size(size);
    } else {
      continue;  // sockets, devices, broken links
    }
    set_modified(e, out);
    (out.directory() ? dirs : files).push_back(std::move(out));
  }

  auto by_name = [](const pb::HostFileEntry &a, const pb::HostFileEntry &b) { return a.name() < b.name(); };
  std::sort(dirs.begin(), dirs.end(), by_name);
  std::sort(files.begin(), files.end(), by_name);
  for (auto *group : {&dirs, &files}) {
    for (auto &e : *group) {
      if (static_cast<std::size_t>(resp.entries_size()) >= opt.max_entries) {
        resp.set_truncated(true);
        return {};
      }
      *resp.add_entries() = std::move(e);
    }
  }
  return {};
}

}  // namespace revkit::api
