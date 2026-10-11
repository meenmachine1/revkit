#include "filesystems.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <set>

namespace revkit::backend {

namespace {

namespace stdfs = std::filesystem;
using api::Error;
using api::Status;
using api::StatusCode;
using container::Entry;
using container::Kind;
using container::Session;

std::string RandomId() {
  unsigned char b[16];
  if (RAND_bytes(b, sizeof b) != 1) throw std::runtime_error("no randomness");
  static const char *hex = "0123456789abcdef";
  std::string out = "fs_";
  for (unsigned char c : b) {
    out += hex[c >> 4];
    out += hex[c & 15];
  }
  return out;
}

pb::FileSystemEntryKind KindOf(Kind k) {
  switch (k) {
    case Kind::file: return pb::FILE_SYSTEM_ENTRY_KIND_FILE;
    case Kind::directory: return pb::FILE_SYSTEM_ENTRY_KIND_DIRECTORY;
    case Kind::symlink: return pb::FILE_SYSTEM_ENTRY_KIND_SYMLINK;
    case Kind::hardlink: return pb::FILE_SYSTEM_ENTRY_KIND_HARDLINK;
    case Kind::char_device: return pb::FILE_SYSTEM_ENTRY_KIND_CHAR_DEVICE;
    case Kind::block_device: return pb::FILE_SYSTEM_ENTRY_KIND_BLOCK_DEVICE;
    case Kind::fifo: return pb::FILE_SYSTEM_ENTRY_KIND_FIFO;
    case Kind::socket: return pb::FILE_SYSTEM_ENTRY_KIND_SOCKET;
    case Kind::other: return pb::FILE_SYSTEM_ENTRY_KIND_OTHER;
  }
  return pb::FILE_SYSTEM_ENTRY_KIND_OTHER;
}

std::string Permissions(std::uint32_t mode) {
  std::string s = "---------";
  const char *rwx = "rwx";
  for (int i = 0; i < 9; ++i)
    if (mode & (1u << (8 - i))) s[i] = rwx[i % 3];
  if (mode & 04000) s[2] = s[2] == 'x' ? 's' : 'S';
  if (mode & 02000) s[5] = s[5] == 'x' ? 's' : 'S';
  if (mode & 01000) s[8] = s[8] == 'x' ? 't' : 'T';
  return s;
}

// The entry `idx` of a layer, without the guess.
void FillEntry(const container::FileSystem &fs, std::uint32_t idx, const std::string &prefix, pb::FileSystemEntry *out) {
  const Entry &e = fs.entry(idx);
  out->set_name(idx == 0 ? "/" : container::display_name(e.name));
  out->set_path(prefix + fs.path_of(idx));
  out->set_kind(KindOf(e.kind));
  if (e.size == UINT64_MAX) {
    out->set_size_unknown(true);
  } else {
    out->set_size(e.size);
  }
  out->set_stored_size(e.stored_size);
  if (e.has_mode) {
    out->set_permissions(Permissions(e.mode));
    out->set_mode(e.mode);
  }
  if (e.has_owner) {
    out->set_has_owner(true);
    out->set_uid(e.uid);
    out->set_gid(e.gid);
  }
  if (e.has_mtime) out->mutable_modified()->set_seconds(e.mtime);
  if (e.kind == Kind::symlink || e.kind == Kind::hardlink) {
    out->set_link_target(container::display_name(e.link_target));
    try {
      if (auto t = fs.resolve_link(idx)) out->set_link_path(prefix + fs.path_of(*t));
    } catch (const container::Error &) {
      // A loop: no target.
    }
  }
  if (!e.note.empty()) out->set_note(e.note);
  out->set_unreadable(e.loc2 == UINT64_MAX && e.kind == Kind::file);
  out->set_renamed(e.renamed);
  if (e.kind == Kind::directory) out->set_child_count(static_cast<std::uint32_t>(e.children.size()));
  if (!e.language.empty()) out->set_language_id(e.language);
  if (e.load_address) {
    out->set_load_address(*e.load_address);
    out->set_has_load_address(true);
  }
}

void FillGuess(const container::Guess &g, pb::FileSystemEntry *out) {
  out->set_detected(g.description);
  out->set_detected_kind(g.kind.empty() ? "data" : g.kind);
  if (g.kind == "container") out->set_container_format(g.format);
  if (!g.processor.empty()) out->set_processor(g.processor);
}

std::function<bool()> Cancelled(const api::CallContext &ctx) { return ctx.cancelled; }

}  // namespace

// ---- the registry -----------------------------------------------------------------

void FileSystemRegistry::PruneLocked() {
  const auto now = std::chrono::steady_clock::now();
  for (auto it = sessions_.begin(); it != sessions_.end();) {
    if (now - it->second->session->last_used() > kIdle && it->second.use_count() == 1)
      it = sessions_.erase(it);
    else
      ++it;
  }
}

Status FileSystemRegistry::Add(const api::CallContext &ctx, std::string project, std::string name,
                               std::shared_ptr<container::Session> session, std::shared_ptr<FsSession> &out) {
  std::lock_guard lock(mu_);
  PruneLocked();
  std::size_t mine = 0;
  std::shared_ptr<FsSession> oldest;
  for (const auto &[id, s] : sessions_)
    if (s->owner == ctx.caller) {
      ++mine;
      if (!oldest || s->session->last_used() < oldest->session->last_used()) oldest = s;
    }
  if (mine >= kMaxPerCaller) {
    // The least recently used goes, if nothing is using it right now.
    if (oldest && oldest.use_count() <= 2)
      sessions_.erase(oldest->id);
    else
      return Error(StatusCode::kResourceExhausted, "you have " + std::to_string(mine) +
                                                       " file systems open; close one first (CloseFileSystem)");
  }
  if (sessions_.size() >= kMaxTotal)
    return Error(StatusCode::kResourceExhausted, "the daemon has " + std::to_string(sessions_.size()) +
                                                     " file systems open; try again later");
  auto s = std::make_shared<FsSession>();
  s->id = RandomId();
  s->owner = ctx.caller;
  s->project_id = std::move(project);
  s->name = std::move(name);
  s->opened_at = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  s->session = std::move(session);
  sessions_[s->id] = s;
  out = s;
  return Status::Ok();
}

Status FileSystemRegistry::Get(const api::CallContext &ctx, const std::string &id, std::shared_ptr<FsSession> &out) {
  std::lock_guard lock(mu_);
  auto it = sessions_.find(id);
  if (it == sessions_.end() || (!ctx.caller_admin && it->second->owner != ctx.caller))
    return Error(StatusCode::kNotFound, "no file system session " + id + " (closed, or idle for 30 minutes)");
  out = it->second;
  return Status::Ok();
}

Status FileSystemRegistry::Close(const api::CallContext &ctx, const pb::CloseFileSystemRequest &req) {
  std::lock_guard lock(mu_);
  auto it = sessions_.find(req.session_id());
  if (it == sessions_.end() || (!ctx.caller_admin && it->second->owner != ctx.caller))
    return Error(StatusCode::kNotFound, "no file system session " + req.session_id());
  sessions_.erase(it);
  return Status::Ok();
}

void FileSystemRegistry::List(const api::CallContext &ctx, pb::ListFileSystemsResponse &resp) {
  std::lock_guard lock(mu_);
  PruneLocked();
  for (const auto &[id, s] : sessions_) {
    if (!ctx.caller_admin && s->owner != ctx.caller) continue;
    pb::OpenFileSystemSession *o = resp.add_sessions();
    o->set_session_id(id);
    o->set_name(container::display_name(s->name));
    o->set_format(s->session->root_format());
    o->set_project_id(s->project_id);
    o->set_owner(s->owner);
    o->mutable_opened_at()->set_seconds(s->opened_at);
    o->set_held_bytes(s->session->budget_used());
  }
}

// ---- limits and layers ----------------------------------------------------------------

container::Limits LimitsFrom(const pb::FileSystemLimits &req) {
  container::Limits l;
  auto lower = [](auto &field, auto asked) {
    if (asked > 0 && static_cast<std::uint64_t>(asked) < static_cast<std::uint64_t>(field))
      field = static_cast<std::remove_reference_t<decltype(field)>>(asked);
  };
  lower(l.max_file_bytes, req.max_file_bytes());
  lower(l.max_total_bytes, req.max_total_bytes());
  lower(l.max_depth, req.max_depth());
  lower(l.max_entries, req.max_entries());
  lower(l.max_ratio, req.max_ratio());
  return l;
}

void FillLimits(const container::Limits &l, pb::FileSystemLimits *out) {
  out->set_max_file_bytes(l.max_file_bytes);
  out->set_max_total_bytes(l.max_total_bytes);
  out->set_max_depth(l.max_depth);
  out->set_max_entries(l.max_entries);
  out->set_max_ratio(static_cast<std::uint32_t>(l.max_ratio));
}

void FillLayer(container::Session &s, const container::FileSystem &fs, const std::string &prefix, std::uint32_t depth,
               pb::FileSystemLayer *out) {
  out->set_format(fs.format());
  out->set_description(fs.description());
  for (const std::string &w : fs.warnings()) out->add_warnings(container::display_name(w));
  out->set_path(prefix + "/");
  out->set_container_path(s.container_path(prefix + "/"));
  out->set_depth(depth);
}

// ---- reading ----------------------------------------------------------------------------

Status ListFileSystemEntries(FsSession &fss, const api::CallContext &ctx, const pb::ListFileSystemRequest &req,
                             pb::ListFileSystemResponse &resp) {
  return FsGuard([&]() -> Status {
    Session &s = *fss.session;
    const auto cancelled = Cancelled(ctx);
    Session::Node dir = s.locate(req.path().empty() ? "/" : req.path(), true, cancelled);
    std::shared_ptr<container::FileSystem> layer = dir.fs;
    std::string prefix = dir.prefix;
    std::uint32_t depth = dir.depth;
    if (layer->entry(dir.entry).kind != Kind::directory) {
      // A container file: its root.
      auto sub = s.mount(dir, cancelled);
      if (!sub) return Error(StatusCode::kInvalidArgument, "not a directory or a container: " + dir.path);
      prefix = dir.path + "!";
      layer = sub;
      dir = Session::Node{sub, 0, prefix + "/", prefix, depth + 1};
      depth += 1;
    }
    FillLayer(s, *layer, prefix, depth, resp.mutable_layer());
    FillEntry(*layer, dir.entry, prefix, resp.mutable_directory());
    // Which entries, in order.
    std::vector<std::uint32_t> list;
    const std::size_t cap = 1u << 20;
    std::function<void(std::uint32_t)> walk = [&](std::uint32_t d) {
      for (std::uint32_t c : layer->entry(d).children) {
        if (list.size() >= cap) return;
        list.push_back(c);
        if (req.recursive() && layer->entry(c).kind == Kind::directory) walk(c);
      }
    };
    walk(dir.entry);
    resp.set_total(static_cast<std::uint32_t>(list.size()));
    const std::size_t limit = req.limit() == 0 ? 1000 : std::min<std::uint32_t>(req.limit(), 20000);
    const std::size_t from = std::min<std::size_t>(req.offset(), list.size());
    const std::size_t to = std::min(list.size(), from + limit);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    for (std::size_t i = from; i < to; ++i) {
      pb::FileSystemEntry *out = resp.add_entries();
      FillEntry(*layer, list[i], prefix, out);
      const Entry &e = layer->entry(list[i]);
      if (!req.detect() || e.kind == Kind::directory) continue;
      if (std::chrono::steady_clock::now() > deadline) {
        resp.set_detect_incomplete(true);
        continue;
      }
      try {
        Session::Node n{layer, list[i], prefix + layer->path_of(list[i]), prefix, depth};
        FillGuess(s.describe(n, cancelled), out);
      } catch (const container::Error &err) {
        out->set_detected(std::string("unreadable: ") + err.what());
        out->set_detected_kind("data");
      }
    }
    return Status::Ok();
  });
}

Status ReadFileSystemFile(FsSession &fss, const api::CallContext &ctx, const pb::ReadFileSystemFileRequest &req,
                          pb::ReadFileSystemFileResponse &resp) {
  return FsGuard([&]() -> Status {
    auto src = fss.session->open_file(req.path(), Cancelled(ctx));
    const std::uint64_t size = src->size();
    const std::uint64_t length = std::min<std::uint64_t>(req.length() == 0 ? (1u << 20) : req.length(), 4u << 20);
    const std::uint64_t offset = std::min(req.offset(), size);
    const std::uint64_t n = std::min(length, size - offset);
    std::string *data = resp.mutable_data();
    data->resize(n);
    data->resize(src->read(offset, std::as_writable_bytes(std::span(data->data(), data->size()))));
    resp.set_size(size);
    resp.set_eof(offset + data->size() >= size);
    return Status::Ok();
  });
}

namespace {

std::string Hex(const unsigned char *p, unsigned n) {
  static const char *hex = "0123456789abcdef";
  std::string out;
  for (unsigned i = 0; i < n; ++i) {
    out += hex[p[i] >> 4];
    out += hex[p[i] & 15];
  }
  return out;
}

}  // namespace

Status FileSystemFileInfo(FsSession &fss, const api::CallContext &ctx, const pb::GetFileSystemFileInfoRequest &req,
                          pb::GetFileSystemFileInfoResponse &resp) {
  return FsGuard([&]() -> Status {
    Session &s = *fss.session;
    const auto cancelled = Cancelled(ctx);
    Session::Node n = s.locate(req.path().empty() ? "/" : req.path(), false, cancelled);
    FillLayer(s, *n.fs, n.prefix, n.depth, resp.mutable_layer());
    pb::FileSystemEntry *e = resp.mutable_entry();
    FillEntry(*n.fs, n.entry, n.prefix, e);
    resp.set_container_path(s.container_path(n.path));
    const Kind kind = n.fs->entry(n.entry).kind;
    if (kind == Kind::directory) return Status::Ok();
    Session::Node file = n;
    if (kind == Kind::symlink || kind == Kind::hardlink) {
      auto t = n.fs->resolve_link(n.entry, s.limits().max_symlink_hops);
      if (!t) return Status::Ok();
      file = Session::Node{n.fs, *t, n.prefix + n.fs->path_of(*t), n.prefix, n.depth};
    }
    if (file.fs->entry(file.entry).kind != Kind::file) return Status::Ok();
    FillGuess(s.describe(file, cancelled), e);
    const auto magic = s.head(file, 64, cancelled);
    resp.set_magic(std::string(reinterpret_cast<const char *>(magic.data()), magic.size()));
    if (!e->container_format().empty()) {
      if (auto sub = s.mount(file, cancelled))
        FillLayer(s, *sub, file.path + "!", file.depth + 1, resp.mutable_container());
    }
    if (req.hashes()) {
      auto src = s.open_file(file.path, cancelled);
      // A stored member is mapped, not decompressed, so the file limit
      // hasn't applied: a sparse 2^60-byte file would hash for ever. Past
      // it the info has no hashes.
      if (src->size() > s.limits().max_file_bytes) return Status::Ok();
      struct Md {
        const EVP_MD *md;
        EVP_MD_CTX *c;
      } mds[3] = {{EVP_sha256(), EVP_MD_CTX_new()}, {EVP_sha1(), EVP_MD_CTX_new()}, {EVP_md5(), EVP_MD_CTX_new()}};
      for (Md &m : mds) EVP_DigestInit_ex(m.c, m.md, nullptr);
      std::vector<std::byte> buf(1u << 20);
      for (std::uint64_t off = 0; off < src->size();) {
        if (ctx.cancelled()) {
          for (Md &m : mds) EVP_MD_CTX_free(m.c);
          return Error(StatusCode::kCancelled, "cancelled");
        }
        const std::size_t got = src->read(off, buf);
        if (got == 0) break;
        for (Md &m : mds) EVP_DigestUpdate(m.c, buf.data(), got);
        off += got;
      }
      std::string out[3];
      for (int i = 0; i < 3; ++i) {
        unsigned char d[EVP_MAX_MD_SIZE];
        unsigned len = 0;
        EVP_DigestFinal_ex(mds[i].c, d, &len);
        EVP_MD_CTX_free(mds[i].c);
        out[i] = Hex(d, len);
      }
      resp.set_sha256(out[0]);
      resp.set_sha1(out[1]);
      resp.set_md5(out[2]);
    }
    return Status::Ok();
  });
}

// ---- extraction --------------------------------------------------------------------------

namespace {

bool Within(const stdfs::path &p, const stdfs::path &root) {
  auto r = root.begin(), q = p.begin();
  for (; r != root.end(); ++r, ++q)
    if (q == p.end() || *q != *r) return false;
  return true;
}

// A member's name as a host file name: display text (valid UTF-8), no
// separators or control characters, never "." or "..", at most 200 bytes.
std::string HostName(const std::string &raw) {
  std::string s = container::display_name(raw);
  for (char &c : s)
    if (c == '/' || c == '\\' || static_cast<unsigned char>(c) < 0x20) c = '_';
  if (s.size() > 200) {
    std::size_t cut = 200;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xc0) == 0x80) --cut;
    s.resize(cut);
  }
  if (s.empty() || s == "." || s == "..") s = "_" + s;
  return s;
}

struct Extractor {
  Session &s;
  const pb::ExtractFromFileSystemRequest &req;
  pb::ExtractFromFileSystemResponse &resp;
  std::function<bool()> cancelled;
  std::uint64_t files = 0;

  void skip(const std::string &path, const std::string &why) {
    if (resp.skipped_size() < 10000) resp.add_skipped(container::display_name(path) + ": " + why);
  }

  // A subdirectory of `dirfd`, made if missing; never through a link.
  int subdir(int dirfd, const std::string &name) {
    if (::mkdirat(dirfd, name.c_str(), 0755) != 0 && errno != EEXIST)
      throw container::Error("cannot make the directory " + name + ": " + std::strerror(errno));
    const int fd = ::openat(dirfd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) throw container::Error(name + " exists and is not a directory (or is a link)");
    return fd;
  }

  void file(int dirfd, const std::string &host_dir, const Session::Node &n) {
    const std::string name = HostName(n.fs->entry(n.entry).name);
    if (++files > 100000) throw container::LimitError("more than 100000 files in one extraction");
    auto src = s.open_file(n.path, cancelled);
    // Stored (mapped) members skip the decompression limits: a sparse
    // 2^60-byte one filled the disk. The file limit and, for the whole
    // extraction, the session's total apply.
    if (src->size() > s.limits().max_file_bytes) {
      skip(n.path, "larger than the file limit");
      return;
    }
    if (src->size() > s.limits().max_total_bytes - std::min(resp.bytes(), s.limits().max_total_bytes)) {
      skip(n.path, "over the extraction's total limit");
      return;
    }
    int fd = ::openat(dirfd, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0 && errno == EEXIST) {
      if (!req.overwrite()) {
        skip(n.path, "exists (overwrite to replace it)");
        return;
      }
      struct stat st {};
      if (::fstatat(dirfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
        skip(n.path, "exists and is not a regular file");
        return;
      }
      ::unlinkat(dirfd, name.c_str(), 0);
      fd = ::openat(dirfd, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    }
    if (fd < 0) throw container::Error("cannot write " + name + ": " + std::strerror(errno));
    std::vector<std::byte> buf(1u << 20);
    std::uint64_t off = 0;
    try {
      while (off < src->size()) {
        if (cancelled && cancelled()) throw container::Error("cancelled");
        const std::size_t got = src->read(off, buf);
        if (got == 0) break;
        for (std::size_t done = 0; done < got;) {
          const ssize_t w = ::write(fd, buf.data() + done, got - done);
          if (w < 0 && errno == EINTR) continue;
          if (w <= 0) throw container::Error("cannot write " + name + ": " + std::strerror(errno));
          done += static_cast<std::size_t>(w);
        }
        off += got;
      }
    } catch (...) {
      ::close(fd);
      throw;
    }
    ::close(fd);
    resp.set_files(resp.files() + 1);
    resp.set_bytes(resp.bytes() + off);
    if (resp.written_size() < 10000) resp.add_written(host_dir + "/" + name);
  }

  void any(int dirfd, const std::string &host_dir, const Session::Node &n, unsigned depth) {
    const Entry &e = n.fs->entry(n.entry);
    switch (e.kind) {
      case Kind::file:
      case Kind::hardlink:
        file(dirfd, host_dir, n);
        return;
      case Kind::directory: {
        if (depth > 256) throw container::LimitError("directories nest too deep");
        int sub = dirfd;
        std::string sub_dir = host_dir;
        if (n.entry != 0) {
          const std::string name = HostName(e.name);
          sub = subdir(dirfd, name);
          sub_dir += "/" + name;
        }
        try {
          for (std::uint32_t c : e.children)
            any(sub, sub_dir, Session::Node{n.fs, c, n.prefix + n.fs->path_of(c), n.prefix, n.depth}, depth + 1);
        } catch (...) {
          if (sub != dirfd) ::close(sub);
          throw;
        }
        if (sub != dirfd) ::close(sub);
        return;
      }
      case Kind::symlink: skip(n.path, "a symbolic link (to " + container::display_name(e.link_target) + "): not written"); return;
      default: skip(n.path, "a " + std::string(container::name(e.kind)) + ": not written"); return;
    }
  }
};

}  // namespace

Status ExtractFileSystem(FsSession &fss, const api::CallContext &ctx, const pb::ExtractFromFileSystemRequest &req,
                         const std::vector<std::string> &browse_roots, pb::ExtractFromFileSystemResponse &resp) {
  if (browse_roots.empty())
    return Error(StatusCode::kFailedPrecondition,
                 "extracting writes under --browse-root, and the daemon has none: start rk-daemon with --browse-root");
  if (req.host_dir().empty()) return Error(StatusCode::kInvalidArgument, "host_dir is required");
  if (req.paths().empty()) return Error(StatusCode::kInvalidArgument, "name the files to extract (paths)");
  // The destination: its parent must exist; both under a root, canonical.
  std::error_code ec;
  const stdfs::path asked = stdfs::path(req.host_dir()).lexically_normal();
  if (!asked.is_absolute()) return Error(StatusCode::kInvalidArgument, "host_dir must be an absolute path");
  stdfs::path parent = stdfs::canonical(asked.parent_path(), ec);
  if (ec) return Error(StatusCode::kNotFound, "no such directory: " + asked.parent_path().string());
  const stdfs::path dest = parent / asked.filename();
  bool inside = false;
  for (const std::string &r : browse_roots) {
    stdfs::path root = stdfs::canonical(r, ec);
    if (!ec && Within(dest, root)) inside = true;
  }
  if (!inside) return Error(StatusCode::kPermissionDenied, "outside the browsable roots: " + dest.string());
  const int pfd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (pfd < 0) return Error(StatusCode::kNotFound, "cannot open " + parent.string());
  int dfd = -1;
  if (asked.filename().empty() || asked.filename() == "/") {
    dfd = pfd;
  } else {
    if (::mkdirat(pfd, asked.filename().c_str(), 0755) != 0 && errno != EEXIST) {
      ::close(pfd);
      return Error(StatusCode::kPermissionDenied, "cannot make " + dest.string() + ": " + std::strerror(errno));
    }
    dfd = ::openat(pfd, asked.filename().c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    ::close(pfd);
    if (dfd < 0) return Error(StatusCode::kInvalidArgument, dest.string() + " is not a directory (or is a link)");
  }
  Status st = FsGuard([&]() -> Status {
    Extractor x{*fss.session, req, resp, Cancelled(ctx)};
    for (const std::string &p : req.paths()) {
      Session::Node n = fss.session->locate(p, false, x.cancelled);
      x.any(dfd, dest.string(), n, 0);
    }
    return Status::Ok();
  });
  ::close(dfd);
  return st;
}

// ---- import plans -------------------------------------------------------------------------

Status PlanFileSystemImport(FsSession &fss, const api::CallContext &ctx, const pb::ImportFromFileSystemRequest &req,
                            std::vector<ImportPlanItem> &out, bool &capped) {
  return FsGuard([&]() -> Status {
    Session &s = *fss.session;
    const auto cancelled = Cancelled(ctx);
    const std::uint32_t cap = req.max_programs() == 0 ? 100 : std::min<std::uint32_t>(req.max_programs(), 1000);
    std::uint32_t chosen = 0;
    std::uint64_t visited = 0;
    std::set<std::string> seen;
    capped = false;
    std::vector<std::string> paths(req.paths().begin(), req.paths().end());
    if (paths.empty()) paths.push_back("/");

    auto consider = [&](const Session::Node &n, bool named, const std::vector<std::string> &folders) {
      if (!seen.insert(n.path).second) return;
      const Entry &e = n.fs->entry(n.entry);
      ImportPlanItem item;
      item.path = n.path;
      item.container_path = s.container_path(n.path);
      item.name = container::display_name(e.name);
      for (char &c : item.name)
        if (c == '/' || static_cast<unsigned char>(c) < 0x20) c = '_';
      item.folders = folders;
      item.language = e.language;
      item.load_address = e.load_address;
      container::Guess g;
      try {
        g = s.describe(n, cancelled);
      } catch (const container::Error &err) {
        item.action = "skipped";
        item.reason = std::string("unreadable: ") + err.what();
        out.push_back(std::move(item));
        return;
      }
      item.detected = g.description;
      item.kind = g.kind;
      const bool program = g.kind == "elf" || g.kind == "pe";
      if (named && !req.programs_only()) {
        item.action = "import";
      } else if (program) {
        item.action = "import";
      } else if (g.kind == "raw" && !item.language.empty()) {
        item.action = "import";
        item.reason = "a raw image whose header names its processor";
      } else if (g.kind == "raw" && req.detect_raw()) {
        item.action = "import";
        item.detect_raw = true;
        item.reason = "if raw detection identifies it";
      } else {
        item.action = "skipped";
        if (g.kind == "raw")
          item.reason = "raw data whose processor no header names (detect_raw tries detection)";
        else if (g.kind == "container")
          item.reason = "a container (" + g.format + "): descend looks inside";
        else
          item.reason = "not a program (" + (g.description.empty() ? g.kind : g.description) + ")";
      }
      if (item.action == "import") {
        if (chosen >= cap) {
          item.action = "skipped";
          item.reason = "over the cap of " + std::to_string(cap) + " programs";
          capped = true;
        } else {
          ++chosen;
        }
      }
      out.push_back(std::move(item));
    };

    auto skipped = [&](const Session::Node &n, std::string why) {
      ImportPlanItem item;
      item.path = n.path;
      item.container_path = s.container_path(n.path);
      item.name = container::display_name(n.fs->entry(n.entry).name);
      item.action = "skipped";
      item.reason = std::move(why);
      out.push_back(std::move(item));
    };
    // `named`: the path was given (not found by walking); `all`: inside a
    // container descended into, where everything below is looked at.
    std::function<void(const Session::Node &, const std::vector<std::string> &, bool, bool)> walk;
    walk = [&](const Session::Node &n, const std::vector<std::string> &folders, bool named, bool all) {
      if (++visited > 200000) throw container::LimitError("more than 200000 entries looked at");
      if (cancelled && cancelled()) throw container::Error("cancelled");
      const Entry &e = n.fs->entry(n.entry);
      if (e.kind == Kind::directory) {
        for (std::uint32_t c : e.children) {
          const Entry &ce = n.fs->entry(c);
          Session::Node cn{n.fs, c, n.prefix + n.fs->path_of(c), n.prefix, n.depth};
          if (ce.kind == Kind::directory) {
            if (!all && !req.recursive()) continue;
            std::vector<std::string> sub = folders;
            sub.push_back(container::display_name(ce.name));
            walk(cn, sub, false, all);
          } else {
            walk(cn, folders, false, all);
          }
        }
        return;
      }
      if (e.kind == Kind::symlink || e.kind == Kind::hardlink) {
        if (!named) return;  // its target is looked at where it is
        auto t = n.fs->resolve_link(n.entry, s.limits().max_symlink_hops);
        if (!t) return skipped(n, "a link whose target isn't in the container");
        walk(Session::Node{n.fs, *t, n.prefix + n.fs->path_of(*t), n.prefix, n.depth}, folders, named, all);
        return;
      }
      if (e.kind != Kind::file) {
        if (named) skipped(n, "a " + std::string(container::name(e.kind)));
        return;
      }
      if (req.descend()) {
        std::string format;
        try {
          format = s.container_format(n, cancelled);
        } catch (const container::Error &) {
        }
        if (!format.empty()) {
          if (n.depth + 1 > s.limits().max_depth) return skipped(n, "a container nested deeper than the limit");
          if (auto sub = s.mount(n, cancelled)) {
            std::vector<std::string> inner = folders;
            inner.push_back(container::display_name(e.name));
            const std::string prefix = n.path + "!";
            walk(Session::Node{sub, 0, prefix + "/", prefix, n.depth + 1}, inner, false, true);
            return;
          }
        }
      }
      consider(n, named, folders);
    };

    for (const std::string &p : paths) {
      Session::Node n = s.locate(p, false, cancelled);
      walk(n, {}, true, false);
    }
    if (!req.keep_folders())
      for (ImportPlanItem &i : out) i.folders.clear();
    return Status::Ok();
  });
}

}  // namespace revkit::backend
