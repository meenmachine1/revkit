#include "revkit/container/session.hh"

#include "asar.hh"

#include <algorithm>

namespace revkit::container {

namespace {

std::vector<std::string_view> layers_of(std::string_view path) {
  std::vector<std::string_view> out;
  std::size_t i = 0;
  for (;;) {
    const std::size_t j = path.find('!', i);
    if (j == std::string_view::npos) {
      out.push_back(path.substr(i));
      return out;
    }
    out.push_back(path.substr(i, j - i));
    i = j + 1;
  }
}

std::string shown(std::string_view path) {
  std::string out;
  for (std::string_view layer : layers_of(path)) {
    if (!out.empty()) out += "!";
    std::string l;
    for (const std::string &c : split_path(layer)) l += "/" + display_name(c);
    out += l.empty() ? "/" : l;
  }
  return out;
}

}  // namespace

Context Session::context(const std::function<bool()> &cancelled) const {
  Context c;
  c.limits = limits_;
  c.budget = budget_;
  if (cancelled) c.cancelled = cancelled;
  return c;
}

std::shared_ptr<Session> Session::open(std::shared_ptr<const Source> root, std::string name, const Limits &limits,
                                       const std::function<bool()> &cancelled) {
  std::shared_ptr<Session> s(new Session());
  s->limits_ = limits;
  s->budget_ = std::make_shared<Budget>(limits.max_total_bytes);
  s->root_name_ = std::move(name);
  s->root_src_ = root;
  const Context ctx = s->context(cancelled);
  const std::string format = identify(*root);
  if (format.empty()) throw Error(display_name(s->root_name_) + " is not a container this daemon can open");
  s->root_ = open_format(format, std::move(root), s->root_name_, ctx);
  return s;
}

std::shared_ptr<Session> Session::open_directory(const std::string &path, const Limits &limits) {
  std::shared_ptr<Session> s(new Session());
  s->limits_ = limits;
  s->budget_ = std::make_shared<Budget>(limits.max_total_bytes);
  s->root_dir_ = path;
  const auto slash = path.find_last_of('/');
  s->root_name_ = slash == std::string::npos || slash + 1 == path.size() ? path : path.substr(slash + 1);
  s->root_ = open_host_directory(path, s->context({}));
  return s;
}

void Session::touch() { last_used_ = std::chrono::steady_clock::now(); }

bool Session::evict_one() {
  // The least recently used entry nothing else holds.
  auto victim = cache_.end();
  for (auto it = cache_.begin(); it != cache_.end(); ++it) {
    const bool held = (it->second.fs && it->second.fs.use_count() > 1) || it->second.src.use_count() > 1;
    if (held) continue;
    if (victim == cache_.end() || it->second.tick < victim->second.tick) victim = it;
  }
  if (victim == cache_.end()) {
    // Everything is in use by a caller; drop the oldest anyway (it lives
    // on with its holder).
    for (auto it = cache_.begin(); it != cache_.end(); ++it)
      if (victim == cache_.end() || it->second.tick < victim->second.tick) victim = it;
    if (victim == cache_.end()) return false;
  }
  cache_.erase(victim);
  return true;
}

std::shared_ptr<const Source> Session::open_entry(const Node &node, const Context &ctx) {
  if (auto it = cache_.find(node.path); it != cache_.end()) {
    it->second.tick = ++tick_;
    return it->second.src;
  }
  const Entry &e = node.fs->entry(node.entry);
  std::uint32_t target = node.entry;
  if (e.kind == Kind::symlink || e.kind == Kind::hardlink) {
    auto t = node.fs->resolve_link(node.entry, limits_.max_symlink_hops);
    if (!t) throw Error(shown(node.path) + " is a link to " + display_name(e.link_target) +
                        ", which isn't in the container");
    target = *t;
  }
  if (node.fs->entry(target).kind != Kind::file && node.fs->entry(target).kind != Kind::hardlink)
    throw Error(shown(node.path) + " is a " + std::string(name(node.fs->entry(target).kind)) + ", not a file");
  for (;;) {
    try {
      auto src = node.fs->open(target, ctx);
      // Small files aren't worth keeping; the rest are, while there's room.
      if (src->size() >= (1u << 20)) {
        while (cache_.size() >= 32 && evict_one()) {
        }
        cache_[node.path] = Cached{src, nullptr, ++tick_};
      }
      return src;
    } catch (const LimitError &err) {
      // The session's budget: make room and try again; the file's own
      // limits: give up.
      if (std::string_view(err.what()).find("the session holds") == std::string_view::npos || !evict_one()) throw;
    }
  }
}

Session::Node Session::locate(std::string_view path, bool follow_last, const std::function<bool()> &cancelled) {
  std::lock_guard lock(mu_);
  touch();
  const auto layers = layers_of(path);
  std::shared_ptr<FileSystem> fs = root_;
  std::string prefix;
  std::uint32_t depth = 1;
  for (std::size_t k = 0; k < layers.size(); ++k) {
    const bool last = k + 1 == layers.size();
    auto idx = fs->find(split_path(layers[k]), last ? follow_last : true, limits_.max_symlink_hops);
    if (!idx) throw Error("no such file: " + shown(prefix + std::string(layers[k])));
    Node n{fs, *idx, prefix + fs->path_of(*idx), prefix, depth};
    if (last) return n;
    auto sub = mount(n, cancelled);
    if (!sub) throw Error(shown(n.path) + " is not a container");
    fs = sub;
    prefix = n.path + "!";
    ++depth;
  }
  return {};
}

std::shared_ptr<FileSystem> Session::mount(const Node &file, const std::function<bool()> &cancelled) {
  std::lock_guard lock(mu_);
  touch();
  if (auto it = cache_.find(file.path); it != cache_.end() && it->second.fs) {
    it->second.tick = ++tick_;
    return it->second.fs;
  }
  if (file.depth + 1 > limits_.max_depth)
    throw LimitError("containers nest deeper than " + std::to_string(limits_.max_depth) + " levels");
  const Context ctx = context(cancelled);
  // Recognise from the head before decompressing all of it; else a
  // payload the rest of it holds.
  std::string format = container_format(file, cancelled);
  if (format.empty()) format = payload_format(file, cancelled);
  if (format.empty()) return nullptr;
  auto src = open_entry(file, ctx);
  const std::string name = file.fs->entry(file.entry).name;
  std::shared_ptr<FileSystem> fs;
  for (;;) {
    try {
      fs = open_format(format, src, name, ctx);
      // An asar's unpacked files are in <name>.unpacked beside it.
      if (format == "asar") attach_unpacked(*fs, file, ctx);
      break;
    } catch (const LimitError &err) {
      if (std::string_view(err.what()).find("the session holds") == std::string_view::npos || !evict_one()) throw;
    }
  }
  while (cache_.size() >= 32 && evict_one()) {
  }
  cache_[file.path] = Cached{src, fs, ++tick_};
  return fs;
}

std::vector<std::byte> Session::head(const Node &node, std::uint64_t n, const std::function<bool()> &cancelled) {
  std::lock_guard lock(mu_);
  if (auto it = cache_.find(node.path); it != cache_.end()) return it->second.src->head(n);
  const Entry &e = node.fs->entry(node.entry);
  std::uint32_t target = node.entry;
  if (e.kind == Kind::symlink || e.kind == Kind::hardlink) {
    auto t = node.fs->resolve_link(node.entry, limits_.max_symlink_hops);
    if (!t) return {};
    target = *t;
  }
  if (node.fs->entry(target).kind != Kind::file) return {};
  return node.fs->head(target, n, context(cancelled));
}

std::string Session::container_format(const Node &file, const std::function<bool()> &cancelled) {
  const Entry &e = file.fs->entry(file.entry);
  if (e.kind == Kind::directory) return "";
  const auto h = head(file, kIdentifyBytes, cancelled);
  return identify_head(h, e.size == UINT64_MAX ? h.size() : e.size);
}

std::string Session::payload_format(const Node &file, const std::function<bool()> &cancelled) {
  std::lock_guard lock(mu_);
  const Entry &e = file.fs->entry(file.entry);
  if (e.kind == Kind::directory) return "";
  auto src = open_entry(file, context(cancelled));
  return identify_payload(*src, cancelled);
}

Guess Session::describe(const Node &file, const std::function<bool()> &cancelled, Payloads payloads) {
  const Entry &e = file.fs->entry(file.entry);
  if (e.kind == Kind::directory) return {"directory", "directory", "", "", "", ""};
  if (e.kind != Kind::file && e.kind != Kind::hardlink && e.kind != Kind::symlink)
    return {std::string(name(e.kind)), std::string(name(e.kind)), "", "", "", ""};
  const auto h = head(file, kIdentifyBytes, cancelled);
  const std::uint64_t size = e.size == UINT64_MAX ? h.size() : e.size;
  const std::string format = identify_head(h, size);
  Guess g = guess(h, size == 0 && !h.empty() ? h.size() : size, format);
  const bool looks = g.kind == "elf" || g.kind == "pe" || g.kind == "macho" || g.kind == "raw";
  if (looks && payloads != Payloads::no) {
    std::uint32_t target = file.entry;
    if (e.kind != Kind::file) {
      auto t = file.fs->resolve_link(file.entry, limits_.max_symlink_hops);
      if (!t) return g;
      target = *t;
    }
    if (payloads == Payloads::yes || file.fs->stored_plain(target)) {
      try {
        g.payload = payload_format(file, cancelled);
      } catch (const Error &) {
      }
    }
  }
  return g;
}

void Session::attach_unpacked(FileSystem &fs, const Node &file, const Context &) {
  // The folder beside the archive, in the archive's own layer.
  const Entry &e = file.fs->entry(file.entry);
  auto dir_components = file.fs->components_of(e.parent);
  dir_components.push_back(e.name + ".unpacked");
  auto dir = file.fs->find(dir_components, true, limits_.max_symlink_hops);
  if (!dir || file.fs->entry(*dir).kind != Kind::directory) return;
  std::weak_ptr<FileSystem> layer = file.fs;
  detail::attach_asar_unpacked(fs, [layer, dir_components, hops = limits_.max_symlink_hops](
                                       const std::vector<std::string> &components, const Context &ctx)
                                       -> std::shared_ptr<Source> {
    auto parent = layer.lock();
    if (!parent) return nullptr;
    auto path = dir_components;
    path.insert(path.end(), components.begin(), components.end());
    auto f = parent->find(path, true, hops);
    if (!f || parent->entry(*f).kind != Kind::file) return nullptr;
    return parent->open(*f, ctx);
  });
}

std::shared_ptr<const Source> Session::open_file(std::string_view path, const std::function<bool()> &cancelled) {
  std::lock_guard lock(mu_);
  Node n = locate(path, true, cancelled);
  return open_entry(n, context(cancelled));
}

std::string Session::container_path(std::string_view session_path) const {
  std::string p(session_path.empty() ? "/" : session_path);
  if (!root_dir_.empty()) return "file://" + root_dir_ + (p == "/" ? "" : p);
  return root_->format() + "://" + encode_component(root_name_) + "!" + p;
}

}  // namespace revkit::container
