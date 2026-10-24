#include "revkit/android/apk_layer.hh"

namespace revkit::android {

namespace {

std::vector<std::string> split(const std::string &p) {
  std::vector<std::string> out;
  std::size_t at = 0;
  while (at <= p.size()) {
    const std::size_t slash = p.find('/', at);
    const std::size_t end = slash == std::string::npos ? p.size() : slash;
    if (end > at) out.push_back(p.substr(at, end - at));
    if (slash == std::string::npos) break;
    at = slash + 1;
  }
  return out;
}

bool has_manifest(const container::FileSystem &fs) {
  auto i = fs.find({"AndroidManifest.xml"}, true);
  return i && fs.entry(*i).kind == container::Kind::file;
}

}  // namespace

std::unique_ptr<ApkLayer> ApkLayer::open(std::shared_ptr<container::Session> session, const std::string &path,
                                         std::function<bool()> cancelled) {
  std::unique_ptr<ApkLayer> l(new ApkLayer());
  l->session_ = session;
  l->cancelled_ = cancelled;
  if (path.empty() || path == "/") {
    l->fs_ = session->root();
    l->prefix_.clear();
  } else {
    const container::Session::Node n = session->locate(path, true, cancelled);
    const container::Kind k = n.fs->entry(n.entry).kind;
    std::shared_ptr<container::FileSystem> sub;
    if (k == container::Kind::file || k == container::Kind::hardlink) sub = session->mount(n, cancelled);
    if (sub && has_manifest(*sub)) {
      l->fs_ = sub;
      l->prefix_ = n.path + "!";
    } else {
      l->fs_ = n.fs;
      l->prefix_ = n.prefix;
    }
  }
  if (!l->fs_ || !has_manifest(*l->fs_))
    throw container::Error("not an Android package: no AndroidManifest.xml at the root of " +
                           (l->prefix_.empty() ? std::string("the outermost container") : l->prefix_));
  return l;
}

std::string ApkLayer::session_path(const std::string &member) const {
  return prefix_ + container::join_path(split(member));
}

std::vector<std::string> ApkLayer::list() {
  std::vector<std::string> out;
  const auto &entries = fs_->entries();
  for (std::uint32_t i = 0; i < entries.size(); ++i) {
    if (entries[i].kind != container::Kind::file) continue;
    std::string p;
    for (const std::string &c : fs_->components_of(i)) p += (p.empty() ? "" : "/") + c;
    if (!p.empty()) out.push_back(std::move(p));
  }
  return out;
}

std::optional<std::uint64_t> ApkLayer::size(const std::string &path) {
  auto i = fs_->find(split(path), true);
  if (!i || fs_->entry(*i).kind != container::Kind::file) return std::nullopt;
  return fs_->entry(*i).size;
}

std::vector<std::byte> ApkLayer::read(const std::string &path, std::uint64_t max) {
  auto src = session_->open_file(session_path(path), cancelled_);
  if (src->size() > max) throw Error(path + " is larger than " + std::to_string(max) + " bytes");
  return src->read_exact(0, src->size(), path);
}

}  // namespace revkit::android
