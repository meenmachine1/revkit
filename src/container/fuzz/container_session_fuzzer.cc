// A browsing session over hostile bytes (container::Session), as
// FileSystemService runs it: the outermost container by magic, containers
// nested in it mounted on demand two and three layers deep, paths as a
// client sends them (layers split by '!', percent-encoded components,
// links followed inside their layer, crafted ".." and long names),
// identify()/guess() of each file, and decode_component of each
// component. Input: up to 16 newline-separated paths, a NUL, then the
// container. Limits are small so a run stays fast.
#include "revkit/container/container.hh"
#include "revkit/container/session.hh"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using namespace revkit::container;

namespace {

Limits SmallLimits() {
  Limits l;
  l.max_file_bytes = 8 << 20;
  l.max_total_bytes = 32 << 20;
  l.max_entries = 4096;
  l.max_depth = 4;
  l.memory_threshold = 32 << 20;
  return l;
}

// Every file of a layer described, the containers among them mounted and
// walked in turn, `depth` layers down at most.
void Walk(Session &s, const std::string &prefix, const std::shared_ptr<FileSystem> &fs, int depth, int &budget) {
  for (std::uint32_t i = 0; i < fs->entries().size() && budget > 0; ++i, --budget) {
    if (fs->entry(i).kind != Kind::file) continue;
    Session::Node n{fs, i, prefix + fs->path_of(i), prefix, static_cast<std::uint32_t>(depth)};
    try {
      (void)s.describe(n);
      if (depth >= 3) continue;
      if (auto inner = s.mount(n)) Walk(s, n.path + "!", inner, depth + 1, budget);
    } catch (const Error &) {
    }
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  const std::string_view in(reinterpret_cast<const char *>(data), size);
  const std::size_t nul = in.find('\0');
  if (nul == std::string_view::npos) return 0;
  std::vector<std::string> paths;
  for (std::size_t at = 0; at < nul && paths.size() < 16;) {
    const std::size_t nl = std::min(in.find('\n', at), nul);
    paths.emplace_back(in.substr(at, nl - at));
    at = nl + 1;
  }
  const std::string_view body = in.substr(nul + 1);
  std::vector<std::byte> bytes(body.size());
  for (std::size_t i = 0; i < body.size(); ++i) bytes[i] = static_cast<std::byte>(body[i]);
  (void)identify_head(bytes, bytes.size());
  (void)guess(bytes, bytes.size());
  std::shared_ptr<Session> s;
  try {
    s = Session::open(memory_source(std::move(bytes)), "fuzz.bin", SmallLimits());
  } catch (const Error &) {
    return 0;
  }
  int budget = 2048;
  Walk(*s, "", s->root(), 1, budget);
  for (std::size_t k = 0; k < paths.size(); ++k) {
    const std::string &p = paths[k];
    for (std::size_t at = 0; at <= p.size();) {
      const std::size_t slash = std::min(p.find('/', at), p.size());
      try {
        (void)decode_component(std::string_view(p).substr(at, slash - at));
      } catch (const Error &) {  // a malformed escape
      }
      at = slash + 1;
    }
    try {
      const Session::Node n = s->locate(p, k & 1);
      (void)s->container_path(n.path);
      (void)s->container_format(n);
      if (n.fs->entry(n.entry).kind == Kind::file) {
        (void)s->head(n, 64);
        auto src = s->open_file(p);
        std::vector<std::byte> buf(4096);
        if (src->size()) src->read(src->size() - 1, buf);
      }
    } catch (const Error &) {
    }
  }
  return 0;
}
