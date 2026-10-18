// Electron's asar archives (resources/app.asar): a Chromium pickle holding a
// JSON header, then the files' bytes. Format from @electron/asar (MIT):
// lib/disk.ts and lib/filesystem.ts write
//
//   u32 4                      the size pickle's payload size
//   u32 H                      the header pickle's size
//   u32 H - 4                  the header pickle's payload size
//   u32 n                      the JSON's length, then n bytes, padded to 4
//   ...files...                from 8 + H; each file's "offset" (a decimal
//                              string) counts from there
//
// The JSON is {"files": {name: entry}}, an entry being a directory
// {"files": {...}}, a file {"size", "offset", "executable", "integrity",
// "unpacked"}, or a link {"link": "target"}. An "unpacked" file's bytes
// aren't in the archive but in <archive>.unpacked/ beside it: the session
// attaches that directory when the archive is inside a container or a host
// directory (attach_asar_unpacked); otherwise they are listed, unreadable.
#include "asar.hh"

#include "formats.hh"
#include "json.hh"

#include <algorithm>

namespace revkit::container::detail {

namespace {

constexpr std::uint64_t kMaxHeader = 64ull << 20;

std::string js_kind(std::string_view name) {
  auto ext = [&](std::string_view e) { return name.size() > e.size() && name.ends_with(e); };
  if (ext(".js") || ext(".mjs") || ext(".cjs") || ext(".jsx")) return "js-source";
  if (ext(".ts") || ext(".tsx") || ext(".mts") || ext(".cts")) return "ts-source";
  if (ext(".jsc")) return "v8-cache";
  if (ext(".node")) return "";  // a native addon: its own header says ELF or PE
  if (ext(".asar")) return "asar";
  return "";
}

class Asar final : public AsarFileSystem {
 public:
  using AsarFileSystem::AsarFileSystem;

  void parse(const Context &ctx) {
    format_ = "asar";
    const std::uint64_t size = src_->size();
    const auto h = src_->read_exact(0, 16, "the asar header");
    Buf b(h, "the asar header");
    if (b.l32(0) != 4) throw Error("not an asar archive (the size pickle isn't 4 bytes)");
    const std::uint64_t hsize = b.l32(4), payload = b.l32(8), jlen = b.l32(12);
    if (hsize > kMaxHeader) throw LimitError("the asar header is over 64 MiB");
    if (8 + hsize > size) throw Error("the asar header runs past the end of the file");
    if (payload + 4 != hsize || jlen + 4 > payload) throw Error("the asar header's sizes don't agree");
    const auto js = src_->read_exact(16, jlen, "the asar header");
    data_ = 8 + hsize;
    const Json root = parse_json(std::string_view(reinterpret_cast<const char *>(js.data()), js.size()),
                                 2 * ctx.limits.max_dir_depth + 4);
    const Json *files = root.get("files");
    if (!files || !files->is_object()) throw Error("the asar header has no \"files\"");
    TreeBuilder tree(*this, ctx.limits);
    std::uint64_t count = 0, packed = 0, unpacked = 0, links = 0;
    std::function<void(const Json &, const std::string &, std::uint32_t)> walk = [&](const Json &dir,
                                                                                      const std::string &prefix,
                                                                                      std::uint32_t depth) {
      if (depth > ctx.limits.max_dir_depth) throw LimitError("the asar's directories nest too deep");
      for (const auto &[name, e] : dir.fields) {
        ctx.check_cancelled();
        if (++count > ctx.limits.max_entries)
          throw LimitError("the asar lists more than " + std::to_string(ctx.limits.max_entries) + " entries");
        if (!e.is_object()) {
          warn("\"" + display_name(prefix + name) + "\" is not an entry");
          continue;
        }
        const std::string path = prefix + name;
        if (const Json *sub = e.get("files"); sub && sub->is_object()) {
          Entry d;
          d.kind = Kind::directory;
          tree.add_path(path, d);
          walk(*sub, path + "/", depth + 1);
          continue;
        }
        if (const Json *link = e.get("link"); link && link->is_string()) {
          Entry l;
          l.kind = Kind::symlink;
          l.link_target = link->str;
          // Links are relative to the archive's root, not the link's directory.
          if (!l.link_target.empty() && l.link_target[0] != '/') l.link_target = "/" + l.link_target;
          l.size = l.link_target.size();
          l.loc2 = UINT64_MAX;
          tree.add_path(path, l);
          ++links;
          continue;
        }
        Entry f;
        f.kind = Kind::file;
        const Json *sz = e.get("size");
        auto n = sz ? sz->as_u64() : std::nullopt;
        if (!n) {
          warn("\"" + display_name(path) + "\" has no size");
          continue;
        }
        f.size = *n;
        f.stored_size = *n;
        f.content_kind = js_kind(name);
        if (const Json *x = e.get("executable"); x && x->type == Json::Type::boolean && x->b) {
          f.mode = 0755;
          f.has_mode = true;
        }
        if (const Json *u = e.get("unpacked"); u && u->type == Json::Type::boolean && u->b) {
          f.loc2 = kUnpacked;
          f.note = "unpacked: in " + display_name(name_) + ".unpacked beside the archive";
          ++unpacked;
        } else {
          const Json *off = e.get("offset");
          auto o = off ? off->as_u64() : std::nullopt;
          if (!o || *o > size - data_ || *n > size - data_ - *o) {
            f.loc2 = UINT64_MAX;
            f.note = "its data lies outside the archive";
          } else {
            f.loc0 = data_ + *o;
            f.loc1 = *n;
          }
          ++packed;
        }
        tree.add_path(path, f);
      }
    };
    walk(*files, "", 0);
    tree.finish();
    description_ = "Electron asar archive, " + plural(packed + unpacked, "file", "files") +
                   (unpacked ? " (" + std::to_string(unpacked) + " unpacked)" : "") +
                   (links ? ", " + plural(links, "link", "links") : "");
  }

  void set_name(std::string_view n) {
    const auto slash = n.find_last_of('/');
    name_ = std::string(slash == std::string_view::npos ? n : n.substr(slash + 1));
  }

 private:
  std::uint64_t data_ = 0;
  std::string name_ = "app.asar";
};

}  // namespace

std::shared_ptr<Source> AsarFileSystem::open(std::uint32_t entry, const Context &ctx) const {
  const std::uint32_t t = target_of(entry);
  const Entry &e = entries_.at(t);
  if (e.loc2 != kUnpacked) return SliceFileSystem::open(entry, ctx);
  if (!unpacked_) throw Error(display_name(e.name) + ": " + e.note + " (open the folder holding both to read it)");
  auto src = unpacked_(components_of(t), ctx);
  if (!src) throw Error(display_name(e.name) + ": not found in the .unpacked folder");
  return src;
}

std::vector<std::byte> AsarFileSystem::head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const {
  const Entry &e = entries_.at(target_of(entry));
  if (e.loc2 != kUnpacked) return SliceFileSystem::head(entry, n, ctx);
  return open(entry, ctx)->head(n);
}

bool AsarFileSystem::has_unpacked() const {
  return std::any_of(entries_.begin(), entries_.end(), [](const Entry &e) { return e.loc2 == kUnpacked; });
}

void AsarFileSystem::attach_unpacked(Resolver r) {
  unpacked_ = std::move(r);
  for (Entry &e : entries_)
    if (e.loc2 == kUnpacked) e.note = "unpacked: read from the .unpacked folder beside the archive";
}

void attach_asar_unpacked(FileSystem &fs, AsarFileSystem::Resolver r) {
  if (auto *a = dynamic_cast<AsarFileSystem *>(&fs); a && a->has_unpacked()) a->attach_unpacked(std::move(r));
}

bool asar_header(std::span<const std::byte> b, std::uint64_t size) {
  if (b.size() < 32 || le32(b.data()) != 4) return false;
  const std::uint64_t hsize = le32(b.data() + 4), payload = le32(b.data() + 8), jlen = le32(b.data() + 12);
  if (payload + 4 != hsize || jlen + 4 > payload || 8 + hsize > size) return false;
  std::string_view j(reinterpret_cast<const char *>(b.data() + 16), std::min<std::size_t>(b.size() - 16, 16));
  return j.starts_with("{\"files\":");
}

std::shared_ptr<FileSystem> open_asar(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx) {
  auto fs = std::make_shared<Asar>(std::move(src));
  fs->set_name(name.empty() ? "app.asar" : name);
  fs->parse(ctx);
  return fs;
}

}  // namespace revkit::container::detail
