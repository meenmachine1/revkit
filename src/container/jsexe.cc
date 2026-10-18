// JavaScript packed into native executables (docs/filesystems.md, "Packed
// executables"): Node's single executable applications, pkg, nexe and Bun.
// Each is found in the executable that carries it and listed as files: the
// scripts as source (content kind "js-source") or V8 code caches, their
// assets, and the packer's own index. Formats from the projects' sources
// (all MIT): nodejs/node src/node_sea.cc and node_sea.h (v20.0 to v26),
// nodejs/postject (where the blob is injected), yao-pkg/pkg and vercel/pkg
// (lib/producer.ts, lib/packer.ts, prelude/bootstrap.js), nexe/nexe
// (src/compiler.ts, src/steps/shim.ts, v3 to v5), oven-sh/bun
// (src/StandaloneModuleGraph.zig, 1.0 to 1.3). Nothing is decompressed but
// what a format compresses, through the containers' own decoders.
#include "jsexe.hh"

#include "bytecode.hh"
#include "exe.hh"
#include "formats.hh"
#include "json.hh"

#include <algorithm>
#include <map>

namespace revkit::container::detail {

namespace {

std::string base_name(std::string_view p) {
  const auto s = p.find_last_of("/\\");
  return std::string(s == std::string_view::npos ? p : p.substr(s + 1));
}

std::string js_kind(std::string_view name) {
  auto ext = [&](std::string_view e) { return name.size() > e.size() && name.ends_with(e); };
  if (ext(".js") || ext(".mjs") || ext(".cjs") || ext(".jsx")) return "js-source";
  if (ext(".ts") || ext(".tsx") || ext(".mts") || ext(".cts")) return "ts-source";
  return "";
}

// A path from a packer's virtual file system as a tree path: drive letters
// and the root's separator dropped, backslashes as slashes.
std::string tree_path(std::string p) {
  std::replace(p.begin(), p.end(), '\\', '/');
  if (p.size() >= 2 && p[1] == ':' && std::isalpha(static_cast<unsigned char>(p[0]))) p = p.substr(2);
  return p;
}

// Searches [from, to) of `src` backwards for `needle`, in windows; the
// offset of the last occurrence.
std::optional<std::uint64_t> rfind(const Source &src, std::string_view needle, std::uint64_t from, std::uint64_t to) {
  constexpr std::uint64_t kWindow = 4ull << 20;
  if (to > src.size()) to = src.size();
  if (to < from + needle.size()) return std::nullopt;
  std::uint64_t end = to;
  for (;;) {
    const std::uint64_t start = end - from > kWindow ? end - kWindow : from;
    const auto w = src.read_exact(start, end - start, "the file");
    const std::string_view v(reinterpret_cast<const char *>(w.data()), w.size());
    if (auto i = v.rfind(needle); i != std::string_view::npos) return start + i;
    if (start == from) return std::nullopt;
    end = start + needle.size() - 1;
  }
}

std::optional<std::uint64_t> find(const Source &src, std::string_view needle, std::uint64_t from, std::uint64_t to) {
  constexpr std::uint64_t kWindow = 4ull << 20;
  if (to > src.size()) to = src.size();
  for (std::uint64_t start = from; start + needle.size() <= to;) {
    const std::uint64_t end = std::min(to, start + kWindow);
    const auto w = src.read_exact(start, end - start, "the file");
    const std::string_view v(reinterpret_cast<const char *>(w.data()), w.size());
    if (auto i = v.find(needle); i != std::string_view::npos) return start + i;
    if (end == to) break;
    start = end - (needle.size() - 1);
  }
  return std::nullopt;
}

class Js : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;

 protected:
  std::uint32_t add(TreeBuilder &tree, const std::string &path, std::uint64_t off, std::uint64_t len,
                    std::string kind = {}, std::string note = {}, Codec codec = Codec::deflate, bool compressed = false,
                    std::uint64_t size = UINT64_MAX) {
    Entry e;
    e.kind = Kind::file;
    e.loc0 = off;
    e.loc1 = len;
    e.stored_size = len;
    e.size = compressed ? size : len;
    e.loc2 = compressed ? 1 + static_cast<std::uint64_t>(codec) : 0;
    if (off > src_->size() || len > src_->size() - off) {
      e.loc2 = UINT64_MAX;
      note = "its data lies outside the file";
    }
    e.content_kind = kind.empty() ? js_kind(path) : kind;
    e.note = std::move(note);
    ++files_;
    return tree.add_path(path, e);
  }
  std::uint64_t files_ = 0;
};

// ---- Node.js single executable applications ------------------------------

constexpr std::uint32_t kSeaMagic = 0x0143da20;
constexpr std::uint32_t kSeaSnapshot = 1u << 1, kSeaCodeCache = 1u << 2, kSeaAssets = 1u << 3, kSeaExecArgv = 1u << 4;

std::optional<Range> find_sea_blob(const Source &src) {
  std::optional<Range> r;
  switch (exe_format(src)) {
    case ExeFormat::elf: r = elf_note(src, "NODE_SEA_BLOB"); break;
    case ExeFormat::pe: r = pe_resource(src, "RCDATA", "NODE_SEA_BLOB"); break;
    case ExeFormat::macho: r = macho_section(src, "NODE_SEA", "__NODE_SEA_BLOB"); break;
    case ExeFormat::none: break;
  }
  if (!r || r->size < 8) return std::nullopt;
  const auto m = src.read_exact(r->offset, 4, "the SEA blob");
  if (le32(m.data()) != kSeaMagic) return std::nullopt;
  return r;
}

struct SeaLayout {
  int version = 0;  // 0: v20.0-20.2, 1: 20.3-20.5, 2: 20.6-24.6, 3: 22.20/24.7-25.7, 4: 25.8 and later
  unsigned size_t_bytes = 8;
  std::uint32_t flags = 0;
  int exec_argv_extension = -1, module_format = -1;
  std::string code_path;
  Range main, cache;
  bool has_cache = false;
  std::vector<std::pair<std::string, Range>> assets;
  std::vector<std::string> exec_argv;
};

// The blob read as one layout; nullopt when it doesn't fit exactly.
std::optional<SeaLayout> sea_layout(std::span<const std::byte> b, std::uint64_t base, int version, unsigned st) {
  SeaLayout l;
  l.version = version;
  l.size_t_bytes = st;
  std::size_t p = 4;
  auto need = [&](std::uint64_t n) { return p <= b.size() && n <= b.size() - p; };
  auto size = [&]() -> std::optional<std::uint64_t> {
    if (!need(st)) return std::nullopt;
    const std::uint64_t v = st == 8 ? le64(b.data() + p) : le32(b.data() + p);
    p += st;
    return v;
  };
  auto strv = [&]() -> std::optional<Range> {
    auto n = size();
    if (!n || !need(*n)) return std::nullopt;
    Range r{base + p, *n};
    p += static_cast<std::size_t>(*n);
    return r;
  };
  auto text = [&](Range r) { return std::string(reinterpret_cast<const char *>(b.data() + (r.offset - base)), r.size); };
  if (version == 0) {
    l.main = {base + 4, b.size() - 4};
    return l;
  }
  if (!need(4)) return std::nullopt;
  l.flags = le32(b.data() + p);
  p += 4;
  if (l.flags >> 7) return std::nullopt;
  if (version >= 3) {
    if (!need(1)) return std::nullopt;
    l.exec_argv_extension = static_cast<std::uint8_t>(b[p++]);
    if (l.exec_argv_extension > 2) return std::nullopt;
  }
  if (version >= 4) {
    if (!need(1)) return std::nullopt;
    l.module_format = static_cast<std::uint8_t>(b[p++]);
    if (l.module_format > 1) return std::nullopt;
  }
  if (version >= 2) {
    auto cp = strv();
    if (!cp || cp->size > 4096) return std::nullopt;
    l.code_path = text(*cp);
    for (char c : l.code_path)
      if (static_cast<unsigned char>(c) < 0x20) return std::nullopt;
  }
  auto main = strv();
  if (!main) return std::nullopt;
  l.main = *main;
  if (version >= 2 && (l.flags & kSeaCodeCache)) {
    auto c = strv();
    if (!c) return std::nullopt;
    l.cache = *c;
    l.has_cache = true;
  }
  if (version >= 2 && (l.flags & kSeaAssets)) {
    auto n = size();
    if (!n || *n > 1000000) return std::nullopt;
    for (std::uint64_t i = 0; i < *n; ++i) {
      auto k = strv();
      if (!k || k->size > 4096) return std::nullopt;
      auto v = strv();
      if (!v) return std::nullopt;
      l.assets.emplace_back(text(*k), *v);
    }
  }
  if (version >= 3 && (l.flags & kSeaExecArgv)) {
    auto n = size();
    if (!n || *n > 4096) return std::nullopt;
    for (std::uint64_t i = 0; i < *n; ++i) {
      auto a = strv();
      if (!a || a->size > 4096) return std::nullopt;
      l.exec_argv.push_back(text(*a));
    }
  }
  if (p != b.size()) return std::nullopt;
  return l;
}

class NodeSea final : public Js {
 public:
  using Js::Js;
  void parse(const Context &ctx) {
    format_ = "node-sea";
    auto r = find_sea_blob(*src_);
    if (!r) throw Error("no Node.js SEA blob (NODE_SEA_BLOB)");
    if (r->size > ctx.limits.max_file_bytes) throw LimitError("the SEA blob is larger than the file limit");
    const auto blob = src_->read_exact(r->offset, r->size, "the SEA blob");
    std::optional<SeaLayout> l;
    for (int v : {4, 3, 2, 1})
      for (unsigned st : {8u, 4u})
        if (!l) l = sea_layout(blob, r->offset, v, st);
    if (!l) {
      l = sea_layout(blob, r->offset, 0, 8);
      warn("the SEA blob's layout isn't one this reader knows: its bytes after the magic are listed as the script");
    }
    TreeBuilder tree(*this, ctx.limits);
    std::string main = l->code_path.empty() ? "main.js" : base_name(l->code_path);
    if (main.empty()) main = "main.js";
    if (l->flags & kSeaSnapshot) {
      add(tree, "startup.snapshot", l->main.offset, l->main.size, "v8-snapshot", "the V8 startup snapshot (--snapshot)");
    } else {
      add(tree, main, l->main.offset, l->main.size, "js-source",
          l->module_format == 1 ? "the main script (ES module)" : "the main script");
    }
    if (l->has_cache)
      add(tree, main + ".cache", l->cache.offset, l->cache.size, "v8-cache",
          "the main script's V8 code cache (useCodeCache)");
    for (const auto &[key, v] : l->assets) {
      std::string path = "assets/" + tree_path(key);
      if (key == "node:sea:vfs.zip") path = "assets/vfs.zip";
      add(tree, path, v.offset, v.size, {}, "an asset (sea.getAsset(\"" + display_name(key) + "\"))");
    }
    tree.finish();
    static const char *versions[] = {"Node 20.0 to 20.2", "Node 20.3 to 20.5", "Node 20.6 to 24.6",
                                     "Node 22.20, 24.7 and later", "Node 25.8 and later"};
    description_ = "Node.js single executable application (" + std::string(versions[l->version]) + " layout), " +
                   plural(files_, "file", "files");
    if (!l->code_path.empty()) description_ += ", main " + display_name(l->code_path);
    if (!l->exec_argv.empty()) {
      std::string a;
      for (const std::string &x : l->exec_argv) a += (a.empty() ? "" : " ") + x;
      description_ += ", execArgv " + display_name(a);
    }
  }
};

// ---- pkg ----------------------------------------------------------------

constexpr std::string_view kPkgPrelude =
    "(function(process, require, console, EXECPATH_FD, PAYLOAD_POSITION, PAYLOAD_SIZE) { return (function "
    "(REQUIRE_COMMON, REQUIRE_SHARED, VIRTUAL_FILESYSTEM, DEFAULT_ENTRYPOINT, SYMLINKS, DICT, DOCOMPRESS) {";
constexpr std::string_view kPkgEnd = "\n);\n})";
constexpr std::uint64_t kPkgTail = 64ull << 20;  // where the prelude is looked for: it ends the file, near a signature

struct PkgPrelude {
  std::uint64_t at = 0, end = 0;
};

std::optional<PkgPrelude> find_pkg(const Source &src) {
  const std::uint64_t size = src.size();
  if (size < kPkgPrelude.size() + kPkgEnd.size()) return std::nullopt;
  // The prelude ends the file, or (macOS) comes before its code signature.
  std::uint64_t end = 0;
  const auto t = src.read_exact(size - kPkgEnd.size(), kPkgEnd.size(), "the end of the file");
  if (std::memcmp(t.data(), kPkgEnd.data(), kPkgEnd.size()) == 0) {
    end = size;
  } else if (exe_format(src) == ExeFormat::macho) {
    auto e = rfind(src, kPkgEnd, size > kPkgTail ? size - kPkgTail : 0, size);
    if (!e) return std::nullopt;
    end = *e + kPkgEnd.size();
  } else {
    return std::nullopt;
  }
  auto at = rfind(src, kPkgPrelude, end > kPkgTail ? end - kPkgTail : 0, end);
  if (!at) return std::nullopt;
  return PkgPrelude{*at, end};
}

class Pkg final : public Js {
 public:
  using Js::Js;
  void parse(const Context &ctx) {
    format_ = "pkg";
    auto pre = find_pkg(*src_);
    if (!pre) throw Error("no pkg prelude");
    if (pre->end - pre->at > (64ull << 20)) throw LimitError("the pkg prelude is over 64 MiB");
    const auto pb = src_->read_exact(pre->at, pre->end - pre->at, "the pkg prelude");
    std::string_view text(reinterpret_cast<const char *>(pb.data()), pb.size());
    text.remove_suffix(kPkgEnd.size());
    // The last five arguments, JSON with no raw newlines, from the end:
    // the file system, the entry point, the links, the names' dictionary,
    // the compression.
    std::string_view args[5];
    for (int i = 4; i >= 1; --i) {
      const auto k = text.rfind("\n,\n");
      if (k == std::string_view::npos) throw Error("the pkg prelude's arguments are missing");
      args[i] = text.substr(k + 3);
      text = text.substr(0, k);
    }
    const auto v = text.rfind("})(),\n");
    if (v == std::string_view::npos) throw Error("the pkg prelude's file system is missing");
    args[0] = text.substr(v + 6);
    const Json vfs = parse_json(args[0], 16, 8ull * ctx.limits.max_entries + 64);
    const Json entry = parse_json(args[1], 4);
    const Json links = parse_json(args[2], 4, 4ull * ctx.limits.max_entries + 64);
    const Json dict = parse_json(args[3], 4, 4ull * ctx.limits.max_entries + 64);
    const Json compress = parse_json(args[4], 2);
    if (!vfs.is_object()) throw Error("the pkg file system isn't an object");
    // 0 none, 1 gzip, 2 Brotli, 3 zstd; anything else is unknown (-1).
    int method = 0;
    if (compress.is_number()) method = compress.num >= 0 && compress.num < 16 ? static_cast<int>(compress.num) : -1;
    // Keys are path components through the dictionary when compressed.
    std::map<std::string, std::string> rev;
    if (dict.is_object())
      for (const auto &[k, id] : dict.fields)
        if (id.is_string()) rev[id.str] = k;
    auto original = [&](const std::string &key) {
      if (method == 0) return key;
      std::string out;
      std::size_t i = 0;
      for (;;) {
        const auto j = key.find('/', i);
        const std::string part = key.substr(i, j == std::string::npos ? std::string::npos : j - i);
        auto it = rev.find(part);
        out += it == rev.end() ? part : it->second;
        if (j == std::string::npos) break;
        out += '/';
        i = j + 1;
      }
      return out;
    };
    // The payload ends where the prelude starts; its size is the furthest
    // stripe's end.
    std::uint64_t payload = 0;
    for (const auto &[key, stores] : vfs.fields)
      for (const auto &[store, ptr] : stores.fields)
        if (ptr.is_array() && ptr.items.size() == 2)
          if (auto o = ptr.items[0].as_u64(), n = ptr.items[1].as_u64(); o && n && *o + *n >= *o)
            payload = std::max(payload, *o + *n);
    if (payload > pre->at) throw Error("the pkg payload doesn't fit before its prelude");
    const std::uint64_t base = pre->at - payload;
    Codec codec = Codec::gzip;
    std::string unread;
    if (method == 2) unread = "Brotli-compressed (pkg --compress Brotli): not read";
    else if (method == 3) codec = Codec::zstd;
    else if (method != 0 && method != 1) unread = "compressed by an unknown method " + std::to_string(method);
    TreeBuilder tree(*this, ctx.limits);
    std::uint64_t blobs = 0;
    for (const auto &[key, stores] : vfs.fields) {
      ctx.check_cancelled();
      if (!stores.is_object()) continue;
      const std::string path = tree_path(original(key));
      auto at = [&](const char *store) -> std::optional<std::pair<std::uint64_t, std::uint64_t>> {
        const Json *p = stores.get(store);
        if (!p || !p->is_array() || p->items.size() != 2) return std::nullopt;
        auto o = p->items[0].as_u64(), n = p->items[1].as_u64();
        if (!o || !n) return std::nullopt;
        return std::make_pair(base + *o, *n);
      };
      const auto content = at("1"), blob = at("0");
      auto put = [&](const std::string &p, std::pair<std::uint64_t, std::uint64_t> r, std::string kind, std::string note) {
        const std::uint32_t i = add(tree, p, r.first, r.second, std::move(kind), std::move(note), codec, method != 0);
        if (!unread.empty()) {
          Entry &e = entries_[i];
          e.loc2 = UINT64_MAX;
          e.note = unread;
        }
      };
      if (content) put(path, *content, {}, {});
      if (blob) {
        put(path + ".jsc", *blob, "v8-cache",
            "V8 code cache of the script, compiled by pkg (its source is left out)");
        ++blobs;
      }
      if (!content && !blob && stores.get("2")) {
        Entry d;
        d.kind = Kind::directory;
        tree.add_path(path, d);
      }
    }
    if (links.is_object())
      for (const auto &[from, to] : links.fields) {
        if (!to.is_string()) continue;
        Entry l;
        l.kind = Kind::symlink;
        l.link_target = tree_path(original(to.str));
        l.size = l.link_target.size();
        l.loc2 = UINT64_MAX;
        tree.add_path(tree_path(original(from)), l);
      }
    tree.finish();
    static const char *methods[] = {"", ", gzip", ", Brotli", ", zstd"};
    description_ = "pkg executable, " + plural(files_, "file", "files") +
                   (method >= 0 && method <= 3 ? methods[method] : "") +
                   (blobs ? " (" + std::to_string(blobs) + " compiled to V8 code caches)" : "");
    if (entry.is_string()) description_ += ", entry " + display_name(tree_path(entry.str));
  }
};

// ---- nexe ---------------------------------------------------------------

constexpr std::string_view kNexeSentinel = "<nexe~~sentinel>";

struct NexeTrailer {
  std::uint64_t code = 0, code_size = 0, resources = 0, resources_size = 0;
};

std::optional<NexeTrailer> find_nexe(const Source &src) {
  const std::uint64_t size = src.size();
  const std::uint64_t from = size > 16000 ? size - 16000 : 0;
  auto at = find(src, kNexeSentinel, from, size);
  if (!at || *at + 32 > size) return std::nullopt;
  const auto t = src.read_exact(*at + 16, 16, "the nexe trailer");
  double code, res;
  std::memcpy(&code, t.data(), 8);
  std::memcpy(&res, t.data() + 8, 8);
  if (!(code >= 0) || !(res >= 0) || code > 9e15 || res > 9e15) return std::nullopt;
  NexeTrailer n;
  n.code_size = static_cast<std::uint64_t>(code);
  n.resources_size = static_cast<std::uint64_t>(res);
  if (n.code_size + n.resources_size > *at) return std::nullopt;
  n.code = *at - n.resources_size - n.code_size;
  n.resources = *at - n.resources_size;
  return n;
}

class Nexe final : public Js {
 public:
  using Js::Js;
  void parse(const Context &ctx) {
    format_ = "nexe";
    auto t = find_nexe(*src_);
    if (!t) throw Error("no nexe trailer");
    TreeBuilder tree(*this, ctx.limits);
    add(tree, "nexe-launch.js", t->code, t->code_size, "js-source",
        "nexe's launcher and the bundled entry script, as one script");
    std::string layout = "nexe";
    // v3 and v4: the launcher sets process.__nexe = {"resources": {path:
    // [offset, length]}}; v5: the resources are a zip.
    bool listed = false;
    if (t->code_size <= (64ull << 20)) {
      const auto code = src_->read_exact(t->code, t->code_size, "the nexe launcher");
      std::string_view c(reinterpret_cast<const char *>(code.data()), code.size());
      constexpr std::string_view kSet = "process.__nexe = ";
      if (auto k = c.find(kSet); k != std::string_view::npos) {
        auto e = c.find(";\n", k);
        if (e != std::string_view::npos) {
          try {
            const Json cfg = parse_json(c.substr(k + kSet.size(), e - k - kSet.size()), 8,
                                        4ull * ctx.limits.max_entries + 64);
            if (const Json *res = cfg.get("resources"); res && res->is_object()) {
              for (const auto &[path, ptr] : res->fields) {
                if (!ptr.is_array() || ptr.items.size() < 2) continue;
                auto o = ptr.items[0].as_u64(), n = ptr.items[1].as_u64();
                if (!o || !n || *o > t->resources_size || *n > t->resources_size - *o) continue;
                add(tree, "resources/" + tree_path(path), t->resources + *o, *n);
              }
              listed = true;
              layout = "nexe 3 or 4";
            }
          } catch (const Error &err) {
            warn(std::string("nexe's resource index: ") + err.what());
          }
        }
      }
    }
    if (!listed && t->resources_size >= 4) {
      const auto h = src_->read_exact(t->resources, 4, "the nexe resources");
      if (std::memcmp(h.data(), "PK\3\4", 4) == 0) {
        add(tree, "resources.zip", t->resources, t->resources_size, {}, "nexe 5's resources: a zip of /snapshot/...");
        layout = "nexe 5";
      } else {
        add(tree, "resources.bin", t->resources, t->resources_size, {}, "the resources (no index found)");
      }
    }
    tree.finish();
    description_ = layout + " executable, " + plural(files_, "file", "files");
  }
};

// ---- Bun ------------------------------------------------------------------

constexpr std::string_view kBunTrailer = "\n---- Bun! ----\n";

struct BunBlob {
  std::uint64_t start = 0, size = 0;  // the blob: data, modules, argv, Offsets, trailer
};

// The blob ends in the trailer, so `end` is where it ends; byte_count says
// where it starts.
std::optional<BunBlob> bun_blob_ending(const Source &src, std::uint64_t end, std::uint64_t floor) {
  if (end < floor + 16 + 24) return std::nullopt;
  const auto t = src.read_exact(end - 16, 16, "the Bun trailer");
  if (std::memcmp(t.data(), kBunTrailer.data(), 16) != 0) return std::nullopt;
  for (std::uint64_t offsets : {32ull, 24ull}) {
    if (end < floor + 16 + offsets) continue;
    const auto o = src.read_exact(end - 16 - offsets, 8, "Bun's offsets");
    const std::uint64_t byte_count = le64(o.data());
    const std::uint64_t data_end = end - 16 - offsets;
    if (byte_count > data_end - floor) continue;
    return BunBlob{data_end - byte_count, end - (data_end - byte_count)};
  }
  return std::nullopt;
}

std::optional<BunBlob> find_bun(const Source &src) {
  const std::uint64_t size = src.size();
  try {
    // Appended (Linux to 1.3.11, Windows to 1.2.18, others): the blob,
    // then the file's original size + blob + 8 as a u64.
    if (size >= 64) {
      if (auto b = bun_blob_ending(src, size - 8, 0)) return b;
    }
    // In a section holding [u64 size][blob]: PE ".bun", Mach-O __BUN/__bun;
    // ELF ".bun" holding the virtual address of the [u64 size][blob].
    std::optional<Range> sec;
    switch (exe_format(src)) {
      case ExeFormat::pe: sec = pe_section(src, ".bun"); break;
      case ExeFormat::macho: sec = macho_section(src, "__BUN", "__bun"); break;
      case ExeFormat::elf:
        if (auto s = elf_section(src, ".bun"); s && s->size >= 8) {
          const auto v = src.read_exact(s->offset, 8, "the .bun section");
          if (auto off = elf_file_offset(src, le64(v.data()))) sec = Range{*off, size - *off};
        }
        break;
      case ExeFormat::none: break;
    }
    if (sec && sec->size >= 8) {
      const auto n = src.read_exact(sec->offset, 8, "the Bun blob's size");
      const std::uint64_t len = le64(n.data());
      if (len <= sec->size - 8)
        if (auto b = bun_blob_ending(src, sec->offset + 8 + len, sec->offset + 8)) return b;
    }
  } catch (const Error &) {
  }
  return std::nullopt;
}

class Bun final : public Js {
 public:
  using Js::Js;
  void parse(const Context &ctx) {
    format_ = "bun";
    auto blob = find_bun(*src_);
    if (!blob) throw Error("no Bun module graph");
    if (blob->size > ctx.limits.max_file_bytes) throw LimitError("the Bun blob is larger than the file limit");
    const auto b = src_->read_exact(blob->start, blob->size, "the Bun blob");
    const std::size_t end = b.size() - 16;
    // Offsets: byte_count, modules {offset, length}, entry point id, ...
    std::size_t off_at = 0;
    for (std::size_t sz : {32u, 24u}) {
      if (end < sz) continue;
      if (le64(b.data() + end - sz) == end - sz) {
        off_at = end - sz;
        break;
      }
    }
    if (!off_at) throw Error("Bun's offsets don't agree with its blob");
    const std::uint32_t mod_off = le32(b.data() + off_at + 8), mod_len = le32(b.data() + off_at + 12);
    const std::uint32_t entry_id = le32(b.data() + off_at + 16);
    if (mod_off > off_at || mod_len > off_at - mod_off) throw Error("Bun's module table lies outside its blob");
    // The module record's layout changed between versions and isn't
    // declared extern: the size whose names all parse wins. Names and
    // contents are its first two string pointers.
    struct Layout {
      std::size_t size;
      const char *versions;
    };
    const Layout layouts[] = {{52, "1.3.9 and later"}, {36, "1.2 to 1.3.8"}, {28, "1.0 and 1.1"}};
    auto sp_ok = [&](std::size_t at) {
      const std::uint32_t o = le32(b.data() + at), n = le32(b.data() + at + 4);
      return o <= off_at && n <= off_at - o;
    };
    auto name_at = [&](std::size_t rec) {
      const std::uint32_t o = le32(b.data() + rec), n = le32(b.data() + rec + 4);
      return std::string(reinterpret_cast<const char *>(b.data() + o), n);
    };
    const Layout *pick = nullptr;
    for (const Layout &l : layouts) {
      if (mod_len == 0 || mod_len % l.size) continue;
      bool ok = true;
      for (std::size_t r = mod_off; ok && r < std::size_t{mod_off} + mod_len; r += l.size) {
        ok = sp_ok(r) && sp_ok(r + 8);
        if (ok) {
          const std::string n = name_at(r);
          ok = !n.empty() && (n.find("$bunfs") != std::string::npos || n.find("~BUN") != std::string::npos ||
                              n[0] == '/' || n.find(':') == 1);
        }
      }
      if (ok) {
        pick = &l;
        break;
      }
    }
    if (!pick) throw Error("Bun's module records aren't in a layout this reader knows");
    TreeBuilder tree(*this, ctx.limits);
    const std::size_t count = mod_len / pick->size;
    std::string entry;
    for (std::size_t i = 0; i < count; ++i) {
      ctx.check_cancelled();
      const std::size_t r = mod_off + i * pick->size;
      std::string name = name_at(r);
      for (std::string_view prefix : {"/$bunfs/root/", "B:/~BUN/root/", "/$bunfs/", "B:/~BUN/"})
        if (name.starts_with(prefix)) {
          name = name.substr(prefix.size());
          break;
        }
      const std::uint32_t co = le32(b.data() + r + 8), cn = le32(b.data() + r + 12);
      add(tree, tree_path(name), blob->start + co, cn);
      if (i == entry_id) entry = name;
      // Bytecode (1.2 and later): JavaScriptCore's cache, not V8's.
      if (pick->size >= 36 && sp_ok(r + 24)) {
        const std::uint32_t bo = le32(b.data() + r + 24), bn = le32(b.data() + r + 28);
        if (bn) add(tree, tree_path(name) + ".jsc-bytecode", blob->start + bo, bn, "jsc-bytecode",
                    "JavaScriptCore bytecode cache (--bytecode)");
      }
    }
    tree.finish();
    description_ = "Bun executable (" + std::string(pick->versions) + " layout), " + plural(files_, "file", "files");
    if (!entry.empty()) description_ += ", entry " + display_name(entry);
  }
};

}  // namespace

bool node_sea_payload(const Source &src) { return find_sea_blob(src).has_value(); }
bool pkg_payload(const Source &src) {
  try {
    return find_pkg(src).has_value();
  } catch (const Error &) {
    return false;
  }
}
bool nexe_payload(const Source &src) {
  try {
    return find_nexe(src).has_value();
  } catch (const Error &) {
    return false;
  }
}
bool bun_payload(const Source &src) { return find_bun(src).has_value(); }

template <class T>
static std::shared_ptr<FileSystem> open_js(std::shared_ptr<const Source> src, const Context &ctx) {
  auto fs = std::make_shared<T>(std::move(src));
  fs->parse(ctx);
  return fs;
}

std::shared_ptr<FileSystem> open_node_sea(std::shared_ptr<const Source> s, std::string_view, const Context &c) {
  return open_js<NodeSea>(std::move(s), c);
}
std::shared_ptr<FileSystem> open_pkg(std::shared_ptr<const Source> s, std::string_view, const Context &c) {
  return open_js<Pkg>(std::move(s), c);
}
std::shared_ptr<FileSystem> open_nexe(std::shared_ptr<const Source> s, std::string_view, const Context &c) {
  return open_js<Nexe>(std::move(s), c);
}
std::shared_ptr<FileSystem> open_bun(std::shared_ptr<const Source> s, std::string_view, const Context &c) {
  return open_js<Bun>(std::move(s), c);
}

}  // namespace revkit::container::detail
