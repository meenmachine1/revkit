// What an input is, for the providers: the bytecode and script formats
// they take, from the container detector's content kind (container::Guess::
// content_kind, docs/filesystems.md "Content kinds": the one detector of
// these formats), mapped to the providers' kinds. Only what the detector
// can't say from a file's head is looked at here: a zip whose first
// members don't make it a jar or an APK (its central directory does), and
// JavaScript, which has no header (its name and its text).
#include "revkit/container/container.hh"
#include "revkit/providers/providers.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace revkit::providers {
namespace {

// A view of bytes the caller keeps alive, as a container source.
class SpanSource final : public container::Source {
 public:
  explicit SpanSource(std::span<const std::byte> b) : b_(b) {}
  std::uint64_t size() const override { return b_.size(); }
  std::size_t read(std::uint64_t offset, std::span<std::byte> out) const override {
    if (offset >= b_.size()) return 0;
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), b_.size() - offset));
    std::memcpy(out.data(), b_.data() + offset, n);
    return n;
  }
  std::span<const std::byte> view() const override { return b_; }

 private:
  std::span<const std::byte> b_;
};

bool text_like(std::span<const std::byte> b) {
  const std::size_t n = std::min<std::size_t>(b.size(), 4096);
  if (n == 0) return false;
  for (std::size_t i = 0; i < n; ++i) {
    const unsigned c = std::to_integer<unsigned>(b[i]);
    if (c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != '\f')) return false;
  }
  return true;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  if (s.size() < suffix.size()) return false;
  for (std::size_t i = 0; i < suffix.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(s[s.size() - suffix.size() + i])) != suffix[i]) return false;
  return true;
}

InputKind make(std::string kind, std::string version, std::string description) {
  return InputKind{std::move(kind), std::move(version), std::move(description)};
}

// A zip's members say whether it is an APK, a jar, or neither.
InputKind zip_kind(std::span<const std::byte> b, std::string_view name) {
  try {
    container::Context ctx;
    auto fs = container::open_format("zip", std::make_shared<SpanSource>(b), name, ctx);
    bool dex = false, manifest = false, android = false, classes = false;
    for (const container::Entry &e : fs->entries()) {
      if (e.kind != container::Kind::file) continue;
      if (e.parent == 0) {
        if (e.name == "AndroidManifest.xml") android = true;
        if (e.name.starts_with("classes") && ends_with(e.name, ".dex")) dex = true;
      }
      if (ends_with(e.name, ".class")) classes = true;
      if (e.name == "MANIFEST.MF") manifest = true;
    }
    if (dex || android) return make("apk", "", "Android package (APK)");
    if (classes || manifest) return make("jar", "", "Java archive (jar)");
  } catch (const std::exception &) {
  }
  return {};
}

}  // namespace

const std::vector<std::string> &all_kinds() {
  static const std::vector<std::string> k = {"dotnet", "dex", "apk", "jar", "class", "pyc", "lua", "luajit", "wasm", "js"};
  return k;
}

InputKind kind_from_format(std::string_view f) {
  auto version_after = [&](std::string_view prefix) {
    return f.size() > prefix.size() + 1 && f[prefix.size()] == ':' ? std::string(f.substr(prefix.size() + 1)) : std::string();
  };
  if (f == "dotnet" || f.starts_with("dotnet:") || f == "clr" || f == "cil" || f == ".NET assembly" || f == "pe-clr")
    return make("dotnet", "", f == "dotnet:mixed" ? "mixed-mode .NET assembly" : ".NET assembly");
  if (f == "dex" || f.starts_with("dex:")) return make("dex", version_after("dex"), "Android DEX");
  if (f == "apk") return make("apk", "", "Android package (APK)");
  if (f == "jar") return make("jar", "", "Java archive (jar)");
  if (f == "class" || f.starts_with("class:")) return make("class", version_after("class"), "Java class");
  if (f.starts_with("java-class:")) {
    const std::string v = version_after("java-class");
    return make("class", v, "Java class (Java " + v + ")");
  }
  if (f == "pyc" || f.starts_with("pyc:")) {
    const std::string v = version_after("pyc");
    return make("pyc", v, "Python " + (v.empty() ? std::string() : v + " ") + "bytecode");
  }
  if (f == "luajit" || f.starts_with("luajit:")) return make("luajit", version_after("luajit"), "LuaJIT bytecode");
  if (f == "lua" || f.starts_with("lua:")) {
    const std::string v = version_after("lua");
    return make("lua", v, "Lua " + (v.empty() ? std::string() : v + " ") + "bytecode");
  }
  if (f == "wasm") return make("wasm", "", "WebAssembly module");
  if (f == "js" || f == "javascript" || f == "js-source") return make("js", "", "JavaScript");
  return {};
}

InputKind detect_kind(std::span<const std::byte> b, std::string_view name) {
  const auto head = b.first(std::min<std::size_t>(b.size(), container::kIdentifyBytes));
  const std::string container = container::identify_head(head, b.size());
  const container::Guess g = container::guess(head, b.size(), container);
  if (!g.content_kind.empty())
    if (InputKind k = kind_from_format(g.content_kind)) return k;
  if (container == "zip")
    if (InputKind k = zip_kind(b, name)) return k;
  if ((ends_with(name, ".js") || ends_with(name, ".mjs") || ends_with(name, ".cjs")) && text_like(b))
    return make("js", "", "JavaScript");
  return kind_from_format(g.format);
}

}  // namespace revkit::providers
