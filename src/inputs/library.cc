#include "revkit/inputs/library.h"

#include "revkit/cparse/archive.h"
#include "revkit/runtime/runtime.h"
#include "revkit/types/hash.h"

#include <algorithm>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>

namespace revkit::inputs {

namespace fs = std::filesystem;

bool crt_function(std::string_view name) {
  static const std::set<std::string, std::less<>> names = {
      "_init",          "_fini",           "_start",          "__libc_csu_init",   "__libc_csu_fini",
      "frame_dummy",    "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux",
      "__do_global_ctors_aux", "_DT_INIT", "_DT_FINI", "_init_proc", "_term_proc", "call_weak_fn",
      "_dl_relocate_static_pie"};
  return names.contains(name);
}

const LibraryFunction *LibraryPrototypes::find(std::string_view name, bool underscore) const {
  auto get = [&](std::string_view n) -> const LibraryFunction * {
    if (n.empty()) return nullptr;
    auto it = functions.find(n);
    return it == functions.end() ? nullptr : &it->second;
  };
  if (const auto *f = get(name)) return f;
  // A symbol version (ELF) or a stdcall suffix (x86 PE): "name@...".
  std::string_view base = name;
  if (const auto at = base.find('@'); at != std::string_view::npos && at > 0) {
    base = base.substr(0, at);
    if (const auto *f = get(base)) return f;
  }
  if (underscore && base.size() > 1 && base[0] == '_') return get(base.substr(1));
  return nullptr;
}

std::vector<std::string> default_library_archives(const loader::Image &image) {
  if (image.format == loader::Format::pe) {
    const std::string model = image.bits == 64 ? "llp64" : "ilp32";
    std::vector<std::string> out;
    for (const char *dll : {"kernel32", "ntdll", "user32", "advapi32", "ws2_32", "msvcrt"})
      out.push_back(std::string(dll) + "-" + model);
    return out;
  }
  if (image.bits == 64) return {"libc-lp64"};
  if (image.bits == 32) return {"libc-ilp32"};
  return {};
}

std::vector<std::string> shipped_library_archives() {
  std::vector<std::string> out;
  const std::optional<fs::path> dir = runtime::typeinfo_dir();
  if (!dir) return out;
  std::error_code ec;
  for (const auto &e : fs::directory_iterator(*dir, ec))
    if (e.path().extension() == ".h") out.push_back(e.path().stem().string());
  std::sort(out.begin(), out.end());
  return out;
}

std::optional<std::string> read_library_archive(const std::string &name) {
  if (name.empty() || cparse::archive_stem(name) != name) return std::nullopt;
  const std::optional<fs::path> dir = runtime::typeinfo_dir();
  if (!dir) return std::nullopt;
  std::ifstream in(*dir / (name + ".h"), std::ios::binary);
  if (!in) return std::nullopt;
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

namespace {

std::string identity_of(std::span<const LibraryArchiveText> archives, const cparse::Profile &profile) {
  types::Sha256 h;
  auto add = [&](std::string_view s) {
    const std::uint64_t n = s.size();
    h.update(std::string_view(reinterpret_cast<const char *>(&n), sizeof n));
    h.update(s);
  };
  add(cparse::describe_profile(profile));
  const cparse::LayoutRules &r = profile.rules;
  std::string rules;
  for (const auto &[size, align] : r.size_alignment) rules += std::to_string(size) + ":" + std::to_string(align) + ",";
  rules += std::to_string(r.long_double_align) + "," + std::to_string(r.max_alignment) + "," +
           std::to_string(r.biggest_alignment) + "," + std::to_string(r.msvc_enums) + "," +
           std::to_string(r.zero_width_bitfield_aligns) + "," + std::to_string(int(profile.compiler)) + "," +
           std::to_string(int(profile.os));
  add(rules);
  for (const LibraryArchiveText &a : archives) {
    add(a.name);
    add(a.header);
  }
  return types::to_hex(h.finish());
}

}  // namespace

std::shared_ptr<const LibraryPrototypes> parse_library(std::span<const LibraryArchiveText> archives,
                                                       const cparse::Profile &profile) {
  const std::string identity = identity_of(archives, profile);
  static std::mutex mu;
  static std::vector<std::shared_ptr<const LibraryPrototypes>> cache;  // most recent last
  {
    std::lock_guard lock(mu);
    for (auto it = cache.begin(); it != cache.end(); ++it)
      if ((*it)->identity == identity) {
        auto hit = *it;
        cache.erase(it);
        cache.push_back(hit);
        return hit;
      }
  }
  auto out = std::make_shared<LibraryPrototypes>();
  out->identity = identity;
  std::set<std::string> keys;
  for (const LibraryArchiveText &a : archives) {
    out->archives.push_back(a.name);
    cparse::Options o;
    o.profile = profile;
    o.limits.wall_time = std::chrono::milliseconds(120'000);
    const cparse::Source src{a.name + ".h", a.header, false};
    cparse::Result r = cparse::parse(out->store, std::span<const cparse::Source>(&src, 1), o);
    std::size_t shown = 0;
    for (const cparse::Diagnostic &d : r.diagnostics)
      if (d.severity == cparse::Severity::Error && !d.text.starts_with("static assertion") && shown++ < 8)
        out->diagnostics.push_back(a.name + ".h:" + std::to_string(d.line) + ": " + d.text);
    for (cparse::Prototype &p : r.prototypes)
      out->functions.try_emplace(p.name, LibraryFunction{p.type, p.noreturn, a.name});
    for (cparse::NamedType &n : r.named)
      if (keys.insert(n.key).second) out->named.push_back(std::move(n));
  }
  std::lock_guard lock(mu);
  cache.push_back(out);
  if (cache.size() > 16) cache.erase(cache.begin());
  return out;
}

std::shared_ptr<const LibraryPrototypes> default_library(const loader::Image &image, const cparse::Profile &profile) {
  std::vector<LibraryArchiveText> texts;
  for (const std::string &name : default_library_archives(image))
    if (std::optional<std::string> h = read_library_archive(name)) texts.push_back({name, std::move(*h)});
  if (texts.empty()) return nullptr;
  return parse_library(texts, profile);
}

}  // namespace revkit::inputs
