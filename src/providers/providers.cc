// External decompiler providers: the definitions, finding the tools,
// running them in the sandbox, and the cache. See providers.h and
// docs/providers.md.
#include "revkit/providers/providers.h"

#include "revkit/container/container.hh"

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <future>
#include <set>
#include <sstream>
#include <thread>

namespace revkit::providers {
namespace fs = std::filesystem;

namespace {

constexpr std::uint64_t kMiB = 1ull << 20;

std::string trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
  std::size_t i = 0;
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  return s.substr(i);
}

bool executable_file(const fs::path &p) {
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode) && ::access(p.c_str(), X_OK) == 0;
}
bool regular_file(const fs::path &p) {
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

fs::path real(const fs::path &p) {
  std::error_code ec;
  fs::path r = fs::canonical(p, ec);
  return ec ? p : r;
}

std::string env_or(const char *name, const std::string &fallback = {}) {
  const char *v = std::getenv(name);
  return v != nullptr && *v != 0 ? std::string(v) : fallback;
}

fs::path search_path(const std::string &name, const std::string &path_var) {
  std::stringstream ss(path_var);
  std::string dir;
  while (std::getline(ss, dir, ':')) {
    if (dir.empty() || dir[0] != '/') continue;
    const fs::path c = fs::path(dir) / name;
    if (executable_file(c)) return c;
  }
  return {};
}

// "~/x/*/bin/tool": `~` is the home directory, and one `*` matches within
// one component; the last match in name order wins (the newest version).
fs::path expand(const std::string &pattern, const std::string &home) {
  std::string p = pattern;
  if (p.starts_with("~/")) {
    if (home.empty()) return {};
    p = home + p.substr(1);
  }
  const auto star = p.find('*');
  if (star == std::string::npos) return regular_file(p) ? fs::path(p) : fs::path();
  const auto slash_before = p.rfind('/', star);
  const auto slash_after = p.find('/', star);
  const fs::path dir = p.substr(0, slash_before);
  const std::string comp = p.substr(slash_before + 1, (slash_after == std::string::npos ? p.size() : slash_after) - slash_before - 1);
  const std::string rest = slash_after == std::string::npos ? std::string() : p.substr(slash_after);
  const std::string pre = comp.substr(0, comp.find('*')), post = comp.substr(comp.find('*') + 1);
  std::vector<std::string> names;
  std::error_code ec;
  for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
    const std::string n = it->path().filename().string();
    if (n.size() >= pre.size() + post.size() && n.starts_with(pre) && n.ends_with(post)) names.push_back(n);
  }
  std::sort(names.begin(), names.end());
  for (auto it = names.rbegin(); it != names.rend(); ++it) {
    const fs::path c = dir / (*it + rest);
    if (regular_file(c)) return c;
  }
  return {};
}

bool is_system_dir(const fs::path &dir) {
  const std::string d = dir.string();
  return d.starts_with("/usr/") || d == "/usr" || d == "/bin" || d == "/sbin" || d.starts_with("/lib");
}

// The version a tool printed: the last word with a digit on the first line
// that has one ("ilspycmd: 11.1.0.9782" -> "11.1.0.9782").
std::string version_from(const std::string &text) {
  std::stringstream ss(text);
  std::string line;
  while (std::getline(ss, line)) {
    std::stringstream ws(line);
    std::string w, last;
    while (ws >> w)
      if (std::any_of(w.begin(), w.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)); })) last = w;
    if (!last.empty()) {
      while (!last.empty() && (last.back() == ',' || last.back() == ')')) last.pop_back();
      return last.substr(0, 64);
    }
  }
  return {};
}

std::string file_sha256_prefix(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::vector<char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return sha256_hex(std::as_bytes(std::span(buf))).substr(0, 12);
}

// A jar's Implementation-Version (or Bundle-Version), read as a zip.
std::string jar_version(const fs::path &jar) {
  try {
    container::Context ctx;
    auto fs = container::open_format("zip", container::open_host_file(jar.string()), jar.filename().string(), ctx);
    auto e = fs->find({"META-INF", "MANIFEST.MF"}, true);
    if (!e) return {};
    auto src = fs->open(*e, ctx);
    const auto bytes = src->head(64 * 1024);
    std::string text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    for (const char *key : {"Implementation-Version: ", "Bundle-Version: "}) {
      const auto at = text.find(key);
      if (at == std::string::npos) continue;
      const auto end = text.find_first_of("\r\n", at);
      return trim(text.substr(at + std::strlen(key), end - at - std::strlen(key))).substr(0, 64);
    }
  } catch (const std::exception &) {
  }
  return {};
}

std::string percent(std::string_view s) {
  std::string out;
  for (char c : s) {
    if (c == '%' || c == '\n' || c == '\r') {
      char b[4];
      std::snprintf(b, sizeof b, "%%%02X", static_cast<unsigned char>(c));
      out += b;
    } else {
      out += c;
    }
  }
  return out;
}
std::string unpercent(std::string_view s) {
  std::string out;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size()) {
      out += static_cast<char>(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16));
      i += 2;
    } else {
      out += s[i];
    }
  }
  return out;
}

std::string safe_stem(std::string_view name) {
  std::string base(name);
  if (auto slash = base.find_last_of("/!"); slash != std::string::npos) base = base.substr(slash + 1);
  if (auto dot = base.rfind('.'); dot != std::string::npos && dot > 0) base = base.substr(0, dot);
  std::string out;
  for (char c : base)
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.') out += c;
  if (out.size() > 64) out.resize(64);
  return out.empty() || out[0] == '.' ? "input" : out;
}

std::string input_extension(const InputKind &k, std::string_view name) {
  if (k.kind == "dotnet") {
    std::string n(name);
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return n.ends_with(".exe") ? ".exe" : ".dll";
  }
  static const std::map<std::string, std::string, std::less<>> ext = {
      {"dex", ".dex"}, {"apk", ".apk"}, {"jar", ".jar"}, {"class", ".class"}, {"pyc", ".pyc"},
      {"lua", ".luac"}, {"luajit", ".luac"}, {"wasm", ".wasm"}, {"js", ".js"}};
  auto it = ext.find(k.kind);
  return it == ext.end() ? ".bin" : it->second;
}

bool valid_utf8_name(std::string_view s) {
  if (s.empty()) return false;
  for (std::size_t i = 0; i < s.size();) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x20 || c == 0x7f) return false;
    std::size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    if (n == 0 || i + n > s.size()) return false;
    for (std::size_t j = 1; j < n; ++j)
      if ((static_cast<unsigned char>(s[i + j]) >> 6) != 2) return false;
    i += n;
  }
  return true;
}

// Leaves only regular files and directories below `out` (a tool's links,
// pipes and devices go), readable by the daemon, with names that are
// valid UTF-8; returns the files, sorted.
std::vector<OutputFile> sanitize(const fs::path &out, std::uint64_t &total) {
  std::vector<OutputFile> files;
  total = 0;
  std::error_code ec;
  // Depth first, renaming as we go (an iterator over a tree being renamed
  // is undefined), so collect first.
  std::vector<fs::path> dirs = {out};
  while (!dirs.empty()) {
    const fs::path d = dirs.back();
    dirs.pop_back();
    ::chmod(d.c_str(), 0755);
    std::vector<fs::directory_entry> entries;
    for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec)) entries.push_back(*it);
    ec.clear();
    for (const fs::directory_entry &e : entries) {
      fs::path p = e.path();
      const fs::file_status st = e.symlink_status(ec);
      if (ec || (!fs::is_regular_file(st) && !fs::is_directory(st))) {
        fs::remove_all(p, ec);
        continue;
      }
      std::string name = p.filename().string();
      if (!valid_utf8_name(name)) {
        const fs::path renamed = p.parent_path() / container::encode_component(name);
        if (fs::exists(fs::symlink_status(renamed, ec)) || ::rename(p.c_str(), renamed.c_str()) != 0) {
          fs::remove_all(p, ec);
          continue;
        }
        p = renamed;
      }
      if (fs::is_directory(st)) {
        dirs.push_back(p);
      } else {
        ::chmod(p.c_str(), 0644);
        OutputFile f;
        f.path = fs::relative(p, out, ec).generic_string();
        f.size = fs::file_size(p, ec);
        f.language = language_of(f.path);
        total += f.size;
        files.push_back(std::move(f));
      }
    }
  }
  std::sort(files.begin(), files.end(), [](const OutputFile &a, const OutputFile &b) { return a.path < b.path; });
  return files;
}

// The file to show first: the largest in the provider's language (jadx's
// under sources/ first), passing over boilerplate a project has
// (AssemblyInfo.cs, package-info.java) when there is more.
std::string pick_main(const std::vector<OutputFile> &files, const std::string &language) {
  auto boiler = [](const std::string &p) {
    const std::string n = p.substr(p.find_last_of('/') + 1);
    return n == "AssemblyInfo.cs" || n == "package-info.java" || n == "module-info.java";
  };
  const OutputFile *best = nullptr;
  auto better = [&](const OutputFile &f) {
    if (!best) return true;
    const bool fs = f.path.starts_with("sources/"), bs = best->path.starts_with("sources/");
    if (fs != bs) return fs;
    if (boiler(f.path) != boiler(best->path)) return !boiler(f.path);
    return f.size > best->size;
  };
  for (const OutputFile &f : files)
    if (f.language == language && better(f)) best = &f;
  if (best) return best->path;
  return files.empty() ? std::string() : files.front().path;
}

bool write_meta(const fs::path &dir, const Result &r) {
  std::ofstream m(dir / "result", std::ios::trunc);
  m << "revkit-provider-result 1\n";
  m << "status " << status_name(r.status) << "\n";
  m << "detail " << percent(r.detail) << "\n";
  m << "seconds " << r.seconds << "\n";
  m << "provider " << percent(r.provider) << "\n";
  m << "version " << percent(r.version) << "\n";
  m << "kind " << percent(r.input.kind) << "\n";
  m << "kind_version " << percent(r.input.version) << "\n";
  m << "kind_description " << percent(r.input.description) << "\n";
  m << "sha256 " << r.sha256 << "\n";
  m << "shape " << (r.shape == Shape::file ? "file" : "tree") << "\n";
  m << "language " << percent(r.language) << "\n";
  m << "main " << percent(r.main_file) << "\n";
  m << "sandbox " << percent(r.sandbox) << "\n";
  m << "finished_at " << r.finished_at << "\n";
  m << "total_bytes " << r.total_bytes << "\n";
  for (const OutputFile &f : r.files) m << "file " << f.size << " " << percent(f.path) << "\n";
  m.close();
  std::ofstream e(dir / "stderr", std::ios::trunc | std::ios::binary);
  e << r.stderr_tail;
  return static_cast<bool>(m);
}

RunStatus status_from(const std::string &s) {
  for (RunStatus r : {RunStatus::ok, RunStatus::failed, RunStatus::crashed, RunStatus::timeout,
                      RunStatus::out_of_memory, RunStatus::output_limit, RunStatus::cancelled, RunStatus::sandbox_error})
    if (s == status_name(r)) return r;
  return RunStatus::sandbox_error;
}

// Kept in the cache: what the same tool would do again on the same bytes.
// Runs stopped by a limit, cancelled or never started are not.
bool cacheable(RunStatus s) { return s == RunStatus::ok || s == RunStatus::failed || s == RunStatus::crashed; }

// Read and execute for every tool: the system's programs, libraries and
// configuration, and /proc and /sys, which runtimes read about themselves.
const std::vector<fs::path> &system_read_paths() {
  static const std::vector<fs::path> p = {"/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc", "/proc", "/sys"};
  return p;
}

struct Runtimes {
  fs::path java, java_home, node, node_root, dotnet_root;
};

Runtimes find_runtimes(const Settings &s) {
  Runtimes r;
  const std::string path = s.search_path.empty() ? env_or("PATH", "/usr/bin:/bin") : s.search_path;
  const std::string home = s.home.empty() ? env_or("HOME") : s.home;
  if (!s.java.empty()) {
    if (executable_file(s.java)) r.java = s.java;
  } else if (const std::string jh = env_or("JAVA_HOME"); !jh.empty() && executable_file(fs::path(jh) / "bin" / "java")) {
    r.java = fs::path(jh) / "bin" / "java";
  } else {
    r.java = search_path("java", path);
  }
  if (!r.java.empty()) {
    r.java = real(r.java);
    r.java_home = r.java.parent_path().parent_path();
  }
  r.node = !s.node.empty() ? (executable_file(s.node) ? fs::path(s.node) : fs::path()) : search_path("node", path);
  if (!r.node.empty()) {
    r.node = real(r.node);
    r.node_root = r.node.parent_path().parent_path();
  }
  auto dotnet_ok = [](const fs::path &d) { return !d.empty() && fs::is_directory(d / "shared" / "Microsoft.NETCore.App"); };
  if (!s.dotnet_root.empty()) {
    if (dotnet_ok(s.dotnet_root)) r.dotnet_root = s.dotnet_root;
  } else if (const std::string dr = env_or("DOTNET_ROOT"); dotnet_ok(dr)) {
    r.dotnet_root = dr;
  } else if (const fs::path d = search_path("dotnet", path); !d.empty() && dotnet_ok(real(d).parent_path())) {
    r.dotnet_root = real(d).parent_path();
  } else {
    for (const fs::path &c : {fs::path("/usr/lib/dotnet"), fs::path("/usr/share/dotnet"), fs::path("/usr/local/share/dotnet"),
                             home.empty() ? fs::path() : fs::path(home) / ".dotnet"})
      if (dotnet_ok(c)) {
        r.dotnet_root = c;
        break;
      }
  }
  return r;
}

// From where a JVM tool was found to its jar: a jar as it is; jadx's
// launcher script beside ../lib/jadx-*-all.jar. Empty when there is none.
fs::path jar_of(const Definition &d, const fs::path &found) {
  const fs::path r = real(found);
  if (r.extension() == ".jar") return r;
  if (d.name == "jadx") {
    const fs::path lib = r.parent_path().parent_path() / "lib";
    std::error_code ec;
    for (fs::directory_iterator it(lib, ec), end; !ec && it != end; it.increment(ec)) {
      const std::string n = it->path().filename().string();
      if (n.starts_with("jadx-") && n.ends_with("-all.jar")) return it->path();
    }
  }
  return {};
}

// webcrack found on PATH is npm's link to its package's src/cli-wrapper.js;
// the package's dist/cli.js is what runs.
fs::path webcrack_cli(const fs::path &found) {
  const fs::path r = real(found);
  for (fs::path dir = r.parent_path(); !dir.empty() && dir != dir.parent_path(); dir = dir.parent_path()) {
    if (dir.filename() == "webcrack" && fs::exists(dir / "dist" / "cli.js")) return dir / "dist" / "cli.js";
    if (dir.filename() == "node_modules") break;
  }
  return r.extension() == ".js" ? r : fs::path();
}

std::vector<std::string> jvm_options(const Settings &s, const fs::path &home, const fs::path &tmp) {
  const std::uint64_t heap = std::max<std::uint64_t>(256, s.limits.memory_bytes * 6 / 10 / kMiB);
  return {"-Xmx" + std::to_string(heap) + "m",
          "-Xss8m",
          "-XX:+UseSerialGC",
          "-XX:-UsePerfData",
          "-XX:ErrorFile=" + (tmp / "hs_err_%p.log").string(),
          "-Djava.io.tmpdir=" + tmp.string(),
          "-Duser.home=" + home.string(),
          "-Djava.awt.headless=true",
          "-Dfile.encoding=UTF-8"};
}

std::vector<std::string> base_env(const fs::path &home, const fs::path &tmp) {
  return {"PATH=/usr/bin:/bin", "HOME=" + home.string(), "TMPDIR=" + tmp.string(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8"};
}

void add_runtime_env(const Definition &d, const ToolStatus &t, std::uint64_t memory, std::vector<std::string> &env) {
  if (d.runtime == Runtime::dotnet) {
    for (const fs::path &p : t.read_paths)
      if (fs::is_directory(p / "shared" / "Microsoft.NETCore.App")) env.push_back("DOTNET_ROOT=" + p.string());
    const std::uint64_t heap = std::max<std::uint64_t>(128 * kMiB, memory * 6 / 10);
    char hex[32];
    std::snprintf(hex, sizeof hex, "%llx", static_cast<unsigned long long>(heap));
    // W^X double mapping sizes a shared-memory file past RLIMIT_FSIZE (the
    // output cap): off.
    env.insert(env.end(), {"DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1", "DOTNET_EnableDiagnostics=0",
                           "DOTNET_EnableWriteXorExecute=0",
                           "DOTNET_gcServer=0", std::string("DOTNET_GCHeapHardLimit=") + hex});
  }
}

// A command line from its template.
std::vector<std::string> expand_command(const std::vector<std::string> &tmpl, const ToolStatus &t, const Settings &s,
                                        const fs::path &in, const fs::path &out, const fs::path &home,
                                        const fs::path &tmp, const std::string &stem, bool version_check) {
  const std::uint64_t heap = version_check ? 256 : std::max<std::uint64_t>(256, s.limits.memory_bytes * 6 / 10 / kMiB);
  const std::vector<std::pair<std::string, std::string>> vars = {
      {"{tool}", t.path}, {"{launcher}", t.launcher}, {"{heap_mib}", std::to_string(heap)}, {"{in}", in.string()},
      {"{out}", out.string()}, {"{stem}", stem}, {"{home}", home.string()}, {"{tmp}", tmp.string()}};
  std::vector<std::string> a;
  for (const std::string &w : tmpl) {
    if (w == "{jvm}") {
      if (version_check) {
        a.insert(a.end(), {"-Xmx256m", "-XX:+UseSerialGC", "-XX:-UsePerfData", "-Djava.io.tmpdir=" + tmp.string(),
                           "-Duser.home=" + home.string()});
      } else {
        for (std::string &o : jvm_options(s, home, tmp)) a.push_back(std::move(o));
      }
      continue;
    }
    std::string x = w;
    for (const auto &[k, v] : vars)
      for (std::size_t at = x.find(k); at != std::string::npos; at = x.find(k, at + v.size())) x.replace(at, k.size(), v);
    a.push_back(std::move(x));
  }
  return a;
}

// A fresh scratch directory: in/, out/, home/, tmp/.
struct Scratch {
  fs::path dir, in, out, home, tmp;
  explicit Scratch(const fs::path &root) {
    std::error_code ec;
    fs::create_directories(root, ec);
    std::string tmpl = (root / "run-XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr)
      throw Error(Error::Code::failed_precondition, "cannot make a scratch directory under " + root.string() + ": " +
                                                         std::strerror(errno));
    dir = tmpl;
    in = dir / "in";
    out = dir / "out";
    home = dir / "home";
    tmp = dir / "tmp";
    for (const fs::path &p : {in, out, home, tmp}) fs::create_directory(p, ec);
  }
  ~Scratch() {
    if (dir.empty()) return;
    std::error_code ec;
    // A tool may leave directories it can't be removed from: open them up.
    for (fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec))
      if (it->is_directory(ec) && !it->is_symlink(ec)) ::chmod(it->path().c_str(), 0700);
    fs::remove_all(dir, ec);
  }
  Scratch(const Scratch &) = delete;
  Scratch &operator=(const Scratch &) = delete;
};

std::string limits_text(const SandboxLimits &l) {
  return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(l.timeout).count()) + " s, " +
         std::to_string(l.memory_bytes / kMiB) + " MiB, output " + std::to_string(l.output_bytes / kMiB) + " MiB";
}

std::int64_t now_unix() { return static_cast<std::int64_t>(std::time(nullptr)); }

}  // namespace

// ---------------------------------------------------------------------------

std::string sha256_hex(std::span<const std::byte> bytes) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int n = 0;
  EVP_Digest(bytes.data(), bytes.size(), md, &n, EVP_sha256(), nullptr);
  static const char *hexd = "0123456789abcdef";
  std::string out;
  for (unsigned int i = 0; i < n; ++i) {
    out += hexd[md[i] >> 4];
    out += hexd[md[i] & 15];
  }
  return out;
}

Definition make_definition(std::string name, std::string title, std::string tool, std::string license,
                           std::string homepage, std::vector<std::string> kinds, Runtime runtime, Shape shape,
                           std::string language) {
  Definition d;
  d.name = std::move(name);
  d.title = std::move(title);
  d.tool = std::move(tool);
  d.license = std::move(license);
  d.homepage = std::move(homepage);
  d.kinds = std::move(kinds);
  d.runtime = runtime;
  d.shape = shape;
  d.language = std::move(language);
  return d;
}

const std::vector<Definition> &definitions() {
  static const std::vector<Definition> d = [] {
    std::vector<Definition> v;
    auto add = [&](Definition x) { v.push_back(std::move(x)); };
    {
      Definition x = make_definition("ilspy", "ILSpy", "ilspycmd", "MIT", "https://github.com/icsharpcode/ILSpy", {"dotnet"}, Runtime::dotnet, Shape::tree, "csharp");
      x.path_names = {"ilspycmd"};
      x.known = {"~/.dotnet/tools/ilspycmd"};
      x.command = {"{tool}", "--disable-updatecheck", "-p", "--nested-directories", "-o", "{out}", "{in}"};
      x.version_command = {"{tool}", "--version"};
      add(x);
    }
    {
      Definition x = make_definition("jadx", "jadx", "jadx", "Apache-2.0", "https://github.com/skylot/jadx", {"dex", "apk", "jar", "class"}, Runtime::java, Shape::tree, "java");
      x.path_names = {"jadx"};
      x.known = {"~/.local/share/revkit-tools/jadx/lib/jadx-*-all.jar", "/opt/jadx/lib/jadx-*-all.jar",
                 "/usr/share/jadx/lib/jadx-*-all.jar", "/usr/share/java/jadx/jadx-*-all.jar"};
      x.command = {"{launcher}", "{jvm}", "-cp", "{tool}", "jadx.cli.JadxCLI", "-d", "{out}", "--log-level", "error", "-j", "2", "{in}"};
      x.version_command = {"{launcher}", "{jvm}", "-cp", "{tool}", "jadx.cli.JadxCLI", "--version"};
      add(x);
    }
    {
      Definition x = make_definition("vineflower", "Vineflower", "vineflower", "Apache-2.0", "https://github.com/Vineflower/vineflower", {"class", "jar"}, Runtime::java, Shape::tree, "java");
      x.path_names = {"vineflower"};
      x.known = {"~/.local/share/revkit-tools/vineflower/vineflower-*.jar", "/usr/share/java/vineflower.jar", "/opt/vineflower/vineflower.jar"};
      x.command = {"{launcher}", "{jvm}", "-jar", "{tool}", "--log-level=error", "{in}", "{out}"};
      x.version_from_manifest = true;
      add(x);
    }
    {
      Definition x = make_definition("cfr", "CFR", "cfr", "MIT", "https://github.com/leibnitz27/cfr", {"class", "jar"}, Runtime::java, Shape::tree, "java");
      x.path_names = {"cfr", "cfr-decompiler"};
      x.known = {"~/.local/share/revkit-tools/cfr/cfr-*.jar", "/usr/share/java/cfr.jar", "/opt/cfr/cfr.jar"};
      x.command = {"{launcher}", "{jvm}", "-jar", "{tool}", "{in}", "--outputdir", "{out}", "--silent", "true"};
      x.version_command = {"{launcher}", "{jvm}", "-jar", "{tool}", "--version"};
      add(x);
    }
    {
      Definition x = make_definition("unluac", "unluac", "unluac", "MIT", "https://sourceforge.net/projects/unluac/", {"lua"}, Runtime::java, Shape::file, "lua");
      x.path_names = {"unluac"};
      x.known = {"~/.local/share/revkit-tools/unluac/unluac*.jar", "/usr/share/java/unluac.jar", "/opt/unluac/unluac.jar"};
      x.command = {"{launcher}", "{jvm}", "-jar", "{tool}", "{in}"};
      x.version_command = {"{launcher}", "{jvm}", "-jar", "{tool}", "--version"};
      x.stdout_extension = ".lua";
      add(x);
    }
    {
      Definition x = make_definition("pycdc", "pycdc (Decompyle++)", "pycdc", "GPL-3.0", "https://github.com/zrax/pycdc", {"pyc"}, Runtime::native, Shape::file, "python");
      x.path_names = {"pycdc"};
      x.known = {"~/.local/share/revkit-tools/pycdc/pycdc", "/opt/pycdc/pycdc"};
      x.command = {"{tool}", "{in}"};
      x.stdout_extension = ".py";
      add(x);
    }
    {
      Definition x = make_definition("webcrack", "webcrack", "webcrack", "MIT", "https://github.com/j4k0xb/webcrack", {"js"}, Runtime::node, Shape::tree, "javascript");
      x.path_names = {"webcrack"};
      x.known = {"~/.local/share/revkit-tools/webcrack/node_modules/webcrack/dist/cli.js"};
      // webcrack replaces its output directory, which it may create but not
      // remove: a directory of its own inside the output.
      x.command = {"{launcher}", "--max-old-space-size={heap_mib}", "{tool}", "{in}", "-o", "{out}/{stem}"};
      x.version_command = {"{launcher}", "{tool}", "--version"};
      add(x);
    }
    {
      Definition x = make_definition("wasm-decompile", "wasm-decompile (WABT)", "wasm-decompile", "Apache-2.0", "https://github.com/WebAssembly/wabt", {"wasm"}, Runtime::native, Shape::file, "wasm");
      x.path_names = {"wasm-decompile"};
      x.known = {"~/.local/share/revkit-tools/wabt/*/bin/wasm-decompile", "~/.local/share/revkit-tools/wabt/bin/wasm-decompile",
                 "/opt/wabt/bin/wasm-decompile"};
      x.command = {"{tool}", "{in}", "-o", "{out}/{stem}.dcmp"};
      x.version_command = {"{tool}", "--version"};
      add(x);
    }
    return v;
  }();
  return d;
}

const Definition *find_definition(std::string_view name) {
  for (const Definition &d : definitions())
    if (d.name == name) return &d;
  return nullptr;
}

std::string language_of(std::string_view path) {
  const auto dot = path.rfind('.');
  if (dot == std::string_view::npos || path.find('/', dot) != std::string_view::npos) return "text";
  std::string ext(path.substr(dot + 1));
  std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  static const std::map<std::string, std::string, std::less<>> m = {
      {"cs", "csharp"},  {"java", "java"},     {"kt", "kotlin"},   {"lua", "lua"},        {"py", "python"},
      {"js", "javascript"}, {"mjs", "javascript"}, {"cjs", "javascript"}, {"jsx", "javascript"}, {"ts", "javascript"},
      {"dcmp", "wasm"},  {"wat", "wasm"},      {"xml", "xml"},     {"csproj", "xml"},     {"xaml", "xml"},
      {"json", "json"},  {"smali", "smali"},   {"txt", "text"},    {"mf", "text"},        {"properties", "text"},
      {"class", "binary"}, {"dex", "binary"},  {"png", "binary"},  {"jpg", "binary"},     {"so", "binary"},
      {"dll", "binary"}, {"arsc", "binary"},   {"resources", "binary"}};
  auto it = m.find(ext);
  return it == m.end() ? "text" : it->second;
}

// ---------------------------------------------------------------------------

struct Service::Inflight {
  bool done = false;
  std::optional<Result> result;
  std::string error;
  Error::Code code = Error::Code::failed_precondition;
};

Service::Service(Settings settings, fs::path cache_root) : root_(std::move(cache_root)), settings_(std::move(settings)) {
  std::error_code ec;
  fs::create_directories(root_, ec);
  // Scratch directories a crashed daemon left.
  fs::remove_all(root_ / "tmp", ec);
}

Service::~Service() = default;

void Service::set_settings(Settings s) {
  std::lock_guard lock(mu_);
  settings_ = std::move(s);
  tools_resolved_ = false;
  tools_.clear();
}

Settings Service::settings() const {
  std::lock_guard lock(mu_);
  return settings_;
}

SandboxSupport Service::support() { return probe_support(); }

std::vector<Definition> Service::all_definitions() const {
  std::vector<Definition> v = definitions();
  std::lock_guard lock(mu_);
  for (const Definition &d : settings_.extra)
    if (!find_definition(d.name)) v.push_back(d);
  return v;
}

std::optional<Definition> Service::definition(const std::string &name) const {
  for (const Definition &d : all_definitions())
    if (d.name == name) return d;
  return std::nullopt;
}

std::vector<std::string> Service::for_kind(const std::string &kind) const {
  // Preferences among the built-in ones: the best source first.
  static const std::map<std::string, std::vector<std::string>, std::less<>> pref = {
      {"jar", {"vineflower", "cfr", "jadx"}},
      {"class", {"vineflower", "cfr", "jadx"}},
  };
  std::vector<std::string> out;
  const std::vector<Definition> defs = all_definitions();
  if (auto it = pref.find(kind); it != pref.end())
    for (const std::string &n : it->second)
      if (std::any_of(defs.begin(), defs.end(), [&](const Definition &d) { return d.name == n; })) out.push_back(n);
  for (const Definition &d : defs)
    if (std::find(d.kinds.begin(), d.kinds.end(), kind) != d.kinds.end() &&
        std::find(out.begin(), out.end(), d.name) == out.end())
      out.push_back(d.name);
  return out;
}

ToolStatus Service::resolve(const Definition &d, const Settings &s) {
  ToolStatus t;
  t.name = d.name;
  const ProviderConfig *cfg = nullptr;
  for (const ProviderConfig &c : s.providers)
    if (c.name == d.name) cfg = &c;
  if (!s.enabled || (cfg && cfg->disabled)) {
    t.disabled = true;
    t.reason = !s.enabled ? "external decompilers are turned off" : "turned off by an admin";
    return t;
  }
  const std::string path = s.search_path.empty() ? env_or("PATH", "/usr/bin:/bin") : s.search_path;
  const std::string home = s.home.empty() ? env_or("HOME") : s.home;
  // Find it.
  fs::path found;
  if (cfg && !cfg->path.empty()) {
    if (!fs::path(cfg->path).is_absolute()) {
      t.reason = "the configured path " + cfg->path + " isn't absolute";
      return t;
    }
    if (!regular_file(cfg->path)) {
      t.reason = "the configured path " + cfg->path + " isn't a file";
      return t;
    }
    found = cfg->path;
    t.found_by = "configured";
  } else {
    for (const std::string &n : d.path_names)
      if (fs::path p = search_path(n, path); !p.empty()) {
        found = p;
        t.found_by = "PATH";
        break;
      }
    if (found.empty())
      for (const std::string &k : d.known)
        if (fs::path p = expand(k, home); !p.empty()) {
          found = p;
          t.found_by = "known location";
          break;
        }
  }
  if (found.empty()) {
    t.reason = d.tool + " not found (configure its path, put it on PATH, or install it: docs/providers.md)";
    return t;
  }
  const Runtimes rt = find_runtimes(s);
  switch (d.runtime) {
    case Runtime::java: {
      const fs::path jar = jar_of(d, found);
      if (jar.empty()) {
        t.reason = "found " + found.string() + ", but not its jar (configure the jar's path)";
        return t;
      }
      if (rt.java.empty()) {
        t.reason = d.tool + " needs Java, and none was found (configure java, set JAVA_HOME or put java on PATH)";
        return t;
      }
      t.path = jar.string();
      t.launcher = rt.java.string();
      // The jar alone, not its directory: a jar kept in $HOME would have
      // granted the tool all of it (bug scrub part 3). Every provider's
      // jar is self-contained (jadx's is its -all.jar).
      t.read_paths.push_back(jar);
      if (!is_system_dir(rt.java_home)) t.read_paths.push_back(rt.java_home);
      break;
    }
    case Runtime::node: {
      const fs::path cli = webcrack_cli(found);
      if (cli.empty()) {
        t.reason = "found " + found.string() + ", but not webcrack's dist/cli.js";
        return t;
      }
      if (rt.node.empty()) {
        t.reason = "webcrack needs Node.js, and none was found (configure node or put it on PATH)";
        return t;
      }
      t.path = cli.string();
      t.launcher = rt.node.string();
      // The package's node_modules (its dependencies are beside it).
      fs::path modules = cli.parent_path().parent_path().parent_path();
      t.read_paths.push_back(modules.filename() == "node_modules" ? modules : cli.parent_path().parent_path());
      if (!is_system_dir(rt.node_root)) t.read_paths.push_back(rt.node_root);
      break;
    }
    case Runtime::dotnet: {
      if (!executable_file(found)) {
        t.reason = found.string() + " isn't executable";
        return t;
      }
      if (rt.dotnet_root.empty()) {
        t.reason = "ilspycmd needs the .NET runtime, and none was found (configure dotnet_root or set DOTNET_ROOT)";
        return t;
      }
      const fs::path r = real(found);
      t.path = r.string();
      t.launcher = t.path;
      // A global tool's apphost finds its assembly in .store beside it.
      if (!is_system_dir(r.parent_path())) t.read_paths.push_back(r.parent_path());
      t.read_paths.push_back(rt.dotnet_root);
      break;
    }
    case Runtime::native: {
      if (!executable_file(found)) {
        t.reason = found.string() + " isn't executable";
        return t;
      }
      const fs::path r = real(found);
      t.path = r.string();
      t.launcher = t.path;
      const std::string dir = r.parent_path().string();
      const bool own_dir = dir.find("revkit-tools") != std::string::npos || dir.starts_with("/opt/");
      if (!is_system_dir(r.parent_path())) t.read_paths.push_back(own_dir ? r.parent_path().parent_path() : r);
      break;
    }
  }
  // Its version: from the jar's manifest, the binary's hash, or by asking
  // it (in the sandbox: a tool is never run outside it).
  if (d.version_from_manifest) {
    t.version = jar_version(t.path);
    if (t.version.empty()) t.version = "build " + file_sha256_prefix(t.path);
  } else if (d.version_command.empty()) {
    t.version = "build " + file_sha256_prefix(t.path);
  } else {
    Scratch sc(root_ / "tmp");
    SandboxSpec spec;
    spec.argv = expand_command(d.version_command, t, s, {}, {}, sc.home, sc.tmp, "", true);
    std::vector<std::string> env = base_env(sc.home, sc.tmp);
    add_runtime_env(d, t, 1ull << 30, env);
    spec.env = env;
    spec.read_paths = system_read_paths();
    spec.read_paths.insert(spec.read_paths.end(), t.read_paths.begin(), t.read_paths.end());
    spec.write_paths = {sc.home, sc.tmp};
    spec.cwd = sc.home;
    spec.stdout_file = sc.dir / "stdout";
    spec.stderr_file = sc.dir / "stderr";
    spec.limits.timeout = std::chrono::seconds(60);
    spec.limits.memory_bytes = 1ull << 30;
    spec.limits.output_bytes = 1 * kMiB;
    spec.allow_weak = s.allow_weak_sandbox;
    const RunOutcome o = run_sandboxed(spec);
    std::ifstream in(spec.stdout_file);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (o.status != RunStatus::ok) {
      std::string tail = trim(o.stderr_tail);
      if (auto nl = tail.rfind('\n'); nl != std::string::npos) tail = tail.substr(nl + 1);
      t.reason = "its version check " + std::string(status_name(o.status)) + ": " + o.detail +
                 (tail.empty() ? std::string() : " (" + tail.substr(0, 300) + ")");
      return t;
    }
    // Some print it on stderr (CFR).
    t.version = version_from(text);
    if (t.version.empty()) t.version = version_from(o.stderr_tail);
    if (t.version.empty()) t.version = "build " + file_sha256_prefix(t.path);
  }
  t.available = true;
  return t;
}

std::vector<ToolStatus> Service::tools(bool refresh) {
  Settings s;
  {
    std::lock_guard lock(mu_);
    s = settings_;
  }
  const std::vector<Definition> defs = all_definitions();
  {
    std::lock_guard lock(mu_);
    if (tools_resolved_ && !refresh) {
      std::vector<ToolStatus> out;
      for (const Definition &d : defs)
        if (auto it = tools_.find(d.name); it != tools_.end()) out.push_back(it->second);
      if (out.size() == defs.size()) return out;
    }
  }
  // Every tool at once: the JVM's start dominates.
  std::vector<std::future<ToolStatus>> futures;
  for (const Definition &d : defs)
    futures.push_back(std::async(std::launch::async, [this, &d, &s] {
      try {
        return resolve(d, s);
      } catch (const std::exception &e) {
        ToolStatus t;
        t.name = d.name;
        t.reason = e.what();
        return t;
      }
    }));
  std::vector<ToolStatus> out;
  for (auto &f : futures) out.push_back(f.get());
  std::lock_guard lock(mu_);
  for (const ToolStatus &t : out) tools_[t.name] = t;
  tools_resolved_ = true;
  return out;
}

ToolStatus Service::tool(const std::string &name, bool refresh) {
  for (const ToolStatus &t : tools(refresh))
    if (t.name == name) return t;
  throw Error(Error::Code::invalid_argument, "no provider named \"" + name + "\"");
}

std::string Service::default_provider(const std::string &kind) {
  const std::vector<std::string> names = for_kind(kind);
  if (names.empty()) return {};
  for (const std::string &n : names)
    if (tool(n).available) return n;
  return names.front();
}

std::string Service::key_dir(const std::string &sha, const std::string &provider, const std::string &version,
                             const InputKind &kind) const {
  const std::optional<Definition> d = definition(provider);
  const std::string key = provider + "\n" + version + "\n" + std::to_string(d ? d->revision : 0) + "\n" + kind.kind;
  const std::string h = sha256_hex(std::as_bytes(std::span(key))).substr(0, 16);
  return (root_ / sha.substr(0, 2) / sha / (provider + "-" + h)).string();
}

std::optional<Result> load_result(const fs::path &dir) {
  std::ifstream m(dir / "result");
  if (!m) return std::nullopt;
  std::string line;
  if (!std::getline(m, line) || line != "revkit-provider-result 1") return std::nullopt;
  Result r;
  r.dir = dir;
  while (std::getline(m, line)) {
    const auto sp = line.find(' ');
    const std::string k = line.substr(0, sp), v = sp == std::string::npos ? std::string() : line.substr(sp + 1);
    try {
      if (k == "status") r.status = status_from(v);
      else if (k == "detail") r.detail = unpercent(v);
      else if (k == "seconds") r.seconds = std::stod(v);
      else if (k == "provider") r.provider = unpercent(v);
      else if (k == "version") r.version = unpercent(v);
      else if (k == "kind") r.input.kind = unpercent(v);
      else if (k == "kind_version") r.input.version = unpercent(v);
      else if (k == "kind_description") r.input.description = unpercent(v);
      else if (k == "sha256") r.sha256 = v;
      else if (k == "shape") r.shape = v == "file" ? Shape::file : Shape::tree;
      else if (k == "language") r.language = unpercent(v);
      else if (k == "main") r.main_file = unpercent(v);
      else if (k == "sandbox") r.sandbox = unpercent(v);
      else if (k == "finished_at") r.finished_at = std::stoll(v);
      else if (k == "total_bytes") r.total_bytes = std::stoull(v);
      else if (k == "file") {
        const auto sp2 = v.find(' ');
        OutputFile f;
        f.size = std::stoull(v.substr(0, sp2));
        f.path = unpercent(v.substr(sp2 + 1));
        f.language = language_of(f.path);
        r.files.push_back(std::move(f));
      }
    } catch (const std::exception &) {
      return std::nullopt;
    }
  }
  std::ifstream e(dir / "stderr", std::ios::binary);
  r.stderr_tail.assign((std::istreambuf_iterator<char>(e)), std::istreambuf_iterator<char>());
  r.cached = true;
  return r;
}

std::optional<Result> Service::cached(const std::string &sha, const InputKind &kind, const std::string &provider_in) {
  const std::string provider = provider_in.empty() ? default_provider(kind.kind) : provider_in;
  if (provider.empty()) return std::nullopt;
  const ToolStatus t = tool(provider);
  if (!t.available) return std::nullopt;
  auto r = load_result(key_dir(sha, provider, t.version, kind));
  if (r) {
    std::error_code ec;
    fs::last_write_time(r->dir / "result", fs::file_time_type::clock::now(), ec);
  }
  return r;
}

Result Service::decompile(std::span<const std::byte> bytes, const std::string &name, const InputKind &kind,
                          const std::string &provider_in, bool refresh, std::function<bool()> cancelled) {
  if (!kind) throw Error(Error::Code::failed_precondition, "this isn't a format any external decompiler takes");
  const std::string provider = provider_in.empty() ? default_provider(kind.kind) : provider_in;
  if (provider.empty()) throw Error(Error::Code::failed_precondition, "no external decompiler takes " + kind.description);
  const std::optional<Definition> d = definition(provider);
  if (!d) throw Error(Error::Code::invalid_argument, "no provider named \"" + provider + "\"");
  if (std::find(d->kinds.begin(), d->kinds.end(), kind.kind) == d->kinds.end())
    throw Error(Error::Code::invalid_argument, d->title + " doesn't take " + kind.description);
  const ToolStatus t = tool(provider);
  if (!t.available) throw Error(Error::Code::failed_precondition, d->title + " isn't available: " + t.reason);
  const Settings s = settings();
  if (bytes.size() > s.max_input_bytes)
    throw Error(Error::Code::invalid_argument, "the input is larger than " + std::to_string(s.max_input_bytes >> 20) +
                                                   " MiB (max_input_bytes)");
  const std::string sha = sha256_hex(bytes);
  const fs::path dir = key_dir(sha, provider, t.version, kind);
  if (!refresh)
    if (auto r = load_result(dir)) {
      std::error_code ec;
      fs::last_write_time(dir / "result", fs::file_time_type::clock::now(), ec);
      return *r;
    }

  // One run per key at a time; the others wait for it.
  std::shared_ptr<Inflight> mine, theirs;
  {
    std::unique_lock lock(mu_);
    auto it = inflight_.find(dir.string());
    if (it != inflight_.end()) {
      theirs = it->second;
    } else {
      mine = std::make_shared<Inflight>();
      inflight_[dir.string()] = mine;
    }
    if (theirs) {
      while (!theirs->done) {
        cv_.wait_for(lock, std::chrono::milliseconds(200));
        if (cancelled && cancelled()) throw Error(Error::Code::cancelled, "cancelled");
      }
      if (theirs->result) return *theirs->result;
      throw Error(theirs->code, theirs->error);
    }
  }
  auto finish = [&](std::optional<Result> r, Error::Code code, std::string err) {
    std::lock_guard lock(mu_);
    mine->done = true;
    mine->result = std::move(r);
    mine->code = code;
    mine->error = std::move(err);
    inflight_.erase(dir.string());
    cv_.notify_all();
  };
  try {
    // A slot: at most max_concurrent run, max_waiting wait.
    {
      std::unique_lock lock(mu_);
      if (running_ >= s.max_concurrent) {
        if (waiting_ >= s.max_waiting)
          throw Error(Error::Code::resource_exhausted, "too many external decompilations at once; try again later");
        ++waiting_;
        while (running_ >= s.max_concurrent) {
          cv_.wait_for(lock, std::chrono::milliseconds(200));
          if (cancelled && cancelled()) {
            --waiting_;
            throw Error(Error::Code::cancelled, "cancelled");
          }
        }
        --waiting_;
      }
      ++running_;
    }
    Result r;
    try {
      r = run(*d, t, bytes, name, kind, sha, s, cancelled);
    } catch (...) {
      std::lock_guard lock(mu_);
      --running_;
      cv_.notify_all();
      throw;
    }
    {
      std::lock_guard lock(mu_);
      --running_;
      cv_.notify_all();
    }
    finish(r, Error::Code::failed_precondition, {});
    return r;
  } catch (const Error &e) {
    finish(std::nullopt, e.code, e.what());
    throw;
  } catch (const std::exception &e) {
    finish(std::nullopt, Error::Code::failed_precondition, e.what());
    throw Error(Error::Code::failed_precondition, e.what());
  }
}

Result Service::run(const Definition &d, const ToolStatus &t, std::span<const std::byte> bytes, const std::string &name,
                    const InputKind &kind, const std::string &sha, const Settings &s, std::function<bool()> cancelled) {
  Scratch sc(root_ / "tmp");
  const std::string stem = safe_stem(name);
  const fs::path in = sc.in / (stem + input_extension(kind, name));
  {
    std::ofstream f(in, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!f) throw Error(Error::Code::failed_precondition, "cannot write the input to " + in.string());
  }
  ::chmod(in.c_str(), 0444);
  ::chmod(sc.in.c_str(), 0555);

  SandboxSpec spec;
  spec.argv = expand_command(d.command, t, s, in, sc.out, sc.home, sc.tmp, stem, false);
  std::vector<std::string> env = base_env(sc.home, sc.tmp);
  add_runtime_env(d, t, s.limits.memory_bytes, env);
  spec.env = env;
  spec.read_paths = system_read_paths();
  spec.read_paths.insert(spec.read_paths.end(), t.read_paths.begin(), t.read_paths.end());
  spec.read_paths.push_back(sc.in);
  spec.write_paths = {sc.out, sc.home, sc.tmp};
  spec.cwd = sc.home;
  spec.stdout_file = sc.dir / "stdout";
  spec.stderr_file = sc.dir / "stderr";
  spec.output_dir = sc.out;
  spec.limits = s.limits;
  spec.allow_weak = s.allow_weak_sandbox;
  spec.cancelled = std::move(cancelled);
  const RunOutcome o = run_sandboxed(spec);

  Result r;
  r.status = o.status;
  r.detail = o.detail;
  r.stderr_tail = o.stderr_tail;
  r.seconds = o.seconds;
  r.provider = d.name;
  r.version = t.version;
  r.input = kind;
  r.sha256 = sha;
  r.shape = d.shape;
  r.language = d.language;
  r.finished_at = now_unix();
  r.sandbox = probe_support().describe() + "; limits " + limits_text(s.limits);
  if (o.status == RunStatus::cancelled) throw Error(Error::Code::cancelled, "cancelled");
  if (!cacheable(o.status)) return r;  // nothing kept: a limit stopped it, or it never ran

  // A tool that writes to stdout: that is its one file.
  std::error_code ec;
  if (d.shape == Shape::file && fs::file_size(spec.stdout_file, ec) > 0 && fs::is_empty(sc.out, ec)) {
    const std::string ext = d.stdout_extension.empty() ? ".txt" : d.stdout_extension;
    fs::rename(spec.stdout_file, sc.out / (stem + ext), ec);
  }
  r.files = sanitize(sc.out, r.total_bytes);
  if (r.status == RunStatus::ok && r.files.empty()) {
    r.status = RunStatus::failed;
    r.detail = "exited 0 but wrote nothing";
  }
  r.main_file = pick_main(r.files, d.language);

  // Into the cache: built in the scratch directory, then renamed into place.
  const fs::path dest = key_dir(sha, d.name, t.version, kind);
  const fs::path staged = sc.dir / "result";
  fs::create_directory(staged, ec);
  fs::rename(sc.out, staged / "out", ec);
  if (ec || !write_meta(staged, r)) return r;
  fs::create_directories(dest.parent_path(), ec);
  if (fs::exists(dest, ec)) fs::remove_all(dest, ec);
  if (::rename(staged.c_str(), dest.c_str()) != 0) return r;
  r.dir = dest;
  trim_cache(s);
  return r;
}

void Service::trim_cache(const Settings &s) {
  if (s.cache_max_bytes == 0) return;
  struct Entry {
    fs::path dir;
    fs::file_time_type used;
    std::uint64_t bytes;
  };
  std::vector<Entry> entries;
  std::uint64_t total = 0;
  std::error_code ec;
  for (fs::directory_iterator a(root_, ec), end; !ec && a != end; a.increment(ec)) {
    if (a->path().filename() == "tmp" || !a->is_directory(ec)) continue;
    for (fs::directory_iterator b(a->path(), ec); !ec && b != end; b.increment(ec))
      for (fs::directory_iterator c(b->path(), ec); !ec && c != end; c.increment(ec)) {
        auto r = load_result(c->path());
        if (!r) continue;
        entries.push_back({c->path(), fs::last_write_time(c->path() / "result", ec), r->total_bytes});
        total += r->total_bytes;
      }
    ec.clear();
  }
  if (total <= s.cache_max_bytes) return;
  std::sort(entries.begin(), entries.end(), [](const Entry &x, const Entry &y) { return x.used < y.used; });
  for (const Entry &e : entries) {
    if (total <= s.cache_max_bytes) break;
    fs::remove_all(e.dir, ec);
    total -= std::min(total, e.bytes);
  }
}

std::string Service::read_file(const Result &r, const std::string &path, std::uint64_t offset, std::uint64_t max,
                               std::uint64_t &size) {
  if (r.dir.empty()) throw Error(Error::Code::not_found, "this result's files weren't kept");
  if (!std::binary_search(r.files.begin(), r.files.end(), OutputFile{path, 0, {}},
                          [](const OutputFile &a, const OutputFile &b) { return a.path < b.path; }))
    throw Error(Error::Code::not_found, "no file " + path + " in the output");
  // Component by component, never following a link.
  int fd = ::open((r.dir / "out").c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  std::stringstream ss(path);
  std::string comp;
  std::vector<std::string> comps;
  while (std::getline(ss, comp, '/')) comps.push_back(comp);
  for (std::size_t i = 0; fd >= 0 && i < comps.size(); ++i) {
    if (comps[i].empty() || comps[i] == "." || comps[i] == "..") {
      ::close(fd);
      fd = -1;
      break;
    }
    const bool last = i + 1 == comps.size();
    const int next = ::openat(fd, comps[i].c_str(), (last ? O_RDONLY : O_RDONLY | O_DIRECTORY) | O_NOFOLLOW | O_CLOEXEC);
    ::close(fd);
    fd = next;
  }
  if (fd < 0) throw Error(Error::Code::not_found, "cannot open " + path + " in the output");
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    ::close(fd);
    throw Error(Error::Code::not_found, path + " isn't a file");
  }
  size = static_cast<std::uint64_t>(st.st_size);
  std::string out;
  if (offset < size) {
    out.resize(static_cast<std::size_t>(std::min<std::uint64_t>(max, size - offset)));
    std::size_t got = 0;
    while (got < out.size()) {
      const ssize_t n = ::pread(fd, out.data() + got, out.size() - got, static_cast<off_t>(offset + got));
      if (n <= 0) break;
      got += static_cast<std::size_t>(n);
    }
    out.resize(got);
  }
  ::close(fd);
  return out;
}

}  // namespace revkit::providers
