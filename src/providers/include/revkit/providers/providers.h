// External decompiler providers (docs/providers.md): dedicated decompilers
// for bytecode (ILSpy for .NET, jadx for DEX and APK, Vineflower and CFR
// for JVM class files and jars, unluac for Lua, pycdc for Python, webcrack
// for JavaScript bundles, wasm-decompile for WebAssembly), each run as a
// sandboxed child process (sandbox.h) on one input file, its output (a
// source tree or one file) cached by the input's SHA-256, the provider and
// the tool's version.
//
// One mechanism: a provider is a definition (the kinds of input it takes,
// how to find the tool, how to run it, how to ask its version); the daemon
// configures paths and turns providers off (Settings); Service resolves the
// tools, runs them with bounded concurrency and keeps the cache.
#pragma once

#include "revkit/providers/sandbox.h"

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::providers {

// --- what an input is ------------------------------------------------------

// "dotnet" (a PE with a CLR header), "dex", "apk", "jar", "class", "pyc",
// "lua", "luajit", "wasm", "js", or "" when it is none of these.
struct InputKind {
  std::string kind;
  std::string version;      // "3.12" for a .pyc, "5.4" for a Lua chunk, "035" for a DEX
  std::string description;  // ".NET assembly", "Python 3.12 bytecode", ...
  explicit operator bool() const { return !kind.empty(); }
};

// From the file's bytes (and its name, for JavaScript, which only its name
// and text say): the container detector's content kind
// (container::Guess::content_kind, docs/filesystems.md "Content kinds")
// through kind_from_format, and a zip's central directory when its first
// members don't say jar or APK.
InputKind detect_kind(std::span<const std::byte> bytes, std::string_view name);
// The kind a content kind ("pyc:3.12", "java-class:21", "dotnet:il",
// "js-source", ...) or a detector format names, or "".
InputKind kind_from_format(std::string_view format);
// Every kind detect_kind() answers, for docs and the API.
const std::vector<std::string> &all_kinds();

// --- definitions -----------------------------------------------------------

enum class Runtime { native, java, dotnet, node };
enum class Shape { tree, file };

struct Definition {
  std::string name;      // "ilspy", "jadx", ...
  std::string title;     // "ILSpy"
  std::string tool;      // "ilspycmd"
  std::string license;   // "MIT"
  std::string homepage;
  std::vector<std::string> kinds;
  Runtime runtime = Runtime::native;
  Shape shape = Shape::tree;
  std::string language;  // what it writes: "csharp", "java", "lua", "python", "javascript", "wasm"
  // Where to look after a configured path: names on PATH, then install
  // locations ("~/" is the home directory; one "*" per component matches
  // the newest version).
  std::vector<std::string> path_names;
  std::vector<std::string> known;
  // The command line. Placeholders: {tool} (the tool, or its jar),
  // {launcher} (java or node), {jvm} (the JVM options, several words),
  // {heap_mib}, {in} (the input file), {out} (the output directory),
  // {stem} (the input's name without extension), {home}, {tmp}.
  std::vector<std::string> command;
  // Asking its version, the same placeholders; empty: the jar manifest's
  // Implementation-Version (version_from_manifest) or the tool's hash.
  std::vector<std::string> version_command;
  bool version_from_manifest = false;
  // A one-file tool that writes to stdout: the file's extension.
  std::string stdout_extension;
  // Bumped when the invocation changes, so the cache doesn't serve output
  // of the old one.
  int revision = 1;
};
Definition make_definition(std::string name, std::string title, std::string tool, std::string license,
                           std::string homepage, std::vector<std::string> kinds, Runtime runtime, Shape shape,
                           std::string language);
// The built-in providers, in the order ListProviders shows them.
const std::vector<Definition> &definitions();
const Definition *find_definition(std::string_view name);

// The language a file is in, from its extension ("csharp", "java", "xml",
// "text", ...).
std::string language_of(std::string_view path);

// --- configuration ---------------------------------------------------------

struct ProviderConfig {
  std::string name;
  std::string path;       // the tool (or its jar); empty: search
  bool disabled = false;
};

struct Settings {
  bool enabled = true;                    // all providers
  std::vector<ProviderConfig> providers;  // per provider
  std::string java;                       // the java executable for jar tools; empty: $JAVA_HOME, PATH
  std::string node;                       // node for webcrack; empty: PATH
  std::string dotnet_root;                // for ilspycmd; empty: $DOTNET_ROOT, beside dotnet on PATH
  SandboxLimits limits;
  bool allow_weak_sandbox = false;        // run where the kernel has no Landlock
  std::uint64_t max_input_bytes = 512ull << 20;
  std::uint64_t cache_max_bytes = 4ull << 30;
  unsigned max_concurrent = 2;
  unsigned max_waiting = 8;
  // The environment's PATH and HOME searched for tools (tests replace them).
  std::string search_path;                // empty: $PATH
  std::string home;                       // empty: $HOME
  // Providers beyond the built-in ones (tests use a fake one).
  std::vector<Definition> extra;
};

// --- tools -----------------------------------------------------------------

struct ToolStatus {
  std::string name;
  bool available = false;
  bool disabled = false;      // by the settings
  std::string path;           // the tool (a jar for the JVM tools)
  std::string launcher;       // java, node or the tool itself
  std::string version;
  std::string found_by;       // "configured", "PATH", "known location"
  std::string reason;         // why not available
  std::vector<std::filesystem::path> read_paths;  // what the sandbox lets it read
};

// --- results ---------------------------------------------------------------

struct OutputFile {
  std::string path;   // relative, "/"-separated
  std::uint64_t size = 0;
  std::string language;
};

struct Result {
  RunStatus status = RunStatus::sandbox_error;
  std::string detail;
  std::string stderr_tail;
  double seconds = 0;
  bool cached = false;
  std::string provider, version;
  InputKind input;
  std::string sha256;
  Shape shape = Shape::tree;
  std::string language;
  std::vector<OutputFile> files;
  std::string main_file;      // the file to show first
  std::uint64_t total_bytes = 0;
  std::string sandbox;        // what was enforced
  std::int64_t finished_at = 0;  // unix seconds
  std::filesystem::path dir;  // holds out/ (empty for runs not kept)
};

// A request that can't be served: maps to an API status.
class Error : public std::runtime_error {
 public:
  enum class Code { invalid_argument, not_found, failed_precondition, resource_exhausted, cancelled };
  Error(Code c, const std::string &m) : std::runtime_error(m), code(c) {}
  Code code;
};

std::string sha256_hex(std::span<const std::byte> bytes);

class Service {
 public:
  // `cache_root`: where results live (<project dir>/.revkit/providers).
  Service(Settings settings, std::filesystem::path cache_root);
  ~Service();

  void set_settings(Settings s);
  Settings settings() const;
  const std::filesystem::path &cache_root() const { return root_; }

  // Every provider's status, resolving tools (and asking their versions,
  // in the sandbox) the first time or when `refresh`.
  std::vector<ToolStatus> tools(bool refresh = false);
  ToolStatus tool(const std::string &name, bool refresh = false);
  // Every provider: the built-in ones and the settings' extra ones.
  std::vector<Definition> all_definitions() const;
  std::optional<Definition> definition(const std::string &name) const;
  // Providers that take `kind`, in order of preference (available or not).
  std::vector<std::string> for_kind(const std::string &kind) const;
  // The provider used when the caller names none: the first available one
  // for the kind, else the first that takes it.
  std::string default_provider(const std::string &kind);

  // Runs `provider` (or the default) on the input, or answers from the
  // cache. Throws Error for requests it can't serve; a tool's failure is a
  // Result with its status.
  Result decompile(std::span<const std::byte> bytes, const std::string &name, const InputKind &kind,
                   const std::string &provider, bool refresh, std::function<bool()> cancelled = {});
  // The cached result for the input, without running anything.
  std::optional<Result> cached(const std::string &sha256, const InputKind &kind, const std::string &provider);
  // A file of a result: `path` must be one of its files. At most `max`
  // bytes from `offset`; `size` gets the file's size.
  std::string read_file(const Result &r, const std::string &path, std::uint64_t offset, std::uint64_t max,
                        std::uint64_t &size);

  SandboxSupport support();

 private:
  struct Inflight;
  std::string key_dir(const std::string &sha, const std::string &provider, const std::string &version,
                      const InputKind &kind) const;
  ToolStatus resolve(const Definition &d, const Settings &s);
  Result run(const Definition &d, const ToolStatus &t, std::span<const std::byte> bytes, const std::string &name,
             const InputKind &kind, const std::string &sha, const Settings &s, std::function<bool()> cancelled);
  void trim_cache(const Settings &s);

  std::filesystem::path root_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  Settings settings_;
  std::map<std::string, ToolStatus> tools_;
  bool tools_resolved_ = false;
  unsigned running_ = 0, waiting_ = 0;
  std::map<std::string, std::shared_ptr<Inflight>> inflight_;
};

// Reads a result's metadata from its directory (the cache's format).
std::optional<Result> load_result(const std::filesystem::path &dir);

}  // namespace revkit::providers
