// The WebAssembly plugin host: loads plugins (a wasm32 module plus its
// manifest), and runs them sandboxed in wasmtime.
//
// Sandbox, per call:
//   - a fresh store and instance, so no state carries from one call to the
//     next and a call's result depends only on its input and what it reads;
//   - fuel: every wasm instruction and every host call costs fuel, and a
//     call that runs out traps (deterministically, so the failure itself
//     can be memoized);
//   - a wall-clock backstop (epoch interruption) for anything fuel misses;
//     a call stopped by it is reported as a timeout and never memoized;
//   - a cap on linear memory: memory.grow past it returns -1, and a module
//     whose initial memory exceeds it doesn't instantiate;
//   - imports: only "revkit:plugin/v1" functions, and only those its
//     granted capabilities cover. No WASI: no files, network, clocks,
//     randomness or environment. A module importing anything else is
//     rejected at load;
//   - determinism: NaN canonicalization, no threads or shared memory, no
//     relaxed SIMD; signals-based traps are off, so the host installs no
//     signal handlers and every trap is an explicit check.
// A trap, an exhausted budget or malformed output is a failed call, never
// a crash: host imports validate every guest pointer and length, and
// exceptions from fact reads are carried across the wasm frames and
// rethrown to the caller.
#pragma once

#include "revkit/plugins/abi.h"
#include "revkit/plugins/manifest.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace revkit::plugins {

// The facts a plugin may pull during a call, each answering one host import
// with a blob in the ABI encoding (see abi.h and docs/plugins.md). Reads made
// inside a fact-engine query go through its QueryContext, which records them
// as the analyzer's dependencies (see queries.h).
class FactProvider {
 public:
  virtual ~FactProvider() = default;
  // ProgramInfo record. Always available to analyzers and commands.
  virtual std::string program_info() = 0;
  // Mapped, initialized bytes at addr into out; stops at a gap. Returns the
  // count copied.
  virtual std::size_t memory_read(std::uint64_t addr, std::span<std::byte> out) = 0;
  virtual std::uint64_t file_size() = 0;
  virtual std::size_t file_read(std::uint64_t offset, std::span<std::byte> out) = 0;
  // list<Function>.
  virtual std::string functions() = 0;
  // FunctionCode record; nullopt if no function starts at entry.
  virtual std::optional<std::string> function_code(std::uint64_t entry) = 0;
  // The effective name at addr (asserted, else discovered), empty if none.
  virtual std::string symbol_name(std::uint64_t addr) = 0;
};

struct Limits {
  std::uint64_t fuel = 0;          // wasm instructions, roughly
  std::uint64_t memory_bytes = 0;  // linear memory cap
  std::chrono::milliseconds wall{0};
};

enum class Failure : std::uint8_t {
  none,
  plugin_error,  // the entry point returned non-zero
  trap,          // unreachable, out-of-bounds access, stack overflow, ...
  out_of_fuel,
  out_of_memory,  // memory.grow failed at the cap, or initial memory exceeds it
  timeout,        // the wall-clock backstop; not deterministic
  bad_output,     // the result did not decode
};
std::string_view to_string(Failure f);

struct CallResult {
  Failure failure = Failure::none;
  std::string output;  // set_output's blob (the error message on failure, if any)
  std::string error;   // human-readable failure
  std::uint64_t fuel_consumed = 0;
  std::vector<std::string> log;  // log() lines, capped
  bool ok() const { return failure == Failure::none; }
};

namespace detail {
struct Runtime;
struct Compiled;
}  // namespace detail

// What a peripheral plugin's imports reach: the emulated machine around it.
class PeripheralHost {
 public:
  virtual ~PeripheralHost() = default;
  virtual std::uint64_t now() = 0;                     // machine ticks
  virtual void schedule(std::int64_t at) = 0;          // tick() at `at`; negative: cancel
  virtual void irq(std::uint32_t line, bool level) = 0;
  virtual void output(std::string_view bytes) = 0;
  virtual bool bus_read(std::uint64_t address, std::span<std::uint8_t> out) = 0;
  virtual bool bus_write(std::uint64_t address, std::span<const std::uint8_t> bytes) = 0;
  virtual void log(std::string_view line) = 0;
};

// A live peripheral plugin: one store and instance for a session, whose
// state carries from call to call. Every call has the plugin's fuel and
// wall-clock budget; a call that fails (a trap, out of fuel, a non-zero
// return) leaves the instance dead, with error() saying why.
class PeripheralInstance {
 public:
  ~PeripheralInstance();
  bool init(std::string_view config);
  bool read(std::uint64_t offset, std::uint32_t size, std::uint64_t &value);
  bool write(std::uint64_t offset, std::uint32_t size, std::uint64_t value);
  bool tick(std::uint64_t now);
  bool input(std::string_view bytes);
  bool irq_in(std::uint32_t line, bool level);
  bool reset();
  bool dead() const;
  const std::string &error() const;
  std::uint64_t fuel_used() const;
  std::uint64_t calls() const;

  struct Impl;

 private:
  friend class Plugin;
  PeripheralInstance() = default;
  std::unique_ptr<Impl> impl_;
};

class Plugin {
 public:
  const Manifest &manifest() const { return manifest_; }
  const std::string &id() const { return id_; }  // name@version
  // Identity of the module's bytes (128-bit hex): memoized analyzer
  // results are keyed by it, so a rebuilt module never reuses them.
  const std::string &fingerprint() const { return fingerprint_; }
  const std::set<Capability> &granted() const { return granted_; }
  const Limits &limits() const { return limits_; }
  const std::filesystem::path &path() const { return path_; }

  // Runs one entry point in a fresh instance. Exceptions thrown by `facts`
  // propagate (after the instance is torn down); everything the plugin
  // does wrong is a failed CallResult.
  CallResult call(std::string_view entry, std::string_view input, FactProvider *facts) const;
  // Peripherals: a live instance whose imports reach `host` (which must
  // outlive it). nullptr with `error` set when it can't be instantiated.
  std::unique_ptr<PeripheralInstance> instantiate(PeripheralHost &host, std::string &error) const;

 private:
  friend class Host;
  Plugin() = default;
  Manifest manifest_;
  std::string id_;
  std::string fingerprint_;
  std::set<Capability> granted_;
  Limits limits_;
  std::filesystem::path path_;
  std::shared_ptr<detail::Compiled> compiled_;
};

struct HostOptions {
  // Limits a plugin gets when its manifest asks for none, and the most it
  // can ask for.
  Limits defaults{2'000'000'000, 64ull << 20, std::chrono::seconds(30)};
  Limits maximum{20'000'000'000, 1ull << 30, std::chrono::seconds(300)};
  // Capabilities granted to any plugin that requests them. `file` is not
  // among them: reading the binary itself needs an explicit grant.
  // Peripherals' irq and output reach only their own emulation session.
  std::set<Capability> default_grants{Capability::memory, Capability::code, Capability::irq, Capability::output};
  // Extra grants by plugin name ("--plugin-grant name=file").
  std::map<std::string, std::set<Capability>> grants;
};

// A plugin that failed to load, with why.
struct Rejected {
  std::filesystem::path path;
  std::string name;  // from the manifest, if it parsed
  std::string version;
  std::string error;
};

class Host {
 public:
  explicit Host(HostOptions options = {});
  ~Host();
  Host(const Host &) = delete;
  Host &operator=(const Host &) = delete;

  // False when revkit was built without wasmtime (REVKIT_PLUGINS=OFF or an
  // unsupported platform); loading then always fails.
  static bool available();

  // Loads NAME.wasm with NAME.json beside it. Throws std::runtime_error
  // with the reason it was rejected.
  std::shared_ptr<const Plugin> load(const std::filesystem::path &wasm);
  // The same from memory. `module` is wasm bytes, or WAT text.
  std::shared_ptr<const Plugin> load(std::string_view manifest_json, std::string_view module,
                                     const std::filesystem::path &origin = {});
  // Every *.wasm in dir, in name order. Rejections are returned, not thrown.
  std::vector<Rejected> load_dir(const std::filesystem::path &dir);

  std::vector<std::shared_ptr<const Plugin>> plugins() const;  // by name
  std::shared_ptr<const Plugin> find(const std::string &name) const;
  const std::vector<Rejected> &rejected() const { return rejected_; }
  const HostOptions &options() const { return options_; }

 private:
  HostOptions options_;
  std::shared_ptr<detail::Runtime> runtime_;
  std::map<std::string, std::shared_ptr<const Plugin>> plugins_;
  std::vector<Rejected> rejected_;
};

// A loaded plugin by module fingerprint, from any live Host in the process:
// how a memoized analyzer query (which only has its key) finds its module.
std::shared_ptr<const Plugin> find_by_fingerprint(const std::string &fingerprint);

// WAT text to wasm bytes (for tests and hand-written plugins). Throws.
std::string wat_to_wasm(std::string_view wat);

// ---- Typed calls ----------------------------------------------------------

struct DerivedItem {
  abi::FactKind kind = abi::FactKind::label;
  std::uint64_t address = 0;
  std::string text;
  std::string sub;
  friend bool operator==(const DerivedItem &, const DerivedItem &) = default;
};

// Runs an analyzer on one scope. Facts it returns are checked: text is
// bounded and kinds are known, else the call fails with bad_output.
CallResult run_analyzer(const Plugin &p, abi::Scope scope, std::uint64_t address, FactProvider &facts,
                        std::vector<DerivedItem> &out);

struct LoadedBlock {
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  std::uint64_t file_offset = 0;
  std::uint64_t file_size = 0;
  std::uint8_t perms = 0;  // abi::Perm
};
struct LoadedSymbol {
  std::string name;
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  bool function = false;
};
struct LoadResult {
  std::string language;  // Ghidra language id, "x86:LE:64:default"
  std::string compiler;  // compiler spec id; empty = "default"
  std::optional<std::uint64_t> entry;
  std::vector<LoadedBlock> blocks;
  std::vector<LoadedSymbol> symbols;
};

// Runs a loader on a file's bytes.
CallResult run_loader(const Plugin &p, std::string_view file, LoadResult &out);
// Whether a loader's manifest magic matches the file.
bool loader_matches(const Plugin &p, std::string_view file);

struct Edit {
  abi::EditOp op = abi::EditOp::rename;
  std::uint64_t address = 0;
  std::string text;
  std::string sub;
  friend bool operator==(const Edit &, const Edit &) = default;
};

// Runs a command with its arguments; missing required args and unknown
// ones are rejected before the plugin runs (std::invalid_argument).
CallResult run_command(const Plugin &p, const std::string &program_id, const std::map<std::string, std::string> &args,
                       FactProvider &facts, std::vector<Edit> &out);

}  // namespace revkit::plugins
