// A plugin's manifest: the JSON file next to its module (NAME.json beside
// NAME.wasm) that says what it is and what it may touch.
//
//   {
//     "name": "string-refs",            // [a-z0-9][a-z0-9._-]*, unique per daemon
//     "version": "1.0.0",               // semver; part of the rule name name@version
//     "kind": "analyzer",               // analyzer | loader | command | peripheral
//     "interface": 1,                   // the plugin interface major version
//     "description": "...",
//     "capabilities": ["memory", "code"],
//     "analyzer": {"scope": "function"},                 // analyzers: program | function
//     "loader": {"magic": "524b524157", "offset": 0},    // loaders: hex bytes at offset
//     "command": {"args": [{"name": "pattern", "required": true, "description": "..."}]},
//     "peripheral": {"outputs": ["irq"], "inputs": 0, "size": 4096},  // peripherals (firmware emulation)
//     "limits": {"fuel": 2000000000, "memory_mb": 64}    // requests; the host caps them
//   }
#pragma once

#include <cstdint>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::plugins {

enum class Kind : std::uint8_t { analyzer, loader, command, peripheral };
std::string_view to_string(Kind k);

// What a plugin may read, beyond its own input. Each one links a set of
// host imports; a module importing something its grants don't cover is
// rejected at load.
enum class Capability : std::uint8_t {
  memory,  // the program's mapped bytes and memory map: memory_read
  code,    // functions, instructions and p-code, names: functions, function_code, symbol_name
  file,    // the raw bytes of the binary under analysis: file_size, file_read
  // Peripherals (docs/firmware-emulation.md):
  irq,     // drive interrupt lines: irq_set (granted by default)
  output,  // write to the session's output, as a UART does: output (granted by default)
  bus,     // read and write the emulated machine's memory (DMA): bus_read, bus_write; needs a grant
};
std::string_view to_string(Capability c);
std::optional<Capability> capability_from_string(std::string_view s);

class ManifestError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct CommandArg {
  std::string name;
  std::string description;
  bool required = false;
};

struct Manifest {
  std::string name;
  std::string version;
  Kind kind = Kind::analyzer;
  std::uint32_t interface_version = 0;
  std::string description;
  std::set<Capability> capabilities;
  // Analyzers: run once per program, or once per function.
  bool function_scope = false;
  // Loaders: the file starts with `magic` at `magic_offset`.
  std::string magic;
  std::uint64_t magic_offset = 0;
  // Commands: the arguments they take.
  std::vector<CommandArg> args;
  // Peripherals: interrupt output names (default {"irq"}), the number of
  // interrupt inputs a controller has (0: none), and the register block's
  // size when the machine gives none.
  std::vector<std::string> outputs;
  std::uint32_t inputs = 0;
  std::uint64_t region_size = 0x1000;
  // Requested limits; 0 means the host default.
  std::uint64_t fuel = 0;
  std::uint64_t memory_bytes = 0;

  // "name@version": the rule name of an analyzer's facts and the provenance
  // id of a command's assertions.
  std::string id() const { return name + "@" + version; }
};

// Throws ManifestError naming the offending field.
Manifest parse_manifest(std::string_view json);

}  // namespace revkit::plugins
