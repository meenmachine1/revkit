// Build metadata a toolchain leaves in an executable: Go's build info
// (the Go version, the main module, its dependencies and the build
// settings, from .go.buildinfo) and the dependency list cargo-auditable
// embeds in a Rust binary (.dep-v0), with the rustc version and commits a
// Rust binary names. docs/build-info.md.
//
// Nothing here runs or trusts the file: every length is bounded, absence is
// not a verdict (a stripped or old binary may have none), and a blob that
// is there but malformed is reported as a warning, not thrown.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "revkit/loader/image.hh"

namespace revkit::loader {

// One module line of Go's module text: "mod" (the main module), "dep", and
// the "=>" replacement that may follow either. A directory replacement has
// no sum and an empty version (or "(devel)" in recent Go).
struct GoModuleReplacement {
  std::string path;
  std::string version;
  std::string sum;
};
struct GoModule {
  std::string path;
  std::string version;
  std::string sum;  // "h1:..."; empty when the build didn't record one
  std::optional<GoModuleReplacement> replacement;
};

// A "build" line: -buildmode, -compiler, -ldflags, -tags, CGO_ENABLED,
// GOOS, GOARCH, GOAMD64, vcs, vcs.revision, vcs.time, vcs.modified, ...
// (Go 1.18 and later), unquoted.
struct GoBuildSetting {
  std::string key;
  std::string value;
};

struct GoBuildInfo {
  // "go1.22.3", "devel go1.23-abc..."; never empty.
  std::string go_version;
  // The main package's import path ("path" line); empty for some tests.
  std::string path;
  std::optional<GoModule> main;
  std::vector<GoModule> deps;
  std::vector<GoBuildSetting> settings;
  // Go 1.18 and later store the strings after the header (inline);
  // earlier ones point to Go string headers elsewhere in memory.
  bool inline_strings = false;
  std::uint32_t pointer_size = 0;  // the header's (4 or 8)
  // Where the header is (a 16-byte aligned address in memory).
  std::uint64_t address = 0;
  // The module text without its 16-byte sentinels: what `go version -m`
  // prints. Empty when the binary was built without module support.
  std::string module_text;
  // Lines of the module text this reader didn't take (an unknown kind,
  // a bad field count, an unterminated last line), as they are.
  std::vector<std::string> unparsed;

  // The value of a build setting, or nullptr.
  const std::string *setting(std::string_view key) const;
};

// Reads `out.size()` bytes at `address`; returns how many were mapped
// (the rest are zero).
using ReadMemoryFn = std::function<std::size_t(std::uint64_t address, std::span<std::byte> out)>;
// The address a pointer stored at `at` holds, from the `raw` word read
// there: relocations and a rebase applied. Identity when unset.
using PointerFn = std::function<std::uint64_t(std::uint64_t at, std::uint64_t raw)>;

// Searches [start, start + size) for Go's build-info header (the magic
// "\xff Go buildinf:" at a 16-byte aligned address) and decodes it, reading
// through `read` (the pointer format follows pointers anywhere in memory).
// nullopt with *error empty: no header; with *error set: a header that
// doesn't decode. The header says the pointer format's size and byte
// order (as Go's reader takes them). The search reads at most 256 MiB.
std::optional<GoBuildInfo> find_go_buildinfo(const ReadMemoryFn &read, std::uint64_t start, std::uint64_t size,
                                             const PointerFn &pointer, std::string *error);

// Parses Go's module text (unframed) into `out`'s path, main, deps,
// settings and unparsed lines. Port of rea's GoModuleText.ts (MIT); Go's
// debug/buildinfo ParseBuildInfo is the format's definition.
void parse_go_module_text(std::string_view text, GoBuildInfo &out);

// Where Go's build info is in an image: the .go.buildinfo section (ELF),
// __go_buildinfo (Mach-O), else the first writable data region Go's own
// reader looks in (an ELF's first writable, non-executable PT_LOAD; a PE's
// first initialized read-write data section, .data).
std::optional<GoBuildInfo> read_go_buildinfo(const Image &image, std::string *error);

// cargo-auditable's dependency list (https://github.com/rust-secure-code/cargo-auditable,
// format 0/1: a zlib stream holding {"format":N,"packages":[...]}).
struct RustPackage {
  std::string name;
  std::string version;
  // "crates.io", "local", "git", "registry", "other" (as cargo-auditable
  // writes it).
  std::string source;
  // "runtime" or "build"; empty when absent (runtime).
  std::string kind;
  // Indexes in RustAuditInfo::packages, as in the file.
  std::vector<std::uint32_t> dependencies;
  bool root = false;
};

struct RustAuditInfo {
  std::uint32_t format = 0;  // the "format" field, 0 when absent
  std::vector<RustPackage> packages;
  // The package marked root (the binary's own crate), if any.
  std::optional<std::uint32_t> root;
  std::uint64_t compressed_size = 0;
  std::uint64_t uncompressed_size = 0;
};

// Limits: 1 MiB compressed, 8 MiB (and at most 64x) inflated, JSON nested
// at most 32 deep, 200k packages and edges.
inline constexpr std::size_t kRustAuditMaxCompressed = 1u << 20;
inline constexpr std::size_t kRustAuditMaxInflated = 8u << 20;

// Inflates and validates a .dep-v0 section's bytes. nullopt with *error
// set when they don't decode: not zlib, not JSON, a package without a name,
// version or source, an index outside the list, two roots. Unknown fields
// are ignored. Port of rea's RustAuditableReader.ts (MIT).
std::optional<RustAuditInfo> parse_rust_audit(std::span<const std::byte> section, std::string *error);

// The .dep-v0 section of an image (ELF, PE; "__DATA,.dep-v0" in Mach-O),
// read from the file. nullopt with *error empty when there is none.
std::optional<RustAuditInfo> read_rust_audit(const Image &image, std::string *error);

// Everything above for one image.
struct BuildMetadata {
  std::optional<GoBuildInfo> go;
  std::optional<RustAuditInfo> rust;
  // "rustc version 1.79.0 (129f3b996 2024-06-10)" from the ELF .comment
  // section, when rustc left one.
  std::string rustc_version;
  // Distinct 40-hex commit hashes of rustc in "/rustc/<hash>/" paths of
  // read-only data (panic locations of the standard library), in file
  // order, at most 16.
  std::vector<std::string> rustc_commits;
  // Blobs that were there but didn't decode.
  std::vector<std::string> warnings;

  bool empty() const { return !go && !rust && rustc_version.empty() && rustc_commits.empty(); }
};

BuildMetadata read_build_metadata(const Image &image);

}  // namespace revkit::loader
