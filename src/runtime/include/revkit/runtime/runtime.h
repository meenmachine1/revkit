// revkit::runtime — what every revkit executable needs to know about the
// installation it runs from: its version, and where Ghidra's processor specs
// are (docs/getting-started.md, "Ghidra processor specs").
//
// The version comes from the VERSION file at the source root (one place;
// scripts/version.sh copies it into the SDKs and the Tauri shell) and the
// git commit of the build.
//
// Ghidra's processor specs (.sla, .ldefs, .pspec, .cspec, function-start
// patterns, plus the Base data type archives and string model) are read at
// run time from a Ghidra install, or from the trimmed copy a revkit bundle
// carries in share/revkit/ghidra (scripts/gather-ghidra-specs.sh). They are
// looked for, in order:
//
//   1. --ghidra DIR (the tool's flag)
//   2. $GHIDRA_INSTALL_DIR
//   3. `ghidra = DIR` in $XDG_CONFIG_HOME/revkit/revkit.conf
//      (~/.config/revkit/revkit.conf), then /etc/revkit/revkit.conf
//   4. the bundle's own copy: <executable>/../share/revkit/ghidra
//   5. the build's GHIDRA_ROOT (source builds)
//   6. common install paths: ~/ghidra*, ~/ghidra/ghidra_*, /opt/ghidra*,
//      /opt/ghidra/ghidra_*, /usr/share/ghidra, /usr/lib/ghidra (newest first)
//
// A directory named explicitly (1-3) that is not a usable Ghidra is an
// error, never skipped: a typo should not silently pick another install.

#pragma once

#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::runtime {

// "0.1.0".
std::string_view version();
// The build's git commit (12 hex digits), or "unknown".
std::string_view git_sha();
// "rk-lift 0.1.0 (git 0123456789ab)".
std::string version_string(std::string_view tool);

// If any argument before a "--" is --version, prints version_string(tool) to stdout and
// returns true (the caller exits 0).
bool print_version_if_asked(int argc, char **argv, std::string_view tool);

// The directory of the running executable (/proc/self/exe), or empty.
std::filesystem::path executable_dir();
// <executable>/../share/revkit when it exists (an installed or bundled
// revkit), else nullopt.
std::optional<std::filesystem::path> share_dir();

// The library type archives (docs/types.md#library-prototypes):
// $REVKIT_TYPEINFO_DIR, else <executable>/../share/revkit/typeinfo, else the
// build's own (source builds); nullopt when none of them is a directory.
std::optional<std::filesystem::path> typeinfo_dir();

class GhidraNotFound : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct GhidraSpecs {
  std::filesystem::path root;
  // Where it came from: "--ghidra", "$GHIDRA_INSTALL_DIR", the config
  // file's path, "bundled", "build default" or "common path".
  std::string source;
  // application.version from Ghidra/application.properties, or empty.
  std::string version;
  // Non-fatal problems (a Ghidra major version other than the one revkit's
  // decompiler is built from); empty when none.
  std::string warning;
};

// The Ghidra major version revkit's SLEIGH engine and decompiler come from.
inline constexpr int kGhidraMajor = 12;

struct FindOptions {
  // Overrides for tests; unset means the real environment.
  std::optional<std::string> env;            // $GHIDRA_INSTALL_DIR
  std::optional<std::vector<std::filesystem::path>> config_files;
  std::optional<std::filesystem::path> bundled;
  std::optional<std::string> build_default;  // REVKIT_DEFAULT_GHIDRA_ROOT
  std::optional<std::vector<std::filesystem::path>> common;
};

// The revkit.conf files, the user's first: $XDG_CONFIG_HOME/revkit/revkit.conf
// (~/.config/revkit/revkit.conf), then /etc/revkit/revkit.conf. Each line is
// `key = value`; `#` starts a comment.
std::vector<std::filesystem::path> config_files();
// Every value of `key` in `file`, in order (quotes around a value removed);
// empty when the file or key is absent.
std::vector<std::string> config_values(const std::filesystem::path &file, std::string_view key);

// Empty when root has the processor specs revkit needs, else why not.
std::string check_ghidra_root(const std::filesystem::path &root);

// Searches in the order above. Throws GhidraNotFound with a message that
// lists every place tried and how to fix it.
GhidraSpecs locate_ghidra(std::string_view flag, const FindOptions &options = {});

// locate_ghidra() for the tools: prints any warning to stderr as
// "<tool>: warning: ..." and returns the root; when nothing is found, prints
// "<tool>: <why and how to fix it>" and returns nullopt (exit 1).
std::optional<std::filesystem::path> find_ghidra(std::string_view flag, std::string_view tool);

}  // namespace revkit::runtime
