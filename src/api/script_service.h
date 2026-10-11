// ScriptService (proto/revkit/v1/script.proto, docs/scripting.md): the
// script libraries the daemon knows, and runs of them in Python host
// processes it starts (`python -m revkit.script.worker --stream`) with a
// run token that acts as the caller.
//
// The pieces below the service are separate so tests can reach them:
// metadata parsing (the same tags revkit/script/meta.py reads), the trust
// pins, finding a Python that can import revkit, and who may run scripts.
#pragma once

#include "revkit/api/backend.h"
#include "revkit/api/server.h"
#include "revkit/auth/store.h"

#include <grpcpp/grpcpp.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace revkit::api {

class AuthGate;

// One `# @arg name[:type][[a|b]][=default] description` line.
struct ScriptArgMeta {
  std::string name, type = "str", description;
  std::optional<std::string> default_value;
  std::vector<std::string> choices;
};

// What the comment block at a script's top says (revkit/script/meta.py).
struct ScriptMeta {
  std::string name;  // @name, else the file's stem
  std::string category, description, menupath, keybinding, context = "program";
  std::vector<ScriptArgMeta> args;
  std::vector<std::string> errors;
};

ScriptMeta ParseScriptMetadata(std::string_view source, const std::string &stem);

// Hex SHA-256.
std::string Sha256Hex(std::string_view data);

// Pins of script text callers confirmed: lines "<sha256> <script_id>
// <caller>" in one file, rewritten atomically.
class ScriptTrust {
 public:
  explicit ScriptTrust(std::filesystem::path file) : file_(std::move(file)) {}
  // The hash `caller` pinned for `script_id`, or "".
  std::string Pinned(const std::string &caller, const std::string &script_id);
  // Pins `sha256` (replacing an older pin of the same script by the same
  // caller). Throws std::runtime_error when the file can't be written.
  void Pin(const std::string &caller, const std::string &script_id, const std::string &sha256);
  const std::filesystem::path &file() const { return file_; }

 private:
  std::map<std::pair<std::string, std::string>, std::string> Load();
  std::filesystem::path file_;
  std::mutex mu_;
};

// Which callers the daemon runs scripts (and consoles) for: the role
// --scripts-host-role names ("off", "viewer", "editor", "admin"), else
// editor when every listener is on loopback and nobody otherwise. Returns
// nullopt for "off"; `why` says how it was decided. A viewer's runs get a
// viewer's run token: they read, and their edits are refused.
std::optional<auth::Role> ScriptHostRole(const std::string &configured, bool all_loopback, std::string &why);

// A Python whose revkit SDK is this daemon's or newer (it imports
// revkit.script.worker and revkit.script.console, and its
// revkit.script.SCRIPT_API is at least the daemon's), with the PYTHONPATH
// it needs ("" for none).
struct PythonChoice {
  std::string python;
  std::string pythonpath;
};
// Tries, in order: `configured` (only it, when set); $REVKIT_PYTHON;
// ~/.local/share/revkit/pyenv/bin/python (or $XDG_DATA_HOME's); python3 on
// PATH; then the same with `sdk_pythonpath` (the source tree's sdk/python)
// on PYTHONPATH. On failure returns nullopt and `problem` says what was
// tried and how to set one up, or, when one has an older SDK, that it must
// be updated (Set up Python, rk-script setup).
std::optional<PythonChoice> FindScriptPython(const std::string &configured, const std::string &sdk_pythonpath,
                                             std::string &problem);

// $XDG_CONFIG_HOME/revkit (or ~/.config/revkit).
std::filesystem::path RevkitConfigDir();

// The environment rk-script setup and SetupScriptPython make, which
// FindScriptPython tries: $XDG_DATA_HOME/revkit/pyenv (or
// ~/.local/share/revkit/pyenv).
std::filesystem::path ScriptPythonEnv();

// What SetupScriptPython installs (ScriptHostOptions::sdk_sources): the
// newest revkit-*.whl of the first directory holding one, else the first
// SDK source tree; "" when there is neither.
std::string FindScriptSdk(const std::vector<std::string> &sources);

struct ScriptServiceOptions {
  ScriptHostOptions host;
  // Every listener is on loopback (Server::Start decides).
  bool all_loopback = true;
};

// Filled in by Server::Start once the gRPC listener is bound: where a
// script host connects, and the certificate it pins.
struct ScriptHostTarget {
  std::mutex mu;
  std::string grpc_target;      // "127.0.0.1:50051"; empty: no gRPC listener
  std::string tls_fingerprint;  // empty: plaintext
};

std::unique_ptr<grpc::Service> MakeScriptService(std::shared_ptr<AuthGate> gate, ScriptServiceOptions options,
                                                 std::shared_ptr<ScriptHostTarget> target,
                                                 std::shared_ptr<std::atomic<bool>> stopping);

}  // namespace revkit::api
