// rk-daemon's authentication mode: accounts or none (--no-auth), from its
// flags, a saved choice in revkit.conf, or a question on first run
// (docs/getting-started.md, docs/security.md).
//
// In order:
//   1. --no-auth, or --auth (--auth-file implies it)
//   2. --ask: ask again (needs a terminal)
//   3. `auth = none|accounts` in ~/.config/revkit/revkit.conf, else in
//      /etc/revkit/revkit.conf (the user's file wins)
//   4. on a terminal (stdin and stderr), with no accounts or tokens yet: ask
//   5. accounts, as before
// Without a terminal nothing is ever asked.
#pragma once

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::daemon {

enum class AuthMode { accounts, none };

std::string_view to_string(AuthMode mode);
// "none" or "accounts"; nullopt for anything else.
std::optional<AuthMode> parse_auth_mode(std::string_view value);

// What the question needs to ask and answer.
class Prompter {
 public:
  virtual ~Prompter() = default;
  // Shows `text` as it is.
  virtual void say(const std::string &text) = 0;
  // A line typed after `question`; nullopt at end of input.
  virtual std::optional<std::string> line(const std::string &question) = 0;
  // The same without echo (a password).
  virtual std::optional<std::string> secret(const std::string &question) = 0;
};

// The process's terminal: questions on stderr, answers from stdin.
class TerminalPrompter : public Prompter {
 public:
  void say(const std::string &text) override;
  std::optional<std::string> line(const std::string &question) override;
  std::optional<std::string> secret(const std::string &question) override;
};

struct AuthChoiceInput {
  bool no_auth_flag = false;  // --no-auth
  bool auth_flag = false;     // --auth, or --auth-file
  bool ask_flag = false;      // --ask
  bool interactive = false;   // stdin and stderr are terminals
  // revkit.conf files, the user's first (runtime::config_files()).
  std::vector<std::filesystem::path> config_files;
  // Where a remembered choice is written (the user's revkit.conf).
  std::filesystem::path user_config;
  // True when the credential file has no accounts or tokens.
  std::function<bool()> no_accounts;
  // Makes an admin account (rk-daemon user add NAME --role admin); throws
  // std::exception with the reason when it can't.
  std::function<void(const std::string &name, const std::string &password)> create_admin;
};

struct AuthChoice {
  AuthMode mode = AuthMode::accounts;
  // Where it came from, for the start-up line: "--no-auth", "--auth",
  // "auth = none in ~/.config/revkit/revkit.conf", "your answer", "the
  // default".
  std::string source;
};

// The saved choice: the first `auth =` line of the first file that has
// one, with that file. Throws std::runtime_error for a value other than
// none or accounts.
std::optional<std::pair<AuthMode, std::filesystem::path>> saved_auth(
    const std::vector<std::filesystem::path> &files);

// Sets `auth = <mode>` in `file`: replaces its first `auth =` line (and
// drops any later ones), keeps every other line as it was, appends the line
// when there is none, and makes the file and its directory when missing.
void save_auth(const std::filesystem::path &file, AuthMode mode);

// Decides the mode as above, asking through `prompter` when it should.
// Throws std::runtime_error when it can't (--ask without a terminal, the
// question abandoned).
AuthChoice choose_auth(const AuthChoiceInput &input, Prompter &prompter);

// The start-up line, without the "rk-daemon: " prefix: "no sign-in (auth =
// none in ~/.config/revkit/revkit.conf; --auth to require accounts)".
std::string describe(const AuthChoice &choice);

// `path` with the home directory written as ~.
std::string home_relative(const std::filesystem::path &path);

}  // namespace revkit::daemon
