#include "auth_choice.h"

#include <termios.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace revkit::daemon {

namespace fs = std::filesystem;

namespace {

std::string trim(std::string s) {
  const auto ws = " \t\r\n";
  s.erase(0, s.find_first_not_of(ws));
  const auto end = s.find_last_not_of(ws);
  s.erase(end == std::string::npos ? 0 : end + 1);
  return s;
}

// The key of a `key = value` line ("" for a comment or anything else).
std::string key_of(const std::string &line) {
  std::string l = line;
  if (auto hash = l.find('#'); hash != std::string::npos) l.erase(hash);
  const auto eq = l.find('=');
  return eq == std::string::npos ? std::string() : trim(l.substr(0, eq));
}

std::string value_of(const std::string &line) {
  std::string l = line;
  if (auto hash = l.find('#'); hash != std::string::npos) l.erase(hash);
  std::string v = trim(l.substr(l.find('=') + 1));
  if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front()) v = v.substr(1, v.size() - 2);
  return v;
}

const char *kIntro =
    "\n"
    "rk-daemon: how should people sign in to this daemon?\n"
    "  1) No sign-in: only this computer can connect, and anyone using it is an admin.\n"
    "     Good for your own machine.\n"
    "  2) Accounts: create an admin account now.\n";

AuthChoice ask(const AuthChoiceInput &in, Prompter &p) {
  p.say(kIntro);
  AuthMode mode = AuthMode::accounts;
  for (int tries = 0;; ++tries) {
    auto a = p.line("Choose 1 or 2: ");
    if (!a) throw std::runtime_error("no answer to the sign-in question (start with --no-auth or --auth)");
    const std::string t = trim(*a);
    if (t == "1" || t == "2") {
      mode = t == "1" ? AuthMode::none : AuthMode::accounts;
      break;
    }
    if (tries == 4) throw std::runtime_error("no answer to the sign-in question (start with --no-auth or --auth)");
    p.say("Type 1 or 2.\n");
  }
  if (mode == AuthMode::accounts) {
    for (int tries = 0;; ++tries) {
      if (tries == 3) throw std::runtime_error("no admin account made (rk-daemon user add NAME --role admin)");
      auto name = p.line("Admin account name: ");
      if (!name) throw std::runtime_error("no admin account made (rk-daemon user add NAME --role admin)");
      const std::string n = trim(*name);
      if (n.empty()) {
        p.say("The name can't be empty.\n");
        continue;
      }
      auto pw = p.secret("Password: ");
      auto again = pw ? p.secret("Again: ") : std::nullopt;
      if (!pw || !again) throw std::runtime_error("no admin account made (rk-daemon user add NAME --role admin)");
      if (*pw != *again) {
        p.say("The passwords differ.\n");
        continue;
      }
      try {
        in.create_admin(n, *pw);
      } catch (const std::exception &e) {
        p.say(std::string("Can't make it: ") + e.what() + "\n");
        continue;
      }
      p.say("Made the admin account " + n + ".\n");
      break;
    }
  }
  AuthChoice c{mode, "your answer"};
  if (in.user_config.empty()) return c;  // no home directory to remember it in
  auto r = p.line("Remember this choice and don't ask again? [y/N] ");
  const std::string yes = r ? trim(*r) : std::string();
  if (yes == "y" || yes == "Y" || yes == "yes" || yes == "Yes") {
    save_auth(in.user_config, mode);
    p.say("Saved auth = " + std::string(to_string(mode)) + " in " + home_relative(in.user_config) +
          " (--ask asks again).\n");
    c.source = "your answer, saved in " + home_relative(in.user_config);
  }
  p.say("\n");
  return c;
}

}  // namespace

std::string_view to_string(AuthMode mode) { return mode == AuthMode::none ? "none" : "accounts"; }

std::optional<AuthMode> parse_auth_mode(std::string_view value) {
  if (value == "none") return AuthMode::none;
  if (value == "accounts") return AuthMode::accounts;
  return std::nullopt;
}

std::string home_relative(const fs::path &path) {
  const char *home = std::getenv("HOME");
  const std::string p = path.string();
  if (home != nullptr && *home != 0) {
    const std::string h = std::string(home) + "/";
    if (p.starts_with(h)) return "~/" + p.substr(h.size());
  }
  return p;
}

std::optional<std::pair<AuthMode, fs::path>> saved_auth(const std::vector<fs::path> &files) {
  for (const fs::path &f : files) {
    std::ifstream in(f);
    if (!in) continue;
    std::string line;
    while (std::getline(in, line)) {
      if (key_of(line) != "auth") continue;
      const std::string v = value_of(line);
      auto mode = parse_auth_mode(v);
      if (!mode)
        throw std::runtime_error(f.string() + ": auth = " + v + " (want auth = none or auth = accounts)");
      return std::make_pair(*mode, f);
    }
  }
  return std::nullopt;
}

void save_auth(const fs::path &file, AuthMode mode) {
  std::vector<std::string> lines;
  {
    std::ifstream in(file);
    std::string line;
    while (in && std::getline(in, line)) lines.push_back(line);
  }
  const std::string set = "auth = " + std::string(to_string(mode));
  bool done = false;
  std::vector<std::string> out;
  for (const std::string &l : lines) {
    if (key_of(l) != "auth") {
      out.push_back(l);
    } else if (!done) {
      out.push_back(set);
      done = true;
    }
  }
  if (!done) out.push_back(set);
  std::error_code ec;
  if (file.has_parent_path()) fs::create_directories(file.parent_path(), ec);
  const fs::path tmp = file.string() + ".tmp";
  {
    std::ofstream o(tmp, std::ios::trunc);
    for (const std::string &l : out) o << l << "\n";
    if (!o) throw std::runtime_error("can't write " + tmp.string());
  }
  fs::rename(tmp, file, ec);
  if (ec) throw std::runtime_error("can't write " + file.string() + ": " + ec.message());
}

AuthChoice choose_auth(const AuthChoiceInput &in, Prompter &prompter) {
  if (in.no_auth_flag && in.auth_flag) throw std::runtime_error("--no-auth and --auth (or --auth-file) contradict each other");
  if (in.no_auth_flag) return {AuthMode::none, "--no-auth"};
  if (in.auth_flag) return {AuthMode::accounts, "--auth"};
  if (in.ask_flag) {
    if (!in.interactive) throw std::runtime_error("--ask needs a terminal (stdin and stderr)");
    return ask(in, prompter);
  }
  if (auto saved = saved_auth(in.config_files))
    return {saved->first, "auth = " + std::string(to_string(saved->first)) + " in " + home_relative(saved->second)};
  if (in.interactive && in.no_accounts && in.no_accounts()) return ask(in, prompter);
  return {AuthMode::accounts, "the default"};
}

std::string describe(const AuthChoice &c) {
  if (c.mode == AuthMode::none) return "no sign-in (" + c.source + "; --auth to require accounts)";
  return "accounts required (" + c.source + "; --no-auth for no sign-in, on loopback only)";
}

void TerminalPrompter::say(const std::string &text) { std::cerr << text << std::flush; }

std::optional<std::string> TerminalPrompter::line(const std::string &question) {
  std::cerr << question << std::flush;
  std::string s;
  if (!std::getline(std::cin, s)) return std::nullopt;
  return s;
}

std::optional<std::string> TerminalPrompter::secret(const std::string &question) {
  std::cerr << question << std::flush;
  termios old{};
  const bool tty = ::tcgetattr(STDIN_FILENO, &old) == 0;
  if (tty) {
    termios quiet = old;
    quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    ::tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
  }
  std::string s;
  const bool ok = static_cast<bool>(std::getline(std::cin, s));
  if (tty) ::tcsetattr(STDIN_FILENO, TCSANOW, &old);
  std::cerr << "\n";
  if (!ok) return std::nullopt;
  return s;
}

}  // namespace revkit::daemon
