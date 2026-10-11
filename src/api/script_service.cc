#include "script_service.h"

#include "grpc_services.h"

#include "revkit/api/auth_policy.h"
#include "revkit/auth/crypto.h"
#include "revkit/v1/script.grpc.pb.h"

#include <google/protobuf/struct.pb.h>
#include <google/protobuf/util/json_util.h>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <thread>

extern char **environ;

namespace revkit::api {

namespace fs = std::filesystem;
namespace gp = google::protobuf;
using Clock = std::chrono::steady_clock;

// ------------------------------------------------------------- metadata --

namespace {

std::string Trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return std::string(s);
}

const std::set<std::string> &Contexts() {
  static const std::set<std::string> c = {"program", "function", "address", "selection"};
  return c;
}
const std::set<std::string> &ArgTypes() {
  static const std::set<std::string> t = {"str", "int", "float", "bool", "address", "file", "choice"};
  return t;
}

}  // namespace

ScriptMeta ParseScriptMetadata(std::string_view source, const std::string &stem) {
  static const std::regex tag_re(R"(^#\s*@(\w+)\s*(.*?)\s*$)");
  static const std::regex arg_re(R"(^(\w+)(?::(\w+))?(?:\[([^\]]*)\])?(?:=(\S*))?(?:\s+(.*))?$)");
  ScriptMeta m;
  m.name = stem;
  std::string name_tag;
  std::string untagged;  // Ghidra's convention: the comment lines are the description
  bool in_licence = false;
  std::size_t pos = 0;
  while (pos <= source.size()) {
    std::size_t nl = source.find('\n', pos);
    std::string_view raw = source.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
    pos = nl == std::string_view::npos ? source.size() + 1 : nl + 1;
    const std::string s = Trim(raw);
    if (s.empty() || s.starts_with("#!")) continue;
    if (!s.starts_with("#")) break;  // the first line of code ends the header
    if (s.starts_with("## ###")) {  // Ghidra's licence block, "## ###" ... "##"
      in_licence = true;
      continue;
    }
    if (in_licence) {
      in_licence = s != "##";
      continue;
    }
    if (s.size() > 4096) continue;  // no tag is that long (and std::regex recurses per character)
    std::smatch t;
    if (!std::regex_match(s, t, tag_re)) {
      const std::size_t body = s.find_first_not_of('#');
      const std::string text = body == std::string::npos ? std::string() : Trim(std::string_view(s).substr(body));
      if (!text.empty() && text.find("-*-") == std::string::npos && !text.starts_with("type:"))
        untagged += (untagged.empty() ? "" : " ") + text;
      continue;
    }
    std::string tag = t[1].str();
    std::transform(tag.begin(), tag.end(), tag.begin(), [](unsigned char c) { return std::tolower(c); });
    std::string value = t[2].str();
    if (value.starts_with(":")) value = Trim(std::string_view(value).substr(1));  // Ghidra's "# @category: Examples"
    if (tag == "arg") {
      std::smatch a;
      if (!std::regex_match(value, a, arg_re)) {
        m.errors.push_back("@arg '" + value + "': expected name[:type][[a|b]][=default] description");
        continue;
      }
      ScriptArgMeta arg;
      arg.name = a[1].str();
      arg.type = a[2].matched ? a[2].str() : "str";
      if (!ArgTypes().contains(arg.type)) {
        m.errors.push_back("@arg " + arg.name + ": unknown type '" + arg.type + "'");
        arg.type = "str";
      }
      if (a[3].matched) {
        const std::string rest = a[3].str();  // a view of str()'s temporary dangled
        std::string cur;
        for (char c : rest) {
          if (c == '|') {
            if (!cur.empty()) arg.choices.push_back(cur);
            cur.clear();
          } else {
            cur += c;
          }
        }
        if (!cur.empty()) arg.choices.push_back(cur);
      }
      if (!arg.choices.empty() && arg.type == "str") arg.type = "choice";
      if (a[4].matched) arg.default_value = a[4].str();
      arg.description = a[5].matched ? a[5].str() : "";
      m.args.push_back(std::move(arg));
    } else if (tag == "context") {
      if (!Contexts().contains(value)) m.errors.push_back("@context '" + value + "': one of program, function, address, selection");
      else m.context = value;
    } else if (tag == "description") {
      m.description = m.description.empty() ? value : m.description + " " + value;
    } else if (tag == "category") {
      m.category = value;
    } else if (tag == "menupath") {
      m.menupath = value;
    } else if (tag == "keybinding") {
      m.keybinding = value;
    } else if (tag == "name") {
      name_tag = value;
    }
  }
  if (!name_tag.empty()) m.name = name_tag;
  if (m.description.empty()) m.description = untagged;
  return m;
}

std::string Sha256Hex(std::string_view data) { return auth::sha256_hex(data); }

fs::path RevkitConfigDir() {
  if (const char *x = std::getenv("XDG_CONFIG_HOME"); x && *x) return fs::path(x) / "revkit";
  if (const char *h = std::getenv("HOME"); h && *h) return fs::path(h) / ".config" / "revkit";
  return fs::path(".revkit");
}

// ---------------------------------------------------------------- trust --

std::map<std::pair<std::string, std::string>, std::string> ScriptTrust::Load() {
  std::map<std::pair<std::string, std::string>, std::string> out;
  std::ifstream in(file_);
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::istringstream ls(line);
    std::string sha, id, caller;
    if (ls >> sha >> id >> caller) out[{caller, id}] = sha;
  }
  return out;
}

std::string ScriptTrust::Pinned(const std::string &caller, const std::string &script_id) {
  std::lock_guard lock(mu_);
  auto pins = Load();
  auto it = pins.find({caller, script_id});
  return it == pins.end() ? "" : it->second;
}

void ScriptTrust::Pin(const std::string &caller, const std::string &script_id, const std::string &sha256) {
  std::lock_guard lock(mu_);
  auto pins = Load();
  pins[{caller, script_id}] = sha256;
  std::error_code ec;
  fs::create_directories(file_.parent_path(), ec);
  const fs::path tmp = file_.string() + ".tmp" + std::to_string(::getpid());
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write " + tmp.string());
    out << "# Scripts confirmed to run (revkit ScriptService): sha256 script-id caller\n";
    for (const auto &[k, sha] : pins) out << sha << " " << k.second << " " << k.first << "\n";
    if (!out.flush()) throw std::runtime_error("cannot write " + tmp.string());
  }
  ::chmod(tmp.c_str(), 0600);
  fs::rename(tmp, file_, ec);
  if (ec) throw std::runtime_error("cannot write " + file_.string() + ": " + ec.message());
}

// ----------------------------------------------------------- host role --

std::optional<auth::Role> ScriptHostRole(const std::string &configured, bool all_loopback, std::string &why) {
  if (configured.empty()) {
    if (all_loopback) {
      why = "scripts run for editors and admins (every listener is on loopback; --scripts-host-role changes it)";
      return auth::Role::kEditor;
    }
    why = "scripts are off: the daemon listens beyond loopback, where a script (full Python as the daemon's user) "
          "is off unless rk-daemon --scripts-host-role editor|admin turns it on";
    return std::nullopt;
  }
  if (configured == "off") {
    why = "scripts are off (rk-daemon --scripts-host-role off)";
    return std::nullopt;
  }
  if (configured == "viewer") {
    why = "scripts and consoles run for everyone, viewers too (--scripts-host-role viewer); a viewer's can't edit";
    return auth::Role::kViewer;
  }
  if (configured == "editor") {
    why = "scripts run for editors and admins (--scripts-host-role editor)";
    return auth::Role::kEditor;
  }
  if (configured == "admin") {
    why = "scripts run for admins only (--scripts-host-role admin)";
    return auth::Role::kAdmin;
  }
  why = "--scripts-host-role must be off, viewer, editor or admin";
  return std::nullopt;
}

// ------------------------------------------------------------- processes --

namespace {

struct Spawned {
  pid_t pid = -1;
  int in = -1;   // the child's stdin (a socket: writes never raise SIGPIPE)
  int out = -1;  // its stdout
  int err = -1;  // its stderr
};

void CloseFd(int &fd) {
  if (fd >= 0) ::close(fd);
  fd = -1;
}

// Starts argv[0] (searched on PATH) in its own process group, with
// default signal handling (the daemon blocks SIGINT/SIGTERM in its
// threads), the given environment, and pipes for its stdio.
bool Spawn(const std::vector<std::string> &argv, const std::vector<std::string> &env, Spawned &s, std::string &error,
           bool capture = true) {
  int in[2] = {-1, -1}, out[2] = {-1, -1}, err[2] = {-1, -1};
  auto fail = [&](const std::string &what) {
    error = what + ": " + std::strerror(errno);
    for (int *fd : {&in[0], &in[1], &out[0], &out[1], &err[0], &err[1]}) CloseFd(*fd);
    return false;
  };
  if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, in) != 0) return fail("socketpair");
  if (::pipe2(out, O_CLOEXEC) != 0 || ::pipe2(err, O_CLOEXEC) != 0) return fail("pipe");
  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, in[1], 0);
  if (capture) {
    posix_spawn_file_actions_adddup2(&fa, out[1], 1);
    posix_spawn_file_actions_adddup2(&fa, err[1], 2);
  } else {
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
  }
  posix_spawn_file_actions_addclosefrom_np(&fa, 3);
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  sigset_t none, defaults;
  sigemptyset(&none);
  sigemptyset(&defaults);
  for (int sig : {SIGINT, SIGTERM, SIGPIPE, SIGHUP, SIGQUIT}) sigaddset(&defaults, sig);
  posix_spawnattr_setsigmask(&attr, &none);
  posix_spawnattr_setsigdefault(&attr, &defaults);
  posix_spawnattr_setpgroup(&attr, 0);
  posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP);
  std::vector<char *> av, ev;
  for (const auto &a : argv) av.push_back(const_cast<char *>(a.c_str()));
  av.push_back(nullptr);
  for (const auto &e : env) ev.push_back(const_cast<char *>(e.c_str()));
  ev.push_back(nullptr);
  pid_t pid = -1;
  int rc = posix_spawnp(&pid, av[0], &fa, &attr, av.data(), ev.data());
  posix_spawn_file_actions_destroy(&fa);
  posix_spawnattr_destroy(&attr);
  CloseFd(in[1]);
  CloseFd(out[1]);
  CloseFd(err[1]);
  if (rc != 0) {
    errno = rc;
    return fail("cannot start " + argv[0]);
  }
  s.pid = pid;
  s.in = in[0];
  s.out = out[0];
  s.err = err[0];
  return true;
}

// The environment the daemon has, with `set` replacing (or adding) names
// and `drop` removed.
std::vector<std::string> ChildEnv(const std::map<std::string, std::string> &set, const std::set<std::string> &drop = {}) {
  std::vector<std::string> out;
  for (char **e = environ; e && *e; ++e) {
    std::string_view kv(*e);
    std::string name(kv.substr(0, kv.find('=')));
    if (set.contains(name) || drop.contains(name)) continue;
    out.emplace_back(kv);
  }
  for (const auto &[k, v] : set) out.push_back(k + "=" + v);
  return out;
}

// Runs a probe to its end, at most `timeout`: its exit status, or -1 when
// it couldn't start, didn't finish or died of a signal.
int RunProbe(const std::vector<std::string> &argv, const std::vector<std::string> &env, std::chrono::seconds timeout) {
  Spawned s;
  std::string err;
  if (!Spawn(argv, env, s, err, /*capture=*/false)) return -1;
  CloseFd(s.in);
  const auto until = Clock::now() + timeout;
  int status = 0;
  while (true) {
    pid_t r = ::waitpid(s.pid, &status, WNOHANG);
    if (r == s.pid) break;
    if (r < 0) return -1;
    if (Clock::now() > until) {
      ::kill(-s.pid, SIGKILL);
      ::waitpid(s.pid, &status, 0);
      return -1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// The script API this daemon needs from the revkit SDK in the script
// Python: revkit.script.SCRIPT_API at least this. Raise both together when
// the daemon starts relying on something an older SDK lacks (1: the
// worker's stream protocol and revkit.script.console, the Python console).
// An SDK without the stamp is older than 1.
constexpr int kScriptSdkApi = 1;

// Exits 0 when the SDK is there and new enough, 3 when it is there but
// older (an SDK without the stamp or the console, a lower stamp), anything
// else when there is none.
std::string SdkProbe() {
  return "import sys\n"
         "try:\n    import revkit.script.worker\nexcept Exception:\n    sys.exit(1)\n"
         "try:\n    import revkit.script.console\n    from revkit.script import SCRIPT_API\nexcept Exception:\n    sys.exit(3)\n"
         "sys.exit(0 if SCRIPT_API >= " + std::to_string(kScriptSdkApi) + " else 3)\n";
}

std::string DataDir() {
  if (const char *x = std::getenv("XDG_DATA_HOME"); x && *x) return std::string(x) + "/revkit";
  if (const char *h = std::getenv("HOME"); h && *h) return std::string(h) + "/.local/share/revkit";
  return ".revkit";
}

}  // namespace

std::filesystem::path ScriptPythonEnv() { return fs::path(DataDir()) / "pyenv"; }

std::string FindScriptSdk(const std::vector<std::string> &sources) {
  std::error_code ec;
  for (const std::string &d : sources) {
    std::vector<fs::path> wheels;
    for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec)) {
      const std::string name = it->path().filename().string();
      if (name.starts_with("revkit-") && name.ends_with(".whl") && it->is_regular_file(ec)) wheels.push_back(it->path());
    }
    ec.clear();
    if (!wheels.empty()) return std::max_element(wheels.begin(), wheels.end())->string();
  }
  for (const std::string &d : sources)
    if (fs::is_regular_file(fs::path(d) / "pyproject.toml", ec) && fs::is_directory(fs::path(d) / "revkit", ec)) return d;
  return "";
}

std::optional<PythonChoice> FindScriptPython(const std::string &configured, const std::string &sdk_pythonpath,
                                             std::string &problem) {
  std::vector<std::string> candidates;
  if (!configured.empty()) {
    candidates.push_back(configured);
  } else {
    if (const char *p = std::getenv("REVKIT_PYTHON"); p && *p) candidates.emplace_back(p);
    const std::string pyenv = (ScriptPythonEnv() / "bin" / "python").string();
    if (fs::exists(pyenv)) candidates.push_back(pyenv);
    candidates.emplace_back("python3");
  }
  const char *existing = std::getenv("PYTHONPATH");
  std::vector<std::string> paths = {""};
  if (!sdk_pythonpath.empty() && fs::exists(fs::path(sdk_pythonpath) / "revkit" / "script" / "worker.py"))
    paths.push_back(sdk_pythonpath);
  // A Python whose SDK is older than this daemon is passed over (another
  // may have a current one); if none does, the problem names it.
  std::string stale;
  for (const std::string &extra : paths) {
    for (const std::string &py : candidates) {
      std::map<std::string, std::string> set;
      if (!extra.empty()) set["PYTHONPATH"] = extra + (existing && *existing ? std::string(":") + existing : "");
      const int rc = RunProbe({py, "-c", SdkProbe()}, ChildEnv(set), std::chrono::seconds(20));
      if (rc == 0) return PythonChoice{py, extra.empty() ? "" : set["PYTHONPATH"]};
      if (rc == 3 && stale.empty()) stale = py;
    }
  }
  if (!stale.empty()) {
    problem = "the revkit SDK in " + stale + " is older than this daemon (it lacks the Python console or script API " +
              std::to_string(kScriptSdkApi) + "). Set up Python (or run `rk-script setup`) to update it";
    return std::nullopt;
  }
  std::string tried;
  for (const auto &c : candidates) tried += (tried.empty() ? "" : ", ") + c;
  const std::string env = ScriptPythonEnv().string();
  problem = "no Python that can import revkit (tried " + tried + "). Set one up: \"Set up Python\" in the Script " +
            "Manager, or rk-script setup (python3 -m venv " + env + " && " + env +
            "/bin/pip install <share/revkit/python/revkit-*.whl, or sdk/python in a source tree>), or give rk-daemon " +
            "--script-python";
  return std::nullopt;
}

// --------------------------------------------------------------- service --

namespace {

constexpr std::size_t kMaxScriptBytes = 1u << 20;
constexpr std::size_t kMaxOutputBytes = 8u << 20;
constexpr std::size_t kMaxLineBytes = 16u << 20;
constexpr std::size_t kRecentRuns = 200;
constexpr auto kKillAfter = std::chrono::seconds(2);

bool ValidFileName(const std::string &f) {
  static const std::regex re(R"(^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,60}\.py$)");
  return std::regex_match(f, re);
}

// A project id that is safe as one path component: the per-project
// library is <project-dir>/<project>/scripts.
bool ValidProjectDir(const std::string &p) {
  static const std::regex re(R"(^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$)");
  return std::regex_match(p, re);
}

int64_t NowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string Hex(uint64_t v) {
  std::ostringstream s;
  s << "0x" << std::hex << v;
  return s.str();
}

// JSON text of a Struct (the host's protocol).
std::string ToJson(const gp::Struct &s) {
  std::string out;
  gp::util::JsonPrintOptions o;
  (void)gp::util::MessageToJsonString(s, &out, o);
  return out;
}

gp::Value Str(const std::string &v) {
  gp::Value x;
  x.set_string_value(v);
  return x;
}

std::string Text(const gp::Struct &s, const char *key) {
  auto it = s.fields().find(key);
  if (it == s.fields().end()) return "";
  const gp::Value &v = it->second;
  switch (v.kind_case()) {
    case gp::Value::kStringValue: return v.string_value();
    case gp::Value::kNumberValue: {
      double d = v.number_value();
      if (d == static_cast<double>(static_cast<int64_t>(d))) return std::to_string(static_cast<int64_t>(d));
      std::ostringstream o;
      o << d;
      return o.str();
    }
    case gp::Value::kBoolValue: return v.bool_value() ? "true" : "false";
    case gp::Value::kListValue: {
      std::string out;
      for (const auto &e : v.list_value().values()) {
        gp::Struct tmp;
        (*tmp.mutable_fields())["x"] = e;
        out += (out.empty() ? "" : ",") + Text(tmp, "x");
      }
      return out;
    }
    default: return "";
  }
}

double Number(const gp::Struct &s, const char *key) {
  auto it = s.fields().find(key);
  if (it == s.fields().end() || it->second.kind_case() != gp::Value::kNumberValue) return 0;
  return it->second.number_value();
}

bool Bool(const gp::Struct &s, const char *key) {
  auto it = s.fields().find(key);
  return it != s.fields().end() && it->second.kind_case() == gp::Value::kBoolValue && it->second.bool_value();
}

bool Has(const gp::Struct &s, const char *key) {
  auto it = s.fields().find(key);
  return it != s.fields().end() && it->second.kind_case() != gp::Value::kNullValue;
}

void Numbers(const gp::Struct &s, const char *key, gp::RepeatedField<uint64_t> *out) {
  auto it = s.fields().find(key);
  if (it == s.fields().end() || it->second.kind_case() != gp::Value::kListValue) return;
  for (const auto &v : it->second.list_value().values())
    if (v.kind_case() == gp::Value::kNumberValue) out->Add(static_cast<uint64_t>(v.number_value()));
}

std::string ReplaceAll(std::string s, const std::string &from, const std::string &to) {
  if (from.empty()) return s;
  for (std::size_t at = s.find(from); at != std::string::npos; at = s.find(from, at + to.size())) s.replace(at, from.size(), to);
  return s;
}

// A script file the service resolved from its id.
struct ScriptFile {
  std::string id;
  pb::ScriptLibrary library = pb::SCRIPT_LIBRARY_UNSPECIFIED;
  std::string project_id;
  std::string file_name;
  fs::path path;
};

// One run: the host process and the events it produces.
class Run {
 public:
  std::string id, owner, token_id;
  ScriptFile script;
  std::string sha256, name;
  std::string program_id;
  int64_t started_ms = 0;
  Spawned proc;

  // The reader thread's output.
  std::mutex mu;
  std::condition_variable cv;
  std::deque<pb::RunScriptResponse> events;
  std::optional<gp::Struct> final_event;  // the host's "result" or "error"
  bool exited = false;
  int exit_status = 0;
  std::size_t output_bytes = 0;
  bool output_truncated = false;
  std::set<uint32_t> open_prompts;

  std::atomic<bool> cancel_requested{false};
  Clock::time_point cancel_at{};
  bool killed = false;

  // A console's host (revkit.script.console): its "ready" message, and the
  // completions it answered, by request id.
  std::optional<gp::Struct> ready;
  std::map<uint32_t, gp::Struct> completions;

  std::mutex write_mu;  // the child's stdin

  bool Send(const gp::Struct &msg) {
    std::lock_guard lock(write_mu);
    if (proc.in < 0) return false;
    std::string line = ToJson(msg) + "\n";
    std::string_view rest = line;
    while (!rest.empty()) {
      ssize_t n = ::send(proc.in, rest.data(), rest.size(), MSG_NOSIGNAL);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) return false;
      rest.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
  }

  void Cancel() {
    bool expected = false;
    if (!cancel_requested.compare_exchange_strong(expected, true)) return;
    {
      std::lock_guard lock(mu);
      cancel_at = Clock::now();
    }
    gp::Struct m;
    (*m.mutable_fields())["type"] = Str("cancel");
    Send(m);
    std::lock_guard lock(mu);
    if (!exited && proc.pid > 0) ::kill(-proc.pid, SIGTERM);
  }

  // SIGKILL once kKillAfter has passed since the cancel.
  void Enforce() {
    if (!cancel_requested.load()) return;
    std::lock_guard lock(mu);
    if (!exited && !killed && proc.pid > 0 && Clock::now() - cancel_at >= kKillAfter) {
      ::kill(-proc.pid, SIGKILL);
      killed = true;
    }
  }

  void Push(pb::RunScriptResponse e) {
    std::lock_guard lock(mu);
    e.set_run_id(id);
    events.push_back(std::move(e));
    cv.notify_all();
  }

  void Output(const std::string &stream, std::string text) {
    std::lock_guard lock(mu);
    if (output_truncated) return;
    if (output_bytes + text.size() > kMaxOutputBytes) {
      output_truncated = true;
      text = "\n[output truncated: more than 8 MiB]\n";
    }
    output_bytes += text.size();
    pb::RunScriptResponse e;
    e.set_run_id(id);
    e.mutable_output()->set_stream(stream);
    e.mutable_output()->set_text(std::move(text));
    events.push_back(std::move(e));
    cv.notify_all();
  }

  // One line of the host's stdout: an event.
  void HostLine(const std::string &line) {
    gp::Struct ev;
    gp::util::JsonParseOptions o;
    o.ignore_unknown_fields = true;
    if (!gp::util::JsonStringToMessage(line, &ev, o).ok()) {
      Output("stdout", line + "\n");  // not the protocol: show it
      return;
    }
    const std::string type = Text(ev, "type");
    if (type == "output") {
      Output(Text(ev, "stream") == "stderr" ? "stderr" : "stdout", Text(ev, "text"));
    } else if (type == "progress") {
      pb::RunScriptResponse e;
      e.mutable_progress()->set_current(static_cast<int64_t>(Number(ev, "current")));
      e.mutable_progress()->set_maximum(static_cast<int64_t>(Number(ev, "maximum")));
      e.mutable_progress()->set_message(Text(ev, "message"));
      Push(std::move(e));
    } else if (type == "prompt") {
      pb::RunScriptResponse e;
      auto *p = e.mutable_prompt();
      p->set_prompt_id(static_cast<uint32_t>(Number(ev, "id")));
      p->set_kind(Text(ev, "kind"));
      p->set_name(Text(ev, "name"));
      p->set_message(Text(ev, "message"));
      if (Has(ev, "default")) {
        p->set_has_default(true);
        p->set_default_value(Text(ev, "default"));
      }
      if (auto it = ev.fields().find("choices"); it != ev.fields().end() && it->second.has_list_value())
        for (const auto &c : it->second.list_value().values()) {
          gp::Struct tmp;
          (*tmp.mutable_fields())["x"] = c;
          p->add_choices(Text(tmp, "x"));
        }
      {
        std::lock_guard lock(mu);
        open_prompts.insert(p->prompt_id());
      }
      Push(std::move(e));
    } else if (type == "result" || type == "error") {
      std::lock_guard lock(mu);
      final_event = ev;
      cv.notify_all();
    } else if (type == "done") {  // a console statement's end
      pb::RunScriptResponse e;
      auto *r = e.mutable_console_result();
      r->set_more(Bool(ev, "more"));
      r->set_status(Text(ev, "status"));
      Numbers(ev, "revisions", r->mutable_revisions());
      Numbers(ev, "seqs", r->mutable_seqs());
      r->set_discarded(static_cast<uint32_t>(Number(ev, "discarded")));
      r->set_seconds(Number(ev, "seconds"));
      r->set_error(Text(ev, "error"));
      Push(std::move(e));
    } else if (type == "ready") {
      std::lock_guard lock(mu);
      ready = ev;
      cv.notify_all();
    } else if (type == "completions") {
      std::lock_guard lock(mu);
      completions[static_cast<uint32_t>(Number(ev, "id"))] = ev;
      cv.notify_all();
    }
    // "start" and anything newer: nothing to forward.
  }

  // Reads the host's stdout and stderr until both end, then reaps it.
  void ReadLoop() {
    std::string out_buf, err_buf;
    bool out_open = true, err_open = true;
    char chunk[65536];
    int status = 0;
    bool reaped = false;
    Clock::time_point drain_until{};
    while (out_open || err_open) {
      // A host that has exited but left a process of its own holding its
      // pipes: what is left is read for half a second, then the run ends.
      if (!reaped && ::waitpid(proc.pid, &status, WNOHANG) == proc.pid) {
        reaped = true;
        drain_until = Clock::now() + std::chrono::milliseconds(500);
      }
      if (reaped && Clock::now() > drain_until) break;
      pollfd fds[2];
      int n = 0;
      if (out_open) fds[n++] = {proc.out, POLLIN, 0};
      if (err_open) fds[n++] = {proc.err, POLLIN, 0};
      int r = ::poll(fds, n, reaped ? 50 : 200);
      if (r < 0 && errno == EINTR) continue;
      if (r < 0) break;
      for (int i = 0; i < n; ++i) {
        if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
        const bool is_out = fds[i].fd == proc.out;
        ssize_t got = ::read(fds[i].fd, chunk, sizeof chunk);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
          (is_out ? out_open : err_open) = false;
          continue;
        }
        if (is_out) {
          out_buf.append(chunk, static_cast<std::size_t>(got));
          for (std::size_t nl; (nl = out_buf.find('\n')) != std::string::npos;) {
            std::string line = out_buf.substr(0, nl);
            out_buf.erase(0, nl + 1);
            if (!line.empty()) HostLine(line);
          }
          if (out_buf.size() > kMaxLineBytes) out_buf.clear();
        } else {
          // stderr: what Python itself says (import errors, warnings), by line.
          err_buf.append(chunk, static_cast<std::size_t>(got));
          std::size_t nl = err_buf.rfind('\n');
          if (nl != std::string::npos) {
            Output("stderr", err_buf.substr(0, nl + 1));
            err_buf.erase(0, nl + 1);
          } else if (err_buf.size() > 65536) {
            Output("stderr", err_buf);
            err_buf.clear();
          }
        }
      }
    }
    if (!out_buf.empty()) HostLine(out_buf);
    if (!err_buf.empty()) Output("stderr", err_buf);
    if (!reaped) ::waitpid(proc.pid, &status, 0);
    std::lock_guard lock(mu);
    exited = true;
    exit_status = status;
    cv.notify_all();
  }
};

// A caller's Python console of one program: a long-lived host
// (revkit.script.console) that runs statements as they come.
struct Console {
  std::string owner, program_id;
  std::shared_ptr<Run> run;
  std::thread reader;
  bool read_only = false;
  bool ghidra = false;
  std::string python_version, engine;
  // Guarded by the service's consoles_mu_.
  bool busy = false;
  bool closing = false;
  Clock::time_point last_used{}, close_at{};
  uint32_t next_id = 0;
  std::atomic<uint32_t> next_completion{0};

  bool Dead() {
    std::lock_guard lock(run->mu);
    return run->exited;
  }
  // SIGINT to the host's group: KeyboardInterrupt in the statement.
  void Interrupt() {
    std::lock_guard lock(run->mu);
    if (!run->exited && run->proc.pid > 0) ::kill(-run->proc.pid, SIGINT);
  }
  // Asks the host to quit; the reaper kills it 2 s later if it hasn't.
  void Close() {
    gp::Struct m;
    (*m.mutable_fields())["type"] = Str("quit");
    run->Send(m);
    std::lock_guard lock(run->mu);
    if (!run->exited && run->proc.pid > 0) ::kill(-run->proc.pid, SIGTERM);
  }
  void Kill() {
    std::lock_guard lock(run->mu);
    if (!run->exited && run->proc.pid > 0) ::kill(-run->proc.pid, SIGKILL);
  }
};

constexpr std::size_t kHistoryEntries = 1000;

class ScriptServiceImpl final : public pb::ScriptService::Service {
 public:
  ScriptServiceImpl(std::shared_ptr<AuthGate> gate, ScriptServiceOptions options, std::shared_ptr<ScriptHostTarget> target,
                    std::shared_ptr<std::atomic<bool>> stopping)
      : gate_(std::move(gate)), opt_(std::move(options)), target_(std::move(target)), stopping_(std::move(stopping)),
        trust_(opt_.host.trust_file.empty() ? RevkitConfigDir() / "trusted-scripts" : fs::path(opt_.host.trust_file)) {
    host_role_ = ScriptHostRole(opt_.host.role, opt_.all_loopback, host_why_);
    user_dir_ = opt_.host.user_dir.empty() ? RevkitConfigDir() / "scripts" : fs::path(opt_.host.user_dir);
    reaper_ = std::thread([this] { Reap(); });
  }

  ~ScriptServiceImpl() override {
    {
      std::lock_guard lock(consoles_mu_);
      reaper_stop_ = true;
    }
    reaper_cv_.notify_all();
    if (reaper_.joinable()) reaper_.join();
    // Shutdown: no handler is left, but be sure no host outlives us.
    std::vector<std::shared_ptr<Console>> consoles;
    {
      std::lock_guard lock(consoles_mu_);
      for (auto &[_, c] : consoles_) consoles.push_back(c);
      consoles_.clear();
    }
    for (auto &c : consoles) {
      c->Kill();
      if (c->reader.joinable()) c->reader.join();
      Revoke(*c->run);
    }
    std::lock_guard lock(runs_mu_);
    for (auto &[_, r] : active_) {
      std::lock_guard rl(r->mu);
      if (!r->exited && r->proc.pid > 0) ::kill(-r->proc.pid, SIGKILL);
    }
  }

  grpc::Status ListScripts(grpc::ServerContext *ctx, const pb::ListScriptsRequest *req,
                           pb::ListScriptsResponse *resp) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "ListScripts", *req, who); !st.ok()) return st;
    if (!req->project_id().empty() && !who->may_use_project(req->project_id()))
      return {grpc::StatusCode::PERMISSION_DENIED, who->display() + " may not use project \"" + req->project_id() + "\""};
    std::string why;
    const bool enabled = MayHost(*who, why);
    resp->set_host_enabled(enabled);
    if (!enabled) resp->set_host_disabled_reason(why);
    if (enabled) {
      std::string problem;
      if (auto py = Python(problem)) resp->set_python(py->python);
      else resp->set_python_problem(problem);
    }
    std::vector<pb::ScriptInfo> all;
    for (const ScriptFile &f : Scan(req->project_id())) {
      std::string source;
      if (!ReadSource(f.path, source)) continue;
      all.push_back(Info(f, source, *who, enabled));
    }
    std::sort(all.begin(), all.end(), [](const auto &a, const auto &b) {
      return std::tie(a.category(), a.name(), a.script_id()) < std::tie(b.category(), b.name(), b.script_id());
    });
    for (auto &s : all) *resp->add_scripts() = std::move(s);
    return grpc::Status::OK;
  }

  grpc::Status GetScript(grpc::ServerContext *ctx, const pb::GetScriptRequest *req, pb::GetScriptResponse *resp) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "GetScript", *req, who); !st.ok()) return st;
    ScriptFile f;
    if (auto st = Resolve(req->script_id(), *who, f); !st.ok()) return st;
    std::string source;
    if (!ReadSource(f.path, source)) return {grpc::StatusCode::NOT_FOUND, "no script " + req->script_id()};
    std::string why;
    *resp->mutable_script() = Info(f, source, *who, MayHost(*who, why));
    resp->set_source(std::move(source));
    return grpc::Status::OK;
  }

  grpc::Status SaveScript(grpc::ServerContext *ctx, const pb::SaveScriptRequest *req, pb::SaveScriptResponse *resp) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "SaveScript", *req, who); !st.ok()) return st;
    std::string why;
    if (!MayHost(*who, why)) return {grpc::StatusCode::PERMISSION_DENIED, why};
    if (!ValidFileName(req->file_name()))
      return {grpc::StatusCode::INVALID_ARGUMENT,
              "file_name \"" + req->file_name() + "\": letters, digits, _ . - ending in .py, at most 64 characters"};
    if (req->source().size() > kMaxScriptBytes) return {grpc::StatusCode::INVALID_ARGUMENT, "a script is at most 1 MiB"};
    std::string id;
    if (req->library() == pb::SCRIPT_LIBRARY_USER) {
      if (!who->projects.empty())
        return {grpc::StatusCode::PERMISSION_DENIED,
                who->display() + " is limited to some projects: save to a project's library instead"};
      id = "user/" + req->file_name();
    } else if (req->library() == pb::SCRIPT_LIBRARY_PROJECT) {
      if (!ValidProjectDir(req->project_id()))
        return {grpc::StatusCode::INVALID_ARGUMENT, "project_id \"" + req->project_id() + "\" is not a project"};
      if (!who->may_use_project(req->project_id()))
        return {grpc::StatusCode::PERMISSION_DENIED, who->display() + " may not use project \"" + req->project_id() + "\""};
      id = "project/" + req->project_id() + "/" + req->file_name();
    } else {
      return {grpc::StatusCode::INVALID_ARGUMENT, "library: SCRIPT_LIBRARY_USER or SCRIPT_LIBRARY_PROJECT (shipped scripts are read-only)"};
    }
    ScriptFile f;
    if (auto st = Resolve(id, *who, f); !st.ok()) return st;
    std::lock_guard lock(save_mu_);
    std::string current;
    const bool exists = ReadSource(f.path, current);
    if (exists && req->expected_sha256().empty())
      return {grpc::StatusCode::ALREADY_EXISTS, id + " exists; send expected_sha256 (from GetScript) to replace it"};
    if (exists && req->expected_sha256() != Sha256Hex(current))
      return {grpc::StatusCode::ABORTED, id + " changed since you read it; read it again (GetScript) and merge"};
    if (!exists && !req->expected_sha256().empty())
      return {grpc::StatusCode::NOT_FOUND, id + " no longer exists"};
    std::error_code ec;
    fs::create_directories(f.path.parent_path(), ec);
    if (ec) return {grpc::StatusCode::FAILED_PRECONDITION, "cannot create " + f.path.parent_path().string() + ": " + ec.message()};
    const fs::path tmp = f.path.string() + ".saving";
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      out << req->source();
      if (!out.flush()) return {grpc::StatusCode::INTERNAL, "cannot write " + tmp.string()};
    }
    fs::rename(tmp, f.path, ec);
    if (ec) return {grpc::StatusCode::INTERNAL, "cannot write " + f.path.string() + ": " + ec.message()};
    try {
      trust_.Pin(who->display(), id, Sha256Hex(req->source()));
    } catch (const std::exception &e) {
      return {grpc::StatusCode::INTERNAL, e.what()};
    }
    *resp->mutable_script() = Info(f, req->source(), *who, true);
    return grpc::Status::OK;
  }

  grpc::Status RunScript(grpc::ServerContext *ctx, const pb::RunScriptRequest *req,
                         grpc::ServerWriter<pb::RunScriptResponse> *writer) override {
    try {
      return Execute(ctx, req, writer);
    } catch (const std::exception &e) {
      return {grpc::StatusCode::INTERNAL, std::string("script service: ") + e.what()};
    }
  }

  grpc::Status Execute(grpc::ServerContext *ctx, const pb::RunScriptRequest *req,
                       grpc::ServerWriter<pb::RunScriptResponse> *writer) {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "RunScript", *req, who); !st.ok()) return st;
    std::string why;
    if (!MayHost(*who, why)) return {grpc::StatusCode::PERMISSION_DENIED, why};
    if (who->token_id.starts_with("run:"))
      return {grpc::StatusCode::PERMISSION_DENIED, "a script the daemon runs can't start scripts itself"};
    if (req->program_id().empty()) return {grpc::StatusCode::INVALID_ARGUMENT, "program_id is required"};
    if (req->interactive()) return Interactive(ctx, *req, writer, *who);
    ScriptFile f;
    if (auto st = Resolve(req->script_id(), *who, f); !st.ok()) return st;
    std::string source;
    if (!ReadSource(f.path, source)) return {grpc::StatusCode::NOT_FOUND, "no script " + req->script_id()};
    const std::string sha = Sha256Hex(source);
    const std::string caller = who->display();

    // Trust: a script's text runs only once the caller has seen it.
    if (f.library != pb::SCRIPT_LIBRARY_SHIPPED) {
      const std::string pinned = trust_.Pinned(caller, f.id);
      if (pinned != sha) {
        if (req->confirm_sha256() != sha) {
          pb::RunScriptResponse e;
          auto *t = e.mutable_trust_required();
          *t->mutable_script() = Info(f, source, *who, true);
          t->set_source(source);
          t->set_reason(pinned.empty() ? "unseen" : "changed");
          t->set_previous_sha256(pinned);
          writer->Write(e);
          return grpc::Status::OK;
        }
        try {
          trust_.Pin(caller, f.id, sha);
        } catch (const std::exception &e) {
          return {grpc::StatusCode::INTERNAL, e.what()};
        }
      }
    }

    std::string problem;
    auto py = Python(problem);
    if (!py) return {grpc::StatusCode::FAILED_PRECONDITION, problem};
    std::string grpc_target, fingerprint;
    {
      std::lock_guard lock(target_->mu);
      grpc_target = target_->grpc_target;
      fingerprint = target_->tls_fingerprint;
    }
    if (grpc_target.empty())
      return {grpc::StatusCode::FAILED_PRECONDITION, "scripts need the daemon's gRPC listener (rk-daemon without --no-grpc)"};

    auto run = std::make_shared<Run>();
    run->id = "run-" + auth::hex(auth::random_bytes(8));
    run->owner = caller;
    run->script = f;
    run->sha256 = sha;
    run->name = ParseScriptMetadata(source, fs::path(f.file_name).stem().string()).name;
    run->program_id = req->program_id();
    run->started_ms = NowMs();
    {
      std::lock_guard lock(runs_mu_);
      if (active_.size() >= opt_.host.max_runs)
        return {grpc::StatusCode::RESOURCE_EXHAUSTED,
                std::to_string(active_.size()) + " scripts are running; wait for one to end or cancel one"};
      active_[run->id] = run;
    }
    struct Unregister {
      ScriptServiceImpl *self;
      std::shared_ptr<Run> run;
      ~Unregister() {
        if (!run->token_id.empty() && self->gate_->store()) self->gate_->store()->revoke_run_token(run->token_id);
        std::lock_guard lock(self->runs_mu_);
        self->active_.erase(run->id);
      }
    } unregister{this, run};

    // The run token: the caller's identity, for this run only.
    std::map<std::string, std::string> env = {{"PYTHONUNBUFFERED", "1"}, {"PYTHONIOENCODING", "utf-8"}};
    if (!py->pythonpath.empty()) env["PYTHONPATH"] = py->pythonpath;
    if (gate_->store()) {
      try {
        env["RK_TOKEN"] = gate_->store()->mint_run_token(*who, 48 * 3600, run->token_id);
      } catch (const std::exception &e) {
        return {grpc::StatusCode::PERMISSION_DENIED, std::string("cannot run scripts as ") + caller + ": " + e.what()};
      }
    }
    if (!fingerprint.empty()) env["RK_TLS_FINGERPRINT"] = fingerprint;
    std::vector<std::string> argv = {py->python, "-u", "-m", "revkit.script.worker", "--stream", "--no-analysis-wait",
                                     "--daemon", grpc_target, "--program", req->program_id(),
                                     "--script", f.path.string(), "--run-id", run->id,
                                     "--context", ContextJson(req->context(), false)};
    if (!req->reason().empty()) argv.insert(argv.end(), {"--reason", req->reason()});
    for (const auto &[k, v] : req->args()) argv.insert(argv.end(), {"--arg", k + "=" + v});
    for (const std::string &dir : Libraries(req->program_id())) argv.insert(argv.end(), {"--lib", dir});
    if (who->role == auth::Role::kViewer) argv.push_back("--read-only");
    std::string error;
    if (!Spawn(argv, ChildEnv(env, {"RK_TOKEN", "RK_TLS_FINGERPRINT", "RK_TLS_CA", "RK_TLS", "RK_GRPC"}), run->proc, error))
      return {grpc::StatusCode::INTERNAL, error};
    std::thread reader([run] { run->ReadLoop(); });

    {
      pb::RunScriptResponse e;
      e.set_run_id(run->id);
      auto *s = e.mutable_started();
      s->set_run_id(run->id);
      *s->mutable_script() = Info(f, source, *who, true);
      s->set_program_id(req->program_id());
      s->set_started_at_ms(run->started_ms);
      writer->Write(e);
    }
    Remember(*run, "running");

    bool client_gone = false;
    while (true) {
      if (!client_gone && (ctx->IsCancelled() || stopping_->load())) {
        client_gone = ctx->IsCancelled();
        run->Cancel();
      }
      run->Enforce();
      std::vector<pb::RunScriptResponse> batch;
      bool done = false;
      {
        std::unique_lock lock(run->mu);
        run->cv.wait_for(lock, std::chrono::milliseconds(100), [&] { return !run->events.empty() || run->exited; });
        while (!run->events.empty() && batch.size() < 256) {
          batch.push_back(std::move(run->events.front()));
          run->events.pop_front();
        }
        done = run->exited && run->events.empty();
      }
      // Adjacent output of one stream goes as one message.
      for (std::size_t i = 0; i < batch.size(); ++i) {
        pb::RunScriptResponse &e = batch[i];
        while (e.has_output() && i + 1 < batch.size() && batch[i + 1].has_output() &&
               batch[i + 1].output().stream() == e.output().stream() && e.output().text().size() < 65536) {
          e.mutable_output()->mutable_text()->append(batch[i + 1].output().text());
          ++i;
        }
        if (!client_gone && !writer->Write(e)) {
          client_gone = true;
          run->Cancel();
        }
      }
      if (done) break;
    }
    reader.join();
    CloseFd(run->proc.in);
    CloseFd(run->proc.out);
    CloseFd(run->proc.err);

    pb::RunScriptResponse last = Final(*run);
    Remember(*run, last.has_result() ? last.result().status() : last.error().result().status(), &last);
    if (!client_gone) writer->Write(last);
    return grpc::Status::OK;
  }


  // ------------------------------------------------------------ console --

  // RunScript{interactive}: `input` in the caller's console of the program,
  // started (again) when there is none or it died.
  grpc::Status Interactive(grpc::ServerContext *ctx, const pb::RunScriptRequest &req,
                           grpc::ServerWriter<pb::RunScriptResponse> *writer, const auth::Principal &who) {
    const std::string caller = who.display();
    const auto key = std::make_pair(caller, req.program_id());
    std::shared_ptr<Console> console;
    std::shared_ptr<Console> dead;
    bool started_now = false;
    {
      std::lock_guard lock(consoles_mu_);
      auto it = consoles_.find(key);
      if (it != consoles_.end()) {
        if (it->second->busy)
          return {grpc::StatusCode::FAILED_PRECONDITION,
                  "the console is running a statement: wait for it, or interrupt it (CancelScript with interrupt)"};
        if (it->second->closing || it->second->Dead()) {
          dead = it->second;
          consoles_.erase(it);
        } else {
          console = it->second;
        }
      }
      if (!console) {
        if (consoles_.size() >= opt_.host.max_consoles)
          return {grpc::StatusCode::RESOURCE_EXHAUSTED,
                  std::to_string(consoles_.size()) + " consoles are open on this daemon; close one (CancelScript)"};
        console = std::make_shared<Console>();
        console->owner = caller;
        console->program_id = req.program_id();
        console->run = std::make_shared<Run>();
        console->run->id = "console-" + auth::hex(auth::random_bytes(8));
        console->run->owner = caller;
        console->run->program_id = req.program_id();
        console->run->name = "console";
        console->run->started_ms = NowMs();
        console->read_only = who.role == auth::Role::kViewer;
        console->ghidra = req.ghidra_names();
        consoles_[key] = console;
        started_now = true;
      }
      console->busy = true;
      console->last_used = Clock::now();
    }
    if (dead) Finish(dead);
    struct Release {
      ScriptServiceImpl *self;
      std::shared_ptr<Console> c;
      ~Release() {
        std::lock_guard lock(self->consoles_mu_);
        c->busy = false;
        c->last_used = Clock::now();
      }
    } release{this, console};
    Run &run = *console->run;

    if (started_now) {
      if (auto st = StartConsole(*console, req, who); !st.ok()) {
        std::shared_ptr<Console> failed;
        {
          std::lock_guard lock(consoles_mu_);
          if (auto it = consoles_.find(key); it != consoles_.end() && it->second == console) {
            failed = it->second;
            consoles_.erase(it);
          }
        }
        if (failed) {
          failed->Kill();
          Finish(failed);
        }
        if (st.error_code() == grpc::StatusCode::UNAVAILABLE) {
          // The host died before it was ready: show what it said.
          pb::RunScriptResponse e;
          e.set_run_id(run.id);
          std::string said;
          {
            std::lock_guard lock(run.mu);
            for (const auto &ev : run.events)
              if (ev.has_output()) said += ev.output().text();
          }
          auto *err = e.mutable_error();
          err->mutable_result()->set_status("error");
          err->set_message(st.error_message() + (said.empty() ? "" : ": " + said));
          writer->Write(e);
          return grpc::Status::OK;
        }
        return st;
      }
    } else if (console->ghidra != req.ghidra_names()) {
      console->ghidra = req.ghidra_names();
    }

    {
      pb::RunScriptResponse e;
      e.set_run_id(run.id);
      auto *st = e.mutable_started();
      st->set_run_id(run.id);
      st->set_program_id(console->program_id);
      st->set_started_at_ms(run.started_ms);
      st->set_console_started(started_now);
      for (auto &h : History(caller)) st->add_history(std::move(h));
      st->set_read_only(console->read_only);
      st->set_python_version(console->python_version);
      st->set_completion_engine(console->engine);
      writer->Write(e);
    }
    if (req.input().find_first_not_of(" \t\r\n") == std::string::npos && req.input().find('\n') == std::string::npos) {
      // Only opening it (or an empty line): nothing to run, but the
      // context and the Ghidra names still apply.
      SendExec(*console, req, ++console->next_id, "");
    } else {
      {
        std::lock_guard lock(run.mu);
        run.output_bytes = 0;
        run.output_truncated = false;
      }
      SendExec(*console, req, ++console->next_id, req.input());
    }

    bool client_gone = false, interrupted = false, got_result = false;
    Clock::time_point gone_at{};
    while (true) {
      if (!client_gone && (ctx->IsCancelled() || stopping_->load())) {
        client_gone = true;
        gone_at = Clock::now();
      }
      if (client_gone && !interrupted) {
        interrupted = true;
        console->Interrupt();
      }
      // A statement that ignores the interrupt with nobody waiting for it:
      // the console goes.
      if (client_gone && Clock::now() - gone_at > std::chrono::seconds(10)) {
        console->Kill();
        gone_at = Clock::now() + std::chrono::hours(1);
      }
      std::vector<pb::RunScriptResponse> batch;
      bool exited = false;
      {
        std::unique_lock lock(run.mu);
        run.cv.wait_for(lock, std::chrono::milliseconds(100), [&] { return !run.events.empty() || run.exited; });
        while (!run.events.empty() && batch.size() < 256) {
          batch.push_back(std::move(run.events.front()));
          run.events.pop_front();
        }
        exited = run.exited && run.events.empty();
      }
      for (std::size_t i = 0; i < batch.size(); ++i) {
        pb::RunScriptResponse &e = batch[i];
        while (e.has_output() && i + 1 < batch.size() && batch[i + 1].has_output() &&
               batch[i + 1].output().stream() == e.output().stream() && e.output().text().size() < 65536) {
          e.mutable_output()->mutable_text()->append(batch[i + 1].output().text());
          ++i;
        }
        if (e.has_console_result()) {
          got_result = true;
          // The history: what ran (an open block isn't a statement yet).
          if (!e.console_result().more()) AddHistory(caller, req.input());
          if (e.console_result().status() == "exit") {  // exit(): the host ends; the next call starts another
            std::lock_guard lock(consoles_mu_);
            console->closing = true;
            console->close_at = Clock::now();
          }
        }
        if (!client_gone && !writer->Write(e)) {
          client_gone = true;
          gone_at = Clock::now();
        }
        if (got_result) break;
      }
      if (got_result) {
        // What came after the result (a background thread's output) waits
        // for the next statement.
        break;
      }
      if (exited) break;
    }
    if (!got_result) {
      int status = 0;
      {
        std::lock_guard lock(run.mu);
        status = run.exit_status;
      }
      pb::RunScriptResponse e;
      e.set_run_id(run.id);
      auto *err = e.mutable_error();
      err->mutable_result()->set_status("error");
      err->mutable_result()->set_exit_code(WIFEXITED(status) ? WEXITSTATUS(status) : -1);
      err->set_message(std::string("the console's Python ") +
                       (WIFSIGNALED(status) ? "died with signal " + std::to_string(WTERMSIG(status))
                                            : "exited with status " + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1)) +
                       "; the next statement starts a new console");
      if (!client_gone) writer->Write(e);
    }
    return grpc::Status::OK;
  }

  // Spawns the console's host and waits for its "ready" (UNAVAILABLE when
  // it ended first).
  grpc::Status StartConsole(Console &c, const pb::RunScriptRequest &req, const auth::Principal &who) {
    std::string problem;
    auto py = Python(problem);
    if (!py) return {grpc::StatusCode::FAILED_PRECONDITION, problem};
    std::string grpc_target, fingerprint;
    {
      std::lock_guard lock(target_->mu);
      grpc_target = target_->grpc_target;
      fingerprint = target_->tls_fingerprint;
    }
    if (grpc_target.empty())
      return {grpc::StatusCode::FAILED_PRECONDITION, "the console needs the daemon's gRPC listener (rk-daemon without --no-grpc)"};
    Run &run = *c.run;
    std::map<std::string, std::string> env = {{"PYTHONUNBUFFERED", "1"}, {"PYTHONIOENCODING", "utf-8"}};
    if (!py->pythonpath.empty()) env["PYTHONPATH"] = py->pythonpath;
    if (gate_->store()) {
      try {
        env["RK_TOKEN"] = gate_->store()->mint_run_token(who, 48 * 3600, run.token_id);
      } catch (const std::exception &e) {
        return {grpc::StatusCode::PERMISSION_DENIED, std::string("cannot open a console as ") + c.owner + ": " + e.what()};
      }
    }
    if (!fingerprint.empty()) env["RK_TLS_FINGERPRINT"] = fingerprint;
    std::vector<std::string> argv = {py->python, "-u", "-m", "revkit.script.console", "--daemon", grpc_target,
                                     "--program", c.program_id, "--run-id", run.id,
                                     "--context", ContextJson(req.context(), false)};
    if (c.read_only) argv.push_back("--read-only");
    if (c.ghidra) argv.push_back("--ghidra");
    for (const std::string &dir : Libraries(c.program_id)) argv.insert(argv.end(), {"--lib", dir});
    std::string error;
    if (!Spawn(argv, ChildEnv(env, {"RK_TOKEN", "RK_TLS_FINGERPRINT", "RK_TLS_CA", "RK_TLS", "RK_GRPC"}), run.proc, error))
      return {grpc::StatusCode::INTERNAL, error};
    c.reader = std::thread([r = c.run] { r->ReadLoop(); });
    std::unique_lock lock(run.mu);
    run.cv.wait_for(lock, std::chrono::seconds(60), [&] { return run.ready.has_value() || run.exited; });
    if (!run.ready) {
      if (!run.exited && run.proc.pid > 0) ::kill(-run.proc.pid, SIGKILL);
      return {grpc::StatusCode::UNAVAILABLE, run.exited ? "the console's Python ended before it was ready"
                                                         : "the console's Python wasn't ready in 60 s"};
    }
    c.python_version = Text(*run.ready, "python");
    c.engine = Text(*run.ready, "engine");
    return grpc::Status::OK;
  }

  void SendExec(Console &c, const pb::RunScriptRequest &req, uint32_t id, const std::string &source) {
    gp::Struct m;
    auto &f = *m.mutable_fields();
    f["type"] = Str("exec");
    f["id"].set_number_value(id);
    f["source"] = Str(source);
    f["ghidra"].set_bool_value(c.ghidra);
    if (req.has_context()) {
      gp::Struct ctx;
      gp::util::JsonParseOptions o;
      if (gp::util::JsonStringToMessage(ContextJson(req.context(), false), &ctx, o).ok()) *f["context"].mutable_struct_value() = ctx;
    }
    c.run->Send(m);
  }

  // A console that ended: its reader joined, its token revoked.
  void Finish(const std::shared_ptr<Console> &c) {
    if (c->reader.joinable()) c->reader.join();
    Revoke(*c->run);
  }

  void Revoke(Run &run) {
    if (!run.token_id.empty() && gate_->store()) gate_->store()->revoke_run_token(run.token_id);
    run.token_id.clear();
  }

  // Closes idle consoles, kills those that didn't quit, and finishes the
  // ended ones.
  void Reap() {
    std::unique_lock lock(consoles_mu_);
    while (!reaper_stop_) {
      reaper_cv_.wait_for(lock, std::chrono::milliseconds(500));
      if (reaper_stop_) break;
      std::vector<std::shared_ptr<Console>> ended;
      const auto now = Clock::now();
      for (auto it = consoles_.begin(); it != consoles_.end();) {
        auto &c = it->second;
        if (c->Dead() && !c->busy) {
          ended.push_back(c);
          it = consoles_.erase(it);
          continue;
        }
        const bool idle = opt_.host.console_idle_seconds > 0 && !c->busy &&
                          now - c->last_used > std::chrono::seconds(opt_.host.console_idle_seconds);
        if (!c->closing && (idle || stopping_->load())) {
          c->closing = true;
          c->close_at = now;
          c->Close();
        } else if (c->closing && now - c->close_at > kKillAfter) {
          c->Kill();
        }
        ++it;
      }
      lock.unlock();
      for (auto &c : ended) Finish(c);
      lock.lock();
    }
  }

  // The console of `caller` on `program_id`, if one is live.
  std::shared_ptr<Console> FindConsole(const std::string &caller, const std::string &program_id) {
    std::lock_guard lock(consoles_mu_);
    auto it = consoles_.find({caller, program_id});
    if (it == consoles_.end() || it->second->closing || it->second->Dead()) return nullptr;
    return it->second;
  }

  // The console with this run id (an admin may reach anyone's).
  std::shared_ptr<Console> ConsoleById(const std::string &run_id, const auth::Principal &who) {
    std::lock_guard lock(consoles_mu_);
    for (auto &[_, c] : consoles_)
      if (c->run->id == run_id && (c->owner == who.display() || who.role == auth::Role::kAdmin)) return c;
    return nullptr;
  }

  grpc::Status CompleteConsole(grpc::ServerContext *ctx, const pb::CompleteConsoleRequest *req,
                               pb::CompleteConsoleResponse *resp) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "CompleteConsole", *req, who); !st.ok()) return st;
    std::string why;
    if (!MayHost(*who, why)) return {grpc::StatusCode::PERMISSION_DENIED, why};
    if (req->text().size() > (1u << 20)) return {grpc::StatusCode::INVALID_ARGUMENT, "text: at most 1 MiB"};
    auto c = FindConsole(who->display(), req->program_id());
    if (!c)
      return {grpc::StatusCode::FAILED_PRECONDITION,
              "no console is open on " + req->program_id() + ": open one first (RunScript with interactive)"};
    const uint32_t id = ++c->next_completion;
    gp::Struct m;
    auto &f = *m.mutable_fields();
    f["type"] = Str("complete");
    f["id"].set_number_value(id);
    f["text"] = Str(req->text());
    f["limit"].set_number_value(req->limit() ? std::min<uint32_t>(req->limit(), 2000) : 200);
    if (!c->run->Send(m)) return {grpc::StatusCode::FAILED_PRECONDITION, "the console has ended"};
    Run &run = *c->run;
    std::unique_lock lock(run.mu);
    const auto until = Clock::now() + std::chrono::seconds(10);
    while (!run.completions.contains(id) && !run.exited && Clock::now() < until && !ctx->IsCancelled())
      run.cv.wait_for(lock, std::chrono::milliseconds(100));
    auto it = run.completions.find(id);
    if (it == run.completions.end()) {
      return {grpc::StatusCode::DEADLINE_EXCEEDED, run.exited ? "the console has ended" : "the console didn't answer in 10 s"};
    }
    gp::Struct ev = std::move(it->second);
    run.completions.erase(it);
    lock.unlock();
    resp->set_prefix_length(static_cast<uint32_t>(Number(ev, "prefix_length")));
    resp->set_engine(Text(ev, "engine"));
    if (auto l = ev.fields().find("completions"); l != ev.fields().end() && l->second.has_list_value())
      for (const auto &v : l->second.list_value().values()) {
        if (!v.has_struct_value()) continue;
        const gp::Struct &x = v.struct_value();
        auto *out = resp->add_completions();
        out->set_text(Text(x, "text"));
        out->set_kind(Text(x, "kind"));
        out->set_signature(Text(x, "signature"));
        out->set_doc(Text(x, "doc"));
      }
    return grpc::Status::OK;
  }

  // ------------------------------------------------------------ history --

  fs::path HistoryFile(const std::string &caller) const {
    std::string safe;
    for (char ch : caller) safe += (std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_' || ch == '.') ? ch : '_';
    if (safe.size() > 64) safe.resize(64);
    return RevkitConfigDir() / "console-history" / (safe + "-" + Sha256Hex(caller).substr(0, 8) + ".json");
  }

  std::vector<std::string> History(const std::string &caller) {
    std::lock_guard lock(history_mu_);
    std::vector<std::string> out;
    std::ifstream in(HistoryFile(caller), std::ios::binary);
    if (!in) return out;
    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string text = buf.str();
    gp::ListValue list;
    gp::util::JsonParseOptions o;
    if (!gp::util::JsonStringToMessage(text, &list, o).ok()) return out;
    for (const auto &v : list.values())
      if (v.kind_case() == gp::Value::kStringValue) out.push_back(v.string_value());
    return out;
  }

  void AddHistory(const std::string &caller, const std::string &input) {
    std::string entry = input;
    while (!entry.empty() && (entry.back() == '\n' || entry.back() == '\r')) entry.pop_back();
    if (entry.find_first_not_of(" \t\n") == std::string::npos || entry.size() > 16384) return;
    std::vector<std::string> h = History(caller);
    std::lock_guard lock(history_mu_);
    if (!h.empty() && h.back() == entry) return;
    h.push_back(entry);
    if (h.size() > kHistoryEntries) h.erase(h.begin(), h.begin() + static_cast<std::ptrdiff_t>(h.size() - kHistoryEntries));
    gp::ListValue list;
    for (const auto &e : h) *list.add_values() = Str(e);
    std::string json;
    gp::util::JsonPrintOptions po;
    if (!gp::util::MessageToJsonString(list, &json, po).ok()) return;
    const fs::path file = HistoryFile(caller);
    std::error_code ec;
    fs::create_directories(file.parent_path(), ec);
    ::chmod(file.parent_path().c_str(), 0700);
    const fs::path tmp = file.string() + ".tmp" + std::to_string(::getpid());
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      out << json;
      if (!out.flush()) return;
    }
    ::chmod(tmp.c_str(), 0600);
    fs::rename(tmp, file, ec);
  }

  // The libraries a run's imports look in: the per-user one, then the
  // program's project's (with --project-dir).
  std::vector<std::string> Libraries(const std::string &program_id) const {
    std::vector<std::string> out = {user_dir_.string()};
    const std::string project = program_id.substr(0, program_id.find('/'));
    if (!opt_.host.project_dir.empty() && ValidProjectDir(project)) out.push_back(ProjectScripts(project).string());
    return out;
  }

  grpc::Status AnswerPrompt(grpc::ServerContext *ctx, const pb::AnswerPromptRequest *req,
                            pb::AnswerPromptResponse *) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "AnswerPrompt", *req, who); !st.ok()) return st;
    std::shared_ptr<Run> run;
    if (auto st = Owned(req->run_id(), *who, run); !st.ok()) return st;
    {
      std::lock_guard lock(run->mu);
      if (!run->open_prompts.erase(req->prompt_id()))
        return {grpc::StatusCode::NOT_FOUND, "run " + req->run_id() + " is not asking prompt " + std::to_string(req->prompt_id())};
    }
    gp::Struct m;
    auto &fields = *m.mutable_fields();
    fields["type"] = Str("answer");
    fields["id"].set_number_value(req->prompt_id());
    if (req->cancelled()) {
      fields["cancelled"].set_bool_value(true);
    } else if (!req->values().empty()) {
      auto *list = fields["value"].mutable_list_value();
      for (const auto &v : req->values()) *list->add_values() = Str(v);
    } else {
      fields["value"] = Str(req->value());
    }
    if (!run->Send(m)) return {grpc::StatusCode::NOT_FOUND, "run " + req->run_id() + " has ended"};
    return grpc::Status::OK;
  }

  grpc::Status CancelScript(grpc::ServerContext *ctx, const pb::CancelScriptRequest *req,
                            pb::CancelScriptResponse *resp) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "CancelScript", *req, who); !st.ok()) return st;
    if (req->run_id().starts_with("console-")) {
      auto c = ConsoleById(req->run_id(), *who);
      if (!c || c->Dead()) {
        resp->set_was_running(false);
        return grpc::Status::OK;
      }
      resp->set_was_running(true);
      if (req->interrupt()) {
        c->Interrupt();
      } else {
        std::lock_guard lock(consoles_mu_);
        if (!c->closing) {
          c->closing = true;
          c->close_at = Clock::now();
          c->Close();
        }
      }
      return grpc::Status::OK;
    }
    std::shared_ptr<Run> run;
    if (auto st = Owned(req->run_id(), *who, run); !st.ok()) {
      if (st.error_code() == grpc::StatusCode::NOT_FOUND && Finished(req->run_id(), *who)) {
        resp->set_was_running(false);
        return grpc::Status::OK;
      }
      return st;
    }
    resp->set_was_running(true);
    if (req->interrupt()) {
      std::lock_guard lock(run->mu);
      if (!run->exited && run->proc.pid > 0) ::kill(-run->proc.pid, SIGINT);
    } else {
      run->Cancel();
    }
    return grpc::Status::OK;
  }

  grpc::Status UpdateContext(grpc::ServerContext *ctx, const pb::UpdateContextRequest *req,
                             pb::UpdateContextResponse *) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "UpdateContext", *req, who); !st.ok()) return st;
    std::shared_ptr<Run> run;
    if (auto st = Owned(req->run_id(), *who, run); !st.ok()) return st;
    gp::Struct m;
    gp::util::JsonParseOptions o;
    if (!gp::util::JsonStringToMessage(ContextJson(req->context(), true), &m, o).ok())
      return {grpc::StatusCode::INTERNAL, "context"};
    if (!run->Send(m)) return {grpc::StatusCode::NOT_FOUND, "run " + req->run_id() + " has ended"};
    return grpc::Status::OK;
  }

  grpc::Status SetupScriptPython(grpc::ServerContext *ctx, const pb::SetupScriptPythonRequest *req,
                                 grpc::ServerWriter<pb::SetupScriptPythonResponse> *writer) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "SetupScriptPython", *req, who); !st.ok()) return st;
    std::string why;
    if (!MayHost(*who, why)) return {grpc::StatusCode::PERMISSION_DENIED, why};
    if (who->token_id.starts_with("run:"))
      return {grpc::StatusCode::PERMISSION_DENIED, "a script the daemon runs can't set up Python"};
    if (!opt_.host.python.empty())
      return {grpc::StatusCode::FAILED_PRECONDITION,
              "rk-daemon --script-python " + opt_.host.python + " names the Python scripts run with; set that one up instead"};
    std::unique_lock busy(setup_mu_, std::try_to_lock);
    if (!busy.owns_lock()) return {grpc::StatusCode::ABORTED, "Python is being set up already; wait for it to finish"};
    try {
      return Setup(ctx, *req, writer);
    } catch (const std::exception &e) {
      return {grpc::StatusCode::INTERNAL, std::string("script service: ") + e.what()};
    }
  }

  grpc::Status ListScriptRuns(grpc::ServerContext *ctx, const pb::ListScriptRunsRequest *req,
                              pb::ListScriptRunsResponse *resp) override {
    std::optional<auth::Principal> who;
    if (auto st = Check(ctx, "ListScriptRuns", *req, who); !st.ok()) return st;
    const bool admin = who->role == auth::Role::kAdmin;
    const uint32_t limit = req->limit() ? std::min<uint32_t>(req->limit(), kRecentRuns) : 50;
    std::lock_guard lock(runs_mu_);
    for (auto it = recent_.rbegin(); it != recent_.rend() && static_cast<uint32_t>(resp->runs_size()) < limit; ++it) {
      if (!admin && it->caller() != who->display()) continue;
      if (!req->program_id().empty() && it->program_id() != req->program_id()) continue;
      const std::string project = it->program_id().substr(0, it->program_id().find('/'));
      if (!who->may_use_project(project)) continue;
      *resp->add_runs() = *it;
    }
    return grpc::Status::OK;
  }

 private:
  grpc::Status Check(grpc::ServerContext *ctx, const char *method, const gp::Message &req,
                     std::optional<auth::Principal> &who) {
    const std::string full = std::string("revkit.v1.ScriptService/") + method;
    return ToGrpc(gate_->Check(ctx, full.c_str(), req, who));
  }

  // SetupScriptPython's steps, as rk-script setup's: a venv (unless there
  // is one and no `force`), the SDK into it, then the import the daemon
  // checks for. Each command's output is streamed as it comes.
  grpc::Status Setup(grpc::ServerContext *ctx, const pb::SetupScriptPythonRequest &req,
                     grpc::ServerWriter<pb::SetupScriptPythonResponse> *writer) {
    bool client_gone = false;
    auto say = [&](const std::string &text) {
      if (client_gone) return;
      pb::SetupScriptPythonResponse r;
      r.set_output(text);
      if (!writer->Write(r)) client_gone = true;
    };
    const fs::path env = ScriptPythonEnv();
    const std::string python = (env / "bin" / "python").string();
    auto finish = [&](bool ok, const std::string &error) {
      pb::SetupScriptPythonResponse r;
      auto *res = r.mutable_result();
      res->set_ok(ok);
      res->set_directory(env.string());
      if (ok) {
        // The daemon looks again now, not in up to 5 s.
        std::string problem;
        {
          std::lock_guard lock(python_mu_);
          python_.reset();
          python_checked_ = {};
        }
        if (auto py = Python(problem)) {
          res->set_python(py->python);
        } else {
          res->set_ok(false);
          res->set_error(problem);
        }
      } else {
        res->set_error(error);
      }
      if (!client_gone) writer->Write(r);
      return grpc::Status::OK;
    };
    const std::string sdk = FindScriptSdk(opt_.host.sdk_sources);
    if (sdk.empty())
      return finish(false, "no revkit SDK to install: this rk-daemon has no share/revkit/python/revkit-*.whl beside it "
                           "(install the revkit package, or pip install the SDK wheel into a Python of your own and "
                           "give rk-daemon --script-python)");
    const std::string base = opt_.host.setup_python.empty() ? "python3" : opt_.host.setup_python;
    // Runs one step to its end (at most `limit`), streaming its output;
    // its exit status, or -1 when it couldn't start or was stopped.
    auto step = [&](const std::vector<std::string> &argv, std::chrono::seconds limit, std::string &error) -> int {
      std::string line = "$";
      for (const auto &a : argv) line += " " + a;
      say(line + "\n");
      Spawned p;
      if (!Spawn(argv, ChildEnv({{"PYTHONUNBUFFERED", "1"}, {"PIP_DISABLE_PIP_VERSION_CHECK", "1"}},
                                {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}),
                 p, error))
        return -1;
      CloseFd(p.in);
      const auto until = Clock::now() + limit;
      std::string buf;
      bool out_open = true, err_open = true;
      char chunk[16384];
      while (out_open || err_open) {
        if (ctx->IsCancelled() || stopping_->load() || Clock::now() > until) {
          ::kill(-p.pid, SIGKILL);
          error = ctx->IsCancelled() || stopping_->load() ? "stopped" : "took longer than " + std::to_string(limit.count()) + " s";
          break;
        }
        pollfd fds[2];
        int n = 0;
        if (out_open) fds[n++] = {p.out, POLLIN, 0};
        if (err_open) fds[n++] = {p.err, POLLIN, 0};
        int r = ::poll(fds, n, 200);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) break;
        for (int i = 0; i < n; ++i) {
          if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
          ssize_t got = ::read(fds[i].fd, chunk, sizeof chunk);
          if (got < 0 && errno == EINTR) continue;
          if (got <= 0) {
            (fds[i].fd == p.out ? out_open : err_open) = false;
            continue;
          }
          buf.append(chunk, static_cast<std::size_t>(got));
          if (auto nl = buf.rfind('\n'); nl != std::string::npos) {
            say(buf.substr(0, nl + 1));
            buf.erase(0, nl + 1);
          }
        }
      }
      if (!buf.empty()) say(buf + "\n");
      int status = 0;
      ::waitpid(p.pid, &status, 0);
      CloseFd(p.out);
      CloseFd(p.err);
      if (!error.empty()) return -1;
      return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    };
    std::string error;
    std::error_code ec;
    if (req.force() || !fs::exists(python, ec)) {
      fs::create_directories(env.parent_path(), ec);
      const int rc = step({base, "-m", "venv", env.string()}, std::chrono::seconds(300), error);
      if (rc != 0) {
        if (rc < 0 && error.starts_with("cannot start"))
          return finish(false, "no " + base + " to make the environment from: install Python 3.10 or newer with its venv " +
                                   "module (Debian and Ubuntu: apt install python3 python3-venv), or give rk-daemon " +
                                   "--script-setup-python");
        return finish(false, base + " -m venv " + env.string() + " failed" + (error.empty() ? "" : ": " + error) +
                                 " (Debian and Ubuntu: apt install python3-venv)");
      }
    }
    if (const int rc = step({python, "-m", "pip", "install", "--upgrade", sdk}, std::chrono::seconds(900), error); rc != 0)
      return finish(false, "installing the revkit SDK (" + sdk + ") failed" + (error.empty() ? "" : ": " + error) +
                               "; pip needs to reach PyPI for grpcio and protobuf (or a mirror: PIP_INDEX_URL)");
    // pip keeps an installed SDK whose version string matches, even when it
    // is an older build of that version: reinstall the SDK itself (not its
    // dependencies) so the environment has this daemon's.
    if (const int rc = step({python, "-m", "pip", "install", "--force-reinstall", "--no-deps", sdk}, std::chrono::seconds(300), error); rc != 0)
      return finish(false, "reinstalling the revkit SDK (" + sdk + ") failed" + (error.empty() ? "" : ": " + error));
    if (const int rc = step({python, "-c", SdkProbe()}, std::chrono::seconds(60), error); rc != 0)
      return finish(false, rc == 3 ? "the revkit SDK installed from " + sdk + " is older than this daemon (script API " +
                                         std::to_string(kScriptSdkApi) + ")"
                                   : python + " can't import revkit.script.worker" + (error.empty() ? "" : ": " + error));
    say("Scripts run with " + python + "\n");
    return finish(true, "");
  }

  bool MayHost(const auth::Principal &who, std::string &why) const {
    if (!host_role_) {
      why = host_why_;
      return false;
    }
    if (who.kind == auth::PrincipalKind::kAnonymous) return true;
    if (!auth::role_allows(who.role, *host_role_)) {
      why = who.display() + " (" + auth::to_string(who.role) + ") may not run scripts on this daemon: " + host_why_;
      return false;
    }
    return true;
  }

  std::optional<PythonChoice> Python(std::string &problem) {
    std::lock_guard lock(python_mu_);
    if (python_) return python_;
    // A failed search is repeated at most every 5 s, so setting Python up
    // needs no restart.
    if (Clock::now() - python_checked_ < std::chrono::seconds(5) && !python_problem_.empty()) {
      problem = python_problem_;
      return std::nullopt;
    }
    python_checked_ = Clock::now();
    python_problem_.clear();
    python_ = FindScriptPython(opt_.host.python, opt_.host.sdk_pythonpath, python_problem_);
    problem = python_problem_;
    return python_;
  }

  static bool ReadSource(const fs::path &p, std::string &out) {
    std::error_code ec;
    if (!fs::is_regular_file(p, ec) || fs::file_size(p, ec) > kMaxScriptBytes) return false;
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::ostringstream s;
    s << in.rdbuf();
    out = s.str();
    return true;
  }

  fs::path ProjectScripts(const std::string &project) const {
    return fs::path(opt_.host.project_dir) / project / "scripts";
  }

  // Every script of the libraries the caller sees.
  std::vector<ScriptFile> Scan(const std::string &project) const {
    std::vector<ScriptFile> out;
    auto scan = [&](const fs::path &dir, pb::ScriptLibrary lib, const std::string &prefix, const std::string &pid) {
      std::error_code ec;
      if (!fs::is_directory(dir, ec)) return;
      std::vector<std::string> names;
      for (const auto &e : fs::directory_iterator(dir, ec)) {
        const std::string n = e.path().filename().string();
        if (n.starts_with("_") || !ValidFileName(n) || !e.is_regular_file(ec)) continue;
        names.push_back(n);
      }
      std::sort(names.begin(), names.end());
      for (const auto &n : names) {
        if (lib == pb::SCRIPT_LIBRARY_SHIPPED &&
            std::any_of(out.begin(), out.end(), [&](const ScriptFile &f) { return f.id == prefix + n; }))
          continue;
        out.push_back({prefix + n, lib, pid, n, dir / n});
      }
    };
    for (const auto &d : opt_.host.shipped_dirs) scan(d, pb::SCRIPT_LIBRARY_SHIPPED, "shipped/", "");
    scan(user_dir_, pb::SCRIPT_LIBRARY_USER, "user/", "");
    if (!project.empty() && !opt_.host.project_dir.empty() && ValidProjectDir(project))
      scan(ProjectScripts(project), pb::SCRIPT_LIBRARY_PROJECT, "project/" + project + "/", project);
    return out;
  }

  // A script id to its file (which need not exist yet, for SaveScript).
  grpc::Status Resolve(const std::string &id, const auth::Principal &who, ScriptFile &f) const {
    auto bad = [&] {
      return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                          "script_id \"" + id + "\": shipped/<file>.py, user/<file>.py or project/<project>/<file>.py");
    };
    f = {};
    f.id = id;
    if (id.starts_with("shipped/")) {
      f.library = pb::SCRIPT_LIBRARY_SHIPPED;
      f.file_name = id.substr(8);
      if (!ValidFileName(f.file_name)) return bad();
      for (const auto &d : opt_.host.shipped_dirs) {
        std::error_code ec;
        if (fs::is_regular_file(fs::path(d) / f.file_name, ec)) {
          f.path = fs::path(d) / f.file_name;
          return grpc::Status::OK;
        }
      }
      return {grpc::StatusCode::NOT_FOUND, "no script " + id};
    }
    if (id.starts_with("user/")) {
      f.library = pb::SCRIPT_LIBRARY_USER;
      f.file_name = id.substr(5);
      if (!ValidFileName(f.file_name)) return bad();
      f.path = user_dir_ / f.file_name;
      return grpc::Status::OK;
    }
    if (id.starts_with("project/")) {
      std::string rest = id.substr(8);
      auto slash = rest.find('/');
      if (slash == std::string::npos) return bad();
      f.library = pb::SCRIPT_LIBRARY_PROJECT;
      f.project_id = rest.substr(0, slash);
      f.file_name = rest.substr(slash + 1);
      if (!ValidProjectDir(f.project_id) || !ValidFileName(f.file_name)) return bad();
      if (!who.may_use_project(f.project_id))
        return {grpc::StatusCode::PERMISSION_DENIED, who.display() + " may not use project \"" + f.project_id + "\""};
      if (opt_.host.project_dir.empty())
        return {grpc::StatusCode::FAILED_PRECONDITION, "project script libraries need rk-daemon --project-dir"};
      f.path = ProjectScripts(f.project_id) / f.file_name;
      return grpc::Status::OK;
    }
    return bad();
  }

  pb::ScriptInfo Info(const ScriptFile &f, const std::string &source, const auth::Principal &who, bool host_enabled) {
    pb::ScriptInfo i;
    i.set_script_id(f.id);
    i.set_library(f.library);
    i.set_project_id(f.project_id);
    i.set_file_name(f.file_name);
    const ScriptMeta m = ParseScriptMetadata(source, fs::path(f.file_name).stem().string());
    i.set_name(m.name);
    i.set_category(m.category);
    i.set_description(m.description);
    i.set_menupath(m.menupath);
    i.set_keybinding(m.keybinding);
    i.set_context(m.context);
    for (const auto &a : m.args) {
      auto *x = i.add_args();
      x->set_name(a.name);
      x->set_type(a.type);
      x->set_has_default(a.default_value.has_value());
      x->set_default_value(a.default_value.value_or(""));
      x->set_description(a.description);
      for (const auto &c : a.choices) x->add_choices(c);
    }
    for (const auto &e : m.errors) i.add_errors(e);
    const std::string sha = Sha256Hex(source);
    i.set_sha256(sha);
    i.set_trusted(f.library == pb::SCRIPT_LIBRARY_SHIPPED || trust_.Pinned(who.display(), f.id) == sha);
    i.set_writable(host_enabled && auth::role_allows(who.role, auth::Role::kEditor) && f.library != pb::SCRIPT_LIBRARY_SHIPPED &&
                   (f.library == pb::SCRIPT_LIBRARY_PROJECT || who.projects.empty()));
    std::error_code ec;
    auto t = fs::last_write_time(f.path, ec);
    if (!ec) {
      // file_time to system time without std::chrono::clock_cast, which the
      // packages' toolchain (GCC 12, Debian 12) lacks: the same offset from
      // each clock's now.
      const auto sys = std::chrono::system_clock::now() +
                       std::chrono::duration_cast<std::chrono::system_clock::duration>(t - fs::file_time_type::clock::now());
      i.set_modified_unix(std::chrono::duration_cast<std::chrono::seconds>(sys.time_since_epoch()).count());
    }
    i.set_size(source.size());
    return i;
  }

  // The host's context JSON: {"address": "0x..", "selection": [..] | null},
  // with "type": "context" for an update.
  static std::string ContextJson(const pb::ScriptContext &c, bool update) {
    std::string s = "{";
    if (update) s += "\"type\":\"context\",";
    s += "\"address\":" + (c.has_address() ? "\"" + Hex(c.address().offset()) + "\"" : std::string("null"));
    s += ",\"selection\":";
    if (c.has_selection() && c.selection().has_first() && c.selection().has_last())
      s += "[\"" + Hex(c.selection().first().offset()) + "\",\"" + Hex(c.selection().last().offset()) + "\"]";
    else
      s += "null";
    return s + "}";
  }

  grpc::Status Owned(const std::string &run_id, const auth::Principal &who, std::shared_ptr<Run> &run) {
    if (run_id.starts_with("console-")) {
      auto c = ConsoleById(run_id, who);
      if (!c) return {grpc::StatusCode::NOT_FOUND, "no console " + run_id};
      run = c->run;
      return grpc::Status::OK;
    }
    std::lock_guard lock(runs_mu_);
    auto it = active_.find(run_id);
    // Someone else's run reads as missing, unless the caller is an admin.
    if (it == active_.end() || (it->second->owner != who.display() && who.role != auth::Role::kAdmin))
      return {grpc::StatusCode::NOT_FOUND, "no running script " + run_id};
    run = it->second;
    return grpc::Status::OK;
  }

  bool Finished(const std::string &run_id, const auth::Principal &who) {
    std::lock_guard lock(runs_mu_);
    return std::any_of(recent_.begin(), recent_.end(), [&](const pb::ScriptRun &r) {
      return r.run_id() == run_id && (r.caller() == who.display() || who.role == auth::Role::kAdmin);
    });
  }

  // The run's last message: the host's result or error, or what its end
  // says when it died without one.
  pb::RunScriptResponse Final(Run &run) {
    pb::RunScriptResponse out;
    out.set_run_id(run.id);
    std::optional<gp::Struct> ev;
    int status = 0;
    bool killed = false;
    {
      std::lock_guard lock(run.mu);
      ev = run.final_event;
      status = run.exit_status;
      killed = run.killed;
    }
    const double seconds = (NowMs() - run.started_ms) / 1000.0;
    auto fill = [&](pb::ScriptResult &r, const gp::Struct *e) {
      if (e) {
        Numbers(*e, "revisions", r.mutable_revisions());
        Numbers(*e, "seqs", r.mutable_seqs());
        r.set_discarded(static_cast<uint32_t>(Number(*e, "discarded")));
        r.set_exit_code(static_cast<int32_t>(Number(*e, "exit_code")));
      }
      r.set_seconds(seconds);
    };
    if (ev && Text(*ev, "type") == "result" && Text(*ev, "status") == "ok") {
      auto *r = out.mutable_result();
      r->set_status("ok");
      fill(*r, &*ev);
      return out;
    }
    auto *err = out.mutable_error();
    auto *r = err->mutable_result();
    // The host names the file as Python resolved it.
    std::string path = run.script.path.string();
    {
      std::error_code ec;
      auto canon = fs::canonical(run.script.path, ec);
      if (!ec) path = canon.string();
    }
    auto ids = [&](const std::string &text) {
      return ReplaceAll(ReplaceAll(text, path, run.script.id), run.script.path.string(), run.script.id);
    };
    if (ev) {
      std::string st = Text(*ev, "status");
      r->set_status(st == "cancelled" ? "cancelled" : "error");
      fill(*r, &*ev);
      err->set_message(ids(Text(*ev, "error")));
      err->set_error_type(Text(*ev, "error_type"));
      err->set_traceback(ids(Text(*ev, "traceback")));
      if (const std::string file = Text(*ev, "error_file"); file == path || file == run.script.path.string()) {
        err->set_script_id(run.script.id);
        err->set_line(static_cast<uint32_t>(Number(*ev, "error_line")));
      }
      return out;
    }
    fill(*r, nullptr);
    if (run.cancel_requested.load()) {
      r->set_status("cancelled");
      err->set_message(killed ? "cancelled (the script host was killed 2 s after it was asked to stop)" : "cancelled");
    } else {
      r->set_status("error");
      if (WIFSIGNALED(status))
        err->set_message("the script host died with signal " + std::to_string(WTERMSIG(status)));
      else
        err->set_message("the script host exited with status " + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) +
                         " without a result (its stderr is in the output)");
    }
    r->set_exit_code(WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return out;
  }

  void Remember(const Run &run, const std::string &status, const pb::RunScriptResponse *last = nullptr) {
    pb::ScriptRun r;
    r.set_run_id(run.id);
    r.set_script_id(run.script.id);
    r.set_name(run.name);
    r.set_version(run.sha256.substr(0, 12));
    r.set_program_id(run.program_id);
    r.set_caller(run.owner);
    r.set_status(status);
    r.set_started_at_ms(run.started_ms);
    if (last) {
      const pb::ScriptResult &res = last->has_result() ? last->result() : last->error().result();
      r.set_seconds(res.seconds());
      *r.mutable_revisions() = res.revisions();
      r.set_assertions(static_cast<uint32_t>(res.seqs_size()));
      if (last->has_error()) r.set_error(last->error().message());
    }
    std::lock_guard lock(runs_mu_);
    auto it = std::find_if(recent_.begin(), recent_.end(), [&](const pb::ScriptRun &x) { return x.run_id() == run.id; });
    if (it != recent_.end()) {
      *it = std::move(r);
      return;
    }
    recent_.push_back(std::move(r));
    while (recent_.size() > kRecentRuns) recent_.pop_front();
  }

  std::shared_ptr<AuthGate> gate_;
  ScriptServiceOptions opt_;
  std::shared_ptr<ScriptHostTarget> target_;
  std::shared_ptr<std::atomic<bool>> stopping_;
  ScriptTrust trust_;
  fs::path user_dir_;
  std::optional<auth::Role> host_role_;
  std::string host_why_;

  std::mutex python_mu_;
  std::optional<PythonChoice> python_;
  std::string python_problem_;
  Clock::time_point python_checked_{};

  std::mutex setup_mu_;
  std::mutex save_mu_;
  std::mutex runs_mu_;
  std::map<std::string, std::shared_ptr<Run>> active_;
  std::deque<pb::ScriptRun> recent_;

  // Consoles by (caller, program), and the thread that closes idle ones.
  std::mutex consoles_mu_;
  std::map<std::pair<std::string, std::string>, std::shared_ptr<Console>> consoles_;
  std::condition_variable reaper_cv_;
  bool reaper_stop_ = false;
  std::thread reaper_;
  std::mutex history_mu_;
};

}  // namespace

std::unique_ptr<grpc::Service> MakeScriptService(std::shared_ptr<AuthGate> gate, ScriptServiceOptions options,
                                                 std::shared_ptr<ScriptHostTarget> target,
                                                 std::shared_ptr<std::atomic<bool>> stopping) {
  return std::make_unique<ScriptServiceImpl>(std::move(gate), std::move(options), std::move(target), std::move(stopping));
}

}  // namespace revkit::api
