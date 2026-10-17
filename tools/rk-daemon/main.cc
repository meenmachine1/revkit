// rk-daemon: serves the revkit API over gRPC (native clients) and
// Connect/gRPC-web (browsers) from one process.
//
//   rk-daemon [--backend image|fake] [--open file]... [--project-dir dir] [--grpc 127.0.0.1:50051]
//             [--http 127.0.0.1:50052] [--web-root dir | --no-web-root]
//             [--allow-origin origin]... [--port-file path] [--peer host:port[,option]...]...
//             [--plugin-dir dir]... [--plugin-grant name=cap[,cap]]... [--debug-live]
//             [--no-auth | --auth-file path] [--tls-cert pem --tls-key pem | --tls-self-signed]
//   rk-daemon user add|del|passwd|role|list ...      accounts (docs/security.md)
//   rk-daemon token create|list|revoke ...           API tokens
//   rk-daemon tls fingerprint                        the listeners' certificate
//   rk-daemon project export|import|import-batch ...  project archives (.rkproj; docs/backend.md), batch import (docs/filesystems.md)
//
// The HTTP port also serves the web UI: --web-root, else $REVKIT_WEB_ROOT,
// else an installed bundle's share/revkit/ui, else the source tree's ui/dist
// when it has been built.

#include "revkit/api/fake_backend.h"
#include "revkit/api/listen_fds.h"
#include "auth_choice.h"

#include "revkit/api/peer_link.h"
#include "revkit/api/server.h"
#include "revkit/auth/store.h"
#include "revkit/auth/tls.h"
#include "revkit/backend/image_backend.h"
#include "revkit/container/container.hh"
#include "revkit/plugins/host.h"
#include "revkit/runtime/runtime.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <termios.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <sstream>

#include <csignal>
#include <filesystem>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <pthread.h>
#include <string>
#include <string_view>
#include <filesystem>
#include <map>
#include <set>
#include <thread>
#include <vector>

namespace {

struct Options {
  revkit::api::ServerOptions server;
  std::string backend = "image";
  std::string port_file;
  std::uint32_t retain = 256;
  std::size_t memo_budget_mb = 0;  // 0: the backend's default
  std::vector<std::string> open;
  std::string ghidra_root;
  std::string project_dir;
  std::vector<std::string> browse_roots;
  std::string symbol_path;
  std::string symbol_cache;
  bool symbol_downloads = false;
  std::vector<std::string> debug_dirs;
  std::vector<std::string> debuginfod_urls;
  revkit::backend::InferMode infer_prototypes = revkit::backend::InferMode::automatic;
  bool function_id = true;
  std::string param_id = "auto";
  bool debug_live = false;
  unsigned decompilers = 2;
  bool decompile_in_process = false;
  unsigned analysis_threads = 0;
  unsigned engine_idle = 15;
  double decompile_timeout = 30;
  std::size_t decompile_max_varnodes = std::size_t{1} << 20;
  bool web_root_set = false;
  std::vector<std::string> plugin_dirs;
  std::map<std::string, std::set<revkit::plugins::Capability>> plugin_grants;
  std::vector<std::string> peers;

  // Authentication and TLS (docs/security.md).
  bool no_auth = false;
  bool auth = false;  // --auth
  bool ask = false;   // --ask
  std::string auth_file;
  double session_ttl_hours = 7 * 24;
  std::string tls_cert, tls_key;
  bool tls_self_signed = false;
  std::string tls_dir;
  std::vector<std::string> tls_sans;
  bool insecure_allow_remote = false;
  std::string peer_secret_file;
  std::string peer_token_file;
  std::string peer_ca;
  std::string peer_fingerprint;
  std::string peer_server_name;
  bool peer_tls = false;
};

void usage(std::ostream &os) {
  os << "usage: rk-daemon [options]\n"
        "  --grpc <host:port>      gRPC listen address (default 127.0.0.1:50051; port 0 = any)\n"
        "  --http <host:port>      Connect/gRPC-web/static listen address (default 127.0.0.1:50052)\n"
        "  --no-grpc, --no-http    disable a listener\n"
        "                          (socket activation: a listening socket systemd passes, LISTEN_FDS,\n"
        "                          is the HTTP listener instead of --http; the same rules apply to\n"
        "                          where it listens; docs/packaging.md)\n"
        "  --web-root <dir>        serve this directory at / (default: $REVKIT_WEB_ROOT, else the\n"
        "                          installed share/revkit/ui, else the source tree's built ui/dist)\n"
        "  --no-web-root           serve no web UI\n"
        "  --allow-origin <origin> allow cross-origin browser calls from origin (repeatable; * = any)\n"
        "  --allow-host <name>     answer HTTP requests for this host name too (repeatable; *.example.com\n"
        "                          for its subdomains; also allow-host = NAME in revkit.conf). Always\n"
        "                          answered: localhost, *.localhost, IP addresses, the TLS certificate's\n"
        "                          names and, beyond loopback, the machine's name (DNS rebinding;\n"
        "                          docs/security.md)\n"
        "  --backend image|fake    data source (default image: real ELF/PE binaries;\n"
        "                          fake: the synthetic demo program, for tests)\n"
        "  --open <file>           import an ELF/PE file into project \"default\" at startup\n"
        "                          (repeatable; image backend)\n"
        "  --ghidra <dir>          Ghidra install for processor specs (default: $GHIDRA_INSTALL_DIR,\n"
        "                          ~/.config/revkit/revkit.conf, the bundled specs, ~/ghidra*,\n"
        "                          /opt/ghidra*; docs/getting-started.md)\n"
        "  --decompilers <n>       decompiler worker processes (rk-decompd), shared by all programs (default 2)\n"
        "  --decompile-in-process  decompile in the daemon instead of workers (debugging under gdb only:\n"
        "                          a decompiler crash then ends the daemon)\n"
        "  --analysis-threads <n>  threads for import-time analysis (default: the hardware's, at most 8)\n"
        "  --engine-idle <s>       let SLEIGH engines idle for <s> seconds go, keeping two per language\n"
        "                          for reuse (default 15; 0: keep them; docs/memory.md)\n"
        "  --decompile-timeout <s> stop a decompilation after <s> seconds (default 30, as Ghidra; 0: none)\n"
        "  --decompile-max-varnodes <n>  stop a decompilation past <n> varnodes, about 1 KB each\n"
        "                          (default 1048576; 0: none)\n"
        "  --infer-prototypes [auto|on|off]  revkit::infer's prototypes for functions nothing else gives\n"
        "                          one, inferred in the background after import (an analysis job):\n"
        "                          auto (default) in programs without debug info on x86-64, AArch64\n"
        "                          and RISC-V 64; on (the bare flag) every program; off none\n"
        "  --no-infer-prototypes   the same as --infer-prototypes off\n"
        "  --function-id on|off    Function ID after import: name library functions from Ghidra's FID databases\n"
        "                          and attached ones (default on; docs/fid.md)\n"
        "  --no-function-id        the same as --function-id off\n"
        "  --param-id <mode>       Ghidra's Decompiler Parameter ID: auto (as Ghidra: PEs under 2 MiB), on, off\n"
        "                          and give unasserted functions those prototypes when decompiling\n"
        "  --project-dir <dir>     keep projects in <dir>/<project>/ (LMDB) and reopen them at\n"
        "                          startup with their assertions and cached derived facts\n"
        "  --browse-root <dir>     let clients list files under dir to import by path (repeatable;\n"
        "                          ListHostFiles; off when not given)\n"
        "  --symbol-path <path>    where Load PDB looks PDBs up (_NT_SYMBOL_PATH syntax:\n"
        "                          srv*<cache>*https://msdl.microsoft.com/download/symbols;<dir>)\n"
        "  --symbol-downloads      let Load PDB download from the path's symbol servers (network\n"
        "                          access; off by default: docs/security.md)\n"
        "  --symbol-cache <dir>    where downloads go when an entry names no cache\n"
        "  --debug-dir <dir>       look ELF debug files up there too, by build ID and debuglink\n"
        "                          (repeatable; docs/backend.md \"External debug files\")\n"
        "  --debuginfod <url>      let Load debug file fetch from this https debuginfod server\n"
        "                          (repeatable; network access, off by default: docs/security.md;\n"
        "                          DEBUGINFOD_URLS is only suggested in the settings)\n"
        "  --retain <n>            revisions kept readable per project (default 256)\n"
        "  --memo-budget <MiB>     derived facts kept in memory per project before the oldest\n"
        "                          are evicted (default 2048; tests run smaller daemons)\n"
        "  --port-file <path>      write {\"grpc\": port, \"http\": port} once listening\n"
        "  --plugin-dir <dir>      load WebAssembly plugins (NAME.wasm + NAME.json) from dir (repeatable;\n"
        "                          image backend; see docs/plugins.md)\n"
        "  --plugin-grant <name>=<cap>[,<cap>]\n"
        "                          grant a plugin a capability it requests beyond memory and code;\n"
        "                          \"file\" lets it read the raw binary under analysis (repeatable)\n"
        "  --debug-live            let debug sessions connect to GDB remote stubs and launch or attach\n"
        "                          to processes on this host (DebugService; off: the emulator only).\n"
        "                          Clients can then run code here; with authentication, only admins\n"
        "                          start live sessions (docs/security.md)\n"
        "  --peer <host:port>[,opt]...\n"
        "                          replicate every project with the daemon whose gRPC listener is\n"
        "                          there, both ways (repeatable; image backend; docs/collab.md).\n"
        "                          Options override the --peer-* defaults for this peer:\n"
        "                          token-file=F, ca=F, fingerprint=SHA256, server-name=N, tls\n"
        "\n"
        "Security (docs/security.md):\n"
        "  --no-auth               no accounts or tokens: every caller is an anonymous admin.\n"
        "                          Local development only; both listeners must be on loopback\n"
        "  --auth                  accounts and tokens (the default), whatever revkit.conf says\n"
        "  --ask                   ask again how people sign in (needs a terminal). On a terminal, with\n"
        "                          neither flag, no auth = none|accounts in ~/.config/revkit/revkit.conf\n"
        "                          (or /etc/revkit/revkit.conf) and no accounts yet, rk-daemon asks once\n"
        "  --auth-file <path>      accounts, API tokens and sessions (default: <project-dir>/.revkit/auth.db,\n"
        "                          else ~/.local/share/revkit/auth.db); manage with rk-daemon user/token\n"
        "  --session-ttl <hours>   login sessions last this long (default 168)\n"
        "  --tls-cert <pem>, --tls-key <pem>\n"
        "                          serve both listeners over TLS with this certificate chain and key\n"
        "  --tls-self-signed       ... with a self-signed certificate kept in <project-dir>/.revkit/tls\n"
        "                          (else ~/.local/share/revkit/tls; --tls-dir to choose), made on first\n"
        "                          use for localhost, the listen addresses, the host name and --tls-san\n"
        "  --tls-san <name|ip>     another name for the self-signed certificate (repeatable)\n"
        "  --insecure-allow-remote allow plaintext listeners on non-loopback addresses (passwords and\n"
        "                          tokens then cross the network in the clear)\n"
        "  --scripts-host-role off|viewer|editor|admin\n"
        "                          who the daemon runs Python scripts and consoles for (ScriptService;\n"
        "                          a script is full Python as this daemon's user; a viewer's can't\n"
        "                          edit). Default: editor when every listener is on loopback, off\n"
        "                          otherwise (docs/scripting.md)\n"
        "  --console-idle-timeout <seconds>\n"
        "                          close a Python console idle this long (default 1800; 0: never)\n"
        "  --script-python <path>  the Python to run scripts with (default: the first of $REVKIT_PYTHON,\n"
        "                          ~/.local/share/revkit/pyenv/bin/python and python3 that imports revkit)\n"
        "  --script-setup-python <path>\n"
        "                          the Python \"Set up Python\" (SetupScriptPython) makes the scripts'\n"
        "                          environment, ~/.local/share/revkit/pyenv, from (default python3)\n"
        "  --scripts-dir <dir>     the per-user script library (default ~/.config/revkit/scripts)\n"
        "  --peer-secret-file <f>  a secret shared by linked daemons (32+ characters): accepted from\n"
        "                          peers, and sent to --peer daemons that have no token-file\n"
        "  --peer-token-file <f>   a peer token the other daemon issued (rk-daemon token create --role peer)\n"
        "  --peer-ca <pem>         trust this CA (or self-signed certificate) for --peer links; implies TLS\n"
        "  --peer-fingerprint <sha256>\n"
        "                          pin the peers' certificate by fingerprint; implies TLS\n"
        "  --peer-tls              connect to peers over TLS, trusting the system's CAs\n"
        "\n"
        "Accounts and tokens (they find the file as the daemon does: --project-dir or --auth-file):\n"
        "  rk-daemon user add <name> --role viewer|editor|admin [--projects a,b] [--password-stdin]\n"
        "  rk-daemon user passwd <name> [--password-stdin]\n"
        "  rk-daemon user role <name> viewer|editor|admin\n"
        "  rk-daemon user projects <name> <a,b | *>\n"
        "  rk-daemon user del <name>\n"
        "  rk-daemon user list\n"
        "  rk-daemon token create --name <name> --role viewer|editor|admin|peer [--user <account>]\n"
        "                         [--projects a,b] [--ttl-days n]\n"
        "  rk-daemon token list\n"
        "  rk-daemon token revoke <id or name>\n"
        "  rk-daemon tls fingerprint [--tls-cert pem | --tls-dir dir]\n"
        "\n"
        "Project archives (.rkproj; docs/backend.md, \"Project archives\"), on a --project-dir no daemon is using:\n"
        "  rk-daemon project export --project-dir <dir> [--project <id>] [--program <id>]... [--folder </path>]...\n"
        "                           [--annotations-only] -o <file.rkproj>\n"
        "  rk-daemon project import --project-dir <dir> <file.rkproj> [--into <project id> [--folder </path>]]\n"
        "                           [--name <new project>] [--binary <file>]... [--search-dir <dir>]\n"
        "                           [--skip-missing] [--inspect]\n"
        "Batch import (docs/filesystems.md): the programs in a host directory or a container, and in the\n"
        "containers inside it:\n"
        "  rk-daemon project import-batch --project-dir <dir> <path> [--into <project id>] [--folder </path>]\n"
        "                           [--recursive] [--no-descend] [--detect-raw] [--max <n>] [--preview]\n"
        "                           [--keep-folders] [--analyze]\n"
        "  rk-daemon --version\n";
}

std::vector<std::string> split_list(std::string_view s, char sep = ',') {
  std::vector<std::string> out;
  while (!s.empty()) {
    auto at = s.find(sep);
    if (at) out.emplace_back(s.substr(0, at));
    if (at == std::string_view::npos) break;
    s.remove_prefix(at + 1);
  }
  return out;
}

std::string data_dir() {
  if (const char *x = std::getenv("XDG_DATA_HOME"); x && *x) return std::string(x) + "/revkit";
  if (const char *h = std::getenv("HOME"); h && *h) return std::string(h) + "/.local/share/revkit";
  return ".revkit";
}

// Where accounts live: --auth-file, else beside the projects, else per user.
std::string auth_file_for(const std::string &explicit_path, const std::string &project_dir) {
  if (!explicit_path.empty()) return explicit_path;
  if (!project_dir.empty()) return (std::filesystem::path(project_dir) / ".revkit" / "auth.db").string();
  return data_dir() + "/auth.db";
}

std::string tls_dir_for(const std::string &explicit_dir, const std::string &project_dir) {
  if (!explicit_dir.empty()) return explicit_dir;
  if (!project_dir.empty()) return (std::filesystem::path(project_dir) / ".revkit" / "tls").string();
  return data_dir() + "/tls";
}

std::string read_text(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("cannot read " + path);
  std::ostringstream s;
  s << in.rdbuf();
  return s.str();
}

// A secret from a file: its first line, trimmed.
std::string read_secret(const std::string &path) {
  std::string s = read_text(path);
  if (auto nl = s.find_first_of("\r\n"); nl != std::string::npos) s.erase(nl);
  while (!s.empty() && s.back() == ' ') s.pop_back();
  while (!s.empty() && s.front() == ' ') s.erase(0, 1);
  if (s.empty()) throw std::runtime_error(path + " is empty");
  return s;
}

std::optional<Options> parse_args(int argc, char **argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    const char *v = nullptr;
    if (arg == "--help" || arg == "-h") return std::nullopt;
    if (arg == "--grpc" && (v = value())) opt.server.grpc_address = v;
    else if (arg == "--http" && (v = value())) opt.server.http_address = v;
    else if (arg == "--no-grpc") opt.server.grpc_address.clear();
    else if (arg == "--no-http") opt.server.http_address.clear();
    else if (arg == "--web-root" && (v = value())) {
      opt.server.web_root = v;
      opt.web_root_set = true;
    } else if (arg == "--no-web-root") {
      opt.server.web_root.clear();
      opt.web_root_set = true;
    } else if (arg == "--allow-origin" && (v = value())) opt.server.allowed_origins.emplace_back(v);
    else if (arg == "--allow-host" && (v = value())) opt.server.allowed_hosts.emplace_back(v);
    else if (arg == "--backend" && (v = value())) opt.backend = v;
    else if (arg == "--retain" && (v = value())) opt.retain = static_cast<std::uint32_t>(std::stoul(v));
    else if (arg == "--memo-budget" && (v = value())) opt.memo_budget_mb = std::stoull(v);
    else if (arg == "--port-file" && (v = value())) opt.port_file = v;
    else if (arg == "--open" && (v = value())) opt.open.emplace_back(v);
    else if (arg == "--ghidra" && (v = value())) opt.ghidra_root = v;
    else if (arg == "--decompilers" && (v = value())) opt.decompilers = static_cast<unsigned>(std::stoul(v));
    else if (arg == "--decompile-in-process") opt.decompile_in_process = true;
    else if (arg == "--analysis-threads" && (v = value())) opt.analysis_threads = static_cast<unsigned>(std::stoul(v));
    else if (arg == "--engine-idle" && (v = value())) opt.engine_idle = static_cast<unsigned>(std::stoul(v));
    else if (arg == "--decompile-timeout" && (v = value())) opt.decompile_timeout = std::stod(v);
    else if (arg == "--decompile-max-varnodes" && (v = value())) opt.decompile_max_varnodes = std::stoull(v);
    else if (arg == "--project-dir" && (v = value())) opt.project_dir = v;
    else if (arg == "--browse-root" && (v = value())) opt.browse_roots.emplace_back(v);
    else if (arg == "--symbol-path" && (v = value())) opt.symbol_path = v;
    else if (arg == "--symbol-cache" && (v = value())) opt.symbol_cache = v;
    else if (arg == "--symbol-downloads") opt.symbol_downloads = true;
    else if (arg == "--debug-dir" && (v = value())) opt.debug_dirs.emplace_back(v);
    else if (arg == "--debuginfod" && (v = value())) opt.debuginfod_urls.emplace_back(v);
    else if (arg == "--infer-prototypes" && i + 1 < argc &&
             (std::string_view(argv[i + 1]) == "auto" || std::string_view(argv[i + 1]) == "on" ||
              std::string_view(argv[i + 1]) == "off")) {
      const std::string_view m = argv[++i];
      opt.infer_prototypes = m == "auto" ? revkit::backend::InferMode::automatic
                             : m == "on" ? revkit::backend::InferMode::on
                                         : revkit::backend::InferMode::off;
    }
    else if (arg == "--infer-prototypes") opt.infer_prototypes = revkit::backend::InferMode::on;
    else if (arg == "--no-infer-prototypes") opt.infer_prototypes = revkit::backend::InferMode::off;
    else if (arg == "--function-id" && (v = value())) opt.function_id = std::string_view(v) != "off";
    else if (arg == "--no-function-id") opt.function_id = false;
    else if (arg == "--param-id" && (v = value())) {
      opt.param_id = v;
      if (!revkit::inputs::parse_param_id_mode(opt.param_id)) {
        std::cerr << "rk-daemon: --param-id must be auto, on or off\n";
        std::exit(2);
      }
    }
    else if (arg == "--debug-live") opt.debug_live = true;
    else if (arg == "--peer" && (v = value())) opt.peers.emplace_back(v);
    else if (arg == "--no-auth") opt.no_auth = true;
    else if (arg == "--auth") opt.auth = true;
    else if (arg == "--ask") opt.ask = true;
    else if (arg == "--auth-file" && (v = value())) opt.auth_file = v;
    else if (arg == "--session-ttl" && (v = value())) opt.session_ttl_hours = std::stod(v);
    else if (arg == "--tls-cert" && (v = value())) opt.tls_cert = v;
    else if (arg == "--tls-key" && (v = value())) opt.tls_key = v;
    else if (arg == "--tls-self-signed") opt.tls_self_signed = true;
    else if (arg == "--tls-dir" && (v = value())) opt.tls_dir = v;
    else if (arg == "--tls-san" && (v = value())) opt.tls_sans.emplace_back(v);
    else if (arg == "--insecure-allow-remote") opt.insecure_allow_remote = true;
    else if (arg == "--peer-secret-file" && (v = value())) opt.peer_secret_file = v;
    else if (arg == "--peer-token-file" && (v = value())) opt.peer_token_file = v;
    else if (arg == "--peer-ca" && (v = value())) opt.peer_ca = v;
    else if (arg == "--peer-fingerprint" && (v = value())) opt.peer_fingerprint = v;
    else if (arg == "--peer-server-name" && (v = value())) opt.peer_server_name = v;
    else if (arg == "--peer-tls") opt.peer_tls = true;
    else if (arg == "--plugin-dir" && (v = value())) opt.plugin_dirs.emplace_back(v);
    else if (arg == "--scripts-host-role" && (v = value())) {
      opt.server.scripts.role = v;
      if (opt.server.scripts.role != "off" && opt.server.scripts.role != "viewer" && opt.server.scripts.role != "editor" &&
          opt.server.scripts.role != "admin") {
        std::cerr << "rk-daemon: --scripts-host-role must be off, viewer, editor or admin\n";
        return std::nullopt;
      }
    }
    else if (arg == "--console-idle-timeout" && (v = value())) {
      char *end = nullptr;
      const unsigned long n = std::strtoul(v, &end, 10);
      if (!end || *end || n > 30u * 24 * 3600) {
        std::cerr << "rk-daemon: --console-idle-timeout takes seconds (0: never)\n";
        return std::nullopt;
      }
      opt.server.scripts.console_idle_seconds = static_cast<unsigned>(n);
    }
    else if (arg == "--script-python" && (v = value())) opt.server.scripts.python = v;
    else if (arg == "--script-setup-python" && (v = value())) opt.server.scripts.setup_python = v;
    else if (arg == "--scripts-dir" && (v = value())) opt.server.scripts.user_dir = v;
    else if (arg == "--plugin-grant" && (v = value())) {
      std::string_view g = v;
      auto eq = g.find('=');
      if (eq == std::string_view::npos || eq == 0) {
        std::cerr << "rk-daemon: --plugin-grant takes name=capability[,capability]\n";
        return std::nullopt;
      }
      auto &caps = opt.plugin_grants[std::string(g.substr(0, eq))];
      for (std::string_view rest = g.substr(eq + 1); !rest.empty();) {
        auto comma = rest.find(',');
        auto cap = revkit::plugins::capability_from_string(rest.substr(0, comma));
        if (!cap) {
          std::cerr << "rk-daemon: unknown capability \"" << rest.substr(0, comma) << "\" (memory, code, file, irq, output, bus)\n";
          return std::nullopt;
        }
        caps.insert(*cap);
        rest = comma == std::string_view::npos ? std::string_view() : rest.substr(comma + 1);
      }
    } else {
      std::cerr << "rk-daemon: bad argument: " << arg << "\n";
      return std::nullopt;
    }
  }
  if (!opt.web_root_set) {
    // The web UI: an explicit environment override, else an installed
    // revkit's copy, else the bundle built in the source tree (cd ui && npm
    // ci && npm run build).
    const auto share = revkit::runtime::share_dir();
    if (const char *env = std::getenv("REVKIT_WEB_ROOT"); env && *env) opt.server.web_root = env;
    else if (share && std::filesystem::exists(*share / "ui" / "index.html"))
      opt.server.web_root = (*share / "ui").string();
    else if (std::filesystem::exists(std::filesystem::path(REVKIT_DEFAULT_WEB_ROOT) / "index.html"))
      opt.server.web_root = REVKIT_DEFAULT_WEB_ROOT;
  }
  {
    // Scripts: the shipped library installed beside us, else the source
    // tree's; per-project libraries with the projects.
    const auto share = revkit::runtime::share_dir();
    if (share && std::filesystem::is_directory(*share / "scripts"))
      opt.server.scripts.shipped_dirs.push_back((*share / "scripts").string());
    if (std::filesystem::is_directory(REVKIT_SOURCE_SDK_PYTHON "/revkit/scripts"))
      opt.server.scripts.shipped_dirs.push_back(REVKIT_SOURCE_SDK_PYTHON "/revkit/scripts");
    opt.server.scripts.sdk_pythonpath = REVKIT_SOURCE_SDK_PYTHON;
    // What "Set up Python" installs: the SDK wheel the packages ship, else
    // this source tree's SDK.
    if (share) {
      opt.server.scripts.sdk_sources.push_back((*share / "python").string());
      opt.server.scripts.sdk_sources.push_back((*share / "sdk").string());
    }
    opt.server.scripts.sdk_sources.push_back(REVKIT_SOURCE_SDK_PYTHON);
    opt.server.scripts.project_dir = opt.project_dir;
  }
  if (opt.backend != "fake" && opt.backend != "image") {
    std::cerr << "rk-daemon: unknown backend \"" << opt.backend << "\" (available: image, fake)\n";
    return std::nullopt;
  }
  if (opt.backend == "fake" && !opt.open.empty()) {
    std::cerr << "rk-daemon: --open needs --backend image\n";
    return std::nullopt;
  }
  if (opt.backend == "fake" && !opt.plugin_dirs.empty()) {
    std::cerr << "rk-daemon: --plugin-dir needs --backend image\n";
    return std::nullopt;
  }
  if (opt.backend == "fake" && !opt.peers.empty()) {
    std::cerr << "rk-daemon: --peer needs --backend image\n";
    return std::nullopt;
  }
  if (opt.tls_cert.empty() != opt.tls_key.empty()) {
    std::cerr << "rk-daemon: --tls-cert and --tls-key go together\n";
    return std::nullopt;
  }
  if (opt.tls_self_signed && !opt.tls_cert.empty()) {
    std::cerr << "rk-daemon: --tls-self-signed or --tls-cert/--tls-key, not both\n";
    return std::nullopt;
  }
  if (opt.no_auth && !opt.auth_file.empty()) {
    std::cerr << "rk-daemon: --no-auth and --auth-file contradict each other\n";
    return std::nullopt;
  }
  if (opt.no_auth && (opt.auth || opt.ask)) {
    std::cerr << "rk-daemon: --no-auth and " << (opt.auth ? "--auth" : "--ask") << " contradict each other\n";
    return std::nullopt;
  }
  if (opt.session_ttl_hours <= 0) {
    std::cerr << "rk-daemon: --session-ttl must be positive\n";
    return std::nullopt;
  }
  return opt;
}

// "127.0.0.1:50052" -> "127.0.0.1"; wildcard binds print as localhost.
std::string HostOf(const std::string &address) {
  std::string host = address.substr(0, address.rfind(':'));
  if (host.empty() || host == "0.0.0.0" || host == "[::]") return "127.0.0.1";
  return host;
}

std::shared_ptr<revkit::api::Backend> make_backend(const Options &opt) {
  if (opt.backend == "fake") {
    revkit::api::FakeBackendOptions fake;
    fake.retained_revisions = opt.retain;
    fake.server_version = revkit::runtime::version_string("rk-daemon") + " (fake backend)";
    return revkit::api::MakeFakeBackend(fake);
  }
  revkit::backend::ImageBackendOptions image;
  const revkit::runtime::GhidraSpecs specs = revkit::runtime::locate_ghidra(opt.ghidra_root);
  if (!specs.warning.empty()) std::cerr << "rk-daemon: warning: " << specs.warning << "\n";
  std::cerr << "rk-daemon: Ghidra processor specs from " << specs.root.string() << " (" << specs.source
            << (specs.version.empty() ? "" : ", Ghidra " + specs.version) << ")\n";
  image.ghidra_root = specs.root.string();
  image.retained_revisions = opt.retain;
  if (opt.memo_budget_mb != 0) image.memo_budget = opt.memo_budget_mb << 20;
  image.server_version = revkit::runtime::version_string("rk-daemon") + " (image backend)";
  image.decompilers_per_program = opt.decompilers;
  image.decompile_workers = opt.decompilers;
  image.decompile_in_process = opt.decompile_in_process;
  image.analysis_threads = opt.analysis_threads;
  image.engine_idle_seconds = opt.engine_idle;
  image.decompile_timeout_seconds = opt.decompile_timeout;
  image.decompile_max_varnodes = opt.decompile_max_varnodes;
  image.project_dir = opt.project_dir;
  image.browse_roots = opt.browse_roots;
  image.symbol_path = opt.symbol_path;
  image.symbol_cache = opt.symbol_cache;
  image.symbol_downloads = opt.symbol_downloads;
  image.debug_dirs = opt.debug_dirs;
  image.debuginfod_urls = opt.debuginfod_urls;
  image.debuginfod = !opt.debuginfod_urls.empty();
  image.infer_prototypes = opt.infer_prototypes;
  image.function_id = opt.function_id;
  image.param_id = revkit::inputs::parse_param_id_mode(opt.param_id).value_or(revkit::inputs::ParamIdMode::automatic);
  image.debug_live = opt.debug_live;
  if (!opt.plugin_dirs.empty()) {
    // Before the backend: reopened projects may need their loader plugins.
    if (!revkit::plugins::Host::available())
      std::cerr << "rk-daemon: built without the WebAssembly runtime (REVKIT_PLUGINS=OFF); plugins will not load\n";
    revkit::plugins::HostOptions ho;
    ho.grants = opt.plugin_grants;
    image.plugins = std::make_shared<revkit::plugins::Host>(ho);
    for (const std::string &dir : opt.plugin_dirs) {
      for (const auto &r : image.plugins->load_dir(dir))
        std::cerr << "rk-daemon: plugin rejected: " << r.error << "\n";
    }
    for (const auto &p : image.plugins->plugins()) {
      std::cerr << "rk-daemon: plugin " << p->id() << " (" << revkit::plugins::to_string(p->manifest().kind);
      for (revkit::plugins::Capability c : p->granted()) std::cerr << ", " << revkit::plugins::to_string(c);
      std::cerr << ")\n";
    }
  }
  std::shared_ptr<revkit::api::Backend> backend = revkit::backend::MakeImageBackend(image);
  std::set<std::string> have;  // reopened from --project-dir
  {
    revkit::api::CallContext ctx;
    revkit::v1::ListProgramsRequest req;
    req.set_project_id(image.default_project);
    revkit::v1::ListProgramsResponse resp;
    if (backend->ListPrograms(ctx, req, resp).ok())
      for (const auto &p : resp.programs()) {
        have.insert(p.name());
        std::cerr << "rk-daemon: reopened " << p.program_id() << "\n";
      }
  }
  for (const std::string &path : opt.open) {
    const std::string name = std::filesystem::path(path).filename().string();
    if (have.contains(name)) {
      std::cerr << "rk-daemon: " << path << " is already in the project as " << image.default_project << "/" << name << "\n";
      continue;
    }
    revkit::api::CallContext ctx;
    revkit::v1::ImportProgramRequest req;
    req.set_project_id(image.default_project);
    req.set_path(path);
    req.mutable_provenance()->set_tool("rk-daemon --open");
    revkit::v1::ImportProgramResponse resp;
    auto st = backend->ImportProgram(ctx, req, resp);
    if (!st.ok()) throw std::runtime_error(path + ": " + st.message);
    std::cerr << "rk-daemon: opened " << path << " as " << resp.program().program_id() << " ("
              << resp.program().language_id() << ")\n";
    for (const auto &w : resp.warnings()) std::cerr << "rk-daemon:   warning: " << w << "\n";
  }
  return backend;
}


// ------------------------------------------------------------ subcommands --

// A password from the terminal (asked twice, not echoed) or, with
// --password-stdin or when stdin is not a terminal, stdin's first line.
std::string read_password(bool from_stdin, bool confirm) {
  auto line = [] {
    std::string s;
    std::getline(std::cin, s);
    if (!s.empty() && s.back() == '\r') s.pop_back();
    return s;
  };
  if (from_stdin || !::isatty(STDIN_FILENO)) return line();
  auto ask = [&](const char *prompt) {
    std::cerr << prompt << std::flush;
    termios old {};
    ::tcgetattr(STDIN_FILENO, &old);
    termios quiet = old;
    quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    ::tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
    std::string s = line();
    ::tcsetattr(STDIN_FILENO, TCSANOW, &old);
    std::cerr << "\n";
    return s;
  };
  std::string pw = ask("Password: ");
  if (confirm && ask("Again: ") != pw) throw std::runtime_error("the passwords differ");
  return pw;
}

std::string format_time(std::int64_t t) {
  if (!t) return "never";
  std::time_t tt = static_cast<std::time_t>(t);
  char buf[32];
  std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M", std::localtime(&tt));
  return buf;
}

std::string projects_text(const std::vector<std::string> &p) {
  if (p.empty()) return "*";
  std::string out;
  for (const auto &x : p) out += (out.empty() ? "" : ",") + x;
  return out;
}

int admin_usage() {
  std::cerr << "usage: rk-daemon user add|passwd|role|projects|del|list ..., rk-daemon token create|list|revoke ...,\n"
               "       rk-daemon tls fingerprint (rk-daemon --help for details)\n";
  return 2;
}

// rk-daemon user|token|tls ...: manage the credential file a daemon uses
// (a running daemon notices within a second).
int run_admin(int argc, char **argv) {
  const std::string group = argv[1];
  std::vector<std::string> pos;
  std::string project_dir, auth_file, role, user, name, projects, tls_cert, tls_dir;
  bool projects_set = false, password_stdin = false;
  double ttl_days = 0;
  for (int i = 2; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&]() -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(std::string(a) + " needs a value");
      return argv[++i];
    };
    if (a == "--project-dir") project_dir = value();
    else if (a == "--auth-file") auth_file = value();
    else if (a == "--role") role = value();
    else if (a == "--user") user = value();
    else if (a == "--name") name = value();
    else if (a == "--projects") projects = value(), projects_set = true;
    else if (a == "--ttl-days") ttl_days = std::stod(value());
    else if (a == "--password-stdin") password_stdin = true;
    else if (a == "--tls-cert") tls_cert = value();
    else if (a == "--tls-dir") tls_dir = value();
    else if (a.starts_with("--")) throw std::runtime_error("unknown option " + std::string(a));
    else pos.emplace_back(a);
  }
  if (pos.empty()) return admin_usage();
  const std::string cmd = pos[0];
  auto parse_role = [](const std::string &r) {
    auto x = revkit::auth::role_from_string(r);
    if (!x) throw std::runtime_error("unknown role \"" + r + "\" (viewer, editor, admin" + ", peer for tokens)");
    return *x;
  };
  auto project_list = [&](const std::string &p) {
    return p == "*" ? std::vector<std::string>{} : split_list(p);
  };

  if (group == "tls") {
    if (cmd != "fingerprint") return admin_usage();
    const std::string cert = !tls_cert.empty() ? tls_cert : tls_dir_for(tls_dir, project_dir) + "/cert.pem";
    std::string fp = revkit::auth::fingerprint_sha256(read_text(cert));
    if (fp.empty()) throw std::runtime_error(cert + " is not a PEM certificate");
    std::cout << fp << "\n";
    return 0;
  }

  revkit::auth::StoreOptions so;
  so.path = auth_file_for(auth_file, project_dir);
  revkit::auth::Store store(so);
  if (group == "user") {
    auto need_name = [&] {
      if (pos.size() < 2) throw std::runtime_error("rk-daemon user " + cmd + " needs an account name");
      return pos[1];
    };
    if (cmd == "add") {
      const std::string n = need_name();
      if (role.empty()) throw std::runtime_error("rk-daemon user add needs --role viewer|editor|admin");
      auto r = parse_role(role);
      std::string pw = read_password(password_stdin, true);
      auto u = store.add_user(n, r, pw, projects_set ? project_list(projects) : std::vector<std::string>{});
      std::cerr << "rk-daemon: account " << u.name << " (" << revkit::auth::to_string(u.role) << ", projects "
                << projects_text(u.projects) << ") in " << store.path() << "\n";
    } else if (cmd == "passwd") {
      const std::string n = need_name();
      std::string pw = read_password(password_stdin, true);
      store.update_user(n, std::nullopt, pw, std::nullopt);
      std::cerr << "rk-daemon: new password for " << n << "; its sessions have ended\n";
    } else if (cmd == "role") {
      const std::string n = need_name();
      if (pos.size() < 3) throw std::runtime_error("rk-daemon user role <name> viewer|editor|admin");
      store.update_user(n, parse_role(pos[2]), std::nullopt, std::nullopt);
      std::cerr << "rk-daemon: " << n << " is now " << pos[2] << "; its sessions have ended\n";
    } else if (cmd == "projects") {
      const std::string n = need_name();
      if (pos.size() < 3) throw std::runtime_error("rk-daemon user projects <name> <a,b | *>");
      auto u = store.update_user(n, std::nullopt, std::nullopt, project_list(pos[2]));
      std::cerr << "rk-daemon: " << n << " may use projects " << projects_text(u.projects) << "\n";
    } else if (cmd == "del") {
      const std::string n = need_name();
      store.delete_user(n);
      std::cerr << "rk-daemon: deleted account " << n << " with its sessions and tokens\n";
    } else if (cmd == "list") {
      for (const auto &u : store.users())
        std::cout << u.name << "\t" << revkit::auth::to_string(u.role) << "\tprojects " << projects_text(u.projects)
                  << "\tcreated " << format_time(u.created_at) << "\n";
    } else {
      return admin_usage();
    }
    return 0;
  }
  if (group == "token") {
    if (cmd == "create") {
      if (name.empty() && pos.size() > 1) name = pos[1];
      if (name.empty() || role.empty()) throw std::runtime_error("rk-daemon token create needs --name and --role");
      auto t = store.create_token(name, parse_role(role), user, projects_set ? project_list(projects) : std::vector<std::string>{},
                                  static_cast<std::int64_t>(ttl_days * 86400));
      std::cerr << "rk-daemon: token " << t.record.name << " (id " << t.record.id << ", "
                << revkit::auth::to_string(t.record.role)
                << (t.record.user.empty() ? ", edits as agent:" + t.record.name : ", acts as user:" + t.record.user)
                << ", expires " << format_time(t.record.expires_at) << "). The secret, shown once:\n";
      std::cout << t.secret << "\n";
    } else if (cmd == "list") {
      for (const auto &t : store.tokens())
        std::cout << t.id << "\t" << t.name << "\t" << revkit::auth::to_string(t.role) << "\t"
                  << (t.user.empty() ? "agent:" + t.name : "user:" + t.user) << "\tprojects " << projects_text(t.projects)
                  << "\texpires " << format_time(t.expires_at) << "\n";
    } else if (cmd == "revoke") {
      if (pos.size() < 2) throw std::runtime_error("rk-daemon token revoke <id or name>");
      if (!store.revoke_token(pos[1])) throw std::runtime_error("no token \"" + pos[1] + "\"");
      std::cerr << "rk-daemon: revoked " << pos[1] << "\n";
    } else {
      return admin_usage();
    }
    return 0;
  }
  return admin_usage();
}

// ------------------------------------------------------------------ peers --

struct PeerSpec {
  std::string target;
  std::string token;
  bool tls = false;
  std::string root_pem;
  std::string fingerprint;
  std::string server_name;
};

PeerSpec parse_peer(const Options &opt, const std::string &arg) {
  auto parts = split_list(arg);
  if (parts.empty()) throw std::runtime_error("empty --peer");
  PeerSpec p;
  p.target = parts[0];
  std::string token_file = opt.peer_token_file, ca = opt.peer_ca;
  p.fingerprint = opt.peer_fingerprint;
  p.server_name = opt.peer_server_name;
  p.tls = opt.peer_tls;
  for (std::size_t i = 1; i < parts.size(); ++i) {
    const std::string &kv = parts[i];
    auto eq = kv.find('=');
    std::string k = kv.substr(0, eq), v = eq == std::string::npos ? "" : kv.substr(eq + 1);
    if (k == "token-file") token_file = v;
    else if (k == "ca") ca = v;
    else if (k == "fingerprint") p.fingerprint = v;
    else if (k == "server-name") p.server_name = v;
    else if (k == "tls") p.tls = true;
    else throw std::runtime_error("--peer " + arg + ": unknown option \"" + k + "\"");
  }
  if (!token_file.empty()) p.token = read_secret(token_file);
  else if (!opt.peer_secret_file.empty()) p.token = read_secret(opt.peer_secret_file);
  if (!ca.empty()) p.root_pem = read_text(ca), p.tls = true;
  if (!p.fingerprint.empty()) p.tls = true;
  return p;
}

// Links to peers; one whose certificate is pinned by fingerprint is linked
// once its certificate has been fetched and checked (it may start later).
class Peers {
 public:
  Peers(std::shared_ptr<revkit::api::Backend> backend, std::string name) : backend_(std::move(backend)), name_(std::move(name)) {}
  ~Peers() { stop(); }

  void add(PeerSpec spec) {
    if (spec.fingerprint.empty()) return link(spec);
    threads_.emplace_back([this, spec]() mutable {
      std::string host;
      int port = 0;
      auto colon = spec.target.rfind(':');
      host = spec.target.substr(0, colon);
      if (host.size() > 2 && host.front() == '[') host = host.substr(1, host.size() - 2);
      try {
        port = std::stoi(spec.target.substr(colon + 1));
      } catch (...) {
        std::cerr << "rk-daemon: --peer " << spec.target << ": want host:port\n";
        return;
      }
      for (auto wait = std::chrono::milliseconds(200);; wait = std::min(wait * 2, std::chrono::milliseconds(5000))) {
        std::string err;
        auto pem = revkit::auth::fetch_server_certificate(host, port, err);
        if (pem && revkit::auth::fingerprint_matches(*pem, spec.fingerprint)) {
          spec.root_pem = *pem;
          if (spec.server_name.empty()) spec.server_name = "localhost";  // every rk-daemon self-signed cert has it
          link(spec);
          return;
        }
        if (pem)
          std::cerr << "rk-daemon: peer " << spec.target << " presents certificate " << revkit::auth::fingerprint_sha256(*pem)
                    << ", not the pinned " << spec.fingerprint << "; not linking\n";
        std::unique_lock lock(mu_);
        if (cv_.wait_for(lock, wait, [&] { return stop_; })) return;
      }
    });
  }

  void stop() {
    {
      std::lock_guard lock(mu_);
      stop_ = true;
    }
    cv_.notify_all();
    for (auto &t : threads_) t.join();
    threads_.clear();
    std::lock_guard lock(mu_);
    links_.clear();
  }

 private:
  void link(const PeerSpec &spec) {
    revkit::api::PeerLinkOptions po;
    po.target = spec.target;
    po.name = name_;
    po.verbose = true;
    po.bearer_token = spec.token;
    po.tls = spec.tls;
    po.tls_root_pem = spec.root_pem;
    po.tls_server_name = spec.server_name;
    std::lock_guard lock(mu_);
    if (stop_) return;
    links_.push_back(std::make_unique<revkit::api::PeerLink>(backend_, po));
    std::cerr << "rk-daemon: replicating with peer " << links_.back()->target() << (spec.tls ? " over TLS" : "")
              << (spec.token.empty() ? "" : ", authenticated") << "\n";
  }

  std::shared_ptr<revkit::api::Backend> backend_;
  std::string name_;
  std::mutex mu_;
  std::condition_variable cv_;
  bool stop_ = false;
  std::vector<std::thread> threads_;
  std::vector<std::unique_ptr<revkit::api::PeerLink>> links_;
};

// Holds <project-dir>/.revkit/lock for the life of the process, so two
// daemons (or a daemon and `rk-daemon project`) never open one project
// directory (docs/backend.md, "Persistence").
bool lock_project_dir(const std::string &dir, std::string &error) {
  if (dir.empty()) return true;
  std::error_code ec;
  const auto meta = std::filesystem::path(dir) / ".revkit";
  std::filesystem::create_directories(meta, ec);
  const std::string path = (meta / "lock").string();
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    error = "cannot open " + path;
    return false;
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    ::close(fd);
    error = "another rk-daemon is using the project directory " + dir + " (it holds " + path + ")";
    return false;
  }
  return true;  // the descriptor stays open: the lock lasts as long as the process
}

int project_usage() {
  std::cerr << "usage: rk-daemon project export --project-dir <dir> [--project <id>] [--program <id>]... [--folder </path>]...\n"
               "                                [--annotations-only] -o <file.rkproj>\n"
               "       rk-daemon project import --project-dir <dir> <file.rkproj> [--into <project id> [--folder </path>]]\n"
               "                                [--name <new project>] [--binary <file>]... [--search-dir <dir>]\n"
               "                                [--skip-missing] [--inspect]\n"
               "       rk-daemon project import-batch --project-dir <dir> <path> [--into <project id>] [--folder </path>]\n"
               "                                [--recursive] [--no-descend] [--detect-raw] [--max <n>] [--preview]\n"
               "                                [--keep-folders] [--analyze]\n";
  return 2;
}

// A folder's id from its path in a project ("/" is the root).
std::string folder_id_of(revkit::api::Backend &backend, const std::string &project, const std::string &path) {
  if (path.empty() || path == "/") return "";
  revkit::api::CallContext ctx;
  revkit::v1::ListProgramsRequest req;
  req.set_project_id(project);
  revkit::v1::ListProgramsResponse resp;
  auto st = backend.ListPrograms(ctx, req, resp);
  if (!st.ok()) throw std::runtime_error(st.message);
  const std::string want = path.size() > 1 && path.back() == '/' ? path.substr(0, path.size() - 1) : path;
  for (const auto &f : resp.folders())
    if (f.path() == want) return f.folder_id();
  throw std::runtime_error("no folder " + path + " in project " + project);
}

std::string size_text(std::uint64_t n) {
  char buf[32];
  if (n >= (1u << 20)) std::snprintf(buf, sizeof buf, "%.1f MB", static_cast<double>(n) / (1 << 20));
  else std::snprintf(buf, sizeof buf, "%.1f KB", static_cast<double>(n) / 1024);
  return buf;
}

std::shared_ptr<revkit::api::Backend> make_backend(const Options &opt);

// rk-daemon project import-batch: the programs in a host directory or a
// container (and the containers inside, unless --no-descend) into a
// project, through FileSystemService as a daemon would serve it
// (docs/filesystems.md, "Batch import").
int import_batch(revkit::api::Backend &backend, const revkit::api::CallContext &ctx, const Options &opt,
                 const std::string &path, const std::string &project, const std::string &folder, bool recursive,
                 bool descend, bool detect_raw, bool preview, bool keep_folders, bool analyze, std::uint32_t max) {
  namespace pb = revkit::v1;
  bool have = false;
  {
    pb::ListProjectsResponse listed;
    if (backend.ListProjects(ctx, pb::ListProjectsRequest(), listed).ok())
      for (const auto &p : listed.projects()) have = have || (p.project_id() == project && p.open());
  }
  if (!have) {
    // The project, made if missing (as a daemon's --project-dir keeps them).
    pb::OpenProjectRequest req;
    req.set_path((std::filesystem::path(opt.project_dir) / project).string());
    req.set_create_if_missing(true);
    req.set_name(project);
    pb::OpenProjectResponse resp;
    auto st = backend.OpenProject(ctx, req, resp);
    if (!st.ok()) throw std::runtime_error("project " + project + ": " + st.message);
    if (resp.project().project_id() != project)
      throw std::runtime_error("the project at " + req.path() + " is " + resp.project().project_id() + ", not " + project);
  }
  std::error_code ec;
  const std::filesystem::path abs = std::filesystem::absolute(path, ec);
  if (!std::filesystem::exists(abs, ec)) throw std::runtime_error("no such file or directory: " + path);
  pb::OpenFileSystemRequest open;
  open.set_project_id(project);
  open.set_host_path(abs.string());
  pb::OpenFileSystemResponse opened;
  std::vector<std::string> paths{"/"};
  auto st = backend.OpenFileSystem(ctx, open, opened);
  if (!st.ok() && std::filesystem::is_regular_file(abs, ec)) {
    // A file that isn't a container (an ELF): from its directory.
    open.set_host_path(abs.parent_path().string());
    st = backend.OpenFileSystem(ctx, open, opened);
    paths = {"/" + revkit::container::encode_component(abs.filename().string())};
  }
  if (!st.ok()) throw std::runtime_error(path + ": " + st.message);
  std::cout << (preview ? "preview of " : "importing from ") << path << " (" << opened.root().description() << ") into "
            << project << (folder.empty() ? "" : folder) << "\n";
  pb::ImportFromFileSystemRequest req;
  req.set_session_id(opened.session_id());
  req.set_project_id(project);
  if (!folder.empty() && folder != "/") {
    std::string id;
    try {
      id = folder_id_of(backend, project, folder);
    } catch (const std::runtime_error &) {
      // Made, with its parents.
      std::string parent, sofar;
      for (const auto &part : std::filesystem::path(folder)) {
        const std::string name = part.string();
        if (name.empty() || name == "/") continue;
        sofar += "/" + name;
        try {
          parent = folder_id_of(backend, project, sofar);
        } catch (const std::runtime_error &) {
          pb::CreateFolderRequest cr;
          cr.set_project_id(project);
          cr.set_parent_id(parent);
          cr.set_name(name);
          cr.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
          cr.mutable_provenance()->set_id(ctx.caller.substr(5));
          pb::CreateFolderResponse cf;
          if (auto s = backend.CreateFolder(ctx, cr, cf); !s.ok()) throw std::runtime_error(s.message);
          parent = cf.folder().folder_id();
        }
      }
      id = parent;
    }
    req.set_folder_id(id);
  }
  for (const auto &p : paths) req.add_paths(p);
  req.set_recursive(recursive);
  req.set_descend(descend);
  req.set_programs_only(paths.size() == 1 && paths[0] == "/");
  req.set_detect_raw(detect_raw);
  req.set_preview(preview);
  req.set_max_programs(max);
  req.set_keep_folders(keep_folders);
  req.mutable_options()->set_analyze(analyze);
  req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id(ctx.caller.substr(5));
  req.mutable_provenance()->set_tool("rk-daemon project import-batch");
  pb::ImportFromFileSystemResponse resp;
  st = backend.ImportFromFileSystem(ctx, req, resp);
  pb::CloseFileSystemRequest close;
  close.set_session_id(opened.session_id());
  pb::CloseFileSystemResponse closed;
  (void)backend.CloseFileSystem(ctx, close, closed);
  if (!st.ok()) throw std::runtime_error(st.message);
  for (const auto &i : resp.items()) {
    std::cout << "  " << i.action() << "  " << i.container_path();
    if (i.program().program_id().size()) std::cout << "  -> " << i.program().program_id() << " in " << i.program().folder_path();
    if (!i.language_id().empty()) std::cout << "  (" << i.language_id() << ")";
    if (!i.reason().empty()) std::cout << "  (" << i.reason() << ")";
    std::cout << "\n";
  }
  std::uint32_t would = 0;
  for (const auto &i : resp.items()) would += i.action() == "import";
  if (preview)
    std::cout << would << " program" << (would == 1 ? "" : "s") << " would be imported, " << resp.skipped()
              << " other file" << (resp.skipped() == 1 ? "" : "s") << " left out" << (resp.capped() ? " (capped)" : "")
              << "\n";
  else
    std::cout << resp.imported() << " imported, " << resp.skipped() << " skipped, " << resp.failed() << " failed"
              << (resp.capped() ? " (capped: --max)" : "") << "\n";
  return resp.failed() ? 1 : 0;
}

// rk-daemon project export|import: archives of a --project-dir's projects,
// through the image backend in this process (as a daemon would serve them).
int run_project(int argc, char **argv) {
  if (argc < 3) return project_usage();
  const std::string cmd = argv[2];
  Options opt;
  opt.decompilers = 1;
  std::string project, into, output, name, search_dir;
  std::vector<std::string> programs, folders, binaries, positional;
  bool annotations = false, skip_missing = false, inspect = false;
  bool recursive = false, descend = true, detect_raw = false, preview = false, keep_folders = false, analyze = false;
  std::uint32_t max_programs = 0;
  for (int i = 3; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&]() -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(std::string(a) + " needs a value");
      return argv[++i];
    };
    if (a == "--project-dir") opt.project_dir = value();
    else if (a == "--ghidra") opt.ghidra_root = value();
    else if (a == "--project") project = value();
    else if (a == "--program") programs.push_back(value());
    else if (a == "--folder") folders.push_back(value());
    else if (a == "--annotations-only") annotations = true;
    else if (a == "-o" || a == "--output") output = value();
    else if (a == "--into") into = value();
    else if (a == "--name") name = value();
    else if (a == "--binary") binaries.push_back(value());
    else if (a == "--search-dir") search_dir = value();
    else if (a == "--skip-missing") skip_missing = true;
    else if (a == "--inspect") inspect = true;
    else if (a == "--recursive") recursive = true;
    else if (a == "--no-descend") descend = false;
    else if (a == "--detect-raw") detect_raw = true;
    else if (a == "--preview") preview = true;
    else if (a == "--keep-folders") keep_folders = true;
    else if (a == "--analyze") analyze = true;
    else if (a == "--max") max_programs = static_cast<std::uint32_t>(std::stoul(value()));
    else if (a == "--plugin-dir") opt.plugin_dirs.push_back(value());
    else if (a.starts_with("-")) throw std::runtime_error("unknown option " + std::string(a));
    else positional.emplace_back(a);
  }
  if (opt.project_dir.empty() || (cmd != "export" && cmd != "import" && cmd != "import-batch")) return project_usage();
  std::string error;
  if (!lock_project_dir(opt.project_dir, error)) throw std::runtime_error(error);
  auto backend = make_backend(opt);
  revkit::api::CallContext ctx;
  ctx.caller = "user:" + std::string(std::getenv("USER") ? std::getenv("USER") : "cli");
  if (cmd == "export") {
    if (output.empty() || !positional.empty()) return project_usage();
    if (project.empty()) project = "default";
    revkit::v1::ExportProjectRequest req;
    req.set_project_id(project);
    for (const auto &p : programs) req.add_program_ids(p.find('/') == std::string::npos ? project + "/" + p : p);
    for (const auto &f : folders) {
      const std::string id = folder_id_of(*backend, project, f);
      if (id.empty()) throw std::runtime_error("--folder / is the whole project: leave --folder out");
      req.add_folder_ids(id);
    }
    req.set_annotations_only(annotations);
    req.set_host_path(std::filesystem::absolute(output).string());
    revkit::v1::ExportSummary summary;
    auto st = backend->ExportProject(ctx, req, [&](const revkit::v1::ExportProjectResponse &r) {
      if (r.has_summary()) summary = r.summary();
      return true;
    });
    if (!st.ok()) throw std::runtime_error(st.message);
    const auto &m = summary.manifest();
    std::cout << "wrote " << output << " (" << size_text(summary.size()) << "): " << m.programs_size() << " program"
              << (m.programs_size() == 1 ? "" : "s") << ", " << m.folders_size() << " folder"
              << (m.folders_size() == 1 ? "" : "s") << ", " << m.log().count() << " ops"
              << (m.annotations_only() ? ", annotations only" : "") << "\n";
    for (const auto &p : m.programs())
      std::cout << "  " << p.folder() << (p.folder() == "/" ? "" : "/") << p.name() << "  " << p.sha256().substr(0, 16)
                << "  " << p.op_count() << " ops\n";
    return 0;
  }
  if (cmd == "import-batch") {
    if (positional.size() != 1) return project_usage();
    return import_batch(*backend, ctx, opt, positional[0], into.empty() ? "default" : into,
                        folders.empty() ? "" : folders.back(), recursive, descend, detect_raw, preview, keep_folders,
                        analyze, max_programs);
  }
  if (positional.size() != 1) return project_usage();
  revkit::v1::ImportProjectArchiveRequest req;
  req.mutable_archive()->set_path(std::filesystem::absolute(positional[0]).string());
  req.set_project_id(into);
  req.set_new_project_name(name);
  if (!folders.empty()) {
    if (into.empty()) throw std::runtime_error("--folder is a folder of the --into project");
    req.set_folder_id(folder_id_of(*backend, into, folders.back()));
  }
  for (const auto &b : binaries) req.add_binaries()->set_path(std::filesystem::absolute(b).string());
  if (!search_dir.empty()) req.set_search_dir(std::filesystem::absolute(search_dir).string());
  req.set_skip_missing(skip_missing);
  req.set_inspect_only(inspect);
  req.mutable_provenance()->set_kind(revkit::v1::PROVENANCE_KIND_USER);
  req.mutable_provenance()->set_id(ctx.caller.substr(5));
  req.mutable_provenance()->set_tool("rk-daemon project import");
  revkit::v1::ImportProjectArchiveResponse resp;
  auto st = backend->ImportProjectArchive(ctx, req, resp);
  if (!st.ok()) throw std::runtime_error(st.message);
  const auto &m = resp.manifest();
  std::cout << (inspect ? "archive" : "imported") << " \"" << m.project_name() << "\" (" << m.created_by()
            << (m.annotations_only() ? ", annotations only" : "") << ")";
  if (!inspect) std::cout << " into project " << resp.project().project_id();
  std::cout << "\n";
  for (const auto &p : resp.programs()) {
    std::cout << "  " << p.name() << "  ";
    if (p.skipped()) std::cout << "skipped: binary not found";
    else if (p.binary_source().empty()) std::cout << "binary not found (sha256 " << p.sha256() << ")";
    else if (inspect) std::cout << "binary: " << p.binary_source();
    else std::cout << "-> " << p.program().program_id() << " in " << p.program().folder_path() << " (binary: " << p.binary_source() << ")";
    std::cout << "\n";
  }
  for (const auto &w : resp.warnings()) std::cerr << "rk-daemon: warning: " << w << "\n";
  return 0;
}

// MetaService.RestartDaemon (docs/ui.md, "Restart daemon"): the handler
// asks for a restart, the signal thread shuts the server down as for
// SIGTERM, main returns (destroying the server, the peers and the backend:
// projects saved, workers stopped), and this exit handler runs the daemon
// again in the same process with the same argv and environment. Under
// socket activation it exits instead, and systemd starts the daemon again
// on the next connection to the socket it keeps.
struct Restart {
  std::atomic<bool> requested{false};
  bool exit_only = false;  // socket activation
  std::string exe;         // /proc/self/exe at start (the binary's path)
  std::vector<std::string> argv;
};
Restart &restart_state() {
  static Restart r;
  return r;
}

void reexec_at_exit() {
  Restart &r = restart_state();
  if (!r.requested) return;
  if (r.exit_only) {
    std::cerr << "rk-daemon: restart: exited; systemd starts the daemon again on the next connection" << std::endl;
    return;
  }
  // Nothing but stdin, stdout and stderr crosses: listeners, the project
  // lock and pipes close on exec (they may lack O_CLOEXEC).
  if (DIR *d = ::opendir("/proc/self/fd")) {
    const int self = ::dirfd(d);
    while (dirent *e = ::readdir(d)) {
      const int fd = std::atoi(e->d_name);
      if (fd > 2 && fd != self) ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    ::closedir(d);
  }
  std::vector<char *> args;
  for (std::string &a : r.argv) args.push_back(a.data());
  args.push_back(nullptr);
  std::cerr << "rk-daemon: restart: running " << r.exe << " again" << std::endl;
  ::execv(r.exe.c_str(), args.data());
  const int err = errno;
  // The binary moved or was replaced by something unrunnable: the running image.
  ::execv("/proc/self/exe", args.data());
  std::cerr << "rk-daemon: restart failed: can't run " << r.exe << ": " << std::strerror(err) << std::endl;
  std::_Exit(1);
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-daemon")) return 0;
  if (argc >= 2 && std::string_view(argv[1]) == "project") {
    try {
      return run_project(argc, argv);
    } catch (const std::exception &e) {
      std::cerr << "rk-daemon: " << e.what() << "\n";
      return 1;
    }
  }
  if (argc >= 2 && (std::string_view(argv[1]) == "user" || std::string_view(argv[1]) == "token" ||
                    std::string_view(argv[1]) == "tls")) {
    try {
      return run_admin(argc, argv);
    } catch (const std::exception &e) {
      std::cerr << "rk-daemon: " << e.what() << "\n";
      return 1;
    }
  }
  auto opt = parse_args(argc, argv);
  if (!opt) {
    usage(std::cerr);
    return 2;
  }
  opt->server.launch_args.assign(argv, argv + argc);

  // Socket activation (systemd, docs/packaging.md): the HTTP listener the
  // service manager opened. Taken first, so no child process inherits it.
  {
    std::vector<revkit::api::InheritedSocket> inherited;
    std::string error;
    if (!revkit::api::TakeListenFds(inherited, error)) {
      std::cerr << "rk-daemon: socket activation: " << error << "\n";
      return 1;
    }
    for (const auto &s : inherited) {
      if (s.name == "grpc") {
        std::cerr << "rk-daemon: socket activation: an inherited gRPC socket is not supported; give --grpc "
                     "(the daemon binds it when it starts)\n";
        return 1;
      }
      if (opt->server.http_fd >= 0) {
        std::cerr << "rk-daemon: socket activation: more than one inherited socket (" << s.address
                  << "); rk-daemon takes one, for HTTP\n";
        return 1;
      }
      if (opt->server.http_address.empty()) {
        std::cerr << "rk-daemon: socket activation: an inherited socket, but --no-http\n";
        return 1;
      }
      opt->server.http_fd = s.fd;
      opt->server.http_address = s.address;
      std::cerr << "rk-daemon: HTTP on the socket the service manager passed, " << s.address << "\n";
    }
  }

  // Accounts or none: the flags, a saved choice, or (once, on a terminal)
  // the user's answer (tools/rk-daemon/auth_choice.h).
  try {
    revkit::daemon::AuthChoiceInput in;
    in.no_auth_flag = opt->no_auth;
    in.auth_flag = opt->auth || !opt->auth_file.empty();
    in.ask_flag = opt->ask;
    in.interactive = ::isatty(STDIN_FILENO) && ::isatty(STDERR_FILENO);
    in.config_files = revkit::runtime::config_files();
    if (!in.config_files.empty() && in.config_files.front() != "/etc/revkit/revkit.conf")
      in.user_config = in.config_files.front();
    revkit::auth::StoreOptions so;
    so.path = auth_file_for(opt->auth_file, opt->project_dir);
    in.no_accounts = [so] { return revkit::auth::Store(so).empty(); };
    in.create_admin = [so](const std::string &name, const std::string &password) {
      revkit::auth::Store store(so);
      store.add_user(name, revkit::auth::Role::kAdmin, password, {});
    };
    revkit::daemon::TerminalPrompter prompter;
    const revkit::daemon::AuthChoice choice = revkit::daemon::choose_auth(in, prompter);
    opt->no_auth = choice.mode == revkit::daemon::AuthMode::none;
    std::cerr << "rk-daemon: " << revkit::daemon::describe(choice) << "\n";
  } catch (const std::exception &e) {
    std::cerr << "rk-daemon: " << e.what() << "\n";
    return 1;
  }

  // Block termination signals in every thread (gRPC and HTTP threads inherit
  // the mask) and take them synchronously on a dedicated thread instead, so
  // shutdown runs as ordinary code rather than in a signal handler.
  sigset_t signals;
  sigemptyset(&signals);
  sigaddset(&signals, SIGINT);
  sigaddset(&signals, SIGTERM);
  pthread_sigmask(SIG_BLOCK, &signals, nullptr);

  std::shared_ptr<revkit::api::Backend> backend;
  try {
    std::string error;
    if (opt->backend == "image" && !lock_project_dir(opt->project_dir, error)) throw std::runtime_error(error);
    backend = make_backend(*opt);
  } catch (const std::exception &e) {
    std::cerr << "rk-daemon: " << e.what() << "\n";
    return 1;
  }
  // Authentication and TLS, before anything listens.
  try {
    if (!opt->no_auth) {
      revkit::auth::StoreOptions so;
      so.path = auth_file_for(opt->auth_file, opt->project_dir);
      so.session_ttl_seconds = static_cast<std::int64_t>(opt->session_ttl_hours * 3600);
      if (!opt->peer_secret_file.empty()) so.peer_secret = read_secret(opt->peer_secret_file);
      opt->server.auth = std::make_shared<revkit::auth::Store>(so);
      std::cerr << "rk-daemon: accounts and tokens in " << so.path << "\n";
      if (opt->server.auth->empty())
        std::cerr << "rk-daemon: no accounts or tokens yet; create one with\n"
                  << "rk-daemon:   rk-daemon user add <name> --role admin"
                  << (opt->auth_file.empty() && !opt->project_dir.empty() ? " --project-dir " + opt->project_dir : "")
                  << (opt->auth_file.empty() ? "" : " --auth-file " + opt->auth_file) << "\n";
    } else {
      std::cerr << "rk-daemon: every caller is an anonymous admin (loopback only)\n";
    }
    if (!opt->tls_cert.empty()) {
      opt->server.tls = {read_text(opt->tls_cert), read_text(opt->tls_key)};
      std::string err;
      if (!revkit::auth::check_cert_key({opt->server.tls.cert_pem, opt->server.tls.key_pem}, err))
        throw std::runtime_error("--tls-cert/--tls-key: " + err);
    } else if (opt->tls_self_signed) {
      std::vector<std::string> hosts = opt->tls_sans;
      for (const std::string *a : {&opt->server.grpc_address, &opt->server.http_address}) {
        std::string h = a->substr(0, a->rfind(':'));
        if (h.size() > 2 && h.front() == '[') h = h.substr(1, h.size() - 2);
        if (!a->empty() && !h.empty()) hosts.push_back(h);
      }
      char hostname[256] = {};
      if (::gethostname(hostname, sizeof hostname - 1) == 0 && *hostname) hosts.emplace_back(hostname);
      const std::string dir = tls_dir_for(opt->tls_dir, opt->project_dir);
      bool created = false;
      auto ck = revkit::auth::load_or_create_self_signed(dir, hosts, created);
      opt->server.tls = {ck.cert_pem, ck.key_pem};
      std::cerr << "rk-daemon: " << (created ? "created" : "using") << " self-signed certificate " << dir << "/cert.pem\n";
      auto names = revkit::auth::certificate_hosts(ck.cert_pem);
      for (const auto &h : hosts)
        if (h != "0.0.0.0" && h != "::" && std::find(names.begin(), names.end(), h) == names.end())
          std::cerr << "rk-daemon: warning: the certificate does not name " << h
                    << " (remove " << dir << " to make a new one; clients pinning it then need the new fingerprint)\n";
    }
    if (opt->server.tls.enabled())
      std::cerr << "rk-daemon: TLS certificate SHA-256 fingerprint "
                << revkit::auth::fingerprint_sha256(opt->server.tls.cert_pem) << "\n";
  } catch (const std::exception &e) {
    std::cerr << "rk-daemon: " << e.what() << "\n";
    return 1;
  }
  // allow-host = NAME lines in revkit.conf add to --allow-host.
  for (const auto &file : revkit::runtime::config_files())
    for (std::string &h : revkit::runtime::config_values(file, "allow-host"))
      opt->server.allowed_hosts.push_back(std::move(h));
  opt->server.insecure_allow_remote = opt->insecure_allow_remote;
  if (opt->insecure_allow_remote && !opt->server.tls.enabled()) {
    for (const std::string *a : {&opt->server.grpc_address, &opt->server.http_address})
      if (!a->empty() && !revkit::api::IsLoopbackAddress(*a))
        std::cerr << "rk-daemon: ******************************************************************\n"
                  << "rk-daemon: WARNING: plaintext on " << *a << " (--insecure-allow-remote).\n"
                  << "rk-daemon: Passwords, session cookies and tokens cross the network in the\n"
                  << "rk-daemon: clear; anyone on the path can read and replay them. Use TLS\n"
                  << "rk-daemon: (--tls-self-signed) unless the network itself is encrypted.\n"
                  << "rk-daemon: ******************************************************************\n";
  }

  // RestartDaemon: shut down as for SIGTERM, then run again (reexec_at_exit).
  {
    Restart &r = restart_state();
    r.exit_only = opt->server.http_fd >= 0;
    // The mode decided at this start stays: a restart neither asks again
    // (--ask, or a first-run answer not remembered) nor changes it.
    bool mode_given = false;
    for (const std::string &a : opt->server.launch_args) {
      if (a == "--ask") continue;
      mode_given |= a == "--no-auth" || a == "--auth" || a == "--auth-file";
      r.argv.push_back(a);
    }
    if (!mode_given) r.argv.emplace_back(opt->no_auth ? "--no-auth" : "--auth");
    std::error_code ec;
    r.exe = std::filesystem::read_symlink("/proc/self/exe", ec).string();
    if (ec || r.exe.empty()) r.exe = "/proc/self/exe";
    opt->server.restart_mode = r.exit_only ? "exit" : "reexec";
    opt->server.restart = [] {
      restart_state().requested = true;
      ::kill(::getpid(), SIGTERM);
    };
    std::atexit(reexec_at_exit);
  }

  std::string error;
  auto server = revkit::api::Server::Start(backend, opt->server, error);
  if (!server) {
    std::cerr << "rk-daemon: " << error << "\n";
    return 1;
  }

  std::cerr << "rk-daemon: backend " << opt->backend;
  if (server->grpc_port()) std::cerr << ", gRPC on port " << server->grpc_port();
  if (server->http_port()) std::cerr << ", HTTP (Connect, gRPC-web) on port " << server->http_port();
  std::cerr << std::endl;
  if (server->http_port()) {
    if (!server->http_also_address().empty())
      std::cerr << "rk-daemon: HTTP also on " << server->http_also_address() << " (both loopback addresses)\n";
    // On loopback without TLS, the name browsers resolve to loopback
    // themselves (*.localhost); the certificate names the addresses.
    const bool local_name = !opt->server.tls.enabled() && revkit::api::IsLoopbackAddress(server->http_address());
    const std::string host = local_name ? "revkit.localhost" : HostOf(opt->server.http_address);
    if (!opt->server.web_root.empty())
      std::cerr << "rk-daemon: web UI at " << (opt->server.tls.enabled() ? "https://" : "http://") << host << ":"
                << server->http_port() << "/ (from " << opt->server.web_root << ")\n";
    else if (!opt->web_root_set)
      std::cerr << "rk-daemon: no web UI bundle; build it with: cd ui && npm ci && npm run build\n";
  }
  if (!opt->port_file.empty()) {
    // Written to a temporary name and renamed, so readers never see a partial file.
    std::string tmp = opt->port_file + ".tmp";
    std::ofstream(tmp) << "{\"grpc\": " << server->grpc_port() << ", \"http\": " << server->http_port()
                       << ", \"tls\": " << (opt->server.tls.enabled() ? "true" : "false") << "}\n";
    std::rename(tmp.c_str(), opt->port_file.c_str());
  }

  // Peers: each link replicates every project both ways until shutdown.
  Peers peers(backend, "rk-daemon@" + std::to_string(server->grpc_port()));
  try {
    for (const std::string &arg : opt->peers) peers.add(parse_peer(*opt, arg));
  } catch (const std::exception &e) {
    std::cerr << "rk-daemon: " << e.what() << "\n";
    server->Shutdown();
    return 1;
  }

  std::thread waiter([&] {
    int sig = 0;
    sigwait(&signals, &sig);
    std::cerr << (restart_state().requested ? "rk-daemon: restarting: shutting down\n" : "rk-daemon: shutting down\n");
    peers.stop();
    server->Shutdown();
  });
  server->Wait();
  waiter.join();
  return 0;
}
