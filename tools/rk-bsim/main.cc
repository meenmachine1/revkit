// rk-bsim: BSim signature databases from the command line (docs/bsim.md).
//
//   rk-bsim create DB [--template 64|32|nosize] [--name N] [--description D] [--lsh-k K] [--lsh-l L]
//   rk-bsim ingest DB FILE... [--category NAME=VALUE]... [--lang ID] [-j N] [--ghidra DIR]
//   rk-bsim info DB
//   rk-bsim list DB [--json]
//   rk-bsim functions DB EXE [--name SUBSTR] [--json]
//   rk-bsim set DB EXE [--name NAME] [--category NAME=VALUE]... [--clear-categories]
//   rk-bsim delete DB EXE...
//   rk-bsim query DB FILE [--function NAME|0xADDR]... [--min-similarity S] [--min-confidence C] [--max N]
//                 [--exe EXE]... [--not-exe EXE]... [--lang PREFIX] [--name SUBSTR] [--category NAME=VALUE]...
//                 [--no-default-names] [--include-self] [--exhaustive|--index-only] [--overview] [--json] [-j N]
//
// DB is a database directory (NAME.rkbsim). EXE is an executable's sha256,
// a unique prefix of it (6+ hex digits) or its unique name. `ingest`
// imports each file into an in-process backend (the daemon's: the same
// analysis, signatures, names and prototypes as a project's IngestBSim)
// and stores it, replacing an earlier ingest of the same file. `query`
// imports FILE the same way and searches the database for each function
// (every one with a body, or those named), as SearchBSim does: matches
// above the thresholds, best first, or with --overview only how many.
#include "revkit/backend/image_backend.h"
#include "revkit/bsim/store.h"
#include "revkit/runtime/runtime.h"

#include "json.hh"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
namespace bsim = revkit::bsim;
using rklift::Json;

int usage() {
  std::cerr
      << "usage:\n"
         "  rk-bsim create DB [--template 64|32|nosize] [--name N] [--description D] [--lsh-k K] [--lsh-l L]\n"
         "  rk-bsim ingest DB FILE... [--category NAME=VALUE]... [--lang ID] [-j N] [--ghidra DIR]\n"
         "  rk-bsim info DB\n"
         "  rk-bsim list DB [--json]\n"
         "  rk-bsim functions DB EXE [--name SUBSTR] [--json]\n"
         "  rk-bsim set DB EXE [--name NAME] [--category NAME=VALUE]... [--clear-categories]\n"
         "  rk-bsim delete DB EXE...\n"
         "  rk-bsim query DB FILE [--function NAME|0xADDR]... [--min-similarity S] [--min-confidence C] [--max N]\n"
         "                [--exe EXE]... [--not-exe EXE]... [--lang PREFIX] [--name SUBSTR] [--category NAME=VALUE]...\n"
         "                [--no-default-names] [--include-self] [--exhaustive|--index-only] [--overview] [--json] [-j N]\n"
         "DB is a database directory (NAME.rkbsim); EXE an executable's sha256, a unique prefix of it or its name.\n";
  return 2;
}

struct Args {
  std::vector<std::string> positional;
  std::map<std::string, std::string> categories;
  std::map<std::string, std::string> options;  // --name, --template, ...
  std::map<std::string, std::vector<std::string>> lists;  // --function, --exe, --not-exe
  std::vector<std::string> flags;               // --json, --clear-categories
  bool ok = true;
};

Args parse(int argc, char **argv, int from) {
  Args a;
  const std::vector<std::string> with_value = {"--template", "--name", "--description", "--lsh-k", "--lsh-l",
                                               "--lang", "-j", "--ghidra", "--min-similarity",
                                               "--min-confidence", "--max"};
  for (int i = from; i < argc; ++i) {
    std::string s = argv[i];
    if (s == "--category") {
      if (i + 1 >= argc) return a.ok = false, a;
      std::string kv = argv[++i];
      const auto eq = kv.find('=');
      if (eq == std::string::npos || eq == 0) {
        std::cerr << "rk-bsim: --category takes NAME=VALUE\n";
        a.ok = false;
        return a;
      }
      a.categories[kv.substr(0, eq)] = kv.substr(eq + 1);
    } else if (std::find(with_value.begin(), with_value.end(), s) != with_value.end()) {
      if (i + 1 >= argc) {
        std::cerr << "rk-bsim: " << s << " takes a value\n";
        a.ok = false;
        return a;
      }
      a.options[s] = argv[++i];
    } else if (s == "--function" || s == "--exe" || s == "--not-exe") {
      if (i + 1 >= argc) {
        std::cerr << "rk-bsim: " << s << " takes a value\n";
        a.ok = false;
        return a;
      }
      a.lists[s].push_back(argv[++i]);
    } else if (s == "--json" || s == "--clear-categories" || s == "--no-default-names" || s == "--include-self" ||
               s == "--exhaustive" || s == "--index-only" || s == "--overview") {
      a.flags.push_back(s);
    } else if (s.starts_with("-") && s.size() > 1) {
      std::cerr << "rk-bsim: unknown option " << s << "\n";
      a.ok = false;
      return a;
    } else {
      a.positional.push_back(s);
    }
  }
  return a;
}

bool has(const Args &a, std::string_view f) { return std::find(a.flags.begin(), a.flags.end(), f) != a.flags.end(); }

std::string when(std::int64_t t) {
  if (t == 0) return "-";
  std::time_t tt = static_cast<std::time_t>(t);
  char buf[32];
  std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M", std::localtime(&tt));
  return buf;
}

std::string cats(const std::map<std::string, std::string> &c) {
  std::string out;
  for (const auto &[k, v] : c) out += (out.empty() ? "" : ",") + k + "=" + v;
  return out;
}

const bsim::Executable &need_exe(const bsim::Database &db, const std::string &key) {
  const bsim::Executable *e = db.find_executable(key);
  if (!e) throw bsim::BsimError("no executable " + key + " (an id, a unique id prefix or a unique name)");
  return *e;
}

int cmd_create(const Args &a) {
  if (a.positional.size() != 1) return usage();
  bsim::DatabaseInfo info;
  if (auto t = a.options.find("--template"); t != a.options.end()) {
    auto p = bsim::parse_template(t->second);
    if (!p) {
      std::cerr << "rk-bsim: --template is 64, 32 or nosize\n";
      return 2;
    }
    info.weights = *p;
  }
  if (auto n = a.options.find("--name"); n != a.options.end()) info.name = n->second;
  if (auto d = a.options.find("--description"); d != a.options.end()) info.description = d->second;
  if (auto k = a.options.find("--lsh-k"); k != a.options.end()) info.lsh.k = static_cast<std::uint32_t>(std::stoul(k->second));
  if (auto l = a.options.find("--lsh-l"); l != a.options.end()) info.lsh.l = static_cast<std::uint32_t>(std::stoul(l->second));
  bsim::Database db = bsim::Database::create(a.positional[0], info);
  std::cout << "created " << db.path().string() << " (" << db.info().name << ", template "
            << bsim::template_name(db.info().weights) << ", LSH k " << db.info().lsh.k << " l " << db.info().lsh.l << ")\n";
  return 0;
}

int cmd_info(const Args &a) {
  if (a.positional.size() != 1) return usage();
  bsim::Database db = bsim::Database::open(a.positional[0]);
  const bsim::DatabaseInfo &i = db.info();
  char settings[16];
  std::snprintf(settings, sizeof settings, "0x%x", i.settings);
  std::cout << "name         " << i.name << "\n"
            << "description  " << i.description << "\n"
            << "template     " << bsim::template_name(i.weights) << " (signature settings " << settings << ")\n"
            << "lsh          k " << i.lsh.k << ", l " << i.lsh.l << "\n"
            << "created      " << when(i.created) << "\n"
            << "executables  " << db.executables().size() << "\n"
            << "functions    " << db.function_count() << "\n";
  return 0;
}

int cmd_list(const Args &a) {
  if (a.positional.size() != 1) return usage();
  bsim::Database db = bsim::Database::open(a.positional[0]);
  if (has(a, "--json")) {
    Json::Array list;
    for (const bsim::Executable *e : db.executables()) {
      Json::Object c;
      for (const auto &[k, v] : e->categories) c[k] = v;
      list.push_back(Json::Object{{"id", e->id}, {"name", e->name}, {"path", e->path}, {"language", e->language},
                                  {"compiler", e->compiler}, {"ingested", e->ingested}, {"source", e->source},
                                  {"categories", Json(std::move(c))},
                                  {"functions", static_cast<std::uint64_t>(e->function_count)}});
    }
    std::cout << Json(std::move(list)).compact() << "\n";
    return 0;
  }
  std::printf("%-12s  %-24s  %-26s  %8s  %-16s  %s\n", "id", "name", "language", "functions", "ingested", "categories");
  for (const bsim::Executable *e : db.executables())
    std::printf("%-12s  %-24s  %-26s  %8u  %-16s  %s\n", e->id.substr(0, 12).c_str(), e->name.c_str(),
                (e->language + (e->compiler.empty() ? "" : ":" + e->compiler)).c_str(), e->function_count,
                when(e->ingested).c_str(), cats(e->categories).c_str());
  return 0;
}

int cmd_functions(const Args &a) {
  if (a.positional.size() != 2) return usage();
  bsim::Database db = bsim::Database::open(a.positional[0]);
  const bsim::Executable &e = need_exe(db, a.positional[1]);
  std::string needle;
  if (auto n = a.options.find("--name"); n != a.options.end()) needle = n->second;
  auto matches = [&](const std::string &name) {
    if (needle.empty()) return true;
    auto low = [](std::string s) {
      for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      return s;
    };
    return low(name).find(low(needle)) != std::string::npos;
  };
  if (has(a, "--json")) {
    Json::Array list;
    for (const bsim::FunctionRecord &f : db.functions(e.id))
      if (matches(f.name))
        list.push_back(Json::Object{{"name", f.name}, {"entry", rklift::hex(f.entry)}, {"prototype", f.prototype},
                                    {"size", static_cast<std::uint64_t>(f.size)},
                                    {"features", static_cast<std::uint64_t>(f.features.size())},
                                    {"default_name", (f.flags & bsim::kDefaultName) != 0}});
    std::cout << Json(std::move(list)).compact() << "\n";
    return 0;
  }
  std::printf("%-18s  %6s  %8s  %-32s  %s\n", "entry", "size", "features", "name", "prototype");
  for (const bsim::FunctionRecord &f : db.functions(e.id))
    if (matches(f.name))
      std::printf("0x%016llx  %6u  %8zu  %-32s  %s\n", static_cast<unsigned long long>(f.entry), f.size,
                  f.features.size(), f.name.c_str(), f.prototype.c_str());
  return 0;
}

int cmd_set(const Args &a) {
  if (a.positional.size() != 2) return usage();
  bsim::Database db = bsim::Database::open(a.positional[0]);
  const bsim::Executable &e = need_exe(db, a.positional[1]);
  const std::string id = e.id;
  std::map<std::string, std::string> c = has(a, "--clear-categories") ? std::map<std::string, std::string>{} : e.categories;
  for (const auto &[k, v] : a.categories) c[k] = v;
  std::string name;
  if (auto n = a.options.find("--name"); n != a.options.end()) name = n->second;
  db.update(id, c, name);
  const bsim::Executable *now = db.executable(id);
  std::cout << now->id.substr(0, 12) << "  " << now->name << "  " << cats(now->categories) << "\n";
  return 0;
}

int cmd_delete(const Args &a) {
  if (a.positional.size() < 2) return usage();
  bsim::Database db = bsim::Database::open(a.positional[0]);
  int missing = 0;
  for (std::size_t i = 1; i < a.positional.size(); ++i) {
    const bsim::Executable *e = db.find_executable(a.positional[i]);
    if (!e) {
      std::cerr << "rk-bsim: no executable " << a.positional[i] << "\n";
      ++missing;
      continue;
    }
    const std::string id = e->id, name = e->name;
    db.remove(id);
    std::cout << "deleted " << id.substr(0, 12) << "  " << name << "\n";
  }
  return missing ? 1 : 0;
}

// An in-process image backend with the database attached to its default
// project; nullopt (and a message) when it can't be made.
struct Session {
  std::unique_ptr<revkit::api::Backend> backend;
  revkit::api::CallContext ctx;
  fs::path db;
  unsigned threads = 1;
};

std::optional<Session> open_session(const Args &a) {
  Session s;
  s.db = fs::absolute(a.positional[0]);
  bsim::Database::peek(s.db);  // a database, before any work
  std::string ghidra;
  if (auto g = a.options.find("--ghidra"); g != a.options.end()) ghidra = g->second;
  auto root = revkit::runtime::find_ghidra(ghidra, "rk-bsim");
  if (!root) return std::nullopt;
  s.threads = std::max(1u, std::min(4u, std::thread::hardware_concurrency() / 2));
  if (auto j = a.options.find("-j"); j != a.options.end()) s.threads = std::max(1u, static_cast<unsigned>(std::stoul(j->second)));
  revkit::backend::ImageBackendOptions o;
  o.ghidra_root = root->string();
  o.server_version = revkit::runtime::version_string("rk-bsim");
  o.decompile_workers = s.threads;
  o.decompilers_per_program = s.threads;
  s.backend = revkit::backend::MakeImageBackend(o);
  pb::AttachBSimDatabaseRequest req;
  req.set_project_id("default");
  req.set_path(s.db.string());
  pb::AttachBSimDatabaseResponse resp;
  if (auto st = s.backend->AttachBSimDatabase(s.ctx, req, resp); !st.ok()) {
    std::cerr << "rk-bsim: " << st.message << "\n";
    return std::nullopt;
  }
  return s;
}

// Imports a file into the session: its program id, or "" (and a message).
std::string import_file(Session &s, const Args &a, const std::string &file) {
  pb::ImportProgramRequest ireq;
  ireq.set_project_id("default");
  ireq.set_path(fs::absolute(file).string());
  if (auto l = a.options.find("--lang"); l != a.options.end()) ireq.mutable_options()->set_language_id(l->second);
  pb::ImportProgramResponse iresp;
  if (auto st = s.backend->ImportProgram(s.ctx, ireq, iresp); !st.ok()) {
    std::cerr << "rk-bsim: " << file << ": " << st.message << "\n";
    return {};
  }
  return iresp.program().program_id();
}

int cmd_ingest(const Args &a) {
  if (a.positional.size() < 2) return usage();
  std::optional<Session> session = open_session(a);
  if (!session) return 1;
  Session &s = *session;
  const fs::path dbpath = s.db;
  const unsigned threads = s.threads;
  auto &b = s.backend;
  auto &ctx = s.ctx;
  int failed = 0;
  for (std::size_t i = 1; i < a.positional.size(); ++i) {
    const std::string file = a.positional[i];
    const std::string program = import_file(s, a, file);
    if (program.empty()) {
      ++failed;
      continue;
    }
    pb::IngestBSimRequest req;
    req.set_project_id("default");
    req.set_database(dbpath.string());
    req.add_program_ids(program);
    req.set_threads(threads);
    req.set_source("rk-bsim");
    for (const auto &[k, v] : a.categories) (*req.mutable_categories())[k] = v;
    pb::IngestBSimResponse resp;
    if (auto st = b->IngestBSim(ctx, req, resp); !st.ok()) {
      std::cerr << "rk-bsim: " << file << ": " << st.message << "\n";
      ++failed;
      continue;
    }
    for (const pb::BSimIngested &r : resp.programs()) {
      std::string excluded;
      for (const auto &[k, n] : r.excluded()) excluded += (excluded.empty() ? "" : ", ") + std::to_string(n) + " " + k;
      std::printf("%s  %s  %u functions%s%s in %.1f s%s\n", r.executable().id().substr(0, 12).c_str(),
                  r.executable().name().c_str(), r.functions(), excluded.empty() ? "" : " (left out: ",
                  excluded.empty() ? "" : (excluded + ")").c_str(), r.seconds(), r.replaced() ? ", replaced" : "");
      if (!r.warning().empty()) std::cerr << "rk-bsim: warning: " << r.warning() << "\n";
    }
    // Free the program before the next one.
    pb::DeleteProgramRequest dreq;
    dreq.set_program_id(program);
    pb::DeleteProgramResponse dresp;
    b->DeleteProgram(ctx, dreq, dresp);
  }
  return failed ? 1 : 0;
}

double number(const Args &a, const char *key, double fallback) {
  auto it = a.options.find(key);
  return it == a.options.end() ? fallback : std::stod(it->second);
}

int cmd_query(const Args &a) {
  if (a.positional.size() != 2) return usage();
  std::optional<Session> session = open_session(a);
  if (!session) return 1;
  Session &s = *session;
  const std::string program = import_file(s, a, a.positional[1]);
  if (program.empty()) return 1;
  pb::SearchBSimRequest req;
  req.set_project_id("default");
  req.set_database(s.db.string());
  req.set_program_id(program);
  req.set_threads(s.threads);
  // --function: a name or an address.
  if (auto f = a.lists.find("--function"); f != a.lists.end()) {
    pb::ListFunctionsRequest lreq;
    lreq.set_program_id(program);
    lreq.mutable_page()->set_page_size(5000);
    std::map<std::string, std::uint64_t> by_name;
    for (;;) {
      pb::ListFunctionsResponse lresp;
      if (auto st = s.backend->ListFunctions(s.ctx, lreq, lresp); !st.ok()) throw std::runtime_error(st.message);
      for (const auto &fn : lresp.functions()) by_name.try_emplace(fn.name(), fn.entry().offset());
      if (lresp.page().next_page_token().empty()) break;
      lreq.mutable_page()->set_page_token(lresp.page().next_page_token());
    }
    for (const std::string &x : f->second) {
      std::uint64_t at = 0;
      if (auto n = by_name.find(x); n != by_name.end()) at = n->second;
      else if (x.starts_with("0x")) at = std::stoull(x.substr(2), nullptr, 16);
      else throw bsim::BsimError("no function " + x + " in " + a.positional[1]);
      req.add_functions()->set_offset(at);
    }
  } else {
    req.set_all_functions(true);
  }
  req.set_min_similarity(number(a, "--min-similarity", 0.7));
  req.set_min_confidence(number(a, "--min-confidence", 0.0));
  req.set_max_matches(static_cast<std::uint32_t>(number(a, "--max", 10)));
  if (auto e = a.lists.find("--exe"); e != a.lists.end())
    for (const auto &x : e->second) req.add_executables(x);
  if (auto e = a.lists.find("--not-exe"); e != a.lists.end())
    for (const auto &x : e->second) req.add_exclude_executables(x);
  if (auto n = a.options.find("--name"); n != a.options.end()) req.set_name_contains(n->second);
  for (const auto &[k, v] : a.categories) (*req.mutable_categories())[k] = v;
  req.set_exclude_default_names(has(a, "--no-default-names"));
  req.set_include_self(has(a, "--include-self"));
  req.set_exhaustive(has(a, "--exhaustive"));
  req.set_index_only(has(a, "--index-only"));
  req.set_overview(has(a, "--overview"));
  pb::SearchBSimResponse resp;
  if (auto st = s.backend->SearchBSim(s.ctx, req, resp); !st.ok()) {
    std::cerr << "rk-bsim: " << st.message << "\n";
    return 1;
  }
  if (has(a, "--json")) {
    Json::Array results;
    for (const pb::BSimQueryResult &q : resp.results()) {
      Json::Array matches;
      for (const pb::BSimMatch &m : q.matches())
        matches.push_back(Json::Object{{"executable", m.executable().id()},
                                       {"executable_name", m.executable().name()},
                                       {"name", m.function().name()},
                                       {"entry", rklift::hex(m.function().entry().offset())},
                                       {"prototype", m.function().prototype()},
                                       {"similarity", m.similarity()},
                                       {"confidence", m.confidence()}});
      Json::Object o{{"entry", rklift::hex(q.function().offset())},
                     {"name", q.name()},
                     {"features", static_cast<std::uint64_t>(q.feature_count())},
                     {"self_significance", q.self_significance()},
                     {"hits", static_cast<std::uint64_t>(q.hit_count())},
                     {"matches", Json(std::move(matches))}};
      if (!q.skipped().empty()) o["skipped"] = q.skipped();
      results.push_back(std::move(o));
    }
    Json::Object doc{{"results", Json(std::move(results))},
                     {"scored", static_cast<std::uint64_t>(resp.scored())},
                     {"total", static_cast<std::uint64_t>(resp.total())},
                     {"seconds", resp.seconds()}};
    std::cout << Json(std::move(doc)).compact() << "\n";
    return 0;
  }
  for (const pb::BSimQueryResult &q : resp.results()) {
    if (!q.skipped().empty()) continue;
    std::printf("0x%llx %s  (%u features, self-significance %.1f): %u hit%s\n",
                static_cast<unsigned long long>(q.function().offset()), q.name().c_str(), q.feature_count(),
                q.self_significance(), q.hit_count(), q.hit_count() == 1 ? "" : "s");
    for (const pb::BSimMatch &m : q.matches())
      std::printf("    %.3f  %6.1f  %-24s  %s  0x%llx\n", m.similarity(), m.confidence(),
                  m.executable().name().c_str(), m.function().name().c_str(),
                  static_cast<unsigned long long>(m.function().entry().offset()));
  }
  std::fprintf(stderr, "rk-bsim: %d functions searched, %llu of %llu scored, %.1f s\n", resp.results_size(),
               static_cast<unsigned long long>(resp.scored()), static_cast<unsigned long long>(resp.total()),
               resp.seconds());
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) return usage();
  const std::string cmd = argv[1];
  if (cmd == "--help" || cmd == "-h" || cmd == "help") {
    usage();
    return 0;
  }
  if (cmd == "--version") {
    std::cout << revkit::runtime::version_string("rk-bsim") << "\n";
    return 0;
  }
  Args a = parse(argc, argv, 2);
  if (!a.ok) return 2;
  try {
    if (cmd == "create") return cmd_create(a);
    if (cmd == "ingest") return cmd_ingest(a);
    if (cmd == "info") return cmd_info(a);
    if (cmd == "list") return cmd_list(a);
    if (cmd == "functions") return cmd_functions(a);
    if (cmd == "set") return cmd_set(a);
    if (cmd == "delete") return cmd_delete(a);
    if (cmd == "query") return cmd_query(a);
  } catch (const bsim::BsimError &e) {
    std::cerr << "rk-bsim: " << e.what() << "\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "rk-bsim: " << e.what() << "\n";
    return 1;
  }
  std::cerr << "rk-bsim: unknown command " << cmd << "\n";
  return usage();
}
