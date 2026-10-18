// rk-diff: match the functions of two binaries (docs/diff.md) from the
// command line, for evaluation and timing.
//
//   rk-diff [options] A B
//
// By default both binaries go through the image backend in this process,
// as rk-daemon serves them (ImportProgram, CreateDiffSession, RunDiff,
// ListMatches, ListUnmatched; with --names-a, AppendAssertions and
// ApplyMarkup). --direct skips the backend: one fact store, discovery and
// the diff queries only (what the timing targets measure). The result is
// JSON (--json FILE, else stdout): every match with its tier, confidence
// and evidence, the unmatched functions with candidates, function sizes,
// names ported by --names-a, and how long each phase took.
//
// Options:
//   --ghidra DIR            Ghidra install (default: the build's)
//   -j N                    threads (default 8)
//   --raw-a/--raw-b SPEC    load A or B as a raw image: "lang=L,base=HEX,entry=HEX,region=name:start:size[:..]..."
//   --direct                fact store and queries only (no backend)
//   --no-propagate          global tiers only (with --direct)
//   --repeat N              run the matching N times (with --direct; the result is the last run's)
//   --bench                 also time interactive edits through the backend: accept and reject a
//                           match, rename a function of B, each followed by a page of the table
//   --names-a FILE          rk-debuginfo JSON (or a firmware truth file): assert its names on A, then
//                           port names over the matches at or above 0.95 (ApplyMarkup) and report
//                           what B's functions are called afterwards
//   --changes               (through the backend) what changed inside every modified pair, to
//                           stderr: GetFunctionDiff's detail summary and the differing addresses
//   --similarity bsim       the BSim tier over the residue (F5, docs/diff.md): through the backend,
//                           the session's similarity_tiers (diff.signature in decompiler workers);
//                           with --direct, the residue's functions signed when the matcher asks
//                           (rk-lift --signatures' inputs: revkit's own, the signature profile)

#include "revkit/analysis/analysis.h"
#include "revkit/runtime/runtime.h"
#include "revkit/decompd/signature.h"
#include "revkit/diff/features.h"
#include "revkit/diff/lsh.h"
#include "revkit/diff/match.h"
#include "revkit/diff/residue.h"
#include "revkit/inputs/inputs.h"
#include "revkit/facts/fact_db.h"
#include "revkit/facts/thread_pool.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#ifdef REVKIT_DIFF_BACKEND
#include "revkit/backend/image_backend.h"
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <cstring>
#include <map>
#include <set>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifndef REVKIT_DEFAULT_GHIDRA_ROOT
#define REVKIT_DEFAULT_GHIDRA_ROOT ""
#endif

namespace {

bool g_changes = false;

namespace diff = revkit::diff;
namespace facts = revkit::facts;
namespace analysis = revkit::analysis;
namespace loader = revkit::loader;
using Clock = std::chrono::steady_clock;

double Ms(Clock::time_point a, Clock::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); }

std::string Hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string Quote(std::string_view s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') out += '\\', out += c;
    else if (static_cast<unsigned char>(c) < 0x20) {
      char buf[8];
      std::snprintf(buf, sizeof buf, "\\u%04x", c);
      out += buf;
    } else out += c;
  }
  return out + "\"";
}

std::optional<loader::RawOptions> ParseRaw(const std::string &spec) {
  loader::RawOptions o;
  std::stringstream ss(spec);
  std::string item;
  while (std::getline(ss, item, ',')) {
    auto eq = item.find('=');
    if (eq == std::string::npos) return std::nullopt;
    std::string k = item.substr(0, eq), v = item.substr(eq + 1);
    if (k == "lang") o.language = v;
    else if (k == "base") o.base = std::stoull(v, nullptr, 16);
    else if (k == "entry") o.entry = std::stoull(v, nullptr, 16);
    else if (k == "region") o.regions.push_back(loader::parse_raw_region(v));
    else return std::nullopt;
  }
  if (o.language.empty()) return std::nullopt;
  return o;
}

// Names from rk-debuginfo's JSON ("entry"/"name") or a firmware truth file
// ("address"/"name"), by a minimal scan: (entry, name).
std::vector<std::pair<std::uint64_t, std::string>> ReadNames(const std::filesystem::path &file) {
  std::ifstream in(file);
  std::stringstream ss;
  ss << in.rdbuf();
  const std::string text = ss.str();
  std::vector<std::pair<std::uint64_t, std::string>> out;
  for (const char *field : {"\"entry\":", "\"address\":"}) {
    std::size_t pos = 0;
    while ((pos = text.find(field, pos)) != std::string::npos) {
      pos = text.find('"', pos + std::strlen(field));
      if (pos == std::string::npos) break;
      ++pos;
      const std::uint64_t entry = std::stoull(text.substr(pos, text.find('"', pos) - pos), nullptr, 16) & ~std::uint64_t{1};
      auto n = text.find("\"name\":", pos);
      auto obj_end = text.find('}', pos);
      if (n == std::string::npos || n > obj_end) continue;
      n = text.find('"', n + 7) + 1;
      out.emplace_back(entry, text.substr(n, text.find('"', n) - n));
    }
    if (!out.empty()) break;
  }
  return out;
}

// What both modes report.
struct Report {
  std::size_t functions_a = 0, functions_b = 0;
  std::uint32_t rounds = 0;
  double load_ms = 0, features_ms = 0, match_ms = 0;
  struct M {
    std::uint64_t a, b;
    std::string tier, relation;
    float confidence, similarity;
    bool unchanged;
    std::uint32_t round, group;
  };
  std::vector<M> matches;
  struct U {
    std::uint64_t entry;
    int reason;
    std::vector<std::pair<std::uint64_t, float>> candidates;
  };
  std::vector<U> unmatched_a;
  std::vector<std::uint64_t> unmatched_b;
  std::map<std::uint64_t, std::uint32_t> instructions_a;
  std::map<std::uint64_t, std::string> ported;  // B entry -> name after porting
  int ported_count = -1;
  double feature_bytes = 0;  // mean encoded size of a function's features (--direct)
  double signatures_ms = -1;  // --direct --similarity bsim: signing the residue (inside match_ms)
  std::vector<std::pair<std::string, double>> bench;  // --bench: interactive latencies (ms)
};

std::string ToJson(const Report &r, const std::string &a, const std::string &b, unsigned threads, const char *mode) {
  std::ostringstream o;
  o << "{\"a\":" << Quote(a) << ",\"b\":" << Quote(b) << ",\"mode\":" << Quote(mode) << ",\"functions_a\":" << r.functions_a
    << ",\"functions_b\":" << r.functions_b << ",\"threads\":" << threads << ",\"rounds\":" << r.rounds
    << ",\"timing_ms\":{\"load\":" << r.load_ms << ",\"features\":" << r.features_ms << ",\"match\":" << r.match_ms
    << ",\"features_and_match\":" << (r.features_ms + r.match_ms) << "}";
  if (r.feature_bytes > 0) o << ",\"feature_bytes_per_function\":" << r.feature_bytes;
  if (r.signatures_ms >= 0) o << ",\"signatures_ms\":" << r.signatures_ms;
  if (!r.bench.empty()) {
    o << ",\"bench_ms\":{";
    for (std::size_t i = 0; i < r.bench.size(); ++i) o << (i ? "," : "") << Quote(r.bench[i].first) << ":" << r.bench[i].second;
    o << "}";
  }
  o << ",\"matches\":[";
  bool first = true;
  for (const auto &m : r.matches) {
    o << (first ? "" : ",") << "\n{\"a\":" << Quote(Hex(m.a)) << ",\"b\":" << Quote(Hex(m.b)) << ",\"tier\":"
      << Quote(m.tier) << ",\"relation\":" << Quote(m.relation) << ",\"confidence\":" << m.confidence
      << ",\"similarity\":" << m.similarity << ",\"unchanged\":" << (m.unchanged ? "true" : "false")
      << ",\"round\":" << m.round << ",\"group\":" << m.group << "}";
    first = false;
  }
  o << "],\"unmatched_a\":[";
  first = true;
  for (const auto &u : r.unmatched_a) {
    o << (first ? "" : ",") << "\n{\"entry\":" << Quote(Hex(u.entry)) << ",\"reason\":" << u.reason << ",\"candidates\":[";
    for (std::size_t i = 0; i < u.candidates.size() && i < 4; ++i)
      o << (i ? "," : "") << "[" << Quote(Hex(u.candidates[i].first)) << "," << u.candidates[i].second << "]";
    o << "]}";
    first = false;
  }
  o << "],\"unmatched_b\":[";
  first = true;
  for (std::uint64_t e : r.unmatched_b) {
    o << (first ? "" : ",") << Quote(Hex(e));
    first = false;
  }
  o << "],\"instructions_a\":{";
  first = true;
  for (const auto &[e, n] : r.instructions_a) {
    o << (first ? "" : ",") << Quote(Hex(e)) << ":" << n;
    first = false;
  }
  o << "}";
  if (r.ported_count >= 0) {
    o << ",\"ported_count\":" << r.ported_count << ",\"ported\":{";
    first = true;
    for (const auto &[e, n] : r.ported) {
      o << (first ? "" : ",") << Quote(Hex(e)) << ":" << Quote(n);
      first = false;
    }
    o << "}";
  }
  o << "}\n";
  return o.str();
}

// ---- direct: a fact store and the queries ----

struct Loaded {
  std::string id;
  analysis::ProgramInfo info;
  std::size_t functions = 0;
  std::shared_ptr<const loader::Image> image;
  std::string language;  // with the compiler
  std::filesystem::path file;
};

// --direct --similarity bsim: one program's signatures, assembled and
// computed on first use, then kept by entry (rk-lift --signatures' path:
// revkit::inputs, the signature profile, decompiler workers). Called from
// diff::match's residue hook, outside any query (workers need their own
// fact stores).
class Signer {
 public:
  Signer(const Loaded &p, unsigned threads, std::uint32_t settings) : p_(p), threads_(threads), settings_(settings) {}

  std::vector<std::vector<std::uint32_t>> get(const std::vector<std::uint64_t> &entries) {
    const auto t0 = Clock::now();
    if (!config_) prepare();
    std::vector<std::uint64_t> missing;
    for (std::uint64_t e : entries)
      if (!done_.contains(e)) missing.push_back(e);
    if (!missing.empty()) {
      revkit::decompd::SignatureBatchOptions o;
      o.signature.settings = settings_;
      o.no_return = no_return_;
      o.max_varnodes = std::size_t{1} << 20;
      for (auto &[e, s] : revkit::decompd::signature_functions(*config_, missing, o))
        done_[e] = s.ok() ? std::move(s.features) : std::vector<std::uint32_t>{};
    }
    std::vector<std::vector<std::uint32_t>> out;
    for (std::uint64_t e : entries) out.push_back(done_.at(e));
    ms += Ms(t0, Clock::now());
    return out;
  }
  double ms = 0;

 private:
  void prepare() {
    analysis_ = revkit::inputs::analyze(*p_.image, p_.language, threads_);
    revkit::inputs::Program program{p_.image, p_.language, analysis_.get(),
                                    revkit::inputs::read_debug_info(*p_.image, p_.file)};
    revkit::lift::DecompileConfig c;
    c.image = p_.image;
    c.language_id = p_.language;
    c.inputs = std::make_shared<revkit::lift::DecompilerInputs>(revkit::inputs::assemble(program, {}, threads_));
    c.default_labels = false;
    c.threads = threads_;
    config_ = std::move(c);
    no_return_ = std::make_shared<const std::vector<std::uint64_t>>(
        revkit::inputs::ghidra_no_return(analysis_->functions(), analysis_->no_return_evidence()));
  }

  const Loaded &p_;
  unsigned threads_;
  std::uint32_t settings_;
  std::unique_ptr<revkit::inputs::Analysis> analysis_;
  std::optional<revkit::lift::DecompileConfig> config_;
  std::shared_ptr<const std::vector<std::uint64_t>> no_return_;
  std::map<std::uint64_t, std::vector<std::uint32_t>> done_;
};

Loaded Load(facts::FactDb &db, facts::ThreadPool &pool, const std::string &id, const std::filesystem::path &file,
            const std::optional<loader::RawOptions> &raw, facts::SpaceId space) {
  loader::Image image = raw ? loader::load_raw_file(file, *raw)
                            : loader::load_file(file, {.image_base = std::nullopt, .ghidra_image_base = true, .macho_slice = {}});
  std::string lang;
  if (raw) lang = raw->language;
  else if (auto l = loader::guess_language(image)) lang = l->id();
  else throw std::runtime_error("no language for " + file.string());
  Loaded out;
  out.id = id;
  out.file = file;
  out.language = lang;
  out.info = analysis::describe(image, lang, space);
  out.info.references = true;
  analysis::import_image(db, analysis::ProgramKey{id}, image, out.info);
  // The seeds' flows in parallel first, as the daemon's import does.
  facts::Snapshot snap = db.snapshot();
  std::vector<analysis::Location> seeds;
  for (const analysis::Seed &s : out.info.seeds) seeds.push_back({{id}, out.info.code_key(s.address, false)});
  snap.get_all<analysis::Flow>(seeds, &pool);
  out.functions = snap.get<analysis::Functions>(analysis::ProgramKey{id})->functions.size();
  out.image = std::make_shared<const loader::Image>(std::move(image));
  return out;
}

Report Direct(const std::vector<std::string> &files, const std::optional<loader::RawOptions> raw[2], unsigned threads,
              bool propagate, int repeat, const std::string &similarity) {
  Report rep;
  facts::FactDb db;
  analysis::register_queries(db.engine());
  diff::register_queries(db.engine());
  facts::ThreadPool pool(std::max(1u, threads));
  db.engine().set_pool(&pool);

  const auto t0 = Clock::now();
  Loaded a = Load(db, pool, "a", files[0], raw[0], 16);
  Loaded b = Load(db, pool, "b", files[1], raw[1], 18);
  const auto t1 = Clock::now();
  facts::Snapshot snap = db.snapshot();
  for (const Loaded *p : {&a, &b}) {
    auto list = snap.get<analysis::Functions>(analysis::ProgramKey{p->id});
    std::vector<analysis::Location> keys;
    for (const auto &f : list->functions) keys.push_back({{p->id}, f.entry.offset});
    snap.get_all<diff::Features>(keys, &pool);
  }
  const auto t2 = Clock::now();
  std::optional<Signer> sign_a, sign_b;
  const diff::WeightTable *weights = nullptr;
  diff::ResidueFn residue;
  if (similarity == "bsim") {
    const diff::Weights w = diff::weights_for(a.language, b.language).value_or(diff::Weights::nosize);
    weights = &diff::WeightTable::builtin(w);
    sign_a.emplace(a, threads, weights->settings());
    sign_b.emplace(b, threads, weights->settings());
    residue = [&](const diff::ResidueRequest &req) {
      return diff::score_residue(
          req, [&](bool side_b, const std::vector<std::uint64_t> &e) { return (side_b ? *sign_b : *sign_a).get(e); },
          *weights);
    };
  }
  facts::Ref<diff::MatchResult> result;
  for (int r = 0; r < repeat; ++r) {
    const auto m0 = Clock::now();
    // The BSim tier signs in worker pools of its own, which can't run
    // inside a query: match directly (the same computation).
    if (!propagate || r > 0 || residue) {
      // The matching alone (features stay memoized).
      diff::MatchInput in;
      std::vector<facts::Ref<diff::FunctionFeatures>> keep;
      for (const char *id : {"a", "b"})
        for (const auto &f : snap.get<analysis::Functions>(analysis::ProgramKey{id})->functions) {
          keep.push_back(snap.get<diff::Features>({{id}, f.entry.offset}));
          (id[0] == 'a' ? in.a : in.b).push_back(keep.back().get());
        }
      in.options.propagate = propagate;
      result = std::make_shared<const diff::MatchResult>(diff::match(in, residue));
    } else {
      result = snap.get<diff::Matches>(diff::SessionKey{"cli", "a", "b", {}});
    }
    rep.match_ms = Ms(m0, Clock::now());
  }
  db.engine().set_pool(nullptr);
  rep.functions_a = a.functions;
  rep.functions_b = b.functions;
  rep.rounds = result->rounds;
  rep.load_ms = Ms(t0, t1);
  rep.features_ms = Ms(t1, t2);
  if (sign_a) rep.signatures_ms = sign_a->ms + sign_b->ms;
  for (const diff::Match &m : result->matches)
    rep.matches.push_back({m.a, m.b, std::string(diff::to_string(m.tier)), std::string(diff::to_string(m.evidence.relation)),
                           m.confidence, m.similarity, m.unchanged, m.evidence.round, m.evidence.group});
  for (const diff::Unmatched &u : result->unmatched_a) {
    Report::U x{u.entry, static_cast<int>(u.reason), {}};
    for (const auto &c : u.candidates) x.candidates.emplace_back(c.entry, c.score);
    rep.unmatched_a.push_back(std::move(x));
  }
  for (const diff::Unmatched &u : result->unmatched_b) rep.unmatched_b.push_back(u.entry);
  std::size_t bytes = 0, n = 0;
  for (const char *id : {"a", "b"})
    for (const auto &f : snap.get<analysis::Functions>(analysis::ProgramKey{id})->functions) {
      auto ff = snap.get<diff::Features>({{id}, f.entry.offset});
      if (id[0] == 'a') rep.instructions_a[f.entry.offset] = ff->instructions;
      bytes += facts::encode_to_string(*ff).size();
      ++n;
    }
  rep.feature_bytes = n ? static_cast<double>(bytes) / static_cast<double>(n) : 0;
  return rep;
}

#ifdef REVKIT_DIFF_BACKEND

// ---- through the image backend, as rk-daemon serves it ----

namespace pb = ::revkit::v1;

void Check(const revkit::api::Status &st, const std::string &what) {
  if (!st.ok()) throw std::runtime_error(what + ": " + st.message);
}

std::string Import(revkit::api::Backend &be, const std::string &file, const std::optional<loader::RawOptions> &raw,
                   const std::string &name) {
  pb::ImportProgramRequest req;
  req.set_project_id("default");
  req.set_path(std::filesystem::absolute(file).string());
  req.set_name(name);
  if (raw) {
    auto *o = req.mutable_options();
    o->set_format("raw");
    auto parts = raw->language;
    // "proc:endian:size:variant[:compiler]"
    int colons = 0;
    std::size_t cut = std::string::npos;
    for (std::size_t i = 0; i < parts.size(); ++i)
      if (parts[i] == ':' && ++colons == 4) cut = i;
    o->set_language_id(cut == std::string::npos ? parts : parts.substr(0, cut));
    if (cut != std::string::npos) o->set_compiler_spec_id(parts.substr(cut + 1));
    o->set_has_image_base(true);
    o->set_image_base(raw->base);
    if (raw->entry) {
      o->set_has_entry_point(true);
      o->set_entry_point(*raw->entry);
    }
    for (const loader::RawRegion &r : raw->regions) {
      auto *m = o->add_regions();
      m->set_name(r.name);
      m->set_start(r.start);
      m->set_size(r.size);
      m->set_read(r.perms.read);
      m->set_write(r.perms.write);
      m->set_execute(r.perms.exec);
      m->set_initialized(r.initialized);
      m->set_is_volatile(r.is_volatile);
    }
  }
  pb::ImportProgramResponse resp;
  Check(be.ImportProgram({}, req, resp), "import " + file);
  return resp.program().program_id();
}

Report Backend(const std::vector<std::string> &files, const std::optional<loader::RawOptions> raw[2], unsigned threads,
               const std::string &ghidra, const std::string &names_a, bool bench, const std::string &similarity) {
  Report rep;
  revkit::backend::ImageBackendOptions o;
  o.ghidra_root = ghidra;
  o.analysis_threads = threads;
  o.import_debug_info = false;
  o.param_id = revkit::inputs::ParamIdMode::off;
  // Signatures (the bsim tier) run in decompiler workers.
  o.decompile_workers = similarity.empty() ? 1 : threads;
  auto be = revkit::backend::MakeImageBackend(o);
  const auto t0 = Clock::now();
  const std::string a = Import(*be, files[0], raw[0], "a");
  const std::string b = Import(*be, files[1], raw[1], "b");
  rep.load_ms = Ms(t0, Clock::now());

  pb::CreateDiffSessionRequest create;
  create.set_project_id("default");
  create.set_program_a(a);
  create.set_program_b(b);
  create.set_run(true);
  if (!similarity.empty()) create.mutable_options()->add_similarity_tiers(similarity);
  pb::CreateDiffSessionResponse created;
  Check(be->CreateDiffSession({}, create, created), "create session");
  const std::string session = created.session().session_id();
  pb::GetDiffStatusResponse st;
  for (;;) {
    pb::GetDiffStatusRequest q;
    q.set_project_id("default");
    q.set_session_id(session);
    Check(be->GetDiffStatus({}, q, st), "status");
    if (st.session().run().state() != pb::DIFF_RUN_STATE_RUNNING) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  if (st.session().run().state() != pb::DIFF_RUN_STATE_SUCCEEDED)
    throw std::runtime_error("run failed: " + st.session().run().message());
  rep.features_ms = st.session().run().features_ms();
  rep.match_ms = st.session().run().match_ms();
  rep.functions_a = st.counts().functions_a();
  rep.functions_b = st.counts().functions_b();
  rep.rounds = st.counts().rounds();
  const std::uint64_t revision = st.session().run().revision();

  auto tier_name = [](pb::DiffTier t) { return std::string(diff::to_string(static_cast<diff::Tier>(static_cast<int>(t)))); };
  auto relation_name = [](pb::DiffRelation r) {
    return std::string(diff::to_string(static_cast<diff::Relation>(static_cast<int>(r))));
  };
  pb::ListMatchesRequest lm;
  lm.set_project_id("default");
  lm.set_session_id(session);
  lm.mutable_read()->set_revision(revision);
  lm.mutable_page()->set_page_size(5000);
  for (;;) {
    pb::ListMatchesResponse r;
    Check(be->ListMatches({}, lm, r), "list matches");
    for (const auto &m : r.matches()) {
      rep.matches.push_back({m.a().entry().offset(), m.b().entry().offset(), tier_name(m.tier()),
                             relation_name(m.evidence().relation()), m.confidence(), m.similarity(),
                             m.change_kind() == pb::DIFF_CHANGE_KIND_UNCHANGED, m.evidence().round(), m.evidence().group()});
      rep.instructions_a[m.a().entry().offset()] = m.a().instructions();
    }
    if (r.page().next_page_token().empty()) break;
    lm.mutable_page()->set_page_token(r.page().next_page_token());
  }
  if (g_changes) {
    const auto t0 = Clock::now();
    std::size_t n = 0;
    double slowest = 0;
    for (const auto &m : rep.matches) {
      if (m.unchanged) continue;
      pb::GetFunctionDiffRequest g;
      g.set_project_id("default");
      g.set_session_id(session);
      g.mutable_read()->set_revision(revision);
      g.mutable_entry_a()->set_offset(m.a);
      g.mutable_entry_b()->set_offset(m.b);
      g.set_detail(true);
      g.set_omit_bytes(true);
      pb::GetFunctionDiffResponse gr;
      Check(be->GetFunctionDiff({}, g, gr), "function diff");
      const pb::DiffDetail &d = gr.detail();
      std::string at;
      for (const pb::DiffLine &l : d.lines()) {
        const pb::DiffRow *r = l.a() >= 0 && l.b() < 0 ? &d.rows_a(l.a()) : l.b() >= 0 ? &d.rows_b(l.b()) : nullptr;
        if (!r || r->status() == pb::DIFF_LINE_STATUS_EQUAL || r->status() == pb::DIFF_LINE_STATUS_UNSPECIFIED) continue;
        at += (at.empty() ? "" : " ") + Hex(r->address().offset());
      }
      std::fprintf(stderr, "change %s -> %s: %s [%s] (%u blocks modified, %u added, %u removed; correlate %.2f ms, detail %.2f ms)\n",
                   Hex(m.a).c_str(), Hex(m.b).c_str(), d.summary().text().c_str(), at.c_str(), d.summary().blocks_modified(),
                   d.summary().blocks_added(), d.summary().blocks_removed(), d.correlate_ms(), d.total_ms());
      slowest = std::max(slowest, d.total_ms());
      ++n;
    }
    std::fprintf(stderr, "rk-diff: %zu modified pairs in %.0f ms (slowest %.1f ms)\n", n, Ms(t0, Clock::now()), slowest);
  }
  for (pb::DiffSide side : {pb::DIFF_SIDE_A, pb::DIFF_SIDE_B}) {
    pb::ListUnmatchedRequest lu;
    lu.set_project_id("default");
    lu.set_session_id(session);
    lu.set_side(side);
    lu.set_max_candidates(4);
    lu.mutable_read()->set_revision(revision);
    lu.mutable_page()->set_page_size(2000);
    for (;;) {
      pb::ListUnmatchedResponse r;
      Check(be->ListUnmatched({}, lu, r), "list unmatched");
      for (const auto &u : r.functions()) {
        if (side == pb::DIFF_SIDE_B) {
          rep.unmatched_b.push_back(u.function().entry().offset());
          continue;
        }
        Report::U x{u.function().entry().offset(), static_cast<int>(u.reason()), {}};
        for (const auto &c : u.candidates()) x.candidates.emplace_back(c.function().entry().offset(), c.score());
        rep.unmatched_a.push_back(std::move(x));
        rep.instructions_a[u.function().entry().offset()] = u.function().instructions();
      }
      if (r.page().next_page_token().empty()) break;
      lu.mutable_page()->set_page_token(r.page().next_page_token());
    }
  }

  if (bench) {
    // Interactive latencies: accept a proposal, then the table again; reject
    // one; rename a function of B, then the table again; run again with
    // nothing changed.
    auto timed = [&](const char *what, const std::function<void()> &fn) {
      const auto t = Clock::now();
      fn();
      rep.bench.emplace_back(what, Ms(t, Clock::now()));
    };
    auto page = [&] {
      pb::ListMatchesRequest q;
      q.set_project_id("default");
      q.set_session_id(session);
      q.mutable_page()->set_page_size(100);
      pb::ListMatchesResponse r;
      Check(be->ListMatches({}, q, r), "list matches");
    };
    std::vector<const Report::M *> proposed;
    for (const auto &m : rep.matches)
      if (m.confidence < 1.f) proposed.push_back(&m);
    if (proposed.size() >= 3) {
      timed("accept_commit", [&] {
        pb::AcceptMatchesRequest q;
        q.set_project_id("default");
        q.set_session_id(session);
        auto *p = q.add_pairs();
        p->mutable_entry_a()->set_offset(proposed[0]->a);
        p->mutable_entry_b()->set_offset(proposed[0]->b);
        pb::AcceptMatchesResponse r;
        Check(be->AcceptMatches({}, q, r), "accept");
      });
      timed("table_after_accept", page);
      timed("reject_commit", [&] {
        pb::RejectMatchesRequest q;
        q.set_project_id("default");
        q.set_session_id(session);
        auto *p = q.add_pairs();
        p->mutable_entry_a()->set_offset(proposed[1]->a);
        p->mutable_entry_b()->set_offset(proposed[1]->b);
        pb::RejectMatchesResponse r;
        Check(be->RejectMatches({}, q, r), "reject");
      });
      timed("table_after_reject", page);
      timed("rename_in_b_commit", [&] {
        pb::AppendAssertionsRequest q;
        q.set_program_id(b);
        q.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
        q.mutable_provenance()->set_id("bench");
        auto *r = q.add_assertions()->mutable_body()->mutable_rename();
        r->mutable_target()->mutable_address()->set_offset(proposed[2]->b);
        r->set_name("renamed_by_bench");
        pb::AppendAssertionsResponse resp;
        Check(be->AppendAssertions({}, q, resp), "rename");
      });
      timed("table_after_rename", page);
      timed("table_unchanged", page);
    }
  }

  if (!names_a.empty()) {
    // The analysed program: A gets its truth names (as an importer would
    // give them), then names are ported over the auto-applicable matches
    // found above, through ApplyMarkup.
    pb::AppendAssertionsRequest app;
    app.set_program_id(a);
    app.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_IMPORT);
    app.mutable_provenance()->set_id("dwarf");
    std::set<std::uint64_t> functions_a;
    for (const auto &m : rep.matches) functions_a.insert(m.a);
    for (const auto &u : rep.unmatched_a) functions_a.insert(u.entry);
    for (const auto &[entry, name] : ReadNames(names_a)) {
      if (!functions_a.contains(entry)) continue;
      auto *r = app.add_assertions()->mutable_body()->mutable_rename();
      r->mutable_target()->mutable_address()->set_offset(entry);
      r->set_name(name);
    }
    pb::AppendAssertionsResponse appended;
    if (app.assertions_size()) Check(be->AppendAssertions({}, app, appended), "assert A's names");
    pb::ApplyMarkupRequest apply;
    apply.set_project_id("default");
    apply.set_session_id(session);
    apply.add_items(pb::DIFF_MARKUP_ITEM_NAMES);
    for (const auto &m : rep.matches) {
      if (m.confidence < 0.95f) continue;
      auto *p = apply.add_pairs();
      p->mutable_entry_a()->set_offset(m.a);
      p->mutable_entry_b()->set_offset(m.b);
    }
    apply.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    apply.mutable_provenance()->set_id("eval");
    pb::ApplyMarkupResponse applied;
    Check(be->ApplyMarkup({}, apply, applied), "apply");
    rep.ported_count = static_cast<int>(applied.names());
    // B's functions named by the port: blame says who.
    for (const auto &m : rep.matches) {
      if (m.confidence < 0.95f) continue;
      pb::BlameRequest bl;
      bl.mutable_key()->set_program_id(b);
      bl.mutable_key()->set_kind(pb::FACT_KIND_NAME);
      bl.mutable_key()->mutable_address()->set_offset(m.b);
      pb::BlameResponse blr;
      Check(be->Blame({}, bl, blr), "blame");
      if (blr.candidates_size() && blr.candidates(0).provenance().kind() == pb::PROVENANCE_KIND_MIGRATION &&
          blr.candidates(0).status() == pb::ASSERTION_STATUS_EFFECTIVE)
        rep.ported[m.b] = blr.value_text();
    }
  }
  return rep;
}

#endif

void Usage() {
  std::cerr << "usage: rk-diff [--ghidra DIR] [-j N] [--raw-a SPEC] [--raw-b SPEC] [--direct] [--no-propagate]\n"
               "               [--repeat N] [--names-a FILE] [--similarity bsim] [--changes] [--json FILE] A B\n";
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-diff")) return 0;
  std::string ghidra;  // --ghidra; else found by revkit::runtime
  unsigned threads = 8;
  std::optional<loader::RawOptions> raw[2];
  bool propagate = true, direct = false, bench = false;
  int repeat = 1;
  std::string json_out, names_a, similarity;
  std::vector<std::string> files;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    auto value = [&]() -> std::string {
      if (i + 1 >= argc) {
        Usage();
        std::exit(2);
      }
      return argv[++i];
    };
    if (arg == "--ghidra") ghidra = value();
    else if (arg == "-j") threads = static_cast<unsigned>(std::stoul(value()));
    else if (arg == "--raw-a" || arg == "--raw-b") {
      auto r = ParseRaw(value());
      if (!r) {
        std::cerr << "rk-diff: bad " << arg << "\n";
        return 2;
      }
      raw[arg == "--raw-a" ? 0 : 1] = std::move(r);
    } else if (arg == "--no-propagate") propagate = false;
    else if (arg == "--direct") direct = true;
    else if (arg == "--bench") bench = true;
    else if (arg == "--changes") g_changes = true;
    else if (arg == "--repeat") repeat = std::max(1, std::stoi(value()));
    else if (arg == "--json") json_out = value();
    else if (arg == "--names-a") names_a = value();
    else if (arg == "--similarity") similarity = value();
    else if (arg == "-h" || arg == "--help") {
      Usage();
      return 0;
    } else if (!arg.empty() && arg[0] == '-') {
      Usage();
      return 2;
    } else files.push_back(arg);
  }
  if (files.size() != 2) {
    Usage();
    return 2;
  }
#ifndef REVKIT_DIFF_BACKEND
  direct = true;
#endif
  if (!similarity.empty() && similarity != "bsim") {
    std::cerr << "rk-diff: unknown similarity tier " << similarity << "\n";
    return 2;
  }
  if (!direct && (!propagate || repeat > 1)) {
    std::cerr << "rk-diff: --no-propagate and --repeat need --direct\n";
    return 2;
  }
  if (auto root = revkit::runtime::find_ghidra(ghidra, "rk-diff")) ghidra = root->string();
  else return 1;
  try {
    revkit::lift::initialize(ghidra);
    Report rep;
#ifdef REVKIT_DIFF_BACKEND
    if (!direct) rep = Backend(files, raw, threads, ghidra, names_a, bench, similarity);
    else
#endif
      rep = Direct(files, raw, threads, propagate, repeat, similarity);
    const std::string out = ToJson(rep, files[0], files[1], threads, direct ? "direct" : "backend");
    if (json_out.empty()) std::cout << out;
    else std::ofstream(json_out) << out;
    std::fprintf(stderr, "rk-diff: %zu vs %zu functions, %zu matched; load %.0f ms, features %.0f ms, match %.0f ms\n",
                 rep.functions_a, rep.functions_b, rep.matches.size(), rep.load_ms, rep.features_ms, rep.match_ms);
  } catch (const std::exception &e) {
    std::cerr << "rk-diff: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
