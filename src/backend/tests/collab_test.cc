// Multi-daemon collaboration (docs/collab.md): image-backend daemons in one
// process, each with its own gRPC server on loopback, replicating through
// PeerLinks. They import nothing but the first daemon's program: the rest
// receive its record and its file from a peer.
//
// Convergence is checked through the public API only: every assertion
// (by global id, with status and retractions), blame on the edited keys,
// the function list and every function's decompiled C must be identical
// on every daemon.
#include "builders.hh"

#include "revkit/api/peer_link.h"
#include "revkit/api/server.h"
#include "revkit/auth/store.h"
#include "revkit/auth/tls.h"
#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using api::CallContext;
using namespace std::chrono_literals;

constexpr const char *kProgram = R"(
#include <stdio.h>
int counter;
__attribute__((noinline)) unsigned checksum(const unsigned char *p, int n) {
  unsigned h = 0x811c9dc5;
  for (int i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193;
  counter++;
  return h;
}
__attribute__((noinline)) int twice(int x) { return checksum((const unsigned char *)&x, 4) * 2; }
__attribute__((noinline)) int lonely(int x) { return x * 7 + counter; }
int main(int argc, char **argv) {
  printf("%u %d %d\n", checksum((const unsigned char *)argv[0], argc), twice(argc), lonely(argc));
  return 0;
}
)";

struct Daemon {
  std::shared_ptr<api::Backend> backend;
  std::unique_ptr<api::Server> server;
  std::map<std::string, std::unique_ptr<api::PeerLink>> links;

  std::string address() const { return "127.0.0.1:" + std::to_string(server->grpc_port()); }
  ~Daemon() {
    links.clear();  // stop replicating before the server and backend go
    server.reset();
  }
};

std::string IdText(const pb::OpId &id) {
  std::ostringstream os;
  os << std::hex << id.replica() << std::dec << "." << id.counter();
  return os.str();
}

class CollabTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) return;
    auto dir = testing::scratch_dir("collab");
    program_ = dir / "prog";
    compiled_ = testing::compile(REVKIT_TEST_CC, kProgram, "-O1 -g", program_);
  }

  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "no C compiler";
  }

  static std::unique_ptr<Daemon> Start(const std::string &project_dir = {},
                                       std::shared_ptr<auth::Store> store = nullptr, api::TlsConfig tls = {}) {
    auto d = std::make_unique<Daemon>();
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir;
    o.analysis_threads = 2;
    o.decompilers_per_program = 1;
    d->backend = MakeImageBackend(o);
    api::ServerOptions so;
    so.grpc_address = "127.0.0.1:0";
    so.http_address.clear();
    so.reflection = false;
    so.auth = std::move(store);
    so.tls = std::move(tls);
    std::string error;
    d->server = api::Server::Start(d->backend, so, error);
    EXPECT_TRUE(d->server) << error;
    return d;
  }

  // `from` replicates with `to`, both ways.
  static void Link(Daemon &from, Daemon &to, api::PeerLinkOptions o = {}) {
    o.target = to.address();
    o.name = from.address();
    o.rescan = 100ms;
    o.min_backoff = 20ms;
    o.max_backoff = 300ms;
    from.links[to.address()] = std::make_unique<api::PeerLink>(from.backend, o);
  }

  static pb::ProjectSyncState State(Daemon &d) {
    CallContext ctx;
    pb::GetSyncStateRequest req;
    req.set_project_id("default");
    pb::GetSyncStateResponse resp;
    EXPECT_TRUE(d.backend->GetSyncState(ctx, req, resp).ok());
    return resp.projects_size() ? resp.projects(0) : pb::ProjectSyncState{};
  }

  static std::map<std::uint64_t, std::uint64_t> Vector(const pb::ProjectSyncState &s) {
    std::map<std::uint64_t, std::uint64_t> out;
    for (const auto &e : s.version_vector().entries()) out[e.replica()] = e.counter();
    return out;
  }

  std::size_t Programs(Daemon &d) {
    pb::ListProgramsRequest req;
    req.set_project_id("default");
    pb::ListProgramsResponse resp;
    return d.backend->ListPrograms(ctx_, req, resp).ok() ? static_cast<std::size_t>(resp.programs_size()) : 0;
  }

  // Every daemon holds the same ops, none waiting, every program loaded.
  void WaitConverged(const std::vector<Daemon *> &ds, std::chrono::seconds limit = 120s) {
    const auto until = std::chrono::steady_clock::now() + limit;
    std::string why;
    while (std::chrono::steady_clock::now() < until) {
      why.clear();
      const auto first = Vector(State(*ds[0]));
      const std::size_t programs = Programs(*ds[0]);
      for (Daemon *d : ds) {
        pb::ProjectSyncState s = State(*d);
        if (Vector(s) != first) why = "version vectors differ";
        else if (s.waiting()) why = "ops waiting";
        else if (s.missing_programs_size()) why = "program files missing";
        else if (Programs(*d) != programs) why = "program counts differ";
      }
      if (why.empty()) return;
      std::this_thread::sleep_for(20ms);
    }
    FAIL() << "daemons did not converge: " << why;
  }

  pb::AppendAssertionsResponse Append(Daemon &d, const pb::AssertionBody &body, const std::string &actor,
                                      pb::ProvenanceKind kind = pb::PROVENANCE_KIND_USER, const std::string &session = {}) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(kind);
    req.mutable_provenance()->set_id(actor);
    req.mutable_provenance()->set_session(session);
    *req.add_assertions()->mutable_body() = body;
    pb::AppendAssertionsResponse resp;
    auto st = d.backend->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  void Retract(Daemon &d, std::uint64_t seq, const std::string &actor) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(id_);
    req.add_seqs(seq);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id(actor);
    pb::RetractAssertionsResponse resp;
    auto st = d.backend->RetractAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  }

  static pb::AssertionBody Rename(std::uint64_t addr, const std::string &name) {
    pb::AssertionBody body;
    body.mutable_rename()->mutable_target()->mutable_address()->set_offset(addr);
    body.mutable_rename()->set_name(name);
    return body;
  }
  static pb::AssertionBody Comment(std::uint64_t addr, pb::CommentKind kind, const std::string &text) {
    pb::AssertionBody body;
    body.mutable_comment()->mutable_address()->set_offset(addr);
    body.mutable_comment()->set_kind(kind);
    body.mutable_comment()->set_text(text);
    return body;
  }
  static pb::AssertionBody Bounds(std::uint64_t entry, std::uint64_t first, std::uint64_t last) {
    pb::AssertionBody body;
    body.mutable_function_bounds()->mutable_entry()->set_offset(entry);
    auto *r = body.mutable_function_bounds()->add_body();
    r->mutable_first()->set_offset(first);
    r->mutable_last()->set_offset(last);
    return body;
  }

  pb::FactKey Key(pb::FactKind kind, std::uint64_t addr, const std::string &sub = {}) {
    pb::FactKey k;
    k.set_program_id(id_);
    k.set_kind(kind);
    k.mutable_address()->set_offset(addr);
    k.set_sub(sub);
    return k;
  }

  pb::BlameResponse Blame(Daemon &d, const pb::FactKey &key) {
    pb::BlameRequest req;
    *req.mutable_key() = key;
    pb::BlameResponse resp;
    auto st = d.backend->Blame(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  // Blame in global terms: ids, never local seqs or revisions.
  std::string BlameText(Daemon &d, const pb::FactKey &key) {
    pb::BlameResponse b = Blame(d, key);
    std::map<std::uint64_t, std::string> ids;
    std::ostringstream os;
    os << pb::FactKind_Name(key.kind()) << "@" << std::hex << key.address().offset() << std::dec << key.sub() << " = "
       << b.value_text() << " (" << (b.origin().has_asserted() ? IdText(b.origin().asserted().id()) : "derived") << ")\n";
    for (const auto &c : b.candidates()) {
      ids[c.seq()] = IdText(c.id());
      os << "  " << IdText(c.id()) << " " << pb::ProvenanceKind_Name(c.provenance().kind()) << ":" << c.provenance().id()
         << " " << c.body().ShortDebugString() << " " << pb::AssertionStatus_Name(c.status());
      for (const auto &r : c.retracted_by_ids()) os << " by:" << IdText(r);
      os << "\n";
    }
    for (std::uint64_t s : b.concurrent_seqs()) os << "  concurrent " << ids[s] << "\n";
    return os.str();
  }

  // The whole log of the program, by global id.
  std::string LogText(Daemon &d) {
    pb::ListAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_filter()->set_include_inactive(true);
    req.mutable_page()->set_page_size(5000);
    pb::ListAssertionsResponse resp;
    EXPECT_TRUE(d.backend->ListAssertions(ctx_, req, resp).ok());
    std::vector<std::string> lines;
    for (const auto &a : resp.assertions()) {
      std::ostringstream os;
      os << IdText(a.id()) << " " << a.stamp() << " " << pb::AssertionOp_Name(a.op()) << " " << a.key().ShortDebugString()
         << " " << pb::ProvenanceKind_Name(a.provenance().kind()) << ":" << a.provenance().id() << " "
         << a.body().ShortDebugString() << " " << pb::AssertionStatus_Name(a.status());
      if (a.has_retracts_id()) os << " retracts:" << IdText(a.retracts_id());
      for (const auto &r : a.retracted_by_ids()) os << " by:" << IdText(r);
      lines.push_back(os.str());
    }
    std::sort(lines.begin(), lines.end());
    std::string out;
    for (auto &l : lines) out += l + "\n";
    return out;
  }

  std::map<std::string, std::uint64_t> Functions(Daemon &d) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id_);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(d.backend->ListFunctions(ctx_, req, resp).ok());
    std::map<std::string, std::uint64_t> out;
    for (const auto &f : resp.functions()) out[f.name()] = f.entry().offset();
    return out;
  }

  // Every function: name, body, and decompiled C.
  std::string CodeText(Daemon &d) {
    pb::ListFunctionsRequest req;
    req.set_program_id(id_);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(d.backend->ListFunctions(ctx_, req, resp).ok());
    std::ostringstream os;
    for (const auto &f : resp.functions()) {
      os << f.name() << " @" << std::hex << f.entry().offset();
      for (const auto &r : f.body()) os << " [" << r.first().offset() << "," << r.last().offset() << "]";
      os << std::dec << "\n";
      pb::DecompileRequest dreq;
      dreq.set_program_id(id_);
      *dreq.mutable_function() = f.entry();
      dreq.mutable_options()->set_include_text(true);
      pb::DecompileResponse dresp;
      auto st = d.backend->Decompile(ctx_, dreq, dresp);
      EXPECT_TRUE(st.ok()) << st.message;
      os << dresp.function().text();
    }
    return os.str();
  }

  void ExpectIdentical(const std::vector<Daemon *> &ds, const std::vector<pb::FactKey> &keys, bool code = true) {
    const std::string log = LogText(*ds[0]);
    std::string blame;
    for (const auto &k : keys) blame += BlameText(*ds[0], k);
    const std::string c = code ? CodeText(*ds[0]) : "";
    for (std::size_t i = 1; i < ds.size(); ++i) {
      SCOPED_TRACE("daemon " + std::to_string(i));
      EXPECT_EQ(LogText(*ds[i]), log);
      std::string b;
      for (const auto &k : keys) b += BlameText(*ds[i], k);
      EXPECT_EQ(b, blame);
      if (code) {
        EXPECT_EQ(CodeText(*ds[i]), c);
      }
    }
  }

  std::string Import(Daemon &d) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_path(program_.string());
    pb::ImportProgramResponse resp;
    auto st = d.backend->ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  std::uint64_t SeqOf(Daemon &d, const pb::FactKey &key, const std::string &value_contains) {
    const pb::BlameResponse b = Blame(d, key);
    for (const auto &c : b.candidates())
      if (c.body().ShortDebugString().find(value_contains) != std::string::npos) return c.seq();
    ADD_FAILURE() << "no candidate " << value_contains;
    return 0;
  }

  static inline fs::path program_;
  static inline bool compiled_ = false;
  CallContext ctx_;
  std::string id_;
};

class Events : public api::EventSink {
 public:
  void Send(pb::SubscribeResponse e) override {
    std::lock_guard lock(mu_);
    events_.push_back(std::move(e));
  }
  void End(api::Status) override {}
  std::vector<pb::SubscribeResponse> events() {
    std::lock_guard lock(mu_);
    return events_;
  }

 private:
  std::mutex mu_;
  std::vector<pb::SubscribeResponse> events_;
};

// Three daemons in a chain (c - b - a, so a's ops reach c through b):
// concurrent renames and comments, retractions, a revert across daemons,
// a partition and its heal, then a late joiner; every step converges to
// identical assertions, blame, functions and decompiled C.
TEST_F(CollabTest, ThreeDaemonsConverge) {
  auto a = Start(), b = Start(), c = Start();
  id_ = Import(*a);
  ASSERT_EQ(id_, "default/prog");
  Link(*b, *a);
  Link(*c, *b);
  WaitConverged({a.get(), b.get(), c.get()});
  ASSERT_EQ(Programs(*c), 1u);  // its record and file came through b
  auto fns = Functions(*a);
  ASSERT_EQ(Functions(*c), fns);
  const std::uint64_t checksum = fns.at("checksum"), lonely = fns.at("lonely"), main = fns.at("main"),
                      twice = fns.at("twice");

  // Live edits on all three at once.
  std::thread ta([&] {
    Append(*a, Rename(checksum, "fnv_a"), "alice");
    Append(*a, Comment(checksum, pb::COMMENT_KIND_EOL, "hash loop"), "alice");
  });
  std::thread tb([&] {
    Append(*b, Rename(checksum, "fnv_b"), "bob");
    Append(*b, Comment(main, pb::COMMENT_KIND_PLATE, "entry point"), "bob");
  });
  std::thread tc([&] {
    // An agent run: its rename loses to the DWARF name, its comment shows.
    Append(*c, Rename(lonely, "solo"), "claude", pb::PROVENANCE_KIND_AGENT, "run1");
    Append(*c, Comment(lonely, pb::COMMENT_KIND_PRE, "agent says"), "claude", pb::PROVENANCE_KIND_AGENT, "run1");
  });
  ta.join();
  tb.join();
  tc.join();
  WaitConverged({a.get(), b.get(), c.get()});
  const std::vector<pb::FactKey> keys{Key(pb::FACT_KIND_NAME, checksum),           Key(pb::FACT_KIND_NAME, lonely),
                                      Key(pb::FACT_KIND_COMMENT, lonely, "pre"),   Key(pb::FACT_KIND_NAME, twice),
                                      Key(pb::FACT_KIND_COMMENT, checksum, "eol"), Key(pb::FACT_KIND_COMMENT, main, "plate")};
  ExpectIdentical({a.get(), b.get(), c.get()}, keys);
  EXPECT_EQ(Blame(*c, keys[1]).value_text(), "lonely");  // import:dwarf outranks the agent
  EXPECT_EQ(Blame(*a, keys[2]).value_text(), "agent says");

  // Retractions on one daemon of another's edits: bob (on b) retracts
  // alice's comment; the agent (on c) retracts bob's plate comment.
  Retract(*b, SeqOf(*b, Key(pb::FACT_KIND_COMMENT, checksum, "eol"), "hash loop"), "bob");
  {
    pb::RetractAssertionsRequest req;
    req.set_program_id(id_);
    req.add_seqs(SeqOf(*c, Key(pb::FACT_KIND_COMMENT, main, "plate"), "entry point"));
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_AGENT);
    req.mutable_provenance()->set_id("claude");
    req.mutable_provenance()->set_session("run1");
    pb::RetractAssertionsResponse resp;
    auto st = c->backend->RetractAssertions(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
  }
  WaitConverged({a.get(), b.get(), c.get()});
  for (Daemon *d : {a.get(), b.get(), c.get()}) {
    EXPECT_EQ(Blame(*d, Key(pb::FACT_KIND_COMMENT, main, "plate")).value_text(), "");
    EXPECT_EQ(Blame(*d, Key(pb::FACT_KIND_COMMENT, checksum, "eol")).value_text(), "");
  }
  ExpectIdentical({a.get(), b.get(), c.get()}, keys);

  // A user on a reverts the agent run: its rename, its comment and its
  // retraction, so bob's comment comes back, on every daemon.
  {
    pb::RevertByProvenanceRequest req;
    req.set_program_id(id_);
    req.mutable_filter()->set_kind(pb::PROVENANCE_KIND_AGENT);
    req.mutable_filter()->set_session("run1");
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("alice");
    pb::RevertByProvenanceResponse resp;
    ASSERT_TRUE(a->backend->RevertByProvenance(ctx_, req, resp).ok());
    EXPECT_EQ(resp.retracted_seqs_size(), 3);
  }
  WaitConverged({a.get(), b.get(), c.get()});
  for (Daemon *d : {a.get(), b.get(), c.get()}) {
    EXPECT_EQ(Blame(*d, Key(pb::FACT_KIND_COMMENT, main, "plate")).value_text(), "entry point");
    EXPECT_EQ(Blame(*d, Key(pb::FACT_KIND_COMMENT, lonely, "pre")).value_text(), "");
  }
  ExpectIdentical({a.get(), b.get(), c.get()}, keys);

  // Partition: a and c edit the same name and each other's comment while
  // cut off; then heal.
  a->links.clear();
  b->links.clear();
  c->links.clear();
  Append(*a, Rename(lonely, "from_a"), "alice");
  Append(*a, Comment(twice, pb::COMMENT_KIND_PRE, "a's note"), "alice");
  Append(*c, Rename(lonely, "from_c"), "carol");
  Retract(*c, SeqOf(*c, Key(pb::FACT_KIND_NAME, checksum), "fnv_"), "carol");
  EXPECT_NE(Blame(*a, Key(pb::FACT_KIND_NAME, lonely)).value_text(), Blame(*c, Key(pb::FACT_KIND_NAME, lonely)).value_text());
  EXPECT_NE(Vector(State(*a)), Vector(State(*c)));
  Link(*b, *a);
  Link(*c, *b);
  WaitConverged({a.get(), b.get(), c.get()});
  const std::vector<pb::FactKey> more{Key(pb::FACT_KIND_COMMENT, twice, "pre")};
  std::vector<pb::FactKey> all = keys;
  all.insert(all.end(), more.begin(), more.end());
  ExpectIdentical({a.get(), b.get(), c.get()}, all);
  // The partitioned renames were concurrent: blame says so, on every daemon.
  pb::BlameResponse contested = Blame(*b, Key(pb::FACT_KIND_NAME, lonely));
  EXPECT_EQ(contested.concurrent_seqs_size(), 1);
  EXPECT_TRUE(contested.value_text() == "from_a" || contested.value_text() == "from_c");

  // A late joiner, linked to c only, catches up on everything, program
  // file included.
  auto d = Start();
  Link(*d, *c);
  WaitConverged({a.get(), b.get(), c.get(), d.get()});
  ASSERT_EQ(Programs(*d), 1u);
  ExpectIdentical({a.get(), d.get()}, all);
}

// Subscribers of one daemon see edits made on another as ordinary
// revisions (cause REPLICATION) with the usual invalidation; presence
// reaches every daemon's clients.
TEST_F(CollabTest, PeersEditsInvalidateSubscribersAndPresenceSpreads) {
  auto a = Start(), b = Start(), c = Start();
  id_ = Import(*a);
  Link(*b, *a);
  Link(*c, *b);
  WaitConverged({a.get(), b.get(), c.get()});
  const std::uint64_t checksum = Functions(*a).at("checksum");

  auto events = std::make_shared<Events>();
  std::unique_ptr<api::Subscription> sub;
  {
    pb::SubscribeRequest req;
    req.set_project_id("default");
    req.set_include_presence(true);
    ASSERT_TRUE(c->backend->Subscribe(ctx_, req, events, sub).ok());
  }
  Append(*a, Rename(checksum, "fnv1a"), "alice");
  {
    pb::UpdatePresenceRequest req;
    req.set_project_id("default");
    auto *p = req.mutable_presence();
    p->set_client_id("tab-1");
    p->mutable_who()->set_kind(pb::PROVENANCE_KIND_USER);
    p->mutable_who()->set_id("alice");
    p->set_program_id(id_);
    p->mutable_address()->set_offset(checksum);
    p->set_view("decompiler");
    pb::UpdatePresenceResponse resp;
    ASSERT_TRUE(a->backend->UpdatePresence(ctx_, req, resp).ok());
    EXPECT_EQ(resp.presence().sequence(), 1u);
  }
  WaitConverged({a.get(), b.get(), c.get()});
  const auto until = std::chrono::steady_clock::now() + 30s;
  bool renamed = false, present = false;
  while (std::chrono::steady_clock::now() < until && !(renamed && present)) {
    for (const auto &e : events->events()) {
      if (e.has_revision() && e.revision().cause() == pb::CHANGE_CAUSE_REPLICATION) {
        bool key = false, decompile = false;
        for (const auto &k : e.revision().changed_keys())
          key = key || (k.kind() == pb::FACT_KIND_NAME && k.address().offset() == checksum);
        for (const auto &q : e.revision().invalidated())
          decompile = decompile || (q.kind() == pb::QUERY_KIND_DECOMPILE && q.address().offset() == checksum);
        renamed = renamed || (key && decompile);
      }
      if (e.has_presence() && e.presence().client_id() == "tab-1") present = e.presence().address().offset() == checksum;
    }
    std::this_thread::sleep_for(20ms);
  }
  EXPECT_TRUE(renamed);
  EXPECT_TRUE(present);
  // Listed on the far daemon too; then the client leaves.
  pb::ListPresenceRequest lreq;
  lreq.set_project_id("default");
  pb::ListPresenceResponse lresp;
  ASSERT_TRUE(c->backend->ListPresence(ctx_, lreq, lresp).ok());
  ASSERT_EQ(lresp.presence_size(), 1);
  EXPECT_EQ(lresp.presence(0).view(), "decompiler");
  {
    pb::UpdatePresenceRequest req;
    req.set_project_id("default");
    req.mutable_presence()->set_client_id("tab-1");
    req.mutable_presence()->set_left(true);
    pb::UpdatePresenceResponse resp;
    ASSERT_TRUE(a->backend->UpdatePresence(ctx_, req, resp).ok());
  }
  const auto left_until = std::chrono::steady_clock::now() + 30s;
  do {
    lresp.Clear();
    ASSERT_TRUE(c->backend->ListPresence(ctx_, lreq, lresp).ok());
    if (!lresp.presence_size()) break;
    std::this_thread::sleep_for(20ms);
  } while (std::chrono::steady_clock::now() < left_until);
  EXPECT_EQ(lresp.presence_size(), 0);
  sub.reset();
}

// Concurrent structural edits (docs/collab.md): two daemons set the same
// function's bounds differently, and bodies of two functions that overlap,
// while partitioned. After the heal one body wins per entry, overlapping
// bodies are split by the rule, and every daemon lists the same functions
// with the same bodies and the same decompiled C.
TEST_F(CollabTest, ConcurrentFunctionBoundsConverge) {
  auto a = Start(), b = Start();
  id_ = Import(*a);
  Link(*b, *a);
  WaitConverged({a.get(), b.get()});
  auto fns = Functions(*a);
  const std::uint64_t lo = std::min(fns.at("checksum"), fns.at("lonely")),
                      hi = std::max(fns.at("checksum"), fns.at("lonely"));
  b->links.clear();
  // a: lo's body runs into hi. b: hi's body starts before hi; and both
  // set lo's bounds.
  Append(*a, Bounds(lo, lo, hi + 3), "alice");
  Append(*b, Bounds(hi, hi - 2, hi + 7), "bob");
  Append(*b, Bounds(lo, lo, lo + 15), "bob");
  Link(*b, *a);
  WaitConverged({a.get(), b.get()});
  const std::vector<pb::FactKey> keys{Key(pb::FACT_KIND_FUNCTION_BOUNDS, lo), Key(pb::FACT_KIND_FUNCTION_BOUNDS, hi)};
  ExpectIdentical({a.get(), b.get()}, keys);
  pb::BlameResponse bounds = Blame(*a, keys[0]);
  EXPECT_EQ(bounds.concurrent_seqs_size(), 1);
  // Bodies are disjoint.
  pb::ListFunctionsRequest req;
  req.set_program_id(id_);
  req.mutable_page()->set_page_size(5000);
  pb::ListFunctionsResponse resp;
  ASSERT_TRUE(a->backend->ListFunctions(ctx_, req, resp).ok());
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
  for (const auto &f : resp.functions())
    for (const auto &r : f.body()) ranges.emplace_back(r.first().offset(), r.last().offset());
  std::sort(ranges.begin(), ranges.end());
  for (std::size_t i = 1; i < ranges.size(); ++i) EXPECT_GT(ranges[i].first, ranges[i - 1].second);
}

// Memory-map edits replicate like any other edit, and a region's bytes from
// another file travel as a program's file does, by their hash
// (docs/memory-map.md, "Collaborators").
TEST_F(CollabTest, MemoryMapEditsReplicateWithTheirBytes) {
  auto a = Start(), b = Start();
  id_ = Import(*a);
  Link(*b, *a);
  WaitConverged({a.get(), b.get()});
  auto add = [&](Daemon &d, const std::string &name, std::uint64_t start, std::uint64_t size, const std::string *bytes) {
    pb::AddMemoryRegionRequest req;
    req.set_program_id(id_);
    req.mutable_region()->set_name(name);
    req.mutable_region()->set_start(start);
    req.mutable_region()->set_size(size);
    req.mutable_region()->set_read(true);
    req.mutable_region()->set_write(true);
    if (bytes) req.set_content(*bytes);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id(name);
    pb::AddMemoryRegionResponse resp;
    auto st = d.backend->AddMemoryRegion(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
  };
  const std::string dump(5000, 'D');
  add(*a, "dump", 0x7f0000000000, 0, &dump);
  add(*b, "sram", 0x7f1000000000, 0x1000, nullptr);
  WaitConverged({a.get(), b.get()});
  auto map = [&](Daemon &d) {
    pb::GetMemoryMapRequest req;
    req.set_program_id(id_);
    pb::GetMemoryMapResponse resp;
    EXPECT_TRUE(d.backend->GetMemoryMap(ctx_, req, resp).ok());
    std::string out;
    for (const auto &m : resp.blocks())
      out += m.name() + "@" + std::to_string(m.range().first().offset()) + ":" +
             std::to_string(static_cast<int>(m.source().kind())) + (m.source().missing() ? "?" : "") + " ";
    return out;
  };
  // The bytes arrive after the edit: wait for them.
  for (auto deadline = std::chrono::steady_clock::now() + 60s;
       map(*b).find("?") != std::string::npos && std::chrono::steady_clock::now() < deadline;)
    std::this_thread::sleep_for(50ms);
  EXPECT_EQ(map(*a), map(*b));
  EXPECT_NE(map(*b).find("dump@139637976727552:2 "), std::string::npos) << map(*b);
  EXPECT_NE(map(*a).find("sram@"), std::string::npos) << map(*a);
  pb::ReadMemoryRequest rr;
  rr.set_program_id(id_);
  rr.mutable_address()->set_offset(0x7f0000000000);
  rr.set_length(5000);
  pb::ReadMemoryResponse rresp;
  ASSERT_TRUE(b->backend->ReadMemory(ctx_, rr, rresp).ok());
  EXPECT_EQ(rresp.data(), dump);
}

// DefineType assertions (TYPE_DEF keyed by content hash) replicate like
// any other: the same type defined on two partitioned daemons is the same
// key with the same value (two candidates, one value), a type defined on
// one daemon resolves on the other, and a retype to it shows everywhere.
TEST_F(CollabTest, DefinedTypesReplicateAndMergeByHash) {
  auto a = Start(), b = Start();
  id_ = Import(*a);
  Link(*b, *a);
  WaitConverged({a.get(), b.get()});
  b->links.clear();
  // int, and struct <name> { int x; int <field> @4 }: returns their hashes.
  auto define = [&](Daemon &d, const std::string &actor, const std::string &name, const std::string &field) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id_);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id(actor);
    pb::TypeNode *i32 = req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
    i32->set_kind(pb::TYPE_KIND_INT);
    i32->set_size(4);
    i32->set_rank(pb::INTEGER_RANK_INT);
    pb::TypeNode *st = req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type();
    st->set_kind(pb::TYPE_KIND_STRUCT);
    st->set_name(name);
    st->set_size(8);
    auto *x = st->add_fields();
    x->set_name("x");
    x->mutable_type()->set_assertion_index(0);
    auto *y = st->add_fields();
    y->set_name(field);
    y->set_offset(4);
    y->mutable_type()->set_assertion_index(0);
    pb::AppendAssertionsResponse resp;
    auto status = d.backend->AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(status.ok()) << status.message;
    std::vector<std::string> hashes;
    for (const auto &as : resp.assertions()) hashes.push_back(as.key().sub());
    return hashes;
  };
  const auto on_a = define(*a, "alice", "pair", "y");
  const auto on_b = define(*b, "bob", "pair", "y");
  const auto other = define(*b, "bob", "pair2", "z");
  ASSERT_EQ(on_a.size(), 2u);
  EXPECT_EQ(on_a, on_b);  // same content, same keys
  ASSERT_NE(other[1], on_a[1]);
  // b types the global `counter` with the int it defined.
  pb::ListSymbolsRequest sreq;
  sreq.set_program_id(id_);
  sreq.set_name_equals("counter");
  pb::ListSymbolsResponse sresp;
  ASSERT_TRUE(b->backend->ListSymbols(ctx_, sreq, sresp).ok());
  ASSERT_EQ(sresp.symbols_size(), 1);
  const std::uint64_t counter = sresp.symbols(0).address().offset();
  pb::AssertionBody retype;
  retype.mutable_retype()->mutable_target()->mutable_address()->set_offset(counter);
  retype.mutable_retype()->mutable_type()->set_type_hash(other[0]);
  Append(*b, retype, "bob");

  Link(*b, *a);
  WaitConverged({a.get(), b.get()});
  const std::vector<pb::FactKey> keys{Key(pb::FACT_KIND_TYPE_DEF, 0, on_a[0]), Key(pb::FACT_KIND_TYPE_DEF, 0, on_a[1]),
                                      Key(pb::FACT_KIND_TYPE_DEF, 0, other[1]), Key(pb::FACT_KIND_TYPE, counter)};
  ExpectIdentical({a.get(), b.get()}, keys);
  // Both definitions of `pair` are candidates of one key, both live.
  pb::BlameResponse pair = Blame(*a, keys[1]);
  ASSERT_EQ(pair.candidates_size(), 2);
  for (const auto &c : pair.candidates())
    EXPECT_TRUE(c.status() == pb::ASSERTION_STATUS_EFFECTIVE || c.status() == pb::ASSERTION_STATUS_SHADOWED);
  // b's own type resolves on a, field by field.
  pb::GetTypesRequest treq;
  treq.set_program_id(id_);
  treq.add_hashes(other[1]);
  pb::GetTypesResponse tresp;
  ASSERT_TRUE(a->backend->GetTypes(ctx_, treq, tresp).ok());
  ASSERT_EQ(tresp.types_size(), 1);
  EXPECT_EQ(tresp.types(0).name(), "pair2");
  EXPECT_EQ(tresp.missing_size(), 0);
  EXPECT_EQ(Blame(*a, keys[3]).candidates_size(), 2);  // DWARF's int and bob's
}

// A persistent daemon keeps what it merged from a peer, the peer's program
// file included, across a restart, and catches up on what it missed.
TEST_F(CollabTest, PersistentReplicaRestartsAndCatchesUp) {
  auto dir = testing::scratch_dir("collab-persist");
  fs::remove_all(dir);
  auto a = Start();
  id_ = Import(*a);
  const std::uint64_t checksum = Functions(*a).at("checksum");
  Append(*a, Rename(checksum, "before_restart"), "alice");
  {
    auto b = Start(dir.string());
    Link(*b, *a);
    WaitConverged({a.get(), b.get()});
  }
  Append(*a, Rename(checksum, "while_away"), "alice");
  auto b = Start(dir.string());
  ASSERT_EQ(Programs(*b), 1u);  // reopened from its own store
  EXPECT_EQ(Blame(*b, Key(pb::FACT_KIND_NAME, checksum)).value_text(), "before_restart");
  Link(*b, *a);
  WaitConverged({a.get(), b.get()});
  EXPECT_EQ(Blame(*b, Key(pb::FACT_KIND_NAME, checksum)).value_text(), "while_away");
  ExpectIdentical({a.get(), b.get()}, {Key(pb::FACT_KIND_NAME, checksum)});
  b.reset();
  fs::remove_all(dir);
}

// Replication between authenticated daemons over TLS (docs/security.md):
// a peer token issued by `a` lets `b` link to it with a's certificate
// pinned; a wrong token or a plaintext link replicates nothing.
TEST_F(CollabTest, AuthenticatedPeersOverTls) {
  auto dir = testing::scratch_dir("collab-auth");
  fs::remove_all(dir);
  fs::create_directories(dir);
  auth::StoreOptions so;
  so.path = (dir / "auth.db").string();
  so.scrypt = {10, 8, 1};
  auto store = std::make_shared<auth::Store>(so);
  const std::string peer_token = store->create_token("daemon-b", auth::Role::kPeer).secret;
  const std::string viewer_token = store->create_token("dash", auth::Role::kViewer).secret;
  const auth::CertKey cert = auth::generate_self_signed({});

  auto a = Start({}, store, {cert.cert_pem, cert.key_pem});
  id_ = Import(*a);
  const std::uint64_t checksum = Functions(*a).at("checksum");
  Append(*a, Rename(checksum, "from_a"), "alice");

  auto b = Start();
  api::PeerLinkOptions tls;
  tls.tls = true;
  tls.tls_root_pem = cert.cert_pem;
  tls.tls_server_name = "localhost";
  // A token without the peer role, and plaintext: nothing arrives.
  {
    api::PeerLinkOptions o = tls;
    o.bearer_token = viewer_token;
    Link(*b, *a, o);
    api::PeerLinkOptions plain;
    plain.bearer_token = peer_token;
    auto c = Start();
    Link(*c, *a, plain);
    std::this_thread::sleep_for(1500ms);
    EXPECT_EQ(Programs(*b), 0u);
    EXPECT_EQ(Programs(*c), 0u);
    b->links.clear();
  }
  // The peer token over TLS with the certificate pinned: both ways.
  api::PeerLinkOptions o = tls;
  o.bearer_token = peer_token;
  Link(*b, *a, o);
  WaitConverged({a.get(), b.get()});
  EXPECT_EQ(Blame(*b, Key(pb::FACT_KIND_NAME, checksum)).value_text(), "from_a");
  Append(*b, Rename(checksum, "from_b"), "bob");
  WaitConverged({a.get(), b.get()});
  EXPECT_EQ(Blame(*a, Key(pb::FACT_KIND_NAME, checksum)).value_text(), "from_b");
  ExpectIdentical({a.get(), b.get()}, {Key(pb::FACT_KIND_NAME, checksum)}, false);
  b.reset();
  a.reset();
  fs::remove_all(dir);
}

}  // namespace
}  // namespace revkit::backend
