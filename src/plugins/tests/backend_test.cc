// Plugins through the image backend, as rk-daemon serves them: a loader
// plugin importing a custom format, a command plugin's edits with their
// provenance, blame and revert, and analyzer facts with precise
// invalidation after an edit.

#include "builders.hh"

#include "revkit/backend/image_backend.h"
#include "revkit/loader/load.hh"
#include "revkit/plugins/host.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace revkit::plugins {
namespace {

namespace pb = ::revkit::v1;
using api::CallContext;
using api::StatusCode;

const char *kFixture = R"(
const char greeting[] __attribute__((aligned(4096))) = "hello, plugin";
__attribute__((noinline)) int sum(const char *s) { int t = 0; while (*s) t += *s++; return t; }
__attribute__((noinline)) int uses_greeting(void) { return sum(greeting); }
__attribute__((noinline)) int no_strings(int x) { return x * 3 + 1; }
void _start(void) {
  volatile int r = uses_greeting() + no_strings(3);
  (void)r;
  for (;;) {}
}
)";

// RKRAW (sdk/plugins/examples/rkraw-loader/README.md) from an ELF's
// initialized blocks and function symbols.
std::string MakeRkraw(const loader::Image &elf, bool truncate = false) {
  std::vector<const loader::Block *> blocks;
  for (const loader::Block &b : elf.blocks)
    if (b.initialized && b.size && (b.name == ".text" || b.name == ".rodata")) blocks.push_back(&b);
  std::vector<const loader::Symbol *> syms;
  for (const loader::Symbol &s : elf.symbols)
    if (s.defined && s.type == loader::SymbolType::func && s.name.size() < 20) syms.push_back(&s);
  std::string out(80 + 48 * blocks.size() + 32 * syms.size(), '\0');
  auto put = [&](std::size_t at, std::uint64_t v, int n) {
    for (int i = 0; i < n; ++i) out[at + i] = static_cast<char>(v >> (8 * i));
  };
  std::memcpy(out.data(), "RKRAW\x01", 6);
  put(6, blocks.size(), 2);
  put(8, *elf.entry, 8);
  std::memcpy(out.data() + 16, "x86:LE:64:default", 17);
  std::memcpy(out.data() + 56, "gcc", 3);
  put(72, syms.size(), 4);
  for (std::size_t i = 0; i < blocks.size(); ++i) {
    const loader::Block &b = *blocks[i];
    std::size_t at = 80 + 48 * i;
    std::memcpy(out.data() + at, b.name.data(), std::min<std::size_t>(b.name.size(), 15));
    put(at + 16, b.start, 8);
    put(at + 24, b.size, 8);
    put(at + 32, out.size(), 4);
    put(at + 36, b.size, 4);
    put(at + 40, b.perms.exec ? 5 : 1, 4);
    std::string bytes(b.size, '\0');
    elf.memory.read(b.start, std::span(reinterpret_cast<std::byte *>(bytes.data()), bytes.size()));
    out += bytes;
  }
  for (std::size_t i = 0; i < syms.size(); ++i) {
    std::size_t at = 80 + 48 * blocks.size() + 32 * i;
    std::memcpy(out.data() + at, syms[i]->name.data(), syms[i]->name.size());
    put(at + 20, syms[i]->value, 8);
    put(at + 28, 1, 4);
  }
  if (truncate) out.resize(100);
  return out;
}

class PluginBackend : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (std::string(REVKIT_GHIDRA_ROOT).empty() || std::string(REVKIT_EXAMPLE_PLUGINS).empty()) return;
    dir_ = revkit::testing::scratch_dir("plugin-backend");
    const std::string flags =
        "-O1 -nostdlib -static -ffreestanding -fno-pie -no-pie -fno-asynchronous-unwind-tables -fno-unwind-tables";
    compiled_ = revkit::testing::compile(REVKIT_TEST_CC, kFixture, flags, dir_ / "named") &&
                revkit::testing::compile(REVKIT_TEST_CC, kFixture, flags + " -s", dir_ / "stripped");
  }

  void SetUp() override {
    if (!Host::available()) GTEST_SKIP() << "built without wasmtime";
    if (std::string(REVKIT_EXAMPLE_PLUGINS).empty()) GTEST_SKIP() << "example plugins not built (no wasm32 clang)";
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!compiled_) GTEST_SKIP() << "can't build the fixture";
    named_ = loader::load_file(dir_ / "named", {.image_base = std::nullopt, .ghidra_image_base = true, .macho_slice = {}});
    for (const loader::Symbol &s : named_.symbols)
      if (s.defined) sym_[s.name] = s.value;
    backend_ = Make();
  }

  std::unique_ptr<api::Backend> Make(const std::string &project_dir = {}, bool with_plugins = true) {
    backend::ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir;
    if (with_plugins) {
      o.plugins = std::make_shared<Host>();
      for (const auto &r : o.plugins->load_dir(REVKIT_EXAMPLE_PLUGINS)) ADD_FAILURE() << r.error;
    }
    return backend::MakeImageBackend(o);
  }

  std::string Import(const std::string &content, const std::string &name, const std::string &format = {},
                     api::Status *status = nullptr, api::Backend *b = nullptr) {
    pb::ImportProgramRequest req;
    req.set_project_id("default");
    req.set_content(content);
    req.set_name(name);
    req.mutable_options()->set_format(format);
    pb::ImportProgramResponse resp;
    auto st = (b ? b : backend_.get())->ImportProgram(ctx_, req, resp);
    if (status) *status = st;
    else EXPECT_TRUE(st.ok()) << st.message;
    format_ = resp.program().format();
    return resp.program().program_id();
  }
  static std::string Read(const std::filesystem::path &p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), {});
  }

  std::map<std::uint64_t, std::string> Functions(const std::string &program, api::Backend *b = nullptr) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse resp;
    auto st = (b ? b : backend_.get())->ListFunctions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    std::map<std::uint64_t, std::string> out;
    for (const auto &f : resp.functions()) out[f.entry().offset()] = f.name();
    return out;
  }

  api::Status Run(const std::string &program, const std::map<std::string, std::string> &args,
                  pb::RunCommandResponse &resp, pb::ProvenanceKind kind = pb::PROVENANCE_KIND_USER, bool dry = false,
                  const std::string &plugin = "rename-regex") {
    pb::RunCommandRequest req;
    req.set_program_id(program);
    req.set_plugin(plugin);
    for (const auto &[k, v] : args) (*req.mutable_args())[k] = v;
    req.mutable_provenance()->set_kind(kind);
    req.mutable_provenance()->set_id(kind == pb::PROVENANCE_KIND_AGENT ? "claude" : "alice");
    req.mutable_provenance()->set_session("s1");
    req.set_dry_run(dry);
    return backend_->RunCommand(ctx_, req, resp);
  }

  pb::GetPluginFactsResponse Facts(const std::string &program, const std::string &plugin) {
    pb::GetPluginFactsRequest req;
    req.set_program_id(program);
    req.add_plugins(plugin);
    pb::GetPluginFactsResponse resp;
    auto st = backend_->GetPluginFacts(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  static inline std::filesystem::path dir_;
  static inline bool compiled_ = false;
  loader::Image named_;
  std::map<std::string, std::uint64_t> sym_;
  std::unique_ptr<api::Backend> backend_;
  std::string format_;
  CallContext ctx_;
};

TEST_F(PluginBackend, ServerInfoAndPluginList) {
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(backend_->GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 6u);  // plugins arrived in 6; later minors keep them
  EXPECT_NE(std::find(info.features().begin(), info.features().end(), "plugins"), info.features().end());

  pb::ListPluginsResponse list;
  ASSERT_TRUE(backend_->ListPlugins(ctx_, {}, list).ok());
  EXPECT_EQ(list.interface_version(), 1u);
  std::map<std::string, pb::Plugin> by_name;
  for (const auto &p : list.plugins()) by_name[p.name()] = p;
  ASSERT_EQ(by_name.size(), 5u);
  EXPECT_EQ(by_name["rename-regex"].kind(), pb::PLUGIN_KIND_COMMAND);
  EXPECT_EQ(by_name["tick-timer"].kind(), pb::PLUGIN_KIND_PERIPHERAL);
  EXPECT_EQ(by_name["tick-timer"].peripheral_outputs_size(), 1);
  EXPECT_EQ(by_name["tick-timer"].peripheral_size(), 256u);
  EXPECT_EQ(by_name["rename-regex"].args_size(), 3);
  EXPECT_EQ(by_name["rkraw-loader"].magic(), "524b52415701");
  EXPECT_TRUE(by_name["string-refs"].function_scope());
  EXPECT_TRUE(by_name["crc32-tables"].loaded());
  EXPECT_EQ(by_name["string-refs"].capabilities_size(), 2);

  pb::ListAnalyzersResponse analyzers;
  ASSERT_TRUE(backend_->ListAnalyzers(ctx_, {}, analyzers).ok());
  bool listed = false;
  for (const auto &a : analyzers.analyzers()) listed |= a.id() == "plugin:string-refs@1.0.0";
  EXPECT_TRUE(listed);
}

// A plugin the daemon rejected is listed with why, but only admins see
// the daemon's plugin directory in it: ListPlugins is a viewer's call.
TEST_F(PluginBackend, RejectedPluginsDontShowViewersTheHostPath) {
  const std::filesystem::path bad = revkit::testing::scratch_dir("plugin-rejected");
  std::ofstream(bad / "broken.wasm") << "not wasm";  // and no manifest: an error naming its path
  backend::ImageBackendOptions o;
  o.ghidra_root = REVKIT_GHIDRA_ROOT;
  o.plugins = std::make_shared<Host>();
  ASSERT_FALSE(o.plugins->load_dir(bad).empty());
  auto b = backend::MakeImageBackend(o);
  CallContext viewer;
  viewer.caller = "user:vera";
  viewer.caller_admin = false;
  for (const CallContext *who : {&ctx_, &viewer}) {
    pb::ListPluginsResponse list;
    ASSERT_TRUE(b->ListPlugins(*who, {}, list).ok());
    ASSERT_EQ(list.plugins_size(), 1);
    EXPECT_FALSE(list.plugins(0).loaded());
    EXPECT_FALSE(list.plugins(0).error().empty());
    EXPECT_EQ(list.plugins(0).error().find(bad.string()) != std::string::npos, who == &ctx_)
        << list.plugins(0).error();
  }
}

TEST_F(PluginBackend, ALoaderPluginImportsACustomFormat) {
  const std::string raw = MakeRkraw(named_);
  // Detected by its magic...
  std::string id = Import(raw, "fixture.rkr");
  EXPECT_EQ(format_, "plugin:rkraw-loader@1.0.0");
  auto fns = Functions(id);
  EXPECT_EQ(fns[sym_["uses_greeting"]], "uses_greeting");
  EXPECT_EQ(fns[sym_["no_strings"]], "no_strings");
  EXPECT_EQ(fns[sym_["_start"]], "_start");
  // ...decompiled like any program...
  pb::DecompileRequest dreq;
  dreq.set_program_id(id);
  dreq.mutable_function()->set_offset(sym_["no_strings"]);
  dreq.mutable_options()->set_include_text(true);
  pb::DecompileResponse dresp;
  ASSERT_TRUE(backend_->Decompile(ctx_, dreq, dresp).ok());
  EXPECT_NE(dresp.function().text().find("no_strings"), std::string::npos) << dresp.function().text();
  // ...or chosen by name.
  Import(raw, "again.rkr", "rkraw-loader");
  EXPECT_EQ(format_, "plugin:rkraw-loader@1.0.0");

  // A malformed file fails the import with the plugin's message.
  api::Status st;
  Import(MakeRkraw(named_, true), "broken.rkr", {}, &st);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  EXPECT_NE(st.message.find("RKRAW: block or symbol table past the end"), std::string::npos) << st.message;
  Import(raw, "x", "no-such-loader", &st);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
}

TEST_F(PluginBackend, ALoaderPluginReopensItsPrograms) {
  auto project_dir = revkit::testing::scratch_dir("plugin-backend-reopen");
  std::string id;
  {
    auto b = Make(project_dir.string());
    id = Import(MakeRkraw(named_), "fixture.rkr", {}, nullptr, b.get());
  }
  {
    auto b = Make(project_dir.string());
    EXPECT_EQ(Functions(id, b.get())[sym_["uses_greeting"]], "uses_greeting");
  }
  {
    // Without the plugin the program can't be loaded; the daemon still starts.
    auto b = Make(project_dir.string(), false);
    pb::ListFunctionsRequest req;
    req.set_program_id(id);
    pb::ListFunctionsResponse resp;
    EXPECT_EQ(b->ListFunctions(ctx_, req, resp).code, StatusCode::kNotFound);
  }
}

TEST_F(PluginBackend, CommandEditsCarryPluginProvenanceAndRevert) {
  const std::string id = Import(Read(dir_ / "stripped"), "stripped");
  auto before = Functions(id);
  std::size_t defaults = 0;
  for (const auto &[a, n] : before) defaults += n.starts_with("FUN_");
  ASSERT_GE(defaults, 3u);

  // A dry run proposes the edits without committing them.
  pb::RunCommandResponse dry;
  ASSERT_TRUE(Run(id, {{"pattern", "^FUN_0*([0-9a-f]+)$"}, {"replace", "sub_\\1"}}, dry, pb::PROVENANCE_KIND_USER, true).ok());
  EXPECT_EQ(static_cast<std::size_t>(dry.assertions_size()), defaults);
  EXPECT_EQ(Functions(id), before);

  pb::RunCommandResponse resp;
  auto st = Run(id, {{"pattern", "^FUN_0*([0-9a-f]+)$"}, {"replace", "sub_\\1"}}, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(static_cast<std::size_t>(resp.assertions_size()), defaults);
  EXPECT_GT(resp.fuel_consumed(), 0u);
  const pb::Assertion &a = resp.assertions(0);
  EXPECT_EQ(a.provenance().kind(), pb::PROVENANCE_KIND_PLUGIN);
  EXPECT_EQ(a.provenance().id(), "rename-regex");
  EXPECT_EQ(a.provenance().version(), "1.0.0");
  EXPECT_EQ(a.provenance().session(), "s1");  // the caller's
  // The normal assertion path gives them replication identities too.
  for (const pb::Assertion &x : resp.assertions()) {
    EXPECT_NE(x.id().replica(), 0u);
    EXPECT_GT(x.id().counter(), 0u);
    EXPECT_GT(x.stamp(), 0u);
  }
  const std::uint64_t entry = sym_["uses_greeting"];
  auto after = Functions(id);
  char hex[32];
  std::snprintf(hex, sizeof hex, "sub_%llx", static_cast<unsigned long long>(entry));
  EXPECT_EQ(after[entry], hex);

  // Blame names the plugin; a user's rename still outranks it.
  pb::BlameRequest breq;
  breq.mutable_key()->set_program_id(id);
  breq.mutable_key()->set_kind(pb::FACT_KIND_NAME);
  breq.mutable_key()->mutable_address()->set_offset(entry);
  pb::BlameResponse blame;
  ASSERT_TRUE(backend_->Blame(ctx_, breq, blame).ok());
  EXPECT_EQ(blame.origin().asserted().provenance().kind(), pb::PROVENANCE_KIND_PLUGIN);
  {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("bob");
    auto *r = req.add_assertions()->mutable_body()->mutable_rename();
    r->mutable_target()->mutable_address()->set_offset(entry);
    r->set_name("greet");
    pb::AppendAssertionsResponse out;
    ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, out).ok());
  }
  EXPECT_EQ(Functions(id)[entry], "greet");

  // Reverting the plugin's work brings every other default name back.
  pb::RevertByProvenanceRequest rreq;
  rreq.set_program_id(id);
  rreq.mutable_filter()->set_kind(pb::PROVENANCE_KIND_PLUGIN);
  rreq.mutable_filter()->set_id("rename-regex");
  rreq.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
  rreq.mutable_provenance()->set_id("alice");
  pb::RevertByProvenanceResponse rresp;
  ASSERT_TRUE(backend_->RevertByProvenance(ctx_, rreq, rresp).ok());
  EXPECT_EQ(static_cast<std::size_t>(rresp.retracted_seqs_size()), defaults);
  auto reverted = Functions(id);
  for (const auto &[addr, name] : before) EXPECT_EQ(reverted[addr], addr == entry ? "greet" : name);
}

TEST_F(PluginBackend, AnAgentRunningACommandKeepsItsProvenance) {
  const std::string id = Import(Read(dir_ / "stripped"), "stripped");
  pb::RunCommandResponse resp;
  ASSERT_TRUE(Run(id, {{"pattern", "^FUN_"}, {"replace", "auto_"}, {"limit", "1"}}, resp, pb::PROVENANCE_KIND_AGENT).ok());
  ASSERT_EQ(resp.assertions_size(), 1);
  EXPECT_EQ(resp.assertions(0).provenance().kind(), pb::PROVENANCE_KIND_AGENT);
  EXPECT_EQ(resp.assertions(0).provenance().id(), "claude");
  EXPECT_EQ(resp.assertions(0).provenance().tool(), "plugin:rename-regex@1.0.0");
}

TEST_F(PluginBackend, CommandErrorsAreReported) {
  const std::string id = Import(Read(dir_ / "stripped"), "stripped");
  pb::RunCommandResponse resp;
  EXPECT_EQ(Run(id, {{"pattern", "x"}}, resp).code, StatusCode::kInvalidArgument);  // replace is required
  EXPECT_EQ(Run(id, {{"pattern", "x"}, {"replace", "y"}, {"bogus", "1"}}, resp).code, StatusCode::kInvalidArgument);
  auto st = Run(id, {{"pattern", "(unclosed"}, {"replace", "y"}}, resp);
  EXPECT_EQ(st.code, StatusCode::kFailedPrecondition);
  EXPECT_NE(st.message.find("bad pattern: missing )"), std::string::npos) << st.message;
  EXPECT_EQ(Run(id, {}, resp, pb::PROVENANCE_KIND_USER, false, "no-such").code, StatusCode::kNotFound);
  EXPECT_EQ(Run(id, {}, resp, pb::PROVENANCE_KIND_USER, false, "string-refs").code, StatusCode::kInvalidArgument);
  // A name the backend won't accept fails the whole batch, as AppendAssertions does.
  st = Run(id, {{"pattern", "^FUN_"}, {"replace", "bad name "}}, resp);
  EXPECT_FALSE(st.ok());
}

TEST_F(PluginBackend, AnalyzerFactsAreServedAndInvalidatedPrecisely) {
  const std::string id = Import(Read(dir_ / "stripped"), "stripped");
  auto resp = Facts(id, "string-refs");
  EXPECT_EQ(resp.errors_size(), 0);
  bool comment = false, label = false;
  for (const auto &f : resp.facts()) {
    EXPECT_EQ(f.origin().derived().rule(), "plugin:string-refs@1.0.0");
    comment |= f.kind() == pb::PLUGIN_FACT_KIND_COMMENT && f.text() == "\"hello, plugin\"";
    label |= f.kind() == pb::PLUGIN_FACT_KIND_LABEL && f.text() == "str_hello_plugin" &&
             f.address().offset() == sym_["uses_greeting"];
  }
  EXPECT_TRUE(comment && label);

  struct Events : api::EventSink {
    std::vector<pb::RevisionEvent> revisions;
    void Send(pb::SubscribeResponse e) override {
      if (e.has_revision()) revisions.push_back(e.revision());
    }
    void End(api::Status) override {}
  };
  auto events = std::make_shared<Events>();
  std::unique_ptr<api::Subscription> sub;
  pb::SubscribeRequest sreq;
  sreq.set_project_id("default");
  ASSERT_TRUE(backend_->Subscribe(ctx_, sreq, events, sub).ok());

  // Renaming one function re-runs only its analyzer: it asked for its name.
  backend::ResetQueryCounters(*backend_, "default");
  {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("bob");
    auto *r = req.add_assertions()->mutable_body()->mutable_rename();
    r->mutable_target()->mutable_address()->set_offset(sym_["uses_greeting"]);
    r->set_name("greet");
    pb::AppendAssertionsResponse out;
    ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, out).ok());
  }
  resp = Facts(id, "string-refs");
  EXPECT_EQ(backend::QueryCounters(*backend_, "default")["plugins.analyze"].executions, 1u);
  // Subscribers were told to refetch plugin facts (the rename is a NAME a
  // plugin may read); a comment, which no plugin reads, doesn't.
  ASSERT_FALSE(events->revisions.empty());
  auto has_plugin_facts = [](const pb::RevisionEvent &ev) {
    return std::any_of(ev.invalidated().begin(), ev.invalidated().end(),
                       [](const auto &q) { return q.kind() == pb::QUERY_KIND_PLUGIN_FACTS; });
  };
  EXPECT_TRUE(has_plugin_facts(events->revisions.back()));
  {
    pb::AppendAssertionsRequest req;
    req.set_program_id(id);
    req.mutable_provenance()->set_kind(pb::PROVENANCE_KIND_USER);
    req.mutable_provenance()->set_id("bob");
    auto *c = req.add_assertions()->mutable_body()->mutable_comment();
    c->mutable_address()->set_offset(sym_["no_strings"]);
    c->set_kind(pb::COMMENT_KIND_EOL);
    c->set_text("x3");
    pb::AppendAssertionsResponse out;
    ASSERT_TRUE(backend_->AppendAssertions(ctx_, req, out).ok());
  }
  EXPECT_FALSE(has_plugin_facts(events->revisions.back()));
  for (const auto &f : resp.facts()) EXPECT_NE(f.kind(), pb::PLUGIN_FACT_KIND_LABEL) << f.text();

  // A range restricts the functions analyzed and the facts returned.
  pb::GetPluginFactsRequest req;
  req.set_program_id(id);
  req.mutable_range()->mutable_first()->set_offset(sym_["no_strings"]);
  req.mutable_range()->mutable_last()->set_offset(sym_["no_strings"]);
  pb::GetPluginFactsResponse ranged;
  ASSERT_TRUE(backend_->GetPluginFacts(ctx_, req, ranged).ok());
  EXPECT_EQ(ranged.facts_size(), 0);
}

}  // namespace
}  // namespace revkit::plugins
