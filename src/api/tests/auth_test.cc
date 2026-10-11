// Authentication, authorization and TLS end to end (docs/security.md): a
// real Server with a credential store and a certificate, exercised over
// gRPC (HTTP/2 + TLS) and over the HTTPS gateway the way a browser would
// (session cookie, CSRF header, Origin).
#include "revkit/api/auth_policy.h"
#include "revkit/api/fake_backend.h"
#include "revkit/api/server.h"
#include "revkit/auth/store.h"
#include "revkit/auth/tls.h"

#include "revkit/v1/assertion.grpc.pb.h"
#include "revkit/v1/diff.pb.h"
#include "revkit/v1/auth.grpc.pb.h"
#include "revkit/v1/meta.grpc.pb.h"
#include "revkit/v1/presence.grpc.pb.h"
#include "revkit/v1/script.pb.h"
#include "revkit/v1/types.grpc.pb.h"
#include "revkit/v1/project.grpc.pb.h"
#include "revkit/v1/query.grpc.pb.h"
#include "revkit/v1/subscription.grpc.pb.h"
#include "revkit/v1/sync.grpc.pb.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/util/json_util.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

namespace revkit::api {
namespace {

namespace fs = std::filesystem;
namespace gp = google::protobuf;

const auth::CertKey &Cert() {
  static const auth::CertKey ck = auth::generate_self_signed({});
  return ck;
}

std::string Envelope(const std::string &payload) {
  std::string out(5, '\0');
  auto n = static_cast<std::uint32_t>(payload.size());
  for (int i = 0; i < 4; ++i) out[1 + i] = static_cast<char>(n >> (24 - 8 * i));
  return out + payload;
}

// "Set-Cookie: name=value; ..." -> value.
std::string CookieValue(const std::string &set_cookie) {
  auto eq = set_cookie.find('=');
  return set_cookie.substr(eq + 1, set_cookie.find(';') - eq - 1);
}

class AuthTest : public ::testing::Test {
 protected:
  void SetUp() override {
    dir_ = fs::temp_directory_path() / ("rk-api-auth-" + std::to_string(::getpid()) + "-" +
                                        ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(dir_);
    fs::create_directories(dir_);
    std::ofstream(dir_ / "ca.pem") << Cert().cert_pem;
    auth::StoreOptions so;
    so.path = (dir_ / "auth.db").string();
    so.scrypt = {10, 8, 1};
    store_ = std::make_shared<auth::Store>(so);
    store_->add_user("root", auth::Role::kAdmin, "root-password");
    store_->add_user("alice", auth::Role::kEditor, "alice-password");
    store_->add_user("vic", auth::Role::kViewer, "vic-password");
    store_->add_user("pat", auth::Role::kEditor, "pat-password", {"other"});
    bot_ = store_->create_token("bot", auth::Role::kEditor).secret;
    peer_ = store_->create_token("daemon-b", auth::Role::kPeer).secret;

    ServerOptions opts;
    opts.grpc_address = "127.0.0.1:0";
    opts.http_address = "127.0.0.1:0";
    opts.auth = store_;
    opts.tls = {Cert().cert_pem, Cert().key_pem};
    opts.allowed_origins = {"tauri://localhost"};
    // RestartDaemon's hook: counted, nothing restarts.
    opts.restart = [this] { ++restarts_; };
    std::string error;
    server_ = Server::Start(MakeFakeBackend(), opts, error);
    ASSERT_TRUE(server_) << error;
    grpc::SslCredentialsOptions ssl;
    ssl.pem_root_certs = Cert().cert_pem;
    grpc::ChannelArguments args;
    args.SetSslTargetNameOverride("localhost");
    channel_ = grpc::CreateCustomChannel("127.0.0.1:" + std::to_string(server_->grpc_port()),
                                         grpc::SslCredentials(ssl), args);
  }
  void TearDown() override {
    server_.reset();
    fs::remove_all(dir_);
  }

  // A context carrying `token` (if any).
  static std::unique_ptr<grpc::ClientContext> Ctx(const std::string &token = "") {
    auto ctx = std::make_unique<grpc::ClientContext>();
    ctx->set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(20));
    if (!token.empty()) ctx->AddMetadata("authorization", "Bearer " + token);
    return ctx;
  }

  std::string Login(const std::string &user, const std::string &password, grpc::Status *status = nullptr) {
    auto stub = pb::AuthService::NewStub(channel_);
    pb::LoginRequest req;
    req.set_username(user);
    req.set_password(password);
    pb::LoginResponse resp;
    auto ctx = Ctx();
    grpc::Status st = stub->Login(ctx.get(), req, &resp);
    if (status) *status = st;
    else EXPECT_TRUE(st.ok()) << st.error_message();
    return resp.token();
  }

  grpc::Status Rename(const std::string &token, const std::string &name, pb::Provenance prov,
                      pb::AppendAssertionsResponse *out = nullptr) {
    auto stub = pb::AssertionService::NewStub(channel_);
    pb::AppendAssertionsRequest req;
    req.set_program_id(fake::kProgramId);
    *req.mutable_provenance() = prov;
    auto *r = req.add_assertions()->mutable_body()->mutable_rename();
    r->mutable_target()->mutable_address()->set_offset(0x401040);
    r->set_name(name);
    pb::AppendAssertionsResponse resp;
    auto ctx = Ctx(token);
    grpc::Status st = stub->AppendAssertions(ctx.get(), req, &resp);
    if (out) *out = resp;
    return st;
  }

  grpc::Status ListFunctions(const std::string &token, const std::string &program = fake::kProgramId) {
    auto stub = pb::QueryService::NewStub(channel_);
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    pb::ListFunctionsResponse resp;
    auto ctx = Ctx(token);
    return stub->ListFunctions(ctx.get(), req, &resp);
  }

  std::unique_ptr<httplib::SSLClient> HttpsClient() {
    auto c = std::make_unique<httplib::SSLClient>("127.0.0.1", server_->http_port());
    c->set_ca_cert_path((dir_ / "ca.pem").string());
    c->enable_server_certificate_verification(true);
    c->set_read_timeout(std::chrono::seconds(10));
    return c;
  }

  static pb::Provenance Prov(pb::ProvenanceKind kind = pb::PROVENANCE_KIND_UNSPECIFIED, const std::string &id = "") {
    pb::Provenance p;
    p.set_kind(kind);
    p.set_id(id);
    p.set_session("s1");
    p.set_reason("test");
    return p;
  }

  fs::path dir_;
  std::shared_ptr<auth::Store> store_;
  std::string bot_, peer_;
  std::unique_ptr<Server> server_;
  std::shared_ptr<grpc::Channel> channel_;
  std::atomic<int> restarts_{0};
};

// MetaService.RestartDaemon: admins only; a dry run restarts nothing; a
// real one answers first and calls the daemon's hook.
TEST_F(AuthTest, RestartDaemonIsForAdminsOnly) {
  auto meta = pb::MetaService::NewStub(channel_);
  auto restart = [&](const std::string &token, bool dry, pb::RestartDaemonResponse *out = nullptr) {
    pb::RestartDaemonRequest req;
    req.set_dry_run(dry);
    req.set_reason("test");
    pb::RestartDaemonResponse resp;
    auto ctx = Ctx(token);
    grpc::Status st = meta->RestartDaemon(ctx.get(), req, &resp);
    if (out) *out = resp;
    return st;
  };
  EXPECT_EQ(restart("", false).error_code(), grpc::StatusCode::UNAUTHENTICATED);
  EXPECT_EQ(restart(Login("vic", "vic-password"), false).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(restart(Login("alice", "alice-password"), false).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(restart(bot_, true).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(restart(peer_, false).error_code(), grpc::StatusCode::PERMISSION_DENIED);

  const std::string root = Login("root", "root-password");
  {
    pb::GetServerInfoRequest req;
    pb::GetServerInfoResponse info;
    auto ctx = Ctx(root);
    ASSERT_TRUE(meta->GetServerInfo(ctx.get(), req, &info).ok());
    EXPECT_NE(std::find(info.features().begin(), info.features().end(), "daemon-restart"), info.features().end());
  }
  // A subscription open: the dry run counts it.
  auto subs = pb::SubscriptionService::NewStub(channel_);
  auto sctx = Ctx(root);
  pb::SubscribeRequest sreq;
  sreq.set_project_id("demo");
  auto stream = subs->Subscribe(sctx.get(), sreq);
  pb::RestartDaemonResponse dry;
  for (int i = 0; i < 100; ++i) {
    ASSERT_TRUE(restart(root, true, &dry).ok());
    if (dry.open_streams() >= 1) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  EXPECT_EQ(dry.mode(), "reexec");
  EXPECT_EQ(dry.open_streams(), 1u);
  sctx->TryCancel();
  stream->Finish();
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  EXPECT_EQ(restarts_.load(), 0) << "a dry run restarted";

  ASSERT_TRUE(restart(root, false).ok());
  for (int i = 0; i < 100 && restarts_.load() == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(restarts_.load(), 1);
}

// A server without a restart hook (not rk-daemon) refuses, and doesn't
// list the feature; with --no-auth the anonymous caller is an admin.
TEST(AuthServer, RestartNeedsTheDaemonsHook) {
  ServerOptions o;
  o.grpc_address = "127.0.0.1:0";
  o.http_address = "";
  std::string error;
  auto server = Server::Start(MakeFakeBackend(), o, error);
  ASSERT_TRUE(server) << error;
  auto ch = grpc::CreateChannel("127.0.0.1:" + std::to_string(server->grpc_port()), grpc::InsecureChannelCredentials());
  auto meta = pb::MetaService::NewStub(ch);
  pb::RestartDaemonRequest req;
  pb::RestartDaemonResponse resp;
  grpc::ClientContext ctx;
  EXPECT_EQ(meta->RestartDaemon(&ctx, req, &resp).error_code(), grpc::StatusCode::FAILED_PRECONDITION);
  pb::GetServerInfoResponse info;
  grpc::ClientContext ctx2;
  ASSERT_TRUE(meta->GetServerInfo(&ctx2, pb::GetServerInfoRequest(), &info).ok());
  EXPECT_EQ(std::find(info.features().begin(), info.features().end(), "daemon-restart"), info.features().end());
}

TEST_F(AuthTest, GrpcServesTlsOnly) {
  auto stub = pb::MetaService::NewStub(channel_);
  pb::GetServerInfoResponse info;
  auto ctx = Ctx();
  grpc::Status st = stub->GetServerInfo(ctx.get(), {}, &info);
  ASSERT_TRUE(st.ok()) << st.error_message();
  for (const char *f : {"auth", "auth-required", "provenance-stamping"})
    EXPECT_NE(std::find(info.features().begin(), info.features().end(), f), info.features().end()) << f;

  auto plain = pb::MetaService::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(server_->grpc_port()),
                                                            grpc::InsecureChannelCredentials()));
  auto ctx2 = Ctx();
  ctx2->set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(3));
  EXPECT_FALSE(plain->GetServerInfo(ctx2.get(), {}, &info).ok());

  // A certificate other than the server's is refused.
  grpc::SslCredentialsOptions other;
  other.pem_root_certs = auth::generate_self_signed({}).cert_pem;
  grpc::ChannelArguments args;
  args.SetSslTargetNameOverride("localhost");
  auto wrong = pb::MetaService::NewStub(grpc::CreateCustomChannel(
      "127.0.0.1:" + std::to_string(server_->grpc_port()), grpc::SslCredentials(other), args));
  auto ctx3 = Ctx();
  ctx3->set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(3));
  EXPECT_FALSE(wrong->GetServerInfo(ctx3.get(), {}, &info).ok());
}

TEST_F(AuthTest, GatewayServesHttpsOnly) {
  auto client = HttpsClient();
  auto &https = *client;
  auto r = https.Post("/revkit.v1.MetaService/GetServerInfo", "{}", "application/json");
  ASSERT_TRUE(r) << httplib::to_string(r.error());
  EXPECT_EQ(r->status, 200);
  EXPECT_EQ(r->get_header_value("X-Content-Type-Options"), "nosniff");

  httplib::Client plain("127.0.0.1", server_->http_port());
  plain.set_read_timeout(std::chrono::seconds(3));
  auto p = plain.Post("/revkit.v1.MetaService/GetServerInfo", "{}", "application/json");
  EXPECT_TRUE(!p || p->status != 200);
}

TEST_F(AuthTest, LoginBearerAndLogout) {
  EXPECT_EQ(ListFunctions("").error_code(), grpc::StatusCode::UNAUTHENTICATED);
  EXPECT_EQ(ListFunctions("rks_forged").error_code(), grpc::StatusCode::UNAUTHENTICATED);
  grpc::Status st;
  Login("alice", "wrong password", &st);
  EXPECT_EQ(st.error_code(), grpc::StatusCode::UNAUTHENTICATED);
  Login("nobody", "alice-password", &st);
  EXPECT_EQ(st.error_code(), grpc::StatusCode::UNAUTHENTICATED);

  std::string token = Login("alice", "alice-password");
  ASSERT_TRUE(token.starts_with("rks_"));
  EXPECT_TRUE(ListFunctions(token).ok());

  auto stub = pb::AuthService::NewStub(channel_);
  pb::WhoAmIResponse who;
  auto ctx = Ctx(token);
  ASSERT_TRUE(stub->WhoAmI(ctx.get(), {}, &who).ok());
  EXPECT_TRUE(who.auth_enabled());
  EXPECT_EQ(who.identity().name(), "alice");
  EXPECT_EQ(who.identity().role(), pb::ROLE_EDITOR);
  EXPECT_EQ(who.identity().provenance().kind(), pb::PROVENANCE_KIND_USER);
  EXPECT_FALSE(who.csrf_token().empty());

  pb::WhoAmIResponse anon;
  auto ctx2 = Ctx();
  ASSERT_TRUE(stub->WhoAmI(ctx2.get(), {}, &anon).ok());
  EXPECT_TRUE(anon.auth_enabled());
  EXPECT_FALSE(anon.has_identity());

  pb::LogoutResponse out;
  auto ctx3 = Ctx(token);
  ASSERT_TRUE(stub->Logout(ctx3.get(), {}, &out).ok());
  EXPECT_EQ(ListFunctions(token).error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST_F(AuthTest, ApiTokensAndManagementOverTheApi) {
  EXPECT_TRUE(ListFunctions(bot_).ok());
  std::string root = Login("root", "root-password");
  auto stub = pb::AuthService::NewStub(channel_);

  pb::CreateTokenRequest creq;
  creq.set_name("ci");
  creq.set_role(pb::ROLE_VIEWER);
  creq.set_ttl_seconds(3600);
  pb::CreateTokenResponse cresp;
  auto ctx = Ctx(root);
  ASSERT_TRUE(stub->CreateToken(ctx.get(), creq, &cresp).ok());
  EXPECT_TRUE(cresp.secret().starts_with("rkt_"));
  EXPECT_TRUE(cresp.token().has_expires_at());
  EXPECT_TRUE(ListFunctions(cresp.secret()).ok());

  // Only admins manage.
  auto ctx2 = Ctx(bot_);
  EXPECT_EQ(stub->CreateToken(ctx2.get(), creq, &cresp).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  pb::ListUsersResponse users;
  auto ctx3 = Ctx(root);
  ASSERT_TRUE(stub->ListUsers(ctx3.get(), {}, &users).ok());
  EXPECT_EQ(users.users_size(), 4);

  pb::CreateUserRequest u;
  u.set_name("carol");
  u.set_role(pb::ROLE_EDITOR);
  u.set_password("carol-password");
  pb::CreateUserResponse ur;
  auto ctx4 = Ctx(root);
  ASSERT_TRUE(stub->CreateUser(ctx4.get(), u, &ur).ok());
  std::string carol = Login("carol", "carol-password");
  pb::UpdateUserRequest up;
  up.set_name("carol");
  up.set_role(pb::ROLE_VIEWER);
  pb::UpdateUserResponse upr;
  auto ctx5 = Ctx(root);
  ASSERT_TRUE(stub->UpdateUser(ctx5.get(), up, &upr).ok());
  EXPECT_EQ(ListFunctions(carol).error_code(), grpc::StatusCode::UNAUTHENTICATED);  // a new role ends sessions

  pb::RevokeTokenRequest rv;
  rv.set_id("ci");
  pb::RevokeTokenResponse rvr;
  auto ctx6 = Ctx(root);
  ASSERT_TRUE(stub->RevokeToken(ctx6.get(), rv, &rvr).ok());
  EXPECT_EQ(ListFunctions(cresp.secret()).error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST_F(AuthTest, RolesAreEnforced) {
  std::string vic = Login("vic", "vic-password"), alice = Login("alice", "alice-password");
  EXPECT_TRUE(ListFunctions(vic).ok());
  EXPECT_EQ(Rename(vic, "x", Prov()).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_TRUE(Rename(alice, "x", Prov()).ok());

  auto projects = pb::ProjectService::NewStub(channel_);
  pb::ImportProgramRequest imp;
  imp.set_project_id("demo");
  imp.set_content("\x7f" "ELF");
  pb::ImportProgramResponse impr;
  auto ctx = Ctx(alice);
  EXPECT_EQ(projects->ImportProgram(ctx.get(), imp, &impr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  pb::ListHostFilesRequest lh;
  pb::ListHostFilesResponse lhr;
  auto ctx2 = Ctx(alice);
  EXPECT_EQ(projects->ListHostFiles(ctx2.get(), lh, &lhr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  pb::OpenProjectRequest op;
  op.set_path("/etc");
  pb::OpenProjectResponse opr;
  auto ctx3 = Ctx(alice);
  EXPECT_EQ(projects->OpenProject(ctx3.get(), op, &opr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  std::string root = Login("root", "root-password");
  auto ctx4 = Ctx(root);
  EXPECT_NE(projects->ListHostFiles(ctx4.get(), lh, &lhr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  // An import's progress (api_minor 22): whoever may import (admin); the
  // backend then answers only the caller that started it.
  pb::GetImportProgressRequest gip;
  gip.set_project_id("demo");
  gip.set_import_id("someone's");
  pb::GetImportProgressResponse gipr;
  auto ctx_gip = Ctx(alice);
  EXPECT_EQ(projects->GetImportProgress(ctx_gip.get(), gip, &gipr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  auto ctx_gip2 = Ctx(root);
  EXPECT_NE(projects->GetImportProgress(ctx_gip2.get(), gip, &gipr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  // Raw layout detection (api_minor 23) reads a host path or an upload, as
  // an import does: whoever may import, and so its progress and stopping it.
  pb::DetectRawLayoutRequest det;
  det.set_project_id("demo");
  det.set_path("/etc/hostname");
  pb::DetectRawLayoutResponse detr;
  pb::GetRawDetectProgressRequest gdp;
  gdp.set_project_id("demo");
  gdp.set_detect_id("someone's");
  pb::GetRawDetectProgressResponse gdpr;
  pb::CancelRawDetectRequest crd;
  crd.set_project_id("demo");
  crd.set_detect_id("someone's");
  pb::CancelRawDetectResponse crdr;
  for (const std::string &who : {vic, alice}) {
    auto c1 = Ctx(who), c2 = Ctx(who), c3 = Ctx(who);
    EXPECT_EQ(projects->DetectRawLayout(c1.get(), det, &detr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_EQ(projects->GetRawDetectProgress(c2.get(), gdp, &gdpr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_EQ(projects->CancelRawDetect(c3.get(), crd, &crdr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  }
  {
    auto c1 = Ctx(root), c2 = Ctx(root), c3 = Ctx(root);
    EXPECT_NE(projects->DetectRawLayout(c1.get(), det, &detr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(projects->GetRawDetectProgress(c2.get(), gdp, &gdpr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_NE(projects->CancelRawDetect(c3.get(), crd, &crdr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
    // Without credentials it is refused before anything is read.
    grpc::ClientContext anonymous;
    EXPECT_EQ(projects->DetectRawLayout(&anonymous, det, &detr).error_code(), grpc::StatusCode::UNAUTHENTICATED);
  }

  // Parsing C (api_minor 25): a viewer's read, unless it reads host files.
  auto types = pb::TypeService::NewStub(channel_);
  pb::ParseCRequest pc;
  pc.set_program_id(fake::kProgramId);
  pc.add_sources()->set_text("struct s { int a; };");
  pb::ParseCResponse pcr;
  auto ctx_pc = Ctx(vic);
  EXPECT_NE(types->ParseC(ctx_pc.get(), pc, &pcr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  pc.add_include_dirs("/usr/include");
  auto ctx_pc2 = Ctx(alice);
  EXPECT_EQ(types->ParseC(ctx_pc2.get(), pc, &pcr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  pc.clear_include_dirs();
  pc.mutable_sources(0)->set_path("/etc/hostname");
  auto ctx_pc3 = Ctx(alice);
  EXPECT_EQ(types->ParseC(ctx_pc3.get(), pc, &pcr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  auto ctx_pc4 = Ctx(root);
  EXPECT_NE(types->ParseC(ctx_pc4.get(), pc, &pcr).error_code(), grpc::StatusCode::PERMISSION_DENIED);

  // Program management (api_minor 19): renaming is an editor's, deleting an admin's.
  pb::RenameProgramRequest ren;
  ren.set_program_id(fake::kProgramId);
  ren.set_name("renamed");
  pb::RenameProgramResponse renr;
  auto ctx7 = Ctx(vic);
  EXPECT_EQ(projects->RenameProgram(ctx7.get(), ren, &renr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  auto ctx8 = Ctx(alice);
  EXPECT_NE(projects->RenameProgram(ctx8.get(), ren, &renr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  pb::DeleteProgramRequest del;
  del.set_program_id(fake::kProgramId);
  pb::DeleteProgramResponse delr;
  auto ctx9 = Ctx(alice);
  EXPECT_EQ(projects->DeleteProgram(ctx9.get(), del, &delr).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  auto ctx10 = Ctx(root);
  EXPECT_NE(projects->DeleteProgram(ctx10.get(), del, &delr).error_code(), grpc::StatusCode::PERMISSION_DENIED);

  // Peers replicate and do nothing else; nobody else replicates.
  EXPECT_EQ(ListFunctions(peer_).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  auto sync = pb::SyncService::NewStub(channel_);
  pb::GetSyncStateResponse ss;
  auto ctx5 = Ctx(root);
  EXPECT_EQ(sync->GetSyncState(ctx5.get(), {}, &ss).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  auto ctx6 = Ctx(peer_);
  EXPECT_NE(sync->GetSyncState(ctx6.get(), {}, &ss).error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuthTest, ProvenanceIsStampedByTheServer) {
  std::string alice = Login("alice", "alice-password"), root = Login("root", "root-password");
  pb::AppendAssertionsResponse r;
  ASSERT_TRUE(Rename(alice, "a1", Prov(), &r).ok());
  EXPECT_EQ(r.assertions(0).provenance().kind(), pb::PROVENANCE_KIND_USER);
  EXPECT_EQ(r.assertions(0).provenance().id(), "alice");
  EXPECT_EQ(r.assertions(0).provenance().session(), "s1");
  EXPECT_EQ(r.assertions(0).provenance().reason(), "test");
  ASSERT_TRUE(Rename(alice, "a2", Prov(pb::PROVENANCE_KIND_USER, "alice"), &r).ok());
  ASSERT_TRUE(Rename(alice, "a3", Prov(pb::PROVENANCE_KIND_USER, ""), &r).ok());
  EXPECT_EQ(r.assertions(0).provenance().id(), "alice");

  // Claiming someone else is refused.
  grpc::Status st = Rename(alice, "evil", Prov(pb::PROVENANCE_KIND_USER, "bob"));
  EXPECT_EQ(st.error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_NE(st.error_message().find("user:alice"), std::string::npos) << st.error_message();
  EXPECT_EQ(Rename(alice, "evil", Prov(pb::PROVENANCE_KIND_AGENT, "bot")).error_code(),
            grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(Rename(alice, "evil", Prov(pb::PROVENANCE_KIND_IMPORT, "ghidra")).error_code(),
            grpc::StatusCode::PERMISSION_DENIED);

  // An agent token writes as agent:<its name>, with the client's version.
  pb::Provenance agent = Prov(pb::PROVENANCE_KIND_AGENT, "");
  agent.set_version("opus-5.5");
  ASSERT_TRUE(Rename(bot_, "b1", agent, &r).ok());
  EXPECT_EQ(r.assertions(0).provenance().kind(), pb::PROVENANCE_KIND_AGENT);
  EXPECT_EQ(r.assertions(0).provenance().id(), "bot");
  EXPECT_EQ(r.assertions(0).provenance().version(), "opus-5.5");
  ASSERT_TRUE(Rename(bot_, "b2", Prov(), &r).ok());
  EXPECT_EQ(r.assertions(0).provenance().id(), "bot");
  EXPECT_EQ(Rename(bot_, "evil", Prov(pb::PROVENANCE_KIND_USER, "alice")).error_code(),
            grpc::StatusCode::PERMISSION_DENIED);

  // An admin's importer keeps its own name (the Ghidra bridge).
  ASSERT_TRUE(Rename(root, "g1", Prov(pb::PROVENANCE_KIND_IMPORT, "ghidra"), &r).ok());
  EXPECT_EQ(r.assertions(0).provenance().kind(), pb::PROVENANCE_KIND_IMPORT);
  EXPECT_EQ(r.assertions(0).provenance().id(), "ghidra");

  // Presence names the server's identity, whatever the client says.
  auto presence = pb::PresenceService::NewStub(channel_);
  pb::UpdatePresenceRequest pr;
  pr.set_project_id("demo");
  pr.mutable_presence()->set_client_id("tab-1");
  pr.mutable_presence()->mutable_who()->set_kind(pb::PROVENANCE_KIND_USER);
  pr.mutable_presence()->mutable_who()->set_id("bob");
  pr.mutable_presence()->set_display_name("Bob");
  pb::UpdatePresenceResponse prr;
  auto ctx = Ctx(alice);
  grpc::Status pst = presence->UpdatePresence(ctx.get(), pr, &prr);
  if (pst.error_code() != grpc::StatusCode::UNIMPLEMENTED) {  // the fake may not keep presence
    ASSERT_TRUE(pst.ok()) << pst.error_message();
    EXPECT_EQ(prr.presence().who().id(), "alice");
    EXPECT_EQ(prr.presence().display_name(), "alice");
  }
}

TEST(AuthPolicyUnit, StampingRules) {
  auth::Principal alice;
  alice.kind = auth::PrincipalKind::kUser;
  alice.name = "alice";
  alice.role = auth::Role::kEditor;
  auth::Principal admin = alice;
  admin.name = "root";
  admin.role = auth::Role::kAdmin;
  auth::Principal bot;
  bot.kind = auth::PrincipalKind::kAgent;
  bot.name = "bot";
  bot.role = auth::Role::kEditor;
  auth::Principal peer;
  peer.kind = auth::PrincipalKind::kPeer;
  peer.role = auth::Role::kPeer;

  auto stamp = [](const auth::Principal &who, pb::ProvenanceKind kind, const std::string &id, pb::Provenance *out = nullptr) {
    pb::Provenance p;
    p.set_kind(kind);
    p.set_id(id);
    p.set_tool("t");
    Status st = StampProvenance(who, p);
    if (out) *out = p;
    return st.ok();
  };
  pb::Provenance p;
  EXPECT_TRUE(stamp(alice, pb::PROVENANCE_KIND_UNSPECIFIED, "", &p));
  EXPECT_EQ(p.kind(), pb::PROVENANCE_KIND_USER);
  EXPECT_EQ(p.id(), "alice");
  EXPECT_EQ(p.tool(), "t");
  EXPECT_TRUE(stamp(alice, pb::PROVENANCE_KIND_USER, "alice"));
  EXPECT_FALSE(stamp(alice, pb::PROVENANCE_KIND_USER, "bob"));
  EXPECT_FALSE(stamp(alice, pb::PROVENANCE_KIND_UNSPECIFIED, "bob"));
  EXPECT_FALSE(stamp(alice, pb::PROVENANCE_KIND_AGENT, ""));
  EXPECT_FALSE(stamp(alice, pb::PROVENANCE_KIND_IMPORT, "ghidra"));
  EXPECT_TRUE(stamp(admin, pb::PROVENANCE_KIND_IMPORT, "ghidra"));
  EXPECT_TRUE(stamp(admin, pb::PROVENANCE_KIND_MIGRATION, "v0"));
  EXPECT_FALSE(stamp(admin, pb::PROVENANCE_KIND_IMPORT, ""));
  EXPECT_FALSE(stamp(admin, pb::PROVENANCE_KIND_AGENT, "bot"));
  EXPECT_TRUE(stamp(bot, pb::PROVENANCE_KIND_AGENT, "", &p));
  EXPECT_EQ(p.id(), "bot");
  EXPECT_FALSE(stamp(bot, pb::PROVENANCE_KIND_AGENT, "claude"));
  EXPECT_FALSE(stamp(bot, pb::PROVENANCE_KIND_USER, "bot"));
  EXPECT_FALSE(stamp(peer, pb::PROVENANCE_KIND_UNSPECIFIED, ""));
  // No authentication: nothing changes.
  EXPECT_TRUE(stamp(AnonymousPrincipal(), pb::PROVENANCE_KIND_USER, "anyone", &p));
  EXPECT_EQ(p.id(), "anyone");

  // A script (api_minor 29): any editor may write script:<name>; the
  // caller is stamped as whom it acted for, and naming someone else there
  // is refused.
  EXPECT_TRUE(stamp(alice, pb::PROVENANCE_KIND_SCRIPT, "fix-names", &p));
  EXPECT_EQ(p.id(), "fix-names");
  EXPECT_EQ(p.on_behalf_of(), "user:alice");
  EXPECT_TRUE(stamp(bot, pb::PROVENANCE_KIND_SCRIPT, "fix-names", &p));
  EXPECT_EQ(p.on_behalf_of(), "agent:bot");
  EXPECT_FALSE(stamp(alice, pb::PROVENANCE_KIND_SCRIPT, ""));
  {
    pb::Provenance forged;
    forged.set_kind(pb::PROVENANCE_KIND_SCRIPT);
    forged.set_id("fix-names");
    forged.set_on_behalf_of("user:bob");
    EXPECT_EQ(StampProvenance(alice, forged).code, StatusCode::kPermissionDenied);
    forged.set_on_behalf_of("user:alice");
    EXPECT_TRUE(StampProvenance(alice, forged).ok());
  }
  // An admin's importer records the admin.
  EXPECT_TRUE(stamp(admin, pb::PROVENANCE_KIND_IMPORT, "ghidra", &p));
  EXPECT_EQ(p.on_behalf_of(), "user:root");
  // Without authentication the client's text is kept.
  {
    pb::Provenance anon;
    anon.set_kind(pb::PROVENANCE_KIND_SCRIPT);
    anon.set_id("fix-names");
    anon.set_on_behalf_of("user:somebody");
    EXPECT_TRUE(StampProvenance(AnonymousPrincipal(), anon).ok());
    EXPECT_EQ(anon.on_behalf_of(), "user:somebody");
  }

  pb::Presence pres;
  pres.mutable_who()->set_id("bob");
  pres.set_display_name("Bob");
  StampPresence(bot, pres);
  EXPECT_EQ(pres.who().kind(), pb::PROVENANCE_KIND_AGENT);
  EXPECT_EQ(pres.who().id(), "bot");
  EXPECT_EQ(pres.display_name(), "bot");
}

TEST(AuthPolicyUnit, NoAuthAllowsEverything) {
  auth::Principal anon = AnonymousPrincipal();
  for (const std::string &m : MethodsWithPolicy()) EXPECT_TRUE(Authorize(&anon, m, pb::PullRequest()).ok()) << m;
  EXPECT_EQ(Authorize(nullptr, "revkit.v1.SyncService/Pull", pb::PullRequest()).code, StatusCode::kUnauthenticated);
  EXPECT_EQ(Authorize(&anon, "revkit.v1.NoSuchService/Method", pb::PullRequest()).code, StatusCode::kPermissionDenied);
}

TEST(AuthPolicyUnit, ProjectsNamed) {
  pb::GetHistoryRequest h;
  h.mutable_key()->set_program_id("proj/prog");
  EXPECT_EQ(ProjectsNamedBy(h), std::vector<std::string>{"proj"});
  pb::SubscribeRequest s;
  s.set_project_id("a");
  s.add_program_ids("b/x");
  EXPECT_EQ(ProjectsNamedBy(s), (std::vector<std::string>{"a", "b"}));
  pb::OpenProjectRequest o;
  o.set_path("/somewhere");
  EXPECT_TRUE(ProjectsNamedBy(o).empty());
  EXPECT_TRUE(ProjectsNamedBy(pb::ListProjectsRequest()).empty());
}

// Debugging: the emulator and saved traces are an editor's; launching or
// attaching on the daemon's host, or connecting from it, an admin's.
TEST(AuthPolicyUnit, LiveDebugTargetsNeedAdmin) {
  auth::Principal editor;
  editor.kind = auth::PrincipalKind::kUser;
  editor.name = "alice";
  editor.role = auth::Role::kEditor;
  auth::Principal admin = editor;
  admin.name = "root";
  admin.role = auth::Role::kAdmin;
  auth::Principal viewer = editor;
  viewer.name = "bob";
  viewer.role = auth::Role::kViewer;
  const std::string create = "revkit.v1.DebugService/CreateDebugSession";
  pb::CreateDebugSessionRequest emu;
  emu.set_program_id("p/prog");
  emu.mutable_emulator();
  pb::CreateDebugSessionRequest trace = emu;
  trace.mutable_trace()->set_name("t");
  pb::CreateDebugSessionRequest launch = emu;
  launch.mutable_launch();
  pb::CreateDebugSessionRequest remote = emu;
  remote.mutable_remote()->set_address("10.0.0.1:3333");
  EXPECT_TRUE(Authorize(&editor, create, emu).ok());
  EXPECT_TRUE(Authorize(&editor, create, trace).ok());
  EXPECT_EQ(Authorize(&viewer, create, emu).code, StatusCode::kPermissionDenied);
  EXPECT_EQ(Authorize(&editor, create, launch).code, StatusCode::kPermissionDenied);
  EXPECT_EQ(Authorize(&editor, create, remote).code, StatusCode::kPermissionDenied);
  EXPECT_TRUE(Authorize(&admin, create, launch).ok());
  EXPECT_TRUE(Authorize(&admin, create, remote).ok());
  EXPECT_TRUE(Authorize(&viewer, "revkit.v1.DebugService/GetDebugState", pb::GetDebugStateRequest()).ok());
  EXPECT_EQ(Authorize(&viewer, "revkit.v1.DebugService/ResumeDebugSession", pb::ResumeDebugSessionRequest()).code,
            StatusCode::kPermissionDenied);
  EXPECT_TRUE(Authorize(&editor, "revkit.v1.DebugService/ResumeDebugSession", pb::ResumeDebugSessionRequest()).ok());
}

// Firmware emulation (docs/firmware-emulation.md): creating, deriving and
// deleting machines needs an editor; reading them and a session's machine
// state a viewer; input to a session's machine is running it.
TEST(AuthPolicyUnit, MachinesNeedAnEditor) {
  auth::Principal editor;
  editor.kind = auth::PrincipalKind::kUser;
  editor.name = "alice";
  editor.role = auth::Role::kEditor;
  auth::Principal viewer = editor;
  viewer.name = "bob";
  viewer.role = auth::Role::kViewer;
  const std::string svc = "revkit.v1.EmulatorService/";
  pb::SaveMachineRequest save;
  save.set_program_id("p/prog");
  pb::DeriveMachineRequest derive;
  derive.set_program_id("p/prog");
  pb::DeleteMachineRequest del;
  del.set_program_id("p/prog");
  pb::ListMachinesRequest list;
  list.set_program_id("p/prog");
  for (auto [method, msg] : std::initializer_list<std::pair<const char *, const google::protobuf::Message *>>{
           {"SaveMachine", &save}, {"DeriveMachine", &derive}, {"DeleteMachine", &del}}) {
    EXPECT_TRUE(Authorize(&editor, svc + method, *msg).ok()) << method;
    EXPECT_EQ(Authorize(&viewer, svc + method, *msg).code, StatusCode::kPermissionDenied) << method;
  }
  EXPECT_TRUE(Authorize(&viewer, svc + "ListMachines", list).ok());
  EXPECT_TRUE(Authorize(&viewer, svc + "GetEmulatorMachine", pb::GetEmulatorMachineRequest()).ok());
  EXPECT_TRUE(Authorize(&viewer, svc + "ListPeripheralKinds", pb::ListPeripheralKindsRequest()).ok());
  EXPECT_EQ(Authorize(&viewer, svc + "WriteEmulatorInput", pb::WriteEmulatorInputRequest()).code,
            StatusCode::kPermissionDenied);
  EXPECT_TRUE(Authorize(&editor, svc + "WriteEmulatorInput", pb::WriteEmulatorInputRequest()).ok());
  EXPECT_EQ(Authorize(&viewer, "revkit.v1.DebugService/WriteDebugInput", pb::WriteDebugInputRequest()).code,
            StatusCode::kPermissionDenied);
  EXPECT_TRUE(Authorize(&viewer, "revkit.v1.DebugService/GetDebugMachine", pb::GetDebugMachineRequest()).ok());
  // A session on a machine is a session: an editor's.
  pb::CreateEmulatorSessionRequest create;
  create.set_program_id("p/prog");
  create.set_machine("{}");
  EXPECT_EQ(Authorize(&viewer, svc + "CreateEmulatorSession", create).code, StatusCode::kPermissionDenied);
  EXPECT_TRUE(Authorize(&editor, svc + "CreateEmulatorSession", create).ok());
}

// Scripts and the console (docs/scripting.md): the gate lets a viewer reach
// RunScript (the service then decides by --scripts-host-role, and a
// viewer's run token can't edit), but saving a script stays an editor's.
TEST(AuthPolicyUnit, ConsolesReachViewersSavingNeedsAnEditor) {
  auth::Principal viewer;
  viewer.kind = auth::PrincipalKind::kUser;
  viewer.name = "victor";
  viewer.role = auth::Role::kViewer;
  viewer.projects = {"p"};
  const std::string svc = "revkit.v1.ScriptService/";
  pb::RunScriptRequest run;
  run.set_program_id("p/prog");
  run.set_interactive(true);
  pb::CompleteConsoleRequest complete;
  complete.set_program_id("p/prog");
  EXPECT_TRUE(Authorize(&viewer, svc + "RunScript", run).ok());
  EXPECT_TRUE(Authorize(&viewer, svc + "CompleteConsole", complete).ok());
  EXPECT_TRUE(Authorize(&viewer, svc + "CancelScript", pb::CancelScriptRequest()).ok());
  EXPECT_TRUE(Authorize(&viewer, svc + "UpdateContext", pb::UpdateContextRequest()).ok());
  EXPECT_TRUE(Authorize(&viewer, svc + "AnswerPrompt", pb::AnswerPromptRequest()).ok());
  // Another project's console is out of reach.
  complete.set_program_id("q/prog");
  EXPECT_EQ(Authorize(&viewer, svc + "CompleteConsole", complete).code, StatusCode::kPermissionDenied);
  run.set_program_id("q/prog");
  EXPECT_EQ(Authorize(&viewer, svc + "RunScript", run).code, StatusCode::kPermissionDenied);
  EXPECT_EQ(Authorize(&viewer, svc + "SaveScript", pb::SaveScriptRequest()).code, StatusCode::kPermissionDenied);
  EXPECT_EQ(Authorize(&viewer, svc + "SetupScriptPython", pb::SetupScriptPythonRequest()).code,
            StatusCode::kPermissionDenied);
}

// Diffing (docs/diff.md): reads are a viewer's, decisions and ports an editor's.
TEST(AuthPolicyUnit, DiffReadsAreViewersDecisionsEditors) {
  auth::Principal viewer;
  viewer.kind = auth::PrincipalKind::kUser;
  viewer.name = "v";
  viewer.role = auth::Role::kViewer;
  auth::Principal editor = viewer;
  editor.role = auth::Role::kEditor;
  for (const char *m : {"ListDiffSessions", "RunDiff", "GetDiffStatus", "ListMatches", "ListUnmatched", "GetFunctionDiff",
                        "SummarizeFunctionDiffs", "CompareFunctions"})
    EXPECT_TRUE(Authorize(&viewer, std::string("revkit.v1.DiffService/") + m, pb::ListMatchesRequest()).ok()) << m;
  for (const char *m : {"CreateDiffSession", "CancelDiff", "AcceptMatches", "RejectMatches", "SetMatch", "ApplyMarkup",
                        "RevertApply", "Unmatch", "PortFunctionMarkup"}) {
    EXPECT_EQ(Authorize(&viewer, std::string("revkit.v1.DiffService/") + m, pb::ApplyMarkupRequest()).code,
              StatusCode::kPermissionDenied)
        << m;
    EXPECT_TRUE(Authorize(&editor, std::string("revkit.v1.DiffService/") + m, pb::ApplyMarkupRequest()).ok()) << m;
  }
  // Project-scoped: a session's project is named by project_id.
  auth::Principal limited = editor;
  limited.projects = {"fw"};
  pb::ApplyMarkupRequest other;
  other.set_project_id("lib");
  EXPECT_EQ(Authorize(&limited, "revkit.v1.DiffService/ApplyMarkup", other).code, StatusCode::kPermissionDenied);
  other.set_project_id("fw");
  EXPECT_TRUE(Authorize(&limited, "revkit.v1.DiffService/ApplyMarkup", other).ok());
}

// Every RPC in the schema has a policy, so none is open by accident; this
// fails when an RPC is added without one.
TEST(AuthPolicyUnit, EveryMethodHasAPolicy) {
  const gp::FileDescriptor *any = pb::GetServerInfoRequest::descriptor()->file();
  std::vector<std::string> missing;
  int methods = 0;
  (void)pb::IngestBSimRequest::descriptor();  // linked in, so the pool has bsim.proto
  for (const char *file : {"revkit/v1/analysis.proto", "revkit/v1/assertion.proto", "revkit/v1/auth.proto",
                           "revkit/v1/bsim.proto", "revkit/v1/debugger.proto", "revkit/v1/diff.proto", "revkit/v1/emulator.proto", "revkit/v1/filesystem.proto", "revkit/v1/meta.proto", "revkit/v1/patch.proto", "revkit/v1/plugin.proto", "revkit/v1/presence.proto",
                           "revkit/v1/project.proto", "revkit/v1/query.proto", "revkit/v1/script.proto", "revkit/v1/subscription.proto",
                           "revkit/v1/sync.proto", "revkit/v1/types.proto"}) {
    const gp::FileDescriptor *f = any->pool()->FindFileByName(file);
    ASSERT_TRUE(f) << file;
    for (int i = 0; i < f->service_count(); ++i)
      for (int j = 0; j < f->service(i)->method_count(); ++j) {
        ++methods;
        std::string m = f->service(i)->full_name() + "/" + f->service(i)->method(j)->name();
        if (!PolicyFor(m)) missing.push_back(m);
      }
  }
  EXPECT_TRUE(missing.empty()) << "no policy for " << ::testing::PrintToString(missing);
  EXPECT_EQ(static_cast<std::size_t>(methods), MethodsWithPolicy().size());
}

// Every non-public method refuses a caller without credentials, over the
// gateway (which reaches every handler): none forgot to check.
TEST_F(AuthTest, EveryMethodRefusesAnonymousCallers) {
  auto client = HttpsClient();
  auto &https = *client;
  int checked = 0;
  for (const std::string &m : MethodsWithPolicy()) {
    const bool public_method = PolicyFor(m)->role == auth::Role::kNone;
    std::string service = m.substr(0, m.find('/')), method = m.substr(m.find('/') + 1);
    const gp::MethodDescriptor *md = gp::DescriptorPool::generated_pool()->FindMethodByName(service + "." + method);
    ASSERT_TRUE(md) << m;
    std::string code;
    if (md->server_streaming()) {
      auto r = https.Post("/" + m, Envelope("{}"), "application/connect+json");
      ASSERT_TRUE(r) << m;
      code = r->body.find("\"unauthenticated\"") != std::string::npos ? "unauthenticated" : "other";
    } else {
      auto r = https.Post("/" + m, "{}", "application/json");
      ASSERT_TRUE(r) << m;
      code = r->status == 401 ? "unauthenticated" : "other";
    }
    // (Login with no credentials answers UNAUTHENTICATED for the wrong password.)
    if (public_method && m != "revkit.v1.AuthService/Login") EXPECT_NE(code, "unauthenticated") << m;
    else if (public_method) {}
    else EXPECT_EQ(code, "unauthenticated") << m;
    ++checked;
  }
  EXPECT_GT(checked, 50);
}

TEST_F(AuthTest, ProjectAccessLists) {
  std::string pat = Login("pat", "pat-password");
  EXPECT_EQ(ListFunctions(pat).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  EXPECT_EQ(Rename(pat, "x", Prov()).error_code(), grpc::StatusCode::PERMISSION_DENIED);
  auto projects = pb::ProjectService::NewStub(channel_);
  pb::ListProjectsResponse lp;
  auto ctx = Ctx(pat);
  ASSERT_TRUE(projects->ListProjects(ctx.get(), {}, &lp).ok());
  EXPECT_EQ(lp.projects_size(), 0);
  std::string alice = Login("alice", "alice-password");
  auto ctx2 = Ctx(alice);
  ASSERT_TRUE(projects->ListProjects(ctx2.get(), {}, &lp).ok());
  EXPECT_EQ(lp.projects_size(), 1);
  // Subscriptions too.
  auto subs = pb::SubscriptionService::NewStub(channel_);
  pb::SubscribeRequest sr;
  sr.set_project_id("demo");
  auto ctx3 = Ctx(pat);
  auto reader = subs->Subscribe(ctx3.get(), sr);
  pb::SubscribeResponse ev;
  EXPECT_FALSE(reader->Read(&ev));
  EXPECT_EQ(reader->Finish().error_code(), grpc::StatusCode::PERMISSION_DENIED);
}

TEST_F(AuthTest, LoginIsRateLimited) {
  grpc::Status st;
  for (int i = 0; i < 6; ++i) {
    Login("vic", "wrong-" + std::to_string(i), &st);
    EXPECT_EQ(st.error_code(), grpc::StatusCode::UNAUTHENTICATED) << i;
  }
  // Now even the right password waits.
  Login("vic", "vic-password", &st);
  EXPECT_EQ(st.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
  EXPECT_NE(st.error_message().find("try again"), std::string::npos);
  // Other accounts from... this same address are throttled too (by address).
  Login("alice", "alice-password", &st);
  EXPECT_EQ(st.error_code(), grpc::StatusCode::RESOURCE_EXHAUSTED);
}

TEST_F(AuthTest, StreamsEndWithTheirSession) {
  std::string token = Login("alice", "alice-password");
  auto subs = pb::SubscriptionService::NewStub(channel_);
  pb::SubscribeRequest sr;
  sr.set_project_id("demo");
  sr.set_heartbeat_seconds(1);
  auto ctx = Ctx(token);
  auto reader = subs->Subscribe(ctx.get(), sr);
  pb::SubscribeResponse ev;
  ASSERT_TRUE(reader->Read(&ev));
  EXPECT_TRUE(ev.has_hello());
  store_->logout(token);
  auto t0 = std::chrono::steady_clock::now();
  while (reader->Read(&ev)) {
  }
  EXPECT_EQ(reader->Finish().error_code(), grpc::StatusCode::UNAUTHENTICATED);
  EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(10));
}

// The browser path: an HttpOnly session cookie, the CSRF header, Origin.
TEST_F(AuthTest, GatewayCookieSessionWithCsrf) {
  auto client = HttpsClient();
  auto &https = *client;
  // Login with session_cookie: the cookie carries the session, the page
  // never sees the token.
  auto r = https.Post("/revkit.v1.AuthService/Login",
                      R"({"username":"alice","password":"alice-password","sessionCookie":true})", "application/json");
  ASSERT_TRUE(r);
  ASSERT_EQ(r->status, 200) << r->body;
  const std::string set_cookie = r->get_header_value("Set-Cookie");
  EXPECT_TRUE(set_cookie.starts_with("__Host-rk_session=rks_")) << set_cookie;
  for (const char *attr : {"HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age="})
    EXPECT_NE(set_cookie.find(attr), std::string::npos) << attr << " in " << set_cookie;
  EXPECT_EQ(r->body.find("\"token\""), std::string::npos) << r->body;
  EXPECT_EQ(r->body.find("rks_"), std::string::npos) << r->body;
  const std::string cookie = "__Host-rk_session=" + CookieValue(set_cookie);

  // WhoAmI with only the cookie (a reloaded page) returns the CSRF token.
  httplib::Headers h = {{"Cookie", cookie}};
  r = https.Post("/revkit.v1.AuthService/WhoAmI", h, "{}", "application/json");
  ASSERT_TRUE(r);
  pb::WhoAmIResponse who;
  ASSERT_TRUE(gp::util::JsonStringToMessage(r->body, &who).ok()) << r->body;
  EXPECT_EQ(who.identity().name(), "alice");
  ASSERT_FALSE(who.csrf_token().empty());

  const std::string rename =
      R"({"programId":"demo/hello","assertions":[{"body":{"rename":{"target":{"address":{"offset":"4198464"}},"name":"viaCookie"}}}]})";
  // Without the CSRF header: refused.
  r = https.Post("/revkit.v1.AssertionService/AppendAssertions", h, rename, "application/json");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, 403) << r->body;
  // With a wrong one: refused.
  r = https.Post("/revkit.v1.AssertionService/AppendAssertions", {{"Cookie", cookie}, {"X-CSRF-Token", "nope"}}, rename,
                 "application/json");
  EXPECT_EQ(r->status, 403);
  // From another origin, even with the token: refused.
  r = https.Post("/revkit.v1.AssertionService/AppendAssertions",
                 {{"Cookie", cookie}, {"X-CSRF-Token", who.csrf_token()}, {"Origin", "https://evil.example"}}, rename,
                 "application/json");
  EXPECT_EQ(r->status, 403);
  // Same origin with the token: accepted, and stamped user:alice.
  const std::string self = "https://127.0.0.1:" + std::to_string(server_->http_port());
  r = https.Post("/revkit.v1.AssertionService/AppendAssertions",
                 {{"Cookie", cookie}, {"X-CSRF-Token", who.csrf_token()}, {"Origin", self}}, rename, "application/json");
  ASSERT_EQ(r->status, 200) << r->body;
  EXPECT_NE(r->body.find(R"("provenance":{"kind":"PROVENANCE_KIND_USER","id":"alice")"), std::string::npos) << r->body;
  // Streams too (Connect server streaming).
  pb::SubscribeRequest sr;
  sr.set_project_id("demo");
  r = https.Post("/revkit.v1.SubscriptionService/Subscribe", h, Envelope(R"({"projectId":"demo","fromRevision":"1"})"),
                 "application/connect+json");
  ASSERT_TRUE(r);
  EXPECT_NE(r->body.find("x-csrf-token"), std::string::npos);

  // Logout clears the cookie and ends the session.
  r = https.Post("/revkit.v1.AuthService/Logout", {{"Cookie", cookie}, {"X-CSRF-Token", who.csrf_token()}}, "{}",
                 "application/json");
  ASSERT_EQ(r->status, 200) << r->body;
  EXPECT_NE(r->get_header_value("Set-Cookie").find("Max-Age=0"), std::string::npos);
  r = https.Post("/revkit.v1.QueryService/ListFunctions", {{"Cookie", cookie}, {"X-CSRF-Token", who.csrf_token()}},
                 R"({"programId":"demo/hello"})", "application/json");
  EXPECT_EQ(r->status, 401);

  // Bearer tokens work through the gateway too (scripts, the Tauri shell).
  r = https.Post("/revkit.v1.QueryService/ListFunctions", {{"Authorization", "Bearer " + bot_}},
                 R"({"programId":"demo/hello"})", "application/json");
  EXPECT_EQ(r->status, 200);
  // A forged gateway header buys nothing.
  r = https.Post("/revkit.v1.QueryService/ListFunctions", {{"X-Rk-Gateway", "guess"}, {"X-Forwarded-For", "1.2.3.4"}},
                 R"({"programId":"demo/hello"})", "application/json");
  EXPECT_EQ(r->status, 401);
}

TEST(AuthServer, ListenerRules) {
  auto start = [](ServerOptions o) {
    std::string error;
    auto s = Server::Start(MakeFakeBackend(), o, error);
    return std::make_pair(s != nullptr, error);
  };
  auth::StoreOptions so;
  so.path = (fs::temp_directory_path() / ("rk-listener-" + std::to_string(::getpid()) + ".db")).string();
  auto store = std::make_shared<auth::Store>(so);

  ServerOptions o;
  o.grpc_address = "0.0.0.0:0";
  o.http_address = "";
  auto [ok, err] = start(o);  // no auth, not loopback
  EXPECT_FALSE(ok);
  EXPECT_NE(err.find("--no-auth"), std::string::npos) << err;
  o.auth = store;
  std::tie(ok, err) = start(o);  // auth, plaintext, not loopback
  EXPECT_FALSE(ok);
  EXPECT_NE(err.find("plaintext"), std::string::npos) << err;
  o.insecure_allow_remote = true;
  EXPECT_TRUE(start(o).first);
  o.insecure_allow_remote = false;
  o.tls = {Cert().cert_pem, Cert().key_pem};
  EXPECT_TRUE(start(o).first);
  o.http_address = "0.0.0.0:0";
  EXPECT_TRUE(start(o).first);
  o.tls = {Cert().cert_pem, auth::generate_self_signed({}).key_pem};  // mismatched key
  EXPECT_FALSE(start(o).first);

  EXPECT_TRUE(IsLoopbackAddress("127.0.0.1:1"));
  EXPECT_TRUE(IsLoopbackAddress("[::1]:1"));
  EXPECT_TRUE(IsLoopbackAddress("localhost:1"));
  EXPECT_FALSE(IsLoopbackAddress("0.0.0.0:1"));
  EXPECT_FALSE(IsLoopbackAddress("100.64.0.1:50052"));
  fs::remove(so.path);
}

}  // namespace
}  // namespace revkit::api
