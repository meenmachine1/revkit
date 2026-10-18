#include "grpc_services.h"

#include "revkit/api/auth_policy.h"
#include "revkit/auth/crypto.h"
#include "revkit/v1/analysis.grpc.pb.h"
#include "revkit/v1/assertion.grpc.pb.h"
#include "revkit/v1/bsim.grpc.pb.h"
#include "revkit/v1/debugger.grpc.pb.h"
#include "revkit/v1/diff.grpc.pb.h"
#include "revkit/v1/emulator.grpc.pb.h"
#include "revkit/v1/filesystem.grpc.pb.h"
#include "revkit/v1/meta.grpc.pb.h"
#include "revkit/v1/patch.grpc.pb.h"
#include "revkit/v1/plugin.grpc.pb.h"
#include "revkit/v1/presence.grpc.pb.h"
#include "revkit/v1/project.grpc.pb.h"
#include "revkit/v1/provider.grpc.pb.h"
#include "revkit/v1/query.grpc.pb.h"
#include "revkit/v1/subscription.grpc.pb.h"
#include "revkit/v1/sync.grpc.pb.h"
#include "revkit/v1/types.grpc.pb.h"

#include <strings.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <iostream>
#include <mutex>
#include <optional>
#include <thread>

namespace revkit::api {

grpc::Status ToGrpc(const Status &status) {
  if (status.ok()) return grpc::Status::OK;
  return {static_cast<grpc::StatusCode>(status.code), status.message};
}

// ------------------------------------------------------------------ AuthGate --

AuthGate::AuthGate(std::shared_ptr<auth::Store> store, std::string gateway_secret)
    : store_(std::move(store)), gateway_secret_(std::move(gateway_secret)) {}

std::string AuthGate::Bearer(const grpc::ServerContext *ctx) {
  const auto &md = ctx->client_metadata();
  auto it = md.find("authorization");
  if (it == md.end()) return "";
  std::string v(it->second.data(), it->second.size());
  // "Bearer <token>", the scheme case-insensitively.
  if (v.size() > 7 && strncasecmp(v.c_str(), "bearer ", 7) == 0) {
    v.erase(0, 7);
    while (!v.empty() && v.front() == ' ') v.erase(0, 1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\r' || v.back() == '\n')) v.pop_back();
    return v;
  }
  return "";
}

std::optional<auth::Principal> AuthGate::Identify(const grpc::ServerContext *ctx) const {
  if (!store_) return AnonymousPrincipal();
  std::string bearer = Bearer(ctx);
  if (bearer.empty()) return std::nullopt;
  return store_->authenticate(bearer);
}

Status AuthGate::Check(const grpc::ServerContext *ctx, const char *method, const google::protobuf::Message &request,
                       std::optional<auth::Principal> &who) const {
  who = Identify(ctx);
  return Authorize(who ? &*who : nullptr, method, request);
}

std::string AuthGate::ClientAddress(const grpc::ServerContext *ctx) const {
  const auto &md = ctx->client_metadata();
  auto gw = md.find(kGatewayMetadata);
  auto fwd = md.find(kForwardedForMetadata);
  if (gw != md.end() && fwd != md.end() && !gateway_secret_.empty() &&
      auth::constant_time_equal(std::string_view(gw->second.data(), gw->second.size()), gateway_secret_))
    return std::string(fwd->second.data(), fwd->second.size());
  // "ipv4:1.2.3.4:5678", "ipv6:[::1]:5678": the address without the port.
  std::string peer = ctx->peer();
  if (auto colon = peer.find(':'); colon != std::string::npos) peer.erase(0, colon + 1);
  if (!peer.empty() && peer.front() == '[') return peer.substr(1, peer.find(']') - 1);
  if (auto colon = peer.rfind(':'); colon != std::string::npos) peer.erase(colon);
  return peer;
}

namespace {

CallContext MakeContext(grpc::ServerContext *ctx, const std::optional<auth::Principal> &who = std::nullopt) {
  CallContext c;
  // gRPC reports "no deadline" as a far-future time point; keep max() for it.
  auto remaining = ctx->deadline() - std::chrono::system_clock::now();
  if (remaining < std::chrono::hours(24 * 365))
    c.deadline = CallContext::Clock::now() +
                 std::chrono::duration_cast<CallContext::Clock::duration>(remaining);
  c.cancelled = [ctx] { return ctx->IsCancelled(); };
  c.peer = ctx->peer();
  if (who) {
    c.caller = who->display();
    c.caller_admin = who->role == auth::Role::kAdmin;
  }
  return c;
}

// Exceptions must not cross into gRPC's threads; a throwing backend is an
// internal error, not a crash.
template <class Fn>
grpc::Status Guard(Fn &&fn) {
  try {
    return ToGrpc(fn());
  } catch (const std::exception &e) {
    return {grpc::StatusCode::INTERNAL, std::string("backend error: ") + e.what()};
  }
}

// Each RPC is a one-line forward to the Backend method of the same name;
// the schema's Request/Response naming makes the signature derivable.
// Every handler first identifies and authorizes the caller (auth_policy.h):
// both transports end up here, the HTTP gateway through its in-process
// channel.
#define RK_UNARY(Method)                                                                          \
  grpc::Status Method(grpc::ServerContext *ctx, const pb::Method##Request *req,                   \
                      pb::Method##Response *resp) override {                                      \
    return Guard([&] {                                                                            \
      static const std::string method = std::string(kService) + #Method;                          \
      std::optional<auth::Principal> who;                                                         \
      if (Status st = auth_->Check(ctx, method.c_str(), *req, who); !st.ok()) return st;          \
      return backend_->Method(MakeContext(ctx, who), *req, *resp);                                \
    });                                                                                           \
  }

// The same for a request that names its author: the server's identity for
// the caller replaces (or must match) what the client said.
#define RK_STAMPED(Method, STAMP)                                                                 \
  grpc::Status Method(grpc::ServerContext *ctx, const pb::Method##Request *req,                   \
                      pb::Method##Response *resp) override {                                      \
    return Guard([&] {                                                                            \
      static const std::string method = std::string(kService) + #Method;                          \
      std::optional<auth::Principal> who;                                                         \
      if (Status st = auth_->Check(ctx, method.c_str(), *req, who); !st.ok()) return st;          \
      pb::Method##Request stamped = *req;                                                         \
      if (Status st = STAMP(*who, stamped); !st.ok()) return st;                                  \
      return backend_->Method(MakeContext(ctx, who), stamped, *resp);                             \
    });                                                                                           \
  }

// A server-streaming query (DecompileMany, ListInstructions, the searches): the backend
// writes each message through `write`, from any of its threads; writes are
// serialized here and fail once the client has gone away.
template <class Req, class Resp, class Fn>
grpc::Status ServeStream(const AuthGate &auth, grpc::ServerContext *ctx, const char *method, const Req &req,
                         grpc::ServerWriter<Resp> *writer, Fn &&fn) {
  return Guard([&] {
    std::optional<auth::Principal> who;
    if (Status st = auth.Check(ctx, method, req, who); !st.ok()) return st;
    std::mutex mu;
    bool gone = false;
    const std::function<bool(const Resp &)> write = [&](const Resp &m) {
      std::lock_guard lock(mu);
      if (gone || ctx->IsCancelled()) return false;
      if (!writer->Write(m)) gone = true;
      return !gone;
    };
    return fn(MakeContext(ctx, who), write);
  });
}

template <class Req>
Status StampRequest(const auth::Principal &who, Req &req) {
  return StampProvenance(who, *req.mutable_provenance());
}

Status StampPresenceRequest(const auth::Principal &who, pb::UpdatePresenceRequest &req) {
  StampPresence(who, *req.mutable_presence());
  return Status::Ok();
}

class Meta final : public pb::MetaService::Service {
 public:
  Meta(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a, DaemonInfo info)
      : backend_(std::move(b)), auth_(std::move(a)), info_(std::move(info)) {}

  grpc::Status GetServerInfo(grpc::ServerContext *ctx, const pb::GetServerInfoRequest *req,
                             pb::GetServerInfoResponse *resp) override {
    return Guard([&] {
      std::optional<auth::Principal> who;
      if (Status st = auth_->Check(ctx, "revkit.v1.MetaService/GetServerInfo", *req, who); !st.ok()) return st;
      Status st = backend_->GetServerInfo(MakeContext(ctx, who), *req, *resp);
      if (st.ok()) {
        // The transport's features, whatever the backend: AuthService and
        // server-stamped provenance (api_minor 13).
        resp->add_features("auth");
        // ScriptService (api_minor 31): ListScripts says whether it runs
        // scripts for the caller.
        resp->add_features("scripts-host");
        // ScriptService.SetupScriptPython (api_minor 33).
        resp->add_features("scripts-setup");
        // The Python console (RunScript interactive, CancelScript interrupt)
        // and its completions (CompleteConsole), api_minor 43.
        resp->add_features("script-console");
        resp->add_features("script-completion");
        if (auth_->enabled()) {
          resp->add_features("auth-required");
          resp->add_features("provenance-stamping");
        }
        // Uptime, the command line and socket activation (api_minor 35).
        resp->add_features("daemon-info");
        resp->set_uptime_seconds(static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - info_.started).count()));
        resp->set_socket_activated(info_.socket_activated);
        // RestartDaemon (api_minor 55), when this process can restart itself.
        if (info_.restart) resp->add_features("daemon-restart");
        // The command line names host paths: admins only (with --no-auth
        // every caller is one).
        if (who && who->role == auth::Role::kAdmin)
          for (const std::string &a : info_.launch_args) resp->add_launch_args(a);
      }
      return st;
    });
  }

  grpc::Status RestartDaemon(grpc::ServerContext *ctx, const pb::RestartDaemonRequest *req,
                             pb::RestartDaemonResponse *resp) override {
    return Guard([&] {
      std::optional<auth::Principal> who;
      if (Status st = auth_->Check(ctx, "revkit.v1.MetaService/RestartDaemon", *req, who); !st.ok()) return st;
      if (!info_.restart) return Error(StatusCode::kFailedPrecondition, "this server can't restart itself (it isn't rk-daemon)");
      resp->set_mode(info_.restart_mode);
      resp->set_open_streams(static_cast<std::uint32_t>(std::max(0, info_.open_streams->load())));
      if (req->dry_run()) return Status::Ok();
      // The audit trail (docs/security.md): who asked, from where, and why.
      std::cerr << "rk-daemon: audit: restart (" << info_.restart_mode << ") requested by "
                << (who ? who->display() : std::string("anonymous")) << " from " << auth_->ClientAddress(ctx)
                << (req->reason().empty() ? "" : ": " + req->reason().substr(0, 200)) << "; "
                << resp->open_streams() << " open stream(s)" << std::endl;
      // After the reply is on its way: the shutdown ends this call's server.
      std::thread([restart = info_.restart] {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        restart();
      }).detach();
      return Status::Ok();
    });
  }

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
  DaemonInfo info_;
};

class Projects final : public pb::ProjectService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.ProjectService/";
  Projects(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  // Lists only the projects the caller may use.
  grpc::Status ListProjects(grpc::ServerContext *ctx, const pb::ListProjectsRequest *req,
                            pb::ListProjectsResponse *resp) override {
    return Guard([&] {
      std::optional<auth::Principal> who;
      if (Status st = auth_->Check(ctx, "revkit.v1.ProjectService/ListProjects", *req, who); !st.ok()) return st;
      Status st = backend_->ListProjects(MakeContext(ctx, who), *req, *resp);
      if (st.ok() && !who->projects.empty()) {
        auto *projects = resp->mutable_projects();
        for (int i = projects->size() - 1; i >= 0; --i)
          if (!who->may_use_project(projects->Get(i).project_id())) projects->DeleteSubrange(i, 1);
      }
      return st;
    });
  }
  RK_UNARY(OpenProject)
  RK_UNARY(CloseProject)
  RK_UNARY(ListPrograms)
  RK_UNARY(ImportProgram)
  RK_UNARY(GetProgramSummary)
  RK_UNARY(ListHostFiles)
  RK_UNARY(ListLanguages)
  RK_STAMPED(DeleteProgram, StampRequest)
  RK_STAMPED(RenameProgram, StampRequest)
  RK_STAMPED(CreateFolder, StampRequest)
  RK_STAMPED(RenameFolder, StampRequest)
  RK_STAMPED(DeleteFolder, StampRequest)
  RK_STAMPED(MoveToFolder, StampRequest)
  RK_UNARY(UploadChunk)
  RK_STAMPED(ImportProjectArchive, StampRequest)
  RK_UNARY(ListProgramLibraries)
  RK_STAMPED(LinkProgramLibrary, StampRequest)
  RK_UNARY(ResolveImport)
  grpc::Status ExportProject(grpc::ServerContext *ctx, const pb::ExportProjectRequest *req,
                             grpc::ServerWriter<pb::ExportProjectResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.ProjectService/ExportProject", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->ExportProject(c, *req, write); });
  }
  RK_UNARY(GetImportProgress)
  RK_UNARY(DetectRawLayout)
  RK_UNARY(GetRawDetectProgress)
  RK_UNARY(CancelRawDetect)
  RK_STAMPED(AddMemoryRegion, StampRequest)
  RK_STAMPED(UpdateMemoryRegion, StampRequest)
  RK_STAMPED(RemoveMemoryRegion, StampRequest)
  RK_STAMPED(SetImageBase, StampRequest)
  RK_STAMPED(SetProgramLanguage, StampRequest)
  RK_UNARY(CompareLanguages)
  RK_STAMPED(LoadPdb, StampRequest)
  RK_STAMPED(LoadDebugFile, StampRequest)
  RK_UNARY(GetSymbolSettings)
  RK_UNARY(SetSymbolSettings)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Assertions final : public pb::AssertionService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.AssertionService/";
  Assertions(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_STAMPED(AppendAssertions, StampRequest)
  RK_STAMPED(RetractAssertions, StampRequest)
  RK_UNARY(GetHistory)
  RK_UNARY(Blame)
  RK_UNARY(ListAssertions)
  RK_STAMPED(RevertByProvenance, StampRequest)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Queries final : public pb::QueryService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.QueryService/";
  Queries(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(GetMemoryMap)
  RK_UNARY(ReadMemory)
  RK_UNARY(ListFunctions)
  RK_UNARY(ListSymbols)
  RK_UNARY(GetFunction)
  RK_UNARY(GetListing)
  RK_UNARY(GetInstruction)
  RK_UNARY(GetXrefs)
  RK_UNARY(Decompile)
  RK_UNARY(SliceDecompiled)
  RK_UNARY(GetTypes)
  RK_UNARY(FindTypes)
  RK_UNARY(GetFunctionGraph)
  RK_UNARY(ListData)
  RK_UNARY(ListComments)
  RK_UNARY(ListRegisterValues)
  RK_UNARY(ListSymbolTree)
  RK_UNARY(PlanClearFlow)
  RK_UNARY(ListRelocations)
  RK_UNARY(GetBuildInfo)
  RK_UNARY(TraceValue)
  RK_UNARY(ListLibraryImporters)
  RK_UNARY(GetClassHierarchy)
  RK_UNARY(ListObjcClasses)
  RK_UNARY(ListCallingConventions)
  RK_UNARY(FindBytes)
  RK_UNARY(GetByteView)
  RK_UNARY(GetOverview)
  RK_UNARY(FindNext)

  grpc::Status DecompileMany(grpc::ServerContext *ctx, const pb::DecompileManyRequest *req,
                             grpc::ServerWriter<pb::DecompileManyResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/DecompileMany", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->DecompileMany(c, *req, write); });
  }
  grpc::Status ExportC(grpc::ServerContext *ctx, const pb::ExportCRequest *req,
                       grpc::ServerWriter<pb::ExportCResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/ExportC", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->ExportC(c, *req, write); });
  }
  grpc::Status ListInstructions(grpc::ServerContext *ctx, const pb::ListInstructionsRequest *req,
                                grpc::ServerWriter<pb::ListInstructionsResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/ListInstructions", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->ListInstructions(c, *req, write); });
  }
  grpc::Status SearchMemory(grpc::ServerContext *ctx, const pb::SearchMemoryRequest *req,
                      grpc::ServerWriter<pb::SearchMemoryResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/SearchMemory", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->SearchMemory(c, *req, write); });
  }
  grpc::Status SearchText(grpc::ServerContext *ctx, const pb::SearchTextRequest *req,
                      grpc::ServerWriter<pb::SearchTextResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/SearchText", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->SearchText(c, *req, write); });
  }
  grpc::Status SearchScalars(grpc::ServerContext *ctx, const pb::SearchScalarsRequest *req,
                      grpc::ServerWriter<pb::SearchScalarsResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/SearchScalars", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->SearchScalars(c, *req, write); });
  }
  grpc::Status SearchDecompiled(grpc::ServerContext *ctx, const pb::SearchDecompiledRequest *req,
                      grpc::ServerWriter<pb::SearchDecompiledResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/SearchDecompiled", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->SearchDecompiled(c, *req, write); });
  }
  grpc::Status FindTypeUses(grpc::ServerContext *ctx, const pb::FindTypeUsesRequest *req,
                            grpc::ServerWriter<pb::FindTypeUsesResponse> *writer) override {
    return ServeStream(*auth_, ctx, "revkit.v1.QueryService/FindTypeUses", *req, writer,
                       [&](const CallContext &c, const auto &write) { return backend_->FindTypeUses(c, *req, write); });
  }

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Analysis final : public pb::AnalysisService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.AnalysisService/";
  Analysis(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(ListAnalyzers)
  RK_UNARY(StartAnalysis)
  RK_UNARY(CancelAnalysis)
  RK_UNARY(GetAnalysisStatus)
  RK_UNARY(ListFidDatabases)
  RK_STAMPED(AttachFidDatabase, StampRequest)
  RK_STAMPED(DetachFidDatabase, StampRequest)
  RK_UNARY(ListFidMatches)
  RK_STAMPED(ApplyFidMatch, StampRequest)
  RK_STAMPED(RejectFidMatch, StampRequest)
  RK_STAMPED(CreateFidDatabase, StampRequest)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Plugins final : public pb::PluginService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.PluginService/";
  Plugins(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(ListPlugins)
  RK_STAMPED(RunCommand, StampRequest)
  RK_UNARY(GetPluginFacts)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Presence final : public pb::PresenceService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.PresenceService/";
  Presence(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_STAMPED(UpdatePresence, StampPresenceRequest)
  RK_UNARY(ListPresence)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Types final : public pb::TypeService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.TypeService/";
  Types(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(ParseC)
  RK_UNARY(AutoStructure)
  RK_UNARY(ExportTypeArchive)
  RK_UNARY(CopyTypes)
  RK_UNARY(ListTypeArchives)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

// Sessions belong to the caller who made them (the backend checks
// CallContext.caller on every session call).
class Diff final : public pb::DiffService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.DiffService/";
  Diff(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_STAMPED(CreateDiffSession, StampRequest)
  RK_UNARY(ListDiffSessions)
  RK_UNARY(RunDiff)
  RK_UNARY(GetDiffStatus)
  RK_UNARY(CancelDiff)
  RK_UNARY(ListMatches)
  RK_UNARY(ListUnmatched)
  RK_UNARY(GetFunctionDiff)
  RK_UNARY(SummarizeFunctionDiffs)
  RK_STAMPED(AcceptMatches, StampRequest)
  RK_STAMPED(RejectMatches, StampRequest)
  RK_STAMPED(SetMatch, StampRequest)
  RK_STAMPED(ApplyMarkup, StampRequest)
  RK_STAMPED(RevertApply, StampRequest)
  RK_STAMPED(Unmatch, StampRequest)
  RK_UNARY(CompareFunctions)
  RK_STAMPED(PortFunctionMarkup, StampRequest)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

// Patching (docs/patching.md): writes are assertions with the caller's
// stamped provenance; export to a host path is raised to admin by Authorize.
class Patch final : public pb::PatchService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.PatchService/";
  Patch(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(Assemble)
  RK_STAMPED(PatchInstruction, StampRequest)
  RK_STAMPED(PatchBytes, StampRequest)
  RK_UNARY(ListPatches)
  RK_STAMPED(RevertPatches, StampRequest)
  RK_UNARY(ExportProgram)
  RK_UNARY(DetectChecksum)
  RK_UNARY(GetExportSettings)
  RK_STAMPED(SetExportSettings, StampRequest)
  RK_STAMPED(OpenOriginal, StampRequest)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

// External decompilers (docs/providers.md): a program's input needs a
// viewer of its project (Authorize), a session's its owner (the backend).
class Providers final : public pb::ProviderService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.ProviderService/";
  Providers(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(ListProviders)
  RK_UNARY(DecompileExternal)
  RK_UNARY(ReadProviderOutput)
  RK_UNARY(GetProviderSettings)
  RK_UNARY(SetProviderSettings)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

// Container file systems (docs/filesystems.md): sessions belong to their
// opener; a host path, upload or bytes are raised to admin by Authorize.
// BSim databases (docs/bsim.md): a host path is admin (auth_policy.cc).
class BSim final : public pb::BSimService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.BSimService/";
  BSim(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_STAMPED(CreateBSimDatabase, StampRequest)
  RK_STAMPED(AttachBSimDatabase, StampRequest)
  RK_STAMPED(DetachBSimDatabase, StampRequest)
  RK_UNARY(ListBSimDatabases)
  RK_UNARY(IngestBSim)
  RK_UNARY(ListBSimExecutables)
  RK_UNARY(ListBSimFunctions)
  RK_UNARY(UpdateBSimExecutable)
  RK_UNARY(DeleteBSimExecutables)
  RK_UNARY(SearchBSim)
  RK_STAMPED(ApplyBSimMatches, StampRequest)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class FileSystems final : public pb::FileSystemService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.FileSystemService/";
  FileSystems(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(OpenFileSystem)
  RK_UNARY(ListFileSystem)
  RK_UNARY(ReadFileSystemFile)
  RK_UNARY(GetFileSystemFileInfo)
  RK_STAMPED(ImportFromFileSystem, StampRequest)
  RK_UNARY(ExtractFromFileSystem)
  RK_UNARY(CloseFileSystem)
  RK_UNARY(ListFileSystems)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Emulator final : public pb::EmulatorService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.EmulatorService/";
  Emulator(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(CreateEmulatorSession)
  RK_UNARY(CloseEmulatorSession)
  RK_UNARY(ListEmulatorSessions)
  RK_UNARY(RunEmulator)
  RK_UNARY(GetEmulatorState)
  RK_UNARY(WriteEmulatorRegisters)
  RK_UNARY(ReadEmulatorMemory)
  RK_UNARY(WriteEmulatorMemory)
  RK_UNARY(SetEmulatorBreakpoints)
  RK_UNARY(GetEmulatorTrace)
  RK_UNARY(WriteEmulatorInput)
  RK_UNARY(GetEmulatorMachine)
  RK_UNARY(ListMachines)
  RK_UNARY(GetMachine)
  RK_UNARY(SaveMachine)
  RK_UNARY(DeleteMachine)
  RK_UNARY(DeriveMachine)
  RK_UNARY(ListPeripheralKinds)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

class Debugger final : public pb::DebugService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.DebugService/";
  Debugger(std::shared_ptr<Backend> b, std::shared_ptr<AuthGate> a) : backend_(std::move(b)), auth_(std::move(a)) {}
  RK_UNARY(CreateDebugSession)
  RK_UNARY(CloseDebugSession)
  RK_UNARY(ListDebugSessions)
  RK_UNARY(ResumeDebugSession)
  RK_UNARY(WaitDebugSession)
  RK_UNARY(InterruptDebugSession)
  RK_UNARY(GetDebugState)
  RK_UNARY(WriteDebugRegisters)
  RK_UNARY(ReadDebugMemory)
  RK_UNARY(WriteDebugMemory)
  RK_UNARY(SetDebugBreakpoints)
  RK_UNARY(SelectDebugThread)
  RK_UNARY(ListDebugModules)
  RK_UNARY(GetDebugTimeline)
  RK_UNARY(SaveDebugTrace)
  RK_UNARY(ListDebugTraces)
  RK_UNARY(DeleteDebugTrace)
  RK_UNARY(WriteDebugInput)
  RK_UNARY(GetDebugMachine)
  RK_UNARY(GetDebugBacktrace)
  RK_UNARY(EvaluateDebug)
  RK_UNARY(DisassembleDebugMemory)
  RK_UNARY(CopyDebugMemory)
  RK_UNARY(RewindDebugSession)
  RK_UNARY(SetDebugHooks)
  RK_UNARY(AnswerDebugHook)

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<AuthGate> auth_;
};

#undef RK_UNARY
#undef RK_STAMPED

// Buffers events between the backend (which must never block) and the
// stream writer. A subscriber that falls this far behind is cut off and
// resumes with from_revision, which is cheaper than unbounded memory.
template <class Sink, class Msg>
class Queue final : public Sink {
 public:
  static constexpr std::size_t kMaxQueued = 10000;

  void Send(Msg event) override {
    std::lock_guard lock(mu_);
    if (end_) return;
    if (events_.size() >= kMaxQueued) {
      end_ = Error(StatusCode::kResourceExhausted,
                   "subscriber fell behind; resubscribe with from_revision set to the last applied revision");
      events_.clear();
    } else {
      events_.push_back(std::move(event));
    }
    cv_.notify_one();
  }

  void End(Status status) override {
    std::lock_guard lock(mu_);
    if (!end_) end_ = std::move(status);
    cv_.notify_one();
  }

  struct Item {
    std::optional<Msg> event;
    std::optional<Status> end;
  };

  // Waits until `until` for an event or the end; both empty on timeout.
  // Queued events are delivered before the end.
  Item Pop(std::chrono::steady_clock::time_point until) {
    std::unique_lock lock(mu_);
    cv_.wait_until(lock, until, [&] { return !events_.empty() || end_; });
    Item item;
    if (!events_.empty()) {
      item.event = std::move(events_.front());
      events_.pop_front();
    } else if (end_) {
      item.end = end_;
    }
    return item;
  }

 private:
  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<Msg> events_;
  std::optional<Status> end_;
};
using EventQueue = Queue<EventSink, pb::SubscribeResponse>;
using PullQueue = Queue<PullSink, pb::PullResponse>;

// Uses the synchronous API: one handler thread per open stream, which keeps
// cancellation and heartbeats simple. A local daemon has a handful of
// subscribers (one per UI window or agent); move to a callback reactor if
// that stops being true.
class Subscriptions final : public pb::SubscriptionService::Service {
 public:
  Subscriptions(std::shared_ptr<Backend> b, std::shared_ptr<std::atomic<bool>> stopping, std::shared_ptr<AuthGate> a,
                std::shared_ptr<std::atomic<int>> open)
      : backend_(std::move(b)), stopping_(std::move(stopping)), auth_(std::move(a)), open_(std::move(open)) {}

  grpc::Status Subscribe(grpc::ServerContext *ctx, const pb::SubscribeRequest *req,
                         grpc::ServerWriter<pb::SubscribeResponse> *writer) override {
    using Clock = std::chrono::steady_clock;
    // Counted while open (RestartDaemon says how many a restart ends).
    struct Count {
      std::atomic<int> &n;
      explicit Count(std::atomic<int> &c) : n(c) { ++n; }
      ~Count() { --n; }
    } count(*open_);
    auto queue = std::make_shared<EventQueue>();
    std::unique_ptr<Subscription> sub;
    if (auto st = Guard([&] {
          std::optional<auth::Principal> who;
          if (Status st = auth_->Check(ctx, "revkit.v1.SubscriptionService/Subscribe", *req, who); !st.ok())
            return st;
          return backend_->Subscribe(MakeContext(ctx, who), *req, queue, sub);
        });
        !st.ok())
      return st;

    const auto heartbeat = std::chrono::seconds(req->heartbeat_seconds() == 0 ? 15 : req->heartbeat_seconds());
    auto next_heartbeat = Clock::now() + heartbeat;
    // Short waits so cancellation and shutdown are noticed promptly.
    constexpr auto kPoll = std::chrono::milliseconds(200);
    while (true) {
      if (ctx->IsCancelled()) return {grpc::StatusCode::CANCELLED, "client cancelled"};
      if (stopping_->load()) return {grpc::StatusCode::UNAVAILABLE, "server shutting down"};
      auto item = queue->Pop(std::min(next_heartbeat, Clock::now() + kPoll));
      if (item.event) {
        if (!writer->Write(*item.event)) return {grpc::StatusCode::CANCELLED, "client went away"};
        continue;
      }
      if (item.end) return ToGrpc(*item.end);
      if (Clock::now() >= next_heartbeat) {
        // A stream outlives neither its session nor its token.
        if (auth_->enabled() && !auth_->Identify(ctx))
          return {grpc::StatusCode::UNAUTHENTICATED, "the session or token this stream used has ended"};
        pb::SubscribeResponse hb;
        hb.mutable_heartbeat()->set_head_revision(sub->head_revision());
        if (!writer->Write(hb)) return {grpc::StatusCode::CANCELLED, "client went away"};
        next_heartbeat += heartbeat;
      }
    }
  }

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<std::atomic<bool>> stopping_;
  std::shared_ptr<AuthGate> auth_;
  std::shared_ptr<std::atomic<int>> open_;
};

// Peer replication: unary calls forward; Pull streams like Subscribe.
class Sync final : public pb::SyncService::Service {
 public:
  static constexpr const char *kService = "revkit.v1.SyncService/";
  Sync(std::shared_ptr<Backend> b, std::shared_ptr<std::atomic<bool>> stopping, std::shared_ptr<AuthGate> a)
      : backend_(std::move(b)), stopping_(std::move(stopping)), auth_(std::move(a)) {}

#define RK_UNARY(Method)                                                                          \
  grpc::Status Method(grpc::ServerContext *ctx, const pb::Method##Request *req,                   \
                      pb::Method##Response *resp) override {                                      \
    return Guard([&] {                                                                            \
      static const std::string method = std::string(kService) + #Method;                          \
      std::optional<auth::Principal> who;                                                         \
      if (Status st = auth_->Check(ctx, method.c_str(), *req, who); !st.ok()) return st;          \
      return backend_->Method(MakeContext(ctx, who), *req, *resp);                                \
    });                                                                                           \
  }
  RK_UNARY(GetSyncState)
  RK_UNARY(Push)
  RK_UNARY(FetchProgram)
#undef RK_UNARY

  grpc::Status Pull(grpc::ServerContext *ctx, const pb::PullRequest *req,
                    grpc::ServerWriter<pb::PullResponse> *writer) override {
    using Clock = std::chrono::steady_clock;
    auto queue = std::make_shared<PullQueue>();
    std::unique_ptr<Subscription> sub;
    if (auto st = Guard([&] {
          std::optional<auth::Principal> who;
          if (Status st = auth_->Check(ctx, "revkit.v1.SyncService/Pull", *req, who); !st.ok()) return st;
          return backend_->Pull(MakeContext(ctx, who), *req, queue, sub);
        });
        !st.ok())
      return st;
    const auto heartbeat = std::chrono::seconds(5);
    auto next_heartbeat = Clock::now() + heartbeat;
    constexpr auto kPoll = std::chrono::milliseconds(200);
    while (true) {
      if (ctx->IsCancelled()) return {grpc::StatusCode::CANCELLED, "client cancelled"};
      if (stopping_->load()) return {grpc::StatusCode::UNAVAILABLE, "server shutting down"};
      auto item = queue->Pop(std::min(next_heartbeat, Clock::now() + kPoll));
      if (item.event) {
        if (!writer->Write(*item.event)) return {grpc::StatusCode::CANCELLED, "client went away"};
        continue;
      }
      if (item.end) return ToGrpc(*item.end);
      if (Clock::now() >= next_heartbeat) {
        if (auth_->enabled() && !auth_->Identify(ctx))
          return {grpc::StatusCode::UNAUTHENTICATED, "the peer's token has been revoked"};
        pb::PullResponse hb;
        hb.mutable_heartbeat()->set_head_revision(sub->head_revision());
        if (!writer->Write(hb)) return {grpc::StatusCode::CANCELLED, "client went away"};
        next_heartbeat += heartbeat;
      }
    }
  }

 private:
  std::shared_ptr<Backend> backend_;
  std::shared_ptr<std::atomic<bool>> stopping_;
  std::shared_ptr<AuthGate> auth_;
};

}  // namespace

GrpcServices::GrpcServices(std::shared_ptr<Backend> backend, std::shared_ptr<std::atomic<bool>> stopping,
                           std::shared_ptr<AuthGate> auth, ScriptServiceOptions scripts,
                           std::shared_ptr<ScriptHostTarget> script_target, DaemonInfo info) {
  if (!script_target) script_target = std::make_shared<ScriptHostTarget>();
  services_.push_back(MakeScriptService(auth, std::move(scripts), std::move(script_target), stopping));
  auto open_streams = info.open_streams;
  services_.push_back(std::make_unique<Meta>(backend, auth, std::move(info)));
  services_.push_back(std::make_unique<Projects>(backend, auth));
  services_.push_back(std::make_unique<Assertions>(backend, auth));
  services_.push_back(std::make_unique<Queries>(backend, auth));
  services_.push_back(std::make_unique<Analysis>(backend, auth));
  services_.push_back(std::make_unique<Plugins>(backend, auth));
  services_.push_back(std::make_unique<Presence>(backend, auth));
  services_.push_back(std::make_unique<Emulator>(backend, auth));
  services_.push_back(std::make_unique<Debugger>(backend, auth));
  services_.push_back(std::make_unique<Diff>(backend, auth));
  services_.push_back(std::make_unique<Types>(backend, auth));
  services_.push_back(std::make_unique<Patch>(backend, auth));
  services_.push_back(std::make_unique<FileSystems>(backend, auth));
  services_.push_back(std::make_unique<BSim>(backend, auth));
  services_.push_back(std::make_unique<Providers>(backend, auth));
  services_.push_back(std::make_unique<Sync>(backend, stopping, auth));
  services_.push_back(std::make_unique<Subscriptions>(backend, std::move(stopping), auth, std::move(open_streams)));
  services_.push_back(MakeAuthService(std::move(auth)));
}

GrpcServices::~GrpcServices() = default;

void GrpcServices::RegisterAll(grpc::ServerBuilder &builder) {
  for (auto &s : services_) builder.RegisterService(s.get());
}

}  // namespace revkit::api
