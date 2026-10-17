// The seam between the API layer and the rest of revkit. Transports (gRPC,
// Connect) translate wire calls into Backend calls; a Backend answers them
// from the fact store, or from synthetic data (FakeBackend) while the store
// and loader are being built.
//
// Requests and responses are the generated revkit.v1 messages: the schema is
// the contract, and restating it as parallel C++ structs would only add a
// translation layer that can drift. Adapters from the fact store's own types
// live inside the Backend implementation.
#pragma once

#include "revkit/v1/analysis.pb.h"
#include "revkit/v1/bsim.pb.h"
#include "revkit/v1/assertion.pb.h"
#include "revkit/v1/debugger.pb.h"
#include "revkit/v1/diff.pb.h"
#include "revkit/v1/emulator.pb.h"
#include "revkit/v1/filesystem.pb.h"
#include "revkit/v1/meta.pb.h"
#include "revkit/v1/patch.pb.h"
#include "revkit/v1/plugin.pb.h"
#include "revkit/v1/presence.pb.h"
#include "revkit/v1/project.pb.h"
#include "revkit/v1/query.pb.h"
#include "revkit/v1/subscription.pb.h"
#include "revkit/v1/sync.pb.h"

#include <chrono>
#include <functional>
#include <memory>
#include <string>

namespace revkit::api {

namespace pb = ::revkit::v1;

// Numeric values are gRPC's status codes, so transports convert by cast.
enum class StatusCode : int {
  kOk = 0,
  kCancelled = 1,
  kUnknown = 2,
  kInvalidArgument = 3,
  kDeadlineExceeded = 4,
  kNotFound = 5,
  kAlreadyExists = 6,
  kPermissionDenied = 7,
  kResourceExhausted = 8,
  kFailedPrecondition = 9,
  kAborted = 10,
  kOutOfRange = 11,
  kUnimplemented = 12,
  kInternal = 13,
  kUnavailable = 14,
  kDataLoss = 15,
  kUnauthenticated = 16,
};

struct Status {
  StatusCode code = StatusCode::kOk;
  std::string message;

  static Status Ok() { return {}; }
  bool ok() const { return code == StatusCode::kOk; }
};

inline Status Error(StatusCode code, std::string message) { return {code, std::move(message)}; }

// Per-call information the transport knows and a backend may honour.
struct CallContext {
  using Clock = std::chrono::steady_clock;
  // Time by which the client stops waiting; max() when it set no deadline.
  Clock::time_point deadline = Clock::time_point::max();
  // True once the client has gone away; long computations should poll it.
  std::function<bool()> cancelled = [] { return false; };
  // "ipv4:127.0.0.1:5555", for logs.
  std::string peer;
  // The authenticated caller ("user:alice", "agent:ci", "peer:daemon-b"),
  // or "anonymous" when the daemon runs without authentication. The
  // transport has already checked the caller's role and projects and
  // stamped its identity on the request's provenance (docs/security.md).
  std::string caller = "anonymous";
  // The caller has the admin role (always so without authentication).
  // Backends that keep per-caller state (emulator sessions) let admins
  // reach everyone's.
  bool caller_admin = true;
};

// Receives subscription events. Called from backend threads, possibly
// concurrently with the transport's own threads; implementations must only
// enqueue and return quickly, never call back into the backend.
class EventSink {
 public:
  virtual ~EventSink() = default;
  virtual void Send(pb::SubscribeResponse event) = 0;
  // The backend ended the stream (project closed, shutdown). No Send follows.
  virtual void End(Status status) = 0;
};

// The same contract for SyncService.Pull's stream.
class PullSink {
 public:
  virtual ~PullSink() = default;
  virtual void Send(pb::PullResponse event) = 0;
  virtual void End(Status status) = 0;
};

// Keeps a subscription registered; destroying it unregisters the sink, after
// which the backend never calls it again.
class Subscription {
 public:
  virtual ~Subscription() = default;
  // Head revision of the subscribed project right now (for heartbeats).
  virtual std::uint64_t head_revision() const = 0;
};

class Backend {
 public:
  virtual ~Backend() = default;

  // MetaService
  virtual Status GetServerInfo(const CallContext &, const pb::GetServerInfoRequest &,
                               pb::GetServerInfoResponse &) = 0;

  // ProjectService
  virtual Status ListProjects(const CallContext &, const pb::ListProjectsRequest &,
                              pb::ListProjectsResponse &) = 0;
  virtual Status OpenProject(const CallContext &, const pb::OpenProjectRequest &,
                             pb::OpenProjectResponse &) = 0;
  virtual Status CloseProject(const CallContext &, const pb::CloseProjectRequest &,
                              pb::CloseProjectResponse &) = 0;
  virtual Status ListPrograms(const CallContext &, const pb::ListProgramsRequest &,
                              pb::ListProgramsResponse &) = 0;
  virtual Status ImportProgram(const CallContext &, const pb::ImportProgramRequest &,
                               pb::ImportProgramResponse &) = 0;
  virtual Status GetProgramSummary(const CallContext &, const pb::GetProgramSummaryRequest &,
                                   pb::GetProgramSummaryResponse &) = 0;
  // Added in api_minor 10. Not pure: backends without a host to browse
  // answer UNIMPLEMENTED.
  virtual Status ListLanguages(const CallContext &, const pb::ListLanguagesRequest &,
                               pb::ListLanguagesResponse &) {
    return Error(StatusCode::kUnimplemented, "ListLanguages is not implemented by this backend");
  }
  virtual Status ListHostFiles(const CallContext &, const pb::ListHostFilesRequest &,
                               pb::ListHostFilesResponse &) {
    return Error(StatusCode::kUnimplemented, "ListHostFiles is not implemented by this backend");
  }
  // Added in api_minor 19 (feature "program-management"). Not pure: other
  // backends answer UNIMPLEMENTED.
  virtual Status DeleteProgram(const CallContext &, const pb::DeleteProgramRequest &, pb::DeleteProgramResponse &) {
    return Error(StatusCode::kUnimplemented, "DeleteProgram is not implemented by this backend");
  }
  virtual Status RenameProgram(const CallContext &, const pb::RenameProgramRequest &, pb::RenameProgramResponse &) {
    return Error(StatusCode::kUnimplemented, "RenameProgram is not implemented by this backend");
  }
  // Folders (api_minor 35, feature "project-folders").
  virtual Status CreateFolder(const CallContext &, const pb::CreateFolderRequest &, pb::CreateFolderResponse &) {
    return Error(StatusCode::kUnimplemented, "CreateFolder is not implemented by this backend");
  }
  virtual Status RenameFolder(const CallContext &, const pb::RenameFolderRequest &, pb::RenameFolderResponse &) {
    return Error(StatusCode::kUnimplemented, "RenameFolder is not implemented by this backend");
  }
  virtual Status DeleteFolder(const CallContext &, const pb::DeleteFolderRequest &, pb::DeleteFolderResponse &) {
    return Error(StatusCode::kUnimplemented, "DeleteFolder is not implemented by this backend");
  }
  virtual Status MoveToFolder(const CallContext &, const pb::MoveToFolderRequest &, pb::MoveToFolderResponse &) {
    return Error(StatusCode::kUnimplemented, "MoveToFolder is not implemented by this backend");
  }
  // Project archives (api_minor 35, feature "project-archive"). Export
  // streams through `write` (false once the client has gone away).
  virtual Status ExportProject(const CallContext &, const pb::ExportProjectRequest &,
                               const std::function<bool(const pb::ExportProjectResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "ExportProject is not implemented by this backend");
  }
  virtual Status UploadChunk(const CallContext &, const pb::UploadChunkRequest &, pb::UploadChunkResponse &) {
    return Error(StatusCode::kUnimplemented, "UploadChunk is not implemented by this backend");
  }
  virtual Status ImportProjectArchive(const CallContext &, const pb::ImportProjectArchiveRequest &,
                                      pb::ImportProjectArchiveResponse &) {
    return Error(StatusCode::kUnimplemented, "ImportProjectArchive is not implemented by this backend");
  }
  // Shared libraries (api_minor 70, feature "program-libraries").
  virtual Status ListProgramLibraries(const CallContext &, const pb::ListProgramLibrariesRequest &,
                                      pb::ListProgramLibrariesResponse &) {
    return Error(StatusCode::kUnimplemented, "ListProgramLibraries is not implemented by this backend");
  }
  virtual Status LinkProgramLibrary(const CallContext &, const pb::LinkProgramLibraryRequest &,
                                    pb::LinkProgramLibraryResponse &) {
    return Error(StatusCode::kUnimplemented, "LinkProgramLibrary is not implemented by this backend");
  }
  virtual Status ResolveImport(const CallContext &, const pb::ResolveImportRequest &, pb::ResolveImportResponse &) {
    return Error(StatusCode::kUnimplemented, "ResolveImport is not implemented by this backend");
  }
  // Added in api_minor 22 (feature "import-progress"): an import's progress,
  // only for the caller (CallContext.caller) that started it.
  virtual Status GetImportProgress(const CallContext &, const pb::GetImportProgressRequest &,
                                   pb::GetImportProgressResponse &) {
    return Error(StatusCode::kUnimplemented, "GetImportProgress is not implemented by this backend");
  }
  // Added in api_minor 23 (feature "raw-detect"): what a raw import of a
  // file needs (language, load address, header offset, regions), detected
  // from its bytes; its progress, for the caller that started it; and
  // stopping it.
  virtual Status DetectRawLayout(const CallContext &, const pb::DetectRawLayoutRequest &,
                                 pb::DetectRawLayoutResponse &) {
    return Error(StatusCode::kUnimplemented, "DetectRawLayout is not implemented by this backend");
  }
  virtual Status GetRawDetectProgress(const CallContext &, const pb::GetRawDetectProgressRequest &,
                                      pb::GetRawDetectProgressResponse &) {
    return Error(StatusCode::kUnimplemented, "GetRawDetectProgress is not implemented by this backend");
  }
  virtual Status CancelRawDetect(const CallContext &, const pb::CancelRawDetectRequest &,
                                 pb::CancelRawDetectResponse &) {
    return Error(StatusCode::kUnimplemented, "CancelRawDetect is not implemented by this backend");
  }
  // Added in api_minor 24 (feature "memory-map"; docs/memory-map.md): edits
  // to a program's memory map after import.
  virtual Status AddMemoryRegion(const CallContext &, const pb::AddMemoryRegionRequest &,
                                 pb::AddMemoryRegionResponse &) {
    return Error(StatusCode::kUnimplemented, "AddMemoryRegion is not implemented by this backend");
  }
  virtual Status UpdateMemoryRegion(const CallContext &, const pb::UpdateMemoryRegionRequest &,
                                    pb::UpdateMemoryRegionResponse &) {
    return Error(StatusCode::kUnimplemented, "UpdateMemoryRegion is not implemented by this backend");
  }
  virtual Status RemoveMemoryRegion(const CallContext &, const pb::RemoveMemoryRegionRequest &,
                                    pb::RemoveMemoryRegionResponse &) {
    return Error(StatusCode::kUnimplemented, "RemoveMemoryRegion is not implemented by this backend");
  }
  // Rebase (api_minor 42, feature "rebase"; docs/memory-map.md).
  virtual Status SetProgramLanguage(const CallContext &, const pb::SetProgramLanguageRequest &,
                                    pb::SetProgramLanguageResponse &) {
    return Error(StatusCode::kUnimplemented, "SetProgramLanguage is not implemented by this backend");
  }
  virtual Status CompareLanguages(const CallContext &, const pb::CompareLanguagesRequest &, pb::CompareLanguagesResponse &) {
    return Error(StatusCode::kUnimplemented, "CompareLanguages is not implemented by this backend");
  }
  virtual Status SetImageBase(const CallContext &, const pb::SetImageBaseRequest &, pb::SetImageBaseResponse &) {
    return Error(StatusCode::kUnimplemented, "SetImageBase is not implemented by this backend");
  }

  // AssertionService
  virtual Status AppendAssertions(const CallContext &, const pb::AppendAssertionsRequest &,
                                  pb::AppendAssertionsResponse &) = 0;
  virtual Status RetractAssertions(const CallContext &, const pb::RetractAssertionsRequest &,
                                   pb::RetractAssertionsResponse &) = 0;
  virtual Status GetHistory(const CallContext &, const pb::GetHistoryRequest &,
                            pb::GetHistoryResponse &) = 0;
  virtual Status Blame(const CallContext &, const pb::BlameRequest &, pb::BlameResponse &) = 0;
  virtual Status ListAssertions(const CallContext &, const pb::ListAssertionsRequest &,
                                pb::ListAssertionsResponse &) = 0;
  virtual Status RevertByProvenance(const CallContext &, const pb::RevertByProvenanceRequest &,
                                    pb::RevertByProvenanceResponse &) = 0;

  // QueryService
  virtual Status GetMemoryMap(const CallContext &, const pb::GetMemoryMapRequest &,
                              pb::GetMemoryMapResponse &) = 0;
  virtual Status ReadMemory(const CallContext &, const pb::ReadMemoryRequest &,
                            pb::ReadMemoryResponse &) = 0;
  virtual Status ListFunctions(const CallContext &, const pb::ListFunctionsRequest &,
                               pb::ListFunctionsResponse &) = 0;
  // Added in api_minor 2. Not pure, so a backend that predates it still
  // builds and answers UNIMPLEMENTED.
  virtual Status ListSymbols(const CallContext &, const pb::ListSymbolsRequest &, pb::ListSymbolsResponse &) {
    return Error(StatusCode::kUnimplemented, "ListSymbols is not implemented by this backend");
  }
  virtual Status GetFunction(const CallContext &, const pb::GetFunctionRequest &,
                             pb::GetFunctionResponse &) = 0;
  virtual Status GetListing(const CallContext &, const pb::GetListingRequest &,
                            pb::GetListingResponse &) = 0;
  virtual Status GetInstruction(const CallContext &, const pb::GetInstructionRequest &,
                                pb::GetInstructionResponse &) = 0;
  virtual Status GetXrefs(const CallContext &, const pb::GetXrefsRequest &,
                          pb::GetXrefsResponse &) = 0;
  virtual Status Decompile(const CallContext &, const pb::DecompileRequest &,
                           pb::DecompileResponse &) = 0;
  virtual Status GetTypes(const CallContext &, const pb::GetTypesRequest &,
                          pb::GetTypesResponse &) = 0;
  virtual Status FindTypes(const CallContext &, const pb::FindTypesRequest &,
                           pb::FindTypesResponse &) = 0;
  // api_minor 11. Not pure: other backends answer UNIMPLEMENTED.
  virtual Status GetFunctionGraph(const CallContext &, const pb::GetFunctionGraphRequest &,
                                  pb::GetFunctionGraphResponse &) {
    return Error(StatusCode::kUnimplemented, "GetFunctionGraph is not implemented by this backend");
  }
  virtual Status ListData(const CallContext &, const pb::ListDataRequest &, pb::ListDataResponse &) {
    return Error(StatusCode::kUnimplemented, "ListData is not implemented by this backend");
  }
  virtual Status PlanClearFlow(const CallContext &, const pb::PlanClearFlowRequest &, pb::PlanClearFlowResponse &) {
    return Error(StatusCode::kUnimplemented, "PlanClearFlow is not implemented by this backend");
  }
  virtual Status ListSymbolTree(const CallContext &, const pb::ListSymbolTreeRequest &, pb::ListSymbolTreeResponse &) {
    return Error(StatusCode::kUnimplemented, "ListSymbolTree is not implemented by this backend");
  }
  virtual Status ListComments(const CallContext &, const pb::ListCommentsRequest &, pb::ListCommentsResponse &) {
    return Error(StatusCode::kUnimplemented, "ListComments is not implemented by this backend");
  }
  virtual Status ListRegisterValues(const CallContext &, const pb::ListRegisterValuesRequest &, pb::ListRegisterValuesResponse &) {
    return Error(StatusCode::kUnimplemented, "ListRegisterValues is not implemented by this backend");
  }
  virtual Status ListRelocations(const CallContext &, const pb::ListRelocationsRequest &, pb::ListRelocationsResponse &) {
    return Error(StatusCode::kUnimplemented, "ListRelocations is not implemented by this backend");
  }
  virtual Status ListLibraryImporters(const CallContext &, const pb::ListLibraryImportersRequest &,
                                      pb::ListLibraryImportersResponse &) {
    return Error(StatusCode::kUnimplemented, "ListLibraryImporters is not implemented by this backend");
  }
  // PDBs and the symbol path (api_minor 49, feature "pdb-load").
  virtual Status LoadDebugFile(const CallContext &, const pb::LoadDebugFileRequest &, pb::LoadDebugFileResponse &) {
    return Error(StatusCode::kUnimplemented, "LoadDebugFile is not implemented by this backend");
  }
  virtual Status LoadPdb(const CallContext &, const pb::LoadPdbRequest &, pb::LoadPdbResponse &) {
    return Error(StatusCode::kUnimplemented, "LoadPdb is not implemented by this backend");
  }
  virtual Status GetSymbolSettings(const CallContext &, const pb::GetSymbolSettingsRequest &,
                                   pb::GetSymbolSettingsResponse &) {
    return Error(StatusCode::kUnimplemented, "GetSymbolSettings is not implemented by this backend");
  }
  virtual Status SetSymbolSettings(const CallContext &, const pb::SetSymbolSettingsRequest &,
                                   pb::SetSymbolSettingsResponse &) {
    return Error(StatusCode::kUnimplemented, "SetSymbolSettings is not implemented by this backend");
  }
  // MSVC RTTI classes (api_minor 45, feature "msvc-rtti").
  virtual Status GetClassHierarchy(const CallContext &, const pb::GetClassHierarchyRequest &,
                                   pb::GetClassHierarchyResponse &) {
    return Error(StatusCode::kUnimplemented, "GetClassHierarchy is not implemented by this backend");
  }
  // QueryService.ListCallingConventions (api_minor 58, feature "calling-conventions").
  virtual Status ListCallingConventions(const CallContext &, const pb::ListCallingConventionsRequest &,
                                        pb::ListCallingConventionsResponse &) {
    return Error(StatusCode::kUnimplemented, "ListCallingConventions is not implemented by this backend");
  }
  // Batch reads for scripts (api_minor 29, feature "script-batch"). Not
  // pure: other backends answer UNIMPLEMENTED. The streaming ones call
  // `write` for each message, possibly from several threads (the transport
  // serializes them); it returns false once the client has gone away, and
  // the backend should then stop.
  virtual Status DecompileMany(const CallContext &, const pb::DecompileManyRequest &,
                               const std::function<bool(const pb::DecompileManyResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "DecompileMany is not implemented by this backend");
  }
  virtual Status ExportC(const CallContext &, const pb::ExportCRequest &,
                         const std::function<bool(const pb::ExportCResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "ExportC is not implemented by this backend");
  }
  virtual Status FindBytes(const CallContext &, const pb::FindBytesRequest &, pb::FindBytesResponse &) {
    return Error(StatusCode::kUnimplemented, "FindBytes is not implemented by this backend");
  }
  virtual Status ListInstructions(const CallContext &, const pb::ListInstructionsRequest &,
                                  const std::function<bool(const pb::ListInstructionsResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "ListInstructions is not implemented by this backend");
  }
  // The byte viewer, the overview bars and next/previous by kind (api_minor
  // 44, features "byte-viewer", "overview", "find-next").
  virtual Status GetByteView(const CallContext &, const pb::GetByteViewRequest &, pb::GetByteViewResponse &) {
    return Error(StatusCode::kUnimplemented, "GetByteView is not implemented by this backend");
  }
  virtual Status GetOverview(const CallContext &, const pb::GetOverviewRequest &, pb::GetOverviewResponse &) {
    return Error(StatusCode::kUnimplemented, "GetOverview is not implemented by this backend");
  }
  virtual Status FindNext(const CallContext &, const pb::FindNextRequest &, pb::FindNextResponse &) {
    return Error(StatusCode::kUnimplemented, "FindNext is not implemented by this backend");
  }
  // Searches (api_minor 41, feature "search"): server streams like the
  // batch reads above. Not pure: other backends answer UNIMPLEMENTED.
  virtual Status SearchMemory(const CallContext &, const pb::SearchMemoryRequest &,
                              const std::function<bool(const pb::SearchMemoryResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "SearchMemory is not implemented by this backend");
  }
  virtual Status SearchText(const CallContext &, const pb::SearchTextRequest &,
                            const std::function<bool(const pb::SearchTextResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "SearchText is not implemented by this backend");
  }
  virtual Status SearchScalars(const CallContext &, const pb::SearchScalarsRequest &,
                               const std::function<bool(const pb::SearchScalarsResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "SearchScalars is not implemented by this backend");
  }
  virtual Status SearchDecompiled(const CallContext &, const pb::SearchDecompiledRequest &,
                                  const std::function<bool(const pb::SearchDecompiledResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "SearchDecompiled is not implemented by this backend");
  }
  // Uses of a struct or union, or one field (api_minor 53, feature
  // "type-uses").
  virtual Status FindTypeUses(const CallContext &, const pb::FindTypeUsesRequest &,
                              const std::function<bool(const pb::FindTypeUsesResponse &)> & /*write*/) {
    return Error(StatusCode::kUnimplemented, "FindTypeUses is not implemented by this backend");
  }

  // Def-use chains and data-flow slices in a decompilation (api_minor 57,
  // feature "decompile-slices").
  virtual Status SliceDecompiled(const CallContext &, const pb::SliceDecompiledRequest &, pb::SliceDecompiledResponse &) {
    return Error(StatusCode::kUnimplemented, "SliceDecompiled is not implemented by this backend");
  }

  // TypeService (api_minor 25, feature "parse-c"). Not pure: other backends
  // answer UNIMPLEMENTED.
  virtual Status ParseC(const CallContext &, const pb::ParseCRequest &, pb::ParseCResponse &) {
    return Error(StatusCode::kUnimplemented, "ParseC is not implemented by this backend");
  }
  // TypeService.AutoStructure (api_minor 32, feature "auto-struct").
  virtual Status AutoStructure(const CallContext &, const pb::AutoStructureRequest &, pb::AutoStructureResponse &) {
    return Error(StatusCode::kUnimplemented, "AutoStructure is not implemented by this backend");
  }
  // TypeService.ExportTypeArchive (api_minor 35, feature "type-archive").
  virtual Status ExportTypeArchive(const CallContext &, const pb::ExportTypeArchiveRequest &,
                                   pb::ExportTypeArchiveResponse &) {
    return Error(StatusCode::kUnimplemented, "ExportTypeArchive is not implemented by this backend");
  }
  // TypeService.CopyTypes and ListTypeArchives (api_minor 52, feature
  // "project-types").
  virtual Status CopyTypes(const CallContext &, const pb::CopyTypesRequest &, pb::CopyTypesResponse &) {
    return Error(StatusCode::kUnimplemented, "CopyTypes is not implemented by this backend");
  }
  virtual Status ListTypeArchives(const CallContext &, const pb::ListTypeArchivesRequest &,
                                  pb::ListTypeArchivesResponse &) {
    return Error(StatusCode::kUnimplemented, "ListTypeArchives is not implemented by this backend");
  }

  // AnalysisService
  virtual Status ListAnalyzers(const CallContext &, const pb::ListAnalyzersRequest &,
                               pb::ListAnalyzersResponse &) = 0;
  virtual Status StartAnalysis(const CallContext &, const pb::StartAnalysisRequest &,
                               pb::StartAnalysisResponse &) = 0;
  virtual Status CancelAnalysis(const CallContext &, const pb::CancelAnalysisRequest &,
                                pb::CancelAnalysisResponse &) = 0;
  virtual Status GetAnalysisStatus(const CallContext &, const pb::GetAnalysisStatusRequest &,
                                   pb::GetAnalysisStatusResponse &) = 0;

  // Function ID (api_minor 49, feature "function-id"; docs/fid.md).
  virtual Status ListFidDatabases(const CallContext &, const pb::ListFidDatabasesRequest &, pb::ListFidDatabasesResponse &) {
    return Error(StatusCode::kUnimplemented, "Function ID is not implemented by this backend");
  }
  virtual Status AttachFidDatabase(const CallContext &, const pb::AttachFidDatabaseRequest &, pb::AttachFidDatabaseResponse &) {
    return Error(StatusCode::kUnimplemented, "Function ID is not implemented by this backend");
  }
  virtual Status DetachFidDatabase(const CallContext &, const pb::DetachFidDatabaseRequest &, pb::DetachFidDatabaseResponse &) {
    return Error(StatusCode::kUnimplemented, "Function ID is not implemented by this backend");
  }
  virtual Status ListFidMatches(const CallContext &, const pb::ListFidMatchesRequest &, pb::ListFidMatchesResponse &) {
    return Error(StatusCode::kUnimplemented, "Function ID is not implemented by this backend");
  }
  virtual Status ApplyFidMatch(const CallContext &, const pb::ApplyFidMatchRequest &, pb::ApplyFidMatchResponse &) {
    return Error(StatusCode::kUnimplemented, "Function ID is not implemented by this backend");
  }
  virtual Status RejectFidMatch(const CallContext &, const pb::RejectFidMatchRequest &, pb::RejectFidMatchResponse &) {
    return Error(StatusCode::kUnimplemented, "Function ID is not implemented by this backend");
  }
  virtual Status CreateFidDatabase(const CallContext &, const pb::CreateFidDatabaseRequest &, pb::CreateFidDatabaseResponse &) {
    return Error(StatusCode::kUnimplemented, "Function ID is not implemented by this backend");
  }

  // PluginService (api_minor 6). Not pure, so backends without plugins
  // still build and answer UNIMPLEMENTED.
  virtual Status ListPlugins(const CallContext &, const pb::ListPluginsRequest &, pb::ListPluginsResponse &) {
    return Error(StatusCode::kUnimplemented, "this backend has no plugins");
  }
  virtual Status RunCommand(const CallContext &, const pb::RunCommandRequest &, pb::RunCommandResponse &) {
    return Error(StatusCode::kUnimplemented, "this backend has no plugins");
  }
  virtual Status GetPluginFacts(const CallContext &, const pb::GetPluginFactsRequest &, pb::GetPluginFactsResponse &) {
    return Error(StatusCode::kUnimplemented, "this backend has no plugins");
  }

  // EmulatorService (api_minor 12, docs/emulator.md). Not pure: a backend
  // without programs to run answers UNIMPLEMENTED.
#define RK_EMULATOR_RPC(Method)                                                                \
  virtual Status Method(const CallContext &, const pb::Method##Request &, pb::Method##Response &) { \
    return Error(StatusCode::kUnimplemented, "the emulator is not implemented by this backend");   \
  }
  RK_EMULATOR_RPC(CreateEmulatorSession)
  RK_EMULATOR_RPC(CloseEmulatorSession)
  RK_EMULATOR_RPC(ListEmulatorSessions)
  RK_EMULATOR_RPC(RunEmulator)
  RK_EMULATOR_RPC(GetEmulatorState)
  RK_EMULATOR_RPC(WriteEmulatorRegisters)
  RK_EMULATOR_RPC(ReadEmulatorMemory)
  RK_EMULATOR_RPC(WriteEmulatorMemory)
  RK_EMULATOR_RPC(SetEmulatorBreakpoints)
  RK_EMULATOR_RPC(GetEmulatorTrace)
  // Firmware (api_minor 20, docs/firmware-emulation.md).
  RK_EMULATOR_RPC(WriteEmulatorInput)
  RK_EMULATOR_RPC(GetEmulatorMachine)
  RK_EMULATOR_RPC(ListMachines)
  RK_EMULATOR_RPC(GetMachine)
  RK_EMULATOR_RPC(SaveMachine)
  RK_EMULATOR_RPC(DeleteMachine)
  RK_EMULATOR_RPC(DeriveMachine)
  RK_EMULATOR_RPC(ListPeripheralKinds)
#undef RK_EMULATOR_RPC

  // DebugService (api_minor 14, docs/debugger.md). Not pure: a backend
  // without programs to debug answers UNIMPLEMENTED.
#define RK_DEBUG_RPC(Method)                                                                     \
  virtual Status Method(const CallContext &, const pb::Method##Request &, pb::Method##Response &) { \
    return Error(StatusCode::kUnimplemented, "the debugger is not implemented by this backend");    \
  }
  RK_DEBUG_RPC(CreateDebugSession)
  RK_DEBUG_RPC(CloseDebugSession)
  RK_DEBUG_RPC(ListDebugSessions)
  RK_DEBUG_RPC(ResumeDebugSession)
  RK_DEBUG_RPC(WaitDebugSession)
  RK_DEBUG_RPC(InterruptDebugSession)
  RK_DEBUG_RPC(GetDebugState)
  RK_DEBUG_RPC(WriteDebugRegisters)
  RK_DEBUG_RPC(ReadDebugMemory)
  RK_DEBUG_RPC(WriteDebugMemory)
  RK_DEBUG_RPC(SetDebugBreakpoints)
  RK_DEBUG_RPC(SelectDebugThread)
  RK_DEBUG_RPC(ListDebugModules)
  RK_DEBUG_RPC(GetDebugTimeline)
  RK_DEBUG_RPC(SaveDebugTrace)
  RK_DEBUG_RPC(ListDebugTraces)
  RK_DEBUG_RPC(DeleteDebugTrace)
  RK_DEBUG_RPC(WriteDebugInput)
  RK_DEBUG_RPC(GetDebugMachine)
  RK_DEBUG_RPC(GetDebugBacktrace)
  RK_DEBUG_RPC(EvaluateDebug)
  RK_DEBUG_RPC(DisassembleDebugMemory)
  RK_DEBUG_RPC(CopyDebugMemory)
  RK_DEBUG_RPC(RewindDebugSession)
  RK_DEBUG_RPC(SetDebugHooks)
  RK_DEBUG_RPC(AnswerDebugHook)
#undef RK_DEBUG_RPC

  // DiffService (api_minor 16, docs/diff.md). Not pure: a backend without
  // a fact store answers UNIMPLEMENTED.
#define RK_DIFF_RPC(Method)                                                                      \
  virtual Status Method(const CallContext &, const pb::Method##Request &, pb::Method##Response &) { \
    return Error(StatusCode::kUnimplemented, "diffing is not implemented by this backend");         \
  }
  RK_DIFF_RPC(CreateDiffSession)
  RK_DIFF_RPC(ListDiffSessions)
  RK_DIFF_RPC(RunDiff)
  RK_DIFF_RPC(GetDiffStatus)
  RK_DIFF_RPC(CancelDiff)
  RK_DIFF_RPC(ListMatches)
  RK_DIFF_RPC(ListUnmatched)
  RK_DIFF_RPC(GetFunctionDiff)
  RK_DIFF_RPC(SummarizeFunctionDiffs)  // api_minor 17
  RK_DIFF_RPC(AcceptMatches)
  RK_DIFF_RPC(RejectMatches)
  RK_DIFF_RPC(SetMatch)
  RK_DIFF_RPC(ApplyMarkup)
  RK_DIFF_RPC(RevertApply)
  RK_DIFF_RPC(Unmatch)             // api_minor 54
  RK_DIFF_RPC(CompareFunctions)    // api_minor 54
  RK_DIFF_RPC(PortFunctionMarkup)  // api_minor 54
#undef RK_DIFF_RPC

  // PatchService (api_minor 27, docs/patching.md). Not pure: a backend
  // without a fact store answers UNIMPLEMENTED.
#define RK_PATCH_RPC(Method)                                                                     \
  virtual Status Method(const CallContext &, const pb::Method##Request &, pb::Method##Response &) { \
    return Error(StatusCode::kUnimplemented, "patching is not implemented by this backend");        \
  }
  RK_PATCH_RPC(Assemble)
  RK_PATCH_RPC(PatchInstruction)
  RK_PATCH_RPC(PatchBytes)
  RK_PATCH_RPC(ListPatches)
  RK_PATCH_RPC(RevertPatches)
  RK_PATCH_RPC(ExportProgram)
  RK_PATCH_RPC(DetectChecksum)
  RK_PATCH_RPC(GetExportSettings)
  RK_PATCH_RPC(SetExportSettings)
  RK_PATCH_RPC(OpenOriginal)
#undef RK_PATCH_RPC

  // FileSystemService (api_minor 48, docs/filesystems.md). Not pure: a
  // backend without a fact store answers UNIMPLEMENTED.
#define RK_FS_RPC(Method)                                                                          \
  virtual Status Method(const CallContext &, const pb::Method##Request &, pb::Method##Response &) { \
    return Error(StatusCode::kUnimplemented, "file systems are not implemented by this backend");   \
  }
  RK_FS_RPC(OpenFileSystem)
  RK_FS_RPC(ListFileSystem)
  RK_FS_RPC(ReadFileSystemFile)
  RK_FS_RPC(GetFileSystemFileInfo)
  RK_FS_RPC(ImportFromFileSystem)
  RK_FS_RPC(ExtractFromFileSystem)
  RK_FS_RPC(CloseFileSystem)
  RK_FS_RPC(ListFileSystems)
#undef RK_FS_RPC

  // BSimService (api_minor 69, docs/bsim.md). Not pure: a backend without a
  // fact store answers UNIMPLEMENTED.
#define RK_BSIM_RPC(Method)                                                                      \
  virtual Status Method(const CallContext &, const pb::Method##Request &, pb::Method##Response &) { \
    return Error(StatusCode::kUnimplemented, "BSim is not implemented by this backend");            \
  }
  RK_BSIM_RPC(CreateBSimDatabase)
  RK_BSIM_RPC(AttachBSimDatabase)
  RK_BSIM_RPC(DetachBSimDatabase)
  RK_BSIM_RPC(ListBSimDatabases)
  RK_BSIM_RPC(IngestBSim)
  RK_BSIM_RPC(ListBSimExecutables)
  RK_BSIM_RPC(ListBSimFunctions)
  RK_BSIM_RPC(UpdateBSimExecutable)
  RK_BSIM_RPC(DeleteBSimExecutables)
  RK_BSIM_RPC(SearchBSim)  // api_minor 72
  RK_BSIM_RPC(ApplyBSimMatches)  // api_minor 76
#undef RK_BSIM_RPC

  // SubscriptionService. On success, `sink` has already received the Hello
  // and any replayed revisions when this returns, and `out` keeps the
  // subscription alive. Heartbeats are the transport's job.
  virtual Status Subscribe(const CallContext &, const pb::SubscribeRequest &,
                           std::shared_ptr<EventSink> sink,
                           std::unique_ptr<Subscription> &out) = 0;

  // PresenceService and SyncService (docs/collab.md), added in api_minor 5.
  // Not pure: a backend without replication answers UNIMPLEMENTED.
  virtual Status UpdatePresence(const CallContext &, const pb::UpdatePresenceRequest &, pb::UpdatePresenceResponse &) {
    return Error(StatusCode::kUnimplemented, "presence is not implemented by this backend");
  }
  virtual Status ListPresence(const CallContext &, const pb::ListPresenceRequest &, pb::ListPresenceResponse &) {
    return Error(StatusCode::kUnimplemented, "presence is not implemented by this backend");
  }
  virtual Status GetSyncState(const CallContext &, const pb::GetSyncStateRequest &, pb::GetSyncStateResponse &) {
    return Error(StatusCode::kUnimplemented, "sync is not implemented by this backend");
  }
  virtual Status Push(const CallContext &, const pb::PushRequest &, pb::PushResponse &) {
    return Error(StatusCode::kUnimplemented, "sync is not implemented by this backend");
  }
  virtual Status FetchProgram(const CallContext &, const pb::FetchProgramRequest &, pb::FetchProgramResponse &) {
    return Error(StatusCode::kUnimplemented, "sync is not implemented by this backend");
  }
  // Like Subscribe: on success `sink` has the hello and the backlog, and
  // `out` keeps the live stream registered. Heartbeats are the transport's.
  virtual Status Pull(const CallContext &, const pb::PullRequest &, std::shared_ptr<PullSink>,
                      std::unique_ptr<Subscription> &) {
    return Error(StatusCode::kUnimplemented, "sync is not implemented by this backend");
  }
};

}  // namespace revkit::api
