#include "revkit/api/auth_policy.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/reflection.h>

#include <algorithm>
#include <map>
#include <set>

namespace revkit::api {
namespace {

namespace gp = google::protobuf;
using auth::Role;

constexpr MethodPolicy kPublic{Role::kNone, false};
constexpr MethodPolicy kView{Role::kViewer, false};
constexpr MethodPolicy kViewProject{Role::kViewer, true};
constexpr MethodPolicy kEditProject{Role::kEditor, true};
constexpr MethodPolicy kEdit{Role::kEditor, false};
constexpr MethodPolicy kAdmin{Role::kAdmin, false};
constexpr MethodPolicy kAdminProject{Role::kAdmin, true};
constexpr MethodPolicy kPeer{Role::kPeer, false};

// Every RPC of revkit.v1. A method missing here is refused to everyone;
// AuthPolicy.EveryMethodHasAPolicy fails until it is added.
const std::map<std::string, MethodPolicy, std::less<>> &Table() {
  static const std::map<std::string, MethodPolicy, std::less<>> t = {
      {"revkit.v1.MetaService/GetServerInfo", kPublic},
      // Ends every client's connection and runs the daemon again: admins
      // (with --no-auth the anonymous caller is one, on loopback only).
      {"revkit.v1.MetaService/RestartDaemon", kAdmin},

      {"revkit.v1.AuthService/Login", kPublic},
      {"revkit.v1.AuthService/WhoAmI", kPublic},
      {"revkit.v1.AuthService/Logout", kView},
      {"revkit.v1.AuthService/ChangePassword", kView},
      {"revkit.v1.AuthService/ListUsers", kAdmin},
      {"revkit.v1.AuthService/CreateUser", kAdmin},
      {"revkit.v1.AuthService/UpdateUser", kAdmin},
      {"revkit.v1.AuthService/DeleteUser", kAdmin},
      {"revkit.v1.AuthService/ListTokens", kAdmin},
      {"revkit.v1.AuthService/CreateToken", kAdmin},
      {"revkit.v1.AuthService/RevokeToken", kAdmin},

      // ListProjects is filtered to the caller's projects instead.
      {"revkit.v1.ProjectService/ListProjects", kView},
      // By path it opens a directory on the host: admin (see Authorize).
      {"revkit.v1.ProjectService/OpenProject", kViewProject},
      {"revkit.v1.ProjectService/CloseProject", kAdminProject},
      {"revkit.v1.ProjectService/ListPrograms", kViewProject},
      // Reads a host path or stores an upload, and runs the loaders.
      {"revkit.v1.ProjectService/ImportProgram", kAdminProject},
      {"revkit.v1.ProjectService/GetProgramSummary", kViewProject},
      // Lists directories under --browse-root on the daemon's host.
      {"revkit.v1.ProjectService/ListHostFiles", kAdmin},
      {"revkit.v1.ProjectService/ListLanguages", kView},
      // Program management (api_minor 19): renaming is an edit; deleting
      // (softly: it hides the program, RetractAssertions restores it) is
      // an admin's, as importing is.
      {"revkit.v1.ProjectService/RenameProgram", kEditProject},
      {"revkit.v1.ProjectService/DeleteProgram", kAdminProject},
      // An import's progress (api_minor 22): whoever may import; the
      // backend answers only the caller that started it.
      {"revkit.v1.ProjectService/GetImportProgress", kAdminProject},
      // Raw layout detection (api_minor 23): reads a host path or takes an
      // upload and runs the decoders on it, as importing does, so whoever
      // may import; its progress and stopping it likewise, and the backend
      // answers only the caller that started it.
      {"revkit.v1.ProjectService/DetectRawLayout", kAdminProject},
      {"revkit.v1.ProjectService/GetRawDetectProgress", kAdminProject},
      {"revkit.v1.ProjectService/CancelRawDetect", kAdminProject},
      // Memory-map edits (api_minor 24): editors' edits, like any other;
      // bytes read from a host path need admin, as importing does (see
      // Authorize). Uploaded bytes are the caller's own.
      {"revkit.v1.ProjectService/AddMemoryRegion", kEditProject},
      {"revkit.v1.ProjectService/UpdateMemoryRegion", kEditProject},
      {"revkit.v1.ProjectService/RemoveMemoryRegion", kEditProject},
      {"revkit.v1.ProjectService/SetImageBase", kEditProject},
      {"revkit.v1.ProjectService/SetProgramLanguage", kEditProject},
      // Decodes the program's code under other languages: its project's.
      {"revkit.v1.ProjectService/CompareLanguages", kViewProject},
      // Load PDB reads files on the daemon's host and may download from
      // symbol servers; the symbol path is the daemon's (docs/security.md).
      {"revkit.v1.ProjectService/LoadPdb", kAdminProject},
      // Load debug file too, and it may contact debuginfod servers
      // (api_minor 86; docs/security.md).
      {"revkit.v1.ProjectService/LoadDebugFile", kAdminProject},
      {"revkit.v1.ProjectService/GetSymbolSettings", kAdmin},
      {"revkit.v1.ProjectService/SetSymbolSettings", kAdmin},
      // Folders (api_minor 35): organizing a project is an edit, like
      // renaming a program; deleting a folder is allowed only when it is
      // empty, so it hides nothing.
      {"revkit.v1.ProjectService/CreateFolder", kEditProject},
      {"revkit.v1.ProjectService/RenameFolder", kEditProject},
      {"revkit.v1.ProjectService/DeleteFolder", kEditProject},
      {"revkit.v1.ProjectService/MoveToFolder", kEditProject},
      // Project archives (api_minor 35): exporting is a read of what the
      // caller may already read (to a host path it writes a file on the
      // daemon's host: admin, see Authorize). Importing creates programs
      // from the archive's binaries and runs the loaders, as ImportProgram
      // does (and may create a project, which a caller limited to some
      // projects can't: it must name one), so it is an admin's; so are
      // uploads, which only importing reads.
      {"revkit.v1.ProjectService/ExportProject", kViewProject},
      {"revkit.v1.ProjectService/UploadChunk", kAdmin},
      {"revkit.v1.ProjectService/ImportProjectArchive", kAdminProject},
      {"revkit.v1.ProjectService/ListProgramLibraries", kViewProject},
      {"revkit.v1.ProjectService/LinkProgramLibrary", kEditProject},
      {"revkit.v1.ProjectService/ResolveImport", kViewProject},

      {"revkit.v1.AssertionService/AppendAssertions", kEditProject},
      {"revkit.v1.AssertionService/RetractAssertions", kEditProject},
      {"revkit.v1.AssertionService/GetHistory", kViewProject},
      {"revkit.v1.AssertionService/Blame", kViewProject},
      {"revkit.v1.AssertionService/ListAssertions", kViewProject},
      {"revkit.v1.AssertionService/RevertByProvenance", kEditProject},

      {"revkit.v1.QueryService/GetMemoryMap", kViewProject},
      {"revkit.v1.QueryService/ReadMemory", kViewProject},
      {"revkit.v1.QueryService/ListFunctions", kViewProject},
      {"revkit.v1.QueryService/ListSymbols", kViewProject},
      {"revkit.v1.QueryService/GetFunction", kViewProject},
      {"revkit.v1.QueryService/GetListing", kViewProject},
      {"revkit.v1.QueryService/GetInstruction", kViewProject},
      {"revkit.v1.QueryService/GetXrefs", kViewProject},
      {"revkit.v1.QueryService/Decompile", kViewProject},
      // A read of the decompilation (api_minor 57).
      {"revkit.v1.QueryService/SliceDecompiled", kViewProject},
      {"revkit.v1.QueryService/GetTypes", kViewProject},
      {"revkit.v1.QueryService/FindTypes", kViewProject},
      {"revkit.v1.QueryService/GetFunctionGraph", kViewProject},
      {"revkit.v1.QueryService/ListData", kViewProject},
      {"revkit.v1.QueryService/ListComments", kViewProject},
      {"revkit.v1.QueryService/ListRegisterValues", kViewProject},
      {"revkit.v1.QueryService/ListSymbolTree", kViewProject},
      {"revkit.v1.QueryService/PlanClearFlow", kViewProject},
      {"revkit.v1.QueryService/ListRelocations", kViewProject},
      {"revkit.v1.QueryService/ListLibraryImporters", kViewProject},
      {"revkit.v1.QueryService/GetClassHierarchy", kViewProject},
      {"revkit.v1.QueryService/ListCallingConventions", kViewProject},
      // Batch reads for scripts (api_minor 29): what the per-item reads
      // (Decompile, ReadMemory, GetInstruction) allow, in one call.
      {"revkit.v1.QueryService/DecompileMany", kViewProject},
      {"revkit.v1.QueryService/ExportC", kViewProject},
      {"revkit.v1.QueryService/FindBytes", kViewProject},
      {"revkit.v1.QueryService/ListInstructions", kViewProject},
      // The byte viewer, the overview bars and next/previous (api_minor 44).
      {"revkit.v1.QueryService/GetByteView", kViewProject},
      {"revkit.v1.QueryService/GetOverview", kViewProject},
      {"revkit.v1.QueryService/FindNext", kViewProject},
      {"revkit.v1.QueryService/SearchMemory", kViewProject},
      {"revkit.v1.QueryService/SearchText", kViewProject},
      {"revkit.v1.QueryService/SearchScalars", kViewProject},
      {"revkit.v1.QueryService/SearchDecompiled", kViewProject},
      {"revkit.v1.QueryService/FindTypeUses", kViewProject},

      // Parsing C is a read of the program's types; reading host files for
      // it (sources or include directories by path) is an admin's, as
      // importing and browsing are (see Authorize).
      {"revkit.v1.TypeService/ParseC", kViewProject},
      // A structure from pointer use or data: a read; applying it is an
      // AppendAssertions.
      {"revkit.v1.TypeService/AutoStructure", kViewProject},
      {"revkit.v1.TypeService/ExportTypeArchive", kViewProject},
      // Project-wide types: CopyTypes asserts (in the project's space and
      // the program's); ListTypeArchives reads.
      {"revkit.v1.TypeService/CopyTypes", kEditProject},
      {"revkit.v1.TypeService/ListTypeArchives", kViewProject},

      {"revkit.v1.SubscriptionService/Subscribe", kViewProject},

      {"revkit.v1.AnalysisService/ListAnalyzers", kViewProject},
      {"revkit.v1.AnalysisService/StartAnalysis", kEditProject},
      // Names a job, not a project.
      {"revkit.v1.AnalysisService/CancelAnalysis", kEdit},
      {"revkit.v1.AnalysisService/GetAnalysisStatus", kViewProject},
      // Function ID: a database file is read (attach) or written (create)
      // on the daemon's host: admin, as ImportProgram by path.
      {"revkit.v1.AnalysisService/ListFidDatabases", kViewProject},
      {"revkit.v1.AnalysisService/AttachFidDatabase", kAdminProject},
      {"revkit.v1.AnalysisService/DetachFidDatabase", kEditProject},
      {"revkit.v1.AnalysisService/ListFidMatches", kViewProject},
      {"revkit.v1.AnalysisService/ApplyFidMatch", kEditProject},
      {"revkit.v1.AnalysisService/RejectFidMatch", kEditProject},
      {"revkit.v1.AnalysisService/CreateFidDatabase", kAdminProject},

      // Plugins are installed by whoever starts the daemon (--plugin-dir,
      // --plugin-grant); running a command is an edit.
      {"revkit.v1.PluginService/ListPlugins", kView},
      {"revkit.v1.PluginService/RunCommand", kEditProject},
      {"revkit.v1.PluginService/GetPluginFacts", kViewProject},

      {"revkit.v1.PresenceService/UpdatePresence", kViewProject},
      {"revkit.v1.PresenceService/ListPresence", kViewProject},

      // Emulation (docs/emulator.md): running code is an action, not a read;
      // sessions belong to whoever made them (the backend checks the caller),
      // so a viewer can't reach anyone's. Reading a session needs viewer, but
      // only its owner (or an admin) gets past "not found".
      {"revkit.v1.EmulatorService/CreateEmulatorSession", kEditProject},
      {"revkit.v1.EmulatorService/CloseEmulatorSession", kEdit},
      {"revkit.v1.EmulatorService/ListEmulatorSessions", kView},
      {"revkit.v1.EmulatorService/RunEmulator", kEdit},
      {"revkit.v1.EmulatorService/GetEmulatorState", kView},
      {"revkit.v1.EmulatorService/WriteEmulatorRegisters", kEdit},
      {"revkit.v1.EmulatorService/ReadEmulatorMemory", kView},
      {"revkit.v1.EmulatorService/WriteEmulatorMemory", kEdit},
      {"revkit.v1.EmulatorService/SetEmulatorBreakpoints", kEdit},
      {"revkit.v1.EmulatorService/GetEmulatorTrace", kView},
      // Firmware (docs/firmware-emulation.md): input to a session's machine
      // is part of running it; its state is a read of the session.
      {"revkit.v1.EmulatorService/WriteEmulatorInput", kEdit},
      {"revkit.v1.EmulatorService/GetEmulatorMachine", kView},
      // Machine descriptions live with the program's project: reading them
      // needs viewer, creating, deriving (a trial run) or deleting editor.
      // Peripheral plugins they name are the daemon's (--plugin-dir), with
      // the capabilities the daemon granted (--plugin-grant): a description
      // can't grant one.
      {"revkit.v1.EmulatorService/ListMachines", kViewProject},
      {"revkit.v1.EmulatorService/GetMachine", kViewProject},
      {"revkit.v1.EmulatorService/SaveMachine", kEditProject},
      {"revkit.v1.EmulatorService/DeleteMachine", kEditProject},
      {"revkit.v1.EmulatorService/DeriveMachine", kEditProject},
      {"revkit.v1.EmulatorService/ListPeripheralKinds", kView},

      // Debugging (docs/debugger.md): as emulation, sessions belong to
      // whoever made them, and running code is an edit. Live targets run
      // code on the daemon's host (launch, attach) or reach other machines
      // from it (a gdb remote address): CreateDebugSession needs admin for
      // those (see Authorize), editor for the emulator and saved traces.
      {"revkit.v1.DebugService/CreateDebugSession", kEditProject},
      {"revkit.v1.DebugService/CloseDebugSession", kEdit},
      {"revkit.v1.DebugService/ListDebugSessions", kView},
      {"revkit.v1.DebugService/ResumeDebugSession", kEdit},
      {"revkit.v1.DebugService/WaitDebugSession", kView},
      {"revkit.v1.DebugService/InterruptDebugSession", kEdit},
      {"revkit.v1.DebugService/GetDebugState", kView},
      {"revkit.v1.DebugService/WriteDebugRegisters", kEdit},
      {"revkit.v1.DebugService/ReadDebugMemory", kView},
      {"revkit.v1.DebugService/WriteDebugMemory", kEdit},
      {"revkit.v1.DebugService/SetDebugBreakpoints", kEdit},
      {"revkit.v1.DebugService/SelectDebugThread", kEdit},
      {"revkit.v1.DebugService/ListDebugModules", kView},
      {"revkit.v1.DebugService/GetDebugTimeline", kView},
      // Writes into the session's project (its directory when persistent).
      {"revkit.v1.DebugService/SaveDebugTrace", kEdit},
      {"revkit.v1.DebugService/ListDebugTraces", kViewProject},
      {"revkit.v1.DebugService/DeleteDebugTrace", kEditProject},
      {"revkit.v1.DebugService/WriteDebugInput", kEdit},
      {"revkit.v1.DebugService/GetDebugMachine", kView},
      // The call stack of the caller's own session (api_minor 59).
      {"revkit.v1.DebugService/GetDebugBacktrace", kView},
      {"revkit.v1.DebugService/EvaluateDebug", kView},
      {"revkit.v1.DebugService/DisassembleDebugMemory", kView},
      // Writes the session's program (a block, patches); a new program is an import (see Authorize).
      {"revkit.v1.DebugService/CopyDebugMemory", kEdit},
      // The caller's own session; a saved branch is a trace, as SaveDebugTrace.
      {"revkit.v1.DebugService/RewindDebugSession", kEdit},
      // Hooks on the caller's own emulator session; the hooks' code runs in the client.
      {"revkit.v1.DebugService/SetDebugHooks", kEdit},
      {"revkit.v1.DebugService/AnswerDebugHook", kEdit},

      // Diffing (docs/diff.md): reading a session, and running it (it only
      // computes what a read would), needs viewer; deciding matches and
      // porting markup are edits, and so is creating a session (a revision)
      // and cancelling someone's run.
      {"revkit.v1.DiffService/CreateDiffSession", kEditProject},
      {"revkit.v1.DiffService/ListDiffSessions", kViewProject},
      {"revkit.v1.DiffService/RunDiff", kViewProject},
      {"revkit.v1.DiffService/GetDiffStatus", kViewProject},
      {"revkit.v1.DiffService/CancelDiff", kEditProject},
      {"revkit.v1.DiffService/ListMatches", kViewProject},
      {"revkit.v1.DiffService/ListUnmatched", kViewProject},
      {"revkit.v1.DiffService/GetFunctionDiff", kViewProject},
      {"revkit.v1.DiffService/SummarizeFunctionDiffs", kViewProject},
      {"revkit.v1.DiffService/AcceptMatches", kEditProject},
      {"revkit.v1.DiffService/RejectMatches", kEditProject},
      {"revkit.v1.DiffService/SetMatch", kEditProject},
      {"revkit.v1.DiffService/ApplyMarkup", kEditProject},
      {"revkit.v1.DiffService/RevertApply", kEditProject},
      // Comparing any two functions reads; porting between them and
      // undoing decisions edit (api_minor 54).
      {"revkit.v1.DiffService/Unmatch", kEditProject},
      {"revkit.v1.DiffService/CompareFunctions", kViewProject},
      {"revkit.v1.DiffService/PortFunctionMarkup", kEditProject},

      // Patching (docs/patching.md): assembling and reading patches is
      // viewing; writing a patch or the export settings is editing.
      // Exporting as a download returns the file's bytes with the patches,
      // nothing a viewer can't already read (ReadMemory); exporting to a
      // host path writes a file on the daemon's host: admin (Authorize).
      {"revkit.v1.PatchService/Assemble", kViewProject},
      {"revkit.v1.PatchService/PatchInstruction", kEditProject},
      {"revkit.v1.PatchService/PatchBytes", kEditProject},
      {"revkit.v1.PatchService/ListPatches", kViewProject},
      {"revkit.v1.PatchService/RevertPatches", kEditProject},
      {"revkit.v1.PatchService/ExportProgram", kViewProject},
      {"revkit.v1.PatchService/DetectChecksum", kViewProject},
      {"revkit.v1.PatchService/GetExportSettings", kViewProject},
      {"revkit.v1.PatchService/SetExportSettings", kEditProject},
      // Imports the stored file again as a program of the project (no host
      // path, no upload): editing the project, like a diff session.
      {"revkit.v1.PatchService/OpenOriginal", kEditProject},

      // Container file systems (api_minor 48; docs/filesystems.md): opening
      // a program's stored file is a read of the project; a host path, an
      // upload or sent bytes need admin (see Authorize), as ImportProgram.
      // Sessions belong to their opener (the backend answers anyone else
      // NOT_FOUND), so browsing them is a viewer's. Importing makes programs
      // from bytes the session already holds (no host path, no upload): an
      // edit of the target project, like PatchService/OpenOriginal.
      // Extracting writes files on the daemon's host: admin.
      {"revkit.v1.FileSystemService/OpenFileSystem", kViewProject},
      {"revkit.v1.FileSystemService/ListFileSystem", kView},
      {"revkit.v1.FileSystemService/ReadFileSystemFile", kView},
      {"revkit.v1.FileSystemService/GetFileSystemFileInfo", kView},
      {"revkit.v1.FileSystemService/ImportFromFileSystem", kEditProject},
      {"revkit.v1.FileSystemService/ExtractFromFileSystem", kAdmin},
      {"revkit.v1.FileSystemService/CloseFileSystem", kView},
      {"revkit.v1.FileSystemService/ListFileSystems", kView},
      // BSim databases (docs/bsim.md): one at a host path is admin's
      // (Authorize); the rest name an attached one.
      {"revkit.v1.BSimService/CreateBSimDatabase", kEditProject},
      {"revkit.v1.BSimService/AttachBSimDatabase", kAdminProject},
      {"revkit.v1.BSimService/DetachBSimDatabase", kEditProject},
      {"revkit.v1.BSimService/ListBSimDatabases", kViewProject},
      {"revkit.v1.BSimService/IngestBSim", kEditProject},
      {"revkit.v1.BSimService/ListBSimExecutables", kViewProject},
      {"revkit.v1.BSimService/ListBSimFunctions", kViewProject},
      {"revkit.v1.BSimService/UpdateBSimExecutable", kEditProject},
      {"revkit.v1.BSimService/DeleteBSimExecutables", kEditProject},
      {"revkit.v1.BSimService/SearchBSim", kViewProject},
      {"revkit.v1.BSimService/ApplyBSimMatches", kEditProject},

      // Scripts (api_minor 31; docs/scripting.md, docs/security.md): seeing
      // the libraries is a read; saving a script is an editor's at least.
      // Running one (or a console, api_minor 43) is gated by the service
      // itself on the role --scripts-host-role names (by default: editor on
      // a loopback daemon, nobody on one listening beyond it; "viewer"
      // opens it to viewers, whose run tokens can't edit), since a script
      // is full Python as the daemon's user. Runs and consoles belong to
      // whoever started them (an admin may answer or cancel anyone's);
      // ListScriptRuns shows the caller's own (an admin's: everyone's).
      {"revkit.v1.ScriptService/ListScripts", kView},
      {"revkit.v1.ScriptService/GetScript", kView},
      {"revkit.v1.ScriptService/RunScript", kViewProject},
      {"revkit.v1.ScriptService/AnswerPrompt", kView},
      {"revkit.v1.ScriptService/CancelScript", kView},
      {"revkit.v1.ScriptService/UpdateContext", kView},
      {"revkit.v1.ScriptService/CompleteConsole", kViewProject},
      {"revkit.v1.ScriptService/SaveScript", kEdit},
      {"revkit.v1.ScriptService/ListScriptRuns", kView},
      // Makes the daemon's user's script Python (api_minor 33): an editor's
      // who may run scripts, as running one is.
      {"revkit.v1.ScriptService/SetupScriptPython", kEdit},

      // Replication: peer daemons only, every project.
      {"revkit.v1.SyncService/GetSyncState", kPeer},
      {"revkit.v1.SyncService/Pull", kPeer},
      {"revkit.v1.SyncService/Push", kPeer},
      {"revkit.v1.SyncService/FetchProgram", kPeer},
  };
  return t;
}

std::string ProjectOfProgram(const std::string &program_id) { return program_id.substr(0, program_id.find('/')); }

void Collect(const gp::Message &m, std::set<std::string> &out, int depth) {
  if (depth > 4) return;
  const gp::Descriptor *d = m.GetDescriptor();
  const gp::Reflection *r = m.GetReflection();
  for (int i = 0; i < d->field_count(); ++i) {
    const gp::FieldDescriptor *f = d->field(i);
    if (f->type() == gp::FieldDescriptor::TYPE_STRING) {
      const bool project = f->name() == "project_id", program = f->name() == "program_id" || f->name() == "program_ids";
      if (!project && !program) continue;
      auto add = [&](const std::string &v) {
        if (!v.empty()) out.insert(project ? v : ProjectOfProgram(v));
      };
      if (f->is_repeated()) {
        for (int j = 0; j < r->FieldSize(m, f); ++j) add(r->GetRepeatedString(m, f, j));
      } else if (!f->containing_oneof() || r->HasField(m, f)) {
        add(r->GetString(m, f));
      }
    } else if (f->type() == gp::FieldDescriptor::TYPE_MESSAGE && !f->is_repeated() && !f->is_map()) {
      if (r->HasField(m, f)) Collect(r->GetMessage(m, f), out, depth + 1);
    }
  }
}

pb::ProvenanceKind KindOf(const auth::Principal &p) {
  return p.kind == auth::PrincipalKind::kUser ? pb::PROVENANCE_KIND_USER : pb::PROVENANCE_KIND_AGENT;
}

const char *KindText(pb::ProvenanceKind k) {
  switch (k) {
    case pb::PROVENANCE_KIND_USER: return "user";
    case pb::PROVENANCE_KIND_IMPORT: return "import";
    case pb::PROVENANCE_KIND_AGENT: return "agent";
    case pb::PROVENANCE_KIND_ANALYSIS: return "analysis";
    case pb::PROVENANCE_KIND_MIGRATION: return "migration";
    case pb::PROVENANCE_KIND_PLUGIN: return "plugin";
    case pb::PROVENANCE_KIND_SCRIPT: return "script";
    default: return "unknown";
  }
}

}  // namespace

std::optional<MethodPolicy> PolicyFor(std::string_view method) {
  auto it = Table().find(method);
  if (it == Table().end()) return std::nullopt;
  return it->second;
}

std::vector<std::string> MethodsWithPolicy() {
  std::vector<std::string> out;
  for (const auto &[k, _] : Table()) out.push_back(k);
  return out;
}

std::vector<std::string> ProjectsNamedBy(const google::protobuf::Message &request) {
  std::set<std::string> out;
  Collect(request, out, 0);
  return {out.begin(), out.end()};
}

Status Authorize(const auth::Principal *caller, std::string_view method, const google::protobuf::Message &request) {
  auto policy = PolicyFor(method);
  if (!policy) return Error(StatusCode::kPermissionDenied, std::string(method) + " has no access policy");
  auth::Role need = policy->role;
  if (method == "revkit.v1.ProjectService/OpenProject") {
    if (const auto *open = dynamic_cast<const pb::OpenProjectRequest *>(&request); open && open->has_path())
      need = auth::Role::kAdmin;  // a directory on the daemon's host
  }
  if (method == "revkit.v1.TypeService/ParseC") {
    if (const auto *parse = dynamic_cast<const pb::ParseCRequest *>(&request)) {
      bool host = !parse->include_dirs().empty() || !parse->system_include_dirs().empty();
      for (const auto &s : parse->sources()) host = host || s.has_path();
      if (host) need = auth::Role::kAdmin;  // files on the daemon's host
    }
  }
  if (method == "revkit.v1.ProjectService/AddMemoryRegion") {
    // A file on the daemon's host: admin, as ImportProgram by path.
    if (const auto *add = dynamic_cast<const pb::AddMemoryRegionRequest *>(&request); add && add->has_path())
      need = auth::Role::kAdmin;
  }
  if (method == "revkit.v1.DebugService/CreateDebugSession") {
    // A process on the daemon's host, or a connection from it: admin.
    if (const auto *create = dynamic_cast<const pb::CreateDebugSessionRequest *>(&request);
        create && (create->has_launch() || create->has_remote()))
      need = auth::Role::kAdmin;
  }
  if (method == "revkit.v1.DebugService/CopyDebugMemory") {
    // A new program is an import: admin, as ImportProgram.
    if (const auto *copy = dynamic_cast<const pb::CopyDebugMemoryRequest *>(&request);
        copy && copy->mode() == pb::DEBUG_COPY_MODE_NEW_PROGRAM)
      need = auth::Role::kAdmin;
  }
  if (method == "revkit.v1.ProjectService/ExportProject") {
    // A file written on the daemon's host: admin.
    if (const auto *ex = dynamic_cast<const pb::ExportProjectRequest *>(&request); ex && !ex->host_path().empty())
      need = auth::Role::kAdmin;
  }
  if (method == "revkit.v1.FileSystemService/OpenFileSystem") {
    // A host file or directory, an upload, or bytes brought in: admin.
    if (const auto *open = dynamic_cast<const pb::OpenFileSystemRequest *>(&request);
        open && !open->has_program_id())
      need = auth::Role::kAdmin;
  }
  if (method == "revkit.v1.BSimService/CreateBSimDatabase") {
    // A directory on the daemon's host: admin; one in the project's own
    // directory (by name) is the project editor's.
    if (const auto *c = dynamic_cast<const pb::CreateBSimDatabaseRequest *>(&request); c && !c->path().empty())
      need = auth::Role::kAdmin;
  }
  if (method == "revkit.v1.PatchService/ExportProgram") {
    // A file written on the daemon's host: admin.
    if (const auto *ex = dynamic_cast<const pb::ExportProgramRequest *>(&request); ex && !ex->host_path().empty())
      need = auth::Role::kAdmin;
  }
  if (need == auth::Role::kNone) return Status::Ok();
  // Authentication disabled (--no-auth): everything, as before.
  if (caller && caller->kind == auth::PrincipalKind::kAnonymous) return Status::Ok();
  if (!caller)
    return Error(StatusCode::kUnauthenticated,
                 "sign in first: send \"authorization: Bearer <token>\" with a session token (AuthService.Login) or "
                 "an API token (rk-daemon token create); see docs/security.md");
  if (!auth::role_allows(caller->role, need))
    return Error(StatusCode::kPermissionDenied, caller->display() + " (" + auth::to_string(caller->role) +
                                                    ") may not call " + std::string(method) + ": it needs " +
                                                    auth::to_string(need));
  // A caller limited to some projects may name only those, whatever the
  // method (ListScripts' project_id, for one, is optional); a
  // project-scoped method must name one.
  if (!caller->projects.empty()) {
    auto named = ProjectsNamedBy(request);
    if (named.empty() && policy->project_scoped)
      return Error(StatusCode::kPermissionDenied,
                   caller->display() + " is limited to some projects; " + std::string(method) + " must name one");
    for (const std::string &p : named)
      if (!caller->may_use_project(p))
        return Error(StatusCode::kPermissionDenied, caller->display() + " may not use project \"" + p + "\"");
  }
  return Status::Ok();
}

Status StampProvenance(const auth::Principal &caller, pb::Provenance &p) {
  if (caller.kind == auth::PrincipalKind::kAnonymous) return Status::Ok();
  if (caller.kind == auth::PrincipalKind::kPeer)
    return Error(StatusCode::kPermissionDenied, "peers replicate; they don't make edits");
  const pb::ProvenanceKind mine = KindOf(caller);
  const std::string me = caller.display();
  // Who the author acted for is always the caller (api_minor 29).
  if (!p.on_behalf_of().empty() && p.on_behalf_of() != me)
    return Error(StatusCode::kPermissionDenied, "provenance on_behalf_of " + p.on_behalf_of() +
                                                    " does not match the authenticated caller " + me +
                                                    "; leave it empty and the server fills it in");
  if (p.kind() == pb::PROVENANCE_KIND_UNSPECIFIED && p.id().empty()) {
    p.set_kind(mine);
    p.set_id(caller.name);
    return Status::Ok();
  }
  if (p.kind() == mine && (p.id().empty() || p.id() == caller.name)) {
    p.set_id(caller.name);
    return Status::Ok();
  }
  // A script any editor runs (docs/scripting.md): its name is the author,
  // the caller who ran it is stamped as whom it acted for, so blame and
  // reverts still name the person.
  if (p.kind() == pb::PROVENANCE_KIND_SCRIPT) {
    if (p.id().empty())
      return Error(StatusCode::kInvalidArgument, "script provenance needs the script's name as its id");
    p.set_on_behalf_of(me);
    return Status::Ok();
  }
  const bool importer = p.kind() == pb::PROVENANCE_KIND_IMPORT || p.kind() == pb::PROVENANCE_KIND_MIGRATION ||
                        p.kind() == pb::PROVENANCE_KIND_ANALYSIS || p.kind() == pb::PROVENANCE_KIND_PLUGIN;
  if (importer && caller.role == auth::Role::kAdmin && !p.id().empty()) {
    p.set_on_behalf_of(me);
    return Status::Ok();
  }
  return Error(StatusCode::kPermissionDenied,
               std::string("provenance ") + KindText(p.kind()) + ":" + p.id() +
                   " does not match the authenticated caller " + caller.display() +
                   "; leave provenance kind and id empty and the server fills them in");
}

void StampPresence(const auth::Principal &caller, pb::Presence &presence) {
  if (caller.kind == auth::PrincipalKind::kAnonymous) return;
  presence.mutable_who()->set_kind(KindOf(caller));
  presence.mutable_who()->set_id(caller.name);
  presence.set_display_name(caller.name);
}

pb::Identity ToIdentity(const auth::Principal &caller) {
  pb::Identity id;
  id.set_kind(static_cast<pb::PrincipalKind>(static_cast<int>(caller.kind)));
  id.set_name(caller.name);
  id.set_role(static_cast<pb::Role>(static_cast<int>(caller.role)));
  for (const auto &p : caller.projects) id.add_projects(p);
  id.set_method(static_cast<pb::AuthMethod>(static_cast<int>(caller.method)));
  if (caller.kind == auth::PrincipalKind::kUser || caller.kind == auth::PrincipalKind::kAgent) {
    id.mutable_provenance()->set_kind(KindOf(caller));
    id.mutable_provenance()->set_id(caller.name);
  }
  if (caller.expires_at) id.mutable_expires_at()->set_seconds(caller.expires_at);
  return id;
}

auth::Principal AnonymousPrincipal() {
  auth::Principal p;
  p.kind = auth::PrincipalKind::kAnonymous;
  p.name = "anonymous";
  p.role = auth::Role::kAdmin;
  p.method = auth::AuthMethod::kNone;
  return p;
}

}  // namespace revkit::api
