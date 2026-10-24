// DebugService for the image backend (docs/debugger.md): debug sessions
// over a program, whatever runs it (the emulator, a GDB remote stub, a
// process the daemon launches, a saved trace), owned by the client that
// made them. Session state is the caller's, not facts. Live targets are
// off unless the daemon allows them (rk-daemon --debug-live).
#pragma once

#include "emulator.h"
#include "program.h"

#include "revkit/api/backend.h"
#include "revkit/debug/session.hh"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>

namespace revkit::backend {

struct DebugBounds {
  unsigned sessions_per_client = 8;
  unsigned sessions = 32;
  std::chrono::milliseconds idle = std::chrono::minutes(30);
  std::uint32_t time_ms = 5000, max_time_ms = 60000;
  std::size_t snapshots = 10000, max_snapshots = 100000;
  std::uint64_t timeline_bytes = 64ull << 20, max_timeline_bytes = 512ull << 20;
  EmulatorBounds emulator;
  // Remote stubs, launching and attaching (rk-daemon --debug-live).
  bool live = false;
  std::size_t traces_per_program = 64;
  std::uint64_t max_trace_bytes = 512ull << 20;
};

// A crash dump's bytes (api_minor 102, docs/crash-dumps.md), resolved by
// the backend: a program's stored file, a host file, an upload.
struct DebugCrashSource {
  std::shared_ptr<const void> keep;  // holds `bytes`
  std::span<const std::byte> bytes;
  std::string name;  // what to call it ("core", "crash.dmp")
  // Where an ELF core's mapped files may be read from (code the dump left
  // out, a module's call-frame information and symbols): --browse-root,
  // for an admin's session; empty: never from the host.
  std::vector<std::string> host_roots;
};

// What a session needs of its program, resolved by the backend.
struct DebugProgram {
  std::string program_id;
  std::shared_ptr<const Program> program;
  // Where its saved traces go (the project's directory); empty: memory.
  std::filesystem::path trace_dir;
  // The entry of the function containing a static address (analysis).
  std::function<std::optional<std::uint64_t>(std::uint64_t)> function_entry;
  // The function containing a static address: its entry and name.
  std::function<std::optional<std::pair<std::uint64_t, std::string>>(std::uint64_t)> function_at;
  // The program's patches when the session started: an emulator target runs
  // the program as patched (docs/patching.md).
  facts::PatchList patches;
  // The project program a runtime module is, by the module's name (api_minor
  // 67, docs/debugger.md "Libraries"): a library this program links, else a
  // program of that name. Its program and function_at are set; nullopt: none.
  std::function<std::optional<DebugProgram>(const std::string &module)> library;
  // A crash dump target's source (CreateDebugSessionRequest.crash).
  std::shared_ptr<const DebugCrashSource> crash;
};

// What evaluating needs of the program at the call's revision (docs/debugger.md
// "Expressions"), resolved by the backend for one EvaluateDebug call.
struct DebugEvalEnv {
  // A type by hash, described as GetTypes would.
  std::function<std::optional<pb::TypeDefinition>(const std::string &hash)> describe;
  // The hash of the program's type with this name ("struct foo", "foo").
  std::function<std::optional<std::string>(const std::string &name)> type_named;
  // A symbol's static address by name.
  std::function<std::optional<std::uint64_t>(const std::string &name)> symbol;
  // "name" or "function+0x10" for a static address, or "".
  std::function<std::string(std::uint64_t)> symbol_at;
  // The type hash of the data defined at a static address, if any.
  std::function<std::optional<std::string>(std::uint64_t)> data_type;
  // The decompiler's variables of the function at an entry (as Decompile names them).
  std::function<std::vector<pb::Variable>(std::uint64_t entry)> variables;
};

// Target memory read for CopyDebugMemory (docs/debugger.md "Copying runtime memory").
struct DebugCopySource {
  std::string program_id;
  std::uint64_t runtime = 0;  // the first byte's runtime address
  std::string bytes;
  // The program's address of the first byte, when the range is in the program.
  std::optional<std::uint64_t> program_address;
  std::string perms;        // the target region's ("r-x"), or ""
  std::string region_name;  // its name ("[heap]", a path), or ""
  std::vector<std::pair<std::uint64_t, std::uint64_t>> unreadable;  // (offset, length)
};

class DebugSessions {
 public:
  explicit DebugSessions(DebugBounds bounds = {});
  ~DebugSessions();

  bool live() const { return bounds_.live; }

  api::Status Create(const api::CallContext &ctx, const pb::CreateDebugSessionRequest &req, DebugProgram program,
                     pb::CreateDebugSessionResponse &resp);
  api::Status Close(const api::CallContext &ctx, const pb::CloseDebugSessionRequest &req);
  api::Status List(const api::CallContext &ctx, const pb::ListDebugSessionsRequest &req, pb::ListDebugSessionsResponse &resp);
  // With `env`, runs pass over breakpoints whose conditions don't hold (docs/debugger.md "Breakpoints").
  api::Status Resume(const api::CallContext &ctx, const pb::ResumeDebugSessionRequest &req, pb::ResumeDebugSessionResponse &resp,
                     const DebugEvalEnv *env = nullptr);
  api::Status Wait(const api::CallContext &ctx, const pb::WaitDebugSessionRequest &req, pb::WaitDebugSessionResponse &resp,
                   const DebugEvalEnv *env = nullptr);
  api::Status Interrupt(const api::CallContext &ctx, const pb::InterruptDebugSessionRequest &req);
  api::Status GetState(const api::CallContext &ctx, const pb::GetDebugStateRequest &req, pb::GetDebugStateResponse &resp);
  api::Status WriteRegisters(const api::CallContext &ctx, const pb::WriteDebugRegistersRequest &req,
                             pb::WriteDebugRegistersResponse &resp);
  api::Status ReadMemory(const api::CallContext &ctx, const pb::ReadDebugMemoryRequest &req, pb::ReadDebugMemoryResponse &resp);
  api::Status WriteMemory(const api::CallContext &ctx, const pb::WriteDebugMemoryRequest &req);
  // With `env`, conditions are checked to parse.
  api::Status SetBreakpoints(const api::CallContext &ctx, const pb::SetDebugBreakpointsRequest &req,
                             pb::SetDebugBreakpointsResponse &resp, const DebugEvalEnv *env = nullptr);
  api::Status SelectThread(const api::CallContext &ctx, const pb::SelectDebugThreadRequest &req,
                           pb::SelectDebugThreadResponse &resp);
  api::Status ListModules(const api::CallContext &ctx, const pb::ListDebugModulesRequest &req, pb::ListDebugModulesResponse &resp);
  api::Status GetTimeline(const api::CallContext &ctx, const pb::GetDebugTimelineRequest &req, pb::GetDebugTimelineResponse &resp);
  api::Status SaveTrace(const api::CallContext &ctx, const pb::SaveDebugTraceRequest &req, pb::SaveDebugTraceResponse &resp);
  api::Status SetHooks(const api::CallContext &ctx, const pb::SetDebugHooksRequest &req, const DebugEvalEnv *env,
                       pb::SetDebugHooksResponse &resp);
  api::Status AnswerHook(const api::CallContext &ctx, const pb::AnswerDebugHookRequest &req, pb::AnswerDebugHookResponse &resp);
  api::Status Rewind(const api::CallContext &ctx, const pb::RewindDebugSessionRequest &req, pb::RewindDebugSessionResponse &resp);
  api::Status ListTraces(const DebugProgram &program, pb::ListDebugTracesResponse &resp);
  api::Status DeleteTrace(const DebugProgram &program, const std::string &name);
  api::Status WriteInput(const api::CallContext &ctx, const pb::WriteDebugInputRequest &req);
  api::Status GetMachine(const api::CallContext &ctx, const pb::GetDebugMachineRequest &req, pb::GetDebugMachineResponse &resp);
  api::Status GetBacktrace(const api::CallContext &ctx, const pb::GetDebugBacktraceRequest &req,
                           pb::GetDebugBacktraceResponse &resp);
  // A crash dump session's summary (api_minor 102, docs/crash-dumps.md).
  api::Status GetCrash(const api::CallContext &ctx, const pb::GetDebugCrashRequest &req, pb::GetDebugCrashResponse &resp);

  api::Status Disassemble(const api::CallContext &ctx, const pb::DisassembleDebugMemoryRequest &req, const DebugEvalEnv &env,
                          pb::DisassembleDebugMemoryResponse &resp);
  api::Status ReadForCopy(const api::CallContext &ctx, const pb::CopyDebugMemoryRequest &req, DebugCopySource &out);
  // The program a session debugs (its owner's or an admin's call), for the backend's environment.
  api::Status ProgramOf(const api::CallContext &ctx, const std::string &session_id, std::string &program_id);
  api::Status Evaluate(const api::CallContext &ctx, const pb::EvaluateDebugRequest &req, const DebugEvalEnv &env,
                       pb::EvaluateDebugResponse &resp);

  void SetMachineSupport(MachineSupport s) { machines_ = std::move(s); }

  struct Entry;

 private:
  // The session, if the caller may use it (its owner, or an admin), locked.
  api::Status Acquire(const api::CallContext &ctx, const std::string &id, std::shared_ptr<Entry> &out,
                      std::unique_lock<std::mutex> &lock);
  void Reap();
  // A saved trace's bytes, from the project directory or memory.
  std::optional<std::string> LoadTrace(const DebugProgram &program, const std::string &name);
  api::Status EmulatorFromSession(const api::CallContext &ctx, const pb::DebugEmulatorTarget &em, Entry &e,
                                  debug::SessionOptions &so, std::unique_ptr<emu::Emulator> &out);
  // Saves the session's timeline as a trace (its lock held).
  api::Status SaveTraceLocked(Entry &e, const std::string &name, pb::DebugTraceInfo *info);

  DebugBounds bounds_;
  MachineSupport machines_;
  std::mutex mu_;
  std::map<std::string, std::shared_ptr<Entry>> sessions_;
  // Traces of programs in projects without a directory: program -> name -> bytes.
  std::mutex traces_mu_;
  std::map<std::string, std::map<std::string, std::string>> traces_;
};

}  // namespace revkit::backend
