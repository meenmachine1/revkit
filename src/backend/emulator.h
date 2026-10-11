// EmulatorService for the image backend: emulation sessions over loaded
// programs (revkit::emu), owned by the caller that made them (the
// authenticated identity, CallContext.caller; admins reach every session), bounded in
// steps, memory and time. Session state is user-visible state, not facts:
// nothing here touches a project's fact store.
#pragma once

#include "program.h"

#include "revkit/api/backend.h"
#include "revkit/emu/emulator.hh"
#include "revkit/emu/machine.hh"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace revkit::backend {

struct EmulatorBounds {
  // Defaults and caps of EmulatorLimits.
  std::uint64_t steps_per_call = 1000000, max_steps_per_call = 50000000;
  std::uint64_t total_steps = 100000000, max_total_steps = 1000000000;
  std::uint64_t memory = 256ull << 20, max_memory = 1ull << 30;
  std::uint32_t trace_capacity = 4096, max_trace_capacity = 1 << 16;
  std::uint32_t time_ms = 5000, max_time_ms = 60000;
  unsigned sessions_per_client = 8;
  unsigned sessions = 64;
  std::chrono::milliseconds idle = std::chrono::minutes(30);
};

// The limits in force for what a request asked (EmulatorLimits: 0 is the
// default, everything capped).
pb::EmulatorLimits ResolveLimits(const pb::EmulatorLimits &asked, const EmulatorBounds &bounds);

// What machines need from the backend (docs/firmware-emulation.md): the
// daemon's peripheral plugins, and the descriptions saved with programs.
struct MachineSupport {
  emu::PeripheralFactory factory;
  // A saved description by program and name; nullopt when there's none.
  std::function<std::optional<std::string>(const std::string &program_id, const std::string &name)> load;
};

// Builds and starts an emulator for `program` as `req` describes (entry,
// start mode, arguments, registers, memory, breakpoints, stubs, stdin, and
// a machine), over the program's bytes as `patches` leave them.
api::Status BuildEmulator(const pb::CreateEmulatorSessionRequest &req, const std::shared_ptr<const Program> &program,
                          const pb::EmulatorLimits &limits, std::unique_ptr<emu::Emulator> &out,
                          const facts::PatchList &patches = {}, const MachineSupport *machines = nullptr);

// A machine's description and state for responses.
void FillMachineInfo(const emu::Machine &m, pb::EmulatorMachineInfo *out);
void FillMachineState(const emu::Emulator &e, pb::EmulatorMachineState *out);
// Its exception events from `from` (numbered from the first ever), at most `limit`.
void FillMachineEvents(const emu::Machine &m, std::uint64_t from, std::uint32_t limit,
                       google::protobuf::RepeatedPtrField<pb::EmulatorException> *out, std::uint64_t &first,
                       std::uint64_t &count);

class EmulatorSessions {
 public:
  explicit EmulatorSessions(EmulatorBounds bounds = {});
  ~EmulatorSessions();

  // `program` is the session's program (the caller resolved
  // request.program_id).
  api::Status Create(const api::CallContext &ctx, const pb::CreateEmulatorSessionRequest &req,
                     std::shared_ptr<const Program> program, pb::CreateEmulatorSessionResponse &resp,
                     const facts::PatchList &patches = {});
  api::Status Close(const api::CallContext &ctx, const pb::CloseEmulatorSessionRequest &req);
  api::Status List(const api::CallContext &ctx, const pb::ListEmulatorSessionsRequest &req,
                   pb::ListEmulatorSessionsResponse &resp);
  api::Status Run(const api::CallContext &ctx, const pb::RunEmulatorRequest &req, pb::RunEmulatorResponse &resp);
  api::Status GetState(const api::CallContext &ctx, const pb::GetEmulatorStateRequest &req, pb::GetEmulatorStateResponse &resp);
  api::Status WriteRegisters(const api::CallContext &ctx, const pb::WriteEmulatorRegistersRequest &req, pb::WriteEmulatorRegistersResponse &resp);
  api::Status ReadMemory(const api::CallContext &ctx, const pb::ReadEmulatorMemoryRequest &req, pb::ReadEmulatorMemoryResponse &resp);
  api::Status WriteMemory(const api::CallContext &ctx, const pb::WriteEmulatorMemoryRequest &req, pb::WriteEmulatorMemoryResponse &resp);
  api::Status SetBreakpoints(const api::CallContext &ctx, const pb::SetEmulatorBreakpointsRequest &req, pb::SetEmulatorBreakpointsResponse &resp);
  api::Status GetTrace(const api::CallContext &ctx, const pb::GetEmulatorTraceRequest &req, pb::GetEmulatorTraceResponse &resp);
  api::Status WriteInput(const api::CallContext &ctx, const pb::WriteEmulatorInputRequest &req);
  api::Status GetMachine(const api::CallContext &ctx, const pb::GetEmulatorMachineRequest &req, pb::GetEmulatorMachineResponse &resp);

  void SetMachineSupport(MachineSupport s) { machines_ = std::move(s); }

  struct Session;

 private:
  // The session, locked for the caller's exclusive use.
  // Another caller's session is NOT_FOUND, unless the caller is an admin.
  api::Status Acquire(const api::CallContext &ctx, const std::string &id, std::shared_ptr<Session> &out, std::unique_lock<std::mutex> &lock);
  void Reap();

  EmulatorBounds bounds_;
  MachineSupport machines_;
  std::mutex mu_;
  std::map<std::string, std::shared_ptr<Session>> sessions_;
};

}  // namespace revkit::backend
