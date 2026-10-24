// Who may call what (docs/security.md, "Authorization"): the role each RPC
// needs, the projects a request names, and the identity the server stamps
// on what a caller writes. Both transports enforce it in one place, the
// gRPC handlers, since the HTTP gateway forwards every call through them.
#pragma once

#include "revkit/api/backend.h"
#include "revkit/auth/store.h"
#include "revkit/v1/auth.pb.h"

#include <google/protobuf/message.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::api {

struct MethodPolicy {
  // kNone: callable without credentials.
  auth::Role role = auth::Role::kAdmin;
  // The request names projects (project_id, program_id, a FactKey's
  // program) and a caller restricted to some projects may only name those.
  bool project_scoped = false;
};

// The policy of "revkit.v1.QueryService/Decompile"; nullopt for a method
// that has none, which every caller is refused (fail closed).
std::optional<MethodPolicy> PolicyFor(std::string_view method);

// Every method with a policy, for tests that walk the schema.
std::vector<std::string> MethodsWithPolicy();

// The project ids a request names, from fields called project_id,
// program_id ("project/program") and program_ids, at any depth.
std::vector<std::string> ProjectsNamedBy(const google::protobuf::Message &request);

// Whether a request's string field of this name holds a project
// ("project_id") or a program ("program_id", "program_ids", any
// "*_program_id(s)" such as a crash dump's "dump_program_id", and
// "program_file", a program's stored file): what ProjectsNamedBy collects,
// and what the schema test (AuthPolicyUnit) checks every method for.
enum class NamedField { none, project, program };
NamedField NamedFieldKind(std::string_view field_name);

// Checks a call. `caller` is null for a call without valid credentials;
// with authentication disabled, pass an anonymous admin. Returns
// UNAUTHENTICATED, PERMISSION_DENIED, or OK.
Status Authorize(const auth::Principal *caller, std::string_view method, const google::protobuf::Message &request);

// Puts the caller's identity on provenance it sent:
//   * kind and id empty: filled in (user:<account> or agent:<token name>);
//   * the caller's own kind and id (or its kind with an empty id): kept;
//   * IMPORT, MIGRATION, ANALYSIS or PLUGIN from an admin: kept, for
//     importers such as the Ghidra bridge (docs/ghidra-interop.md);
//   * anything else, such as user:bob from alice or user:alice from an
//     agent token: PERMISSION_DENIED.
// version, session, reason and tool are the client's. An anonymous caller
// (no authentication) is left alone.
Status StampProvenance(const auth::Principal &caller, pb::Provenance &provenance);

// Presence names its client by the server's identity, whatever it said.
void StampPresence(const auth::Principal &caller, pb::Presence &presence);

// The wire form of a caller.
pb::Identity ToIdentity(const auth::Principal &caller);

// An anonymous admin: the caller when authentication is disabled.
auth::Principal AnonymousPrincipal();

}  // namespace revkit::api
