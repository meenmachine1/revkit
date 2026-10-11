// Project-wide types and type archives (api_minor 52, feature
// "project-types"; docs/types.md#project-types). Types defined at project
// scope are seen by every program of the project after its own definition
// of a name; an edit there reaches them all. "Move to project" makes a
// program's named types the project's; "Copy to program" gives one program
// its own copy. Type archives (revkit's shipped library archives, Ghidra's
// "ghidra", and archives attached to the project) apply their prototypes
// to every program's imports by name; each can be switched off.
//
//   await moveTypesToProject(rk, programId, ["struct cJSON"], { kind: ProvenanceKind.USER });
//   const archives = await listTypeArchives(rk, programId);
//   await setTypeArchiveEnabled(rk, programId, "ghidra", false, { kind: ProvenanceKind.USER });
import { create } from "@bufbuild/protobuf";

import {
  AppendAssertionsRequestSchema,
  AssertionBodySchema,
  type AppendAssertionsResponse,
  type AssertionBody,
} from "./gen/revkit/v1/assertion_pb";
import type { ProvenanceKind } from "./gen/revkit/v1/common_pb";
import { CopyTypesMode, type CopyTypesResponse, type TypeArchiveInfo } from "./gen/revkit/v1/types_pb";
import type { Revkit } from "./index";

export const PROJECT_TYPES_FEATURE = "project-types";
export const LIBRARY_TYPES_FEATURE = "library-types";

export interface ProvenanceInit {
  kind: ProvenanceKind;
  id?: string;
  session?: string;
  reason?: string;
}

/** Moves named types ("struct cJSON") to project scope with every type they
 * reach (one revision); the program's own definitions are retracted. */
export function moveTypesToProject(rk: Revkit, programId: string, keys: string[], provenance: ProvenanceInit): Promise<CopyTypesResponse> {
  return rk.types.copyTypes({ programId, keys, mode: CopyTypesMode.MOVE_TO_PROJECT, provenance });
}

/** Copies project types into one program and binds their names there. */
export function copyTypesToProgram(rk: Revkit, programId: string, keys: string[], provenance: ProvenanceInit): Promise<CopyTypesResponse> {
  return rk.types.copyTypes({ programId, keys, mode: CopyTypesMode.COPY_TO_PROGRAM, provenance });
}

/** define_type, bind_type_name and type_category bodies at project scope,
 * laid out for `programId`'s data model (one revision). */
export function appendProjectTypes(rk: Revkit, programId: string, bodies: AssertionBody[], provenance: ProvenanceInit): Promise<AppendAssertionsResponse> {
  return rk.assertions.appendAssertions(create(AppendAssertionsRequestSchema, {
    programId,
    assertions: bodies.map((body) => ({ body })),
    provenance,
    projectScope: true,
  }));
}

/** The type archives of the program's project: shipped (`applies` to this
 * program's format and data model), Ghidra's and attached, each enabled or not. */
export async function listTypeArchives(rk: Revkit, programId: string): Promise<TypeArchiveInfo[]> {
  return (await rk.types.listTypeArchives({ programId })).archives;
}

/** The body turning an archive on or off (or attaching one with a header). */
export function typeArchiveBody(setting: { name: string; enabled?: boolean; header?: string; sidecar?: string; detach?: boolean }): AssertionBody {
  return create(AssertionBodySchema, { kind: { case: "typeArchive", value: { enabled: false, ...setting } } });
}

function setting(rk: Revkit, programId: string, body: AssertionBody, provenance: ProvenanceInit) {
  return rk.assertions.appendAssertions(create(AppendAssertionsRequestSchema, { programId, assertions: [{ body }], provenance }));
}

/** Turns an archive ("libc-lp64", "ghidra") on or off for every program of the project. */
export function setTypeArchiveEnabled(rk: Revkit, programId: string, name: string, enabled: boolean,
                                      provenance: ProvenanceInit): Promise<AppendAssertionsResponse> {
  return setting(rk, programId, typeArchiveBody({ name, enabled }), provenance);
}

/** Attaches an archive (a header and, optionally, its sidecar) to the project. */
export function attachTypeArchive(rk: Revkit, programId: string, archive: { name: string; header: string; sidecar?: string; enabled?: boolean },
                                  provenance: ProvenanceInit): Promise<AppendAssertionsResponse> {
  return setting(rk, programId, typeArchiveBody({ enabled: true, ...archive }), provenance);
}

/** Detaches an attached archive (or clears a shipped one's setting: back on). */
export function detachTypeArchive(rk: Revkit, programId: string, name: string, provenance: ProvenanceInit): Promise<AppendAssertionsResponse> {
  return setting(rk, programId, typeArchiveBody({ name, detach: true }), provenance);
}
