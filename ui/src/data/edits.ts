// Edits as assertions: every edit (rename, retype, comment, function
// bounds, flow override, note) is an AppendAssertions call with this tab's
// user provenance. Undo appends a retraction (RetractAssertions); redo
// retracts that retraction, which reinstates the original (docs/api.md,
// "Assertions, provenance, blame").

import { create } from "@bufbuild/protobuf";
import { AssertionBodySchema, CommentKind, type CopyTypesMode, EquateScope, FlowOverrideKind, InstructionSet, Mutability, ReferenceType, ScalarFormat, StringEncoding, StringLayout, type AssertionBody, type DefineData, type FactKey, type Provenance, type Revkit, type TypeNode, type TypeNodeRef } from "@revkit/api";
import { userProvenance } from "../api/client";

export type RenameTarget = { case: "address"; address: bigint } | { case: "local"; function: bigint; storageKey: string };

function target(t: RenameTarget) {
  return t.case === "address"
    ? { kind: { case: "address" as const, value: { offset: t.address } } }
    : { kind: { case: "local" as const, value: { function: { offset: t.function }, storageKey: t.storageKey } } };
}

/** A data definition as the UI asks for it: a type (C, or a Ghidra builtin
 * name: byte, word, dword, qword, char, float, double, pointer...), an
 * array count, or a string's encoding and layout. */
export interface DataSpec {
  decl?: string;
  count?: number;
  string?: StringEncoding;
  layout?: StringLayout;
  collapsed?: boolean;
}

/** A scalar an OperandDisplay names: an instruction's operand (by index,
 * or found by its value), or a decompiler constant by its hash. `value` is
 * the 64-bit pattern (ListingToken.value as unsigned, CodeToken.value). */
export interface ScalarRef {
  address: bigint;
  operandIndex?: number;
  value: bigint;
  constantHash?: bigint;
}

/** How a scalar shows: a format, an equate's name, an enum member, or
 * (null) as the disassembler prints it. */
export type ScalarDisplay = { format: ScalarFormat } | { equate: { name: string; enumTypeHash?: string; member?: string } } | null;

/** A user reference (Ghidra's References > Add / Delete / Set primary). */
export interface ReferenceSpec {
  from: bigint;
  /** Unset: the instruction as a whole (Ghidra's mnemonic reference). */
  operandIndex?: number;
  to: bigint;
  type: ReferenceType;
  primary?: boolean;
  remove?: boolean;
}

interface UndoEntry {
  label: string;
  /** Seqs to retract to undo (assertions, or retractions for a redo). */
  seqs: bigint[];
  /** An edit session that adds to this step while it is the newest (recordSession). */
  session?: string;
}

export interface EditResult {
  revision: bigint;
  seqs: bigint[];
  changed: FactKey[];
}

export class Edits {
  private undoStack: UndoEntry[] = [];
  private redoStack: UndoEntry[] = [];
  onChange: (() => void) | null = null;

  constructor(
    private rk: Revkit,
    private programId: string,
  ) {}

  private async append(label: string, bodies: AssertionBody[], reason = "", projectScope = false): Promise<EditResult> {
    const r = await this.rk.assertions.appendAssertions({
      programId: this.programId,
      provenance: userProvenance(reason),
      assertions: bodies.map((body) => ({ body })),
      projectScope,
    });
    const seqs = r.assertions.map((a) => a.seq);
    this.undoStack.push({ label, seqs });
    this.redoStack = [];
    this.onChange?.();
    return { revision: r.snapshot?.revision ?? 0n, seqs, changed: r.changedKeys };
  }

  /**
   * Asks the daemon whether an edit would be accepted (validate_only), so
   * a dialog can show its error and stay open. Resolves to the error
   * message, or null when it is valid.
   */
  async check(body: AssertionBody): Promise<string | null> {
    try {
      await this.rk.assertions.appendAssertions({ programId: this.programId, provenance: userProvenance(), assertions: [{ body }], validateOnly: true });
      return null;
    } catch (e) {
      const m = e && typeof e === "object" && "rawMessage" in e ? String((e as { rawMessage: string }).rawMessage) : String(e);
      return m.replace(/^assertions\[0\]:\s*/, "");
    }
  }

  rename(t: RenameTarget, name: string, label = `Rename to ${name}`): Promise<EditResult> {
    return this.append(label, [Edits.renameBody(t, name)]);
  }

  static renameBody(t: RenameTarget, name: string): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "rename", value: { target: target(t), name } } });
  }

  /** A type as a C declaration (a prototype for a function). */
  static retypeBody(t: RenameTarget, cDeclaration: string): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "retype", value: { target: target(t), type: { kind: { case: "cDeclaration", value: cDeclaration } } } } });
  }

  retype(t: RenameTarget, cDeclaration: string, label = `Set type ${cDeclaration}`): Promise<EditResult> {
    return this.append(label, [Edits.retypeBody(t, cDeclaration)]);
  }

  comment(address: bigint, kind: CommentKind, text: string): Promise<EditResult> {
    const label = text ? "Comment" : "Delete comment";
    return this.append(label, [create(AssertionBodySchema, { kind: { case: "comment", value: { address: { offset: address }, kind, text } } })]);
  }

  static boundsBody(entry: bigint, remove: boolean): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "functionBounds", value: { entry: { offset: entry }, remove } } });
  }

  /** Declares a function at `entry` (its body is what analysis finds), or that none starts there. */
  functionBounds(entry: bigint, remove: boolean, label: string): Promise<EditResult> {
    return this.append(label, [Edits.boundsBody(entry, remove)]);
  }

  static flowBody(address: bigint, kind: FlowOverrideKind): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "flowOverride", value: { address: { offset: address }, kind } } });
  }

  flowOverride(address: bigint, kind: FlowOverrideKind, label: string): Promise<EditResult> {
    return this.append(label, [Edits.flowBody(address, kind)]);
  }

  /** Whether a function returns, as the user says (feature no-return; Ghidra's Set No-Return). */
  static noReturnBody(entry: bigint, noReturn: boolean): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "noReturn", value: { function: { offset: entry }, noReturn } } });
  }

  /** A call's signature override (feature call-signature-override): a C
   * prototype, or "" to remove it (Ghidra's Remove Signature Override). */
  static callSignatureBody(call: bigint, prototype: string): AssertionBody {
    return create(AssertionBodySchema, {
      kind: {
        case: "callSignature",
        value: { call: { offset: call }, signature: prototype ? { kind: { case: "cDeclaration", value: prototype } } : undefined },
      },
    });
  }

  callSignature(call: bigint, prototype: string, label: string): Promise<EditResult> {
    return this.append(label, [Edits.callSignatureBody(call, prototype)]);
  }

  static noteBody(address: bigint, tag: string, text: string): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "note", value: { address: { offset: address }, tag, text } } });
  }

  note(address: bigint, tag: string, text: string): Promise<EditResult> {
    return this.append(text ? `Note ${tag}` : `Clear note ${tag}`, [Edits.noteBody(address, tag, text)]);
  }

  /** Several bodies as one edit (one revision, one undo step). */
  bodies(label: string, bodies: AssertionBody[], reason = ""): Promise<EditResult> {
    return this.append(label, bodies, reason);
  }

  /** Type bodies (define_type, bind_type_name, type_category) at project
   * scope, seen by every program of the project, as one undo step
   * (api_minor 52, feature "project-types"). */
  projectBodies(label: string, bodies: AssertionBody[], reason = ""): Promise<EditResult> {
    return this.append(label, bodies, reason, true);
  }

  /** CopyTypes (move named types to the project, or copy the project's into
   * the program) as one undo step: its assertions and retractions. */
  async copyTypes(label: string, keys: string[], mode: CopyTypesMode): Promise<EditResult> {
    const r = await this.rk.types.copyTypes({ programId: this.programId, keys, mode, provenance: userProvenance() });
    const head = r.snapshot?.revision ?? 0n;
    // The revision's ops: what undo retracts (retracting a move's
    // retractions brings the program's definitions back).
    const seqs = [...r.seqs];
    if (seqs.length) {
      this.undoStack.push({ label, seqs });
      this.redoStack = [];
      this.onChange?.();
    }
    return { revision: head, seqs, changed: [] };
  }

  /** Several bodies as one edit under another provenance (a header import:
   * import:header with its own session), still this tab's undo step. */
  async bodiesAs(label: string, bodies: AssertionBody[], provenance: Provenance): Promise<EditResult> {
    const r = await this.rk.assertions.appendAssertions({ programId: this.programId, provenance, assertions: bodies.map((body) => ({ body })) });
    const seqs = r.assertions.map((a) => a.seq);
    this.undoStack.push({ label, seqs });
    this.redoStack = [];
    this.onChange?.();
    return { revision: r.snapshot?.revision ?? 0n, seqs, changed: r.changedKeys };
  }

  /**
   * Bodies, then retractions of other assertions, as one undo step (two
   * revisions): a type renamed is its new definition and binding, and the
   * old name's binding retracted. Undo retracts all of it, which brings the
   * old binding back.
   */
  async bodiesAndRetract(label: string, bodies: AssertionBody[], retract: bigint[]): Promise<EditResult> {
    const r = await this.rk.assertions.appendAssertions({ programId: this.programId, provenance: userProvenance(), assertions: bodies.map((body) => ({ body })) });
    const seqs = r.assertions.map((a) => a.seq);
    let revision = r.snapshot?.revision ?? 0n;
    const changed = [...r.changedKeys];
    if (retract.length) {
      try {
        const x = await this.rk.assertions.retractAssertions({ programId: this.programId, seqs: retract, provenance: userProvenance() });
        seqs.push(...x.retractions.map((a) => a.seq));
        revision = x.snapshot?.revision ?? revision;
        changed.push(...x.changedKeys);
      } catch (e) {
        // Keep it one step: the new definition goes too.
        await this.rk.assertions.retractAssertions({ programId: this.programId, seqs, provenance: userProvenance("undo") }).catch(() => undefined);
        throw e;
      }
    }
    this.undoStack.push({ label, seqs });
    this.redoStack = [];
    this.onChange?.();
    return { revision, seqs, changed };
  }

  /** The daemon's view of a batch without committing it (validate_only): its keys (a define_type's carries its hash). */
  async validate(bodies: AssertionBody[]): Promise<FactKey[]> {
    const r = await this.rk.assertions.appendAssertions({ programId: this.programId, provenance: userProvenance(), assertions: bodies.map((body) => ({ body })), validateOnly: true });
    return r.assertions.map((a) => a.key!).filter(Boolean);
  }

  /** Assertions made elsewhere on this tab's behalf (a plugin command): undoable like its own. */
  record(label: string, seqs: bigint[]) {
    if (!seqs.length) return;
    this.undoStack.push({ label, seqs });
    this.redoStack = [];
    this.onChange?.();
  }

  /**
   * Records writes of an edit session (the byte viewer's typing) as one
   * undo step: added to the newest step while it is this session's, else a
   * new step. True when a new step was started.
   */
  recordSession(session: string, label: string, seqs: bigint[]): boolean {
    if (!seqs.length) return false;
    const top = this.undoStack.at(-1);
    this.redoStack = [];
    if (top?.session === session) {
      top.seqs.push(...seqs);
      top.label = label;
      this.onChange?.();
      return false;
    }
    this.undoStack.push({ label, seqs: [...seqs], session });
    this.onChange?.();
    return true;
  }

  /** Whether the newest undo step is this session's (its writes still add to it). */
  sessionOnTop(session: string): boolean {
    return this.undoStack.at(-1)?.session === session;
  }

  static defineTypeBody(type: TypeNode): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "defineType", value: { type } } });
  }

  static bindTypeBody(ref: TypeNodeRef): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "bindTypeName", value: { type: ref } } });
  }

  /** A type by hash (one the program has, or one this request defines first). */
  static retypeHashBody(t: RenameTarget, hash: string): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "retype", value: { target: target(t), type: { kind: { case: "typeHash", value: hash } } } } });
  }

  // Listing edits (feature listing-edit, docs/listing-edit.md): what bytes are.

  /** Clear: [address, address + length) become undefined bytes. */
  static clearBody(address: bigint, length: bigint): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "listingEdit", value: { address: { offset: address }, kind: { case: "clear", value: { length } } } } });
  }

  /** Disassemble here: code starts at the address (optionally a function too). */
  static disassembleBody(address: bigint, instructionSet: InstructionSet = InstructionSet.UNSPECIFIED, fn = false): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "listingEdit", value: { address: { offset: address }, kind: { case: "disassemble", value: { instructionSet, function: fn } } } } });
  }

  /** Define data: a typed item, an array of `count` of them, or a string. */
  static defineDataBody(address: bigint, data: DataSpec | DefineData): AssertionBody {
    const value =
      "$typeName" in data
        ? data
        : {
            type: data.decl ? { kind: { case: "cDeclaration" as const, value: data.decl } } : undefined,
            count: BigInt(data.count ?? 0),
            string: data.string ?? StringEncoding.UNSPECIFIED,
            layout: data.layout ?? StringLayout.UNSPECIFIED,
            collapsed: data.collapsed,
          };
    return create(AssertionBodySchema, { kind: { case: "listingEdit", value: { address: { offset: address }, kind: { case: "data", value } } } });
  }

  /** Constant, volatile, writable or back to the memory map's say, by range. */
  static mutabilityBody(address: bigint, length: bigint, mutability: Mutability): AssertionBody {
    return create(AssertionBodySchema, { kind: { case: "mutability", value: { address: { offset: address }, length, mutability } } });
  }

  // Equates and user references (features equates, user-references).

  /** How a scalar shows (Convert, Set Equate, Remove Equate), here or on
   * every operand holding its value in the function or program. */
  static operandDisplayBody(r: ScalarRef, display: ScalarDisplay, applyTo: EquateScope = EquateScope.UNSPECIFIED): AssertionBody {
    const shown =
      display === null
        ? { case: "format" as const, value: ScalarFormat.UNSPECIFIED }
        : "format" in display
          ? { case: "format" as const, value: display.format }
          : { case: "equate" as const, value: { name: display.equate.name, enumTypeHash: display.equate.enumTypeHash ?? "", member: display.equate.member ?? "" } };
    return create(AssertionBodySchema, {
      kind: {
        case: "operandDisplay",
        value: { address: { offset: r.address }, operandIndex: r.operandIndex, value: BigInt.asUintN(64, r.value), display: shown, constantHash: r.constantHash ?? 0n, applyTo },
      },
    });
  }

  /** A reference from an instruction (or one of its operands), or its removal. */
  static referenceBody(r: ReferenceSpec): AssertionBody {
    return create(AssertionBodySchema, {
      kind: { case: "reference", value: { from: { offset: r.from }, operandIndex: r.operandIndex, to: { offset: r.to }, type: r.type, primary: !!r.primary, remove: !!r.remove } },
    });
  }

  /** Retracts specific assertions (the provenance badge's undo). */
  async retract(seqs: bigint[], label = "Retract"): Promise<EditResult> {
    const r = await this.rk.assertions.retractAssertions({ programId: this.programId, seqs, provenance: userProvenance("undo") });
    const out = r.retractions.map((a) => a.seq);
    this.undoStack.push({ label: `${label} (retraction)`, seqs: out });
    this.redoStack = [];
    this.onChange?.();
    return { revision: r.snapshot?.revision ?? 0n, seqs: out, changed: r.changedKeys };
  }

  get canUndo() {
    return this.undoStack.length > 0;
  }
  get canRedo() {
    return this.redoStack.length > 0;
  }
  get undoLabel() {
    return this.undoStack.at(-1)?.label;
  }
  get redoLabel() {
    return this.redoStack.at(-1)?.label;
  }

  /** Retracts this tab's most recent edit. */
  async undo(): Promise<{ label: string; result: EditResult } | null> {
    const e = this.undoStack.pop();
    if (!e) return null;
    try {
      const r = await this.rk.assertions.retractAssertions({ programId: this.programId, seqs: e.seqs, provenance: userProvenance("undo") });
      const seqs = r.retractions.map((a) => a.seq);
      this.redoStack.push({ label: e.label, seqs });
      this.onChange?.();
      return { label: e.label, result: { revision: r.snapshot?.revision ?? 0n, seqs, changed: r.changedKeys } };
    } catch (err) {
      this.undoStack.push(e);
      throw err;
    }
  }

  /** Retracts the last undo's retractions, reinstating the edit. */
  async redo(): Promise<{ label: string; result: EditResult } | null> {
    const e = this.redoStack.pop();
    if (!e) return null;
    try {
      const r = await this.rk.assertions.retractAssertions({ programId: this.programId, seqs: e.seqs, provenance: userProvenance("redo") });
      const seqs = r.retractions.map((a) => a.seq);
      this.undoStack.push({ label: e.label, seqs });
      this.onChange?.();
      return { label: e.label, result: { revision: r.snapshot?.revision ?? 0n, seqs, changed: r.changedKeys } };
    } catch (err) {
      this.redoStack.push(e);
      throw err;
    }
  }
}
