// Apple applications (api_minor 100, feature "apple-bundles";
// docs/apple-apps.md and docs/ui.md "Apple bundles"): the bundle view of
// the file system browser (an .ipa, an .app, a framework or an extension:
// what Info.plist says, the main executable and its code signature, the
// bundles inside, the provisioning profile, Interface Builder files, and
// Import main executable / with frameworks and extensions), a property
// list viewer (XML, binary, a provisioning profile's), and a program's
// code signature and entitlements. Signatures are read, never verified,
// and every view says so.

import type {
  AppleBundle, CodeSignature, FileSystemSession, PlistValue, ProvisioningProfile, Revkit, UiAction,
} from "@revkit/api";
import { displayPath } from "@revkit/api";
import { errText } from "../data/format";
import { h, overlayRoot } from "./dom";

export const APPLE_BUNDLES_FEATURE = "apple-bundles";
export const UI_ACTIONS_FEATURE = "ui-actions";

const NOT_VERIFIED = "Read from the file, not verified: no hash, signature or certificate chain is checked.";

/** A plist value's one-line text (scalars) and its type's name. */
function scalar(v: PlistValue): { type: string; text: string } {
  const x = v.value;
  switch (x.case) {
    case "stringValue": return { type: "string", text: x.value };
    case "integerValue": case "unsignedValue": return { type: "integer", text: x.value.toString() };
    case "realValue": return { type: "real", text: String(x.value) };
    case "boolValue": return { type: "boolean", text: x.value ? "true" : "false" };
    case "dateValue": return { type: "date", text: new Date(Number(x.value.seconds) * 1000).toISOString().replace(".000Z", "Z") };
    case "dataValue": {
      const hex = [...x.value.slice(0, 32)].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      return { type: "data", text: `${Number(v.dataSize).toLocaleString("en-US")} bytes${hex ? `: ${hex}${v.dataSize > 32n ? " …" : ""}` : ""}` };
    }
    case "uidValue": return { type: "UID", text: `CF$UID ${x.value}` };
    case "nullValue": return { type: "null", text: "null" };
    case "arrayValue": return { type: "array", text: `${x.value.items.length} item${x.value.items.length === 1 ? "" : "s"}${v.omitted ? ` (+${v.omitted} not shown)` : ""}` };
    case "dictValue": return { type: "dictionary", text: `${x.value.entries.length} key${x.value.entries.length === 1 ? "" : "s"}${v.omitted ? ` (+${v.omitted} not shown)` : ""}` };
    default: return { type: "", text: "" };
  }
}

/** A property list as a tree of <details>: dictionaries and arrays open to `openDepth`. */
export function plistTree(root: PlistValue | undefined, o: { openDepth?: number; testid?: string } = {}): HTMLElement {
  const box = h("div", { class: "ap-plist mono", role: "tree", "data-testid": o.testid ?? "ap-plist" });
  if (!root) return box;
  let budget = 5000;
  const node = (key: string, v: PlistValue, depth: number): HTMLElement => {
    const s = scalar(v);
    const label = [h("span", { class: "ap-key" }, key), h("span", { class: "ap-type dim" }, s.type), h("span", { class: "ap-val", title: s.text }, s.text)];
    const x = v.value;
    const kids: [string, PlistValue][] = x.case === "dictValue" ? x.value.entries.map((e) => [e.key, e.value!])
      : x.case === "arrayValue" ? x.value.items.map((item, i) => [String(i), item]) : [];
    if (x.case !== "dictValue" && x.case !== "arrayValue")
      return h("div", { class: "ap-leaf", role: "treeitem", "data-key": key }, ...label);
    const d = h("details", { class: "ap-node", role: "treeitem", "data-key": key }, h("summary", {}, ...label)) as HTMLDetailsElement;
    d.open = depth < (o.openDepth ?? 1);
    for (const [k, c] of kids) {
      if (--budget < 0) {
        d.append(h("div", { class: "ap-leaf dim" }, "… more not shown"));
        break;
      }
      d.append(node(k, c, depth + 1));
    }
    return d;
  };
  box.append(node("Root", root, 0));
  return box;
}

const plural = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;

function entitlementCount(sig: CodeSignature): number {
  return sig.entitlements?.value.case === "dictValue" ? sig.entitlements.value.value.entries.length : 0;
}

/** One line: "com.example.app · team ABCDE12345 · hardened runtime · 5 entitlements". */
export function signatureSummary(sig: CodeSignature | undefined): string {
  if (!sig || !sig.codeDirectories.length) return sig?.warnings[0] ? `unreadable: ${sig.warnings[0]}` : "not signed";
  const cd = sig.codeDirectories[0];
  const parts = [cd.identifier || "(no identifier)"];
  if (cd.teamId) parts.push(`team ${cd.teamId}`);
  if (sig.adhoc) parts.push("ad hoc");
  if (cd.flagNames.includes("runtime")) parts.push("hardened runtime");
  const n = entitlementCount(sig);
  if (n) parts.push(plural(n, "entitlement"));
  return parts.join(" · ");
}

const fields = (rows: [string, string | Node, string?][]) =>
  h("dl", { class: "bi-fields" }, ...rows.filter(([, v]) => v !== "").flatMap(([k, v, testid]) => [h("dt", {}, k), h("dd", { class: "mono", "data-testid": testid, title: typeof v === "string" ? v : undefined }, v)]));
const section = (title: string, ...body: (Node | null)[]) =>
  h("section", { class: "ap-section" }, h("h3", {}, title), ...body.filter((b): b is Node => !!b));

/** A code signature: its CodeDirectories, requirements, certificates and entitlements. */
export function signatureView(sig: CodeSignature): HTMLElement {
  const cd = sig.codeDirectories[0];
  const out = h("div", { class: "ap-signature", "data-testid": "ap-signature" });
  out.append(h("div", { class: "bi-warn", "data-testid": "ap-not-verified" }, NOT_VERIFIED));
  if (cd) {
    out.append(fields([
      ["Identifier", cd.identifier, "ap-sig-identifier"],
      ["Team", cd.teamId, "ap-sig-team"],
      ["Flags", cd.flagNames.length ? cd.flagNames.join(", ") : "none", "ap-sig-flags"],
      ["Hashes", `${cd.hashType}, ${plural(cd.codeSlots, "page")} of ${cd.pageSize || "the whole file"}${cd.pageSize ? " bytes" : ""}${cd.specialHashes.length ? `; also ${cd.specialHashes.join(", ")}` : ""}`],
      ["CDHash", sig.codeDirectories.map((c) => `${c.cdhash} (${c.hashType}${c.alternate ? ", alternate" : ""})`).join("\n"), "ap-sig-cdhash"],
      ["Executable segment", cd.execSegFlagNames.join(", ")],
      ["Signed by", sig.adhoc ? "ad hoc (no certificate)" : sig.certificates.map((c) => c.commonName || c.subject).join(" ← ") || (sig.hasCms ? "a CMS signature without certificates" : ""), "ap-sig-signer"],
    ]));
  }
  if (sig.requirements.length)
    out.append(section("Requirements", ...sig.requirements.map((r) => h("div", { class: "ap-req mono", "data-testid": "ap-sig-requirement" }, h("span", { class: "dim" }, `${r.typeName} => `), r.text))));
  if (sig.entitlements)
    out.append(section(`Entitlements${sig.hasDerEntitlements ? " (XML and DER)" : ""}`, plistTree(sig.entitlements, { testid: "ap-entitlements" })));
  if (sig.warnings.length) out.append(h("div", { class: "bi-warn" }, sig.warnings.join(" · ")));
  return out;
}

function profileView(path: string, p: ProvisioningProfile): HTMLElement {
  const date = (t?: { seconds: bigint }) => (t ? new Date(Number(t.seconds) * 1000).toISOString().slice(0, 10) : "");
  return section(
    "Provisioning profile",
    fields([
      ["File", displayPath(path)],
      ["Name", p.name, "ap-profile-name"],
      ["Kind", p.kind, "ap-profile-kind"],
      ["App ID", p.applicationIdentifier],
      ["Team", [p.teamName, ...p.teamIdentifiers].filter(Boolean).join(" · ")],
      ["Platforms", p.platforms.join(", ")],
      ["Devices", p.provisionsAllDevices ? "all (enterprise)" : String(p.provisionedDevices)],
      ["Valid", `${date(p.creationDate)} to ${date(p.expirationDate)}`],
      ["Signed by", p.signerCertificates.map((c) => c.commonName).join(" ← ")],
    ]),
    h("div", { class: "bi-warn" }, "The profile's CMS signature is not verified."),
    p.entitlements ? h("details", { class: "bi-details" }, h("summary", {}, "Its entitlements"), plistTree(p.entitlements, { testid: "ap-profile-entitlements" })) : null,
  );
}

function modal(title: string, testid: string, body: HTMLElement, buttons: HTMLElement[] = []) {
  const restore = document.activeElement as HTMLElement | null;
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal bi ap-dialog", role: "dialog", "aria-modal": "true", tabindex: "-1", "aria-label": title, "data-testid": testid },
    h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, title), h("span", { class: "spacer" }), ...buttons,
      h("button", { class: "btn", type: "button", "data-testid": "ap-close", onclick: () => close(), text: "Close" })),
    body,
    h("div", { class: "modal-hint" }, "Esc closes"),
  );
  const backdrop = h("div", { class: "backdrop top" }, box);
  box.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Escape") close();
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });
  overlayRoot().append(backdrop);
  box.focus();
  return { close };
}

/** Property list… : a plist file (XML, binary, a provisioning profile's) as a tree. */
export async function showPropertyListDialog(fs: FileSystemSession, path: string, name: string) {
  const body = h("div", { class: "bi-body", "data-testid": "ap-plist-body" }, h("div", { class: "dim" }, "Reading…"));
  modal(`Property list: ${name}`, "ap-plist-dialog", body);
  try {
    const r = await fs.propertyList(path);
    body.replaceChildren(
      h("div", { class: "dim", "data-testid": "ap-plist-format" },
        `${r.format === "mobileprovision" ? "A provisioning profile's plist (its CMS signature not verified)" : `${r.format === "xml" ? "XML" : "Binary"} property list`}` +
        `${r.keyedArchive ? ", an NSKeyedArchiver archive" : ""} · ${plural(Number(r.values), "value")}${r.truncated ? " (some not shown)" : ""}`),
      plistTree(r.root, { openDepth: 1 }),
    );
  } catch (e) {
    body.replaceChildren(h("div", { class: "error" }, errText(e)));
  }
}

export interface AppleBundleOptions {
  fs: FileSystemSession;
  path: string;
  /** Imports files of the session (the browser's import, with its toast); `libraries`: their frameworks too. */
  importPaths: (paths: string[], libraries: boolean) => Promise<void>;
  /** The daemon traces UI actions (api_minor 101, feature "ui-actions"). */
  uiActions?: boolean;
  /** Opens a program at an address (a UI action's method). */
  openProgram?: (programId: string, address: bigint) => void;
}

/** What an action is sent to: "File's Owner (ViewController)", "First Responder", a class. */
function targetText(a: UiAction): string {
  if (a.target === "files-owner") return `File's Owner${a.targetClass ? ` (${a.targetClass})` : ""}`;
  if (a.target === "first-responder" || a.target === "") return "First Responder";
  return a.targetClass || "an object";
}

/** UI actions: each control's action in the bundle's nibs, and the method it runs. */
async function uiActionsSection(o: AppleBundleOptions, path: string, holder: HTMLElement, done: () => void) {
  holder.replaceChildren(h("h3", {}, "UI actions"), h("div", { class: "dim" }, "Reading the nibs…"));
  try {
    const r = await o.fs.uiActions(path);
    const resolved = r.actions.filter((a) => a.resolution.startsWith("resolved")).length;
    const program = r.programId;
    const method = (a: UiAction): HTMLElement => {
      const imp = a.implementation?.offset;
      if (a.method && imp !== undefined && program && o.openProgram) {
        return h("button", {
          class: "ap-method mono", type: "button", "data-testid": "ap-ui-method", title: `Open ${program} at 0x${imp.toString(16)}${a.resolution === "resolved-by-selector" ? " (the one class implementing it)" : ""}`,
          onclick: () => { done(); o.openProgram!(program, imp); },
        }, a.method + (a.resolution === "resolved-by-selector" ? " (by selector)" : ""));
      }
      const text = a.method ? a.method
        : a.resolution === "ambiguous" ? `ambiguous: ${a.candidates.join(", ")}`
        : a.resolution === "external" ? `${a.targetClass} (not in the program)`
        : a.resolution === "unresolved" ? "no method in the program"
        : "—";
      return h("span", { class: "mono" + (a.method ? "" : " dim"), title: text }, text);
    };
    const parts: (HTMLElement | null)[] = [
      h("h3", { "data-testid": "ap-ui-title" }, `UI actions (${r.actions.length}${program ? `, ${resolved} resolved in ${program.split("/").pop()}` : ""})`),
      !program && r.actions.length ? h("div", { class: "dim", "data-testid": "ap-ui-hint" }, "Import the main executable to trace these to the methods they run.") : null,
      r.actions.length
        ? h("div", { class: "bi-table", "data-testid": "ap-ui-actions" },
          h("div", { class: "bi-row bi-th ap-actions" }, h("span", {}, "Control"), h("span", {}, "Events"), h("span", {}, "Selector"), h("span", {}, "Target"), h("span", {}, "Runs")),
          ...r.actions.map((a) => h("div", { class: "bi-row ap-actions", "data-testid": "ap-ui-action", "data-selector": a.selector, "data-resolution": a.resolution, title: displayPath(a.document) },
            h("span", { title: a.controlClass }, `${a.controlClass}${a.controlLabel ? ` “${a.controlLabel}”` : ""}`),
            h("span", { class: "dim" }, a.events.join(", ") || "action"),
            h("span", { class: "mono" }, a.selector),
            h("span", {}, targetText(a)),
            method(a))))
        : h("div", { class: "dim" }, "No actions in its nibs."),
      r.warnings.length ? h("div", { class: "bi-warn" }, r.warnings.join(" · ")) : null,
    ];
    holder.replaceChildren(...parts.filter((x): x is HTMLElement => !!x));
  } catch (e) {
    holder.replaceChildren(h("h3", {}, "UI actions"), h("div", { class: "error" }, errText(e)));
  }
}

/** Apple bundle… : a bundle's anatomy, with Import main executable. */
export async function showAppleBundleDialog(o: AppleBundleOptions) {
  const body = h("div", { class: "bi-body", "data-testid": "ap-bundle-body" }, h("div", { class: "dim" }, "Reading…"));
  const importMain = h("button", { class: "btn small", type: "button", disabled: true, "data-testid": "ap-import-main", text: "Import main executable", title: "Import it with the frameworks it loads (@rpath, @executable_path, @loader_path inside the bundle)" }) as HTMLButtonElement;
  const importAll = h("button", { class: "btn small", type: "button", disabled: true, "data-testid": "ap-import-all", text: "Import with frameworks and extensions", title: "The main executable and every nested bundle's executable" }) as HTMLButtonElement;
  const dlg = modal("Apple bundle", "ap-bundle-dialog", body, [importMain, importAll]);
  const show = async (path: string) => {
    body.replaceChildren(h("div", { class: "dim" }, "Reading…"));
    try {
      const r = await o.fs.appleBundle(path);
      if (r.bundle) render(r.bundle, r.apps.map((a) => a.path));
    } catch (e) {
      body.replaceChildren(h("div", { class: "error", "data-testid": "ap-bundle-error" }, errText(e)));
    }
  };
  const render = (b: AppleBundle, apps: string[]) => {
    const i = b.info;
    const title = i?.displayName || i?.name || displayPath(b.path).split("/").pop() || b.path;
    const exe = b.executablePath;
    const nestedExes = b.nested.map((n) => n.executablePath).filter(Boolean);
    importMain.disabled = !exe;
    importAll.disabled = !exe;
    importMain.onclick = () => { dlg.close(); void o.importPaths([exe], true); };
    importAll.onclick = () => { dlg.close(); void o.importPaths([exe, ...nestedExes], true); };
    const parts: (Node | null)[] = [
      h("div", { class: "bi-section-head" }, h("h3", { "data-testid": "ap-bundle-title" }, title),
        h("span", { class: "badge mono" }, b.kind), h("span", { class: "dim" }, `${b.platform} · ${b.layout} layout`)),
      fields([
        ["Path", displayPath(b.path), "ap-bundle-path"],
        ["Identifier", i?.identifier ?? "", "ap-bundle-id"],
        ["Version", i ? [i.shortVersion, i.version && i.version !== i.shortVersion ? `(${i.version})` : ""].filter(Boolean).join(" ") : ""],
        ["Minimum OS", i?.minimumOs ?? "", "ap-bundle-minos"],
        ["Devices", i?.deviceFamilies.join(", ") ?? ""],
        ["Executable", exe ? `${displayPath(exe)}${b.executableDetected ? ` · ${b.executableDetected}` : ""}` : "none", "ap-bundle-exe"],
        ["Signature", b.codeSignature ? signatureSummary(b.codeSignature) : "", "ap-bundle-signature"],
        ["URL schemes", i?.urlSchemes.join(", ") ?? "", "ap-bundle-schemes"],
        ["Queries schemes", i?.queriedUrlSchemes.join(", ") ?? ""],
        ["Background modes", i?.backgroundModes.join(", ") ?? "", "ap-bundle-background"],
        ["Extension point", i?.extensionPoint ?? ""],
        ["Principal class", i?.principalClass ?? ""],
        ["Main storyboard", i?.mainStoryboard ?? ""],
        ["Main nib", i?.mainNib ?? ""],
        ["Capabilities", i?.requiredCapabilities.join(", ") ?? ""],
        ["App Transport", i && (i.allowsArbitraryLoads || i.atsExceptionDomains.length) ? `${i.allowsArbitraryLoads ? "arbitrary loads allowed" : "default"}${i.atsExceptionDomains.length ? `; exceptions for ${i.atsExceptionDomains.join(", ")}` : ""}` : ""],
        ["Built with", [i?.sdk, i?.xcode ? `Xcode ${i.xcode}` : "", i?.buildMachineOs].filter(Boolean).join(" · ")],
        ["Other apps", apps.length > 1 ? apps.map(displayPath).join(", ") : ""],
      ]),
    ];
    if (i?.usageDescriptions.length)
      parts.push(section("Privacy usage descriptions", h("div", { class: "bi-table", "data-testid": "ap-usage" },
        ...i.usageDescriptions.map((u) => h("div", { class: "bi-row bi-kv" }, h("span", { class: "mono", title: u.key }, u.key), h("span", {}, u.text))))));
    if (i?.documentTypes.length || i?.exportedTypes.length || i?.importedTypes.length)
      parts.push(section("Documents and types", h("div", { class: "bi-table", "data-testid": "ap-types" },
        ...(i?.documentTypes ?? []).map((d) => h("div", { class: "bi-row bi-kv" }, h("span", {}, `${d.name || "document"} (${d.role || "?"})`), h("span", { class: "mono" }, [...d.contentTypes, ...d.extensions.map((x) => "." + x)].join(", ")))),
        ...(i?.exportedTypes ?? []).map((t) => h("div", { class: "bi-row bi-kv" }, h("span", { class: "mono" }, `exports ${t.identifier}`), h("span", {}, [t.description, t.extensions.map((x) => "." + x).join(" "), t.conformsTo.length ? `conforms to ${t.conformsTo.join(", ")}` : ""].filter(Boolean).join(" · ")))),
        ...(i?.importedTypes ?? []).map((t) => h("div", { class: "bi-row bi-kv" }, h("span", { class: "mono" }, `imports ${t.identifier}`), h("span", {}, [t.description, t.extensions.map((x) => "." + x).join(" ")].filter(Boolean).join(" · ")))))));
    if (b.nested.length)
      parts.push(section(`Bundles inside (${b.nested.length})`, h("div", { class: "bi-table", "data-testid": "ap-nested" },
        h("div", { class: "bi-row bi-th" }, h("span", {}, "Bundle"), h("span", {}, "Role"), h("span", {}, "Identifier"), h("span", {}, "Version")),
        ...b.nested.map((n) => h("div", { class: "bi-row ap-link", "data-testid": "ap-nested-row", "data-path": n.path, role: "button", tabindex: "0", title: `Open ${displayPath(n.path)}`,
          onclick: () => void show(n.path), onkeydown: (e: Event) => { if ((e as KeyboardEvent).key === "Enter") void show(n.path); } },
        h("span", { class: "mono" }, displayPath(n.path).split("/").pop() ?? n.path), h("span", {}, n.role), h("span", { class: "mono" }, n.identifier), h("span", {}, n.version))))));
    if (b.interfaceFiles.length) {
      parts.push(section(`Interface Builder files (${b.interfaceFiles.length})`, h("div", { class: "ap-files mono", "data-testid": "ap-interface-files" }, ...b.interfaceFiles.map((f) => h("div", {}, displayPath(f).slice(displayPath(b.path).length + 1))))));
      if (o.uiActions) {
        const holder = h("section", { class: "ap-section", "data-testid": "ap-ui-section" });
        parts.push(holder);
        void uiActionsSection(o, b.path, holder, () => dlg.close());
      }
    }
    if (b.codeSignature) parts.push(section("Main executable's code signature", signatureView(b.codeSignature)));
    if (b.provisioningProfile) parts.push(profileView(b.provisioningProfilePath, b.provisioningProfile));
    if (b.infoPlist) parts.push(h("details", { class: "bi-details" }, h("summary", {}, `Info.plist (${displayPath(b.infoPlistPath)})`), plistTree(b.infoPlist, { openDepth: 1, testid: "ap-info-plist" })));
    if (b.warnings.length) parts.push(h("div", { class: "bi-warn", "data-testid": "ap-bundle-warnings" }, b.warnings.join(" · ")));
    body.replaceChildren(...parts.filter((p): p is Node => !!p));
  };
  await show(o.path);
}

/** Code signature… of a program (its summary's MachoSummary.codeSignature). */
export async function showCodeSignatureDialog(rk: Revkit, o: { programId: string; programName: string }) {
  const body = h("div", { class: "bi-body", "data-testid": "ap-sig-body" }, h("div", { class: "dim" }, "Reading…"));
  modal(`Code signature of ${o.programName}`, "ap-sig-dialog", body);
  try {
    const s = (await rk.projects.getProgramSummary({ programId: o.programId })).summary;
    const sig = s?.macho?.codeSignature;
    body.replaceChildren(sig ? signatureView(sig) : h("div", { class: "dim", "data-testid": "ap-sig-none" }, s?.macho ? "This Mach-O has no code signature." : "Not a Mach-O program."));
  } catch (e) {
    body.replaceChildren(h("div", { class: "error" }, errText(e)));
  }
}

/** Whether a listing entry is a plist the viewer reads. */
export function isPropertyList(contentKind: string): boolean {
  return contentKind.startsWith("plist:") || contentKind === "keyed-archive" || contentKind === "nib:keyed" || contentKind === "mobileprovision";
}
