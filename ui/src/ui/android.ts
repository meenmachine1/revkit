// Android packages (api_minor 98, feature "android"; docs/android.md and
// docs/ui.md "Android packages"): an APK in the file system browser, from
// its context menu (Android package…) or the browser's Android… button
// when the file system is one. Tabs:
//
//   Manifest   the package, versions and SDK levels, the application's
//              flags (debuggable, allowBackup, cleartext traffic, the
//              network security config, which Show decodes), permissions
//              and the components with their exported flags and intent
//              filters;
//   XML        AndroidManifest.xml as text, references named or resolved;
//   Resources  resources.arsc's entries by type and configuration, filtered
//              (the strings table first);
//   Native     the libraries by ABI with their JNI exports and JNI_OnLoad,
//              Import (with the libraries they need from the same
//              directory), and the DEX's native methods with the library
//              exporting each;
//   Flutter    the Dart snapshot hash, its features and the engine's build
//              ID per ABI (when the package is a Flutter app).

import { encodeName, type AndroidComponent, type AndroidPackage, type FileSystemSession, type Revkit } from "@revkit/api";
import { errText } from "../data/format";
import { toast } from "./dialogs";
import { h, overlayRoot } from "./dom";

export const ANDROID_FEATURE = "android";

type Tab = "manifest" | "xml" | "resources" | "native" | "flutter";

export interface AndroidDialogOptions {
  rk: Revkit;
  fs: FileSystemSession;
  /** The APK's session path ("" when the file system is one). */
  path: string;
  name: string;
  /** Imports these session paths with the libraries they need. */
  importPaths?: (paths: string[]) => Promise<void>;
}

const yesNo = (v: boolean | undefined, dflt: string) => (v === undefined ? `not set (${dflt})` : v ? "true" : "false");

function bytes(n: bigint | number): string {
  const v = Number(n);
  if (v < 1024) return `${v} B`;
  if (v < 1 << 20) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1 << 20)).toFixed(1)} MB`;
}

function filterText(c: AndroidComponent): string {
  return c.intentFilters
    .map((f) => {
      const data = f.data.map((d) => `${d.scheme ? d.scheme + "://" : ""}${d.host}${d.port ? ":" + d.port : ""}${d.path || d.pathPrefix || d.pathPattern}${d.mimeType ? ` (${d.mimeType})` : ""}`);
      return [...f.actions.map((a) => a.replace(/^android\.intent\.action\./, "")), ...data].join(", ");
    })
    .join(" · ");
}

export function showAndroidDialog(o: AndroidDialogOptions) {
  const restore = document.activeElement as HTMLElement | null;
  let tab: Tab = "manifest";
  let pkg: AndroidPackage | null = null;
  const body = h("div", { class: "bi-body and-body", "data-testid": "and-body" }, h("div", { class: "dim" }, "Reading the package…"));
  const tabs = h("div", { class: "and-tabs", role: "tablist" });
  const close = () => {
    backdrop.remove();
    restore?.focus({ preventScroll: true });
  };
  const box = h(
    "div",
    { class: "modal bi and", role: "dialog", tabindex: "-1", "aria-label": `Android package ${o.name}`, "data-testid": "and-dialog" },
    h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, `Android package: ${o.name}`), h("span", { class: "spacer" }), tabs,
      h("button", { class: "btn", type: "button", "data-testid": "and-close", onclick: close, text: "Close" })),
    body,
    h("div", { class: "modal-hint" }, "From AndroidManifest.xml, resources.arsc, classes*.dex and lib/<abi>/*.so, read in the daemon · Esc closes"),
  );
  const backdrop = h("div", { class: "backdrop top" }, box);
  box.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      close();
    }
  });
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });

  const fields = (rows: [string, string | Node, string?][]) =>
    h("dl", { class: "bi-fields" }, ...rows.filter(([, v]) => v !== "").flatMap(([k, v, testid]) => [h("dt", {}, k), h("dd", { class: "mono", "data-testid": testid }, v)]));
  const table = (testid: string, head: string[], rows: HTMLElement[], cls: string) =>
    h("div", { class: "bi-table", role: "table", "data-testid": testid }, h("div", { class: `bi-row bi-th ${cls}`, role: "row" }, ...head.map((c) => h("span", { role: "columnheader" }, c))), ...rows);
  const cell = (text: string, cls = "mono") => h("span", { class: cls, role: "cell", title: text }, text);
  const section = (title: string, ...rest: (Node | null)[]) => h("div", { class: "and-section" }, h("div", { class: "bi-section-head" }, h("h3", {}, title)), ...rest.filter((n): n is Node => !!n));

  const showXml = async (path: string, title: string) => {
    const pre = h("pre", { class: "and-xml", "data-testid": "and-xml-file" }, "Decoding…");
    const sub = h("div", { class: "modal bi", role: "dialog", tabindex: "-1", "aria-label": title },
      h("div", { class: "libs-head" }, h("div", { class: "modal-title" }, title), h("span", { class: "spacer" }), h("button", { class: "btn", onclick: () => sb.remove(), text: "Close" })), pre);
    const sb = h("div", { class: "backdrop top" }, sub);
    sub.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        sb.remove();
      }
    });
    overlayRoot().append(sb);
    sub.focus();
    try {
      pre.textContent = await o.fs.androidXml(path);
    } catch (e) {
      pre.textContent = errText(e);
    }
  };

  const member = (p: string) => (pkg?.path ?? "") + "/" + p.split("/").map(encodeName).join("/");

  const manifestTab = (p: AndroidPackage): HTMLElement[] => {
    const m = p.manifest;
    if (!p.manifestPresent || !m) return [h("div", { class: "bi-warn" }, "No AndroidManifest.xml could be read.")];
    const sdk = [m.minSdk !== undefined ? `min ${m.minSdk}` : "", m.targetSdk !== undefined ? `target ${m.targetSdk}` : "", m.compileSdk !== undefined ? `compile ${m.compileSdk}${m.compileSdkCodename && m.compileSdkCodename !== String(m.compileSdk) ? ` (${m.compileSdkCodename})` : ""}` : "", m.maxSdk !== undefined ? `max ${m.maxSdk}` : ""].filter(Boolean).join(" · ");
    const nsc = m.networkSecurityConfig
      ? h("span", {}, m.networkSecurityConfig, m.networkSecurityConfigFile ? h("button", { class: "btn small and-inline", "data-testid": "and-nsc-show", onclick: () => void showXml(member(m.networkSecurityConfigFile), m.networkSecurityConfigFile), text: "Show" }) : null)
      : "";
    const cleartextDefault = (m.targetSdk ?? 0) >= 28 ? "false from API 28" : "true below API 28";
    const flag = (v: boolean | undefined, dflt: string, risky: boolean) => {
      const text = yesNo(v, dflt);
      return risky ? h("span", { class: "and-risk" }, text) : text;
    };
    const out: HTMLElement[] = [
      fields([
        ["Package", m.package, "and-package"],
        ["Version", `${m.versionName || "—"}${m.versionCode !== undefined ? ` (code ${m.versionCode})` : ""}`, "and-version"],
        ["SDK", sdk || "—", "and-sdk"],
        ["Application", m.applicationClass || "—", "and-app-class"],
        ["Label", m.label],
        ["Debuggable", flag(m.debuggable, "false", m.debuggable === true), "and-debuggable"],
        ["Allow backup", flag(m.allowBackup, "true", m.allowBackup !== false), "and-allow-backup"],
        ["Cleartext traffic", flag(m.usesCleartextTraffic, cleartextDefault, m.usesCleartextTraffic === true), "and-cleartext"],
        ["Network security config", nsc, "and-nsc"],
        ["Extract native libs", m.extractNativeLibs === undefined ? "" : String(m.extractNativeLibs)],
        ["Test only", m.testOnly ? "true" : ""],
        ["Shared user id", m.sharedUserId],
        ["Component factory", m.appComponentFactory],
      ]),
    ];
    if (m.usesPermissions.length || m.permissions.length)
      out.push(section(`Permissions (${m.usesPermissions.length} used, ${m.permissions.length} declared)`,
        table("and-permissions", ["Permission", "Note"], [
          ...m.usesPermissions.map((x) => h("div", { class: "bi-row bi-kv", role: "row", "data-testid": "and-permission" }, cell(x.name), cell(x.maxSdk !== undefined ? `up to API ${x.maxSdk}` : "", "dim"))),
          ...m.permissions.map((x) => h("div", { class: "bi-row bi-kv", role: "row" }, cell(x.name), cell(`declared · ${x.protectionLevel}`, "dim"))),
        ], "bi-kv")));
    const exported = m.components.filter((c) => c.exported).length;
    out.push(section(`Components (${m.components.length}, ${exported} exported)`,
      table("and-components", ["Kind", "Name", "Exported", "Permission", "Intent filters"], m.components.map((c) =>
        h("div", { class: "bi-row and-comp", role: "row", "data-testid": "and-component", "data-name": c.name },
          cell(c.kind + (c.launcher ? " ★" : ""), "dim"), cell(c.name),
          cell(c.exported ? (c.exportedExplicit ? "yes" : "yes (implied)") : "no", c.exported && !c.permission ? "and-risk" : "dim"),
          cell(c.permission || c.readPermission || "—", c.permission ? "mono" : "dim"),
          cell(filterText(c) || (c.authorities ? `authorities ${c.authorities}` : "—"), "mono dim"))), "and-comp")));
    if (m.metaData && Object.keys(m.metaData).length)
      out.push(section("Meta-data", table("and-meta", ["Name", "Value"], Object.entries(m.metaData).map(([k, v]) => h("div", { class: "bi-row bi-kv", role: "row" }, cell(k), cell(v))), "bi-kv")));
    return out;
  };

  const xmlTab = (p: AndroidPackage): HTMLElement[] => {
    let resolved = false;
    const pre = h("pre", { class: "and-xml", "data-testid": "and-manifest-xml" }, p.manifestXml);
    const toggle = h("label", { class: "and-check" }, h("input", { type: "checkbox", "data-testid": "and-resolve", onchange: (e: Event) => {
      resolved = (e.target as HTMLInputElement).checked;
      pre.textContent = resolved ? p.manifestXmlResolved : p.manifestXml;
    } }), " Resolve references");
    const copy = h("button", { class: "btn small", onclick: () => void navigator.clipboard?.writeText(pre.textContent ?? "").then(() => toast("Copied the manifest")), text: "Copy" });
    return [h("div", { class: "bi-section-head" }, toggle, copy), pre];
  };

  const resourcesTab = (p: AndroidPackage): HTMLElement[] => {
    if (!p.resources?.present) return [h("div", { class: "dim" }, "The package has no resources.arsc.")];
    const types = p.resources.packages.flatMap((x) => x.types.map((t) => t.name));
    const typeSel = h("select", { "data-testid": "and-res-type", "aria-label": "Type" }, h("option", { value: "" }, "every type"), ...[...new Set(types)].map((t) => h("option", { value: t, selected: t === "string" }, t))) as HTMLSelectElement;
    const configSel = h("select", { "data-testid": "and-res-config", "aria-label": "Configuration" }) as HTMLSelectElement;
    const q = h("input", { class: "filter", spellcheck: "false", placeholder: "Name or value", "aria-label": "Filter resources", "data-testid": "and-res-filter" }) as HTMLInputElement;
    const list = h("div", { class: "and-res" });
    const count = h("span", { class: "dim", "data-testid": "and-res-count" });
    let seq = 0;
    const load = async () => {
      const my = ++seq;
      try {
        const r = await o.fs.androidResources(p.path, { type: typeSel.value, config: configSel.value, query: q.value, limit: 1000 });
        if (my !== seq) return;
        const keep = configSel.value;
        configSel.replaceChildren(h("option", { value: "*", selected: keep === "*" }, "every configuration"), ...r.configs.map((c) => h("option", { value: c, selected: c === keep }, c || "default")));
        if (!configSel.value) configSel.value = keep;
        count.textContent = `${r.total.toLocaleString("en-US")} entr${r.total === 1 ? "y" : "ies"}${r.total > r.entries.length ? ` (first ${r.entries.length})` : ""}`;
        list.replaceChildren(table("and-resources", ["Name", "Config", "Value"], r.entries.map((e) =>
          h("div", { class: "bi-row and-resrow", role: "row", "data-testid": "and-resource", "data-name": e.name },
            cell(e.name), cell(e.config || "default", "dim"),
            cell(e.valueType === "bag" ? `${e.parent ? `parent ${e.parent} · ` : ""}${e.items.join(" · ")}` : e.value + (e.reference ? `  (${e.reference})` : "")))), "and-resrow"));
      } catch (err) {
        list.replaceChildren(h("div", { class: "error" }, errText(err)));
      }
    };
    configSel.value = "";
    typeSel.addEventListener("change", () => void load());
    configSel.addEventListener("change", () => void load());
    let t = 0;
    q.addEventListener("input", () => {
      clearTimeout(t);
      t = window.setTimeout(() => void load(), 200);
    });
    void load();
    const summary = `${p.resources.values.toLocaleString("en-US")} values in ${p.resources.packages.map((x) => `${x.name} (0x${x.id.toString(16)})`).join(", ")}`;
    return [h("div", { class: "bi-section-head and-res-head" }, typeSel, configSel, q, count), h("div", { class: "dim" }, summary), list];
  };

  const nativeTab = (p: AndroidPackage): HTMLElement[] => {
    const out: HTMLElement[] = [];
    if (!p.nativeLibraries.length) out.push(h("div", { class: "dim" }, "No native libraries (lib/<abi>/*.so)."));
    for (const abi of p.abis) {
      const libs = p.nativeLibraries.filter((l) => l.abi === abi);
      const importAll = o.importPaths
        ? h("button", { class: "btn small", "data-testid": `and-import-${abi}`, title: "Import every library of this ABI, linked to each other", onclick: () => void o.importPaths!(libs.map((l) => l.path)), text: `Import ${abi}` })
        : null;
      out.push(h("div", { class: "and-section" },
        h("div", { class: "bi-section-head" }, h("h3", {}, `${abi} (${libs.length})`), importAll),
        table("and-libs", ["Library", "Machine", "Size", "Exports", "JNI"], libs.map((l) => {
          const jni = [l.jniExports.length ? `${l.jniExports.length} Java_` : "", l.jniOnload ? "JNI_OnLoad" : "", l.flutter ? `Flutter ${l.flutter}` : ""].filter(Boolean).join(" · ");
          const name = o.importPaths
            ? h("button", { class: "link mono", title: `Import ${l.name} (and the libraries it needs)`, "data-testid": "and-lib-import", onclick: () => void o.importPaths!([l.path]) }, l.name)
            : cell(l.name);
          const row = h("div", { class: "bi-row and-lib", role: "row", "data-testid": "and-lib", "data-name": l.name, title: [l.soname && `soname ${l.soname}`, l.needed.length && `needs ${l.needed.join(", ")}`, l.buildId && `build id ${l.buildId}`, l.error].filter(Boolean).join("\n") },
            name, cell(l.machine || "?", "dim"), cell(bytes(l.size), "dim"), cell(String(l.exports), "dim"), cell(jni || "—", jni ? "mono" : "dim"));
          return row;
        }), "and-lib")));
    }
    if (p.nativeMethods.length) {
      const linked = p.nativeMethods.filter((m) => m.libraries.length).length;
      out.push(section(`Native methods (${p.nativeMethods.length}, ${linked} found in a library)`,
        table("and-methods", ["Method", "JNI name", "Library"], p.nativeMethods.map((m) =>
          h("div", { class: "bi-row and-method", role: "row", "data-testid": "and-method" },
            cell(`${m.className}.${m.method}${m.signature}`), cell(m.libraries.length ? m.jniName : m.jniName, "mono dim"),
            cell(m.libraries.length ? m.libraries.map((x) => x.replace(/^.*\/lib\//, "lib/")).join(", ") : "registered at run time (RegisterNatives), or elsewhere", m.libraries.length ? "mono" : "dim"))), "and-method")));
    }
    if (p.dexFiles.length) out.push(h("div", { class: "dim" }, p.dexFiles.map((d) => `${d.path.replace(/^.*!\//, "").replace(/^\//, "")}: DEX ${d.version}, ${d.classes.toLocaleString("en-US")} classes, ${d.methods.toLocaleString("en-US")} methods`).join(" · ")));
    return out;
  };

  const flutterTab = (p: AndroidPackage): HTMLElement[] => {
    const f = p.flutter!;
    return [
      fields([["Dart snapshot hash", f.snapshotHash || "the ABIs disagree (below)", "and-flutter-hash"]]),
      h("div", { class: "dim" }, "The hash names the Dart SDK release that built the snapshot; revkit has no table of them."),
      ...f.abis.map((a) => section(a.abi, fields([
        ["Snapshot hash", a.snapshotHash || (a.hashCandidates.length ? a.hashCandidates.join(", ") : "—")],
        ["Features", a.features],
        ["Kind", a.snapshots.filter((s) => s.header).map((s) => `${s.symbol.replace(/^_kDart/, "")}: ${s.kindName}`).join(" · ")],
        ["Engine build ID", a.engineBuildId || "—", `and-flutter-build-${a.abi}`],
        ["Dart version", a.dartVersion],
        ["Toolchain", a.toolchain.join("\n")],
        ["Warnings", a.warnings.join(" · ")],
      ]))),
    ];
  };

  const render = () => {
    if (!pkg) return;
    const p = pkg;
    const list: [Tab, string][] = [["manifest", "Manifest"], ["xml", "XML"], ["resources", "Resources"], ["native", "Native"]];
    if (p.flutter?.detected) list.push(["flutter", "Flutter"]);
    tabs.replaceChildren(...list.map(([k, label]) => h("button", { class: "btn seg" + (tab === k ? " on" : ""), role: "tab", "aria-selected": String(tab === k), "data-testid": `and-tab-${k}`, onclick: () => {
      tab = k;
      render();
    } }, label)));
    const parts = tab === "manifest" ? manifestTab(p) : tab === "xml" ? xmlTab(p) : tab === "resources" ? resourcesTab(p) : tab === "native" ? nativeTab(p) : flutterTab(p);
    if (tab === "manifest" && p.warnings.length) parts.push(h("details", { class: "bi-details" }, h("summary", {}, `Warnings (${p.warnings.length})`), h("div", { class: "bi-warn" }, p.warnings.join("\n"))));
    body.replaceChildren(...parts);
  };

  overlayRoot().append(backdrop);
  box.focus();
  void (async () => {
    try {
      pkg = await o.fs.androidPackage(o.path);
      render();
    } catch (e) {
      body.replaceChildren(h("div", { class: "error", "data-testid": "and-error" }, errText(e)));
    }
  })();
}
