// Load debug file… and Debug files and debuginfod… (feature debug-files;
// docs/backend.md "External debug files"): a stripped ELF's separate debug
// file, from a path on the daemon's host, or (empty) the one its build ID or
// .gnu_debuglink names, found locally and, only when an admin turned it on,
// on debuginfod servers; "another build's" forces a file whose build ID
// differs. The settings (directories, servers, http) are an admin's; the
// daemon's DEBUGINFOD_URLS is only a suggestion shown here.

import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { askMore, toast } from "./dialogs";
import type { PdbHost } from "./pdb";

export async function loadDebugFile(host: PdbHost) {
  let done: { text: string; warn: boolean; revision: bigint } | null = null;
  const r = await askMore({
    title: "Load debug file",
    placeholder: "a .debug file on the daemon's host",
    hint: "Empty: look it up by build ID and debuglink (and on debuginfod servers, when they are on) · Enter to load · Esc to cancel",
    controls: [{ kind: "check", name: "force", label: "Load it even if it is another build's (ignore the build ID)", value: false }],
    check: async (path, controls) => {
      try {
        const res = await host.rk.projects.loadDebugFile({
          programId: host.programId,
          source: path.trim() ? { case: "path", value: path.trim() } : { case: "search", value: true },
          force: controls.force === true,
          provenance: userProvenance("Load debug file"),
        });
        const what = `${res.functions.toLocaleString()} functions, ${res.variables.toLocaleString()} globals, ${res.types.toLocaleString()} types`;
        host.recordUndo("Load debug file", res.assertionSeqs);
        done = {
          text: `Loaded ${res.debugFile.split("/").pop()} (${res.source}): ${what}${res.exact ? "" : " · another build's debug file"}`,
          warn: !res.exact,
          revision: res.snapshot?.revision ?? 0n,
        };
        return null;
      } catch (e) {
        return errText(e);
      }
    },
  });
  if (r === null || !done) return;
  const d = done as { text: string; warn: boolean; revision: bigint };
  await host.settle(d.revision);
  toast(d.text, { kind: d.warn ? "error" : "info", action: { label: "Undo", run: host.undo } });
}

/** "a;b" or "a b" (or one per line) as a list. */
const list = (s: string, sep: RegExp) => s.split(sep).map((x) => x.trim()).filter((x) => x.length > 0);

export async function debugFileSettings(host: PdbHost) {
  let current;
  let suggested: string[] = [];
  try {
    const res = await host.rk.projects.getSymbolSettings({});
    current = res.settings;
    suggested = res.suggestedDebuginfodUrls;
  } catch (e) {
    toast(`Debug file settings: ${errText(e)}`, { kind: "error" });
    return;
  }
  const hint = suggested.length
    ? `The daemon's DEBUGINFOD_URLS suggests ${suggested.join(" ")} (not used unless entered) · Enter to save · Esc to cancel`
    : "Enter to save · Esc to cancel";
  const r = await askMore({
    title: "Debug file directories (searched like /usr/lib/debug; separated by ;)",
    value: (current?.debugDirs ?? []).join(";"),
    placeholder: "/srv/debug;/home/me/debug-files",
    hint,
    extra: { label: "debuginfod servers", value: (current?.debuginfodUrls ?? []).join(" "), placeholder: "https://debuginfod.example.org (space-separated)" },
    controls: [
      { kind: "check", name: "debuginfod", label: "Fetch from debuginfod servers (the daemon contacts them: network access)", value: current?.debuginfod ?? false },
      { kind: "check", name: "http", label: "Allow plain http:// servers (default: https only)", value: current?.debuginfodAllowHttp ?? false },
    ],
    // Saved here, so the daemon's refusal (an http:// server, a relative
    // directory) keeps the dialog open and says why.
    check: async (dirs, controls, urls) => {
      try {
        await host.rk.projects.setSymbolSettings({
          settings: {
            ...current!,
            debugDirs: list(dirs, /;/),
            debuginfodUrls: list(urls, /\s+/),
            debuginfod: controls.debuginfod === true,
            debuginfodAllowHttp: controls.http === true,
          },
        });
        return null;
      } catch (e) {
        return errText(e);
      }
    },
  });
  if (r !== null) toast("Debug file settings saved");
}
