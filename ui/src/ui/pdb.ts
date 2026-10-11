// Load PDB… and Symbol settings… (feature pdb-load; docs/pdb.md): Ghidra's
// Load PDB File on an open program. A path on the daemon's host, or empty
// for the PDB the program's CodeView record names, found on the symbol
// path; "another build's" forces a PDB whose GUID or age differ. The
// symbol settings (path, cache, downloads) are an admin's.

import type { Revkit } from "@revkit/api";
import { userProvenance } from "../api/client";
import { errText } from "../data/format";
import { askMore, toast } from "./dialogs";

export interface PdbHost {
  rk: Revkit;
  programId: string;
  /** Resolves once this tab has the revision (its views refreshed). */
  settle: (revision: bigint) => Promise<void>;
  /** The load as one step on the tab's undo stack. */
  recordUndo: (label: string, seqs: bigint[]) => void;
  undo: () => void;
}

export async function loadPdb(host: PdbHost) {
  let done: { text: string; warn: boolean; revision: bigint } | null = null;
  const r = await askMore({
    title: "Load PDB",
    placeholder: "a .pdb file on the daemon's host",
    hint: "Empty: the program's own PDB, from the symbol path · Enter to load · Esc to cancel",
    controls: [{ kind: "check", name: "force", label: "Load it even if it is another build's (ignore GUID and age)", value: false }],
    check: async (path, controls) => {
      try {
        const res = await host.rk.projects.loadPdb({
          programId: host.programId,
          source: path.trim() ? { case: "path", value: path.trim() } : { case: "symbolPath", value: true },
          force: controls.force === true,
          provenance: userProvenance("Load PDB"),
        });
        const what = `${res.functions.toLocaleString()} functions, ${res.variables.toLocaleString()} globals, ${res.types.toLocaleString()} types`;
        host.recordUndo("Load PDB", res.assertionSeqs);
        done = { text: `Loaded ${res.pdbFile.split(/[\\/]/).pop()} (${res.source}): ${what}${res.exact ? "" : " · another build's PDB"}`, warn: !res.exact, revision: res.snapshot?.revision ?? 0n };
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

export async function symbolSettings(host: PdbHost) {
  let current;
  try {
    current = (await host.rk.projects.getSymbolSettings({})).settings;
  } catch (e) {
    toast(`Symbol settings: ${errText(e)}`, { kind: "error" });
    return;
  }
  const r = await askMore({
    title: "Symbol path (_NT_SYMBOL_PATH syntax)",
    value: current?.symbolPath ?? "",
    placeholder: "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols;/home/me/pdbs",
    extra: { label: "Download cache", value: current?.cacheDir ?? "", placeholder: "where servers' PDBs are kept" },
    controls: [{ kind: "check", name: "downloads", label: "Download from symbol servers (the daemon contacts them: network access)", value: current?.downloads ?? false }],
  });
  if (r === null) return;
  try {
    await host.rk.projects.setSymbolSettings({ settings: { symbolPath: r.value.trim(), downloads: r.controls.downloads === true, cacheDir: r.extra.trim() } });
    toast("Symbol settings saved");
  } catch (e) {
    toast(`Symbol settings: ${errText(e)}`, { kind: "error" });
  }
}
