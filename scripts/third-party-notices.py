#!/usr/bin/env python3
"""Regenerates the generated sections of THIRD_PARTY_NOTICES.md, and
optionally gathers every third-party license text into a directory (the
packages' share/doc/revkit/licenses).

Sections, each between <!-- BEGIN GENERATED: name --> and
<!-- END GENERATED: name --> markers:

  npm      the web UI's runtime dependencies (bundled into ui/dist), from
           `npm ls --omit=dev` in ui/ (needs ui/node_modules: npm ci)
  python   what `pip install revkit[mcp]` brings in, from a venv that has
           the wheel installed (--python-venv; default: a temporary venv
           where the wheel from sdk/python is installed)
  tauri    the Rust crates compiled into the desktop shell, from
           `cargo metadata` on ui/tauri/src-tauri (normal dependencies only)
  wasmtime the Rust crates statically linked into libwasmtime.a (the
           plugin host), from `cargo metadata` on the wasmtime source of the
           pinned version (--wasmtime-src DIR; skipped without it)

Usage:
  scripts/third-party-notices.py [--sections npm,python,tauri,wasmtime]
      [--python-venv DIR] [--wasmtime-src DIR] [--licenses-dir OUT] [--check]

--check exits 1 if THIRD_PARTY_NOTICES.md would change (the sections
that could be generated here). --licenses-dir copies the license files of
the npm, Python and Rust packages it lists into OUT/<ecosystem>/<name>.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
LICENSE_NAMES = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|UNLICENSE)([-._].*)?$", re.I)


def table(rows: list[tuple[str, str, str]], head=("Package", "Version", "License")) -> str:
    out = [f"| {head[0]} | {head[1]} | {head[2]} |", "| --- | --- | --- |"]
    out += [f"| {n} | {v} | {l} |" for n, v, l in sorted(set(rows), key=lambda r: (r[0].lower(), r[1]))]
    return "\n".join(out)


def license_files(d: Path) -> list[Path]:
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and LICENSE_NAMES.match(p.name))


def copy_licenses(dest: Path | None, kind: str, name: str, files: list[Path]) -> None:
    if dest is None or not files:
        return
    target = dest / kind / name.replace("/", "__")
    target.mkdir(parents=True, exist_ok=True)
    for f in files:
        shutil.copyfile(f, target / f.name)


# --------------------------------------------------------------------- npm --
def npm_section(dest: Path | None) -> str:
    ui = ROOT / "ui"
    if not (ui / "node_modules").is_dir():
        raise SystemExit("ui/node_modules missing: (cd ui && npm ci)")
    r = subprocess.run(["npm", "ls", "--omit=dev", "--all", "--parseable"], cwd=ui, capture_output=True, text=True)
    rows = []
    for line in r.stdout.splitlines()[1:]:
        pkg = Path(line)
        meta = json.loads((pkg / "package.json").read_text())
        lic = meta.get("license") or "see package"
        if isinstance(lic, dict):
            lic = lic.get("type", "see package")
        rows.append((meta["name"], meta["version"], lic))
        copy_licenses(dest, "npm", meta["name"], license_files(pkg))
    return (
        "Bundled (minified) into the web UI, `ui/dist` (`share/revkit/ui` in a package), and so into the\n"
        "desktop app. Generated from `npm ls --omit=dev` in `ui/`; license texts are in\n"
        "`share/doc/revkit/licenses/npm/`. elkjs is dual-licensed; revkit uses it under EPL-2.0, unmodified\n"
        "(source: https://github.com/kieler/elkjs). The JetBrains Mono font is under the SIL Open Font\n"
        "License 1.1.\n\n" + table(rows)
    )


# ------------------------------------------------------------------ python --
def python_section(venv: Path | None, dest: Path | None) -> str:
    tmp = None
    if venv is None:
        tmp = tempfile.TemporaryDirectory(prefix="rk-notices-")
        venv = Path(tmp.name) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        subprocess.run([str(venv / "bin/pip"), "install", "-q", f"{ROOT / 'sdk/python'}[mcp]"], check=True)
    code = r"""
import json, importlib.metadata as m
out = []
for d in m.distributions():
    md = d.metadata
    lic = md.get("License-Expression") or ""
    if not lic:
        cls = [c.split(" :: ")[-1] for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
        if cls:
            lic = " OR ".join(cls)
        elif md.get("License"):
            lic = md.get("License").strip().splitlines()[0][:60]
    files = [str(d.locate_file(f)) for f in (d.files or []) if "licen" in str(f).lower() or "copying" in str(f).lower() or str(f).lower().endswith("notice")]
    out.append({"name": md["Name"], "version": md["Version"], "license": lic or "see package", "files": files})
print(json.dumps(out))
"""
    r = subprocess.run([str(venv / "bin/python"), "-c", code], capture_output=True, text=True, check=True)
    rows = []
    for d in json.loads(r.stdout):
        if d["name"].lower() in ("pip", "setuptools", "wheel", "revkit"):
            continue
        rows.append((d["name"], d["version"], d["license"]))
        copy_licenses(dest, "python", d["name"], [Path(f) for f in d["files"] if Path(f).is_file()])
    if tmp:
        tmp.cleanup()
    return (
        "Not shipped by revkit: `pip install revkit` (the Python SDK wheel) installs `grpcio` and\n"
        "`protobuf`; the `mcp` extra adds the MCP server's dependencies below. Generated from a fresh venv\n"
        "with `revkit[mcp]` installed.\n\n" + table(rows)
    )


# ------------------------------------------------------------------- cargo --
def cargo_closure(manifest: Path, roots: set[str], dest: Path | None, kind: str) -> list[tuple[str, str, str]]:
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    r = subprocess.run(
        [cargo, "metadata", "--format-version", "1", "--manifest-path", str(manifest),
         "--filter-platform", "x86_64-unknown-linux-gnu"],
        capture_output=True, text=True, check=True)
    meta = json.loads(r.stdout)
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    todo = [i for i, p in pkgs.items() if p["name"] in roots]
    seen = set()
    while todo:
        i = todo.pop()
        if i in seen:
            continue
        seen.add(i)
        for dep in nodes[i]["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]):  # normal dependencies only
                todo.append(dep["pkg"])
    rows = []
    for i in seen:
        p = pkgs[i]
        if p["name"] in roots:
            continue
        rows.append((p["name"], p["version"], p.get("license") or "see crate"))
        copy_licenses(dest, kind, f'{p["name"]}-{p["version"]}', license_files(Path(p["manifest_path"]).parent))
    return rows


def tauri_section(dest: Path | None) -> str:
    rows = cargo_closure(ROOT / "ui/tauri/src-tauri/Cargo.toml", {"revkit-shell"}, dest, "rust-tauri")
    return (
        "Compiled into the desktop shell (`revkit-shell`, the `.deb`/AppImage from `scripts/package.sh\n"
        "--desktop`). Generated from `cargo metadata` on `ui/tauri/src-tauri` (normal dependencies for\n"
        "x86_64 Linux; build-time-only crates excluded).\n\n" + table(rows)
    )


def wasmtime_section(src: Path, dest: Path | None) -> str:
    rows = cargo_closure(src / "Cargo.toml", {"wasmtime-c-api"}, dest, "rust-wasmtime")
    return (
        "Statically linked into every revkit executable that hosts plugins, through wasmtime's prebuilt\n"
        "C API (`libwasmtime.a`). Generated from `cargo metadata` on the wasmtime source of the pinned\n"
        "release (all features of the workspace, so a superset of what the release links).\n\n" + table(rows)
    )


def splice(text: str, name: str, body: str) -> str:
    begin, end = f"<!-- BEGIN GENERATED: {name} -->", f"<!-- END GENERATED: {name} -->"
    if begin not in text or end not in text:
        raise SystemExit(f"THIRD_PARTY_NOTICES.md has no {begin} ... {end} markers")
    a = text.index(begin) + len(begin)
    b = text.index(end)
    return text[:a] + "\n" + body.rstrip() + "\n" + text[b:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sections", default="npm,python,tauri")
    ap.add_argument("--python-venv", type=Path)
    ap.add_argument("--wasmtime-src", type=Path)
    ap.add_argument("--licenses-dir", type=Path)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.licenses_dir:
        a.licenses_dir.mkdir(parents=True, exist_ok=True)
    text = NOTICES.read_text()
    new = text
    for s in [x for x in a.sections.split(",") if x]:
        if s == "npm":
            new = splice(new, s, npm_section(a.licenses_dir))
        elif s == "python":
            new = splice(new, s, python_section(a.python_venv, a.licenses_dir))
        elif s == "tauri":
            new = splice(new, s, tauri_section(a.licenses_dir))
        elif s == "wasmtime":
            if not a.wasmtime_src:
                print("third-party-notices: wasmtime needs --wasmtime-src; skipped", file=sys.stderr)
                continue
            new = splice(new, s, wasmtime_section(a.wasmtime_src, a.licenses_dir))
        else:
            raise SystemExit(f"unknown section {s}")
    if a.check:
        if new != text:
            print("THIRD_PARTY_NOTICES.md is out of date: scripts/third-party-notices.py", file=sys.stderr)
            return 1
        return 0
    if new != text:
        NOTICES.write_text(new)
        print("third-party-notices: updated THIRD_PARTY_NOTICES.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
