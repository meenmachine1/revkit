// Unit tests for the Open dialog's columns (src/data/programs.ts).

import assert from "node:assert/strict";
import { archText, comparePrograms, dateText, formatText, matchesQuery, sizeText, type ProgramRowInfo } from "../src/data/programs";

assert.equal(archText("ARM:LE:32:v4t"), "ARM · 32-bit · LE (v4T)");
assert.equal(archText("x86:LE:64:default"), "x86 · 64-bit · LE");
assert.equal(archText("AARCH64:LE:64:v8A"), "AArch64 · 64-bit · LE (v8A)");
assert.equal(archText("MIPS:BE:32:default"), "MIPS · 32-bit · BE");
assert.equal(archText("RISCV:LE:64:RV64GC"), "RISC-V · 64-bit · LE (RV64GC)");
assert.equal(archText("8051:BE:16:default"), "8051 · 16-bit · BE");
assert.equal(archText("not a language"), "not a language");
assert.equal(formatText("elf"), "ELF");
assert.equal(formatText("raw"), "Raw binary");
assert.equal(formatText("macho"), "Mach-O");
assert.equal(formatText(""), "—");
const now = Date.UTC(2026, 9, 9, 12, 0, 0);
assert.equal(dateText(now - 10_000, now), "just now");
assert.equal(dateText(now - 6 * 60_000, now), "6 min ago");
assert.equal(dateText(now - 3 * 3600_000, now), "3 hours ago");
assert.match(dateText(now - 2 * 86400_000, now), /^Oct [67], 2026$/);
assert.equal(dateText(0, now), "");
assert.equal(sizeText(512), "512 B");
assert.equal(sizeText(65536), "64.0 KB");
const p = (name: string, languageId: string, importedMs = 0, folderPath = "/"): ProgramRowInfo => ({ name, languageId, format: "elf", folderPath, importedMs, status: "3" });
const a = p("alpha", "x86:LE:64:default", 2), b = p("Beta", "ARM:LE:32:v4t", 1), c = p("prog10", "x86:LE:64:default", 3), d = p("prog9", "x86:LE:64:default", 3);
const sortBy = (xs: ProgramRowInfo[], key: "name" | "arch" | "date", dir: 1 | -1) => [...xs].sort((x, y) => comparePrograms(x, y, { key, dir })).map((x) => x.name);
assert.deepEqual(sortBy([c, b, a, d], "name", 1), ["alpha", "Beta", "prog9", "prog10"]);
assert.deepEqual(sortBy([c, b, a, d], "name", -1), ["prog10", "prog9", "Beta", "alpha"]);
assert.deepEqual(sortBy([a, b, c, d], "arch", 1), ["Beta", "alpha", "prog9", "prog10"]);
assert.deepEqual(sortBy([a, b, c, d], "date", -1), ["prog9", "prog10", "alpha", "Beta"]);
assert.ok(matchesQuery(b, "arm 32"));
assert.ok(matchesQuery(b, "v4T"));
assert.ok(matchesQuery(p("x", "x86:LE:64:default", 0, "/fw/boot"), "boot"));
assert.ok(matchesQuery(a, "ELF"));
assert.ok(!matchesQuery(a, "arm"));
assert.ok(matchesQuery(a, "  "));
console.log("ok   open dialog columns");
