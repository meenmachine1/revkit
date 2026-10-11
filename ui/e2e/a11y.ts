// Accessibility checks for the e2e test, runnable offline: every focusable
// or interactive element has a name, text meets WCAG AA contrast against
// what is behind it, dialogs are named, and lists and trees hold their
// items. With axe-core reachable (RK_AXE=<path to axe.min.js>, or the
// axe-core package installed) axe's own rules run too.

import type { Page } from "playwright";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";

export interface A11yIssue {
  rule: string;
  where: string;
  detail: string;
}

/** The built-in checks, in the page. */
function pageChecks(): A11yIssue[] {
  const out: A11yIssue[] = [];
  const visible = (el: Element) => {
    const r = (el as HTMLElement).getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && !(el as HTMLElement).closest("[hidden],[aria-hidden=true]");
  };
  const where = (el: Element) => {
    const e = el as HTMLElement;
    return `${e.tagName.toLowerCase()}${e.id ? "#" + e.id : ""}${e.dataset.testid ? `[data-testid=${e.dataset.testid}]` : ""}${e.className && typeof e.className === "string" ? "." + e.className.trim().split(/\s+/).slice(0, 2).join(".") : ""}`;
  };
  const name = (el: Element) => {
    const e = el as HTMLElement;
    const by = e.getAttribute("aria-labelledby");
    if (by) return by.split(/\s+/).map((id) => document.getElementById(id)?.textContent ?? "").join(" ").trim();
    const label = e.getAttribute("aria-label") ?? "";
    if (label.trim()) return label.trim();
    if (e instanceof HTMLInputElement || e instanceof HTMLSelectElement || e instanceof HTMLTextAreaElement) {
      const lab = e.labels?.[0]?.textContent ?? "";
      if (lab.trim()) return lab.trim();
      if (e instanceof HTMLInputElement && e.placeholder) return e.placeholder;
    }
    const text = (e.textContent ?? "").trim();
    if (text && !(e instanceof HTMLInputElement)) return text;
    return (e.getAttribute("title") ?? "").trim();
  };
  // 1. Names.
  const interactive = "button, input:not([type=hidden]), select, textarea, a[href], canvas[tabindex], [tabindex]:not([tabindex='-1']), [role=button], [role=tab], [role=option], [role=treeitem], [role=menuitem], [role=menuitemcheckbox], [role=dialog], [role=listbox], [role=tree], [role=combobox]";
  for (const el of document.querySelectorAll(interactive)) {
    if (!visible(el) || (el as HTMLButtonElement).disabled) continue;
    if (!name(el)) out.push({ rule: "name", where: where(el), detail: "no accessible name" });
  }
  // 2. Owned items.
  const needs: Record<string, string[]> = { listbox: ["option", "group"], tree: ["treeitem", "group"], menu: ["menuitem", "menuitemcheckbox", "menuitemradio", "group"], tablist: ["tab"] };
  for (const [role, kids] of Object.entries(needs))
    for (const el of document.querySelectorAll(`[role=${role}]`)) {
      if (!visible(el)) continue;
      const own = [...el.querySelectorAll("[role]")].filter((k) => k.closest(`[role=${role}]`) === el && kids.includes(k.getAttribute("role")!));
      if (!own.length) out.push({ rule: "children", where: where(el), detail: `${role} without ${kids.join("/")}` });
    }
  // 3. Contrast: text against the first opaque background behind it.
  const parse = (c: string): [number, number, number, number] | null => {
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number);
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  };
  const lum = ([r, g, b]: number[]) => {
    const f = (c: number) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const behind = (el: Element): number[] | null => {
    // Background layers from the element out, composited over white.
    const layers: number[][] = [];
    for (let e: Element | null = el; e; e = e.parentElement) {
      const s = getComputedStyle(e);
      if (s.backgroundImage !== "none") return null;
      const c = parse(s.backgroundColor);
      if (c && c[3] > 0) {
        layers.push(c);
        if (c[3] >= 1) break;
      }
    }
    let rgb = [255, 255, 255];
    for (const c of layers.reverse()) rgb = rgb.map((v, i) => v * (1 - c[3]) + c[i] * c[3]);
    return rgb;
  };
  const seen = new Set<Element>();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const el = n.parentElement;
    if (!el || seen.has(el) || !(n.textContent ?? "").trim() || !visible(el)) continue;
    seen.add(el);
    if (el.closest("canvas, .cm-gutters, [aria-disabled=true], button:disabled, option")) continue;
    const s = getComputedStyle(el);
    const fg = parse(s.color);
    const bg = behind(el);
    if (!fg || !bg) continue;
    const opacity = Number(s.opacity) * (el.closest("[style*=opacity]") ? 1 : 1);
    const mixed = fg.slice(0, 3).map((v, i) => v * fg[3] * opacity + bg[i] * (1 - fg[3] * opacity));
    const a = lum(mixed), b = lum(bg);
    const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const px = parseFloat(s.fontSize), bold = Number(s.fontWeight) >= 700;
    const need = px >= 24 || (bold && px >= 18.66) ? 3 : 4.5;
    if (ratio < need - 0.05) out.push({ rule: "contrast", where: where(el), detail: `${ratio.toFixed(2)} < ${need} (${s.color} on rgb(${bg.map((v) => Math.round(v)).join(",")})): "${(n.textContent ?? "").trim().slice(0, 30)}"` });
  }
  return out;
}

let axeSource: string | null | undefined;

function axePath(): string | null {
  if (process.env.RK_AXE && existsSync(process.env.RK_AXE)) return process.env.RK_AXE;
  try {
    return createRequire(import.meta.url).resolve("axe-core/axe.min.js");
  } catch {
    return null;
  }
}

/** The built-in checks, plus axe's serious and critical violations when axe is reachable. */
export async function audit(p: Page): Promise<{ issues: A11yIssue[]; axe: boolean }> {
  // tsx (esbuild, keepNames) wraps named functions in __name(): give the page one.
  await p.evaluate("globalThis.__name ??= (f) => f");
  const issues = (await p.evaluate(pageChecks)) as A11yIssue[];
  if (axeSource === undefined) axeSource = axePath();
  if (axeSource) {
    await p.addScriptTag({ path: axeSource });
    const v = (await p.evaluate(async () => {
      const axe = (window as unknown as { axe: { run: (d: Document, o: object) => Promise<{ violations: { id: string; impact: string; nodes: { target: string[] }[] }[] }> } }).axe;
      const r = await axe.run(document, { resultTypes: ["violations"] });
      return r.violations.map((x) => ({ id: x.id, impact: x.impact, targets: x.nodes.slice(0, 3).map((n) => n.target.join(" ")) }));
    })) as { id: string; impact: string; targets: string[] }[];
    for (const x of v) if (x.impact === "serious" || x.impact === "critical") issues.push({ rule: `axe:${x.id}`, where: x.targets.join(", "), detail: x.impact });
  }
  return { issues, axe: !!axeSource };
}
