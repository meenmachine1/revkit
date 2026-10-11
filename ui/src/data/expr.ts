// Go To expressions (Ghidra's address expressions): `main+0x10`,
// `0x1000 + 4*3`, `(sym - 8) / 2`, a file offset `file:0x200`, a space's
// address `mem:0x100`, and wildcards in names (`FUN_*`, `str?cpy`) that list
// matches. Numbers are hex, as Ghidra's and as the listing shows addresses
// (`10` is 0x10; `0x` is optional). Names are looked up through a resolver,
// so this module has no imports and is unit-tested without a daemon
// (ui/test/expr.ts).

export type Expr =
  | { k: "num"; v: bigint }
  | { k: "sym"; name: string; /** The name is also hex ("add"): its value when no symbol has it. */ num?: bigint }
  | { k: "file"; e: Expr }
  | { k: "space"; space: string; e: Expr }
  | { k: "neg"; e: Expr }
  | { k: "bin"; op: "+" | "-" | "*" | "/"; a: Expr; b: Expr };

export class ExprError extends Error {
  constructor(
    message: string,
    /** Character offset in the text where it went wrong. */
    readonly at: number,
  ) {
    super(message);
  }
}

/** Looks names up for evaluate(). */
export interface Resolver {
  /** A symbol's address by its exact name, else null. */
  symbol(name: string): Promise<bigint | null> | bigint | null;
  /** The address a file offset loads to, else null (not mapped). */
  fileOffset?(offset: bigint): bigint | null;
  /** Whether `name` is an address space ("mem", "code"), and an offset in it as an address. */
  isSpace?(name: string): boolean;
  spaceAddress?(name: string, offset: bigint): bigint | null;
}

interface Tok {
  t: "num" | "id" | "op" | "colon";
  s: string;
  at: number;
}

const NAME_START = /[A-Za-z_.$@?]/;
const NAME_PART = /[A-Za-z0-9_.$@?]/;
const HEX = /^(0x)?[0-9a-f]+$/i;

function tokenize(text: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if ("+-*/()".includes(c)) {
      out.push({ t: "op", s: c, at: i++ });
      continue;
    }
    if (c === ":") {
      out.push({ t: "colon", s: c, at: i++ });
      continue;
    }
    if (NAME_PART.test(c)) {
      const at = i;
      // A name may hold C++'s "::" (ns::f); a single ':' ends it (file:, mem:).
      while (i < text.length && (NAME_PART.test(text[i]) || (text[i] === ":" && text[i + 1] === ":" && NAME_PART.test(text[i + 2] ?? "")))) i += text[i] === ":" ? 2 : 1;
      const s = text.slice(at, i);
      // Hex starting with a digit (an optional 0x, an h suffix) is a number,
      // like the listing's addresses; letters alone ("add", "face") are a
      // name if one exists, else a number (evaluate()).
      out.push({ t: /^[0-9]/.test(s) && HEX.test(s.replace(/h$/i, "")) ? "num" : "id", s, at });
      continue;
    }
    throw new ExprError(`unexpected "${c}"`, i);
  }
  return out;
}

function number(s: string, at: number): bigint {
  const h = s.replace(/h$/i, "").replace(/^0x/i, "");
  if (!/^[0-9a-f]+$/i.test(h) || h.length > 16) throw new ExprError(`not a number: ${s}`, at);
  return BigInt("0x" + h);
}

/** Parses an expression; throws ExprError. `isSpace` tells a space prefix ("mem:") from a name. */
export function parseExpr(text: string, isSpace: (name: string) => boolean = () => false): Expr {
  const toks = tokenize(text);
  if (!toks.length) throw new ExprError("empty", 0);
  let p = 0;
  const peek = () => toks[p];
  const end = () => (toks.length ? toks[toks.length - 1].at + toks[toks.length - 1].s.length : 0);
  const expect = (s: string) => {
    const t = toks[p];
    if (!t || t.s !== s) throw new ExprError(`expected "${s}"`, t ? t.at : end());
    p++;
  };
  const sum = (): Expr => {
    let a = product();
    while (peek()?.t === "op" && (peek().s === "+" || peek().s === "-")) {
      const op = toks[p++].s as "+" | "-";
      a = { k: "bin", op, a, b: product() };
    }
    return a;
  };
  const product = (): Expr => {
    let a = unary();
    while (peek()?.t === "op" && (peek().s === "*" || peek().s === "/")) {
      const op = toks[p++].s as "*" | "/";
      a = { k: "bin", op, a, b: unary() };
    }
    return a;
  };
  const unary = (): Expr => {
    const t = peek();
    if (t?.t === "op" && t.s === "-") {
      p++;
      return { k: "neg", e: unary() };
    }
    if (t?.t === "op" && t.s === "+") {
      p++;
      return unary();
    }
    return primary();
  };
  const primary = (): Expr => {
    const t = toks[p];
    if (!t) throw new ExprError("expected a number or a name", end());
    if (t.t === "op" && t.s === "(") {
      p++;
      const e = sum();
      expect(")");
      return e;
    }
    // file:<offset>, <space>:<offset>
    if ((t.t === "id" || t.t === "num") && toks[p + 1]?.t === "colon") {
      const prefix = t.s.toLowerCase();
      if (prefix === "file") {
        p += 2;
        return { k: "file", e: unary() };
      }
      if (isSpace(t.s)) {
        p += 2;
        return { k: "space", space: t.s, e: unary() };
      }
      throw new ExprError(`no address space "${t.s}"`, t.at);
    }
    if (t.t === "num") {
      p++;
      return { k: "num", v: number(t.s, t.at) };
    }
    if (t.t === "id") {
      p++;
      if (!NAME_START.test(t.s[0])) throw new ExprError(`not a number or a name: ${t.s}`, t.at);
      return /^[a-f]{1,16}$/i.test(t.s) ? { k: "sym", name: t.s, num: BigInt("0x" + t.s) } : { k: "sym", name: t.s };
    }
    throw new ExprError(`unexpected "${t.s}"`, t.at);
  };
  const e = sum();
  if (p < toks.length) throw new ExprError(`unexpected "${toks[p].s}"`, toks[p].at);
  return e;
}

const MASK = (1n << 64n) - 1n;

/** Evaluates a parsed expression to an address (64-bit); throws ExprError for unknown names and bad arithmetic. */
export async function evaluate(e: Expr, r: Resolver): Promise<bigint> {
  switch (e.k) {
    case "num":
      return e.v;
    case "sym": {
      const a = await r.symbol(e.name);
      if (a !== null) return a;
      if (e.num !== undefined) return e.num;
      throw new ExprError(`no symbol "${e.name}"`, 0);
    }
    case "file": {
      const off = await evaluate(e.e, r);
      const a = r.fileOffset?.(off) ?? null;
      if (a === null) throw new ExprError(`file offset 0x${off.toString(16)} isn't loaded`, 0);
      return a;
    }
    case "space": {
      const off = await evaluate(e.e, r);
      const a = r.spaceAddress?.(e.space, off) ?? null;
      if (a === null) throw new ExprError(`no address ${e.space}:${off.toString(16)}`, 0);
      return a;
    }
    case "neg":
      return (-(await evaluate(e.e, r))) & MASK;
    case "bin": {
      const a = await evaluate(e.a, r);
      const b = await evaluate(e.b, r);
      switch (e.op) {
        case "+":
          return (a + b) & MASK;
        case "-":
          return (a - b) & MASK;
        case "*":
          return (a * b) & MASK;
        case "/":
          if (b === 0n) throw new ExprError("division by zero", 0);
          return a / b;
      }
    }
  }
}

/** Parses and evaluates. */
export async function evaluateText(text: string, r: Resolver): Promise<bigint> {
  return evaluate(parseExpr(text, (n) => r.isSpace?.(n) ?? false), r);
}

/**
 * Whether the palette should evaluate `text` as an expression: it has an
 * operator, parentheses or a file: prefix (a plain name or address is
 * found as before).
 */
export function isExpression(text: string): boolean {
  const t = text.trim();
  if (!t || isGlob(t)) return false;
  if (/^file:/i.test(t)) return true;
  // A leading minus alone is no expression ("-" typed first).
  return /[+*/()]|.-./.test(t);
}

/** Wildcards in a name: `*` any run, `?` one character; no spaces or arithmetic around them. */
export function isGlob(text: string): boolean {
  const t = text.trim();
  if (!/[*?]/.test(t) || /[\s+()/]/.test(t)) return false;
  // `4*3`, `10*0x8`: arithmetic on numbers, not a pattern.
  if (/^(0x)?[0-9a-f]+(\*(0x)?[0-9a-f]+)+$/i.test(t)) return false;
  return /^[A-Za-z0-9_.$@?*:<>~-]+$/.test(t);
}

/** A glob as an anchored, case-sensitive regular expression. */
export function globToRegExp(glob: string): RegExp {
  const body = glob
    .trim()
    .split("")
    .map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[\\^$.|+()[\]{}]/g, "\\$&")))
    .join("");
  return new RegExp(`^${body}$`);
}

/** The longest run of a glob without wildcards (what to ask the daemon for by substring). */
export function globLiteral(glob: string): string {
  return glob
    .trim()
    .split(/[*?]/)
    .reduce((a, b) => (b.length > a.length ? b : a), "");
}
