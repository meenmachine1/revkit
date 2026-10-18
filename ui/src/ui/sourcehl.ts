// Syntax highlighting for an external decompiler's source (docs/ui.md
// "External decompilers"): small stream tokenizers on CodeMirror's
// StreamLanguage, as the script editor's Python (scripts/python.ts), in the
// theme's token colours. C-like languages (C#, Java, JavaScript, Kotlin,
// wasm-decompile's pseudo-code) share one tokenizer with their keywords;
// Lua and XML have their own; Python is the script editor's.

import { HighlightStyle, StreamLanguage, syntaxHighlighting, type StreamParser } from "@codemirror/language";
import type { Extension } from "@codemirror/state";
import { tags as t } from "@lezer/highlight";
import { python } from "../scripts/python";

/** The theme's token colours (style.css --k-*), as the decompiler's C. */
const sourceHighlight = syntaxHighlighting(
  HighlightStyle.define([
    { tag: t.keyword, color: "var(--k-kw)" },
    { tag: [t.string, t.special(t.string)], color: "var(--k-st)" },
    { tag: t.comment, color: "var(--k-cm)", fontStyle: "italic" },
    { tag: t.number, color: "var(--k-co)" },
    { tag: [t.typeName, t.tagName], color: "var(--k-ty)" },
    { tag: [t.function(t.variableName), t.definition(t.variableName)], color: "var(--k-fn)" },
    { tag: t.standard(t.variableName), color: "var(--k-ty)" },
    { tag: [t.propertyName, t.attributeName], color: "var(--k-fd)" },
    { tag: t.meta, color: "var(--k-gv)" },
    { tag: t.operator, color: "var(--k-op)" },
    { tag: t.punctuation, color: "var(--k-pu)" },
  ]),
);

const words = (s: string) => new Set(s.split(" "));

const KEYWORDS: Record<string, Set<string>> = {
  csharp: words(
    "abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using var virtual void volatile while async await get set init record yield nint nuint dynamic when where global",
  ),
  java: words(
    "abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new null package private protected public return short static strictfp super switch synchronized this throw throws transient true false try var void volatile while record yield sealed permits non-sealed",
  ),
  kotlin: words(
    "as break class continue do else false for fun if in interface is null object package return super this throw true try typealias val var when while by catch constructor finally get import init set where abstract override private protected public internal open data companion",
  ),
  javascript: words(
    "async await break case catch class const continue debugger default delete do else export extends false finally for function if import in instanceof let new null of return static super switch this throw true try typeof undefined var void while with yield",
  ),
  wasm: words("function export import if else loop block br br_if return var let global memory table goto label continue break while"),
};

interface ClikeState {
  /** Inside a block comment, or a multi-line string's closing quote. */
  comment: boolean;
  string: string;
}

function clike(keywords: Set<string>, opts: { templates?: boolean; verbatim?: boolean } = {}): StreamParser<ClikeState> {
  return {
    name: "clike",
    startState: () => ({ comment: false, string: "" }),
    copyState: (s) => ({ ...s }),
    token(stream, state) {
      if (state.comment) {
        if (stream.skipTo("*/")) {
          stream.pos += 2;
          state.comment = false;
        } else stream.skipToEnd();
        return "comment";
      }
      if (state.string) {
        while (!stream.eol()) {
          if (stream.match(state.string)) {
            state.string = "";
            break;
          }
          if (stream.next() === "\\" && state.string !== '"""' && !opts.verbatim) stream.next();
        }
        return "string";
      }
      if (stream.eatSpace()) return null;
      if (stream.match("//")) {
        stream.skipToEnd();
        return "comment";
      }
      if (stream.match("/*")) {
        state.comment = true;
        return "comment";
      }
      if (stream.match('"""')) {
        state.string = '"""';
        return "string";
      }
      if (opts.verbatim && stream.match('@"')) {
        state.string = '"';
        return "string";
      }
      const q = stream.peek();
      if (q === '"' || q === "'" || (opts.templates && q === "`")) {
        stream.next();
        let closed = false;
        while (!stream.eol()) {
          const c = stream.next();
          if (c === "\\") stream.next();
          else if (c === q) {
            closed = true;
            break;
          }
        }
        if (!closed && q === "`") state.string = "`";
        return "string";
      }
      if (stream.match(/^0[xX][0-9a-fA-F_]+[lLuU]*|^\d[\d_]*(\.[\d_]*)?([eE][+-]?\d+)?[fFdDmMlLuU]*/)) return "number";
      if (stream.sol() && stream.match(/^\s*#\w+/)) {
        stream.skipToEnd();
        return "meta";
      }
      if (stream.match(/^@[\w.]+/)) return "meta";
      const word = stream.match(/^[A-Za-z_$][\w$]*/) as RegExpMatchArray | null;
      if (word) {
        const w = word[0];
        if (keywords.has(w)) return "keyword";
        if (/^[A-Z]/.test(w)) return "typeName";
        if (stream.match(/^\s*\(/, false)) return "variableName.function";
        return "variableName";
      }
      if (stream.match(/^[-+*/%&|^~<>=!?:]+/)) return "operator";
      stream.next();
      return "punctuation";
    },
    languageData: { commentTokens: { line: "//", block: { open: "/*", close: "*/" } } },
  };
}

const LUA_KEYWORDS = words("and break do else elseif end false for function goto if in local nil not or repeat return then true until while");

interface LuaState {
  /** Inside a long string or comment: its closing bracket ("]==]"), and whether a comment. */
  close: string;
  comment: boolean;
}

const luaParser: StreamParser<LuaState> = {
  name: "lua",
  startState: () => ({ close: "", comment: false }),
  copyState: (s) => ({ ...s }),
  token(stream, state) {
    if (state.close) {
      const style = state.comment ? "comment" : "string";
      if (stream.skipTo(state.close)) {
        stream.pos += state.close.length;
        state.close = "";
      } else stream.skipToEnd();
      return style;
    }
    if (stream.eatSpace()) return null;
    const long = (comment: boolean) => {
      const m = stream.match(/^\[(=*)\[/) as RegExpMatchArray | null;
      if (!m) return false;
      state.close = `]${m[1]}]`;
      state.comment = comment;
      return true;
    };
    if (stream.match("--")) {
      if (long(true)) return "comment";
      stream.skipToEnd();
      return "comment";
    }
    if (long(false)) return "string";
    const q = stream.peek();
    if (q === '"' || q === "'") {
      stream.next();
      while (!stream.eol()) {
        const c = stream.next();
        if (c === "\\") stream.next();
        else if (c === q) break;
      }
      return "string";
    }
    if (stream.match(/^0[xX][0-9a-fA-F]+|^\d+(\.\d*)?([eE][+-]?\d+)?/)) return "number";
    const word = stream.match(/^[A-Za-z_]\w*/) as RegExpMatchArray | null;
    if (word) {
      if (LUA_KEYWORDS.has(word[0])) return "keyword";
      if (stream.match(/^\s*\(/, false)) return "variableName.function";
      return "variableName";
    }
    if (stream.match(/^[-+*/%^#&|~<>=.:]+/)) return "operator";
    stream.next();
    return "punctuation";
  },
  languageData: { commentTokens: { line: "--" } },
};

const xmlParser: StreamParser<{ inTag: boolean; comment: boolean }> = {
  name: "xml",
  startState: () => ({ inTag: false, comment: false }),
  copyState: (s) => ({ ...s }),
  token(stream, state) {
    if (state.comment) {
      if (stream.skipTo("-->")) {
        stream.pos += 3;
        state.comment = false;
      } else stream.skipToEnd();
      return "comment";
    }
    if (stream.match("<!--")) {
      state.comment = true;
      return "comment";
    }
    if (!state.inTag) {
      if (stream.match(/^<\/?[\w:.-]+/)) {
        state.inTag = true;
        return "typeName";
      }
      stream.next();
      while (!stream.eol() && stream.peek() !== "<") stream.next();
      return null;
    }
    if (stream.eatSpace()) return null;
    if (stream.match(/^\/?>/)) {
      state.inTag = false;
      return "typeName";
    }
    if (stream.match(/^"[^"]*"?|^'[^']*'?/)) return "string";
    if (stream.match(/^[\w:.-]+/)) return "propertyName";
    stream.next();
    return "operator";
  },
};

const languages = new Map<string, Extension>();

/** The highlighting for a file's language ("csharp", "java", ...), or none. */
export function sourceLanguage(lang: string): Extension {
  const known = languages.get(lang);
  if (known) return known;
  let ext: Extension = [];
  if (lang === "python") ext = [python, sourceHighlight];
  else if (lang === "lua") ext = [StreamLanguage.define(luaParser), sourceHighlight];
  else if (lang === "xml") ext = [StreamLanguage.define(xmlParser), sourceHighlight];
  else if (KEYWORDS[lang])
    ext = [StreamLanguage.define(clike(KEYWORDS[lang], { templates: lang === "javascript", verbatim: lang === "csharp" })), sourceHighlight];
  languages.set(lang, ext);
  return ext;
}

/** A language's name for people: "C#", "Java", ... */
export function languageTitle(lang: string): string {
  return (
    { csharp: "C#", java: "Java", kotlin: "Kotlin", javascript: "JavaScript", python: "Python", lua: "Lua", wasm: "wasm-decompile", xml: "XML" }[lang] ??
    lang
  );
}
