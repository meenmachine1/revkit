// Python for the script editor: a small stream tokenizer (keywords,
// builtins, strings with their prefixes and triple quotes, numbers,
// comments, decorators, def/class names) and colours from the theme's
// token variables. Completion and signature help are assist.ts.

import { HighlightStyle, StreamLanguage, syntaxHighlighting, type StreamParser } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";

const KEYWORDS = new Set(
  "False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case".split(" "),
);
const BUILTINS = new Set(
  "abs all any bin bool bytes callable chr dict dir divmod enumerate filter float format frozenset getattr hasattr hash hex id input int isinstance issubclass iter len list map max min next object oct open ord pow print range repr reversed round set setattr slice sorted str sum super tuple type vars zip self".split(" "),
);
// The flat API's names (revkit.script), shown like builtins.
const SCRIPT_API = new Set(
  "current_program current_address current_function current_selection args script run_id client monitor functions function_at function_containing symbol_at to_addr decompile decompile_many read_bytes find_bytes strings instructions xrefs_to xrefs_from rename rename_local retype retype_local comment set_function remove_function flow_override note define_type commit pending_edits revert ask_string ask_int ask_float ask_address ask_yes_no ask_choice ask_choices ask_file ask_values log current_project project_programs folders create_folder rename_folder move_to_folder delete_folder export_project open_filesystem import_from_filesystem".split(
    " ",
  ),
);

interface State {
  /** Inside a triple-quoted string: its quote ('''/"""), else "". */
  triple: string;
  /** The previous word was def or class. */
  defining: boolean;
}

function readString(stream: Parameters<StreamParser<State>["token"]>[0], quote: string): boolean {
  // True when it ended on this line.
  while (!stream.eol()) {
    if (stream.match(quote)) return true;
    if (stream.next() === "\\") stream.next();
  }
  return false;
}

export const pythonParser: StreamParser<State> = {
  name: "python",
  startState: () => ({ triple: "", defining: false }),
  copyState: (s) => ({ ...s }),
  token(stream, state) {
    if (state.triple) {
      if (readString(stream, state.triple)) state.triple = "";
      return "string";
    }
    if (stream.eatSpace()) return null;
    if (stream.match("#")) {
      stream.skipToEnd();
      return "comment";
    }
    if (stream.sol() && stream.match(/^@[\w.]+/)) return "meta";
    // Strings, with prefixes (r, b, f, rb, ...).
    const open = stream.match(/^(?:[rRbBuUfF]{0,2})("""|'''|"|')/) as RegExpMatchArray | null;
    if (open) {
      const q = open[1];
      if (q.length === 3) {
        if (!readString(stream, q)) state.triple = q;
      } else readString(stream, q);
      state.defining = false;
      return "string";
    }
    if (stream.match(/^0[xX][0-9a-fA-F_]+|^0[oO][0-7_]+|^0[bB][01_]+|^\d[\d_]*(\.[\d_]*)?([eE][+-]?\d+)?j?|^\.\d[\d_]*([eE][+-]?\d+)?j?/)) return "number";
    const word = stream.match(/^[A-Za-z_]\w*/) as RegExpMatchArray | null;
    if (word) {
      const w = word[0];
      if (state.defining) {
        state.defining = false;
        return "def";
      }
      if (KEYWORDS.has(w)) {
        state.defining = w === "def" || w === "class";
        return "keyword";
      }
      if (BUILTINS.has(w) || SCRIPT_API.has(w)) return "builtin";
      return "variableName";
    }
    if (stream.match(/^[-+*/%&|^~<>=!@]=?|^\*\*|^\/\//)) return "operator";
    stream.next();
    return "punctuation";
  },
  languageData: { commentTokens: { line: "#" } },
};

export const python = StreamLanguage.define(pythonParser);

export const pythonHighlight = syntaxHighlighting(
  HighlightStyle.define([
    { tag: t.keyword, color: "var(--k-kw)" },
    { tag: t.string, color: "var(--k-st)" },
    { tag: t.comment, color: "var(--k-cm)", fontStyle: "italic" },
    { tag: t.number, color: "var(--k-co)" },
    { tag: [t.standard(t.variableName), t.function(t.variableName)], color: "var(--k-ty)" },
    { tag: t.definition(t.variableName), color: "var(--k-fn)" },
    { tag: t.meta, color: "var(--k-gv)" },
    { tag: t.operator, color: "var(--k-op)" },
    { tag: t.punctuation, color: "var(--k-pu)" },
  ]),
);
