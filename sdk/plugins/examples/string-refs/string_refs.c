/* string-refs: per function, finds constants in its p-code that point at C
 * strings in non-executable memory.
 *
 * Function scope: each run reads the function's code (plugins.code), its
 * name (plugins.name) and the pages of the strings it found, so a patched
 * string or a rename re-runs only the functions that read them. Emits an
 * end-of-line comment with the string at each instruction that references
 * one, and, for a function still named FUN_..., a label suggestion
 * str_<first string>. */
#include "revkit_plugin.h"

enum { kMaxString = 96, kMinString = 4 };

static int printable(uint8_t c) { return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n'; }

/* The C string at addr, if there is one of at least kMinString printable
 * characters (escaped into out). */
static int string_at(const rk_program *prog, uint64_t addr, rk_buf *out, rk_buf *raw) {
  const rk_block *b = rk_block_at(prog, addr);
  if (!b || !b->initialized || (b->perms & RK_PERM_X)) return 0;
  uint8_t bytes[kMaxString + 1];
  uint32_t n = rk_read_memory(addr, bytes, sizeof bytes);
  uint32_t len = 0;
  while (len < n && printable(bytes[len])) ++len;
  if (len < kMinString || len >= n || bytes[len] != 0) return 0;
  rk_buf_puts(out, rk_s("\""));
  for (uint32_t i = 0; i < len; ++i) {
    if (bytes[i] == '\n') rk_buf_puts(out, rk_s("\\n"));
    else if (bytes[i] == '\t') rk_buf_puts(out, rk_s("\\t"));
    else if (bytes[i] == '"' || bytes[i] == '\\') {
      rk_buf_put(out, "\\", 1);
      rk_buf_put(out, &bytes[i], 1);
    } else {
      rk_buf_put(out, &bytes[i], 1);
    }
  }
  rk_buf_puts(out, rk_s("\""));
  if (raw) rk_buf_put(raw, bytes, len);
  return 1;
}

static int ident_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static int analyze(const rk_analyze_request *req, rk_list_out *facts) {
  rk_code code;
  if (!rk_get_function_code(req->address, &code)) return 0;
  rk_program prog;
  rk_get_program(&prog);

  rk_buf first = {0, 0, 0};
  uint64_t seen[64];
  uint32_t nseen = 0;
  for (uint32_t i = 0; i < code.ninsns; ++i) {
    const rk_insn *in = &code.insns[i];
    for (uint32_t k = 0; k < in->npcode; ++k) {
      const rk_pcode *op = &in->pcode[k];
      for (uint32_t j = 0; j < op->ninputs; ++j) {
        const rk_varnode *v = &op->inputs[j];
        if (!rk_str_eq(v->space, rk_s("const")) || v->size < 4) continue;
        uint64_t target = v->offset;
        int dup = 0;
        for (uint32_t s = 0; s < nseen; ++s) dup |= seen[s] == target;
        if (dup) continue;
        rk_buf text = {0, 0, 0};
        if (!string_at(&prog, target, &text, first.len ? 0 : &first)) continue;
        if (nseen < 64) seen[nseen++] = target;
        rk_emit_fact(facts, RK_FACT_COMMENT, in->address, rk_buf_str(&text), rk_s("eol"));
      }
    }
  }

  if (first.len) {
    rk_str name = rk_get_symbol_name(req->address);
    if (rk_str_starts_with(name, rk_s("FUN_"))) {
      rk_buf label = {0, 0, 0};
      rk_buf_puts(&label, rk_s("str_"));
      int underscore = 0;
      for (uint32_t i = 0; i < first.len && label.len < 28; ++i) {
        char c = (char)first.data[i];
        if (ident_char(c)) {
          if (underscore && label.len > 4) rk_buf_put(&label, "_", 1);
          rk_buf_put(&label, &c, 1);
          underscore = 0;
        } else {
          underscore = 1;
        }
      }
      if (label.len > 4) rk_emit_fact(facts, RK_FACT_LABEL, req->address, rk_buf_str(&label), rk_s(""));
    }
  }
  return 0;
}

RK_ANALYZER(analyze)
