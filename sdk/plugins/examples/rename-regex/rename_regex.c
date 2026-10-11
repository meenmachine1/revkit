/* rename-regex: renames functions by a regular-expression rule.
 *
 *   pattern  searched in each function's current name
 *   replace  what each match becomes; \0/$0 the match, \1..\9/$1..$9 groups
 *   limit    at most this many renames (optional)
 *
 * It only reads facts (the function list with effective names) and returns
 * rename edits; the daemon asserts them with provenance
 * plugin:rename-regex@1.0.0 (or the calling agent's), so they can be
 * blamed and reverted like any other edit. */
#include "regex.h"

static uint64_t parse_limit(rk_str s) {
  uint64_t n = 0;
  if (!s.ptr) return ~(uint64_t)0;
  if (s.len == 0) rk_fail("rename-regex: limit must be a number");
  for (uint32_t i = 0; i < s.len; ++i) {
    if (s.ptr[i] < '0' || s.ptr[i] > '9') rk_fail("rename-regex: limit must be a number");
    n = n * 10 + (uint64_t)(s.ptr[i] - '0');
  }
  return n;
}

/* Appends `replace` for one match. */
static void substitute(rk_buf *out, rk_str replace, rk_str name, const int32_t *caps) {
  for (uint32_t i = 0; i < replace.len; ++i) {
    char c = replace.ptr[i];
    if ((c == '\\' || c == '$') && i + 1 < replace.len && replace.ptr[i + 1] >= '0' && replace.ptr[i + 1] <= '9') {
      int g = replace.ptr[++i] - '0';
      if (caps[2 * g] >= 0 && caps[2 * g + 1] >= caps[2 * g])
        rk_buf_put(out, name.ptr + caps[2 * g], (uint32_t)(caps[2 * g + 1] - caps[2 * g]));
    } else if (c == '\\' && i + 1 < replace.len) {
      rk_buf_put(out, &replace.ptr[++i], 1);
    } else {
      rk_buf_put(out, &c, 1);
    }
  }
}

static int command(const rk_command_request *req, rk_list_out *edits) {
  rk_str pattern = rk_command_arg(req, "pattern");
  rk_str replace = rk_command_arg(req, "replace");
  uint64_t limit = parse_limit(rk_command_arg(req, "limit"));
  const char *error = 0;
  rx_program *rx = rx_compile(pattern, &error);
  if (!rx) {
    rk_buf msg = {0, 0, 0};
    rk_buf_puts(&msg, rk_s("rename-regex: bad pattern: "));
    rk_buf_puts(&msg, rk_s(error));
    rk_buf_put(&msg, "", 1);
    rk_fail((const char *)msg.data);
  }

  rk_function *fns;
  uint32_t n = rk_get_functions(&fns);
  uint64_t renamed = 0;
  for (uint32_t i = 0; i < n && renamed < limit; ++i) {
    rk_str name = fns[i].name;
    int32_t caps[2 * RX_GROUPS];
    rk_buf out = {0, 0, 0};
    uint32_t pos = 0;
    int matched = 0;
    /* Every non-overlapping match, left to right (an empty match moves on
     * by one character). */
    while (pos <= name.len && rx_search(rx, name, pos, caps)) {
      matched = 1;
      rk_buf_put(&out, name.ptr + pos, (uint32_t)caps[0] - pos);
      substitute(&out, replace, name, caps);
      if (caps[1] > caps[0]) {
        pos = (uint32_t)caps[1];
      } else {
        if ((uint32_t)caps[1] < name.len) rk_buf_put(&out, name.ptr + caps[1], 1);
        pos = (uint32_t)caps[1] + 1;
      }
    }
    if (!matched) continue;
    if (pos < name.len) rk_buf_put(&out, name.ptr + pos, name.len - pos);
    rk_str new_name = rk_buf_str(&out);
    if (new_name.len == 0 || rk_str_eq(new_name, name)) continue;
    rk_emit_edit(edits, RK_EDIT_RENAME, fns[i].entry, new_name, rk_s(""));
    ++renamed;
  }
  return 0;
}

RK_COMMAND(command)
