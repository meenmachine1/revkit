/* revkit plugin SDK for C (interface 1), for wasm32 modules built with clang:
 *
 *   clang --target=wasm32 -O2 -ffreestanding -nostdlib -Isdk/plugins/c \
 *         -Wl,--no-entry -o my-plugin.wasm my_plugin.c sdk/plugins/c/revkit_plugin.c
 *
 * No libc: the SDK provides memcpy/memset/memmove/memcmp, a bump allocator
 * (everything is freed when the call returns, since every call runs in a
 * fresh instance), string and buffer helpers, decoders for the facts the
 * host hands out and encoders for results. The wire format is specified in
 * docs/plugins.md.
 *
 * A plugin defines one entry point with one of the RK_ANALYZER, RK_LOADER or
 * RK_COMMAND macros (a peripheral defines rk_peripheral_* exports itself,
 * see below), and ships a manifest (NAME.json) beside NAME.wasm. Only
 * the host imports a plugin calls end up in its module, and each needs the
 * capability the manifest requests: memory_read needs "memory";
 * functions, function_code and symbol_name need "code"; file_size and
 * file_read need "file".
 */
#ifndef REVKIT_PLUGIN_H
#define REVKIT_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#define RK_ABI_VERSION 1

#define RK_IMPORT(name) __attribute__((import_module("revkit:plugin/v1"), import_name(name)))
#define RK_EXPORT(name) __attribute__((export_name(name)))

/* ---- host imports (raw) ---------------------------------------------------- */

RK_IMPORT("log") void rk_host_log(const void *text, int32_t len);
RK_IMPORT("fail") void rk_host_fail(const void *message, int32_t len); /* does not return */
RK_IMPORT("set_output") void rk_host_set_output(const void *data, int32_t len);
RK_IMPORT("take") int32_t rk_host_take(void *dst);
RK_IMPORT("program_info") int32_t rk_host_program_info(void);
RK_IMPORT("memory_read") int32_t rk_host_memory_read(uint64_t addr, void *dst, int32_t len);
RK_IMPORT("file_size") int64_t rk_host_file_size(void);
RK_IMPORT("file_read") int32_t rk_host_file_read(uint64_t offset, void *dst, int32_t len);
RK_IMPORT("functions") int32_t rk_host_functions(void);
RK_IMPORT("function_code") int32_t rk_host_function_code(uint64_t entry);
RK_IMPORT("symbol_name") int32_t rk_host_symbol_name(uint64_t addr);

/* Peripherals (kind "peripheral", docs/firmware-emulation.md). One instance
 * lives as long as the emulation session: keep state in globals, and don't
 * allocate per call (the bump allocator never frees). A peripheral exports
 *   int32_t  rk_peripheral_buffer(void)                     a static buffer of >= 4096 bytes
 *   int32_t  rk_peripheral_init(const uint8_t *json, int32_t n)   its machine-description object
 *   int64_t  rk_peripheral_read(int64_t offset, int32_t size)
 *   int32_t  rk_peripheral_write(int64_t offset, int32_t size, int64_t value)
 * and optionally rk_peripheral_tick(int64_t now), rk_peripheral_input(ptr, n),
 * rk_peripheral_irq_in(int32_t line, int32_t level), rk_peripheral_reset();
 * each returns 0 on success. Capabilities: "irq" for irq_set and "output"
 * (granted by default), "bus" for bus_read and bus_write (needs
 * rk-daemon --plugin-grant NAME=bus). */
RK_IMPORT("now") int64_t rk_now(void);                 /* machine ticks */
RK_IMPORT("schedule") void rk_schedule(int64_t at);    /* rk_peripheral_tick at `at`; negative cancels */
RK_IMPORT("irq_set") void rk_irq_set(int32_t line, int32_t level);
RK_IMPORT("output") void rk_output(const void *data, int32_t len);
RK_IMPORT("bus_read") int32_t rk_bus_read(uint64_t addr, void *dst, int32_t len);
RK_IMPORT("bus_write") int32_t rk_bus_write(uint64_t addr, const void *src, int32_t len);

/* ---- memory and strings ------------------------------------------------------ */

/* Bump allocation; never returns NULL (traps with "out of memory"). */
void *rk_alloc_bytes(size_t n);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t rk_strlen(const char *s);

/* A byte string; not NUL-terminated. */
typedef struct {
  const char *ptr;
  uint32_t len;
} rk_str;

rk_str rk_s(const char *cstr);
int rk_str_eq(rk_str a, rk_str b);
int rk_str_starts_with(rk_str s, rk_str prefix);
/* A NUL-terminated copy. */
char *rk_str_dup(rk_str s);

/* Growable byte buffer, also the encoder for results. */
typedef struct {
  uint8_t *data;
  uint32_t len;
  uint32_t cap;
} rk_buf;

void rk_buf_put(rk_buf *b, const void *data, uint32_t n);
void rk_buf_puts(rk_buf *b, rk_str s);
void rk_buf_put_hex(rk_buf *b, uint64_t v);
void rk_buf_put_dec(rk_buf *b, uint64_t v);
rk_str rk_buf_str(const rk_buf *b);

void rk_log(rk_str text);
/* Fails the call with a message: the host reports it as a plugin error
 * ("out of memory", which the allocator uses, as out of memory). */
_Noreturn void rk_fail(const char *message);

/* ---- the encoding (docs/plugins.md, "Blobs") ------------------------------------ */

typedef struct {
  const uint8_t *p;
  const uint8_t *end;
} rk_reader;

uint8_t rk_read_u8(rk_reader *r);
uint32_t rk_read_u32(rk_reader *r);
uint64_t rk_read_u64(rk_reader *r);
rk_str rk_read_str(rk_reader *r);
/* A record's fields; the parent moves past the whole record, so fields a
 * newer host appends are skipped. */
rk_reader rk_read_record(rk_reader *r);
uint32_t rk_read_list(rk_reader *r);

void rk_put_u8(rk_buf *b, uint8_t v);
void rk_put_u32(rk_buf *b, uint32_t v);
void rk_put_u64(rk_buf *b, uint64_t v);
void rk_put_str(rk_buf *b, rk_str s);
/* Starts a record or list: returns where its size or count goes. */
uint32_t rk_begin(rk_buf *b);
void rk_end_record(rk_buf *b, uint32_t at);
void rk_end_list(rk_buf *b, uint32_t at, uint32_t count);

/* ---- facts (analyzers and commands) ---------------------------------------- */

enum { RK_PERM_R = 1, RK_PERM_W = 2, RK_PERM_X = 4 };

typedef struct {
  rk_str name;
  uint64_t start, size;
  uint8_t perms;
  uint8_t initialized;
} rk_block;

typedef struct {
  rk_str language; /* "x86:LE:64:default" */
  rk_str compiler;
  uint8_t pointer_size;
  uint8_t big_endian;
  uint8_t has_entry;
  uint64_t entry;
  uint64_t file_size;
  uint32_t nblocks;
  rk_block *blocks;
} rk_program;

void rk_get_program(rk_program *out);
const rk_block *rk_block_at(const rk_program *p, uint64_t addr);

/* Mapped, initialized bytes at addr; stops at a gap. Needs "memory". */
uint32_t rk_read_memory(uint64_t addr, void *dst, uint32_t n);

typedef struct {
  uint64_t first, last; /* inclusive */
} rk_range;

enum { RK_FN_NORETURN = 1, RK_FN_THUNK = 2, RK_FN_DISCOVERED = 4, RK_FN_ASSERTED = 8 };

typedef struct {
  uint64_t entry;
  rk_str name;
  uint32_t flags;
  uint32_t nranges;
  rk_range *ranges;
} rk_function;

/* Every function, by entry, with its effective name. Needs "code". */
uint32_t rk_get_functions(rk_function **out);

typedef struct {
  rk_str space; /* ram, register, unique, const, ... */
  uint64_t offset;
  uint32_t size;
} rk_varnode;

typedef struct {
  rk_str opcode; /* Ghidra's name: COPY, INT_ADD, CALL, ... */
  uint8_t has_output;
  rk_varnode output;
  uint32_t ninputs;
  rk_varnode *inputs;
} rk_pcode;

typedef struct {
  uint64_t address;
  uint32_t length;
  rk_str mnemonic;
  rk_str text;
  uint32_t npcode;
  rk_pcode *pcode;
} rk_insn;

typedef struct {
  uint64_t entry;
  uint32_t ninsns;
  rk_insn *insns;
} rk_code;

/* The function's instructions with p-code; 0 if no function starts at
 * entry. Needs "code". */
int rk_get_function_code(uint64_t entry, rk_code *out);
/* The effective name at addr (empty if none). Needs "code". */
rk_str rk_get_symbol_name(uint64_t addr);

/* Raw bytes of the binary under analysis. Needs "file", which an operator
 * must grant explicitly. */
uint64_t rk_file_size(void);
uint32_t rk_read_file(uint64_t offset, void *dst, uint32_t n);

/* ---- results ---------------------------------------------------------------- */

typedef struct {
  rk_buf buf;
  uint32_t at;
  uint32_t count;
} rk_list_out;

enum { RK_FACT_LABEL = 1, RK_FACT_COMMENT = 2, RK_FACT_DATA_TYPE = 3, RK_FACT_NOTE = 4 };
void rk_emit_fact(rk_list_out *out, uint8_t kind, uint64_t address, rk_str text, rk_str sub);

enum { RK_EDIT_RENAME = 1, RK_EDIT_COMMENT = 2, RK_EDIT_FUNCTION = 3, RK_EDIT_NOTE = 4 };
void rk_emit_edit(rk_list_out *out, uint8_t op, uint64_t address, rk_str text, rk_str sub);

typedef struct {
  rk_buf head, blocks, symbols;
  uint32_t nblocks, nsymbols;
  uint8_t has_entry;
  uint64_t entry;
} rk_load_out;

/* language: a Ghidra language id ("x86:LE:64:default"); compiler: a
 * compiler spec id, or empty for the language's default. */
void rk_load_target(rk_load_out *out, rk_str language, rk_str compiler);
void rk_load_entry(rk_load_out *out, uint64_t entry);
/* A block of `size` bytes at `start`; its first `file_size` bytes come from
 * the file at `file_offset`, the rest read as zero. */
void rk_load_block(rk_load_out *out, rk_str name, uint64_t start, uint64_t size, uint64_t file_offset,
                   uint64_t file_size, uint8_t perms);
void rk_load_symbol(rk_load_out *out, rk_str name, uint64_t address, uint64_t size, int is_function);

/* ---- entry points --------------------------------------------------------------- */

enum { RK_SCOPE_PROGRAM = 0, RK_SCOPE_FUNCTION = 1 };
typedef struct {
  uint8_t scope;
  uint64_t address; /* the function's entry, for function scope */
} rk_analyze_request;

typedef struct {
  rk_str key, value;
} rk_arg;
typedef struct {
  rk_str program_id;
  uint32_t nargs;
  rk_arg *args;
} rk_command_request;
/* The argument's value, or a NULL ptr if it wasn't given. */
rk_str rk_command_arg(const rk_command_request *req, const char *key);

typedef int (*rk_analyze_fn)(const rk_analyze_request *req, rk_list_out *facts);
typedef int (*rk_load_fn)(const uint8_t *file, uint32_t size, rk_load_out *out);
typedef int (*rk_command_fn)(const rk_command_request *req, rk_list_out *edits);

int32_t rk__analyze(const uint8_t *in, int32_t n, rk_analyze_fn fn);
int32_t rk__load(const uint8_t *in, int32_t n, rk_load_fn fn);
int32_t rk__command(const uint8_t *in, int32_t n, rk_command_fn fn);

/* Exactly one of these per plugin. The function returns 0 on success; on
 * failure, rk_fail() gives the host a message. */
#define RK_ANALYZER(fn) \
  RK_EXPORT("rk_analyze") int32_t rk_analyze(const uint8_t *in, int32_t n) { return rk__analyze(in, n, fn); }
#define RK_LOADER(fn) \
  RK_EXPORT("rk_load") int32_t rk_load(const uint8_t *in, int32_t n) { return rk__load(in, n, fn); }
#define RK_COMMAND(fn) \
  RK_EXPORT("rk_command") int32_t rk_command(const uint8_t *in, int32_t n) { return rk__command(in, n, fn); }

#endif
