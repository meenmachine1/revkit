# Build info: Go modules and Rust crates

A Go or Rust binary often says what built it and from what. revkit reads
that metadata from the file (it never runs the program) and shows it as
the program's **build info**: `QueryService.GetBuildInfo` (api_minor 88,
feature `build-info`), `Program.build_info()` in the Python SDK, the MCP
tool `build_info`, and the UI's **Build info…** (Analyze menu, the palette,
and the Open dialog's details). The reader is `src/loader/buildinfo.cc`
(`revkit/loader/buildinfo.hh`).

## Go

Since Go 1.13 the linker writes a build-info blob: a 32-byte header that
starts with the magic `\xff Go buildinf:` at a 16-byte aligned address,
the Go version, and the module text `go version -m` prints. revkit looks
for it where Go's own `debug/buildinfo` does:

| Format | Where |
| --- | --- |
| ELF | the `.go.buildinfo` section; without section names, the first writable, non-executable `PT_LOAD` |
| PE | the first initialized read-write data section (`.data`) |
| Mach-O | the `__go_buildinfo` section (any segment); else the first writable, non-executable section |

Two layouts exist, and both are read:

- **Go 1.18 and later** (`format: "inline"`): header flag 2 set; the
  version and the module text follow the header, each a uvarint length
  and its bytes.
- **Go 1.13 to 1.17** (`format: "pointer"`): the header holds two pointers
  (its own size, 4 or 8, and byte order) to Go string headers (pointer,
  length) elsewhere in memory. A pointer is the link-time address: a
  RELATIVE relocation at its slot (a PIE) gives the target, and a rebased
  image (`SetImageBase`) moves it with the image.

The module text is framed by two 16-byte sentinels; inside it, revkit takes
the line kinds of Go's `debug/buildinfo.ParseBuildInfo`:

| Line | What |
| --- | --- |
| `path\t<import path>` | the main package (`path`) |
| `mod\t<path>\t<version>[\t<sum>]` | the main module (`main`) |
| `dep\t<path>\t<version>[\t<sum>]` | a dependency module (`deps`) |
| `=>\t<path>\t<version>\t<sum>` | the previous module's replacement; a local directory has no sum and an empty version (Go 1.17) or `(devel)` (recent Go) |
| `build\t<key>=<value>` | a build setting (Go 1.18+), with Go-quoted keys and values unquoted: `-buildmode`, `-compiler`, `-ldflags`, `-tags`, `-trimpath`, `CGO_ENABLED`, `CGO_CFLAGS`, `GOOS`, `GOARCH`, `GOAMD64`, `DefaultGODEBUG`, `vcs`, `vcs.revision`, `vcs.time`, `vcs.modified` |

A line it doesn't take (an unknown kind, a wrong field count, a
replacement with nothing before it, an unterminated last line) is kept in
`unparsed` as it is, rather than failing the whole blob (Go's own parser
refuses those). `-trimpath` builds don't record `-ldflags` (they may hold
paths), and a build outside a version-control checkout has no `vcs.*`.

## Rust

[cargo-auditable](https://github.com/rust-secure-code/cargo-auditable)
(`cargo auditable build`) embeds the crate graph as zlib-compressed JSON in
a `.dep-v0` section (`__DATA,.dep-v0` in Mach-O):
`{"format":1,"packages":[{"name","version","source","kind","dependencies","root"}]}`.
revkit inflates it and returns each package (name, version, source:
`crates.io`, `local`, `git`, `registry` or `other`; kind `runtime` or
`build`; the dependency edges as indexes; the root crate). Unknown fields
are ignored. Every Rust binary also gets:

- `rustc_version`: `rustc version 1.79.0 (129f3b996 2024-06-10)` from an
  ELF's `.comment` section, when rustc left one;
- `rustc_commits`: the 40-hex commit of rustc in the standard library's
  `/rustc/<hash>/` panic paths in read-only data (at most 16 distinct), so
  a binary built without cargo-auditable still names its toolchain.

## Limits and refusals

The file is hostile input. A blob that is absent gives nothing (an unset
`go` or `rust`; absence says nothing about the language); one that is
there and doesn't decode gives a line in `warnings` instead.

- Go: the header search reads at most 256 MiB, each string at most 1 MiB;
  a truncated header, a length past 64 bits, a pointer size other than 4
  or 8, a pointer outside memory, an empty Go version are refused. Text
  that isn't UTF-8 is kept with U+FFFD in place of the bad bytes.
- Rust: the section at most 1 MiB, inflated at most 8 MiB and 64 times its
  size; one complete zlib stream (zero padding after it is allowed: a PE
  section's file alignment); JSON nested at most 32 deep; a package needs
  a non-empty name, version and source; a dependency index must be in the
  list; at most one root; two `.dep-v0` sections are refused.

## Tests and fuzzing

- `src/loader/tests/buildinfo_test.cc`: synthetic ELF images for both Go
  layouts (64-bit little-endian, 32-bit big-endian, rebased, found by the
  writable-segment fallback at an aligned address only) and every refusal;
  the module-text parser's line kinds and Go escapes; cargo-auditable
  lists with escapes, padding and every refusal (a zip bomb among them).
  Then real binaries built at test time: the current Go (ELF and a
  Windows PE; a local `replace` keeps it offline, a git checkout gives the
  `vcs.*` settings), a Go before 1.18 for the pointer layout (ELF, PIE and
  PE) when `$RK_GO_OLD` names one, and `cargo auditable build` of a crate
  with a path dependency. Each skips when its toolchain is missing; the
  test's CMake finds `go` (also in `~/.local/go/bin`, `/usr/local/go/bin`)
  and `cargo` (also in `~/.cargo/bin`, with `cargo-auditable` beside it),
  and `$RK_GO`, `$RK_GO_OLD`, `$RK_CARGO` override them. Recipe: Go from
  https://go.dev/dl/ unpacked into `~/.local/go` (and an old one, e.g.
  `go1.17.13`, anywhere for `$RK_GO_OLD`); `cargo install cargo-auditable`.
- `sdk/python/tests/test_build_info.py`: the SDK and the MCP tool on a Go
  and a Rust binary built the same way; `test_mcp_tools.py` checks a C
  program has none.
- `ui/e2e/buildinfo.ts`: the dialog, its filter, and the Open dialog's
  "Built with" line.
- Fuzzers (`-DREVKIT_FUZZ=ON`, `src/loader/fuzz`): `go_buildinfo_fuzzer`
  (the header search and both layouts over the input as memory, the
  module-text parser, and `read_build_metadata` over a parsed ELF or PE)
  and `rust_audit_fuzzer` (the zlib and JSON readers; an even first byte
  compresses the input first so the JSON reader sees it). First runs
  (3 minutes each, `-rss_limit_mb=2048`, `-max_len=65536`, seeded with
  both Go layouts, module text, an ELF carrying both sections and a
  cargo-auditable list): 695k and 3.3M executions, nothing found. The
  first Go run found the search reading up to 256 MiB of zero fill for an
  ELF whose section or segment claimed a huge size (120 executions a
  second); the search now reads only the bytes the file backs.

## Go function names from pclntab

Done (`api_minor` 93, feature `go-pclntab`): a Go program's functions are
named from its pclntab at import, with their source lines, Go's no-return
functions and the golang compiler spec; `GetBuildInfo` summarizes the
table as `go_pclntab`. See [go.md](go.md).
