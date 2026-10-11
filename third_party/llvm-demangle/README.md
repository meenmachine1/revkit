# Vendored LLVM demangler

- Source: [llvm-project](https://github.com/llvm/llvm-project) tag
  `llvmorg-23.1.2`: `llvm/lib/Demangle/*.cpp` in `lib/`,
  `llvm/include/llvm/Demangle/*` in `include/llvm/Demangle/`.
- Changes: none. `config/llvm/Config/llvm-config.h` is ours: an empty
  stand-in for LLVM's generated config header, which `DemangleConfig.h`
  includes.
- License: Apache-2.0 WITH LLVM-exception, see `LICENSE.TXT`
  (`llvm/LICENSE.TXT` at the same tag).
- Provides the Itanium (GCC/Clang), Microsoft, Rust v0 and D demanglers.
  revkit uses it through `src/demangle` (`revkit::demangle`); it replaces
  Ghidra's GNU demangler, which is GPL.

To upgrade, download the same files from the new tag, update the tag here,
and re-run `revkit_demangle_test`.
