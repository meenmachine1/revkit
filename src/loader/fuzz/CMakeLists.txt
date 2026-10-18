# libFuzzer targets for the ELF, Mach-O and PE parsers. Built only with
# -DREVKIT_FUZZ=ON and clang; the top-level CMakeLists adds coverage and
# ASan/UBSan instrumentation to everything in that configuration.
foreach(target fuzz_elf fuzz_macho fuzz_pe pe_reloc_fuzzer raw_loader_fuzzer go_buildinfo_fuzzer go_pclntab_fuzzer rust_audit_fuzzer)
  add_executable(${target} ${target}.cc)
  target_link_libraries(${target} PRIVATE revkit::loader ZLIB::ZLIB)
  target_compile_options(${target} PRIVATE -Wall -Wextra)
  target_link_options(${target} PRIVATE -fsanitize=fuzzer)
endforeach()
