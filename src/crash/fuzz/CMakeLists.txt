# libFuzzer targets for revkit::crash (REVKIT_FUZZ=ON, clang; docs/crash-dumps.md).
foreach(format elf-core minidump)
  string(REPLACE "-" "_" name "${format}")
  add_executable(crash_${name}_fuzzer crash_fuzzer.cc)
  target_compile_definitions(crash_${name}_fuzzer PRIVATE RK_FUZZ_FORMAT="${format}")
  target_link_libraries(crash_${name}_fuzzer PRIVATE revkit::crash)
  target_link_options(crash_${name}_fuzzer PRIVATE -fsanitize=fuzzer)
endforeach()
