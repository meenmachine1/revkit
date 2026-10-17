# libFuzzer target (REVKIT_FUZZ=ON, clang; docs/bug-scrub.md, "Fuzz harnesses").
add_executable(data_program_fuzzer data_program_fuzzer.cc)
target_link_libraries(data_program_fuzzer PRIVATE revkit::analysis revkit::loader)
target_link_options(data_program_fuzzer PRIVATE -fsanitize=fuzzer)
