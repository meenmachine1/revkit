# libFuzzer target (REVKIT_FUZZ=ON, clang; docs/bug-scrub.md, "Fuzz harnesses").
add_executable(detect_fuzzer detect_fuzzer.cc)
target_link_libraries(detect_fuzzer PRIVATE revkit::detect revkit::lift)
target_link_options(detect_fuzzer PRIVATE -fsanitize=fuzzer)
