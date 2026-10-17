# libFuzzer target (REVKIT_FUZZ=ON, clang; docs/bug-scrub.md, "Fuzz harnesses").
add_executable(msvc_markup_fuzzer msvc_markup_fuzzer.cc)
target_link_libraries(msvc_markup_fuzzer PRIVATE revkit::msvc revkit::loader)
target_link_options(msvc_markup_fuzzer PRIVATE -fsanitize=fuzzer)
