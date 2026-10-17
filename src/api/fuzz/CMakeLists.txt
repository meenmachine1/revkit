# libFuzzer target (REVKIT_FUZZ=ON, clang; docs/bug-scrub.md, "Fuzz harnesses").
add_executable(script_metadata_fuzzer script_metadata_fuzzer.cc)
target_include_directories(script_metadata_fuzzer PRIVATE ${PROJECT_SOURCE_DIR}/src/api)
target_link_libraries(script_metadata_fuzzer PRIVATE revkit::api)
target_link_options(script_metadata_fuzzer PRIVATE -fsanitize=fuzzer)
