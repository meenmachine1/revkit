add_executable(cparse_fuzzer cparse_fuzzer.cc)
target_link_libraries(cparse_fuzzer PRIVATE revkit::cparse revkit::types)
target_link_options(cparse_fuzzer PRIVATE -fsanitize=fuzzer)
