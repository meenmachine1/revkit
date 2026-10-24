# libFuzzer target for the providers' input detection (REVKIT_FUZZ=ON, clang;
# docs/providers.md): detect_kind over an uploaded file's bytes and name.
add_executable(providers_kinds_fuzzer providers_kinds_fuzzer.cc)
target_link_libraries(providers_kinds_fuzzer PRIVATE revkit::providers)
target_compile_options(providers_kinds_fuzzer PRIVATE -Wall -Wextra)
target_link_options(providers_kinds_fuzzer PRIVATE -fsanitize=fuzzer)
