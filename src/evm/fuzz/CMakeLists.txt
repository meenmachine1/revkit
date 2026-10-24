# libFuzzer target for revkit::evm (REVKIT_FUZZ=ON, clang; docs/evm.md): what
# the backend does with an EVM file at import.
add_executable(evm_fuzzer evm_fuzzer.cc)
target_link_libraries(evm_fuzzer PRIVATE revkit::evm)
target_compile_options(evm_fuzzer PRIVATE -Wall -Wextra)
target_link_options(evm_fuzzer PRIVATE -fsanitize=fuzzer)
