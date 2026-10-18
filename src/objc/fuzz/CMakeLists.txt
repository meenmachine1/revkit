# libFuzzer target for the Objective-C and Swift metadata readers over
# what the Mach-O loader makes of the input (REVKIT_FUZZ=ON, clang).
add_executable(objc_fuzzer objc_fuzzer.cc)
target_link_libraries(objc_fuzzer PRIVATE revkit::objc revkit::loader)
target_compile_options(objc_fuzzer PRIVATE -Wall -Wextra)
target_link_options(objc_fuzzer PRIVATE -fsanitize=fuzzer)
