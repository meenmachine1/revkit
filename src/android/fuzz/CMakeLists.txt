# libFuzzer targets for revkit::android (REVKIT_FUZZ=ON, clang; docs/android.md).
foreach(format axml arsc dex elf jni)
  add_executable(android_${format}_fuzzer android_fuzzer.cc)
  target_compile_definitions(android_${format}_fuzzer PRIVATE RK_FUZZ_FORMAT="${format}")
  target_link_libraries(android_${format}_fuzzer PRIVATE revkit::android)
  target_link_options(android_${format}_fuzzer PRIVATE -fsanitize=fuzzer)
endforeach()
