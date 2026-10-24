# libFuzzer targets for revkit::apple's readers (REVKIT_FUZZ=ON, clang):
# apple_<target>_fuzzer, one per reader (docs/apple-apps.md, "Tests").
foreach(target plist codesign provision nib)
  add_executable(apple_${target}_fuzzer apple_fuzzer.cc)
  target_compile_definitions(apple_${target}_fuzzer PRIVATE RK_FUZZ_TARGET="${target}")
  target_link_libraries(apple_${target}_fuzzer PRIVATE revkit::apple)
  target_link_options(apple_${target}_fuzzer PRIVATE -fsanitize=fuzzer)
endforeach()
