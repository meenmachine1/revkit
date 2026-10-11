add_executable(revkit_patch_tests checksum_test.cc export_test.cc)
target_link_libraries(revkit_patch_tests PRIVATE revkit::patch revkit::loader GTest::gtest_main)
target_compile_options(revkit_patch_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_patch_tests)
