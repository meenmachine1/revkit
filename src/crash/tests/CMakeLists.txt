# Cores are made at test time (cc and the kernel, or gcore; aarch64 under
# qemu-aarch64), minidumps by tests/data/crash/make_minidump.py; a test
# without its tools skips itself.
add_executable(revkit_crash_tests crash_test.cc)
target_link_libraries(revkit_crash_tests PRIVATE revkit::crash GTest::gtest_main)
target_compile_options(revkit_crash_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_crash_tests PRIVATE REVKIT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(revkit_crash_tests)
