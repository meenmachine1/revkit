# Fixtures are written at test time by tests/data/android/make_apk.py (with
# the host's cc, and aarch64-linux-gnu-gcc when it is installed).
add_executable(revkit_android_tests android_test.cc)
target_link_libraries(revkit_android_tests PRIVATE revkit::android_fs GTest::gtest_main)
target_compile_options(revkit_android_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_android_tests PRIVATE REVKIT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(revkit_android_tests)
