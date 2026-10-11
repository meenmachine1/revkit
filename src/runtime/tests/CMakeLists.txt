add_executable(revkit_runtime_tests runtime_test.cc)
target_link_libraries(revkit_runtime_tests PRIVATE revkit::runtime GTest::gtest_main)
target_compile_options(revkit_runtime_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_runtime_tests)
# The packages' build versions (scripts/version.sh build, docs/packaging.md).
add_test(NAME version_build COMMAND "${PROJECT_SOURCE_DIR}/scripts/version-test.sh")
