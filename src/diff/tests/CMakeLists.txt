add_executable(revkit_diff_tests
  correlate_test.cc
  diff_test.cc
  lsh_test.cc
  residue_test.cc
)
target_include_directories(revkit_diff_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_diff_tests PRIVATE revkit::diff revkit::loader GTest::gtest_main)
target_compile_options(revkit_diff_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_diff_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_TEST_CLANG="${REVKIT_CLANG}"
  REVKIT_TEST_LLD="${REVKIT_LLD}"
  REVKIT_TEST_OBJCOPY="${REVKIT_OBJCOPY}"
  REVKIT_ARMFW_DIR="${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armfw"
  REVKIT_DIFF_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/data")
gtest_discover_tests(revkit_diff_tests DISCOVERY_TIMEOUT 60)
