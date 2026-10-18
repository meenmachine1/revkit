add_executable(revkit_infer_tests infer_test.cc accesses_test.cc structures_test.cc)
target_include_directories(revkit_infer_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_infer_tests PRIVATE revkit::infer GTest::gtest_main)
target_compile_options(revkit_infer_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_infer_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}")
gtest_discover_tests(revkit_infer_tests DISCOVERY_TIMEOUT 60)
