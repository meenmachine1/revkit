add_executable(revkit_fid_tests fid_test.cc ${PROJECT_SOURCE_DIR}/tools/rk-lift/json.cc)
target_include_directories(revkit_fid_tests PRIVATE ${PROJECT_SOURCE_DIR}/tools/rk-lift)
target_link_libraries(revkit_fid_tests PRIVATE revkit::fid revkit::inputs revkit::loader GTest::gtest_main)
target_compile_options(revkit_fid_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_fid_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_CORPUS_DIR="${REVKIT_CORPUS_DIR}"
  REVKIT_FID_TEST_DATA="${CMAKE_CURRENT_SOURCE_DIR}/data")
gtest_discover_tests(revkit_fid_tests DISCOVERY_TIMEOUT 60)
