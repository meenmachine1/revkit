add_executable(revkit_cparse_test
  archive_test.cc
  cparse_test.cc)
target_link_libraries(revkit_cparse_test PRIVATE revkit::cparse revkit::types GTest::gtest_main)
target_compile_options(revkit_cparse_test PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_cparse_test)

add_executable(revkit_cparse_spec_test spec_test.cc)
target_link_libraries(revkit_cparse_spec_test PRIVATE revkit::cparse_spec revkit::cparse revkit::types revkit::lift GTest::gtest_main)
target_compile_options(revkit_cparse_spec_test PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_cparse_spec_test PRIVATE REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}")
gtest_discover_tests(revkit_cparse_spec_test)

# rk-cparse's layouts against clang's on every target (docs/cparse.md). A
# test oracle only: clang is never linked or shipped.
option(REVKIT_WITH_CLANG "Test the C parser's layouts against clang's (test only)" OFF)
if(REVKIT_WITH_CLANG)
  find_program(REVKIT_CLANG NAMES clang clang-19 clang-18 REQUIRED)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME cparse_clang_oracle
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/clang_oracle.py
            --rk-cparse $<TARGET_FILE:rk-cparse> --clang ${REVKIT_CLANG})
endif()
