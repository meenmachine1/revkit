find_program(REVKIT_AARCH64_CC aarch64-linux-gnu-gcc)
find_program(REVKIT_RISCV64_CC riscv64-linux-gnu-gcc)
foreach(var REVKIT_AARCH64_CC REVKIT_RISCV64_CC)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_lift_tests lift_test.cc decompile_test.cc format_string_test.cc)
target_include_directories(revkit_lift_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_lift_tests PRIVATE revkit::lift GTest::gtest_main)
target_compile_options(revkit_lift_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_lift_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_TEST_AARCH64_CC="${REVKIT_AARCH64_CC}"
  REVKIT_TEST_RISCV64_CC="${REVKIT_RISCV64_CC}")
gtest_discover_tests(revkit_lift_tests)
