# Fixtures (fixtures/*.c) are compiled at test time with the host C compiler
# and, when present, clang (with lld) and the aarch64, riscv64 and mingw
# cross compilers. Cases whose compiler is missing skip themselves.
find_program(REVKIT_AARCH64_CC aarch64-linux-gnu-gcc)
find_program(REVKIT_RISCV64_CC riscv64-linux-gnu-gcc)
find_program(REVKIT_MINGW_CC x86_64-w64-mingw32-gcc)
find_program(REVKIT_CLANG clang)
find_program(REVKIT_LLD ld.lld)
if(NOT REVKIT_LLD)
  set(REVKIT_CLANG "")
endif()
foreach(var REVKIT_AARCH64_CC REVKIT_RISCV64_CC REVKIT_MINGW_CC REVKIT_CLANG)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_analysis_tests analysis_test.cc data_test.cc)
target_include_directories(revkit_analysis_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_analysis_tests PRIVATE revkit::analysis GTest::gtest_main)
target_compile_options(revkit_analysis_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_analysis_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_TEST_CLANG="${REVKIT_CLANG}"
  REVKIT_TEST_AARCH64_CC="${REVKIT_AARCH64_CC}"
  REVKIT_TEST_RISCV64_CC="${REVKIT_RISCV64_CC}"
  REVKIT_TEST_MINGW_CC="${REVKIT_MINGW_CC}")
gtest_discover_tests(revkit_analysis_tests DISCOVERY_TIMEOUT 60)
