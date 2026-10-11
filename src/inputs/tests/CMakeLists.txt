# The firmware fixture (src/analysis/tests/fixtures/armfw) and the stripped
# ARM program (fixtures/armelf) are built at test time with clang, ld.lld
# and llvm-objcopy; their tests skip without them.
find_program(REVKIT_CLANG clang)
find_program(REVKIT_LLD ld.lld)
find_program(REVKIT_OBJCOPY NAMES llvm-objcopy llvm-objcopy-18)
foreach(var REVKIT_CLANG REVKIT_LLD REVKIT_OBJCOPY)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_inputs_tests inputs_test.cc firmware_test.cc param_id_test.cc demangled_test.cc)
target_include_directories(revkit_inputs_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_inputs_tests PRIVATE revkit::inputs revkit::debuginfo revkit::types GTest::gtest_main)
target_compile_options(revkit_inputs_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_inputs_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_CORPUS_DIR="${REVKIT_CORPUS_DIR}"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_TEST_CLANG="${REVKIT_CLANG}"
  REVKIT_TEST_LLD="${REVKIT_LLD}"
  REVKIT_TEST_OBJCOPY="${REVKIT_OBJCOPY}"
  REVKIT_ARMFW_DIR="${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armfw"
  REVKIT_ARMELF_DIR="${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armelf")
gtest_discover_tests(revkit_inputs_tests DISCOVERY_TIMEOUT 60)
