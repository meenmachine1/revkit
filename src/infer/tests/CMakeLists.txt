add_executable(revkit_infer_tests infer_test.cc accesses_test.cc structures_test.cc arm32_test.cc)
target_include_directories(revkit_infer_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_infer_tests PRIVATE revkit::infer GTest::gtest_main)
target_compile_options(revkit_infer_tests PRIVATE -Wall -Wextra)
# The 32-bit ARM fixture (tests/data/arm32/make_fixture.py) is built at test
# time with clang and ld.lld; without them its tests skip.
find_program(REVKIT_ARM32_CLANG clang)
find_program(REVKIT_ARM32_LLD NAMES ld.lld ld.lld-18)
find_program(REVKIT_ARM32_PYTHON python3)
foreach(var REVKIT_ARM32_CLANG REVKIT_ARM32_LLD REVKIT_ARM32_PYTHON)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()
target_compile_definitions(revkit_infer_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_ARM32_CLANG="${REVKIT_ARM32_CLANG}"
  REVKIT_ARM32_LLD="${REVKIT_ARM32_LLD}"
  REVKIT_ARM32_PYTHON="${REVKIT_ARM32_PYTHON}"
  REVKIT_ARM32_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/arm32")
gtest_discover_tests(revkit_infer_tests DISCOVERY_TIMEOUT 60)
