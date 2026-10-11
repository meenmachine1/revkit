# Fixtures are built at test time: the host C compiler and, when present,
# cross compilers. Tests that need a missing compiler skip themselves.
find_program(REVKIT_AARCH64_CC aarch64-linux-gnu-gcc)
find_program(REVKIT_MINGW_CC x86_64-w64-mingw32-gcc)
foreach(var REVKIT_AARCH64_CC REVKIT_MINGW_CC)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_loader_tests elf_test.cc malformed_test.cc pe_test.cc raw_test.cc)
target_link_libraries(revkit_loader_tests PRIVATE revkit::loader GTest::gtest_main)
target_compile_options(revkit_loader_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_loader_tests PRIVATE
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_TEST_AARCH64_CC="${REVKIT_AARCH64_CC}"
  REVKIT_TEST_MINGW_CC="${REVKIT_MINGW_CC}")
gtest_discover_tests(revkit_loader_tests)
