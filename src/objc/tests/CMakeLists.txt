# The fixtures (tests/data/macho) are built at test time with clang and
# ld64.lld; without them those tests skip themselves.
find_program(REVKIT_OBJC_CLANG clang)
find_program(REVKIT_OBJC_LD64 NAMES ld64.lld ld64.lld-18)
find_program(REVKIT_OBJC_LIPO NAMES llvm-lipo llvm-lipo-18)
find_program(REVKIT_OBJC_NM NAMES llvm-nm llvm-nm-18)
find_program(REVKIT_OBJC_OBJDUMP NAMES llvm-objdump llvm-objdump-18)
foreach(var REVKIT_OBJC_CLANG REVKIT_OBJC_LD64 REVKIT_OBJC_LIPO REVKIT_OBJC_NM REVKIT_OBJC_OBJDUMP)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_objc_tests objc_test.cc)
target_include_directories(revkit_objc_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_objc_tests PRIVATE revkit::objc revkit::loader revkit::types GTest::gtest_main)
target_compile_options(revkit_objc_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_objc_tests PRIVATE
  REVKIT_TEST_CLANG="${REVKIT_OBJC_CLANG}"
  REVKIT_TEST_LD64="${REVKIT_OBJC_LD64}"
  REVKIT_TEST_LIPO="${REVKIT_OBJC_LIPO}"
  REVKIT_TEST_NM="${REVKIT_OBJC_NM}"
  REVKIT_TEST_OBJDUMP="${REVKIT_OBJC_OBJDUMP}"
  REVKIT_MACHO_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/macho")
gtest_discover_tests(revkit_objc_tests)
