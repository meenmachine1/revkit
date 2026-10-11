# The fixture (tests/data/msvc) is built at test time with clang in cl mode
# and lld-link; without them the tests skip themselves.
find_program(REVKIT_CLANG_FOR_MSVC clang)
find_program(REVKIT_LLD_LINK NAMES lld-link lld-link-18)
foreach(var REVKIT_CLANG_FOR_MSVC REVKIT_LLD_LINK)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_msvc_tests msvc_test.cc)
target_link_libraries(revkit_msvc_tests PRIVATE revkit::msvc revkit::loader revkit::types GTest::gtest_main)
target_compile_options(revkit_msvc_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_msvc_tests PRIVATE
  REVKIT_TEST_CLANG="${REVKIT_CLANG_FOR_MSVC}"
  REVKIT_TEST_LLD_LINK="${REVKIT_LLD_LINK}"
  REVKIT_MSVC_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/msvc")
gtest_discover_tests(revkit_msvc_tests)
