# The fixtures (tests/data/apple) are made at test time: the plists by
# make_bundle.py (python3), the bundles by build.sh with clang and
# ld64.lld; without them those tests skip themselves.
find_program(REVKIT_APPLE_CLANG clang)
find_program(REVKIT_APPLE_LD64 NAMES ld64.lld ld64.lld-18)
foreach(var REVKIT_APPLE_CLANG REVKIT_APPLE_LD64)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_apple_tests apple_test.cc)
target_link_libraries(revkit_apple_tests PRIVATE revkit::apple revkit::loader GTest::gtest_main)
target_compile_options(revkit_apple_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_apple_tests PRIVATE
  REVKIT_TEST_CLANG="${REVKIT_APPLE_CLANG}"
  REVKIT_TEST_LD64="${REVKIT_APPLE_LD64}"
  REVKIT_APPLE_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/apple")
gtest_discover_tests(revkit_apple_tests)
