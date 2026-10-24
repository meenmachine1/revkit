# The fixtures (tests/data/nds/make_fixture.py) are built at test time with
# clang and ld.lld for ARMv5TE and ARMv4T; without them those tests skip.
find_program(REVKIT_NDS_CLANG clang)
find_program(REVKIT_NDS_LLD NAMES ld.lld ld.lld-18)
find_program(REVKIT_NDS_PYTHON python3)
foreach(var REVKIT_NDS_CLANG REVKIT_NDS_LLD REVKIT_NDS_PYTHON)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_nds_tests nds_test.cc)
target_link_libraries(revkit_nds_tests PRIVATE revkit::nds GTest::gtest_main)
target_compile_options(revkit_nds_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_nds_tests PRIVATE
  REVKIT_NDS_CLANG="${REVKIT_NDS_CLANG}"
  REVKIT_NDS_LLD="${REVKIT_NDS_LLD}"
  REVKIT_NDS_PYTHON="${REVKIT_NDS_PYTHON}"
  REVKIT_NDS_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/nds")
gtest_discover_tests(revkit_nds_tests)
