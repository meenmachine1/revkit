add_executable(revkit_types_test
  hash_test.cc
  print_test.cc
  store_test.cc
  transform_test.cc)
target_link_libraries(revkit_types_test PRIVATE revkit::types GTest::gtest_main)
target_compile_options(revkit_types_test PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_types_test)
