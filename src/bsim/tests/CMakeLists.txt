add_executable(revkit_bsim_tests store_test.cc)
target_link_libraries(revkit_bsim_tests PRIVATE revkit::bsim GTest::gtest_main)
target_compile_options(revkit_bsim_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_bsim_tests DISCOVERY_TIMEOUT 60)
