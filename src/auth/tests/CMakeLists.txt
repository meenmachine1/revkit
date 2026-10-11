add_executable(revkit_auth_tests
  password_test.cc
  rate_limit_test.cc
  store_test.cc
  tls_test.cc)
target_link_libraries(revkit_auth_tests PRIVATE revkit::auth GTest::gtest_main)
target_compile_options(revkit_auth_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_auth_tests DISCOVERY_TIMEOUT 60)
