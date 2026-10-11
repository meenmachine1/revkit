add_executable(revkit_facts_tests
  address_test.cc
  assertion_log_test.cc
  replication_test.cc
  engine_test.cc
  patch_test.cc
  rebase_test.cc
  storage_test.cc
  toy_test.cc)
target_link_libraries(revkit_facts_tests PRIVATE revkit::facts revkit::facts_testing GTest::gtest_main)
target_compile_options(revkit_facts_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_facts_tests DISCOVERY_TIMEOUT 60)
