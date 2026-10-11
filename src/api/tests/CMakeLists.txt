add_executable(revkit_api_tests
  auth_test.cc
  fake_backend_test.cc
  host_files_test.cc
  script_service_test.cc
  listen_fds_test.cc
  server_test.cc)
target_link_libraries(revkit_api_tests PRIVATE revkit::api revkit_httplib GTest::gtest_main)
target_include_directories(revkit_api_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/api)
target_compile_options(revkit_api_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_api_tests DISCOVERY_TIMEOUT 60)
