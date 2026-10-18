# The provider mechanism with a fake provider (fake_provider.sh), input
# detection, and each real tool where it is installed (skipped otherwise).
add_executable(revkit_providers_tests providers_test.cc)
target_link_libraries(revkit_providers_tests PRIVATE revkit::providers GTest::gtest_main)
target_compile_options(revkit_providers_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_providers_tests PRIVATE REVKIT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
add_dependencies(revkit_providers_tests rk-sandbox)
gtest_discover_tests(revkit_providers_tests PROPERTIES TIMEOUT 600)
