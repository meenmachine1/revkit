add_executable(revkit_plugins_tests analyzer_test.cc manifest_test.cc peripheral_test.cc sandbox_test.cc)
target_include_directories(revkit_plugins_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_plugins_tests PRIVATE revkit::plugins revkit::lift GTest::gtest_main)
target_compile_options(revkit_plugins_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_plugins_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_EXAMPLE_PLUGINS="${REVKIT_EXAMPLE_PLUGINS_DIR}"
  REVKIT_FWEMU_DIR="${PROJECT_SOURCE_DIR}/src/emu/tests/fixtures/fwemu"
  REVKIT_FWEMU_TEST_OUT="${CMAKE_CURRENT_BINARY_DIR}/fwemu"
  REVKIT_FWEMU_CLANG="${REVKIT_WASM_CC}")
if(TARGET revkit_example_plugins)
  add_dependencies(revkit_plugins_tests revkit_example_plugins)
endif()
gtest_discover_tests(revkit_plugins_tests DISCOVERY_TIMEOUT 60)
# Loader and command plugins through the image backend (the API path).
if(TARGET revkit_backend)
  add_executable(revkit_plugins_backend_tests backend_test.cc)
  target_include_directories(revkit_plugins_backend_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/loader/tests)
  target_link_libraries(revkit_plugins_backend_tests PRIVATE revkit::backend revkit::plugins revkit::loader
    GTest::gtest_main)
  target_compile_options(revkit_plugins_backend_tests PRIVATE -Wall -Wextra)
  target_compile_definitions(revkit_plugins_backend_tests PRIVATE
    REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
    REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
    REVKIT_EXAMPLE_PLUGINS="${REVKIT_EXAMPLE_PLUGINS_DIR}")
  if(TARGET revkit_example_plugins)
    add_dependencies(revkit_plugins_backend_tests revkit_example_plugins)
  endif()
  gtest_discover_tests(revkit_plugins_backend_tests DISCOVERY_TIMEOUT 60)
endif()
