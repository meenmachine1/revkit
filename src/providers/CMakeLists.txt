# External decompiler providers (docs/providers.md): the definitions, the
# sandbox (run_sandboxed and, for rk-sandbox, confine_self), the cache.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
add_library(revkit_providers STATIC
  kinds.cc
  providers.cc
  sandbox.cc
  sandbox_exec.cc)
add_library(revkit::providers ALIAS revkit_providers)
target_include_directories(revkit_providers PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_providers PUBLIC revkit::container PRIVATE OpenSSL::Crypto)
target_compile_options(revkit_providers PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_providers PRIVATE REVKIT_SANDBOX_BUILD_PATH="$<TARGET_FILE:rk-sandbox>")

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
