# The provider sandbox's helper: confines itself (limits, Landlock,
# seccomp) and runs an external decompiler (docs/providers.md).
if(REVKIT_SANITIZE)
  # Sanitizer builds: the helper runs under the limits it sets on itself,
  # and RLIMIT_DATA counts ASan's and TSan's shadow memory ("Failed to
  # mmap" after the first allocation), so it is built uninstrumented from
  # its own sources: the daemon's side of the sandbox (sandbox.cc, the run
  # queue, the cache) is what the sanitizers check (docs/bug-scrub.md,
  # part 3).
  add_executable(rk-sandbox main.cc ${PROJECT_SOURCE_DIR}/src/providers/sandbox_exec.cc)
  target_include_directories(rk-sandbox PRIVATE ${PROJECT_SOURCE_DIR}/src/providers/include)
  target_compile_definitions(rk-sandbox PRIVATE REVKIT_SANDBOX_STANDALONE REVKIT_SANDBOX_VERSION="${PROJECT_VERSION}")
  target_compile_options(rk-sandbox PRIVATE -Wall -Wextra -fno-sanitize=all)
  target_link_options(rk-sandbox PRIVATE -fno-sanitize=all)
else()
  add_executable(rk-sandbox main.cc)
  target_link_libraries(rk-sandbox PRIVATE revkit::providers revkit::runtime)
  target_compile_options(rk-sandbox PRIVATE -Wall -Wextra)
endif()
