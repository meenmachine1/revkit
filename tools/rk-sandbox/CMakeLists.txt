# The provider sandbox's helper: confines itself (limits, Landlock,
# seccomp) and runs an external decompiler (docs/providers.md).
add_executable(rk-sandbox main.cc)
target_link_libraries(rk-sandbox PRIVATE revkit::providers revkit::runtime)
target_compile_options(rk-sandbox PRIVATE -Wall -Wextra)
