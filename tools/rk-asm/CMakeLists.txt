add_executable(rk-asm main.cc)
target_link_libraries(rk-asm PRIVATE revkit::asm revkit::lift revkit::loader revkit::runtime)
target_compile_options(rk-asm PRIVATE -Wall -Wextra)
target_compile_definitions(rk-asm PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")
