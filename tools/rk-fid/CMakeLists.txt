# Function ID from the command line (docs/fid.md).
add_executable(rk-fid main.cc ${PROJECT_SOURCE_DIR}/tools/rk-lift/json.cc)
target_include_directories(rk-fid PRIVATE ${PROJECT_SOURCE_DIR}/tools/rk-lift)
target_link_libraries(rk-fid PRIVATE revkit::fid revkit::debuginfo revkit::inputs revkit::lift revkit::loader)
target_compile_options(rk-fid PRIVATE -Wall -Wextra)
target_compile_definitions(rk-fid PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")
