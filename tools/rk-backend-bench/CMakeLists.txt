# Built only with the backend (which needs the API component).
if(NOT TARGET revkit::backend)
  return()
endif()
add_executable(rk-backend-bench main.cc)
target_link_libraries(rk-backend-bench PRIVATE revkit::backend)
target_compile_options(rk-backend-bench PRIVATE -Wall -Wextra)
target_compile_definitions(rk-backend-bench PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")
add_dependencies(rk-backend-bench rk-decompd)
