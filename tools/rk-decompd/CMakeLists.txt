# The decompiler worker (rk-decompd --worker, started by revkit::decompd's
# WorkerPool) and the repro tool (rk-decompd --bundle FILE).
add_executable(rk-decompd main.cc)
target_link_libraries(rk-decompd PRIVATE revkit::decompd revkit::lift revkit::runtime)
# The worker serves every mode: the image backend's tokens and
# revkit::infer's observations too.
if(TARGET revkit::infer)
  target_link_libraries(rk-decompd PRIVATE revkit::infer)
  target_compile_definitions(rk-decompd PRIVATE REVKIT_DECOMPD_INFER=1)
endif()
if(TARGET revkit::backend)
  target_link_libraries(rk-decompd PRIVATE revkit::backend)
  target_compile_definitions(rk-decompd PRIVATE REVKIT_DECOMPD_BACKEND=1)
endif()
target_compile_options(rk-decompd PRIVATE -Wall -Wextra)
target_compile_definitions(rk-decompd PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")
