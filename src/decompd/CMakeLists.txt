# What identifies the decompiler a failure was observed with: Ghidra's
# version and a hash of everything under third_party/ghidra (the vendored
# sources and any patch series applied to them). Recomputed at configure
# time; the glob re-runs configuration when files come or go.
file(GLOB_RECURSE REVKIT_GHIDRA_FILES CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/third_party/ghidra/*.cc ${PROJECT_SOURCE_DIR}/third_party/ghidra/*.hh
  ${PROJECT_SOURCE_DIR}/third_party/ghidra/*.h ${PROJECT_SOURCE_DIR}/third_party/ghidra/*.y
  ${PROJECT_SOURCE_DIR}/third_party/ghidra/*.patch ${PROJECT_SOURCE_DIR}/third_party/ghidra/*.txt
  ${PROJECT_SOURCE_DIR}/third_party/ghidra/*.cmake ${PROJECT_SOURCE_DIR}/third_party/ghidra/patches/series)
list(SORT REVKIT_GHIDRA_FILES)
set(_rk_ghidra_hashes "")
foreach(f ${REVKIT_GHIDRA_FILES})
  file(SHA256 ${f} _h)
  file(RELATIVE_PATH _rel ${PROJECT_SOURCE_DIR}/third_party/ghidra ${f})
  string(APPEND _rk_ghidra_hashes "${_rel}:${_h}\n")
endforeach()
string(SHA256 _rk_ghidra_sum "${_rk_ghidra_hashes}")
string(SUBSTRING ${_rk_ghidra_sum} 0 12 _rk_ghidra_short)
set(REVKIT_DECOMPILER_BUILD "ghidra-12.1.4+${_rk_ghidra_short}" CACHE INTERNAL "decompiler build identity")
message(STATUS "revkit decompiler build: ${REVKIT_DECOMPILER_BUILD}")

add_library(revkit_decompd STATIC
  batch.cc
  builder.cc
  bundle.cc
  lift_mode.cc
  param_id.cc
  pool.cc
  runner.cc
  signature.cc)
add_library(revkit::decompd ALIAS revkit_decompd)
target_include_directories(revkit_decompd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_decompd PUBLIC revkit::facts revkit::inputs revkit::lift revkit::loader)
target_compile_options(revkit_decompd PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_decompd PRIVATE
  REVKIT_DECOMPILER_BUILD="${REVKIT_DECOMPILER_BUILD}"
  REVKIT_DECOMPD_BUILD_PATH="$<TARGET_FILE:rk-decompd>")

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
