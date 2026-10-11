# Function ID (docs/fid.md): Ghidra-compatible function hashes, Ghidra's
# .fidbf databases and revkit's .rkfid, matching and naming, and creating
# databases from programs with symbols.
add_library(revkit_fid STATIC
  create.cc
  db.cc
  hash.cc
  match.cc
  program.cc
)
add_library(revkit::fid ALIAS revkit_fid)
target_include_directories(revkit_fid PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_fid PUBLIC revkit::analysis revkit::lift revkit::demangle)
target_compile_options(revkit_fid PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
