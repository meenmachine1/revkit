# Decompiler inputs from revkit's own loader, function discovery and debug
# info (see include/revkit/inputs/inputs.h), shared by rk-lift and the
# image backend.

add_library(revkit_inputs STATIC
  assemble.cc
  codec.cc
  data.cc
  debug.cc
  demangled.cc
  function.cc
  ghidra_archive.cc
  library.cc
  ghidra_types.cc
  loader.cc
  param_id.cc
  profile.cc
  stack_locals.cc)
add_library(revkit::inputs ALIAS revkit_inputs)
target_include_directories(revkit_inputs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_inputs PUBLIC revkit::analysis revkit::cparse revkit::demangle revkit::lift revkit::loader revkit::types
  PRIVATE revkit::cparse_spec revkit::debuginfo revkit::facts revkit::runtime ZLIB::ZLIB)
target_compile_options(revkit_inputs PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
