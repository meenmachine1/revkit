# Inter-procedural prototype and type inference over the fact engine
# (include/revkit/infer/infer.h, docs/infer.md).

set(REVKIT_SIGDBS
  kSigdbGlibcLp64=${CMAKE_CURRENT_SOURCE_DIR}/data/glibc-lp64.sigs
  kSigdbWin64=${CMAKE_CURRENT_SOURCE_DIR}/data/win64.sigs)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sigdb_data.cc
  COMMAND ${CMAKE_COMMAND} -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/sigdb_data.cc "-DINPUTS=${REVKIT_SIGDBS}"
          -P ${CMAKE_CURRENT_SOURCE_DIR}/embed.cmake
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/embed.cmake ${CMAKE_CURRENT_SOURCE_DIR}/data/glibc-lp64.sigs
          ${CMAKE_CURRENT_SOURCE_DIR}/data/win64.sigs
  VERBATIM)

add_library(revkit_infer STATIC
  abi.cc
  accesses.cc
  decompiler.cc
  feedback.cc
  merge.cc
  queries.cc
  remote.cc
  sigdb.cc
  structures.cc
  types_bridge.cc
  vtype.cc
  ${CMAKE_CURRENT_BINARY_DIR}/sigdb_data.cc)
add_library(revkit::infer ALIAS revkit_infer)
target_include_directories(revkit_infer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_infer PUBLIC revkit::analysis revkit::decompd revkit::facts revkit::lift revkit::loader revkit::types)
target_compile_options(revkit_infer PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
