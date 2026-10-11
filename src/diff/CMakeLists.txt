# Binary diffing / version tracking (docs/diff.md): per-function
# fingerprints as fact-engine queries, the matcher over them, and BSim's
# vector comparison and the residue matcher (F5).
# One source per line: other branches add theirs beside these.

set(_bsim "${PROJECT_SOURCE_DIR}/third_party/bsim")
set(_weights_h "${CMAKE_CURRENT_BINARY_DIR}/generated/lsh_weights_data.h")
add_custom_command(
  OUTPUT "${_weights_h}"
  COMMAND ${CMAKE_COMMAND} -DSRC=${_bsim} -DOUT=${_weights_h} -P ${CMAKE_CURRENT_SOURCE_DIR}/embed_weights.cmake
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/embed_weights.cmake
    ${_bsim}/lshweights_32.xml
    ${_bsim}/lshweights_64.xml
    ${_bsim}/lshweights_64_32.xml
    ${_bsim}/lshweights_nosize.xml
  COMMENT "Embedding BSim's weight tables")

add_library(revkit_diff STATIC
  code.cc
  correlate.cc
  features.cc
  lsh.cc
  match.cc
  residue.cc
  "${_weights_h}"
)
add_library(revkit::diff ALIAS revkit_diff)
target_include_directories(revkit_diff PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(revkit_diff PUBLIC revkit::analysis revkit::facts revkit::lift)
target_compile_options(revkit_diff PRIVATE -Wall -Wextra)
# BSim's comparison must round as Java's doubles do (lsh.cc).
set_source_files_properties(lsh.cc PROPERTIES COMPILE_OPTIONS "-ffp-contract=off")

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
