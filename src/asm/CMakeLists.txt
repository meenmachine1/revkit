# The SLEIGH-inverting assembler (docs/patching.md): one line of assembly to
# its encodings, for any language Ghidra specifies.

add_library(revkit_asm STATIC
  assembler.cc
  grammar.cc
  parser.cc
  solver.cc)
add_library(revkit::asm ALIAS revkit_asm)
target_include_directories(revkit_asm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_asm PUBLIC revkit::lift PRIVATE ghidra::decomp)
target_compile_options(revkit_asm PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
