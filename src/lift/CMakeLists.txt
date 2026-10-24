# SLEIGH lifting over loaded images, and a Ghidra Architecture for the
# decompiler. Specs (.ldefs/.pspec/.sla) come from the Ghidra install.

add_library(revkit_lift STATIC
  abi.cc
  budget.cc
  context.cc
  decomp_inputs.cc
  decompile.cc
  format_string.cc
  functions.cc
  image_arch.cc
  fid_insn.cc
  ghidra_text.cc
  lifter.cc
  sleigh_decoder.cc
  param_id.cc)
add_library(revkit::lift ALIAS revkit_lift)
target_include_directories(revkit_lift PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_lift PUBLIC revkit::loader revkit::loader_ghidra ghidra::decomp PRIVATE revkit::runtime)
target_compile_options(revkit_lift PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
