# A p-code emulator over lifted SLEIGH p-code (include/revkit/emu/emulator.hh,
# docs/emulator.md).

add_library(revkit_emu STATIC
  cpu_arm.cc
  cpu_cortexm.cc
  cpu_mips.cc
  derive.cc
  emulator.cc
  float.cc
  interp.cc
  json.cc
  linux.cc
  machine.cc
  peripherals.cc
  state.cc
  stubs.cc
  trace.cc)
add_library(revkit::emu ALIAS revkit_emu)
target_include_directories(revkit_emu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_emu PUBLIC revkit::lift revkit::loader PRIVATE ghidra::decomp)
target_compile_options(revkit_emu PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
