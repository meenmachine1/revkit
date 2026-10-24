# The debugger: one target interface over revkit's p-code emulator and live
# processes behind GDB remote stubs, sessions that map runtime addresses to
# the program and record every stop (include/revkit/debug/, docs/debugger.md).

add_library(revkit_debug STATIC
  crash_target.cc
  emu_target.cc
  gdb_remote.cc
  launch.cc
  rsp.cc
  session.cc
  unwind.cc
  expr.cc
  target.cc
  timeline.cc
  trace_target.cc
  xml.cc)
add_library(revkit::debug ALIAS revkit_debug)
target_include_directories(revkit_debug PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_debug PUBLIC revkit::crash revkit::emu revkit::lift revkit::loader)
target_compile_options(revkit_debug PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
