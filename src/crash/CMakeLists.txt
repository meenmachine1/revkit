# revkit::crash (docs/crash-dumps.md): ELF core files and Windows minidumps
# read into one model (threads and registers, memory, mapped files and
# modules, the signal or exception). No dependency on the rest of revkit;
# revkit::debug's CrashTarget presents a dump as a stopped session.
add_library(revkit_crash STATIC common.cc elfcore.cc minidump.cc)
add_library(revkit::crash ALIAS revkit_crash)
target_include_directories(revkit_crash PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(revkit_crash PRIVATE -Wall -Wextra)
set_target_properties(revkit_crash PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
