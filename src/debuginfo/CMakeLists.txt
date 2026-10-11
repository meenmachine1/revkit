add_library(revkit_debuginfo STATIC
  die.cc
  image.cc
  import.cc
  msf.cc
  pdb.cc
  pdb_types.cc)
add_library(revkit::debuginfo ALIAS revkit_debuginfo)
target_include_directories(revkit_debuginfo PUBLIC include)
target_link_libraries(revkit_debuginfo PUBLIC revkit::types revkit::loader PRIVATE revkit::demangle)
target_compile_options(revkit_debuginfo PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
