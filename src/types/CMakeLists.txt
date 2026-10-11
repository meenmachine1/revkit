add_library(revkit_types STATIC
  describe.cc
  graph_util.cc
  packing.cc
  print.cc
  sha256.cc
  store.cc
  transform.cc)
add_library(revkit::types ALIAS revkit_types)
target_include_directories(revkit_types PUBLIC include)
target_compile_options(revkit_types PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
