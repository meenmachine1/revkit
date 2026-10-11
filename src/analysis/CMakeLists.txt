# Function discovery and code coverage as queries over the fact engine
# (see include/revkit/analysis/analysis.h and the README).

add_library(revkit_analysis STATIC
  data.cc
  data_program.cc
  decode.cc
  flow.cc
  functions.cc
  jump_tables.cc
  memory.cc
  units.cc
  user_refs.cc
  no_return.cc
  patterns.cc
  plausible.cc
  program.cc
  search.cc
  strings.cc)
add_library(revkit::analysis ALIAS revkit_analysis)
target_include_directories(revkit_analysis PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_analysis PUBLIC revkit::facts revkit::lift revkit::loader)
target_compile_options(revkit_analysis PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
