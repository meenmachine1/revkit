add_library(revkit_cparse STATIC
  archive.cc
  builtin_headers.cc
  cparse.cc
  lexer.cc
  literal.cc
  parser.cc
  preprocessor.cc
  profile.cc)
add_library(revkit::cparse ALIAS revkit_cparse)
target_include_directories(revkit_cparse PUBLIC include)
target_link_libraries(revkit_cparse PUBLIC revkit::types)
target_compile_options(revkit_cparse PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()

# Profiles from Ghidra's compiler specs.
add_library(revkit_cparse_spec STATIC spec.cc)
add_library(revkit::cparse_spec ALIAS revkit_cparse_spec)
target_link_libraries(revkit_cparse_spec PUBLIC revkit::cparse PRIVATE revkit::lift)
target_compile_options(revkit_cparse_spec PRIVATE -Wall -Wextra)
