# revkit::msvc: Microsoft-specific analysis of PE images (docs/pe.md):
# MSVC RTTI and vftables, the PE headers and directories, exception data,
# as typed data, names and functions for the image backend to assert.
add_library(revkit_msvc STATIC markup.cc pe_markup.cc rtti.cc rtti_markup.cc)
add_library(revkit::msvc ALIAS revkit_msvc)
target_include_directories(revkit_msvc PUBLIC include)
target_link_libraries(revkit_msvc PUBLIC revkit::loader revkit::types PRIVATE revkit::demangle)
target_compile_options(revkit_msvc PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
