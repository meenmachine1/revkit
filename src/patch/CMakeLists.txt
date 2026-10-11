# Export of patched programs (docs/patching.md): patches to file offsets,
# checksum fixups and their detector, verification.

add_library(revkit_patch STATIC
  checksum.cc
  export.cc)
add_library(revkit::patch ALIAS revkit_patch)
target_include_directories(revkit_patch PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_patch PUBLIC revkit::loader)
target_compile_options(revkit_patch PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
