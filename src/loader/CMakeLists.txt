# Binary loaders. revkit::loader is the parser library (what the fuzzers
# link; its only dependency is zlib, for compressed ELF sections);
# revkit::loader_ghidra adds the ghidra::LoadImage adapter.

add_library(revkit_loader STATIC
  elf.cc
  image.cc
  language.cc
  pe.cc
  raw.cc
  sections.cc)
add_library(revkit::loader ALIAS revkit_loader)
target_include_directories(revkit_loader PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_loader PRIVATE ZLIB::ZLIB)
target_compile_options(revkit_loader PRIVATE -Wall -Wextra)

add_library(revkit_loader_ghidra STATIC ghidra_loadimage.cc)
add_library(revkit::loader_ghidra ALIAS revkit_loader_ghidra)
target_link_libraries(revkit_loader_ghidra PUBLIC revkit::loader ghidra::decomp)
target_compile_options(revkit_loader_ghidra PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
