# revkit::nds: Nintendo DS formats (docs/nds.md): ds-decomp's project files
# (config.yaml, symbols.txt, relocs.txt, delinks.txt), .nds ROM images
# (header, overlays, autoloads, NitroFS), NARC archives and the DS
# compressions (BLZ, LZ10, LZ11, Huffman, RLE). No dependencies: the
# fuzzers link it alone.
add_library(revkit_nds STATIC compress.cc dsd.cc rom.cc yaml.cc)
add_library(revkit::nds ALIAS revkit_nds)
target_include_directories(revkit_nds PUBLIC include)
target_compile_options(revkit_nds PRIVATE -Wall -Wextra)
set_target_properties(revkit_nds PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
