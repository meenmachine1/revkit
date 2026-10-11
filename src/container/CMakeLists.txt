# Container file systems (docs/filesystems.md): archives, compression,
# file system images and firmware packages, browsed as trees and nested.
# revkit::container is the parser library (what the fuzzers link); its
# dependencies are the compression libraries: zlib, liblzma, libzstd and
# libbz2 (LZ4 and LZO1X are decoded here).

find_package(PkgConfig REQUIRED)
pkg_check_modules(RK_LZMA REQUIRED IMPORTED_TARGET liblzma)
pkg_check_modules(RK_ZSTD REQUIRED IMPORTED_TARGET libzstd)
find_package(BZip2 REQUIRED)

add_library(revkit_container STATIC
  ar.cc
  common.cc
  compressed.cc
  core.cc
  cpio.cc
  cramfs.cc
  decompress.cc
  dir.cc
  ext.cc
  fat.cc
  firmware.cc
  identify.cc
  iso9660.cc
  session.cc
  squashfs.cc
  tar.cc
  zip.cc)
add_library(revkit::container ALIAS revkit_container)
target_include_directories(revkit_container PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_container PRIVATE ZLIB::ZLIB PkgConfig::RK_LZMA PkgConfig::RK_ZSTD BZip2::BZip2)
target_compile_options(revkit_container PRIVATE -Wall -Wextra)
set_target_properties(revkit_container PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
