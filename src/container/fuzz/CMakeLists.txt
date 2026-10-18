# libFuzzer targets for the container formats (REVKIT_FUZZ=ON, clang): one
# per format, from one source naming its format, and one for the LZ4 and
# LZO1X block decoders, and one for the bytecode headers (docs/filesystems.md, "Fuzzing"; docs/roadmap.md,
# "Bug scrub").
foreach(format zip tar cpio ar iso9660 gzip bzip2 xz lzma zstd lz4 squashfs ext cramfs fat uimage android-boot uf2 partitions codecs
               bytecode asar pyinstaller pyz lua-chunks node-sea pkg nexe bun)
  string(REPLACE "-" "_" name "${format}")
  add_executable(container_${name}_fuzzer container_fuzzer.cc)
  target_compile_definitions(container_${name}_fuzzer PRIVATE RK_FUZZ_FORMAT="${format}")
  target_link_libraries(container_${name}_fuzzer PRIVATE revkit::container)
  target_link_options(container_${name}_fuzzer PRIVATE -fsanitize=fuzzer)
endforeach()

# Sessions: nesting, paths and identification (docs/bug-scrub.md).
add_executable(container_session_fuzzer container_session_fuzzer.cc)
target_link_libraries(container_session_fuzzer PRIVATE revkit::container)
target_link_options(container_session_fuzzer PRIVATE -fsanitize=fuzzer)
