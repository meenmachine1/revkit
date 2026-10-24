# libFuzzer targets for the DS formats (REVKIT_FUZZ=ON, clang; docs/bug-scrub.md
# "Fuzz harnesses", docs/nds.md): the ROM, the compressions, NARC and NitroFS,
# and ds-decomp's text files.
foreach(target nds_rom_fuzzer nds_compress_fuzzer nds_narc_fuzzer nds_dsd_fuzzer)
  add_executable(${target} ${target}.cc)
  target_link_libraries(${target} PRIVATE revkit::nds)
  target_compile_options(${target} PRIVATE -Wall -Wextra)
  target_link_options(${target} PRIVATE -fsanitize=fuzzer)
endforeach()
