add_executable(dwarf_fuzzer dwarf_fuzzer.cc)
target_link_libraries(dwarf_fuzzer PRIVATE revkit::debuginfo revkit::types)
target_link_options(dwarf_fuzzer PRIVATE -fsanitize=fuzzer)

add_executable(pdb_fuzzer pdb_fuzzer.cc)
target_link_libraries(pdb_fuzzer PRIVATE revkit::debuginfo revkit::types)
target_link_options(pdb_fuzzer PRIVATE -fsanitize=fuzzer)
add_executable(pdb_seed pdb_seed.cc)
