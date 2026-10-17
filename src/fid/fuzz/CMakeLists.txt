# libFuzzer target for Function ID databases (.fidbf and .rkfid): a file a
# user attaches. Built only with -DREVKIT_FUZZ=ON and clang.
add_executable(fuzz_fid_db fuzz_fid_db.cc)
target_link_libraries(fuzz_fid_db PRIVATE revkit::fid)
target_compile_options(fuzz_fid_db PRIVATE -Wall -Wextra)
target_link_options(fuzz_fid_db PRIVATE -fsanitize=fuzzer)

# Matching against a hostile database, and a hostile PE's relocations as
# hashing reads them (docs/bug-scrub.md).
add_executable(fid_program_fuzzer fid_program_fuzzer.cc)
target_link_libraries(fid_program_fuzzer PRIVATE revkit::fid revkit::loader)
target_link_options(fid_program_fuzzer PRIVATE -fsanitize=fuzzer)
