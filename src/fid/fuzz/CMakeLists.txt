# libFuzzer target for Function ID databases (.fidbf and .rkfid): a file a
# user attaches. Built only with -DREVKIT_FUZZ=ON and clang.
add_executable(fuzz_fid_db fuzz_fid_db.cc)
target_link_libraries(fuzz_fid_db PRIVATE revkit::fid)
target_compile_options(fuzz_fid_db PRIVATE -Wall -Wextra)
target_link_options(fuzz_fid_db PRIVATE -fsanitize=fuzzer)
