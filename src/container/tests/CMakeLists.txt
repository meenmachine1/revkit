# Fixtures are made at test time with the standard tools (zip, tar,
# mksquashfs, mke2fs, xorriso, mkfs.fat, mkfs.cramfs, cpio) or Python;
# a test whose tool is missing skips itself with a message.
add_executable(revkit_container_tests archive_test.cc filesystem_test.cc)
target_link_libraries(revkit_container_tests PRIVATE revkit::container GTest::gtest_main)
target_compile_options(revkit_container_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_container_tests PRIVATE REVKIT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
gtest_discover_tests(revkit_container_tests)
