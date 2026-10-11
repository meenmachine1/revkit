# libFuzzer target for project archives (REVKIT_FUZZ=ON, clang): the
# container, the manifest, the op log and its validation (docs/backend.md,
# "Project archives"; docs/roadmap.md, "Bug scrub").
add_executable(project_archive_fuzzer project_archive_fuzzer.cc)
target_include_directories(project_archive_fuzzer PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_link_libraries(project_archive_fuzzer PRIVATE revkit::backend)
target_link_options(project_archive_fuzzer PRIVATE -fsanitize=fuzzer)
