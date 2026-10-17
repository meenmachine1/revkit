# libFuzzer target for project archives (REVKIT_FUZZ=ON, clang): the
# container, the manifest, the op log and its validation (docs/backend.md,
# "Project archives"; docs/roadmap.md, "Bug scrub").
add_executable(project_archive_fuzzer project_archive_fuzzer.cc)
target_include_directories(project_archive_fuzzer PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_link_libraries(project_archive_fuzzer PRIVATE revkit::backend)
target_link_options(project_archive_fuzzer PRIVATE -fsanitize=fuzzer)

# The bug scrub's part 2 (docs/bug-scrub.md, "Fuzz harnesses"): symbol
# server cabinets and paths, external debug files, assertion values from
# archives, type archive sidecars, BSim prototypes and extraction.
foreach(target cabinet_fuzzer symbol_path_fuzzer debug_file_fuzzer assertion_values_fuzzer type_archive_fuzzer
               skeleton_prototype_fuzzer extract_fuzzer)
  add_executable(${target} ${target}.cc)
  target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
  target_link_libraries(${target} PRIVATE revkit::backend revkit::loader revkit::lift revkit::cparse revkit::types
                        revkit::analysis revkit::container revkit::debuginfo revkit::facts revkit::inputs
                        revkit::decompd revkit_httplib)
  target_link_options(${target} PRIVATE -fsanitize=fuzzer)
endforeach()
