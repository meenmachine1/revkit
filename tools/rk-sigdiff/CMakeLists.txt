# Signature measurements (docs/diff.md): the design's stability table over
# rk-lift --signatures outputs, idf re-derivation.
add_executable(rk-sigdiff main.cc ${PROJECT_SOURCE_DIR}/tools/rk-lift/json.cc)
target_include_directories(rk-sigdiff PRIVATE ${PROJECT_SOURCE_DIR}/tools/rk-lift)
target_link_libraries(rk-sigdiff PRIVATE revkit::diff)
target_compile_options(rk-sigdiff PRIVATE -Wall -Wextra)
