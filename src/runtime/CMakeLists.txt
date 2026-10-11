# revkit::runtime — the version every executable reports and where Ghidra's
# processor specs are found at run time (include/revkit/runtime/runtime.h).
#
# build_info.h (version and git commit) is regenerated on every build but
# rewritten only when it changes. The version is REVKIT_BUILD_VERSION when
# set (package builds), else VERSION. REVKIT_GIT_SHA overrides git (packaging
# builds from a copy of the tree without .git).

set(REVKIT_GIT_SHA "" CACHE STRING "Git commit reported by --version (default: git rev-parse)")
set(_gen ${CMAKE_CURRENT_BINARY_DIR}/generated)
add_custom_target(revkit_build_info
  COMMAND ${CMAKE_COMMAND} -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -DVERSION=${REVKIT_FULL_VERSION}
          -DGIT_SHA=${REVKIT_GIT_SHA} -DOUTPUT=${_gen}/revkit/runtime/build_info.h
          -P ${PROJECT_SOURCE_DIR}/cmake/build_info.cmake
  BYPRODUCTS ${_gen}/revkit/runtime/build_info.h
  VERBATIM)
# Configure-time copy so the first build's dependency scan finds it.
execute_process(COMMAND ${CMAKE_COMMAND} -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -DVERSION=${REVKIT_FULL_VERSION}
                        -DGIT_SHA=${REVKIT_GIT_SHA} -DOUTPUT=${_gen}/revkit/runtime/build_info.h
                        -P ${PROJECT_SOURCE_DIR}/cmake/build_info.cmake)

add_library(revkit_runtime STATIC runtime.cc)
add_library(revkit::runtime ALIAS revkit_runtime)
add_dependencies(revkit_runtime revkit_build_info)
target_include_directories(revkit_runtime PUBLIC include PRIVATE ${_gen})
target_compile_definitions(revkit_runtime PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}"
                                                   REVKIT_DEFAULT_TYPEINFO_DIR="${REVKIT_TYPEINFO_DIR}")
target_compile_options(revkit_runtime PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
