add_executable(rk-infer main.cc)
target_link_libraries(rk-infer PRIVATE revkit::analysis revkit::decompd revkit::facts revkit::infer revkit::lift revkit::loader revkit::runtime)
add_dependencies(rk-infer rk-decompd)
target_compile_options(rk-infer PRIVATE -Wall -Wextra)
target_compile_definitions(rk-infer PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")

if(REVKIT_BUILD_TESTS)
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_FOUND)
    # The held-out gate's matchability rule (matchable.py, docs/heldout.md).
    add_test(NAME rk_infer_matchable_unit
      COMMAND ${Python3_EXECUTABLE} -m unittest discover
              -s ${CMAKE_CURRENT_SOURCE_DIR}/tests -t ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  endif()
endif()
