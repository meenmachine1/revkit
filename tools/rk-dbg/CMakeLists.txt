add_executable(rk-dbg main.cc)
target_link_libraries(rk-dbg PRIVATE revkit::debug revkit::emu revkit::infer revkit::lift revkit::loader revkit::runtime)
target_compile_options(rk-dbg PRIVATE -Wall -Wextra)
target_compile_definitions(rk-dbg PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")

if(REVKIT_BUILD_TESTS AND GHIDRA_ROOT)
  add_test(NAME rk_dbg_smoke
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/smoke.sh $<TARGET_FILE:rk-dbg> ${GHIDRA_ROOT}
            ${PROJECT_SOURCE_DIR}/src/debug/tests/programs/debuggee.c ${CMAKE_CURRENT_BINARY_DIR}/smoke)
  set_tests_properties(rk_dbg_smoke PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)
endif()
