add_executable(rk-emu main.cc)
target_link_libraries(rk-emu PRIVATE revkit::emu revkit::infer revkit::lift revkit::loader revkit::plugins revkit::runtime)
target_compile_options(rk-emu PRIVATE -Wall -Wextra)
target_compile_definitions(rk-emu PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")

if(REVKIT_BUILD_TESTS AND GHIDRA_ROOT)
  add_test(NAME rk_emu_smoke
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/smoke.sh $<TARGET_FILE:rk-emu> ${GHIDRA_ROOT}
            ${PROJECT_BINARY_DIR}/src/emu/tests/programs/syscalls-x86_64-O2 ${CMAKE_CURRENT_BINARY_DIR}/smoke)
  set_tests_properties(rk_emu_smoke PROPERTIES SKIP_RETURN_CODE 77)
endif()
