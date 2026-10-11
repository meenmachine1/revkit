add_executable(rk-debuginfo main.cc)
target_link_libraries(rk-debuginfo PRIVATE revkit::debuginfo revkit::cparse revkit::types revkit::loader revkit::runtime)
target_compile_options(rk-debuginfo PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_FOUND)
    add_test(NAME protonorm_unit
      COMMAND ${Python3_EXECUTABLE} -m unittest discover
              -s ${CMAKE_CURRENT_SOURCE_DIR}/tests -t ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    # rk-dwarf (the compatibility name) on an ELF fixture.
    set(fixture ${CMAKE_BINARY_DIR}/src/debuginfo/tests/fixtures/gcc-dwarf5)
    add_test(NAME rk_dwarf_smoke
      COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh
              ${CMAKE_BINARY_DIR}/tools/rk-dwarf/rk-dwarf ${fixture}
              ${Python3_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/smoke)
    # rk-debuginfo on a PE fixture with a PDB (skipped if it wasn't built).
    set(pe_fixture ${CMAKE_BINARY_DIR}/src/debuginfo/tests/fixtures/pe-smoke.exe)
    add_test(NAME rk_debuginfo_pe_smoke
      COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke_pe.sh
              $<TARGET_FILE:rk-debuginfo> ${pe_fixture}
              ${Python3_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/smoke-pe)
    set_tests_properties(rk_debuginfo_pe_smoke PROPERTIES SKIP_RETURN_CODE 77)
  endif()
endif()
