add_executable(rk-decomp main.cc)
target_link_libraries(rk-decomp PRIVATE revkit::lift revkit::loader ghidra::decomp revkit::runtime)
target_compile_options(rk-decomp PRIVATE -Wall -Wextra)
target_compile_definitions(rk-decomp PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")

if(REVKIT_BUILD_TESTS AND GHIDRA_ROOT)
  find_program(REVKIT_AARCH64_CC aarch64-linux-gnu-gcc)
  add_test(NAME rk_decomp_elf_x86_64
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/elf_smoke.sh $<TARGET_FILE:rk-decomp> ${GHIDRA_ROOT}
            ${PROJECT_SOURCE_DIR}/tests/data/checksum.c ${CMAKE_CURRENT_BINARY_DIR}/elf-x86-64
            ${CMAKE_C_COMPILER})
  set_tests_properties(rk_decomp_elf_x86_64 PROPERTIES SKIP_RETURN_CODE 77)
  if(REVKIT_AARCH64_CC)
    add_test(NAME rk_decomp_elf_aarch64
      COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/elf_smoke.sh $<TARGET_FILE:rk-decomp> ${GHIDRA_ROOT}
              ${PROJECT_SOURCE_DIR}/tests/data/checksum.c ${CMAKE_CURRENT_BINARY_DIR}/elf-aarch64
              ${REVKIT_AARCH64_CC})
    set_tests_properties(rk_decomp_elf_aarch64 PROPERTIES SKIP_RETURN_CODE 77)
  endif()
endif()
