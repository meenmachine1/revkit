add_executable(rk-lift main.cc detect.cc inputs_json.cc json.cc sha256.cc)
target_link_libraries(rk-lift PRIVATE revkit::analysis revkit::decompd revkit::detect revkit::facts revkit::infer revkit::inputs revkit::lift revkit::loader revkit::runtime)
add_dependencies(rk-lift rk-decompd)
target_compile_options(rk-lift PRIVATE -Wall -Wextra)
target_compile_definitions(rk-lift PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")

if(REVKIT_BUILD_TESTS AND GHIDRA_ROOT)
  find_program(REVKIT_AARCH64_CC aarch64-linux-gnu-gcc)
  add_test(NAME rk_lift_x86_64
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/smoke.sh $<TARGET_FILE:rk-lift> ${GHIDRA_ROOT}
            ${CMAKE_CURRENT_BINARY_DIR}/smoke-x86-64 ${CMAKE_C_COMPILER})
  set_tests_properties(rk_lift_x86_64 PROPERTIES SKIP_RETURN_CODE 77)
  add_test(NAME rk_lift_signatures
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/signatures_smoke.sh $<TARGET_FILE:rk-lift>
            ${GHIDRA_ROOT} ${CMAKE_CURRENT_BINARY_DIR}/smoke-signatures ${REVKIT_CORPUS_DIR})
  set_tests_properties(rk_lift_signatures PROPERTIES SKIP_RETURN_CODE 77)
  if(REVKIT_AARCH64_CC)
    add_test(NAME rk_lift_aarch64
      COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/smoke.sh $<TARGET_FILE:rk-lift> ${GHIDRA_ROOT}
              ${CMAKE_CURRENT_BINARY_DIR}/smoke-aarch64 ${REVKIT_AARCH64_CC})
    set_tests_properties(rk_lift_aarch64 PROPERTIES SKIP_RETURN_CODE 77)
  endif()
  find_program(REVKIT_CLANG clang)
  if(REVKIT_CLANG)
    add_test(NAME rk_lift_ebpf
      COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/ebpf_smoke.sh $<TARGET_FILE:rk-lift> ${GHIDRA_ROOT}
              ${CMAKE_CURRENT_BINARY_DIR}/smoke-ebpf ${REVKIT_CLANG})
    set_tests_properties(rk_lift_ebpf PROPERTIES SKIP_RETURN_CODE 77)
  endif()
  find_program(REVKIT_LLD ld.lld)
  find_program(REVKIT_OBJCOPY NAMES llvm-objcopy llvm-objcopy-18)
  if(REVKIT_CLANG AND REVKIT_LLD AND REVKIT_OBJCOPY)
    add_test(NAME rk_lift_raw_arm
      COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/raw_smoke.sh $<TARGET_FILE:rk-lift> ${GHIDRA_ROOT}
              ${CMAKE_CURRENT_BINARY_DIR}/smoke-raw-arm ${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armfw
              ${REVKIT_CLANG} ${REVKIT_LLD} ${REVKIT_OBJCOPY})
    set_tests_properties(rk_lift_raw_arm PROPERTIES SKIP_RETURN_CODE 77)
  endif()
  if(REVKIT_CLANG AND REVKIT_LLD)
    # Source shape: tests/data/shape on ARMv5TE, x86-64 and AArch64.
    add_test(NAME rk_lift_source_shape
      COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh ${CMAKE_CURRENT_SOURCE_DIR}/shape_smoke.sh $<TARGET_FILE:rk-lift> ${GHIDRA_ROOT}
              ${CMAKE_CURRENT_BINARY_DIR}/smoke-shape ${PROJECT_SOURCE_DIR}/tests/data/shape ${REVKIT_CLANG} ${REVKIT_LLD})
    set_tests_properties(rk_lift_source_shape PROPERTIES SKIP_RETURN_CODE 77)
  endif()
endif()
