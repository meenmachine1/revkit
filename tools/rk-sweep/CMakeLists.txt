add_executable(rk-sweep main.cc)
target_link_libraries(rk-sweep PRIVATE revkit::analysis revkit::emu revkit::lift revkit::loader revkit::facts
                      revkit::runtime)
target_compile_options(rk-sweep PRIVATE -Wall -Wextra)
target_compile_definitions(rk-sweep PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}")

if(REVKIT_BUILD_TESTS AND GHIDRA_ROOT)
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_FOUND)
    # The processor sweep on a deterministic sample of languages (the
    # processors docs/firmware.md benchmarks, then every Nth): no crash, no
    # hang, every language loads (docs/processors.md has the full sweep).
    add_test(NAME processor_sweep_sampled
      COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/processor_sweep.py
              --rk-sweep $<TARGET_FILE:rk-sweep> --sample 16 --timeout 300 -j 2 --no-samples --check)
    # Discovery and decompilation on built AVR, 8051, MSP430 and Z80
    # firmware (skipped without the firmware corpus or its Docker image).
    add_test(NAME mcu_fixtures
      COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/mcu_fixtures_test.py
              --rk-lift $<TARGET_FILE:rk-lift> --corpus ${PROJECT_SOURCE_DIR}/out/firmware-corpus)
    set_tests_properties(mcu_fixtures PROPERTIES SKIP_RETURN_CODE 77)
  endif()
endif()
