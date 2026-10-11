if(GHIDRA_ROOT)
  # Under the tsan preset the emulator is `setarch -R`; it must wrap the
  # shell too, or rk-decomp starts without it and TSan aborts.
  add_test(NAME decompile_smoke
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR}
            sh ${CMAKE_CURRENT_SOURCE_DIR}/smoke.sh
            $<TARGET_FILE:rk-decomp>
            ${GHIDRA_ROOT}
            ${CMAKE_CURRENT_SOURCE_DIR}/data/checksum.c
            ${CMAKE_CURRENT_BINARY_DIR}/smoke)
else()
  message(STATUS "GHIDRA_ROOT not set: skipping decompile_smoke test")
endif()
