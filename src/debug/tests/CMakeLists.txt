# The debugger's tests. Live ones compile small programs when they start and
# skip when a tool is missing: gdbserver (x86-64), aarch64-linux-gnu-gcc and
# qemu-aarch64 (AArch64 under qemu-user), clang/ld.lld/llvm-objcopy and
# qemu-system-arm (the bare-metal firmware).
find_program(REVKIT_EMU_CLANG clang)
find_program(REVKIT_EMU_LLD ld.lld)
find_program(REVKIT_EMU_OBJCOPY NAMES llvm-objcopy llvm-objcopy-18)

add_executable(revkit_debug_tests rsp_test.cc timeline_test.cc live_test.cc firmware_test.cc expr_test.cc)
target_link_libraries(revkit_debug_tests PRIVATE revkit::debug revkit::emu revkit::lift revkit::loader GTest::gtest_main)
target_compile_definitions(revkit_debug_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_DEBUG_TEST_SRC="${CMAKE_CURRENT_SOURCE_DIR}"
  REVKIT_DEBUG_TEST_OUT="${CMAKE_CURRENT_BINARY_DIR}/out"
  REVKIT_ARMFW_DIR="${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armfw"
  REVKIT_CLANG="${REVKIT_EMU_CLANG}"
  REVKIT_LLD="${REVKIT_EMU_LLD}"
  REVKIT_OBJCOPY="${REVKIT_EMU_OBJCOPY}")
target_compile_options(revkit_debug_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_debug_tests DISCOVERY_TIMEOUT 120 PROPERTIES TIMEOUT 300)
