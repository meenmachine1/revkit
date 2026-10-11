# Unit tests, and correctness against real execution: small C programs
# (programs/) built for x86-64, AArch64 and RISC-V 64 with the cross
# compilers found here, run natively or under qemu-user at test time and
# in the emulator, whose registers, memory, output and exit status must
# agree. Missing compilers or qemu skip those cases.

set(EMU_PROGRAMS arith loops calls memory floats syscalls)
set(EMU_PROGRAM_DIR ${CMAKE_CURRENT_BINARY_DIR}/programs)
set(EMU_PROGRAM_FLAGS -static -nostdlib -fno-pie -no-pie -ffreestanding -fno-stack-protector -fno-math-errno
                      -fno-asynchronous-unwind-tables)
find_program(REVKIT_EMU_CC_X86_64 gcc)
find_program(REVKIT_EMU_CC_AARCH64 aarch64-linux-gnu-gcc)
find_program(REVKIT_EMU_CC_RISCV64 riscv64-linux-gnu-gcc)
find_program(REVKIT_QEMU_AARCH64 qemu-aarch64)
find_program(REVKIT_QEMU_RISCV64 qemu-riscv64)
set(emu_outputs)
foreach(arch x86_64 aarch64 riscv64)
  string(TOUPPER ${arch} ARCH)
  set(cc ${REVKIT_EMU_CC_${ARCH}})
  if(NOT cc)
    continue()
  endif()
  foreach(prog ${EMU_PROGRAMS})
    foreach(opt O0 O2)
      set(out ${EMU_PROGRAM_DIR}/${prog}-${arch}-${opt})
      add_custom_command(
        OUTPUT ${out}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${EMU_PROGRAM_DIR}
        COMMAND ${cc} -${opt} ${EMU_PROGRAM_FLAGS} -o ${out} ${CMAKE_CURRENT_SOURCE_DIR}/programs/rt.c
                ${CMAKE_CURRENT_SOURCE_DIR}/programs/${prog}.c -lgcc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/programs/rt.c ${CMAKE_CURRENT_SOURCE_DIR}/programs/rt.h
                ${CMAKE_CURRENT_SOURCE_DIR}/programs/${prog}.c
        VERBATIM)
      list(APPEND emu_outputs ${out})
    endforeach()
  endforeach()
endforeach()
if(REVKIT_EMU_CC_X86_64)
  # Dynamically linked, position independent: runs on the library stubs.
  set(out ${EMU_PROGRAM_DIR}/dynamic-x86_64)
  add_custom_command(
    OUTPUT ${out}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${EMU_PROGRAM_DIR}
    COMMAND ${REVKIT_EMU_CC_X86_64} -O1 -fno-stack-protector -o ${out} ${CMAKE_CURRENT_SOURCE_DIR}/programs/dynamic.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/programs/dynamic.c
    VERBATIM)
  list(APPEND emu_outputs ${out})
endif()
# Statically linked against glibc: its own start-up code runs in the emulator.
foreach(arch x86_64 aarch64)
  string(TOUPPER ${arch} ARCH)
  if(REVKIT_EMU_CC_${ARCH})
    set(out ${EMU_PROGRAM_DIR}/libc-${arch})
    add_custom_command(
      OUTPUT ${out}
      COMMAND ${CMAKE_COMMAND} -E make_directory ${EMU_PROGRAM_DIR}
      COMMAND ${REVKIT_EMU_CC_${ARCH}} -O2 -static -o ${out} ${CMAKE_CURRENT_SOURCE_DIR}/programs/libc.c
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/programs/libc.c
      VERBATIM)
    list(APPEND emu_outputs ${out})
  endif()
endforeach()
add_custom_target(revkit_emu_programs DEPENDS ${emu_outputs})

# The synthetic ARM firmware (src/analysis/tests/fixtures/armfw), built as
# the other firmware tests build it.
find_program(REVKIT_EMU_CLANG clang)
find_program(REVKIT_EMU_LLD ld.lld)
find_program(REVKIT_EMU_OBJCOPY NAMES llvm-objcopy llvm-objcopy-18)

add_executable(revkit_emu_tests emu_test.cc realexec_test.cc firmware_test.cc machine_test.cc)
target_link_libraries(revkit_emu_tests PRIVATE revkit::emu revkit::lift revkit::loader GTest::gtest_main)
add_dependencies(revkit_emu_tests revkit_emu_programs)
target_compile_definitions(revkit_emu_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_EMU_PROGRAM_DIR="${EMU_PROGRAM_DIR}"
  REVKIT_QEMU_AARCH64="${REVKIT_QEMU_AARCH64}"
  REVKIT_QEMU_RISCV64="${REVKIT_QEMU_RISCV64}"
  REVKIT_ARMFW_DIR="${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armfw"
  REVKIT_ARMFW_OUT="${CMAKE_CURRENT_BINARY_DIR}/armfw"
  REVKIT_FWEMU_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures/fwemu"
  REVKIT_FWEMU_OUT="${CMAKE_CURRENT_BINARY_DIR}/fwemu"
  REVKIT_CLANG="${REVKIT_EMU_CLANG}"
  REVKIT_LLD="${REVKIT_EMU_LLD}"
  REVKIT_OBJCOPY="${REVKIT_EMU_OBJCOPY}")
target_compile_options(revkit_emu_tests PRIVATE -Wall -Wextra)
gtest_discover_tests(revkit_emu_tests DISCOVERY_TIMEOUT 120 PROPERTIES TIMEOUT 600)
