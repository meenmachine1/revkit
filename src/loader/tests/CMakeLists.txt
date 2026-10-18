# Fixtures are built at test time: the host C compiler and, when present,
# cross compilers. Tests that need a missing compiler skip themselves.
find_program(REVKIT_AARCH64_CC aarch64-linux-gnu-gcc)
find_program(REVKIT_MINGW_CC x86_64-w64-mingw32-gcc)
# Go and cargo (with cargo-auditable) for the build-info tests, when present
# (buildinfo_test.cc; $RK_GO, $RK_GO_OLD and $RK_CARGO override them).
find_program(REVKIT_TEST_GO_EXE go HINTS $ENV{HOME}/.local/go/bin /usr/local/go/bin)
find_program(REVKIT_TEST_CARGO_EXE cargo HINTS $ENV{HOME}/.cargo/bin)
# The Mach-O fixtures (tests/data/macho/build.sh): clang, ld64.lld, llvm-lipo,
# llvm-nm and llvm-objdump.
find_program(REVKIT_MACHO_CLANG clang)
find_program(REVKIT_LD64_LLD NAMES ld64.lld ld64.lld-18)
find_program(REVKIT_LLVM_LIPO NAMES llvm-lipo llvm-lipo-18)
find_program(REVKIT_LLVM_NM NAMES llvm-nm llvm-nm-18)
find_program(REVKIT_LLVM_OBJDUMP NAMES llvm-objdump llvm-objdump-18)
foreach(var REVKIT_AARCH64_CC REVKIT_MINGW_CC REVKIT_TEST_GO_EXE REVKIT_TEST_CARGO_EXE REVKIT_MACHO_CLANG REVKIT_LD64_LLD
            REVKIT_LLVM_LIPO REVKIT_LLVM_NM REVKIT_LLVM_OBJDUMP)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_loader_tests buildinfo_test.cc elf_test.cc gopclntab_test.cc macho_test.cc malformed_test.cc pe_test.cc raw_test.cc)
target_link_libraries(revkit_loader_tests PRIVATE revkit::loader ZLIB::ZLIB GTest::gtest_main)
target_compile_options(revkit_loader_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_loader_tests PRIVATE
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_TEST_AARCH64_CC="${REVKIT_AARCH64_CC}"
  REVKIT_TEST_MINGW_CC="${REVKIT_MINGW_CC}"
  REVKIT_TEST_GO="${REVKIT_TEST_GO_EXE}"
  REVKIT_TEST_CARGO="${REVKIT_TEST_CARGO_EXE}"
  REVKIT_TEST_CLANG="${REVKIT_MACHO_CLANG}"
  REVKIT_TEST_LD64="${REVKIT_LD64_LLD}"
  REVKIT_TEST_LIPO="${REVKIT_LLVM_LIPO}"
  REVKIT_TEST_NM="${REVKIT_LLVM_NM}"
  REVKIT_TEST_OBJDUMP="${REVKIT_LLVM_OBJDUMP}"
  REVKIT_MACHO_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/macho")
gtest_discover_tests(revkit_loader_tests)
