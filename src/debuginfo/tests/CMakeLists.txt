# Fixtures are compiled at build time by whichever compilers are installed;
# tests for a missing compiler are skipped.
set(FIXTURE_DIR ${CMAKE_CURRENT_BINARY_DIR}/fixtures)
file(MAKE_DIRECTORY ${FIXTURE_DIR})
set(C_FIXTURE ${CMAKE_CURRENT_SOURCE_DIR}/data/fixture.c)
set(CXX_FIXTURE ${CMAKE_CURRENT_SOURCE_DIR}/data/fixture.cc)

find_program(FIXTURE_GCC NAMES gcc)
find_program(FIXTURE_GXX NAMES g++)
find_program(FIXTURE_CLANG NAMES clang clang-18)
find_program(FIXTURE_AARCH64_GCC NAMES aarch64-linux-gnu-gcc)
find_program(FIXTURE_RISCV64_GCC NAMES riscv64-linux-gnu-gcc)

set(fixture_outputs "")
function(add_fixture name compiler source)
  if(NOT ${compiler})
    message(STATUS "debuginfo fixture ${name}: ${compiler} not found, skipping")
    return()
  endif()
  set(out ${FIXTURE_DIR}/${name})
  add_custom_command(OUTPUT ${out}
    COMMAND ${${compiler}} ${ARGN} ${source} -o ${out}
    DEPENDS ${source}
    COMMENT "Compiling DWARF fixture ${name}")
  set(fixture_outputs ${fixture_outputs} ${out} PARENT_SCOPE)
endfunction()

add_fixture(gcc-dwarf5 FIXTURE_GCC ${C_FIXTURE} -g -O0)
add_fixture(gcc-dwarf4 FIXTURE_GCC ${C_FIXTURE} -g -gdwarf-4 -O0)
add_fixture(gcc-O2 FIXTURE_GCC ${C_FIXTURE} -g -O2)
add_fixture(clang-dwarf5 FIXTURE_CLANG ${C_FIXTURE} -g -O0)
add_fixture(clang-dwarf4 FIXTURE_CLANG ${C_FIXTURE} -g -gdwarf-4 -O0)
add_fixture(clang-O2 FIXTURE_CLANG ${C_FIXTURE} -g -O2)
add_fixture(aarch64-gcc FIXTURE_AARCH64_GCC ${C_FIXTURE} -g -O0)
add_fixture(riscv64-gcc FIXTURE_RISCV64_GCC ${C_FIXTURE} -g -O0)
find_program(FIXTURE_CLANGXX NAMES clang++ clang++-18)
add_fixture(gxx-dwarf5 FIXTURE_GXX ${CXX_FIXTURE} -g -O0)
add_fixture(gxx-typeunits FIXTURE_GXX ${CXX_FIXTURE} -g -O0 -fdebug-types-section)
add_fixture(clangxx-typeunits FIXTURE_CLANGXX ${CXX_FIXTURE} -g -O0 -fdebug-types-section)

# PE fixtures with a CodeView PDB: clang targeting mingw, linked by lld.
# (mingw gcc can't write CodeView.) Each image carries DWARF too, so the
# tests can check the PDB against DWARF for the very same code. Probe once
# that the toolchain (clang, lld, mingw headers and libraries) works.
set(PE_PROBE_DIR ${CMAKE_CURRENT_BINARY_DIR}/pe-probe)
file(MAKE_DIRECTORY ${PE_PROBE_DIR})
file(WRITE ${PE_PROBE_DIR}/probe.c "int main(void) { return 0; }\n")
set(PE_FIXTURES_OK FALSE)
if(FIXTURE_CLANG)
  execute_process(
    COMMAND ${FIXTURE_CLANG} --target=x86_64-windows-gnu -gcodeview -fuse-ld=lld
            -Wl,--pdb=${PE_PROBE_DIR}/probe.pdb ${PE_PROBE_DIR}/probe.c -o ${PE_PROBE_DIR}/probe.exe
    RESULT_VARIABLE pe_probe_rc OUTPUT_QUIET ERROR_QUIET)
  if(pe_probe_rc EQUAL 0 AND EXISTS ${PE_PROBE_DIR}/probe.pdb)
    file(READ ${PE_PROBE_DIR}/probe.pdb pe_probe_magic LIMIT 24 HEX)
    # "Microsoft C/C++ MSF 7.00"
    if(pe_probe_magic STREQUAL "4d6963726f736f667420432f432b2b204d534620372e3030")
      set(PE_FIXTURES_OK TRUE)
    endif()
  endif()
endif()
if(NOT PE_FIXTURES_OK)
  message(STATUS "PDB fixtures: clang --target=x86_64-windows-gnu with lld can't write a PDB, skipping")
endif()

function(add_pe_fixture name compiler source)
  if(NOT PE_FIXTURES_OK OR NOT ${compiler})
    return()
  endif()
  set(exe ${FIXTURE_DIR}/${name}.exe)
  set(pdb ${FIXTURE_DIR}/${name}.pdb)
  add_custom_command(OUTPUT ${exe} ${pdb}
    COMMAND ${${compiler}} --target=x86_64-windows-gnu -gcodeview -gdwarf ${ARGN}
            -fuse-ld=lld -Wl,--pdb=${pdb} ${source} -o ${exe}
    DEPENDS ${source}
    COMMENT "Compiling PE+PDB fixture ${name}")
  set(fixture_outputs ${fixture_outputs} ${exe} PARENT_SCOPE)
endfunction()

add_pe_fixture(pe-clang-O0 FIXTURE_CLANG ${C_FIXTURE} -O0)
add_pe_fixture(pe-clang-O2 FIXTURE_CLANG ${C_FIXTURE} -O2)
add_pe_fixture(pe-clangxx-O0 FIXTURE_CLANGXX ${CXX_FIXTURE} -O0)
# For rk-debuginfo's smoke test: the image records only the PDB's file
# name, as the corpus does, so the PDB must be found beside it.
add_pe_fixture(pe-smoke FIXTURE_CLANG ${C_FIXTURE} -O0 -Wl,-Xlink=-pdbaltpath:%_PDB%)
add_custom_target(debuginfo_fixtures ALL DEPENDS ${fixture_outputs})

add_executable(revkit_debuginfo_test
  dwarf_test.cc
  malformed_test.cc
  pdb_malformed_test.cc
  pdb_test.cc)
target_link_libraries(revkit_debuginfo_test PRIVATE
  revkit::debuginfo revkit::loader GTest::gtest_main)
target_compile_definitions(revkit_debuginfo_test PRIVATE
  REVKIT_FIXTURE_DIR="${FIXTURE_DIR}"
  REVKIT_PE_FIXTURES=$<BOOL:${PE_FIXTURES_OK}>)
target_compile_options(revkit_debuginfo_test PRIVATE -Wall -Wextra)
add_dependencies(revkit_debuginfo_test debuginfo_fixtures)
gtest_discover_tests(revkit_debuginfo_test)
