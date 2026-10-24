# Ghidra's C++ decompiler and SLEIGH engine: revkit's fork of Ghidra
# 12.1.4 (Ghidra/Features/Decompiler/src/decompile), kept as the pristine
# release (decompiler/ = upstream cpp/, datatests/, unittests/) plus the
# ordered patch series in patches/ (README.md here). At configure time
# fork.sh verifies the pristine copy and applies the series into the build
# tree, failing if any patch doesn't apply exactly; everything below builds
# from that patched copy.
# The file groups mirror LIBDECOMP_NAMES in the upstream Makefile, minus the
# files that need libbfd (bfd_arch, loadimage_bfd, codedata, analyzesigs)
# and the Ghidra pipe-protocol files.

set(GHIDRA_FORK_DIR "${CMAKE_CURRENT_BINARY_DIR}/src" CACHE INTERNAL "Patched Ghidra decompiler sources")
file(GLOB _fork_inputs CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/patches/*"
  "${CMAKE_CURRENT_SOURCE_DIR}/decompiler/*"
  "${CMAKE_CURRENT_SOURCE_DIR}/datatests/*"
  "${CMAKE_CURRENT_SOURCE_DIR}/unittests/*")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${_fork_inputs}
  "${CMAKE_CURRENT_SOURCE_DIR}/fork.sh"
  "${CMAKE_CURRENT_SOURCE_DIR}/PRISTINE.sha256"
  "${CMAKE_CURRENT_SOURCE_DIR}/UPSTREAM_VERSION")
execute_process(
  COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/fork.sh" apply "${GHIDRA_FORK_DIR}"
  RESULT_VARIABLE _fork_result
  ERROR_VARIABLE _fork_error)
if(NOT _fork_result EQUAL 0)
  message(FATAL_ERROR "Ghidra decompiler fork: the patch series did not apply:\n${_fork_error}")
endif()
file(STRINGS "${GHIDRA_FORK_DIR}/.series" _fork_series)
list(LENGTH _fork_series _fork_count)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/UPSTREAM_VERSION" _fork_version)
message(STATUS "Ghidra decompiler: pristine ${_fork_version} plus ${_fork_count} patches")

set(_cpp "${GHIDRA_FORK_DIR}/cpp")

set(_core
  xml marshal space float address pcoderaw translate opcodes globalcontext)

set(_deccore
  capability architecture options graph cover block cast typeop database cpool
  comment stringmanage modelrules fspec action loadimage grammar varnode op type
  variable varmap jumptable emulate emulateutil flow userop expression multiprecision
  funcdata funcdata_block funcdata_op funcdata_varnode unionresolve pcodeinject
  heritage prefersplit rangeutil ruleaction subflow blockaction merge double
  transform constseq bitfield coreaction condexe override dynamic crc32 prettyprint
  printlanguage printc printjava memstate opbehavior paramid signature)

set(_sleigh
  sleigh pcodeparse pcodecompile sleighbase slghsymbol
  slghpatexpress slghpattern semantics context slaformat compression filemanage)

set(_extra
  callgraph ifacedecomp ifaceterm inject_sleigh interface
  libdecomp loadimage_xml raw_arch rulecompile sleigh_arch testfunction unify xml_arch)

set(_names ${_core} ${_deccore} ${_sleigh} ${_extra})
list(TRANSFORM _names PREPEND "${_cpp}/")
list(TRANSFORM _names APPEND ".cc")

add_library(ghidra_decomp STATIC ${_names})
add_library(ghidra::decomp ALIAS ghidra_decomp)

# Upstream builds with the compiler's default dialect (C++17 on GCC 13).
set_target_properties(ghidra_decomp PROPERTIES
  CXX_STANDARD 17
  CXX_EXTENSIONS ON
  POSITION_INDEPENDENT_CODE ON)

target_include_directories(ghidra_decomp SYSTEM PUBLIC "${_cpp}")
target_compile_definitions(ghidra_decomp PRIVATE __TERMINAL__)
# Vendored code: keep its warnings out of our build output.
target_compile_options(ghidra_decomp PRIVATE -w)
target_link_libraries(ghidra_decomp PUBLIC ZLIB::ZLIB)

# Upstream's own executables, from the same patched sources:
#   ghidra_decomp_dbg  the decompiler console (upstream decomp_dbg), which
#                      replays Ghidra's "Debug Function Decompilation" files
#   ghidra_test        upstream's test driver (decomp_test_dbg): unittests/
#                      and the datatests/ XML suite, the patches' repros included
add_executable(ghidra_decomp_dbg "${_cpp}/consolemain.cc")
file(GLOB _unittests "${GHIDRA_FORK_DIR}/unittests/*.cc")
add_executable(ghidra_test "${_cpp}/test.cc" ${_unittests})
foreach(t ghidra_decomp_dbg ghidra_test)
  set_target_properties(${t} PROPERTIES CXX_STANDARD 17 CXX_EXTENSIONS ON)
  target_compile_definitions(${t} PRIVATE __TERMINAL__)
  target_compile_options(${t} PRIVATE -w)
  # Whole archive: the architecture capabilities (xml, raw, sleigh) register
  # themselves from static constructors nothing else references.
  target_link_libraries(${t} PRIVATE -Wl,--whole-archive ghidra_decomp -Wl,--no-whole-archive ZLIB::ZLIB)
endforeach()

if(REVKIT_BUILD_TESTS)
  # The pristine copy matches PRISTINE.sha256, the series applies to it
  # exactly, and the build tree holds what it produces.
  add_test(NAME ghidra_fork_series
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/fork.sh" check "${GHIDRA_FORK_DIR}")
  if(GHIDRA_ROOT)
    # Upstream's own test suites, run on the patched sources.
    foreach(kind unittests datatests)
      add_test(NAME ghidra_${kind}
        COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh "${CMAKE_CURRENT_SOURCE_DIR}/upstream-tests.sh"
                $<TARGET_FILE:ghidra_test> "${GHIDRA_ROOT}" "${GHIDRA_FORK_DIR}/datatests" ${kind})
    endforeach()
    # Each patch's repro (repro/*.xml or *.bundle with a .expect): replayed
    # in the console (a savefile) or rk-decompd (a revkit input bundle), the
    # function must fail cleanly or decompile as expected.
    file(GLOB _repros CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/repro/*.expect")
    foreach(e ${_repros})
      get_filename_component(n "${e}" NAME_WE)
      if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/repro/${n}.bundle")
        add_test(NAME ghidra_repro_${n}
          COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh "${CMAKE_CURRENT_SOURCE_DIR}/repro/replay.sh"
                  $<TARGET_FILE:rk-decompd> "${GHIDRA_ROOT}" "${CMAKE_CURRENT_SOURCE_DIR}/repro/${n}.bundle")
      else()
        # A <decompilertest> (upstream's datatests format, its checks
        # inside) runs in ghidra_test; a savefile in the console.
        file(READ "${CMAKE_CURRENT_SOURCE_DIR}/repro/${n}.xml" _head LIMIT 64)
        if(_head MATCHES "<decompilertest>")
          set(_runner ghidra_test)
        else()
          set(_runner ghidra_decomp_dbg)
        endif()
        add_test(NAME ghidra_repro_${n}
          COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} sh "${CMAKE_CURRENT_SOURCE_DIR}/repro/replay.sh"
                  $<TARGET_FILE:${_runner}> "${GHIDRA_ROOT}" "${CMAKE_CURRENT_SOURCE_DIR}/repro/${n}.xml")
      endif()
    endforeach()
  endif()
endif()
