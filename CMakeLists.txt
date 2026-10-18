cmake_minimum_required(VERSION 3.20)
# The one version number (scripts/version.sh copies it into the SDKs and the
# Tauri shell; every binary's --version and GetServerInfo report it).
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" REVKIT_VERSION LIMIT_COUNT 1)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS VERSION)
project(revkit VERSION ${REVKIT_VERSION} LANGUAGES C CXX)
# What a package build says it is: scripts/package.sh passes
# `scripts/version.sh build` (0.1.0~git<commit time>.<sha> between releases);
# --version, GetServerInfo and the .deb carry it. Other builds say VERSION.
set(REVKIT_BUILD_VERSION "" CACHE STRING "Version reported and packaged (default: VERSION)")
if(REVKIT_BUILD_VERSION STREQUAL "")
  set(REVKIT_FULL_VERSION ${PROJECT_VERSION})
else()
  set(REVKIT_FULL_VERSION ${REVKIT_BUILD_VERSION})
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(REVKIT_BUILD_TESTS "Build unit tests" ON)
option(REVKIT_SANITIZE "Build with sanitizers: address (ASan+UBSan) or thread" "")
option(REVKIT_FUZZ "Build libFuzzer targets (requires clang)" OFF)
# Release packaging (docs/packaging.md): no build paths in the binaries, and
# installed executables find their private libraries in ../lib/revkit.
option(REVKIT_REPRODUCIBLE "Map source and build paths out of the binaries" OFF)

if(REVKIT_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "REVKIT_FUZZ needs clang (libFuzzer); compiler is ${CMAKE_CXX_COMPILER_ID}")
  endif()
  # Coverage for libFuzzer plus ASan/UBSan, trapping on any UB report.
  # Harnesses that reach the vendored decompiler or SLEIGH engine (whose
  # known reports tools/sanitizers/ubsan.supp lists; detect_fuzzer) need
  # UBSan recoverable, since suppressions only apply then: configure with
  # -DREVKIT_FUZZ_UBSAN_RECOVER=ON and run with UBSAN_OPTIONS=
  # halt_on_error=1:suppressions=tools/sanitizers/ubsan.supp, which still
  # stops on any other report (docs/bug-scrub.md).
  option(REVKIT_FUZZ_UBSAN_RECOVER "Fuzz builds: UBSan recoverable, for suppressions" OFF)
  if(REVKIT_FUZZ_UBSAN_RECOVER)
    set(_rk_fuzz_recover -fsanitize-recover=undefined)
  else()
    set(_rk_fuzz_recover -fno-sanitize-recover=all)
  endif()
  add_compile_options(-fsanitize=fuzzer-no-link,address,undefined ${_rk_fuzz_recover} -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# Ghidra install whose processor specs (.ldefs, .pspec, .cspec, .sla) we load.
set(GHIDRA_ROOT "$ENV{GHIDRA_INSTALL_DIR}" CACHE PATH "Ghidra installation root")
# Where the build writes the library type archives (tools/rk-typeinfo); a
# source build's tools read them from here, an installed one from
# share/revkit/typeinfo.
set(REVKIT_TYPEINFO_DIR ${CMAKE_BINARY_DIR}/typeinfo)
# The benchmark corpus (scripts/phase0.sh builds it); tests that use it skip
# when it is missing.
set(REVKIT_CORPUS_DIR "${PROJECT_SOURCE_DIR}/out/corpus" CACHE PATH "Built corpus binaries")

if(REVKIT_SANITIZE STREQUAL "address")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
elseif(REVKIT_SANITIZE STREQUAL "thread")
  add_compile_options(-fsanitize=thread)
  add_link_options(-fsanitize=thread)
endif()

if(REVKIT_REPRODUCIBLE)
  add_compile_options(-ffile-prefix-map=${PROJECT_SOURCE_DIR}=. -ffile-prefix-map=${PROJECT_BINARY_DIR}=build)
  add_link_options(-Wl,--build-id=sha1)
endif()
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
  # Optional (-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON); the release preset
  # leaves it off because GCC's LTO reports ODR violations in Ghidra's
  # bison parsers (docs/packaging.md). LTO links are the memory peaks: at
  # most two at a time, four LTRANS jobs each.
  set_property(GLOBAL APPEND PROPERTY JOB_POOLS revkit_lto_link=2)
  set(CMAKE_JOB_POOL_LINK revkit_lto_link)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_link_options(-flto=4)
  endif()
endif()

find_package(ZLIB REQUIRED)

if(REVKIT_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  include(GoogleTest)
  enable_testing()
endif()

add_subdirectory(third_party/ghidra)
add_subdirectory(third_party/llvm-demangle)
add_subdirectory(src)
add_subdirectory(tools/rk-asm)
add_subdirectory(tools/rk-backend-bench)
add_subdirectory(tools/rk-bsim)
add_subdirectory(tools/rk-cparse)
add_subdirectory(tools/rk-daemon)
add_subdirectory(tools/ghidra-interop)
add_subdirectory(tools/rk-dbg)
add_subdirectory(tools/rk-decomp)
add_subdirectory(tools/rk-decompd)
add_subdirectory(tools/rk-diff)
add_subdirectory(tools/rk-debuginfo)
add_subdirectory(tools/rk-dwarf)
add_subdirectory(tools/rk-emu)
add_subdirectory(tools/rk-fid)
add_subdirectory(tools/rk-factbench)
add_subdirectory(tools/rk-infer)
add_subdirectory(tools/rk-lift)
add_subdirectory(tools/rk-sandbox)
add_subdirectory(tools/rk-sigdiff)
add_subdirectory(tools/rk-sweep)
add_subdirectory(tools/rk-typeinfo)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
  add_subdirectory(tools/refdiff)
endif()

include(cmake/install.cmake)
