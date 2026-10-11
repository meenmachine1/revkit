# revkit::plugins — the WebAssembly plugin host (wasmtime), the plugin
# interface, and plugins as fact-engine queries (docs/plugins.md).
#
# wasmtime comes as its prebuilt C API release, pinned by version and
# SHA-256 (about 16 MB to download, nothing to compile). Building it from
# source needs a Rust toolchain and several CPU-minutes per build directory
# (default, asan, tsan); the release archive is what wasmtime publishes for
# embedders. Linux x86-64 and aarch64 are fetched; elsewhere, or with
# -DREVKIT_PLUGINS=OFF, the library builds without a runtime and loading a
# plugin fails with a message saying so.
#
# Example plugins (sdk/plugins/examples) are compiled to wasm32 with clang
# and wasm-ld when both are present, into ${CMAKE_BINARY_DIR}/plugins
# (rk-daemon --plugin-dir build/plugins); otherwise they are skipped with a
# message, and so are the tests that need them.

option(REVKIT_PLUGINS "WebAssembly plugins: fetch the prebuilt wasmtime C API" ON)

set(REVKIT_WASMTIME_VERSION 49.0.2)
set(REVKIT_WASMTIME_SHA256_x86_64 4818e139aeb83b7adbaaf41b267bf18992c18463ae26d1a9acdcfc63ea9eb316)
set(REVKIT_WASMTIME_SHA256_aarch64 a97a874152b5fb49c4720b39b96a71d00ba61eab5ad59976163b7ddd1a3b14c0)
set(revkit_wasmtime_arch "")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
  set(revkit_wasmtime_arch x86_64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(revkit_wasmtime_arch aarch64)
endif()

set(revkit_have_wasmtime OFF)
if(REVKIT_PLUGINS)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND revkit_wasmtime_arch)
    include(FetchContent)
    FetchContent_Declare(wasmtime
      URL https://github.com/bytecodealliance/wasmtime/releases/download/v${REVKIT_WASMTIME_VERSION}/wasmtime-v${REVKIT_WASMTIME_VERSION}-${revkit_wasmtime_arch}-linux-c-api.tar.xz
      URL_HASH SHA256=${REVKIT_WASMTIME_SHA256_${revkit_wasmtime_arch}}
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE
      SOURCE_SUBDIR no-cmake)
    FetchContent_MakeAvailable(wasmtime)
    find_package(Threads REQUIRED)
    add_library(revkit_wasmtime STATIC IMPORTED GLOBAL)
    set_target_properties(revkit_wasmtime PROPERTIES
      IMPORTED_LOCATION ${wasmtime_SOURCE_DIR}/lib/libwasmtime.a
      INTERFACE_INCLUDE_DIRECTORIES ${wasmtime_SOURCE_DIR}/include)
    target_link_libraries(revkit_wasmtime INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)
    set(revkit_have_wasmtime ON)
    message(STATUS "revkit plugins: wasmtime ${REVKIT_WASMTIME_VERSION} (prebuilt C API)")
  else()
    message(WARNING "revkit plugins: no prebuilt wasmtime for ${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}; "
                    "the plugin host is built without a WebAssembly runtime")
  endif()
else()
  message(STATUS "revkit plugins: REVKIT_PLUGINS=OFF, the plugin host is built without a WebAssembly runtime")
endif()

add_library(revkit_plugins STATIC
  guest_copy.cc
  host.cc
  load.cc
  manifest.cc
  peripheral.cc
  queries.cc)
add_library(revkit::plugins ALIAS revkit_plugins)
target_include_directories(revkit_plugins PUBLIC include
  PRIVATE ${PROJECT_SOURCE_DIR}/src/analysis)  # analysis's pooled decoder (internal.h)
target_link_libraries(revkit_plugins PUBLIC revkit::facts revkit::analysis revkit::loader revkit::emu PRIVATE revkit::lift)
target_compile_options(revkit_plugins PRIVATE -Wall -Wextra)
if(REVKIT_SANITIZE STREQUAL "thread")
  # Copies into guest memory, which wasmtime maps behind TSan's back: built
  # uninstrumented, and kept from turning into calls to the intercepted
  # memcpy (see guest_copy.cc). The only TSan exclusion for plugins.
  set_source_files_properties(guest_copy.cc PROPERTIES COMPILE_OPTIONS
    "-fno-sanitize=thread;-fno-builtin;$<$<CXX_COMPILER_ID:GNU>:-fno-tree-loop-distribute-patterns>")
endif()
if(revkit_have_wasmtime)
  target_link_libraries(revkit_plugins PRIVATE revkit_wasmtime)
  target_compile_definitions(revkit_plugins PRIVATE REVKIT_HAVE_WASMTIME)
endif()

# ---- example plugins (wasm32, clang + wasm-ld) ----------------------------------
set(REVKIT_PLUGIN_SDK ${PROJECT_SOURCE_DIR}/sdk/plugins)
set(REVKIT_PLUGIN_OUT ${CMAKE_BINARY_DIR}/plugins)
find_program(REVKIT_WASM_CC NAMES clang-18 clang)
set(revkit_wasm_ok OFF)
if(REVKIT_WASM_CC)
  set(_probe_dir ${CMAKE_CURRENT_BINARY_DIR}/wasm-probe)
  file(MAKE_DIRECTORY ${_probe_dir})
  file(WRITE ${_probe_dir}/probe.c "int f(int x) { return x + 1; }\n")
  execute_process(
    COMMAND ${REVKIT_WASM_CC} --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export=f -o ${_probe_dir}/probe.wasm ${_probe_dir}/probe.c
    RESULT_VARIABLE _probe_rc OUTPUT_QUIET ERROR_QUIET)
  if(_probe_rc EQUAL 0)
    set(revkit_wasm_ok ON)
  endif()
endif()

set(REVKIT_PLUGIN_EXAMPLES crc32-tables string-refs rkraw-loader rename-regex tick-timer)
if(revkit_wasm_ok)
  message(STATUS "revkit plugins: building the example plugins with ${REVKIT_WASM_CC} into ${REVKIT_PLUGIN_OUT}")
  file(MAKE_DIRECTORY ${REVKIT_PLUGIN_OUT})
  set(_sdk_c ${REVKIT_PLUGIN_SDK}/c/revkit_plugin.c)
  set(_sdk_h ${REVKIT_PLUGIN_SDK}/c/revkit_plugin.h)
  set(_outputs)
  foreach(name IN LISTS REVKIT_PLUGIN_EXAMPLES)
    set(_dir ${REVKIT_PLUGIN_SDK}/examples/${name})
    file(GLOB _srcs CONFIGURE_DEPENDS ${_dir}/*.c)
    add_custom_command(
      OUTPUT ${REVKIT_PLUGIN_OUT}/${name}.wasm
      COMMAND ${REVKIT_WASM_CC} --target=wasm32 -O2 -std=c11 -ffreestanding -nostdlib -Wall -Wextra -Werror
              -I${REVKIT_PLUGIN_SDK}/c -Wl,--no-entry -Wl,-z,stack-size=131072 -Wl,--strip-debug
              -o ${REVKIT_PLUGIN_OUT}/${name}.wasm ${_srcs} ${_sdk_c}
      DEPENDS ${_srcs} ${_sdk_c} ${_sdk_h}
      COMMENT "wasm32 plugin ${name}"
      VERBATIM)
    add_custom_command(
      OUTPUT ${REVKIT_PLUGIN_OUT}/${name}.json
      COMMAND ${CMAKE_COMMAND} -E copy ${_dir}/${name}.json ${REVKIT_PLUGIN_OUT}/${name}.json
      DEPENDS ${_dir}/${name}.json
      VERBATIM)
    list(APPEND _outputs ${REVKIT_PLUGIN_OUT}/${name}.wasm ${REVKIT_PLUGIN_OUT}/${name}.json)
  endforeach()
  add_custom_target(revkit_example_plugins ALL DEPENDS ${_outputs})
  set(REVKIT_EXAMPLE_PLUGINS_DIR ${REVKIT_PLUGIN_OUT} CACHE INTERNAL "")
else()
  message(STATUS "revkit plugins: example plugins skipped (needs clang with the wasm32 target and wasm-ld)")
  set(REVKIT_EXAMPLE_PLUGINS_DIR "" CACHE INTERNAL "")
endif()

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
