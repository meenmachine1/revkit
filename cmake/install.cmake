# Install rules and CPack for a relocatable revkit (docs/packaging.md):
#
#   <prefix>/bin/                 rk-daemon, rk-decompd (its decompiler worker,
#                                 found beside it), rk-sandbox (the external
#                                 decompilers' sandbox, found beside it), rk-lift,
#                                 rk-decomp, rk-emu, rk-dbg, rk-diff, rk-infer,
#                                 rk-debuginfo, rk-cparse, rk-bsim
#   <prefix>/lib/revkit/          private shared libraries (REVKIT_BUNDLE_LIBS)
#   <prefix>/share/revkit/ui/     the web UI (REVKIT_UI_DIST, when built)
#   <prefix>/share/revkit/ghidra/ Ghidra's processor specs (REVKIT_GHIDRA_SPECS,
#                                 from scripts/gather-ghidra-specs.sh)
#   <prefix>/share/revkit/plugins/ the example WebAssembly plugins (when built)
#   <prefix>/share/revkit/scripts/ the starter scripts (ScriptService's shipped library)
#   <prefix>/share/revkit/python/ the Python SDK's wheel (REVKIT_PYTHON_WHEEL, when given),
#                                 which bin/rk-script makes the scripts' Python from
#   <prefix>/share/doc/revkit/    README, getting started, THIRD_PARTY_NOTICES
#
# Executables carry an RPATH of $ORIGIN/../lib/revkit (DT_RPATH, not RUNPATH,
# so it also applies to the bundled libraries' own dependencies), and look
# for share/revkit relative to themselves (revkit::runtime), so the tree
# runs from any directory. scripts/package.sh drives this.

include(GNUInstallDirs)

set(REVKIT_SHIPPED_TOOLS rk-daemon rk-decompd rk-sandbox rk-lift rk-decomp rk-emu rk-dbg rk-diff rk-infer rk-debuginfo rk-cparse rk-bsim)
set(REVKIT_UI_DIST "${PROJECT_SOURCE_DIR}/ui/dist" CACHE PATH "Built web UI to install as share/revkit/ui")
set(REVKIT_GHIDRA_SPECS "" CACHE PATH
    "Ghidra spec tree to install as share/revkit/ghidra (scripts/gather-ghidra-specs.sh output; empty: none)")
option(REVKIT_BUNDLE_LIBS "Install the executables' non-glibc shared libraries into lib/revkit" OFF)
set(REVKIT_EXTRA_LICENSES "" CACHE PATH
    "More license texts to install under share/doc/revkit/licenses (scripts/package.sh: npm, debian)")
set(REVKIT_PYTHON_WHEEL "" CACHE FILEPATH
    "The Python SDK wheel to install as share/revkit/python (scripts/package.sh builds it; empty: none)")

set(_installed)
foreach(t IN LISTS REVKIT_SHIPPED_TOOLS)
  if(TARGET ${t})
    list(APPEND _installed ${t})
    set_target_properties(${t} PROPERTIES INSTALL_RPATH "$ORIGIN/../lib/revkit")
    target_link_options(${t} PRIVATE "LINKER:--disable-new-dtags")
  endif()
endforeach()

if(REVKIT_BUNDLE_LIBS)
  cmake_minimum_required(VERSION 3.21)  # install(RUNTIME_DEPENDENCY_SET)
  install(TARGETS ${_installed} RUNTIME_DEPENDENCY_SET revkit_deps RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  # Everything but glibc and the C++ runtime, which every target system has
  # (and which must match the system's loader).
  install(RUNTIME_DEPENDENCY_SET revkit_deps
    PRE_EXCLUDE_REGEXES
      "^ld-linux" "^linux-vdso" "^libc\\.so" "^libm\\.so" "^libdl\\.so" "^libpthread\\.so" "^librt\\.so"
      "^libresolv\\.so" "^libutil\\.so" "^libstdc\\+\\+\\.so" "^libgcc_s\\.so"
    POST_EXCLUDE_REGEXES "^/lib/ld-linux" "^/lib64/ld-linux"
    LIBRARY DESTINATION lib/revkit)
else()
  install(TARGETS ${_installed} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY "${REVKIT_UI_DIST}/" DESTINATION share/revkit/ui OPTIONAL
        PATTERN "*.map" EXCLUDE)
if(REVKIT_GHIDRA_SPECS)
  install(DIRECTORY "${REVKIT_GHIDRA_SPECS}/" DESTINATION share/revkit/ghidra)
endif()
if(TARGET revkit_example_plugins)
  install(DIRECTORY "${CMAKE_BINARY_DIR}/plugins/" DESTINATION share/revkit/plugins OPTIONAL)
endif()
# revkit: starts the server with sensible defaults and opens the browser
# (docs/getting-started.md, "The revkit command").
install(PROGRAMS packaging/revkit DESTINATION ${CMAKE_INSTALL_BINDIR})
# The starter scripts: the daemon's shipped script library (docs/scripting.md).
install(DIRECTORY sdk/python/revkit/scripts/ DESTINATION share/revkit/scripts
        FILES_MATCHING PATTERN "*.py" PATTERN "__init__.py" EXCLUDE PATTERN "__pycache__" EXCLUDE)
# The Python SDK, and rk-script, which runs it from the environment the
# daemon runs scripts with, made from that wheel on first use
# (docs/scripting.md#rk-script).
if(REVKIT_PYTHON_WHEEL)
  install(FILES "${REVKIT_PYTHON_WHEEL}" DESTINATION share/revkit/python)
  install(PROGRAMS packaging/linux/rk-script DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
# systemd user units: rk-daemon started on the first connection to its HTTP
# port (socket activation; opt in with systemctl --user enable --now
# revkit-daemon.socket; docs/packaging.md). They run /usr/bin/rk-daemon,
# the .deb's; the portable bundle carries them for reference.
install(FILES packaging/linux/systemd/revkit-daemon.socket packaging/linux/systemd/revkit-daemon.service
        DESTINATION lib/systemd/user)
# A system socket on port 80 of the loopback addresses, forwarding to the
# daemon's port: http://revkit.localhost without a port, rk-daemon keeping
# no privilege. Off until enabled (sudo systemctl enable --now
# revkit-http80.socket; docs/getting-started.md).
install(FILES packaging/linux/systemd/revkit-http80.socket packaging/linux/systemd/revkit-http80.service
        DESTINATION lib/systemd/system)
# The C plugin SDK and the example plugins' sources (docs/plugins.md).
install(DIRECTORY sdk/plugins/c sdk/plugins/examples DESTINATION share/revkit/sdk/plugins)
install(FILES LICENSE README.md THIRD_PARTY_NOTICES.md docs/getting-started.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES third_party/ghidra/GHIDRA_LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses RENAME Ghidra-Apache-2.0.txt)
install(FILES third_party/llvm-demangle/LICENSE.TXT DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses
        RENAME LLVM-Apache-2.0-with-LLVM-exception.txt)
install(FILES third_party/rea/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses RENAME rea-MIT.txt)
if(REVKIT_EXTRA_LICENSES)
  install(DIRECTORY "${REVKIT_EXTRA_LICENSES}/" DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses OPTIONAL)
endif()
# The fetched dependencies compiled in (THIRD_PARTY_NOTICES.md).
include(FetchContent)
FetchContent_GetProperties(lmdb SOURCE_DIR _lmdb)
FetchContent_GetProperties(cpp_httplib SOURCE_DIR _httplib)
FetchContent_GetProperties(wasmtime SOURCE_DIR _wasmtime)
if(_lmdb)
  install(FILES ${_lmdb}/libraries/liblmdb/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses RENAME LMDB-OpenLDAP-2.8.txt)
  install(FILES ${_lmdb}/libraries/liblmdb/COPYRIGHT DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses RENAME LMDB-COPYRIGHT.txt)
endif()
if(_httplib)
  install(FILES ${_httplib}/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses RENAME cpp-httplib-MIT.txt)
endif()
if(_wasmtime)
  install(FILES ${_wasmtime}/LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR}/licenses
          RENAME wasmtime-Apache-2.0-with-LLVM-exception.txt)
endif()

# ---- CPack: .deb (scripts/package.sh) ---------------------------------------
set(CPACK_PACKAGE_NAME revkit)
set(CPACK_PACKAGE_VERSION ${REVKIT_FULL_VERSION})  # 0.1.0~git… between releases
set(CPACK_PACKAGE_VENDOR "revkit")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Reverse-engineering daemon, CLIs and web UI built on Ghidra's decompiler")
set(CPACK_PACKAGE_CONTACT "revkit maintainers <noreply@revkit.invalid>")
set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION devel)
# Debian's name for the architecture built for (amd64, arm64).
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE arm64)
else()
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE amd64)
endif()
# Private libraries live in /usr/lib/revkit, so only the C and C++ runtimes
# are dependencies: glibc 2.34 (the newest symbol version the binaries use)
# and GCC 12's libstdc++ (GLIBCXX_3.4.30): Ubuntu 22.04, Debian 12 and later.
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.34), libstdc++6 (>= 12)")
# Scripts (rk-script, the Script Manager) run in a Python environment made
# from the shipped wheel: wanted, never required (the daemon, the CLIs and
# the web UI need no Python).
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "python3 (>= 3.10), python3-venv")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
    "revkit serves binaries to a web UI, Python and TypeScript SDKs and AI agents over\n gRPC and Connect, with Ghidra's decompiler and SLEIGH engine linked in.")
set(CPACK_STRIP_FILES ON)
set(CPACK_SOURCE_GENERATOR "")
include(CPack)
