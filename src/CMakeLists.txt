# Each component is a library under src/<name>/ with its own CMakeLists.txt,
# public headers in src/<name>/include/revkit/<name>/, and tests in
# src/<name>/tests/ (GoogleTest, registered with gtest_discover_tests).
# Add one add_subdirectory() line per component, keeping them sorted.
#
# Tests that run our binaries through a script (sh, python) must start with
# ${CMAKE_CROSSCOMPILING_EMULATOR}: the tsan preset sets it to `setarch -R`,
# without which TSan binaries abort at startup on this kernel.

add_subdirectory(analysis)
add_subdirectory(android)
add_subdirectory(api)
add_subdirectory(apple)
add_subdirectory(asm)
add_subdirectory(auth)
add_subdirectory(backend)
add_subdirectory(bsim)
add_subdirectory(container)
add_subdirectory(cparse)
add_subdirectory(crash)
add_subdirectory(debug)
add_subdirectory(debuginfo)
add_subdirectory(decompd)
add_subdirectory(demangle)
add_subdirectory(detect)
add_subdirectory(diff)
add_subdirectory(emu)
add_subdirectory(evm)
add_subdirectory(facts)
add_subdirectory(fid)
add_subdirectory(infer)
add_subdirectory(inputs)
add_subdirectory(lift)
add_subdirectory(loader)
add_subdirectory(msvc)
add_subdirectory(nds)
add_subdirectory(objc)
add_subdirectory(patch)
add_subdirectory(plugins)
add_subdirectory(providers)
add_subdirectory(runtime)
add_subdirectory(types)
