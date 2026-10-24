# revkit::evm: Ethereum Virtual Machine bytecode (docs/evm.md): detection,
# where a file's runtime code is, the function dispatcher's selectors and a
# short table of well-known signatures, and computed jumps' targets from an
# abstract stack, for the image backend to assert at import.
add_library(revkit_evm STATIC evm.cc)
add_library(revkit::evm ALIAS revkit_evm)
target_include_directories(revkit_evm PUBLIC include)
target_link_libraries(revkit_evm PUBLIC revkit::loader)
target_compile_options(revkit_evm PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
