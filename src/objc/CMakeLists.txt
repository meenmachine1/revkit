# revkit::objc: Objective-C and Swift metadata of Mach-O images
# (docs/macho.md), as typed data, names, functions and prototypes for the
# image backend to assert. The markup uses revkit::msvc's model.
add_library(revkit_objc STATIC markup.cc objc.cc swift.cc)
add_library(revkit::objc ALIAS revkit_objc)
target_include_directories(revkit_objc PUBLIC include)
target_link_libraries(revkit_objc PUBLIC revkit::loader revkit::msvc revkit::types)
target_compile_options(revkit_objc PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
