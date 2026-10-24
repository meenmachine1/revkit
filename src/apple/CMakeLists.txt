# revkit::apple: Apple application formats read as data
# (docs/apple-apps.md): property lists (XML and bplist00), Info.plist
# keys and bundle kinds, embedded code signatures and provisioning
# profiles (CMS, not verified), Interface Builder's compiled nibs
# (NIBArchive and keyed archives). Its only dependency is OpenSSL's
# libcrypto (a CodeDirectory's cdhash).
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(revkit_apple STATIC bundle.cc codesign.cc der.cc ib.cc plist.cc)
add_library(revkit::apple ALIAS revkit_apple)
target_include_directories(revkit_apple PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_apple PRIVATE OpenSSL::Crypto)
target_compile_options(revkit_apple PRIVATE -Wall -Wextra)
set_target_properties(revkit_apple PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
