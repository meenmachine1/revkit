# BSim signature databases (docs/bsim.md): a persistent store of
# executables' functions and their BSim feature vectors, an LSH index, and
# similar-function search. JSON from tools/rk-lift/json.cc (compiled here:
# a binary linking revkit_bsim mustn't compile it again).
add_library(revkit_bsim STATIC
  store.cc
  ${PROJECT_SOURCE_DIR}/tools/rk-lift/json.cc
)
add_library(revkit::bsim ALIAS revkit_bsim)
target_include_directories(revkit_bsim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${PROJECT_SOURCE_DIR}/tools/rk-lift)
target_link_libraries(revkit_bsim PUBLIC revkit::diff)
target_compile_options(revkit_bsim PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
