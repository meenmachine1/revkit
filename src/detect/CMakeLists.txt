# Auto-detection of a raw image's processor, load address and header offset
# (docs/autodetect.md; include/revkit/detect/detect.hh).

add_library(revkit_detect STATIC
  candidates.cc
  detect.cc
  fit.cc
  layout.cc
  regions.cc
  segments.cc
  sweep.cc
  variants.cc)
add_library(revkit::detect ALIAS revkit_detect)
target_include_directories(revkit_detect PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(revkit_detect PUBLIC revkit::lift revkit::loader)
target_compile_options(revkit_detect PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
