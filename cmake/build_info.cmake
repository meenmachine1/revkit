# Writes OUTPUT, a header with revkit's version and the source's git commit,
# touching it only when the content changes (so a build that changes nothing
# relinks nothing). Run at build time by src/runtime:
#
#   cmake -DSOURCE_DIR=... -DOUTPUT=... -DVERSION=0.1.0 [-DGIT_SHA=sha] -P build_info.cmake
#
# GIT_SHA overrides `git rev-parse` (packaging builds from a tree without
# .git pass it in); without either it is "unknown".
if(NOT GIT_SHA)
  execute_process(
    COMMAND git rev-parse --short=12 HEAD
    WORKING_DIRECTORY ${SOURCE_DIR}
    OUTPUT_VARIABLE GIT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE rc)
  if(NOT rc EQUAL 0 OR GIT_SHA STREQUAL "")
    set(GIT_SHA "unknown")
  endif()
endif()
set(content "#pragma once\n#define REVKIT_VERSION \"${VERSION}\"\n#define REVKIT_GIT_SHA \"${GIT_SHA}\"\n")
if(EXISTS ${OUTPUT})
  file(READ ${OUTPUT} old)
endif()
if(NOT old STREQUAL content)
  file(WRITE ${OUTPUT} "${content}")
endif()
