# revkit::facts — assertion log, incremental query engine, storage backends.

include(FetchContent)

# LMDB ships no CMake build; it is two C files, so build them here.
FetchContent_Declare(lmdb
  URL https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz
  URL_HASH SHA256=dd70a8c67807b3b8532b3e987b0a4e998962ecc28643e1af5ec77696b081c9b0
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SOURCE_SUBDIR no-cmake)
FetchContent_MakeAvailable(lmdb)

set(LMDB_DIR ${lmdb_SOURCE_DIR}/libraries/liblmdb)
add_library(revkit_lmdb STATIC ${LMDB_DIR}/mdb.c ${LMDB_DIR}/midl.c)
target_include_directories(revkit_lmdb SYSTEM PUBLIC ${LMDB_DIR})
find_package(Threads REQUIRED)
target_link_libraries(revkit_lmdb PUBLIC Threads::Threads)
set_target_properties(revkit_lmdb PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(REVKIT_SANITIZE STREQUAL "thread")
  # LMDB shares its reader table and meta pages lock-free by design (volatile
  # reads ordered by its own barriers). Build it uninstrumented, like the
  # system libraries in tools/sanitizers/tsan.supp, so TSan reports only
  # races involving our code.
  get_target_property(lmdb_opts revkit_lmdb COMPILE_OPTIONS)
  list(REMOVE_ITEM lmdb_opts -fsanitize=thread)
  set_target_properties(revkit_lmdb PROPERTIES COMPILE_OPTIONS "${lmdb_opts}")
endif()

add_library(revkit_facts STATIC
  address.cc
  assertion_log.cc
  engine.cc
  fact.cc
  fact_db.cc
  fingerprint.cc
  lmdb_storage.cc
  memory_storage.cc
  thread_pool.cc)
add_library(revkit::facts ALIAS revkit_facts)
target_include_directories(revkit_facts PUBLIC include)
target_link_libraries(revkit_facts PUBLIC Threads::Threads PRIVATE revkit_lmdb)
target_compile_options(revkit_facts PRIVATE -Wall -Wextra)

# Toy ISA, synthetic program generator and analysis queries, shared by the
# tests and tools/rk-factbench.
add_library(revkit_facts_testing STATIC testing/toy_program.cc)
add_library(revkit::facts_testing ALIAS revkit_facts_testing)
target_include_directories(revkit_facts_testing PUBLIC testing)
target_link_libraries(revkit_facts_testing PUBLIC revkit::facts)
target_compile_options(revkit_facts_testing PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
