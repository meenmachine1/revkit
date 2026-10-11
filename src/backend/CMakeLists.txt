# revkit::backend — a revkit::api::Backend that serves real binaries: the
# loader, SLEIGH listings and the in-process Ghidra decompiler behind the
# API seam, with each project's assertions and derived facts in a
# revkit::facts::FactDb.
# Built only with the API component (system gRPC; see src/api).
if(NOT TARGET revkit::api)
  message(STATUS "revkit backend skipped: the API component is not built")
  return()
endif()

find_package(OpenSSL REQUIRED COMPONENTS Crypto)  # program hashes
# Regular expressions for the searches (search.cc): RE2, which gRPC already
# links, so the daemon gains no library.
pkg_check_modules(RK_RE2 REQUIRED IMPORTED_TARGET re2)

add_library(revkit_backend STATIC
  api_util.cc
  auto_struct.cc
  decompiler.cc
  debug_import.cc
  debugger.cc
  define_type.cc
  diff_detail.cc
  function_compare.cc
  diff_session.cc
  emulator.cc
  bsim_catalog.cc
  fid.cc
  filesystems.cc
  machines.cc
  libraries.cc
  image_backend.cc
  import_progress.cc
  model.cc
  msvc_import.cc
  own_inputs.cc
  param_id.cc
  parse_c.cc
  type_archive.cc
  patching.cc
  project_archive.cc
  program.cc
  queries.cc
  raw_detect.cc
  rebase.cc
  relocate.cc
  search.cc
  symbol_server.cc
  signatures.cc
  slice.cc
  sync_util.cc
  type_record.cc
  library_types.cc
  listing_edit.cc)
add_library(revkit::backend ALIAS revkit_backend)
target_include_directories(revkit_backend PUBLIC include PRIVATE .)
target_link_libraries(revkit_backend PUBLIC revkit::api revkit::decompd revkit::bsim revkit::diff revkit::facts revkit::fid revkit::analysis revkit::infer revkit::inputs revkit::plugins
  PRIVATE revkit::asm revkit::container revkit::cparse revkit::cparse_spec revkit::runtime revkit::debug revkit::demangle revkit::detect revkit::emu revkit::lift revkit::loader revkit::msvc revkit::patch revkit::debuginfo revkit::types revkit_httplib OpenSSL::Crypto ZLIB::ZLIB PkgConfig::RK_RE2)
target_compile_options(revkit_backend PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
