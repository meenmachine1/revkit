find_program(REVKIT_CLANG clang)
find_program(REVKIT_LLD ld.lld)
find_program(REVKIT_OBJCOPY NAMES llvm-objcopy llvm-objcopy-18)
find_program(REVKIT_LLD_LINK NAMES lld-link lld-link-18)
foreach(var REVKIT_CLANG REVKIT_LLD REVKIT_OBJCOPY REVKIT_LLD_LINK)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_backend_tests auto_struct_test.cc bsim_api_test.cc byte_view_test.cc collab_test.cc debugger_api_test.cc decompiler_test.cc diff_api_test.cc emulator_api_test.cc equates_test.cc fact_store_test.cc function_compare_test.cc firmware_api_test.cc
  image_backend_test.cc import_progress_test.cc listing_edit_test.cc memory_map_test.cc param_id_test.cc parse_c_test.cc patch_api_test.cc program_management_test.cc project_org_test.cc program_test.cc raw_detect_test.cc raw_import_test.cc search_test.cc signature_test.cc type_archive_test.cc
  views_test.cc library_test.cc project_types_test.cc callsite_test.cc demangle_test.cc rebase_test.cc msvc_test.cc hover_test.cc symbol_server_test.cc slice_test.cc libraries_test.cc
  data_settings_test.cc debug_files_test.cc http_fetch_test.cc extract_test.cc)
add_dependencies(revkit_backend_tests rk-decompd)
target_include_directories(revkit_backend_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/backend ${PROJECT_SOURCE_DIR}/src/loader/tests)
target_link_libraries(revkit_backend_tests PRIVATE revkit::backend revkit::debug revkit::detect revkit::lift revkit::loader revkit::debuginfo
  revkit::types revkit::facts revkit::inputs revkit::decompd revkit::asm revkit::patch revkit::auth revkit::container revkit_httplib OpenSSL::Crypto ZLIB::ZLIB GTest::gtest_main)
target_compile_options(revkit_backend_tests PRIVATE -Wall -Wextra)
target_compile_definitions(revkit_backend_tests PRIVATE
  REVKIT_GHIDRA_ROOT="${GHIDRA_ROOT}"
  REVKIT_TEST_CC="${CMAKE_C_COMPILER}"
  REVKIT_CORPUS="${REVKIT_CORPUS_DIR}"
  REVKIT_TEST_CLANG="${REVKIT_CLANG}"
  REVKIT_TEST_LLD="${REVKIT_LLD}"
  REVKIT_TEST_OBJCOPY="${REVKIT_OBJCOPY}"
  REVKIT_TEST_LLD_LINK="${REVKIT_LLD_LINK}"
  REVKIT_MSVC_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/msvc"
  REVKIT_ARMFW_DIR="${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armfw"
  REVKIT_FWEMU_DIR="${PROJECT_SOURCE_DIR}/src/emu/tests/fixtures/fwemu")
gtest_discover_tests(revkit_backend_tests DISCOVERY_TIMEOUT 60)
