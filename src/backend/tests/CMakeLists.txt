find_program(REVKIT_CLANG clang)
find_program(REVKIT_LLD ld.lld)
find_program(REVKIT_OBJCOPY NAMES llvm-objcopy llvm-objcopy-18)
find_program(REVKIT_LLD_LINK NAMES lld-link lld-link-18)
find_program(REVKIT_LD64_LLD NAMES ld64.lld ld64.lld-18)
find_program(REVKIT_LLVM_LIPO NAMES llvm-lipo llvm-lipo-18)
find_program(REVKIT_LLVM_NM NAMES llvm-nm llvm-nm-18)
find_program(REVKIT_LLVM_OBJDUMP NAMES llvm-objdump llvm-objdump-18)
find_program(REVKIT_BACKEND_PYTHON python3)
# Go for go_test.cc ($RK_GO overrides it).
find_program(REVKIT_BACKEND_GO go HINTS $ENV{HOME}/.local/go/bin /usr/local/go/bin)
foreach(var REVKIT_BACKEND_PYTHON REVKIT_BACKEND_GO REVKIT_CLANG REVKIT_LLD REVKIT_OBJCOPY REVKIT_LLD_LINK REVKIT_LD64_LLD REVKIT_LLVM_LIPO REVKIT_LLVM_NM
            REVKIT_LLVM_OBJDUMP)
  if(NOT ${var})
    set(${var} "")
  endif()
endforeach()

add_executable(revkit_backend_tests auto_struct_test.cc bsim_api_test.cc byte_view_test.cc collab_test.cc debugger_api_test.cc decompiler_test.cc diff_api_test.cc emulator_api_test.cc equates_test.cc fact_store_test.cc function_compare_test.cc firmware_api_test.cc
  image_backend_test.cc import_progress_test.cc listing_edit_test.cc memory_map_test.cc param_id_test.cc parse_c_test.cc patch_api_test.cc program_management_test.cc project_org_test.cc program_test.cc raw_detect_test.cc raw_import_test.cc search_test.cc signature_test.cc type_archive_test.cc
  views_test.cc library_test.cc project_types_test.cc callsite_test.cc demangle_test.cc rebase_test.cc msvc_test.cc hover_test.cc symbol_server_test.cc slice_test.cc trace_test.cc libraries_test.cc
  data_settings_test.cc debug_files_test.cc http_fetch_test.cc extract_test.cc macho_test.cc go_test.cc evm_test.cc apple_test.cc nds_test.cc cxx_this_test.cc)
add_dependencies(revkit_backend_tests rk-decompd)
target_include_directories(revkit_backend_tests PRIVATE ${PROJECT_SOURCE_DIR}/src/backend ${PROJECT_SOURCE_DIR}/src/loader/tests
  ${PROJECT_SOURCE_DIR}/src/apple/tests ${PROJECT_SOURCE_DIR}/src/nds/tests)
target_link_libraries(revkit_backend_tests PRIVATE revkit::backend revkit::msvc revkit::nds revkit::debug revkit::detect revkit::lift revkit::loader revkit::debuginfo
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
  REVKIT_TEST_LD64="${REVKIT_LD64_LLD}"
  REVKIT_TEST_LIPO="${REVKIT_LLVM_LIPO}"
  REVKIT_TEST_NM="${REVKIT_LLVM_NM}"
  REVKIT_TEST_OBJDUMP="${REVKIT_LLVM_OBJDUMP}"
  REVKIT_TEST_GO="${REVKIT_BACKEND_GO}"
  REVKIT_MACHO_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/macho"
  REVKIT_EVM_DATA="${PROJECT_SOURCE_DIR}/tests/data/evm"
  REVKIT_APPLE_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/apple"
  REVKIT_MSVC_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/msvc"
  REVKIT_NDS_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/nds"
  REVKIT_NDS_PYTHON="${REVKIT_BACKEND_PYTHON}"
  REVKIT_ARM32_FIXTURE="${PROJECT_SOURCE_DIR}/tests/data/arm32"
  REVKIT_ARMFW_DIR="${PROJECT_SOURCE_DIR}/src/analysis/tests/fixtures/armfw"
  REVKIT_FWEMU_DIR="${PROJECT_SOURCE_DIR}/src/emu/tests/fixtures/fwemu")
gtest_discover_tests(revkit_backend_tests DISCOVERY_TIMEOUT 60)
