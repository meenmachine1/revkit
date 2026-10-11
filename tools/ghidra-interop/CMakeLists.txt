# Ghidra <-> revkit interop (Python; docs/ghidra-interop.md). Registers:
#   ghidra_interop_mapping  the JSON mapping's unit tests, plus a quick import
#                           into rk-daemon (seconds; no Ghidra needed)
#   ghidra_roundtrip        the headless round trip through Ghidra (about 30 s;
#                           skipped without the PyGhidra venv or the corpus)
# Both need REVKIT_PYTHON (see tools/rk-daemon) with grpcio and pytest.
if(NOT REVKIT_BUILD_TESTS OR NOT TARGET rk-daemon OR NOT REVKIT_PYTHON)
  return()
endif()
execute_process(COMMAND "${REVKIT_PYTHON}" -c "import grpc, google.protobuf, pytest"
                RESULT_VARIABLE _rk_py_ok OUTPUT_QUIET ERROR_QUIET)
if(NOT _rk_py_ok EQUAL 0)
  message(STATUS "No Python with grpcio/protobuf/pytest at REVKIT_PYTHON: skipping the Ghidra interop tests")
  return()
endif()

set(_rk_env "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PYTHONPATH=${PROJECT_SOURCE_DIR}/sdk/python;PYTHONDONTWRITEBYTECODE=1")
add_test(NAME ghidra_interop_mapping
  COMMAND "${REVKIT_PYTHON}" -m pytest -q -p no:cacheprovider tests
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set_tests_properties(ghidra_interop_mapping PROPERTIES ENVIRONMENT "${_rk_env}" TIMEOUT 120)

set(REVKIT_PYGHIDRA "$ENV{HOME}/.local/share/revkit-pyghidra/bin/python" CACHE FILEPATH
    "PyGhidra venv python for the ghidra_roundtrip test (scripts/setup-pyghidra.sh)")
add_test(NAME ghidra_roundtrip
  COMMAND "${REVKIT_PYTHON}" ${CMAKE_CURRENT_SOURCE_DIR}/roundtrip_test.py
          --binary ${PROJECT_SOURCE_DIR}/out/corpus/elf-x86_64/gcc-O0/stripped/features)
set_tests_properties(ghidra_roundtrip PROPERTIES
  ENVIRONMENT "${_rk_env};REVKIT_PYGHIDRA=${REVKIT_PYGHIDRA};GHIDRA_INSTALL_DIR=${GHIDRA_ROOT}"
  SKIP_RETURN_CODE 77 TIMEOUT 300 PROCESSORS 4 RESOURCE_LOCK ghidra LABELS ghidra)

# Ghidra's C parser reads revkit's type archives (docs/types.md#type-archives):
# the corpus debug builds' types exported as archives, parsed by Ghidra
# through PyGhidra for each binary's language, and every layout compared
# with revkit's. Skipped without the PyGhidra venv or the corpus.
add_test(NAME type_archive_ghidra
  COMMAND "${REVKIT_PYTHON}" ${CMAKE_CURRENT_SOURCE_DIR}/type_archive_check.py
          --rk-debuginfo $<TARGET_FILE:rk-debuginfo> --rk-cparse $<TARGET_FILE:rk-cparse>
          --pyghidra ${REVKIT_PYGHIDRA} --corpus ${PROJECT_SOURCE_DIR}/out/corpus)
set_tests_properties(type_archive_ghidra PROPERTIES
  ENVIRONMENT "GHIDRA_INSTALL_DIR=${GHIDRA_ROOT}"
  SKIP_RETURN_CODE 77 TIMEOUT 600 PROCESSORS 2 RESOURCE_LOCK ghidra LABELS ghidra)

# The same archives through a real compiler for each target (clang
# -fsyntax-only): every _Static_assert of a size holds.
if(REVKIT_CLANG)
  add_test(NAME type_archive_compile
    COMMAND "${REVKIT_PYTHON}" ${CMAKE_CURRENT_SOURCE_DIR}/type_archive_check.py --compile-only
            --rk-debuginfo $<TARGET_FILE:rk-debuginfo> --rk-cparse $<TARGET_FILE:rk-cparse>
            --clang ${REVKIT_CLANG} --corpus ${PROJECT_SOURCE_DIR}/out/corpus)
  set_tests_properties(type_archive_compile PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)
endif()

# The Ghidra compatibility corpus (sdk/python/tests/ghidra_corpus,
# docs/scripting.md#running-ghidra-scripts): 30 of Ghidra's own scripts run
# under revkit.ghidra.compat and, live through PyGhidra, in Ghidra, on the
# SDK fixture and (when scripts/build-corpus.sh built it) the corpus program
# features; the gate is 20 agreeing per program. Skipped without the
# PyGhidra venv. The python_sdk test runs the same scripts against Ghidra's
# recorded results.
add_test(NAME ghidra_compat_corpus
  COMMAND "${REVKIT_PYTHON}" ${PROJECT_SOURCE_DIR}/sdk/python/tests/ghidra_corpus/run.py
          --programs fixture,features --ghidra live)
set_tests_properties(ghidra_compat_corpus PROPERTIES
  ENVIRONMENT "${_rk_env};REVKIT_PYGHIDRA=${REVKIT_PYGHIDRA};GHIDRA_INSTALL_DIR=${GHIDRA_ROOT};RK_CORPUS_DIR=${PROJECT_SOURCE_DIR}/out/corpus"
  SKIP_RETURN_CODE 77 TIMEOUT 1200 PROCESSORS 4 RESOURCE_LOCK ghidra LABELS ghidra)
