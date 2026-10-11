# Built only when the API component is (it needs system gRPC; see src/api).
if(NOT TARGET revkit::api)
  return()
endif()
# The authentication mode's choice (flags, revkit.conf, the first-run
# question), apart so its test can drive it.
add_library(rk_daemon_auth_choice STATIC auth_choice.cc)
target_include_directories(rk_daemon_auth_choice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(rk_daemon_auth_choice PRIVATE -Wall -Wextra)
add_executable(rk-daemon main.cc)
target_link_libraries(rk-daemon PRIVATE rk_daemon_auth_choice revkit::api revkit::backend revkit::container revkit::plugins
                                        revkit::runtime)
if(REVKIT_BUILD_TESTS)
  add_executable(rk_daemon_auth_choice_test auth_choice_test.cc)
  target_link_libraries(rk_daemon_auth_choice_test PRIVATE rk_daemon_auth_choice GTest::gtest_main)
  target_compile_options(rk_daemon_auth_choice_test PRIVATE -Wall -Wextra)
  gtest_discover_tests(rk_daemon_auth_choice_test DISCOVERY_TIMEOUT 60)
endif()
target_compile_definitions(rk-daemon PRIVATE REVKIT_DEFAULT_GHIDRA_ROOT="${GHIDRA_ROOT}"
                                             REVKIT_DEFAULT_WEB_ROOT="${PROJECT_SOURCE_DIR}/ui/dist"
                                             REVKIT_SOURCE_SDK_PYTHON="${PROJECT_SOURCE_DIR}/sdk/python")
target_compile_options(rk-daemon PRIVATE -Wall -Wextra)

# python_sdk and ui_e2e drive whole daemons (and a browser): under a sanitizer
# on a busy machine they run several times slower, so they get three times
# as long.
set(_rk_e2e_timeout 300)
set(_rk_e2e_scale 1)
# ui_e2e runs in five memory-capped parts, one after another (ui/e2e/run.sh);
# python_sdk is some 250 tests, each with its daemons (about 10 minutes on a
# busy machine).
set(_rk_ui_e2e_timeout 1800)
set(_rk_py_sdk_timeout 900)
if(REVKIT_SANITIZE)
  set(_rk_e2e_timeout 900)
  set(_rk_e2e_scale 3)
  set(_rk_ui_e2e_timeout 5400)
  set(_rk_py_sdk_timeout 2700)
endif()

# The Python SDK's tests start this daemon and talk to it over gRPC and
# Connect. They need a Python with grpcio and protobuf; point REVKIT_PYTHON
# at one (default: the venv docs/api.md sets up).
if(REVKIT_BUILD_TESTS)
  set(REVKIT_PYTHON "$ENV{HOME}/.cache/revkit/venv/bin/python" CACHE FILEPATH
      "Python with grpcio, protobuf and pytest, for the SDK tests")
  set(_py_ok 1)
  if(EXISTS "${REVKIT_PYTHON}")
    execute_process(COMMAND "${REVKIT_PYTHON}" -c "import grpc, google.protobuf, pytest"
                    RESULT_VARIABLE _py_ok OUTPUT_QUIET ERROR_QUIET)
  endif()
  if(_py_ok EQUAL 0)
    # In four parts (python_sdk_1..4, label python_sdk), the test modules dealt
    # round-robin: the whole suite took 500 s on a loaded host, over one
    # entry's timeout; the parts run in parallel and each stays well under.
    file(GLOB _py_modules CONFIGURE_DEPENDS RELATIVE ${PROJECT_SOURCE_DIR}/sdk/python
         ${PROJECT_SOURCE_DIR}/sdk/python/tests/test_*.py)
    list(SORT _py_modules)
    set(_py_parts 4)
    foreach(_g RANGE 1 ${_py_parts})
      set(_py_part_${_g} "")
    endforeach()
    set(_i 0)
    foreach(_m ${_py_modules})
      math(EXPR _g "${_i} % ${_py_parts} + 1")
      list(APPEND _py_part_${_g} ${_m})
      math(EXPR _i "${_i} + 1")
    endforeach()
    foreach(_g RANGE 1 ${_py_parts})
      add_test(NAME python_sdk_${_g}
        COMMAND "${REVKIT_PYTHON}" -m pytest -q -p no:cacheprovider ${_py_part_${_g}}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/python)
      set_tests_properties(python_sdk_${_g} PROPERTIES
        ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;RK_LIFT=$<TARGET_FILE:rk-lift>;RK_PLUGIN_DIR=${REVKIT_EXAMPLE_PLUGINS_DIR};PYTHONPATH=${PROJECT_SOURCE_DIR}/sdk/python;PYTHONDONTWRITEBYTECODE=1"
        TIMEOUT ${_rk_py_sdk_timeout} LABELS python_sdk)
    endforeach()
  else()
    message(STATUS "No Python with grpcio/protobuf/pytest at REVKIT_PYTHON: skipping python_sdk test")
  endif()
endif()

# Socket activation (systemd's protocol, played by the test): a request
# waiting on the inherited socket is answered, default authentication
# applies, and the listener rules hold. Python's standard library only.
if(REVKIT_BUILD_TESTS)
  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(NAME daemon_socket_activation
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/socket_activation_test.py $<TARGET_FILE:rk-daemon>)
    set_tests_properties(daemon_socket_activation PROPERTIES TIMEOUT 120)
    # MetaService.RestartDaemon: re-exec in the same process, a dry run,
    # a viewer refused, and an exit under socket activation.
    add_test(NAME daemon_restart
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/restart_test.py $<TARGET_FILE:rk-daemon>)
    set_tests_properties(daemon_restart PROPERTIES TIMEOUT 120)
  endif()
endif()

# The web UI's end-to-end test (ui/e2e/run.ts): typechecks and builds the
# bundle into the build tree, then drives it in headless Chrome against this
# rk-daemon serving a program compiled by the test. Needs Node on PATH,
# ui/node_modules (npm ci in ui/) and REVKIT_UI_BROWSER: a Chrome/Chromium
# binary, or "chromium" for Playwright's own (npx playwright install chromium).
if(REVKIT_BUILD_TESTS)
  find_program(REVKIT_NODE node)
  set(REVKIT_UI_BROWSER "/usr/bin/google-chrome" CACHE STRING
      "Browser for the ui_e2e test: a Chrome binary, or chromium for Playwright's")
  if(REVKIT_NODE AND EXISTS "${PROJECT_SOURCE_DIR}/ui/node_modules/playwright"
     AND (EXISTS "${REVKIT_UI_BROWSER}" OR REVKIT_UI_BROWSER STREQUAL "chromium"))
    get_filename_component(_node_dir "${REVKIT_NODE}" DIRECTORY)
    add_test(NAME ui_e2e COMMAND "${PROJECT_SOURCE_DIR}/ui/e2e/run.sh")
    set_tests_properties(ui_e2e PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;RK_E2E_TIME_SCALE=${_rk_e2e_scale};RK_WEB_ROOT=${CMAKE_CURRENT_BINARY_DIR}/ui-dist;RK_PLUGIN_DIR=${REVKIT_EXAMPLE_PLUGINS_DIR};RK_BROWSER=${REVKIT_UI_BROWSER};REVKIT_PYTHON=${REVKIT_PYTHON};PYTHONPATH=${PROJECT_SOURCE_DIR}/sdk/python;PYTHONDONTWRITEBYTECODE=1;PATH=${_node_dir}:$ENV{PATH}"
      TIMEOUT ${_rk_ui_e2e_timeout})
  else()
    message(STATUS "No node, ui/node_modules or REVKIT_UI_BROWSER: skipping ui_e2e test")
  endif()
  # The UI's unit tests that need neither a daemon nor a browser: the Go To
  # expression evaluator and Copy Special's formats (ui/test/unit.ts).
  if(REVKIT_NODE AND EXISTS "${PROJECT_SOURCE_DIR}/ui/node_modules/.bin/tsx")
    get_filename_component(_node_dir "${REVKIT_NODE}" DIRECTORY)
    add_test(NAME ui_unit COMMAND "${PROJECT_SOURCE_DIR}/ui/node_modules/.bin/tsx" test/unit.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ui)
    set_tests_properties(ui_unit PROPERTIES ENVIRONMENT "PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 60)
  endif()
endif()
# The TypeScript client against an authenticated TLS daemon (sdk/ts/test/auth.ts):
# every protocol with a pinned self-signed certificate and API tokens; and
# raw layout detection (sdk/ts/test/detect.ts). Need Node and
# sdk/ts/node_modules (npm ci in sdk/ts).
if(REVKIT_BUILD_TESTS)
  find_program(REVKIT_NODE node)
  if(REVKIT_NODE AND EXISTS "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/@connectrpc/connect-node")
    get_filename_component(_node_dir "${REVKIT_NODE}" DIRECTORY)
    add_test(NAME ts_sdk_auth COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/auth.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_auth PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 120)
    # The header import helpers (src/headers.ts), without a daemon.
    add_test(NAME ts_sdk_headers COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/headers.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_headers PROPERTIES ENVIRONMENT "PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 60)
    # The structure helpers (src/structures.ts: AutoStructure's bodies), without a daemon.
    add_test(NAME ts_sdk_structures COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/structures.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_structures PROPERTIES ENVIRONMENT "PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 60)
    # Type archives and categories through the client (sdk/ts/test/archives.ts):
    # the corpus's debug cJSON into its stripped twin and back.
    add_test(NAME ts_sdk_archives COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/archives.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_archives PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;REVKIT_CORPUS=${REVKIT_CORPUS_DIR};PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # Project-wide types and type archives through the client
    # (sdk/ts/test/projecttypes.ts).
    add_test(NAME ts_sdk_projecttypes COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/projecttypes.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_projecttypes PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;REVKIT_CORPUS=${REVKIT_CORPUS_DIR};PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # Raw layout detection through the client (sdk/ts/test/detect.ts), on
    # the image backend: the daemon's own code as a blob with no header.
    add_test(NAME ts_sdk_detect COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/detect.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_detect PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT ${_rk_e2e_timeout})
    # Container file systems through the client (sdk/ts/test/filesystems.ts).
    add_test(NAME ts_sdk_filesystems COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/filesystems.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_filesystems PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # The memory map after import through the client (sdk/ts/test/memory.ts).
    add_test(NAME ts_sdk_memory COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/memory.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_memory PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # Clear, Disassemble here, Define data and mutability through the client (sdk/ts/test/listing_edit.ts).
    add_test(NAME ts_sdk_listing_edit COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/listing_edit.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_listing_edit PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # Convert, Set Equate, the Equates table and user references through the client (sdk/ts/test/equates.ts).
    add_test(NAME ts_sdk_equates COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/equates.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_equates PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # Batch reads and script provenance through the client (sdk/ts/test/scripting.ts).
    add_test(NAME ts_sdk_scripting COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/scripting.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_scripting PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # The searches through the client (sdk/ts/test/search.ts).
    add_test(NAME ts_sdk_search COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/search.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_search PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
    # Scripts the daemon runs, through the client (sdk/ts/test/scripts.ts): the
    # daemon's script host needs the test Python and the source tree's SDK.
    add_test(NAME ts_sdk_scripts COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/scripts.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_scripts PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;REVKIT_PYTHON=${REVKIT_PYTHON};PYTHONPATH=${PROJECT_SOURCE_DIR}/sdk/python;PYTHONDONTWRITEBYTECODE=1;PATH=${_node_dir}:$ENV{PATH}"
      TIMEOUT 180)
    # Folders and project archives through the client (sdk/ts/test/projects.ts).
    add_test(NAME ts_sdk_projects COMMAND "${PROJECT_SOURCE_DIR}/sdk/ts/node_modules/.bin/tsx" test/projects.ts
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/sdk/ts)
    set_tests_properties(ts_sdk_projects PROPERTIES
      ENVIRONMENT "RK_DAEMON=$<TARGET_FILE:rk-daemon>;PATH=${_node_dir}:$ENV{PATH}" TIMEOUT 180)
  else()
    message(STATUS "No node or sdk/ts/node_modules: skipping ts_sdk_auth and ts_sdk_detect tests")
  endif()
endif()
add_dependencies(rk-daemon rk-decompd)
