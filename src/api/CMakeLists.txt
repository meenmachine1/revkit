# revkit::api — the revkit.v1 schema compiled for C++, the Backend seam, a
# fake backend, and the gRPC + Connect/gRPC-web server used by rk-daemon.
#
# gRPC and protobuf come from the system (Ubuntu 24.04: libgrpc++-dev,
# libprotobuf-dev, protobuf-compiler-grpc), found via pkg-config. Building
# gRPC from source costs ~10 minutes per build directory, so it is not done
# here; without the packages this component is skipped with a warning and the
# rest of revkit builds as before.

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(RK_GRPC IMPORTED_TARGET grpc++ protobuf)
endif()
find_program(RK_PROTOC protoc)
find_program(RK_GRPC_CPP_PLUGIN grpc_cpp_plugin)
find_package(OpenSSL QUIET COMPONENTS Crypto SSL)

if(NOT RK_GRPC_FOUND OR NOT RK_PROTOC OR NOT RK_GRPC_CPP_PLUGIN OR NOT OpenSSL_FOUND)
  message(WARNING
    "revkit API skipped: needs pkg-config modules grpc++ and protobuf, protoc, grpc_cpp_plugin "
    "and OpenSSL (apt install libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc libssl-dev)")
  return()
endif()

include(FetchContent)
# Embedded HTTP/1.1 server for the browser transport; header-only.
FetchContent_Declare(cpp_httplib
  URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.59.0.tar.gz
  URL_HASH SHA256=7c8cc7df044abb837d75f7c1e56333305acb40335c3788b8f5fbf5927e63e148
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SOURCE_SUBDIR no-cmake)
FetchContent_MakeAvailable(cpp_httplib)
add_library(revkit_httplib INTERFACE)
target_include_directories(revkit_httplib SYSTEM INTERFACE ${cpp_httplib_SOURCE_DIR})
# HTTPS for the gateway (and the tests' client); every user of httplib.h
# must agree on this, so it is set here once.
target_compile_definitions(revkit_httplib INTERFACE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(revkit_httplib INTERFACE OpenSSL::SSL OpenSSL::Crypto)

# --- generated code ---------------------------------------------------------
set(RK_PROTO_ROOT ${PROJECT_SOURCE_DIR}/proto)
set(RK_PROTOS analysis apple assertion auth bsim common debugger decompile diff emulator filesystem listing meta patch plugin presence project provider query script subscription sync types)
set(RK_PROTO_OUT ${CMAKE_CURRENT_BINARY_DIR}/gen)
file(MAKE_DIRECTORY ${RK_PROTO_OUT})

set(_proto_srcs)
set(_proto_files)
foreach(name IN LISTS RK_PROTOS)
  set(_in ${RK_PROTO_ROOT}/revkit/v1/${name}.proto)
  set(_base ${RK_PROTO_OUT}/revkit/v1/${name})
  list(APPEND _proto_files ${_in})
  list(APPEND _proto_srcs ${_base}.pb.cc ${_base}.grpc.pb.cc)
  add_custom_command(
    OUTPUT ${_base}.pb.cc ${_base}.pb.h ${_base}.grpc.pb.cc ${_base}.grpc.pb.h
    COMMAND ${RK_PROTOC}
      --proto_path=${RK_PROTO_ROOT}
      --cpp_out=${RK_PROTO_OUT}
      --grpc_out=${RK_PROTO_OUT}
      --plugin=protoc-gen-grpc=${RK_GRPC_CPP_PLUGIN}
      ${_in}
    DEPENDS ${_in}
    COMMENT "protoc revkit/v1/${name}.proto"
    VERBATIM)
endforeach()

add_library(revkit_api_proto STATIC ${_proto_srcs})
target_include_directories(revkit_api_proto SYSTEM PUBLIC ${RK_PROTO_OUT})
target_link_libraries(revkit_api_proto PUBLIC PkgConfig::RK_GRPC)
set_target_properties(revkit_api_proto PROPERTIES POSITION_INDEPENDENT_CODE ON)

# --- library ----------------------------------------------------------------
add_library(revkit_api STATIC
  auth_policy.cc
  auth_service.cc
  connect_gateway.cc
  fake_backend.cc
  fake_program.cc
  grpc_services.cc
  host_files.cc
  listen_fds.cc
  peer_link.cc
  script_service.cc
  server.cc)
add_library(revkit::api ALIAS revkit_api)
target_include_directories(revkit_api PUBLIC include)
target_link_libraries(revkit_api
  PUBLIC revkit_api_proto revkit::auth
  PRIVATE revkit_httplib OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(revkit_api PRIVATE -Wall -Wextra)

find_library(RK_GRPC_REFLECTION grpc++_reflection)
if(RK_GRPC_REFLECTION)
  # Whole-archive/no-as-needed: the plugin registers itself from a static
  # initializer, so nothing references the library directly.
  target_link_libraries(revkit_api PRIVATE "-Wl,--push-state,--no-as-needed" ${RK_GRPC_REFLECTION} "-Wl,--pop-state")
  target_compile_definitions(revkit_api PRIVATE REVKIT_GRPC_REFLECTION)
endif()

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(REVKIT_FUZZ)
  add_subdirectory(fuzz)
endif()
