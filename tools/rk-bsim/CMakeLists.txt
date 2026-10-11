# BSim signature databases from the command line (docs/bsim.md). Ingest runs
# an in-process image backend, so it needs the API component (system gRPC).
if(NOT TARGET revkit::api)
  return()
endif()
add_executable(rk-bsim main.cc)
target_include_directories(rk-bsim PRIVATE ${PROJECT_SOURCE_DIR}/tools/rk-lift)
target_link_libraries(rk-bsim PRIVATE revkit::backend revkit::bsim revkit::runtime)
target_compile_options(rk-bsim PRIVATE -Wall -Wextra)
add_dependencies(rk-bsim rk-decompd)
