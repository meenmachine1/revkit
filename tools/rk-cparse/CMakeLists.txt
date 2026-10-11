add_executable(rk-cparse main.cc)
target_link_libraries(rk-cparse PRIVATE revkit::cparse revkit::cparse_spec revkit::lift revkit::types revkit::runtime)
target_compile_options(rk-cparse PRIVATE -Wall -Wextra)
