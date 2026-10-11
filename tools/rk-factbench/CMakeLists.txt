add_executable(rk-factbench main.cc)
target_link_libraries(rk-factbench PRIVATE revkit::facts revkit::facts_testing)
target_compile_options(rk-factbench PRIVATE -Wall -Wextra)
