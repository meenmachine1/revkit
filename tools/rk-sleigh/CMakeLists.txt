# rk-sleigh: the SLEIGH compiler (Ghidra's slgh_compile, from the decompiler
# fork in third_party/ghidra), so revkit builds its own processors with no
# Java (docs/bytecode-lifting.md, "E6"; docs/processors.md, "revkit's own
# processors"). It writes the same .sla as Ghidra's support/sleigh:
#
#   rk-sleigh [-D name=value] in.slaspec out.sla

add_executable(rk-sleigh
  ${GHIDRA_FORK_DIR}/cpp/slgh_compile.cc
  ${GHIDRA_FORK_DIR}/cpp/slghparse.cc
  ${GHIDRA_FORK_DIR}/cpp/slghscan.cc)
set_target_properties(rk-sleigh PROPERTIES CXX_STANDARD 17 CXX_EXTENSIONS ON)
# Vendored code: upstream's warnings stay out of our build output.
target_compile_options(rk-sleigh PRIVATE -w)
target_link_libraries(rk-sleigh PRIVATE ghidra::decomp ZLIB::ZLIB)
# Installed with the other tools (cmake/install.cmake).
