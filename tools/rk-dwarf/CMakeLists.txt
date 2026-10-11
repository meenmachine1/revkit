# rk-dwarf is rk-debuginfo's old name; keep it working for scripts.
# protonorm.py here is a symlink to ../rk-debuginfo/protonorm.py.
add_custom_target(rk-dwarf ALL
  COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:rk-debuginfo>
          ${CMAKE_CURRENT_BINARY_DIR}/rk-dwarf
  DEPENDS rk-debuginfo
  COMMENT "Linking rk-dwarf -> rk-debuginfo")
