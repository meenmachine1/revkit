# Writes OUTPUT, a C++ source defining one `extern const char <symbol>[]`
# per signature database: cmake -DOUTPUT=f.cc -DINPUTS="sym=file;..." -P embed.cmake
set(text "// Generated from the signature databases in src/infer/data by embed.cmake.\n")
foreach(pair ${INPUTS})
  string(REPLACE "=" ";" parts "${pair}")
  list(GET parts 0 symbol)
  list(GET parts 1 file)
  file(READ "${file}" content)
  string(APPEND text "extern const char ${symbol}[];\nconst char ${symbol}[] = R\"sigdb(${content})sigdb\";\n")
endforeach()
file(WRITE "${OUTPUT}.tmp" "${text}")
execute_process(COMMAND ${CMAKE_COMMAND} -E copy_if_different "${OUTPUT}.tmp" "${OUTPUT}")
