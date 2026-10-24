# rk-typeinfo and the library type archives the build makes with it
# (docs/types.md#library-prototypes): the C library from the host's glibc
# headers (LP64 and ILP32) and the Windows API and C runtime from mingw-w64's
# headers (LLP64 and ILP32), each a C header plus its JSON sidecar in
# ${CMAKE_BINARY_DIR}/typeinfo, installed to share/revkit/typeinfo.

add_executable(rk-typeinfo main.cc)
target_link_libraries(rk-typeinfo PRIVATE revkit::cparse revkit::types revkit::runtime)
target_compile_options(rk-typeinfo PRIVATE -Wall -Wextra)

option(REVKIT_TYPEINFO "Build the library type archives from the host's headers" ON)
if(NOT REVKIT_TYPEINFO OR CMAKE_CROSSCOMPILING)
  return()
endif()

set(_out ${REVKIT_TYPEINFO_DIR})
set(_here ${CMAKE_CURRENT_SOURCE_DIR})
set(_archives)

# rk_typeinfo(NAME TARGET HEADERS SOURCE ARGS...)
function(rk_typeinfo name target headers source)
  add_custom_command(
    OUTPUT ${_out}/${name}.h ${_out}/${name}.json
    # The tsan preset's emulator (setarch -R): an instrumented rk-typeinfo
    # stops with "unexpected memory mapping" under full ASLR, so the whole
    # tree didn't build under TSan (bug scrub part 3). Empty otherwise.
    COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} $<TARGET_FILE:rk-typeinfo> --name ${name} --target ${target} --out ${_out} --headers ${headers} --source ${source} ${ARGN}
    DEPENDS rk-typeinfo ${headers} ${_here}/extra-glibc.h ${_here}/extra-mingw.h
    COMMENT "Library type archive ${name}"
    VERBATIM)
  set(_archives ${_archives} ${_out}/${name}.h PARENT_SCOPE)
endfunction()

# glibc (/usr/include, the host's multiarch directory): every function the
# headers declare, with fortification and glibc's asm-label aliases.
set(_glibc_multiarch /usr/include/${CMAKE_LIBRARY_ARCHITECTURE})
if(EXISTS /usr/include/stdio.h AND EXISTS ${_glibc_multiarch}/bits/wordsize.h)
  execute_process(COMMAND sh -c "sed -n 's/^#define[[:space:]]*__GLIBC_MINOR__[[:space:]]*//p' /usr/include/features.h"
                  OUTPUT_VARIABLE _glibc_minor OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(_glibc_src "glibc 2.${_glibc_minor} headers (/usr/include), LGPL-2.1-or-later (prototypes only)")
  set(_glibc_args -isystem ${_glibc_multiarch} -isystem /usr/include
      -D _GNU_SOURCE -D _LARGEFILE64_SOURCE -D _FORTIFY_SOURCE=2 -D __OPTIMIZE__
      --include ${_here}/extra-glibc.h --min-functions 1000)
  rk_typeinfo(libc-lp64 x86_64-linux-gnu ${_here}/glibc.headers "${_glibc_src}" ${_glibc_args})
  rk_typeinfo(libc-ilp32 i386-linux-gnu ${_here}/glibc.headers "${_glibc_src}" -isystem ${_here}/overlay-ilp32 ${_glibc_args})
else()
  message(STATUS "rk-typeinfo: no glibc headers in /usr/include: no libc type archives")
endif()

# mingw-w64 (gcc-mingw-w64's headers and import libraries): one archive per
# DLL and data model, the functions its import library exports.
foreach(_arch x86_64 i686)
  set(_mingw /usr/${_arch}-w64-mingw32)
  if(_arch STREQUAL x86_64)
    set(_target x86_64-w64-mingw32)
    set(_model llp64)
  else()
    set(_target i686-w64-mingw32)
    set(_model ilp32)
  endif()
  if(NOT EXISTS ${_mingw}/include/windows.h OR NOT EXISTS ${_mingw}/lib/libkernel32.a)
    message(STATUS "rk-typeinfo: no mingw-w64 headers in ${_mingw}: no ${_model} Windows type archives")
    continue()
  endif()
  set(_src "mingw-w64 headers and import libraries (${_mingw}), public domain and ZPL-2.1 (prototypes only)")
  set(_args -isystem ${_here}/overlay-mingw -isystem ${_mingw}/include -D WIN32_LEAN_AND_MEAN -D _CRT_SECURE_NO_WARNINGS -D _WIN32_WINNT=0x0A00
      --include ${_here}/extra-mingw.h)
  foreach(_dll kernel32 user32 ntdll advapi32 ws2_32)
    rk_typeinfo(${_dll}-${_model} ${_target} ${_here}/windows.headers "${_src}" ${_args}
                --exports ${_mingw}/lib/lib${_dll}.a --min-functions 50)
  endforeach()
  # The C runtime (msvcrt.dll, and the Universal CRT: ucrtbase.dll and its
  # api-ms-win-crt-* forwarders): Windows' C library for this data model.
  set(_crt --exports ${_mingw}/lib/libmsvcrt.a)
  foreach(_lib ucrt ucrtbase)
    if(EXISTS ${_mingw}/lib/lib${_lib}.a)
      list(APPEND _crt --exports ${_mingw}/lib/lib${_lib}.a)
    endif()
  endforeach()
  rk_typeinfo(msvcrt-${_model} ${_target} ${_here}/windows.headers "${_src}" ${_args} ${_crt} --min-functions 500)
endforeach()

add_custom_target(revkit_typeinfo ALL DEPENDS ${_archives})
install(DIRECTORY ${_out}/ DESTINATION share/revkit/typeinfo FILES_MATCHING PATTERN "*.h" PATTERN "*.json")
