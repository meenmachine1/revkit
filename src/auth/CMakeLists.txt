# revkit::auth — accounts, password hashes, session and API tokens, roles,
# login rate limiting and TLS certificates for rk-daemon (docs/security.md).
#
# Only OpenSSL (libssl-dev), which rk-daemon needs for TLS anyway: password
# hashes are scrypt (EVP_PBE_scrypt), tokens come from RAND_bytes.

find_package(OpenSSL QUIET COMPONENTS Crypto SSL)
if(NOT OpenSSL_FOUND)
  message(WARNING "revkit auth skipped: needs OpenSSL (apt install libssl-dev)")
  return()
endif()

add_library(revkit_auth STATIC
  crypto.cc
  password.cc
  rate_limit.cc
  store.cc
  tls.cc)
add_library(revkit::auth ALIAS revkit_auth)
target_include_directories(revkit_auth PUBLIC include)
target_link_libraries(revkit_auth PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(revkit_auth PRIVATE -Wall -Wextra)

if(REVKIT_BUILD_TESTS)
  add_subdirectory(tests)
endif()
