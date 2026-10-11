# The release build environment (scripts/package.sh): Debian 12, whose
# glibc 2.36 is the oldest the bundle runs on. Everything else revkit links
# dynamically (gRPC, protobuf, Abseil, OpenSSL, c-ares, RE2, zlib, liblzma,
# libbz2) is copied into the bundle's lib/revkit; libzstd-dev is for builds
# without plugins (wasmtime carries zstd otherwise). The mingw-w64 headers
# and import libraries (and libc6-dev's glibc headers) are what
# tools/rk-typeinfo builds the library type archives from.
FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config git patch ca-certificates file xz-utils \
      zlib1g-dev liblzma-dev libzstd-dev libbz2-dev libssl-dev libgrpc++-dev libprotobuf-dev protobuf-compiler protobuf-compiler-grpc \
      clang lld python3 mingw-w64-x86-64-dev mingw-w64-i686-dev \
 && rm -rf /var/lib/apt/lists/*
