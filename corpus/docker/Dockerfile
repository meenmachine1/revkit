# Toolchain image for the revkit benchmark corpus.
# The base image is pinned by digest and apt resolves against a fixed
# snapshot.debian.org date, so rebuilding the image gives the same compilers.
FROM debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c

ARG SNAPSHOT=20260915T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' \
      "$SNAPSHOT" "$SNAPSHOT" > /etc/apt/sources.list && \
    apt-get -o Acquire::Retries=5 update && \
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
      gcc clang lld llvm make python3 ca-certificates \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      gcc-riscv64-linux-gnu libc6-dev-riscv64-cross \
      gcc-mingw-w64-x86-64 mingw-w64-x86-64-dev \
      binutils-aarch64-linux-gnu binutils-riscv64-linux-gnu && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
