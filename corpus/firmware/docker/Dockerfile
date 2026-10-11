# Toolchain image for the revkit firmware corpus (corpus/firmware).
# The base image is the main corpus's, pinned by digest, and apt resolves
# against the same fixed snapshot.debian.org date, so rebuilding the image
# gives the same compilers. Espressif's Xtensa toolchain (ESP32, windowed
# ABI) and TI's MSP430 GCC are not Debian packages: they are pinned
# downloads in firmware.json, unpacked at build time. SDCC builds the
# 8051 and Z80 images.
FROM debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c

ARG SNAPSHOT=20260915T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' \
      "$SNAPSHOT" "$SNAPSHOT" > /etc/apt/sources.list && \
    apt-get -o Acquire::Retries=5 update && \
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
      gcc libc6-dev make patch python3 python3-pyelftools ca-certificates xz-utils bzip2 unzip file \
      bc bison flex libssl-dev libgnutls28-dev uuid-dev device-tree-compiler \
      python3-dev python3-setuptools swig \
      gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-powerpc-linux-gnu gcc-sh4-linux-gnu \
      gcc-m68k-linux-gnu gcc-arm-none-eabi libnewlib-arm-none-eabi \
      gcc-avr avr-libc binutils-avr gcc-xtensa-lx106 binutils-xtensa-lx106 \
      sdcc gcc-riscv64-unknown-elf gcc-sparc64-linux-gnu lib32gcc-14-dev-sparc64-cross && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
