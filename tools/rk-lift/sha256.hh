// SHA-256 (FIPS 180-4), for the reference format's binary.sha256.
#pragma once

#include <cstddef>
#include <span>
#include <string>

namespace rklift {

std::string sha256_hex(std::span<const std::byte> data);

}  // namespace rklift
