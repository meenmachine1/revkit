// Library signatures for code outside revkit::infer (the emulator's skipped
// import calls): the prototype the signature databases give an import.
#pragma once

#include "revkit/infer/vtype.h"
#include "revkit/loader/image.hh"

#include <optional>
#include <string_view>

namespace revkit::infer {

// The prototype of `name` as the image's platform library declares it
// (glibc for ELF, the Windows headers for PE), sized for the image.
std::optional<Prototype> library_prototype(const loader::Image &image, std::string_view name);

}  // namespace revkit::infer
