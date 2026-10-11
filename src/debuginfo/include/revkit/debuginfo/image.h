// Debug sections of a binary loaded by revkit::loader (ELF, or PE carrying
// DWARF, as mingw images do for their runtime).
#pragma once

#include "revkit/debuginfo/dwarf.h"
#include "revkit/loader/image.hh"

#include <string>
#include <vector>

namespace revkit::debuginfo {

// The image's DWARF sections, inflated where compressed. `sections` points
// into `storage` and into the image's file bytes, so keep both this object
// and the image alive while it is in use. Sections that fail to inflate are
// left out and reported in `warnings`.
struct ImageSections {
  Sections sections;
  std::vector<loader::Bytes> storage;
  std::vector<std::string> warnings;

  ImageSections() = default;
  ImageSections(ImageSections &&) = default;
  ImageSections &operator=(ImageSections &&) = default;
  ImageSections(const ImageSections &) = delete;
  ImageSections &operator=(const ImageSections &) = delete;
};

ImageSections dwarf_sections(const loader::Image &image);

// True if addr lies in an executable section (ELF SHF_EXECINSTR, PE
// IMAGE_SCN_MEM_EXECUTE) of the image as loaded.
bool is_code(const loader::Image &image, std::uint64_t addr);

}  // namespace revkit::debuginfo
