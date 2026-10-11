// Export of a patched program (docs/patching.md, "Export"): the program's
// file with each patch at the file offset the loader read its address
// from, fixups applied (checksums into a field or the file name, the PE
// CheckSum), and a check that loading the output gives the patched bytes.
#pragma once

#include "revkit/loader/image.hh"
#include "revkit/patch/checksum.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::patch {

struct Patch {
  std::uint64_t address = 0;
  std::string bytes;
};

struct FilePatch {
  std::uint64_t file_offset = 0;
  std::string bytes;
  std::uint64_t address = 0;
};

// Each patch at its file offsets (a patch spanning two regions is split).
// A patch over bytes the file doesn't back (bss, a declared RAM or MMIO
// region, synthesized memory) is an error naming it: nothing is dropped.
struct MapResult {
  std::vector<FilePatch> mapped;
  std::string error;
};
MapResult map_to_file(const loader::Image &image, const std::vector<Patch> &patches);

struct Fixup {
  enum class Kind : std::uint8_t { checksum, pe_checksum } kind = Kind::checksum;
  Spec spec;  // checksum
};

struct ExportOptions {
  // The whole file, or only the loaded slice of a raw image (without its header).
  bool image_only = false;
  std::uint64_t image_offset = 0;
  std::uint64_t image_length = 0;  // 0: to the end of the file
  std::vector<Fixup> fixups;
  // "{NAME}_{SUM:08X}.bin": {NAME} the original stem, {EXT} its extension
  // (with the dot), {SUM}, {SUM:08X}, {SUM:08x}, {SUM:X} the name
  // checksum's value. Empty: the original name.
  std::string name_template;
  std::string original_name;
};

struct Change {
  std::uint64_t file_offset = 0;
  std::uint32_t length = 0;
  std::optional<std::uint64_t> address;
  std::string what;
};

struct ExportResult {
  std::vector<std::uint8_t> data;
  std::string file_name;
  std::vector<Change> changes;
  std::vector<std::string> fixups;  // "sum32 over 0x0..EOF = 0x1234ABCD (file name)"
  // File ranges fixups wrote: verification leaves them out.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> fixed;
  std::string error;
};

ExportResult build_export(std::span<const std::uint8_t> file, const std::vector<FilePatch> &patches,
                          const ExportOptions &options);

// The output name for a template.
std::string render_name(const std::string &name_template, const std::string &original_name,
                        std::optional<std::uint64_t> sum, unsigned sum_bits);

// What a template should be for a name whose hex run holds a name checksum:
// the run replaced by {SUM:08X} (or lower case, as the name spells it).
std::string template_for(const std::string &file_name, std::uint64_t value);

struct Verification {
  bool ok = false;
  std::uint64_t compared = 0;
  std::uint64_t mismatches = 0;
  std::optional<std::uint64_t> first_mismatch;
  std::string detail;
};

// Every file-backed byte of `original` (the image the program was loaded
// as), with `patches` laid over it, against the same address in `reloaded`
// (the output loaded with the same options), leaving out bytes whose file
// offset a fixup wrote (`fixed`, in the output's file offsets less
// `image_offset` for an image-only export).
Verification verify_export(const loader::Image &original, const std::vector<Patch> &patches,
                           const loader::Image &reloaded,
                           const std::vector<std::pair<std::uint64_t, std::uint64_t>> &fixed,
                           std::uint64_t file_delta = 0);

}  // namespace revkit::patch
