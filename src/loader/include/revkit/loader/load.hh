// Entry points: detect the container format and parse it.
#pragma once

#include "revkit/loader/image.hh"

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace revkit::loader {

// Parse an ELF32/ELF64 file of either endianness. Throws LoadError.
Image parse_elf(std::shared_ptr<const Bytes> file, const LoadOptions &options = {});

// Parse a PE32/PE32+ image. Throws LoadError.
Image parse_pe(std::shared_ptr<const Bytes> file, const LoadOptions &options = {});

// Parse a Mach-O file, or a slice of a universal (fat) one (the default
// slice unless LoadOptions::macho_slice names one). Throws LoadError.
Image parse_macho(std::shared_ptr<const Bytes> file, const LoadOptions &options = {});

// A universal Mach-O's slices, in file order; empty when the file isn't a
// well-formed universal file (a thin Mach-O has none).
std::vector<MachoSlice> macho_slices(std::span<const std::byte> file);
// Whether the file is a Mach-O, thin or universal, by its magic.
bool is_macho(std::span<const std::byte> file);
// The slice a universal file loads by default: the first arm64 or arm64e
// one, else the first x86-64 one, else the first.
std::size_t macho_default_slice(const std::vector<MachoSlice> &slices);
// The arch name of a CPU type and subtype, as lipo spells it: "arm64",
// "arm64e", "x86_64", "i386", "armv7", "armv7s", "ppc", ...
std::string macho_arch_name(std::uint32_t cputype, std::uint32_t cpusubtype);

// Load a flat binary (firmware) as RawOptions say. Throws LoadError when the
// language isn't proc:endian:size:variant, the slice is outside the file, a
// region is empty, wraps or overlaps another, or the image is empty.
Image parse_raw(std::shared_ptr<const Bytes> file, const RawOptions &options);

// Read a whole file and load it with parse_raw.
Image load_raw_file(const std::filesystem::path &path, const RawOptions &options);

// Parses "name:start:size[:perms][:init|uninit|volatile][:space=NAME]"
// (numbers in hex, with or without 0x; perms like "rw-" or "rwx"; default
// rw-, uninit; the default space unless one is named), the command-line
// spelling of a RawRegion. Throws LoadError.
RawRegion parse_raw_region(std::string_view spec);

// What a file holds, by content (RawContainer::detect's rule): ihex or
// srec when every line is a well-formed record of that format, hexbytes
// when it is all hex digit pairs (an optional "0x" first; whitespace between
// pairs), else binary.
RawContainer detect_raw_container(std::span<const std::byte> file);
// The bytes hex text spells (hexbytes), or nullopt when it isn't hex text.
std::optional<Bytes> decode_hex_text(std::span<const std::byte> file);
// "binary", "ihex", "srec", "detect", and back (nullopt: unknown name).
std::string_view to_string(RawContainer c);
std::optional<RawContainer> raw_container_from_string(std::string_view name);

// Sniff the magic and dispatch. Throws LoadError for unknown formats.
Image parse(std::shared_ptr<const Bytes> file, const LoadOptions &options = {});

// Read a whole file and parse it. Throws LoadError (including for I/O errors).
Image load_file(const std::filesystem::path &path, const LoadOptions &options = {});

// The first section with this name, or null.
const Section *find_section(const Image &image, std::string_view name);

// A section's bytes as stored in the file: ELF sh_size bytes, or for PE
// VirtualSize bytes clipped to the raw data (no file-alignment padding).
// Empty for sections with no file data (.bss, data outside the file).
std::span<const std::byte> section_bytes(const Image &image, const Section &section);

// A section's contents: section_bytes(), inflated if it is an ELF
// SHF_COMPRESSED section (zlib). Throws LoadError if a compressed section
// is malformed, uses another algorithm, or would inflate past 1 GiB.
Bytes section_contents(const Image &image, const Section &section);

// The Ghidra language and compiler spec for an image.
struct LanguageSpec {
  std::string language;  // e.g. "x86:LE:64:default"
  std::string compiler;  // e.g. "gcc"

  std::string id() const { return language + ":" + compiler; }
};

// Choose the Ghidra language for an image from its machine, class, endianness
// and flags. Returns nullopt for machines we don't map.
std::optional<LanguageSpec> guess_language(const Image &image);

// Every language/compiler pair guess_language can return, so tests can check
// each one exists in the Ghidra install.
std::vector<LanguageSpec> all_language_specs();

}  // namespace revkit::loader
