// What the packers' containers need to know of the executable that carries
// their payload: an ELF section or note, a PE resource or the PE's
// overlay, a Mach-O section. Bounded reads of hostile headers; nullopt when
// absent or malformed. Internal.
#pragma once

#include "revkit/container/container.hh"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace revkit::container::detail {

struct Range {
  std::uint64_t offset = 0, size = 0;
};

enum class ExeFormat { none, elf, pe, macho };
ExeFormat exe_format(const Source &src);

// An ELF section's file bytes, by name ("pydata", ".bun").
std::optional<Range> elf_section(const Source &src, std::string_view name);
// An ELF note's descriptor, by note name, in any SHT_NOTE section or
// PT_NOTE segment ("NODE_SEA_BLOB", as postject writes it).
std::optional<Range> elf_note(const Source &src, std::string_view name);
// A PE resource's data: type and name as strings ("RCDATA" for type 10,
// or a named type such as "PYTHONSCRIPT"; a name, or "#1" for id 1).
// The first language of it.
std::optional<Range> pe_resource(const Source &src, std::string_view type, std::string_view name);
// The file offset an ELF virtual address is loaded from (a PT_LOAD's).
std::optional<std::uint64_t> elf_file_offset(const Source &src, std::uint64_t vaddr);
// A PE section's raw data, by name (".bun").
std::optional<Range> pe_section(const Source &src, std::string_view name);
// Where a PE's sections end in the file (its overlay starts): the largest
// raw pointer + raw size, and the certificate table's end when it lies
// past them.
std::optional<std::uint64_t> pe_end_of_image(const Source &src);
// A Mach-O section by segment and section name (thin files only).
std::optional<Range> macho_section(const Source &src, std::string_view segment, std::string_view section);

}  // namespace revkit::container::detail
