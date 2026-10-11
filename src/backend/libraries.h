// Shared libraries (api_minor 70, docs/api.md "Libraries"): the pure parts
// of finding a program's libraries on the daemon's host and resolving its
// imports to a library's exports. image_backend.cc keeps the project side
// (which program a library is, the link assertions, the imports).
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::backend::libs {

// "free@GLIBC_2.2.5" and "free@@GLIBC_2.2.5" are "free".
std::string StripVersion(std::string_view name);

// Whether two library names are the same library: exactly for ELF, without
// case for PE (Windows file names).
bool SameLibrary(std::string_view a, std::string_view b, bool pe);

// A library image's exports: name (version dropped) -> address. ELF: its
// defined global and weak dynamic symbols (functions, indirect functions
// and objects; the symbol table's when there is no dynamic one); PE: its
// export directory's named exports, forwarders left out.
std::map<std::string, std::uint64_t> Exports(const loader::Image &img);

// What a file's header says it runs on, read without loading it.
struct FileArch {
  loader::Format format = loader::Format::elf;
  unsigned bits = 0;
  loader::Endian endian = loader::Endian::little;
  std::uint32_t machine = 0;
};
std::optional<FileArch> PeekArch(const std::filesystem::path &file);
// Whether a library of that arch can be `img`'s.
bool Compatible(const FileArch &a, const loader::Image &img);

// Where to look for `img`'s libraries, in order: `user` (absolute paths),
// the file's own directory and its runpath ($ORIGIN expanded) when it came
// from `source_path`, then, for a file of this host (`host`), the host's
// library directories (/lib, /usr/lib, their multiarch and 64-bit forms).
// Directories that don't exist are left out; each appears once.
std::vector<std::filesystem::path> SearchDirs(const std::vector<std::string> &user, const std::string &source_path,
                                              const loader::Image &img, bool host);

// The first regular file named `name` (any case for PE) in `dirs` whose
// header is compatible with `img`.
std::optional<std::filesystem::path> FindLibrary(const std::string &name, const std::vector<std::filesystem::path> &dirs,
                                                 const loader::Image &img);

}  // namespace revkit::backend::libs
