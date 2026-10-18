// Shared libraries (api_minor 70, docs/api.md "Libraries"): the pure parts
// of finding a program's libraries on the daemon's host and resolving its
// imports to a library's exports. image_backend.cc keeps the project side
// (which program a library is, the link assertions, the imports).
#pragma once

#include "revkit/loader/image.hh"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
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
// A Mach-O library name's file name: "@rpath/libfoo.dylib" and
// "/usr/lib/libfoo.dylib" are "libfoo.dylib" (a framework's
// "Foo.framework/Versions/A/Foo" is "Foo").
std::string LibraryLeaf(std::string_view name);

// A library image's exports: name (version dropped) -> address. ELF: its
// defined global and weak dynamic symbols (functions, indirect functions
// and objects; the symbol table's when there is no dynamic one); PE: its
// export directory's named exports, forwarders left out; Mach-O: its
// export trie's, re-exports left out (its global symbols without one).
std::map<std::string, std::uint64_t> Exports(const loader::Image &img);

// What a file's header says it runs on, read without loading it.
struct FileArch {
  loader::Format format = loader::Format::elf;
  unsigned bits = 0;
  loader::Endian endian = loader::Endian::little;
  std::uint32_t machine = 0;
  // A universal Mach-O: each slice's (cputype, cpusubtype); `machine` and
  // `bits` are then the first's.
  std::vector<std::pair<std::uint32_t, std::uint32_t>> slices;
};
std::optional<FileArch> PeekArch(const std::filesystem::path &file);
// Whether a library of that arch can be `img`'s (a universal Mach-O: one
// of its slices can).
bool Compatible(const FileArch &a, const loader::Image &img);
// The slice of a universal Mach-O library to load for `img`
// (ImportOptions.macho_slice): its slice of img's CPU type and subtype,
// else of its CPU type ("#N"); "" for a thin file or none.
std::string MachoSliceFor(const FileArch &a, const loader::Image &img);

// Where to look for `img`'s libraries, in order: `user` (absolute paths),
// the file's own directory and its runpath ($ORIGIN expanded) when it came
// from `source_path`, then, for a file of this host (`host`), the host's
// library directories (/lib, /usr/lib, their multiarch and 64-bit forms).
// Directories that don't exist are left out; each appears once.
std::vector<std::filesystem::path> SearchDirs(const std::vector<std::string> &user, const std::string &source_path,
                                              const loader::Image &img, bool host);

// The first regular file named `name` (any case for PE) in `dirs` whose
// header is compatible with `img`. A Mach-O's names are paths: the file
// is looked for by its LibraryLeaf (SearchDirs has put the rpaths in).
std::optional<std::filesystem::path> FindLibrary(const std::string &name, const std::vector<std::filesystem::path> &dirs,
                                                 const loader::Image &img);

// --- A program's own root file system (api_minor 79) -----------------------
//
// A program imported from a container, or from a root file system extracted
// on the daemon's host, finds its libraries in that tree, not the host's:
// paths are absolute inside the root ("/usr/lib/libc.so.6"), and symbolic
// links are followed inside it only (an absolute target is from the root,
// ".." stops there), as a chroot would.
class LibraryRoot {
 public:
  virtual ~LibraryRoot() = default;
  // A regular file at a path inside the root (raw bytes, '/' separated),
  // links followed inside it: a key to read it by, or nullopt.
  virtual std::optional<std::string> file(const std::string &path) = 0;
  // The names in a directory of the root (none when it isn't one).
  virtual std::vector<std::string> names(const std::string &dir) = 0;
  // Up to n bytes at offset of a file found (its key).
  virtual std::vector<unsigned char> read(const std::string &key, std::uint64_t offset, std::size_t n) = 0;
  // The directory a found file is in, as a path inside the root (its
  // $ORIGIN, where its own libraries are looked for).
  virtual std::string origin(const std::string &key) = 0;
  // The whole file (at most `max` bytes), read so that it is the file the
  // key names inside the root; null when it can't be, or when the root
  // has no such reader (a container's opens its members itself).
  virtual std::shared_ptr<loader::Bytes> read_all(const std::string &key, std::uint64_t max) {
    (void)key;
    (void)max;
    return nullptr;
  }
};

// A directory of the daemon's host (canonical) as a root: every component
// is checked with lstat, links resolved inside the root, so a found file's
// key is a host path below `root` with no symbolic link in it.
std::shared_ptr<LibraryRoot> HostRoot(const std::filesystem::path &root);

// The extracted root file system a host file lies in: the nearest ancestor
// of its directory, at or below `limit` and not "/", that has lib or
// usr/lib and one of bin, sbin, usr/bin or etc (directories named usr and
// local are passed over: they hold lib and bin themselves). Both canonical.
std::optional<std::filesystem::path> FindRootFileSystem(const std::filesystem::path &file,
                                                        const std::filesystem::path &limit);

// What a file's header says it runs on, from the root.
std::optional<FileArch> PeekArchIn(LibraryRoot &root, const std::string &key);

// Where to look inside a root for `img`'s libraries, in order: `user`
// (absolute paths in the root), `origin` (the file's directory in the
// root), its runpath ($ORIGIN expanded; absolute entries inside the root),
// then for ELF the directories /etc/ld.so.conf names (one level of
// include) and the standard ones (/lib and /usr/lib, their multiarch and
// 64-bit forms, /usr/local/lib). PE: user and origin (beside the exe).
// Mach-O: user, origin, its LC_RPATHs (@loader_path and @executable_path
// as origin); its absolute install names are tried as they are first
// (FindLibraryIn).
std::vector<std::string> RootSearchDirs(LibraryRoot &root, const std::vector<std::string> &user,
                                        const std::string &origin, const loader::Image &img);

// The first regular file named `name` (any case for PE) in `dirs` of the
// root whose header is compatible with `img`: its key.
std::optional<std::string> FindLibraryIn(LibraryRoot &root, const std::string &name, const std::vector<std::string> &dirs,
                                         const loader::Image &img);

}  // namespace revkit::backend::libs
