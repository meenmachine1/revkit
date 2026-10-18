// PyInstaller's CArchive and PYZ (pyinstaller.cc). Internal.
#pragma once

#include "formats.hh"

#include <map>

namespace revkit::container::detail {

// Archive entries holding bare marshalled code, read back as .pyc files: a
// header with the right magic number in front of their bytes.
class PycFileSystem : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;
  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override;
  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override;

 protected:
  // Before the file system is shared: `entry` reads with a header of
  // `magic` (its size grows by the header's).
  void restore(std::uint32_t entry, std::uint16_t magic);

 private:
  std::map<std::uint32_t, std::uint16_t> magic_;
};

// The file carries a PyInstaller archive: its cookie, in the ELF section
// "pydata" or near the end of the file.
bool pyinstaller_payload(const Source &src);
bool pyz_header(std::span<const std::byte> head);
std::shared_ptr<FileSystem> open_pyinstaller(std::shared_ptr<const Source> src, std::string_view name,
                                             const Context &ctx);
std::shared_ptr<FileSystem> open_pyz(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx);

}  // namespace revkit::container::detail
