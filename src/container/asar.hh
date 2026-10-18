// Electron asar archives (asar.cc). Internal.
#pragma once

#include "formats.hh"

#include <functional>

namespace revkit::container::detail {

// An asar whose "unpacked" files are read from <archive>.unpacked/ once the
// session attaches that folder.
class AsarFileSystem : public SliceFileSystem {
 public:
  using SliceFileSystem::SliceFileSystem;
  // A file of the .unpacked folder by its components in the archive, or
  // null when it isn't there.
  using Resolver = std::function<std::shared_ptr<Source>(const std::vector<std::string> &, const Context &)>;
  std::shared_ptr<Source> open(std::uint32_t entry, const Context &ctx) const override;
  std::vector<std::byte> head(std::uint32_t entry, std::uint64_t n, const Context &ctx) const override;
  bool has_unpacked() const;
  // Before the file system is shared (Session::mount).
  void attach_unpacked(Resolver r);

 protected:
  static constexpr std::uint64_t kUnpacked = UINT64_MAX - 1;  // Entry::loc2

 private:
  Resolver unpacked_;
};

// Gives an asar (open_asar's) the folder its unpacked files are in; other
// file systems are left as they are.
void attach_asar_unpacked(FileSystem &fs, AsarFileSystem::Resolver r);

// The header's start: the pickle sizes agree and the JSON starts {"files":.
bool asar_header(std::span<const std::byte> head, std::uint64_t size);
std::shared_ptr<FileSystem> open_asar(std::shared_ptr<const Source> src, std::string_view name, const Context &ctx);

}  // namespace revkit::container::detail
