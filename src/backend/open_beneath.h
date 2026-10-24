// Opening a file below a directory without following any symbolic link
// on the way: what openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) does,
// one component at a time with openat(O_NOFOLLOW), so it needs no Linux
// 5.6. For paths checked first (canonicalized, or resolved inside a root
// with lstat) and opened after: a local user who can write below the
// directory and swaps a component for a link between the two steps gets
// ELOOP or ENOTDIR instead of the daemon opening what the link names.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace revkit::backend {

// Opens `rel` below `dirfd`. `rel` must be relative with no ".." (a
// canonical path made relative to its root); "" or "." opens `dirfd`
// itself again. Every component but the last must be a directory, none a
// link; `flags` (O_NOFOLLOW and O_CLOEXEC added) and `mode` apply to the
// last. Returns a new descriptor, or -1 with errno set.
int OpenBeneath(int dirfd, const std::filesystem::path &rel, int flags, mode_t mode = 0);

// The same from a directory path: `root` is opened as given (it is the
// daemon's own configuration, such as a --browse-root), then `rel` below
// it as OpenBeneath does.
int OpenBeneath(const std::filesystem::path &root, const std::filesystem::path &rel, int flags, mode_t mode = 0);

// Reads the regular file at `canonical` (absolute and canonical: checked
// by the caller, read here without trusting it again), at most
// `max_bytes`. With `roots` (--browse-root directories), it must lie below
// one and is opened from it with OpenBeneath, so no link is followed on the
// way; without, its last component isn't followed. Opened O_NONBLOCK, so
// a FIFO doesn't block, and anything but a regular file is refused (a
// device, a FIFO, a directory). nullopt with `why` ("missing", "not a
// regular file", "too large", "outside the browse roots", "unreadable").
std::optional<std::string> ReadRegularFile(const std::filesystem::path &canonical, const std::vector<std::string> &roots,
                                           std::uint64_t max_bytes, std::string *why = nullptr);

}  // namespace revkit::backend
