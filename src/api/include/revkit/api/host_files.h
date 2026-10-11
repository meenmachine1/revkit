#pragma once

// ListHostFiles: a directory listing on the daemon's host, confined to a
// set of roots, for picking a file to import by path.

#include "revkit/api/backend.h"

#include <cstddef>
#include <string>
#include <vector>

namespace revkit::api {

struct HostFilesOptions {
  // Browsable roots. Empty: listing is refused.
  std::vector<std::string> roots;
  // Entries returned per listing; the rest are reported as truncated.
  std::size_t max_entries = 5000;
};

// Lists req.path (or the first root) if its canonical form lies inside a
// canonical root, so neither ".." nor a symlink can leave the roots.
Status ListHostFiles(const HostFilesOptions &opt, const pb::ListHostFilesRequest &req,
                     pb::ListHostFilesResponse &resp);

}  // namespace revkit::api
