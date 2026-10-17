// Extraction to the host (ExtractFileSystem) of a hostile container: every
// entry written under a scratch browse root, then checked: nothing outside
// the destination (a sibling directory stays empty), no links, only
// regular files and directories, and no more bytes than the session's
// limits allow. Traversal names, links, devices and duplicate names are
// the container's to try. The first byte sets overwrite and what to
// extract; the rest is the container.
//
// Needs RK_FUZZ_SCRATCH: a directory of the fuzzer's own (each process
// works in <scratch>/<pid>, removed between runs).
#include "filesystems.h"

#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
namespace pb = ::revkit::v1;
using namespace revkit;

namespace {

fs::path g_root;

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  const char *scratch = std::getenv("RK_FUZZ_SCRATCH");
  if (!scratch) {
    std::fprintf(stderr, "extract_fuzzer: set RK_FUZZ_SCRATCH to a scratch directory\n");
    std::abort();
  }
  g_root = fs::path(scratch) / std::to_string(::getpid());
  fs::remove_all(g_root);
  fs::create_directories(g_root / "root" / "outside");
  g_root = fs::canonical(g_root / "root");
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size < 1) return 0;
  container::Limits limits;
  limits.max_file_bytes = 1 << 20;
  limits.max_total_bytes = 4 << 20;
  limits.max_entries = 2048;
  limits.max_depth = 3;
  limits.memory_threshold = 4 << 20;
  std::vector<std::byte> bytes(size - 1);
  for (std::size_t i = 1; i < size; ++i) bytes[i - 1] = std::byte{data[i]};
  backend::FsSession s;
  try {
    s.session = container::Session::open(container::memory_source(std::move(bytes)), "fuzz.bin", limits);
  } catch (const container::Error &) {
    return 0;
  }
  const fs::path out = g_root / "out";
  fs::remove_all(out);
  pb::ExtractFromFileSystemRequest req;
  req.set_host_dir(out.string());
  req.set_overwrite(data[0] & 1);
  req.add_paths((data[0] & 2) ? "/" : "/a");
  pb::ExtractFromFileSystemResponse resp;
  for (int pass = 0; pass < ((data[0] & 4) ? 2 : 1); ++pass)  // twice: over what the first wrote
    (void)backend::ExtractFileSystem(s, api::CallContext{}, req, {g_root.string()}, resp);
  std::uint64_t total = 0;
  std::error_code ec;
  if (fs::exists(out, ec)) {
    for (auto it = fs::recursive_directory_iterator(out, ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec)) {
      const fs::file_status st = it->symlink_status();
      if (fs::is_symlink(st) || !(fs::is_regular_file(st) || fs::is_directory(st))) __builtin_trap();
      if (fs::is_regular_file(st)) total += fs::file_size(it->path());
    }
  }
  // Two passes may each write the session's total.
  if (total > 2 * limits.max_total_bytes) __builtin_trap();
  if (!fs::is_empty(g_root / "outside")) __builtin_trap();
  for (const auto &e : fs::directory_iterator(g_root))
    if (e.path() != out && e.path() != g_root / "outside") __builtin_trap();
  fs::remove_all(out);
  return 0;
}
