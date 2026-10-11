// Function ID databases from untrusted bytes: parse, then read every
// function's library and relations so bad offsets in the result surface.
#include "revkit/fid/db.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  try {
    const revkit::fid::Database db =
        revkit::fid::Database::parse(std::as_bytes(std::span(data, size)), "fuzz");
    for (const revkit::fid::Function &f : db.functions()) {
      (void)db.library(f.library);
      (void)db.superior(f.id, f.hash.full);
      (void)db.by_full(f.hash.full);
    }
    (void)db.serialize();
  } catch (const revkit::fid::FidError &) {
  }
  return 0;
}
