// An in-memory Backend with deterministic synthetic data, so clients and the
// transports can be built and tested before the fact store and loader land.
//
// It serves one project ("demo") holding one program ("demo/hello"): a small
// x86-64 ELF-like image with four functions (entry, main, an FNV-1a checksum
// and an unreferenced helper), string and global data, xrefs, p-code and
// decompiler token streams. Assertions really change what queries return,
// every commit is a new immutable snapshot (so pinned reads work), and
// subscribers receive the changed keys and invalidated queries.
//
// ImportProgram ignores the bytes it is given (beyond hashing them) and
// creates another copy of the same synthetic program.
#pragma once

#include "revkit/api/backend.h"

#include <cstdint>
#include <memory>
#include <string>

namespace revkit::api {

struct FakeBackendOptions {
  // Revisions kept readable per project (ReadOptions.revision).
  std::uint32_t retained_revisions = 256;
  std::string server_version = "rk-daemon (fake backend)";
};

std::unique_ptr<Backend> MakeFakeBackend(FakeBackendOptions options = {});

// Well-known ids and addresses of the synthetic program, for tests and docs.
namespace fake {
inline constexpr const char *kProjectId = "demo";
inline constexpr const char *kProgramId = "demo/hello";
inline constexpr std::uint64_t kEntry = 0x401000;
inline constexpr std::uint64_t kMain = 0x401010;
inline constexpr std::uint64_t kChecksum = 0x401040;  // default name FUN_00401040
inline constexpr std::uint64_t kHelper = 0x401070;    // FUN_00401070, no callers
inline constexpr std::uint64_t kHelloString = 0x402000;
inline constexpr std::uint64_t kGlobalResult = 0x403000;
}  // namespace fake

}  // namespace revkit::api
