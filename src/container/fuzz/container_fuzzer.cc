// libFuzzer target for one container format (REVKIT_FUZZ=ON, clang): the
// format named at build time (RK_FUZZ_FORMAT) opened from the input, every
// entry listed, its links resolved and its contents read, within small
// limits; or (RK_FUZZ_FORMAT "codecs") the LZ4 and LZO1X block decoders;
// or ("bytecode") the bytecode headers: guess() (a PE's CLR header too)
// and a Lua chunk's header and walk at the input's start.
// docs/filesystems.md, "Fuzzing"; docs/roadmap.md, "Bug scrub".
#include "revkit/container/container.hh"
#include "revkit/container/decompress.hh"
#include "revkit/container/session.hh"

#include "../bytecode.hh"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using namespace revkit::container;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  const std::string format = RK_FUZZ_FORMAT;
  std::vector<std::byte> bytes(size);
  for (std::size_t i = 0; i < size; ++i) bytes[i] = static_cast<std::byte>(data[i]);
  if (format == "codecs") {
    if (size < 1) return 0;
    std::vector<std::byte> out;
    std::span<const std::byte> in(bytes.data() + 1, size - 1);
    try {
      if (data[0] & 1)
        lz4_decode_block(in, out, 1 << 20);
      else
        lzo1x_decode(in, out, 1 << 20);
    } catch (const Error &) {
    }
    return 0;
  }
  if (format == "bytecode") {
    (void)guess(bytes, bytes.size());
    if (auto h = detail::lua_header(bytes)) (void)detail::lua_chunk_length(bytes, 0, *h);
    (void)detail::zip_content_kind(bytes);
    return 0;
  }
  Context ctx;
  ctx.limits.max_file_bytes = 16 << 20;
  ctx.limits.max_total_bytes = 64 << 20;
  ctx.limits.max_entries = 4096;
  ctx.limits.memory_threshold = 64 << 20;
  ctx.budget = std::make_shared<Budget>(ctx.limits.max_total_bytes);
  try {
    auto fs = open_format(format, memory_source(std::move(bytes)), "fuzz.bin", ctx);
    for (std::uint32_t i = 0; i < fs->entries().size(); ++i) {
      const Entry &e = fs->entry(i);
      (void)fs->path_of(i);
      try {
        if (e.kind == Kind::symlink || e.kind == Kind::hardlink) (void)fs->resolve_link(i);
        if (e.kind == Kind::file) {
          (void)fs->head(i, 64, ctx);
          auto src = fs->open(i, ctx);
          std::vector<std::byte> buf(4096);
          for (std::uint64_t off = 0; off < src->size(); off += buf.size()) src->read(off, buf);
        }
      } catch (const Error &) {
      }
    }
  } catch (const Error &) {
  }
  return 0;
}
