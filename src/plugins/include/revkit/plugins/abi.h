// The plugin interface, version 1: a core-WebAssembly ABI (see
// docs/plugins.md for the full specification and why it is not WIT).
//
// A plugin is a wasm32 module plus a JSON manifest. The module imports only
// functions from the module "revkit:plugin/v1" (and only those its granted
// capabilities allow) and exports:
//
//   memory                        its linear memory
//   rk_abi_version() -> i32       the interface major version it was built for (1)
//   rk_alloc(size i32) -> i32     a buffer of `size` bytes for the host to write input into
//   rk_analyze(ptr, len) -> i32   analyzers: input is an AnalyzeRequest
//   rk_load(ptr, len) -> i32      loaders: input is the file's bytes
//   rk_command(ptr, len) -> i32   commands: input is a CommandRequest
//
// The entry point returns 0 on success, with its result passed to
// set_output; anything else is a failure, and the output (if any) is the
// message. fail(ptr, len) ends the call at once with a message. Every call runs in a fresh instance, so nothing survives from
// one call to the next.
//
// Blobs (requests, results, and what the fact imports return) use one
// little-endian encoding:
//   u8, u32, u64     fixed width, little endian
//   str              u32 length, then that many bytes (UTF-8 for text)
//   list<T>          u32 count, then the items
//   record           u32 size, then the fields; a reader skips fields it
//                    does not know, so a minor version may append fields
#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>

namespace revkit::plugins::abi {

// The interface major version this host speaks. A plugin whose manifest or
// rk_abi_version() names another is rejected at load.
inline constexpr std::uint32_t kInterfaceVersion = 1;
// Within a major version, records may grow fields at their end and new
// imports may appear; this counts those additions.
inline constexpr std::uint32_t kInterfaceMinor = 1;  // 1: peripheral plugins

inline constexpr std::string_view kImportModule = "revkit:plugin/v1";

inline constexpr std::string_view kExportMemory = "memory";
inline constexpr std::string_view kExportVersion = "rk_abi_version";
inline constexpr std::string_view kExportAlloc = "rk_alloc";
inline constexpr std::string_view kExportAnalyze = "rk_analyze";
inline constexpr std::string_view kExportLoad = "rk_load";
inline constexpr std::string_view kExportCommand = "rk_command";
// Peripherals (kind "peripheral"): one instance lives as long as the
// emulation session, so its state carries from call to call.
//   rk_peripheral_buffer() -> i32            a buffer of at least 4096 bytes for input from the host
//   rk_peripheral_init(ptr, len) -> i32      the peripheral's JSON object from the machine description
//   rk_peripheral_read(offset i64, size i32) -> i64
//   rk_peripheral_write(offset i64, size i32, value i64) -> i32
//   rk_peripheral_tick(now i64) -> i32       optional: the time asked for with schedule() came
//   rk_peripheral_input(ptr, len) -> i32     optional: host input (a UART's receiver), in the buffer
//   rk_peripheral_irq_in(line i32, level i32) -> i32  optional: an interrupt input changed (controllers)
//   rk_peripheral_reset() -> i32             optional: the machine resets
inline constexpr std::string_view kExportPeripheralBuffer = "rk_peripheral_buffer";
inline constexpr std::string_view kExportPeripheralInit = "rk_peripheral_init";
inline constexpr std::string_view kExportPeripheralRead = "rk_peripheral_read";
inline constexpr std::string_view kExportPeripheralWrite = "rk_peripheral_write";
inline constexpr std::string_view kExportPeripheralTick = "rk_peripheral_tick";
inline constexpr std::string_view kExportPeripheralInput = "rk_peripheral_input";
inline constexpr std::string_view kExportPeripheralIrqIn = "rk_peripheral_irq_in";
inline constexpr std::string_view kExportPeripheralReset = "rk_peripheral_reset";
inline constexpr std::uint32_t kPeripheralBuffer = 4096;

// Return values of the fact imports that stage a blob (program_info,
// functions, function_code, symbol_name): the blob's length, or one of these.
inline constexpr std::int32_t kNotFound = -1;

// What an analyzer derives (AnalyzeResult facts).
enum class FactKind : std::uint8_t {
  label = 1,      // a name for the address
  comment = 2,    // `sub` is the comment kind: eol, pre, post, plate
  data_type = 3,  // a C type for the data at the address
  note = 4,       // free-form; `sub` is a tag
};

// What a command asks to assert (CommandResult edits).
enum class EditOp : std::uint8_t {
  rename = 1,    // text = the new name
  comment = 2,   // text = the comment, sub = its kind (eol if empty)
  function = 3,  // a function starts at the address
  note = 4,      // text = the note, sub = its tag
};

// Memory block permissions (ProgramInfo, LoadResult).
enum Perm : std::uint8_t { kRead = 1, kWrite = 2, kExec = 4 };

// Analyzer scopes (AnalyzeRequest.scope).
enum class Scope : std::uint8_t { program = 0, function = 1 };

class AbiError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class Writer {
 public:
  void u8(std::uint8_t v) { buf_.push_back(static_cast<char>(v)); }
  void u32(std::uint32_t v) {
    for (int i = 0; i < 4; ++i) buf_.push_back(static_cast<char>(v >> (8 * i)));
  }
  void u64(std::uint64_t v) {
    for (int i = 0; i < 8; ++i) buf_.push_back(static_cast<char>(v >> (8 * i)));
  }
  void str(std::string_view s) {
    u32(static_cast<std::uint32_t>(s.size()));
    buf_.append(s);
  }
  // Starts a record or list; end() patches its size or count.
  std::size_t begin() {
    std::size_t at = buf_.size();
    u32(0);
    return at;
  }
  void end_record(std::size_t at) { patch(at, static_cast<std::uint32_t>(buf_.size() - at - 4)); }
  void end_list(std::size_t at, std::uint32_t count) { patch(at, count); }

  const std::string &bytes() const { return buf_; }
  std::string take() && { return std::move(buf_); }

 private:
  void patch(std::size_t at, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) buf_[at + i] = static_cast<char>(v >> (8 * i));
  }
  std::string buf_;
};

class Reader {
 public:
  explicit Reader(std::string_view in) : in_(in) {}

  std::uint8_t u8() { return static_cast<std::uint8_t>(take(1)[0]); }
  std::uint32_t u32() {
    auto s = take(4);
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= std::uint32_t(static_cast<std::uint8_t>(s[i])) << (8 * i);
    return v;
  }
  std::uint64_t u64() {
    auto s = take(8);
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= std::uint64_t(static_cast<std::uint8_t>(s[i])) << (8 * i);
    return v;
  }
  std::string_view str() { return take(u32()); }
  // A record's fields as a reader of their own; this reader moves past it.
  Reader record() { return Reader(take(u32())); }
  // A list's count, checked against what is left (every item is at least
  // `min_item` bytes), so a hostile count can't make the host allocate.
  std::uint32_t list(std::size_t min_item = 1) {
    std::uint32_t n = u32();
    if (min_item && n > remaining() / min_item) throw AbiError("list count exceeds the data");
    return n;
  }
  bool done() const { return pos_ == in_.size(); }
  std::size_t remaining() const { return in_.size() - pos_; }

 private:
  std::string_view take(std::size_t n) {
    if (n > in_.size() - pos_) throw AbiError("truncated blob");
    std::string_view s = in_.substr(pos_, n);
    pos_ += n;
    return s;
  }
  std::string_view in_;
  std::size_t pos_ = 0;
};

}  // namespace revkit::plugins::abi
