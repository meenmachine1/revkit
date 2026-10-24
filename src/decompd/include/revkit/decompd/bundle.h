// Self-contained decompiler input bundles.
//
// A bundle holds everything Ghidra's decompiler asks about while it
// decompiles one function: the bytes it reads, the answers to its symbol,
// label, type and comment queries (what lift::FactLookup or infer's
// SymbolEnv would answer in process), the function's flow overrides,
// tracked registers and recovered jump tables, the decoding context and the
// options. A decompiler worker (rk-decompd) decompiles from a bundle alone:
// it never calls back into the process that made it. Bundles encode
// canonically, so equal inputs give equal bytes, and their hash is the
// decompilation's cache key and an exact repro (rk-decompd --bundle).
//
// The parent assembles a bundle before the decompiler runs, from what it
// predicts the decompiler will ask (builder.h). A query the bundle doesn't
// answer is a miss: the worker answers it as "nothing" (no symbol, no type;
// bytes it lacks read as unreadable, so the decompiler never follows made-up
// code), carries on, and reports it; the parent then looks the missed keys
// up. If every true answer is what the worker assumed, the run stands (the
// bundle with those answers added gives the same output); otherwise the
// parent decompiles again with them added. Misses are counted, never
// answered by calling back.
#pragma once

#include "revkit/facts/codec.h"
#include "revkit/facts/fingerprint.h"
#include "revkit/lift/budget.hh"
#include "revkit/lift/context.hh"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/lift/image_arch.hh"
#include "revkit/loader/image.hh"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace revkit::decompd {

// Bumped when the encoding or its meaning changes.
inline constexpr std::uint32_t kBundleVersion = 6;  // 2: types encoded; 3: functions' context_reach; 4: this_guessed; 5: calls' signature overrides; 6: source-shape options
// Bytes travel in aligned chunks of this size.
inline constexpr std::uint64_t kChunk = 1024;

// What a worker does with a bundle, and what its result holds.
enum class Mode : std::uint8_t {
  c_text = 1,   // lift::InputDecompiler with the C printer: lift::DecompileResult (rk-lift)
  tokens = 2,   // the same with the image backend's token printer: backend::DecompileOutput (rk-daemon)
  observe = 3,  // infer::Decompiler: infer::Observation (rk-infer, prototype inference)
  param_id = 4,  // c_text's decompiler as Ghidra's Decompiler Parameter ID runs it (unreachable
                 // code kept, no printing): the lift::CommittedSignature (param_id.h)
  signature = 5,  // the "normalize" action group and BSim's GraphSigManager, no printing: the
                  // FunctionSignature (signature.h); Bundle::extra holds the SignatureOptions
};
const char *mode_name(Mode m);

// An address in a named space ("" for the default code/data space).
using SpaceAddr = std::pair<std::string, std::uint64_t>;

// What lift::FactLookup answers about one address. Indexes are into
// LiftFacts' tables (-1: nothing).
struct AddressAnswer {
  std::int32_t starts = -1;    // function_at
  std::int32_t contains = -1;  // body_containing, with the range below
  std::uint64_t body_first = 0, body_last = 0;
  std::int32_t data = -1;      // data_containing
  std::int32_t external = -1;  // external_at
  std::int32_t label = -1;     // label_at
  std::optional<lift::Mutability> block;  // block_at

  friend bool operator==(const AddressAnswer &, const AddressAnswer &) = default;
  void encode(facts::Encoder &e) const;
  static AddressAnswer decode(facts::Decoder &d);
};

// The lift modes' answers (c_text, tokens).
struct LiftFacts {
  // lift::DecompileConfig's naming options.
  bool default_names = true;
  bool default_labels = true;
  bool default_extrapop = true;
  // lift::DecompileConfig::format_strings: call-site prototypes from
  // constant printf/scanf formats.
  bool format_strings = false;
  // lift::DecompileConfig::shape: the fork's source-shape options.
  lift::SourceShape shape;
  std::string address_prefix;
  // block_at for an address without an answer of its own.
  std::vector<lift::BlockFacts> blocks;
  // The spaces the parent's facts can say anything about ("" the default
  // space): an address elsewhere (a register) has no answer to miss.
  std::vector<std::string> spaces{std::string()};

  std::vector<lift::FunctionFacts> functions;
  std::vector<lift::DataFacts> data;
  std::vector<lift::ExternalRefFacts> externals;
  std::vector<lift::LabelFacts> labels;
  std::map<SpaceAddr, AddressAnswer> addresses;
  std::map<SpaceAddr, std::optional<std::string>> code_labels;
  // Types by id, each its encoded lift::DecompElement ("" where the lookup
  // has none): decoded by a worker only when the decompiler asks.
  std::map<std::uint64_t, std::string> types;
  // About the function being decompiled (FactLookup::comments,
  // flow_overrides, tracked at the entry).
  std::vector<lift::CommentFacts> comments;
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides;
  std::vector<lift::TrackedFacts> tracked;
  // lift::RunHooks: recovered jump tables, and flow overrides and comments
  // besides the lookup's.
  std::map<std::uint64_t, std::vector<std::uint64_t>> jump_tables;
  std::vector<std::pair<std::uint64_t, std::string>> hook_flow_overrides;
  std::vector<lift::CommentFacts> hook_comments;
  // lift::RunHooks: the user's equates, call targets and jump tables.
  std::vector<lift::EquateFacts> hook_equates;
  std::map<std::uint64_t, std::uint64_t> hook_call_targets;
  std::vector<std::uint64_t> hook_forced_tables;  // sorted
  // Calls' signature overrides (RunHooks::call_protos).
  std::map<std::uint64_t, lift::FunctionFacts> hook_call_protos;

  // The answer block_at gives where `addresses` has none.
  std::optional<lift::Mutability> default_block(const std::string &space, std::uint64_t a) const;

  void encode(facts::Encoder &e) const;
  static LiftFacts decode(facts::Decoder &d);
};

struct Bundle {
  Mode mode = Mode::c_text;
  std::string language_id;  // with the compiler: "x86:LE:64:default:gcc"
  std::uint64_t entry = 0;
  // The image as far as a decompiler sees it: format, pointer size and
  // blocks (for infer's block lookups), the ranges that hold bytes (the
  // file's memory and the loader's patches), and the bytes it reads, as
  // the loader's patches leave them.
  loader::Format format = loader::Format::elf;
  unsigned bits = 64;
  std::vector<loader::Block> image_blocks;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> mapped;  // inclusive, sorted, disjoint
  std::map<std::uint64_t, std::string> chunks;                  // chunk index -> kChunk bytes
  std::vector<lift::ContextRegion> context;
  // Join records to lay out before decompiling (in that order), as earlier
  // functions decompiled on the same architecture left them: batch tools
  // that decompile a program in address order on one decompiler (--in-order,
  // Ghidra's sequence) chain them; otherwise unset, and a worker's records
  // are whatever its earlier functions left (variable numbering of
  // multi-register values only, as in process).
  std::optional<std::vector<lift::JoinFacts>> joins;
  LiftFacts lift;      // c_text, tokens, param_id, signature
  std::string extra;   // observe: infer's encoding of its answers; signature: its options

  bool mapped_at(std::uint64_t a) const;
  // Everything a worker caches an architecture for (mode, language,
  // naming options, image shape, context): bundles with the same key can
  // share one.
  std::string arch_key() const;

  void encode(facts::Encoder &e) const;
  static Bundle decode(facts::Decoder &d);
};

std::string encode_bundle(const Bundle &b);
Bundle decode_bundle(std::string_view bytes);  // throws facts::DecodeError
// "b2-" and the 128-bit fingerprint of the encoding, in hex.
std::string bundle_hash(std::string_view encoded);

// A query a bundle didn't answer.
struct Miss {
  enum Kind : std::uint8_t {
    address = 1,     // a FactLookup address query (function, body, data, external, label, block)
    code_label = 2,  // FactLookup::code_label_at
    type = 3,        // FactLookup::type (value: the id)
    chunk = 4,       // bytes (value: the chunk index)
    entry = 5,       // comments, flow overrides or tracked registers of another function
    function = 6,    // observe: SymbolEnv::function
    import = 7,      // observe: SymbolEnv::import_slot
  };
  Kind kind = address;
  std::string space;
  std::uint64_t value = 0;

  friend auto operator<=>(const Miss &, const Miss &) = default;
  void encode(facts::Encoder &e) const;
  static Miss decode(facts::Decoder &d);
};

// One run's bounds, which aren't part of the bundle (a failure records them).
struct Limits {
  double timeout_seconds = 0;  // cooperative (lift::DecompileLimits); 0: none
  std::uint64_t max_varnodes = 0;

  void encode(facts::Encoder &e) const;
  static Limits decode(facts::Decoder &d);
};

// What a run reports besides its mode's payload.
struct RunResult {
  bool ran = false;     // false: the worker couldn't run it (`error` says why)
  std::string error;
  std::string payload;  // the mode's result, encoded (lift_result.h, backend, infer)
  lift::DecompileStop stopped = lift::DecompileStop::none;
  std::vector<Miss> misses;           // sorted, unique
  std::vector<SpaceAddr> asked;       // addresses the decompiler looked up (sorted)
  std::vector<std::uint64_t> asked_functions;  // observe: entries SymbolEnv::function was asked
  std::vector<lift::JoinFacts> joins_made;     // with Bundle::joins: records this run added
  std::uint64_t varnodes = 0;
  double milliseconds = 0;
  std::uint64_t rss = 0;       // the worker's resident memory after the run (bytes)
  std::uint64_t rss_anon = 0;  // of which not file-backed

  void encode(facts::Encoder &e) const;
  static RunResult decode(facts::Decoder &d);
};

}  // namespace revkit::decompd
