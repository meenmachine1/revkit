// One loaded binary: the image, its language, and the engines that read it
// (SLEIGH lifters, decompiler instances). Immutable once loaded and safe to
// share between threads.
//
// It holds no derived facts: the analyses below are pure functions of the
// image and of what function discovery (revkit::analysis) found, run by the
// fact-store queries in queries.h, which memoize and persist their results.
#pragma once

#include "data_settings.h"
#include "decompiler.h"
#include "model.h"
#include "pool.h"
#include <chrono>

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/memory.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/image.hh"
#include "revkit/loader/load.hh"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <thread>
#include <optional>
#include <string>
#include <vector>

namespace revkit::backend {

// Patches laid over the image's bytes (docs/patching.md): what the
// decoding helpers below read when given one, so the listing,
// instructions and memory show the program as patched. Bytes no patch
// touches decode exactly as without one.
class PatchedBytes {
 public:
  virtual ~PatchedBytes() = default;
  // The live patches overlapping [first, last], lower precedence first.
  virtual facts::PatchList overlapping(std::uint64_t first, std::uint64_t last) = 0;
};

// From a query: the patch spans read become its dependencies.
class QueryPatches final : public PatchedBytes {
 public:
  QueryPatches(facts::QueryContext &ctx, facts::SpaceId space) : ctx_(ctx), space_(space) {}
  facts::PatchList overlapping(std::uint64_t first, std::uint64_t last) override {
    return facts::patches_overlapping(ctx_, space_, first, last);
  }

 private:
  facts::QueryContext &ctx_;
  facts::SpaceId space_;
};

// From a snapshot (request handlers).
class SnapshotPatches final : public PatchedBytes {
 public:
  SnapshotPatches(const facts::Snapshot &snap, facts::SpaceId space) : snap_(snap), space_(space) {}
  facts::PatchList overlapping(std::uint64_t first, std::uint64_t last) override {
    return facts::patches_overlapping(snap_, space_, first, last);
  }

 private:
  const facts::Snapshot &snap_;
  facts::SpaceId space_;
};

class Program : public std::enable_shared_from_this<Program> {
 public:
  struct Options {
    std::string language_id;       // "proc:endian:size:variant"; empty = detect
    std::string compiler_spec_id;  // empty = detect
    std::optional<std::uint64_t> image_base;
    std::string macho_slice;  // a universal Mach-O's slice (loader::LoadOptions); empty: the default
    unsigned decompilers = 2;
    // Decompiler workers shared with other programs (null: the program's own).
    std::shared_ptr<decompd::WorkerPool> decompile_workers;
    // Bounds on each decompilation unless the request sets its own
    // (DecompileLimitsScope).
    lift::DecompileLimits decompile_limits;
    unsigned lifters = 4;
    // Read the image's DWARF and, for a PE, its PDB (looked up beside
    // `binary`, the path it was read from, if known).
    bool debug_info = true;
    std::filesystem::path binary;
    // An ELF without .debug_info: its separate debug file, found and
    // checked (debug_files.h), and where it was; null when there is none.
    struct DebugFile {
      std::filesystem::path file;
      std::shared_ptr<const loader::Bytes> bytes;
    };
    std::function<std::optional<DebugFile>(const loader::Image &)> find_debug_file;
    // An image a loader plugin built (docs/plugins.md): used instead of
    // parsing the file, with `format` ("plugin:name@version") and, unless
    // language_id is set, `language`.
    std::shared_ptr<const loader::Image> image;
    std::string format;
    loader::LanguageSpec language;
    // A raw image laid out as this says (format "raw"); language_id is
    // required.
    std::optional<loader::RawOptions> raw;
    // Called once the image is parsed and its language known, before the
    // debug info is read (an import's progress: loading ends there).
    std::function<void(const loader::Image &)> loaded;
    // The pool a discovery of a large image is about to run on: its SLEIGH
    // engines are built there in the background once the language is known
    // (analysis::prepare_decoders; WaitForDecoders()).
    facts::ThreadPool *discovery_pool = nullptr;
  };

  // Parses and picks the language. Throws loader::LoadError or
  // lift::LiftError.
  static std::shared_ptr<Program> Load(std::shared_ptr<const loader::Bytes> bytes, const Options &options);
  // Until the engines Options::discovery_pool asked for are built.
  void WaitForDecoders() const {
    if (preparing_ && preparing_->joinable()) preparing_->join();
  }

  // The program with a memory map's edits laid over its image
  // (docs/memory-map.md): itself when `map` has none; else a program over a
  // copy of its image with the blocks edited and the user's regions added,
  // their bytes from `bytes` (a region's staged bytes, as RegionBytes says
  // where; null if they can't be read: the region is then uninitialized).
  // It shares the language, debug info, decompiler workers and the
  // bookkeeping below with this one; its SLEIGH engines and decompiler
  // architecture read the new image. Built once per map, the last few kept.
  // Call it on the loaded program (ProgramSource::program).
  using RegionBytesReader = std::function<std::shared_ptr<const loader::Bytes>(const analysis::RegionBytes &)>;
  std::shared_ptr<const Program> WithMemory(const analysis::MemoryMapInfo &map, const RegionBytesReader &bytes) const;

  const loader::Image &image() const { return *image_; }
  const std::shared_ptr<const loader::Image> &image_ptr() const { return image_; }
  const loader::LanguageSpec &language() const { return language_; }
  const std::string &format() const { return format_; }
  const std::string &code_space() const { return code_space_; }
  // The language's address spaces, in SLEIGH's order.
  const std::vector<lift::SpaceDef> &spaces() const { return spaces_; }
  const std::vector<std::string> &warnings() const { return warnings_; }
  // Loaded address minus link-time address (rebased PIEs), for debug info.
  std::uint64_t rebase_delta() const { return rebase_delta_; }

  // Mapped and initialized bytes from addr, up to len (stops at a gap);
  // with `patches`, as patched.
  std::string read(std::uint64_t addr, std::uint32_t len, PatchedBytes *patches = nullptr) const;
  // The bytes the program was loaded from (before any relocation), and the
  // image those bytes load to with this program's options (verification of
  // an export); null for a loader plugin's image.
  const std::shared_ptr<const loader::Bytes> &file() const { return file_; }
  std::shared_ptr<const loader::Image> Reload(std::shared_ptr<const loader::Bytes> bytes) const;
  const loader::Block *block_containing(std::uint64_t addr) const;
  bool executable(std::uint64_t addr) const;

  // One instruction with p-code, and the names of the registers its p-code
  // touches, keyed by (offset, size). nullopt if nothing decodes at addr.
  struct Decoded {
    lift::Instruction insn;
    std::map<std::pair<std::uint64_t, std::uint32_t>, std::string> registers;
  };
  // With `thumb` (ARM), decoded as Thumb; with `patches`, as patched.
  std::optional<Decoded> instruction(std::uint64_t addr, bool thumb = false, PatchedBytes *patches = nullptr) const;

  DecompilerPool &decompiler() const { return *decompiler_; }
  // Lets the SLEIGH engines idle for `idle_for` go to their language's
  // spares (docs/memory.md "SLEIGH engines"), this program's and its
  // memory-map variants'. How many parked.
  std::size_t ParkIdleEngines(std::chrono::steady_clock::duration idle_for) const;
  // The debug info read at load (null if none): the decompiler's inputs and
  // the import assertions both come from it.
  const std::shared_ptr<const inputs::DebugInfo> &debug() const { return debug_; }
  // The separate debug file its DWARF came from ("" its own, or none).
  const std::filesystem::path &debug_file() const { return debug_file_; }
  // A SLEIGH engine over the image, for the caller's exclusive use.
  Pool<lift::Lifter>::Lease lifter() const { return lifters_->Acquire(); }
  // One only the stack analysis of functions' decompiler inputs decodes
  // with (inputs::assemble_function), as rk-lift's: what other decoding
  // commits to the context (SLEIGH globalset: a Thumb bl's target is
  // Thumb) doesn't reach it, so ARM functions keep their stack locals.
  Pool<lift::Lifter>::Lease walk_lifter() const { return walk_lifters_->Acquire(); }

  // What function discovery starts from: code ranges, seeds, import slots.
  // `space` is the program's code space in the fact store.
  // With `bytes`, reading the program as patched (analysis::describe).
  analysis::ProgramInfo Describe(facts::SpaceId space, const analysis::ByteSource &bytes = {}) const;

  // --- Analyses (pure functions of the image and discovery's results) ---

  // Defined non-function symbols in mapped memory and PE import slots,
  // with symbol sizes. Seed entries (`info`) are functions, not labels.
  LabelMap LoaderLabels(const analysis::ProgramInfo &info) const;
  // Listing spans of the instructions discovery reached.
  CodeMap Code(const std::vector<analysis::CodeUnit> &code) const;
  // References from one function's instructions: p-code operands, and
  // computed jumps to their jump tables' destinations.
  std::vector<StaticXref> FunctionXrefs(const analysis::FunctionInfo &f, const analysis::FlowGraph &flow) const;
  // The operand a reference is in: the first address or scalar token of
  // the instruction's display text holding its target, else -1.
  int XrefOperand(const StaticXref &x) const;
  // Loader labels plus FUN_/LAB_/DAT_ for unnamed reference targets.
  // `data`: analysis::Data's items, which name their addresses as
  // Ghidra's database does (s_<text>_<address>, PTR_<target>_<address>).
  LabelMap DefaultLabels(const LabelMap &loader_labels, const FunctionTable &functions, const XrefTable &xrefs,
                         const analysis::DataList &data) const;
  // Code spans plus data spans for the gaps, split at labels, numbered.
  // Each data item is one DATA row.
  RowIndex Rows(const CodeMap &code, const LabelMap &labels, const analysis::DataList &data) const;
  // Rows [page * kPageRows, ...) with bytes and SLEIGH tokens, as patched.
  // Data rows show as `settings` say (data_settings.h; none: as their types do).
  std::vector<StaticRow> Page(const RowIndex &rows, std::int64_t page, PatchedBytes *patches = nullptr,
                              const DataSettingsMap *settings = nullptr) const;
  // `k`: the row's index in its span (a user's expanded item: 0 is the
  // item, then its fields or elements).
  void DataRow(const RowIndex &rows, const ListingSpan &span, std::int64_t k, StaticRow &row,
               PatchedBytes *patches = nullptr, const DataSettingsMap *settings = nullptr) const;
  // A user data item's own fields' and elements' rows when expanded.
  static std::uint32_t DataComponents(const analysis::DataItem &d);
  void UserValue(analysis::ValueFormat format, std::uint64_t at, std::uint64_t size, StaticRow &row,
                 PatchedBytes *patches, const DataSettings &settings = {}) const;
  // A value of `format` with settings (none empty): integers, floats, pointers, char arrays.
  void SetValue(analysis::ValueFormat format, std::uint64_t at, std::uint64_t size, StaticRow &row,
                PatchedBytes *patches, const DataSettings &settings) const;
  static constexpr std::uint32_t kMaxDataRowBytes = 4096;  // bytes a data row carries
  static constexpr std::uint64_t kMaxElementRows = 4096;   // an expanded array's element rows

  // --- Bookkeeping for subscription events ---

  // Functions whose decompilation looked up `target`, from the
  // decompilations served so far: best effort, used only to widen events.
  void NoteDecompile(std::uint64_t entry, const std::vector<std::uint64_t> &touched) const;
  std::vector<std::uint64_t> DecompilesTouching(std::uint64_t target) const;
  // Every function whose decompilation was served so far.
  std::vector<std::uint64_t> DecompilesServed() const;

  // The escalated retry of a timed-out decompilation (DecompileOptions.
  // escalate), by the bundle hash it failed on: what later requests for a
  // function with that bundle get instead of the timeout.
  std::shared_ptr<const DecompileOutput> Escalated(const std::string &bundle_hash) const;
  void SetEscalated(const std::string &bundle_hash, std::shared_ptr<const DecompileOutput> out) const;

  // Whether the decompilation last served for a function failed (a crash,
  // a timeout, out of memory): Function.decompile_failed, best effort.
  void NoteDecompileFailure(std::uint64_t entry, bool failed) const;
  bool DecompileFailed(std::uint64_t entry) const;

 private:
  Program() = default;
  std::shared_ptr<const loader::Bytes> file_;
  std::unique_ptr<lift::Lifter> MakeLifter() const;

  std::shared_ptr<const loader::Image> image_;
  loader::LanguageSpec language_;
  std::string format_;
  std::string code_space_ = "ram";
  std::vector<lift::SpaceDef> spaces_;
  std::vector<std::string> warnings_;
  std::uint64_t rebase_delta_ = 0;
  Options options_;
  std::shared_ptr<std::jthread> preparing_;  // analysis::prepare_decoders, if asked

  // The SLEIGH engine pools and the decompiler, over image_.
  void MakeEngines(std::unique_ptr<DecompilerPool> decompiler);

  std::unique_ptr<Pool<lift::Lifter>> lifters_;
  std::unique_ptr<Pool<lift::Lifter>> thumb_lifters_;  // ARM: TMode set everywhere
  std::unique_ptr<Pool<lift::Lifter>> walk_lifters_;   // see walk_lifter()
  std::unique_ptr<DecompilerPool> decompiler_;
  std::shared_ptr<const inputs::DebugInfo> debug_;
  std::filesystem::path debug_file_;

  // What the program's memory-map variants share with it: the bookkeeping
  // below is per program, whatever its memory.
  struct Shared {
    std::mutex touch_mu;
    std::map<std::string, std::shared_ptr<const DecompileOutput>> escalated;
    std::map<std::uint64_t, std::vector<std::uint64_t>> touched_by;  // target -> functions
    std::set<std::uint64_t> served;
    std::set<std::uint64_t> failed;
  };
  std::shared_ptr<Shared> shared_ = std::make_shared<Shared>();
  // The loaded program's variants by the encoded map they were built for,
  // most recent first (variants hold none: no cycle).
  mutable std::mutex variants_mu_;
  mutable std::vector<std::pair<std::string, std::shared_ptr<const Program>>> variants_;
};

std::string FormatAddressName(const char *prefix, std::uint64_t addr);

// An instruction's flow as its p-code decodes (no override), with its
// static branch and call targets in `targets`.
pb::FlowKind FlowOf(const lift::Instruction &insn, const std::string &code_space, std::vector<std::uint64_t> &targets);

}  // namespace revkit::backend
