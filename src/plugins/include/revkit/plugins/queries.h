// Plugins in the fact engine.
//
// An analyzer is a query: plugins.analyze(plugin, module fingerprint,
// program, scope) runs the plugin and memoizes what it derives. Everything
// the plugin reads during the call goes through the query's context, so the
// memo depends on exactly the facts it looked at and is invalidated like a
// built-in rule's:
//
//   import            reads                                          via
//   program_info      plugins.program, analysis.program              plugins.program_info
//   memory_read       the pages it read (facts::MemoryPage)          (direct)
//   file_read         the file's pages it read                       (direct)
//   functions         analysis.functions, NAME at every entry        plugins.functions
//   function_code     analysis.function, that function's pages       plugins.code
//   symbol_name       NAME at the address, analysis.function there   plugins.name
//
// A patched byte re-runs the analyzers that read its page; a rename re-runs
// those that asked for that name (or for the function list). The module
// fingerprint is in the key, so a rebuilt plugin never reuses old memos.
// Determinism (no clocks, randomness or host state, fuel instead of time)
// is what makes memoizing them sound; a deterministic failure (a trap, out
// of fuel or memory) is memoized as the result, a timeout is not.
//
// Commands read the same facts through a Snapshot (StoreFacts<Snapshot>).
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/memory.h"
#include "revkit/facts/engine.h"
#include "revkit/facts/fact_db.h"
#include "revkit/plugins/host.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace revkit::plugins {

// ---- inputs --------------------------------------------------------------

struct Block {
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  std::uint8_t perms = 0;  // abi::Perm
  bool initialized = true;

  void encode(facts::Encoder &e) const;
  static Block decode(facts::Decoder &d);
  friend bool operator==(const Block &, const Block &) = default;
};

// What plugins see of a program beyond discovery's ProgramInfo: its memory
// map, entry point and where its file's bytes are.
struct ProgramFacts {
  std::vector<Block> blocks;  // sorted by start
  std::optional<std::uint64_t> entry;
  facts::SpaceId file_space = 0;  // 0: the file's bytes aren't in the store
  std::uint64_t file_size = 0;

  const Block *block_at(std::uint64_t a) const;
  void encode(facts::Encoder &e) const;
  static ProgramFacts decode(facts::Decoder &d);
  friend bool operator==(const ProgramFacts &, const ProgramFacts &) = default;
};

// Input, set at import (stage_program) next to analysis::Program.
struct Program {
  static constexpr std::string_view name = "plugins.program";
  using Key = analysis::ProgramKey;
  using Value = ProgramFacts;
  static std::string describe(const Key &k) { return k.id; }
};

ProgramFacts describe(const loader::Image &image, facts::SpaceId file_space, std::uint64_t file_size);
// Stages ProgramFacts for the image, in the caller's transaction. The file's
// bytes, if plugins may read them, are the caller's to write to file_space.
void stage_program(facts::FactDb::Transaction &tx, const analysis::ProgramKey &program, const loader::Image &image,
                   facts::SpaceId file_space, std::uint64_t file_size);

// ---- fact blobs (the ABI encoding, memoized) ---------------------------------

struct ProgramInfoBlob {
  static constexpr std::string_view name = "plugins.program_info";
  static constexpr std::uint32_t version = 2;  // 2: the memory map's blocks (docs/memory-map.md)
  using Key = analysis::ProgramKey;
  using Value = std::string;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

struct FunctionsBlob {
  static constexpr std::string_view name = "plugins.functions";
  static constexpr std::uint32_t version = 1;
  using Key = analysis::ProgramKey;
  using Value = std::string;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

// The function's instructions with p-code; empty if none starts there.
struct CodeBlob {
  static constexpr std::string_view name = "plugins.code";
  static constexpr std::uint32_t version = 2;  // 2: patches through patch.page
  using Key = analysis::Location;
  using Value = std::string;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// The effective name at an address: a NAME assertion, else the discovered
// function's name, else empty.
struct Name {
  static constexpr std::string_view name = "plugins.name";
  static constexpr std::uint32_t version = 1;
  using Key = analysis::Location;
  using Value = std::string;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return analysis::describe(k); }
};

// ---- analyzers -------------------------------------------------------------

struct AnalyzeKey {
  std::string plugin;       // name@version
  std::string fingerprint;  // the module's
  analysis::ProgramKey program;
  abi::Scope scope = abi::Scope::program;
  std::uint64_t address = 0;  // function scope: the entry

  void encode(facts::Encoder &e) const;
  static AnalyzeKey decode(facts::Decoder &d);
  friend auto operator<=>(const AnalyzeKey &, const AnalyzeKey &) = default;
};

struct AnalyzeOutput {
  Failure failure = Failure::none;
  std::string error;
  std::vector<DerivedItem> facts;
  std::uint64_t fuel = 0;
  std::vector<std::string> log;

  void encode(facts::Encoder &e) const;
  static AnalyzeOutput decode(facts::Decoder &d);
  friend bool operator==(const AnalyzeOutput &, const AnalyzeOutput &) = default;
};

// Throws (and so is not memoized) when the module isn't loaded in this
// process or the call timed out.
struct Analyze {
  static constexpr std::string_view name = "plugins.analyze";
  static constexpr std::uint32_t version = 1;
  using Key = AnalyzeKey;
  using Value = AnalyzeOutput;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k);
};

// The keys to read for one analyzer over a program: one per function
// (whose entry is in [first, last]) for function-scope analyzers, else one.
std::vector<AnalyzeKey> analyze_keys(const facts::Snapshot &snap, const Plugin &p, const analysis::ProgramKey &program,
                                     std::uint64_t first = 0, std::uint64_t last = UINT64_MAX);

// Registers the input and queries above. Needs analysis::register_queries.
void register_queries(facts::Engine &engine);

// ---- the fact provider --------------------------------------------------------

// Answers a plugin's fact imports from the store, through `Reader` (a
// QueryContext inside a query, or a Snapshot).
template <class Reader>
class StoreFacts final : public FactProvider {
 public:
  StoreFacts(Reader &reader, analysis::ProgramKey program) : r_(reader), program_(std::move(program)) {}

  std::string program_info() override { return *r_.template get<ProgramInfoBlob>(program_); }
  std::size_t memory_read(std::uint64_t addr, std::span<std::byte> out) override {
    // With memory-map edits: the effective map's blocks, and an added
    // region's bytes where ProgramInfo::sources says they are.
    if (const analysis::MemoryMapInfo &map = memory(); map.edited) {
      const analysis::ProgramInfo &pi = info();
      std::size_t n = 0;
      while (n < out.size()) {
        const std::uint64_t a = addr + n;
        if (a < addr) break;  // wrapped
        const analysis::MemoryBlock *b = map.block(a);
        if (!b || !b->initialized) break;
        std::uint64_t last = b->range.last;
        std::size_t chunk = 0;
        auto s = std::find_if(pi.sources.begin(), pi.sources.end(), [&](const auto &x) { return x.range.contains(a); });
        if (s != pi.sources.end()) {
          last = std::min(last, s->range.last);
          if (s->space == 0) {
            chunk = static_cast<std::size_t>(std::min<std::uint64_t>(out.size() - n, last - a + 1));
            std::fill(out.begin() + n, out.begin() + n + chunk, std::byte{0});
          } else {
            const std::uint64_t at = s->offset + (a - s->range.first);
            chunk = copy(s->space, at, out.subspan(n), at + (last - a));
            if (chunk) {  // the file's bytes, then the patches over them
              std::string bytes(reinterpret_cast<const char *>(out.data() + n), chunk);
              facts::apply_patches(facts::patches_overlapping(r_, pi.space, a, a + (chunk - 1)), a, bytes);
              std::memcpy(out.data() + n, bytes.data(), chunk);
            }
          }
        } else {
          chunk = copy(pi.space, a, out.subspan(n), last);
        }
        if (!chunk) break;
        n += chunk;
      }
      return n;
    }
    const ProgramFacts &pf = facts();
    std::size_t n = 0;
    while (n < out.size()) {
      const std::uint64_t a = addr + n;
      if (a < addr) break;  // wrapped
      const Block *b = pf.block_at(a);
      if (!b || !b->initialized) break;
      const std::size_t chunk = copy(info().space, a, out.subspan(n), b->start + (b->size - 1));
      if (!chunk) break;
      n += chunk;
    }
    return n;
  }
  std::uint64_t file_size() override { return facts().file_space ? facts().file_size : 0; }
  std::size_t file_read(std::uint64_t offset, std::span<std::byte> out) override {
    const ProgramFacts &pf = facts();
    if (!pf.file_space || offset >= pf.file_size) return 0;
    std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), pf.file_size - offset));
    std::size_t n = 0;
    while (n < want) {
      std::size_t chunk = copy(pf.file_space, offset + n, out.subspan(n, want - n), pf.file_size - 1);
      if (!chunk) break;
      n += chunk;
    }
    return n;
  }
  std::string functions() override { return *r_.template get<FunctionsBlob>(program_); }
  std::optional<std::string> function_code(std::uint64_t entry) override {
    auto blob = r_.template get<CodeBlob>(analysis::Location{program_, entry});
    if (blob->empty()) return std::nullopt;
    return *blob;
  }
  std::string symbol_name(std::uint64_t addr) override { return *r_.template get<Name>(analysis::Location{program_, addr}); }

 private:
  const ProgramFacts &facts() {
    if (!facts_) facts_ = r_.template get<Program>(program_);
    return *facts_;
  }
  const analysis::MemoryMapInfo &memory() {
    if (!memory_) memory_ = r_.template get<analysis::MemoryMap>(program_);
    return *memory_;
  }
  const analysis::ProgramInfo &info() {
    if (!info_) info_ = r_.template get<analysis::Program>(program_);
    return *info_;
  }
  // Copies from one page of `space` at a, up to `last` (inclusive).
  std::size_t copy(facts::SpaceId space, std::uint64_t a, std::span<std::byte> out, std::uint64_t last) {
    auto page = r_.template get<facts::EffectivePage>(facts::PageKey{space, a / facts::kPageSize});
    if (page->size() < facts::kPageSize) return 0;
    const std::uint64_t off = a % facts::kPageSize;
    std::uint64_t n = std::min<std::uint64_t>(facts::kPageSize - off, out.size());
    n = std::min<std::uint64_t>(n, last - a + 1);
    std::memcpy(out.data(), page->data() + off, n);
    return static_cast<std::size_t>(n);
  }

  Reader &r_;
  analysis::ProgramKey program_;
  facts::Ref<ProgramFacts> facts_;
  facts::Ref<analysis::ProgramInfo> info_;
  facts::Ref<analysis::MemoryMapInfo> memory_;
};

}  // namespace revkit::plugins
