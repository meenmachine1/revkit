// Assembling bundles in the parent (rk-lift, rk-daemon, rk-infer).
//
// ProgramImage is what every bundle of one program shares: the language,
// the image's shape, which ranges hold bytes and what they read as once
// the loader's patches are applied. predict() decodes a function's body
// with SLEIGH and lists what the decompiler is likely to ask about: every
// address its p-code names (constants that land in mapped memory, absolute
// memory operands, call and branch targets, pointers stored at those
// addresses, page-plus-offset pairs), the labels of branch targets inside
// it, and the chunks of bytes it will read. LiftBundleBuilder answers those
// from the caller's lift::FactLookup (an index over a program's inputs, or
// the backend's fact-store lookup), with the types the answers reach, and
// after a run adds what the worker reports it missed.
#pragma once

#include "revkit/decompd/bundle.h"
#include "revkit/lift/decompile.hh"
#include "revkit/lift/lifter.hh"

#include <functional>
#include <map>
#include <condition_variable>
#include <mutex>
#include <unordered_map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace revkit::decompd {

class ProgramImage {
 public:
  // `patches`: bytes the loader changed (relocations) and memory no file
  // backs (a PE's thread block), laid over the image as
  // lift::ImageArchitecture lays them.
  ProgramImage(std::shared_ptr<const loader::Image> image, std::string language_id,
               const lift::ArchitectureOptions::Patches &patches,
               std::optional<std::vector<lift::ContextRegion>> context = std::nullopt);

  const loader::Image &image() const { return *image_; }
  const std::shared_ptr<const loader::Image> &image_ptr() const { return image_; }
  const std::string &language_id() const { return language_id_; }
  const std::vector<std::pair<std::uint64_t, std::uint64_t>> &mapped() const { return mapped_; }
  bool mapped_at(std::uint64_t a) const;
  bool mapped_in(std::uint64_t first, std::uint64_t last) const;  // any byte of the range
  const std::vector<lift::ContextRegion> &context() const { return context_; }
  // The bytes at `addr` as the decompiler reads them (unmapped: zero);
  // returns how many are mapped.
  std::size_t read(std::uint64_t addr, std::span<std::uint8_t> out) const;
  std::string chunk(std::uint64_t index) const;  // kChunk bytes
  unsigned pointer_size() const { return image_->bits / 8; }

  // A bundle with this program's shared parts filled in.
  Bundle bundle(Mode mode, std::uint64_t entry) const;

 private:
  struct Patch {
    std::uint64_t addr;
    std::uint32_t offset, size;  // in bytes_
  };
  std::shared_ptr<const loader::Image> image_;
  std::string language_id_;
  std::vector<Patch> patches_;  // sorted by address (stable: later patches win)
  std::vector<std::uint8_t> bytes_;
  std::uint64_t longest_ = 0;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> mapped_;
  std::vector<lift::ContextRegion> context_;
};

// What predict() expects the decompiler to ask.
struct Prediction {
  std::set<SpaceAddr> addresses;
  std::set<std::uint64_t> calls;  // direct call targets (among `addresses`)
  std::set<SpaceAddr> code_labels;
  std::set<std::uint64_t> chunks;
};

// Decodes `body` (inclusive ranges) with `lifter`, which must be over the
// program's image, and follows flow leaving it for a while (from the entry
// alone, much further, when `body` is empty). `blocks`: the
// memory blocks the decompiler is told of (pointers into those count, the
// image's own or not). `seeds`: register offsets (in the register space)
// and the values the function's entry has in them (tracked registers such
// as RISC-V's gp), which constants are folded from. Deterministic for the
// same bytes, body and seeds.
Prediction predict(lift::Lifter &lifter, const ProgramImage &program, std::uint64_t entry,
                   const std::vector<std::pair<std::uint64_t, std::uint64_t>> &body,
                   const std::vector<lift::BlockFacts> &blocks = {},
                   const std::vector<std::pair<std::uint64_t, std::uint64_t>> &seeds = {});

// SLEIGH engines for predict(), lent to one thread at a time, by the
// decoding context a function asks for (FunctionFacts::context: ARM
// firmware's Thumb functions decode with TMode 1), painted over the whole
// space on top of the image's own context. At most `per_context` engines
// (35 MB each) per context.
class LifterPool {
 public:
  using Context = std::vector<std::pair<std::string, std::uint32_t>>;
  LifterPool(std::shared_ptr<const loader::Image> image, std::string language, unsigned per_context = 2);
  ~LifterPool();

  struct Lease {
    LifterPool *owner = nullptr;
    Context context;
    std::unique_ptr<lift::Lifter> lifter;
    Lease() = default;
    Lease(Lease &&) = default;
    Lease &operator=(Lease &&) = default;
    ~Lease();
    lift::Lifter &operator*() { return *lifter; }
  };
  Lease take(const Context &context = {});

 private:
  std::shared_ptr<const loader::Image> image_;
  std::string language_;  // without the compiler
  unsigned per_context_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::map<Context, std::vector<std::unique_ptr<lift::Lifter>>> idle_;
  std::map<Context, unsigned> made_;
};

// The seeds for predict(): a function's tracked registers, as lift::FactLookup
// gives them, resolved to register offsets.
std::vector<std::pair<std::uint64_t, std::uint64_t>> tracked_seeds(lift::Lifter &lifter,
                                                                   const std::vector<lift::TrackedFacts> &tracked);

// Chunk, address and type counts, for statistics.
struct BundleStats {
  std::size_t bytes = 0, chunks = 0, addresses = 0, types = 0;
};
BundleStats bundle_stats(const Bundle &b, std::size_t encoded_size);

// Encoded types and the ids each references, shared by the builders of
// one batch over a lookup whose answers don't change (lift::FactLookup::
// stable()): a type is encoded once, not once per function using it.
class TypeCache {
 public:
  struct Entry {
    std::string encoded;  // "" where the lookup has no such type
    std::vector<std::uint64_t> refs;
  };
  std::shared_ptr<const Entry> get(std::uint64_t id, lift::FactLookup &facts);

 private:
  std::mutex mu_;
  std::unordered_map<std::uint64_t, std::shared_ptr<const Entry>> entries_;
};

class LiftBundleBuilder {
 public:
  // `facts` answers as the decompiler's lookup would in process; `blocks`
  // is block_at's answer for addresses without one of their own (the
  // program's memory blocks).
  LiftBundleBuilder(const ProgramImage &program, Mode mode, std::uint64_t entry, lift::FactLookup &facts,
                    std::vector<lift::BlockFacts> blocks, std::string address_prefix);

  void set_naming(bool default_names, bool default_labels, bool default_extrapop);
  void set_format_strings(bool on) { lift_.format_strings = on; }
  void set_hooks(std::map<std::uint64_t, std::vector<std::uint64_t>> jump_tables,
                 std::vector<std::pair<std::uint64_t, std::string>> flow_overrides,
                 std::vector<lift::CommentFacts> comments);
  // The user's equates, call targets and forced jump tables (RunHooks).
  void set_user_hooks(std::vector<lift::EquateFacts> equates, std::map<std::uint64_t, std::uint64_t> call_targets,
                      std::set<std::uint64_t> forced_tables);
  // Calls' signature overrides (RunHooks::call_protos): their types join
  // the bundle's.
  void set_call_protos(std::map<std::uint64_t, lift::FunctionFacts> protos) { lift_.hook_call_protos = std::move(protos); }
  void set_joins(std::optional<std::vector<lift::JoinFacts>> joins) { joins_ = std::move(joins); }
  // The spaces `facts` can answer anything in (default: only the default space).
  void set_spaces(std::vector<std::string> spaces) { lift_.spaces = std::move(spaces); }
  // Types encoded by others before (null: this builder's own).
  void set_type_cache(std::shared_ptr<TypeCache> cache) { types_ = std::move(cache); }
  // The mode's own options (Bundle::extra).
  void set_extra(std::string extra) { extra_ = std::move(extra); }
  // Rewrites each chunk of bytes before it goes into the bundle (chunk
  // index, the program's bytes): the image backend lays the program's
  // patches over them (docs/patching.md), reading only the patches of the
  // chunks the decompiler reads.
  void set_chunk_hook(std::function<std::string(std::uint64_t, std::string)> hook) { chunk_hook_ = std::move(hook); }

  // Answers everything `p` lists (and the entry's own facts).
  void add(const Prediction &p);
  // Adds answers for what a run missed. True if any differs from what the
  // worker assumed (nothing; zero bytes), so the run must be repeated.
  bool fill(const std::vector<Miss> &misses);

  // The bundle as answered so far, canonical (tables sorted by encoding).
  Bundle bundle();

 private:
  bool add_address(const std::string &space, std::uint64_t a);  // true: says something
  bool add_code_label(const std::string &space, std::uint64_t a);
  bool add_chunk(std::uint64_t index);
  void add_types();
  template <class T>
  std::int32_t intern(std::vector<T> &table, std::map<std::string, std::int32_t> &index, const T &value);

  const ProgramImage &program_;
  std::function<std::string(std::uint64_t, std::string)> chunk_hook_;
  Mode mode_;
  std::uint64_t entry_;
  lift::FactLookup &facts_;
  LiftFacts lift_;
  std::map<std::uint64_t, std::string> chunks_;
  std::optional<std::vector<lift::JoinFacts>> joins_;
  std::string extra_;
  std::map<std::string, std::int32_t> function_ix_, data_ix_, external_ix_, label_ix_;
  std::set<std::uint64_t> type_done_;
  std::shared_ptr<TypeCache> types_ = std::make_shared<TypeCache>();
  bool entry_done_ = false;
};

}  // namespace revkit::decompd
