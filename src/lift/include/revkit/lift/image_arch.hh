// A Ghidra Architecture over a revkit loader::Image, so the decompiler can
// work on real executables.
#pragma once

#include "revkit/lift/context.hh"
#include "revkit/lift/decomp_inputs.hh"
#include "revkit/loader/image.hh"

#include "sleigh.hh"
#include "stringmanage.hh"
#include "sleigh_arch.hh"

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace revkit::lift {

namespace detail {
// Holds an ImageArchitecture's own SLEIGH translator. It is a base listed
// before SleighArchitecture so it is destroyed after ~Architecture, which
// has finished with the translator by then.
struct OwnedTranslator {
  std::unique_ptr<ghidra::Sleigh> translator;
};
}  // namespace detail

// Where an ImageArchitecture reads bytes instead of the image's memory and
// patches (a decompiler worker answers from a bundle's bytes, see
// revkit::decompd). Called from the decompiler's thread.
class MemorySource {
 public:
  virtual ~MemorySource() = default;
  // Fills `out` with the bytes at `addr`, unmapped ones zero, and returns
  // how many were mapped (0: none, which the decompiler sees as no data).
  virtual std::size_t read(std::uint64_t addr, std::span<std::uint8_t> out) = 0;
};

// A record of the decompiler's join space (multi-register storage), so a
// worker can lay out the same records an earlier sequence of functions
// left behind (variable numbering follows join addresses).
struct JoinFacts {
  std::vector<StorageVarnode> pieces;  // most significant first
  int logical_size = 0;                // a float extension's size (one piece); 0 otherwise
  friend bool operator==(const JoinFacts &, const JoinFacts &) = default;
};

// How an ImageArchitecture presents the image. The defaults are what the
// image backend uses; the decompiler-parity tools turn on Ghidra's naming.
struct ArchitectureOptions {
  // init_image() registers the image's function symbols (ELF symbols, PE
  // exports and entry) in the global scope.
  bool image_symbols = true;
  // Bytes that replace the image's, e.g. relocations a loader applied:
  // `patches`, and `shared_patches` that several architectures read.
  using Patches = std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>>;
  Patches patches;
  std::shared_ptr<const Patches> shared_patches;
  // Inclusive ranges whose bytes count as constant. When set, they replace
  // the image's non-writable blocks as the decompiler's read-only ranges.
  std::optional<std::vector<std::pair<std::uint64_t, std::uint64_t>>> readonly;
  // Decode strings as Ghidra's Java side does (JavaStringManager) rather
  // than with the decompiler's own UTF-8 detection.
  bool java_strings = false;
  // Bytes from here instead of the image's memory and the patches.
  std::shared_ptr<MemorySource> memory;
  // Decoding context to paint instead of the image's (image_context()).
  std::optional<std::vector<ContextRegion>> context;
};

// DecompileCallback.getStringData's decoding: see image_arch.cc.
class JavaStringManager : public ghidra::StringManager {
 public:
  // The value of the defined string data containing an address, if any.
  using DefinedString = std::function<std::optional<std::string>(const ghidra::Address &addr)>;
  JavaStringManager(ghidra::Architecture *arch, int max_chars) : ghidra::StringManager(max_chars), glb_(arch) {}
  void set_defined(DefinedString f) { defined_ = std::move(f); }
  const std::vector<ghidra::uint1> &getStringData(const ghidra::Address &addr, ghidra::Datatype *charType,
                                                  bool &isTrunc) override;

 private:
  ghidra::Architecture *glb_;
  DefinedString defined_;
};

class ImageScope;
class ImageTypeFactory;

// An address's offset as Ghidra's default names write it: in the space's
// addressable units (AVR's code space counts 2-byte words) and padded to
// the space's size in hex digits, at most 8: "003a" for code:0x003a,
// "00101000" on x86-64.
std::string ghidra_offset_text(const ghidra::Address &addr);
// Whether Ghidra's default names carry the space (FUN_ram_00101000): the
// language has more than one memory space.
bool ghidra_qualifies_names(const ghidra::AddrSpaceManager &spaces);

// Unlike a stock SleighArchitecture, which shares one static translator per
// language between all instances (and re-points it at whichever instance
// was built last), each ImageArchitecture has its own. Several may then
// exist at once, each used by one thread at a time.
//
// Reading bytes outside the image is a bad instruction (halt_baddata), as
// when Ghidra's Java side can't supply an instruction, rather than an error
// that abandons the whole function.
class ImageArchitecture : private detail::OwnedTranslator, public ghidra::SleighArchitecture {
 public:
  // `language_id` must include the compiler: "x86:LE:64:default:gcc".
  // Call revkit::lift::initialize() first. With other threads using Ghidra,
  // construct under lock_ghidra_globals() (the base constructor builds a C
  // printer) and print under share_ghidra_globals(). Then call init_image()
  // (or init() and add_image_symbols() under the exclusive lock).
  ImageArchitecture(std::shared_ptr<const loader::Image> image, const std::string &name,
                    const std::string &language_id, std::ostream *errors, ArchitectureOptions options = {});
  ~ImageArchitecture() override;

  // init() under the process-wide spec-parsing lock, then
  // add_image_symbols() if options.image_symbols, else add_image_context().
  // Safe to call from several threads for different instances.
  void init_image();

  // After init(): register the image's function symbols in the global scope
  // and apply ARM Thumb context (add_image_context), so calls print by name
  // and decode in the right mode.
  void add_image_symbols();

  // After init(): the image's decoding context (ARM Thumb regions) only.
  void add_image_context();

  // Paints a context variable over [first, end) of the code space (end 0:
  // to the top); later decodes see it. Throws LowlevelError for a variable
  // the language lacks.
  void set_context_region(const std::string &name, std::uint64_t first, std::uint64_t end, std::uint32_t value);
  // Sets every context variable over [first, end) back to what the language
  // and the image's context (add_image_context) say there, whatever was
  // painted or decoding set since (SLEIGH's globalset: ARM's BL and BLX
  // mark their targets ARM or Thumb, an IT instruction the ones after it).
  // Without this what decoding one function set stays for every function
  // decoded after it; Ghidra's decompiler takes the context from the
  // program's database, where only the function's own disassembly set it.
  // (Nothing changes where the language's own context isn't the same over
  // the whole code space.)
  void reset_context(std::uint64_t first, std::uint64_t end);

  // Flow overrides applied to instructions' p-code as it is emitted, as
  // Ghidra's Java side applies a flow override (PcodeOverride) before the
  // decompiler sees the p-code: at each address, a computed jump
  // (BRANCHIND) becomes a RETURN (kind RETURN), a CALLIND (CALL), or a
  // CALLIND and a RETURN (CALL_RETURN), whatever else the instruction does
  // (ARM's conditional "movne pc, lr", which Funcdata::overrideFlow can't
  // change). Kinds are ghidra::Override values. Replaces the previous set.
  void set_pcode_overrides(std::map<std::uint64_t, std::uint32_t> overrides);

  // Fallthrough overrides (Ghidra's Set Fallthrough), applied to the p-code
  // as Ghidra's Java side applies them (PcodeEmit): at each address of
  // `falls`, a branch to the instruction's next address goes to the
  // override's instead, and a BRANCH there ends its p-code. Decoding at an
  // address of `stops` fails (BadDataError), so the decompiler's flow stops
  // there as Ghidra's does where no instruction follows one with no
  // fallthrough. Replaces the previous sets.
  void set_fallthroughs(std::map<std::uint64_t, std::uint64_t> falls, std::set<std::uint64_t> stops);

  const loader::Image &image() const { return *image_; }
  const ArchitectureOptions &options() const { return options_; }

  // The global scope, with revkit's naming hooks.
  ImageScope &global_scope() const;
  ImageTypeFactory &type_factory() const;
  JavaStringManager *java_strings() const;  // null unless options.java_strings
  // Some register starts at this address (Java's Program.getRegister(addr)).
  bool register_starts_at(const ghidra::Address &addr) const;

  // Forgets the instructions SLEIGH decoded recently, so the next decode of
  // any address reads its bytes again (from a MemorySource that changed).
  void flush_decode_cache();

  // The join records from `offset` (0: every one) in the order they were
  // made; `offset` is left at the next record's. add_join() makes one
  // (or finds it, if it exists).
  std::vector<JoinFacts> joins_from(std::uint64_t &offset) const;
  void add_join(const JoinFacts &join);

  // "FUN_00401000", as Ghidra names functions it has no symbol for (the
  // stock C++ default is "func_0x00401000").
  void nameFunction(const ghidra::Address &addr, std::string &name) const override;

 protected:
  void buildLoader(ghidra::DocumentStorage &store) override;
  ghidra::Translate *buildTranslator(ghidra::DocumentStorage &store) override;
  void buildContext(ghidra::DocumentStorage &store) override;
  ghidra::Scope *buildDatabase(ghidra::DocumentStorage &store) override;
  void buildTypegrp(ghidra::DocumentStorage &store) override;
  void buildStringManager(ghidra::DocumentStorage &store) override;
  // Core types exactly as Ghidra's Java side declares them to the decompiler
  // (PcodeDataTypeManager): names, sizes and ids follow the compiler spec's
  // data organization ("undefined4", "uint", "long" or "longlong", ...), so
  // output and variable-name prefixes (uVar, lVar) match Ghidra. Also sizes
  // "long" as the decompiler process sees it under Ghidra (see
  // ImageTypeFactory::java_long_size).
  void buildCoreTypes(ghidra::DocumentStorage &store) override;
  void resolveArchitecture() override;
  void postSpecFile() override;

 private:
  std::shared_ptr<const loader::Image> image_;
  std::string language_id_;
  ArchitectureOptions options_;
  std::vector<ContextRegion> image_context_;  // what add_image_context painted, by start
  std::vector<std::uint64_t> image_context_reach_;  // the largest end among those up to each
  // The language's context words, where one context holds over the whole
  // code space before the image's is painted.
  std::optional<std::vector<std::uint32_t>> language_context_;
  ghidra::DocumentStorage store_;
  std::unique_lock<std::shared_mutex> *init_lock_ = nullptr;  // held by init_image() during init()
};

// The type factory of an ImageArchitecture: a TypeFactory that can fetch a
// type it doesn't have by name and id from a resolver, as TypeFactoryGhidra
// asks the Java side.
class ImageTypeFactory : public ghidra::TypeFactory {
 public:
  using Resolver = std::function<ghidra::Datatype *(const std::string &name, std::uint64_t id)>;
  explicit ImageTypeFactory(ghidra::Architecture *arch) : ghidra::TypeFactory(arch) {}
  void set_resolver(Resolver r) { resolver_ = std::move(r); }
  // The type with this name and id, fetching it if needed.
  ghidra::Datatype *fetch(const std::string &name, std::uint64_t id) { return findById(name, id, 0); }

  // Ghidra's Java side sends the compiler spec's data organization without
  // the fields equal to its own defaults (DataOrganizationImpl.encode), so
  // the decompiler process never learns that "long" is 4 bytes on LLP64 and
  // assumes 8 (affecting literal suffixes: 1L, not 1LL). Mirror that.
  void java_long_size(long cspec_long_size);

 protected:
  ghidra::Datatype *findById(const std::string &n, ghidra::uint8 id, ghidra::int4 sz) override;

 private:
  Resolver resolver_;
  int depth_ = 0;  // nested resolutions
};

// The global scope of an ImageArchitecture: a ScopeInternal that can also
// work like Ghidra's ScopeGhidra, where every address the decompiler asks
// about is answered once by a resolver (Java's getMappedSymbols) and cached
// until reset() (Java flushes the cache after every function).
class ImageScope : public ghidra::ScopeInternal {
 public:
  ImageScope(ghidra::Architecture *arch);

  // What a resolver found for an address: a symbol it added to `scope` (with
  // add_mapsym), or nothing, with the range around the address that has no
  // symbol and that range's mutability (a "hole").
  struct Hole {
    std::uint64_t first = 0, last = 0;
    bool readonly = false;
    bool is_volatile = false;
  };
  using Resolver = std::function<ghidra::Symbol *(const ghidra::Address &addr, Hole &hole)>;
  // The name of the code label at an address, or "" (Java's getCodeLabel).
  using LabelResolver = std::function<std::string(const ghidra::Address &addr)>;
  // The function an external reference at `slot` resolves to (Java's
  // getExternalRef), added to the scope, or null.
  using ExternalResolver = std::function<ghidra::Funcdata *(const ghidra::Address &slot)>;

  void set_resolvers(Resolver symbols, LabelResolver labels, ExternalResolver externals);
  bool resolving() const { return static_cast<bool>(resolver_); }

  // Decodes a <mapsym> into this scope; null and a warning on failure.
  ghidra::Symbol *add_mapsym(const ghidra::Element &mapsym, std::string *error = nullptr);

  // Drops every symbol, function and cached query, and restores the memory
  // properties to what they were at the last snapshot_properties().
  void reset();
  void snapshot_properties();

  ghidra::SymbolEntry *findAddr(const ghidra::Address &addr, const ghidra::Address &usepoint) const override;
  ghidra::SymbolEntry *findContainer(const ghidra::Address &addr, ghidra::int4 size,
                                     const ghidra::Address &usepoint) const override;
  ghidra::Funcdata *findFunction(const ghidra::Address &addr) const override;
  ghidra::ExternRefSymbol *findExternalRef(const ghidra::Address &addr) const override;
  ghidra::LabSymbol *findCodeLabel(const ghidra::Address &addr) const override;
  ghidra::Funcdata *resolveExternalRefFunction(ghidra::ExternRefSymbol *sym) const override;

 private:
  ghidra::Symbol *query(const ghidra::Address &addr) const;  // ScopeGhidra::removeQuery

  Resolver resolver_;
  LabelResolver label_resolver_;
  ExternalResolver external_resolver_;
  mutable ghidra::RangeList holes_;
  std::vector<bool> global_spaces_;  // by space index: in the global scope's ranges
  mutable bool busy_ = false;  // resolving: answer from the cache only
  mutable bool properties_dirty_ = false;
  ghidra::partmap<ghidra::Address, ghidra::uint4> default_properties_;
};

}  // namespace revkit::lift
