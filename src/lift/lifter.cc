#include "revkit/lift/lifter.hh"

#include "revkit/loader/ghidra_loadimage.hh"
#include "revkit/runtime/runtime.h"

#include "ghidra_text.hh"

#include "libdecomp.hh"
#include "sleigh.hh"
#include "sleigh_arch.hh"

#include <algorithm>
#include <cstdlib>
#include <atomic>
#include <map>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <sstream>

namespace revkit::lift {

namespace {

std::mutex g_init_mutex;
std::optional<std::filesystem::path> g_root;
std::shared_mutex g_globals;

void require_initialized() {
  std::lock_guard lock(g_init_mutex);
  if (!g_root) throw LiftError("revkit::lift::initialize() was not called");
}

// "x86:LE:64:default:gcc" -> "x86:LE:64:default"
std::string base_language(const std::string &id) {
  if (std::count(id.begin(), id.end(), ':') >= 4) return id.substr(0, id.rfind(':'));
  return id;
}

const ghidra::LanguageDescription *find_language(const std::string &id) {
  const std::string base = base_language(id);
  for (const ghidra::LanguageDescription &d : ghidra::SleighArchitecture::getDescriptions())
    if (d.getId() == base) return &d;
  return nullptr;
}

std::string find_spec_file(const std::string &name) {
  std::string path;
  ghidra::SleighArchitecture::specpaths.findFile(path, name);
  if (path.empty()) throw LiftError("cannot find spec file " + name + " in the Ghidra install");
  return path;
}

// Collects raw p-code. Also tells apart LOAD/STORE ops that SLEIGH
// synthesizes for dynamic operands (e.g. an x86 memory operand) from ones
// written in the spec: Java emits the former's space operand with size 4,
// C++ with sizeof(AddrSpace*), so we rewrite them to match Ghidra. The two
// kinds are only distinguishable by where SleighBuilder put their varnodes:
// a dynamic LOAD's output is an input slot of the op that consumes it, and
// a dynamic STORE's value input is the output slot of the op before it.
class PcodeCollector : public ghidra::PcodeEmit {
 public:
  explicit PcodeCollector(std::vector<PcodeOp> &out) : out_(out) {}

  void dump(const ghidra::Address &, ghidra::OpCode opc, ghidra::VarnodeData *outvar,
            ghidra::VarnodeData *vars, ghidra::int4 isize) override {
    PcodeOp op;
    op.opcode = ghidra::get_opname(opc);
    if (outvar != nullptr) op.output = convert(*outvar);
    for (ghidra::int4 i = 0; i < isize; ++i) {
      // LOAD/STORE name their address space with a constant that holds an
      // AddrSpace pointer; report the space by name instead.
      if (i == 0 && (opc == ghidra::CPUI_LOAD || opc == ghidra::CPUI_STORE) &&
          vars[0].space->getType() == ghidra::IPTR_CONSTANT) {
        op.inputs.push_back({"space", 0, vars[0].size, vars[0].getSpaceFromConst()->getName()});
        continue;
      }
      op.inputs.push_back(convert(vars[i]));
    }
    out_.push_back(std::move(op));
    slots_.push_back({opc, outvar, vars, isize});
  }

  // Call once after emission, while SLEIGH's p-code cache is still intact.
  void mark_dynamic_spaces() {
    constexpr std::uint32_t kJavaSpaceIdSize = 4;
    for (std::size_t k = 0; k < slots_.size(); ++k) {
      const Slot &s = slots_[k];
      bool dynamic = false;
      if (s.opc == ghidra::CPUI_LOAD && s.out != nullptr) {
        for (std::size_t j = k + 1; j < slots_.size() && !dynamic; ++j)
          dynamic = slots_[j].in != nullptr && s.out >= slots_[j].in && s.out < slots_[j].in + slots_[j].isize;
      } else if (s.opc == ghidra::CPUI_STORE && s.isize == 3 && s.in != nullptr) {
        for (std::size_t j = 0; j < k && !dynamic; ++j) dynamic = slots_[j].out == s.in + 2;
      }
      PcodeOp &op = out_[out_.size() - slots_.size() + k];
      if (dynamic && !op.inputs.empty() && !op.inputs[0].referenced_space.empty())
        op.inputs[0].size = kJavaSpaceIdSize;
    }
  }

 private:
  struct Slot {
    ghidra::OpCode opc;
    const ghidra::VarnodeData *out;
    const ghidra::VarnodeData *in;
    ghidra::int4 isize;
  };

  static Varnode convert(const ghidra::VarnodeData &v) {
    std::uint64_t offset = v.offset;
    // Constants are masked to their size: SLEIGH may hand back a
    // sign-extended 64-bit value for a 4-byte constant.
    if (v.space->getType() == ghidra::IPTR_CONSTANT && v.size < 8)
      offset &= (std::uint64_t{1} << (8 * v.size)) - 1;
    return {v.space->getName(), offset, v.size, {}};
  }
  std::vector<PcodeOp> &out_;
  std::vector<Slot> slots_;
};

std::atomic<std::size_t> g_engines_live{0};

// Sleigh with access to the parse tree of a decoded instruction.
class Engine : public ghidra::Sleigh {
 public:
  Engine(ghidra::LoadImage *loader, ghidra::ContextDatabase *context) : ghidra::Sleigh(loader, context) { ++g_engines_live; }
  ~Engine() override { --g_engines_live; }
  const ghidra::ParserContext &parsed(const ghidra::Address &addr) const {
    return *obtainContext(addr, ghidra::ParserContext::pcode);
  }
  // The parse of the instruction at addr, with its handles resolved, as
  // oneInstruction() starts from.
  ghidra::ParserContext *for_pcode(const ghidra::Address &addr) const {
    return obtainContext(addr, ghidra::ParserContext::pcode);
  }
  // The mnemonic of the instruction at addr, as printAssembly prints it,
  // without printing its operands.
  std::string mnemonic(const ghidra::Address &addr) const {
    ghidra::ParserContext *pos = obtainContext(addr, ghidra::ParserContext::disassembly);
    ghidra::ParserWalker walker(pos);
    walker.baseState();
    std::ostringstream out;
    walker.getConstructor()->printMnemonic(out, walker);
    return out.str();
  }
  // Drops any cached parse of the instruction at addr, so the next decode
  // reads its bytes again.
  void forget(const ghidra::Address &addr) const {
    obtainContext(addr, ghidra::ParserContext::uninitialized)->setParserState(ghidra::ParserContext::uninitialized);
  }
};

// Serves the image's bytes, or while a window is set, only the window's:
// bytes outside it read as zero, and a request that misses it entirely is
// unavailable, as unmapped memory is for the image.
class WindowLoadImage : public ghidra::LoadImage {
 public:
  explicit WindowLoadImage(loader::GhidraLoadImage &image) : ghidra::LoadImage("revkit"), image_(image) {}

  void set_window(std::uint64_t start, std::span<const std::byte> bytes) {
    window_start_ = start;
    window_ = bytes;
    active_ = true;
  }
  void clear_window() { active_ = false; }

  void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address &addr) override {
    if (!active_) return image_.loadFill(ptr, size, addr);
    if (size <= 0) return;
    std::fill(ptr, ptr + size, ghidra::uint1{0});
    const std::uint64_t at = addr.getOffset();
    const std::uint64_t end = window_start_ + window_.size();  // windows never wrap (see Lifter::lift)
    bool any = false;
    if (addr.getSpace() == space_) {
      for (ghidra::int4 i = 0; i < size; ++i) {
        std::uint64_t a = at + static_cast<std::uint64_t>(i);
        if (a < at) break;
        if (a >= window_start_ && a < end) {
          ptr[i] = std::to_integer<ghidra::uint1>(window_[a - window_start_]);
          any = true;
        }
      }
    }
    if (!any) throw ghidra::DataUnavailError("no bytes supplied at this address");
  }
  std::string getArchType() const override { return image_.getArchType(); }
  void adjustVma(long adjust) override { image_.adjustVma(adjust); }
  void attach(ghidra::AddrSpace *space) {
    space_ = space;
    image_.attach(space);
  }

 private:
  loader::GhidraLoadImage &image_;
  ghidra::AddrSpace *space_ = nullptr;
  std::uint64_t window_start_ = 0;
  std::span<const std::byte> window_;
  bool active_ = false;
};

class NullAssembly : public ghidra::AssemblyEmit {
 public:
  void dump(const ghidra::Address &, const std::string &, const std::string &) override {}
};

class AssemblyCollector : public ghidra::AssemblyEmit {
 public:
  void dump(const ghidra::Address &, const std::string &mnem, const std::string &body) override {
    mnemonic = mnem;
    operands = body;
  }
  std::string mnemonic;
  std::string operands;
};

}  // namespace

namespace {
std::optional<loader::LanguageMemory> language_memory_cached(std::string_view language);
}  // namespace

std::unique_lock<std::shared_mutex> lock_ghidra_globals() { return std::unique_lock(g_globals); }
std::shared_lock<std::shared_mutex> share_ghidra_globals() { return std::shared_lock(g_globals); }

void initialize(const std::filesystem::path &ghidra_root) {
  std::lock_guard lock(g_init_mutex);
  if (g_root) {
    if (*g_root != ghidra_root)
      throw LiftError("SLEIGH already initialized with " + g_root->string() + ", not " + ghidra_root.string());
    return;
  }
  if (!std::filesystem::is_directory(ghidra_root))
    throw LiftError("Ghidra root " + ghidra_root.string() + " is not a directory");
  {
    auto globals = lock_ghidra_globals();
    // revkit's own processors (EVM) beside Ghidra's: each
    // <dir>/<processor>/data/languages (runtime::processors_dir).
    std::vector<std::string> own;
    if (std::optional<std::filesystem::path> dir = runtime::processors_dir()) {
      std::error_code ec;
      for (const auto &p : std::filesystem::directory_iterator(*dir, ec))
        if (std::filesystem::is_directory(p.path() / "data" / "languages", ec))
          own.push_back((p.path() / "data" / "languages").string());
      std::sort(own.begin(), own.end());
    }
    ghidra::startDecompilerLibrary(ghidra_root.string().c_str(), own);
    ghidra::SleighArchitecture::getDescriptions();  // scan the .ldefs now, not racily later
  }
  g_root = ghidra_root;
  loader::set_language_memory_provider(language_memory_cached);
}

namespace {

std::optional<loader::LanguageMemory> compute_language_memory(const std::string &language) {
  std::string pspec;
  {
    auto globals = lock_ghidra_globals();
    const ghidra::LanguageDescription *desc = find_language(language);
    if (desc == nullptr) return std::nullopt;
    pspec = find_spec_file(desc->getProcessorSpec());
  }
  std::vector<SpaceDef> spaces;
  try {
    Lifter lifter(std::make_shared<const loader::Image>(), language);
    spaces = lifter.spaces();
  } catch (const LiftError &) {
    return std::nullopt;
  }
  loader::LanguageMemory out;
  std::string code;
  auto digits = [](const SpaceDef &d) { return std::min<std::uint32_t>(8, std::max<std::uint32_t>(1, 2 * d.address_size)); };
  for (std::size_t i = 0; i < spaces.size(); ++i) {
    const SpaceDef &d = spaces[i];
    if (d.is_default) {
      code = d.name;
      out.code = {d.name, 0, false, d.wordsize, digits(d)};
    }
    if (d.kind != SpaceDef::Kind::processor || d.is_register || d.is_default) continue;
    out.spaces.push_back({d.name, static_cast<std::uint64_t>(i) << loader::kSpaceKeyShift, false, d.wordsize, digits(d)});
  }
  auto wordsize = [&](const std::string &name) -> std::uint64_t {
    for (const SpaceDef &d : spaces)
      if (d.name == name) return d.wordsize;
    return 1;
  };
  auto split = [&](const std::string &value, std::string &space, std::uint64_t &offset) {
    std::string off = value;
    space.clear();
    if (auto colon = value.find(':'); colon != std::string::npos) {
      space = value.substr(0, colon);
      off = value.substr(colon + 1);
    }
    char *end = nullptr;
    // Ghidra reads a bare number in an address as hex ("INTMEM:20").
    offset = std::strtoull(off.c_str(), &end, 16);
    return !off.empty() && end == off.c_str() + off.size();
  };
  // Its labels (entry points are discovery's seeds).
  for (const ProcessorSymbol &p : processor_symbols(language)) {
    if (p.entry) continue;
    const std::string space = p.space.empty() || p.space == code ? std::string() : p.space;
    out.labels.push_back({p.name, space, p.address * wordsize(p.space.empty() ? code : p.space)});
  }
  // <default_memory_blocks> of the processor spec.
  auto globals = lock_ghidra_globals();
  try {
    ghidra::DocumentStorage store;
    ghidra::Element *root = store.openDocument(pspec)->getRoot();
    for (const ghidra::Element *child : root->getChildren()) {
      if (child->getName() != "default_memory_blocks") continue;
      for (const ghidra::Element *b : child->getChildren()) {
        if (b->getName() != "memory_block") continue;
        loader::DefaultBlock block;
        std::string start, length, byte_mapped, bit_mapped, mode = "rw";
        bool initialized = true;
        for (int i = 0; i < b->getNumAttributes(); ++i) {
          const std::string &n = b->getAttributeName(i), &v = b->getAttributeValue(i);
          if (n == "name") block.name = v;
          else if (n == "start_address") start = v;
          else if (n == "length") length = v;
          else if (n == "initialized") initialized = v == "true";
          else if (n == "mode") mode = v;
          else if (n == "byte_mapped_address") byte_mapped = v;
          else if (n == "bit_mapped_address") bit_mapped = v;
        }
        std::uint64_t offset = 0;
        if (!split(start, block.space, offset)) continue;
        if (block.space.empty()) block.space = code;
        const std::uint64_t len = std::strtoull(length.c_str(), nullptr, 0);
        if (!byte_mapped.empty()) {
          // A byte view of another space's memory (AVR's codebyte over code):
          // an alias of the default space when it views that.
          std::string onto;
          std::uint64_t at = 0;
          if (split(byte_mapped, onto, at) && (onto.empty() || onto == code) && at == 0 && offset == 0)
            for (loader::AddressSpace &a : out.spaces)
              if (a.name == block.space) {
                a.alias_of_default = true;
                a.base = 0;
              }
          continue;
        }
        if (!bit_mapped.empty() || len == 0) continue;  // bit views have no bytes of their own
        const std::uint64_t ws = wordsize(block.space);
        block.start = offset * ws;
        block.size = len * ws;
        block.initialized = initialized;
        block.perms = {mode.find('r') != std::string::npos || mode.empty(), mode.find('w') != std::string::npos,
                       mode.find('x') != std::string::npos};
        if (block.space == code) block.space.clear();
        out.blocks.push_back(std::move(block));
      }
    }
  } catch (const ghidra::DecoderError &) {
  } catch (const ghidra::LowlevelError &) {
  }
  return out;
}

std::optional<loader::LanguageMemory> language_memory_cached(std::string_view language) {
  static std::mutex mu;
  static std::map<std::string, std::optional<loader::LanguageMemory>, std::less<>> cache;
  const std::string base = base_language(std::string(language));
  {
    std::lock_guard lock(mu);
    if (auto it = cache.find(base); it != cache.end()) return it->second;
  }
  std::optional<loader::LanguageMemory> m = compute_language_memory(base);
  std::lock_guard lock(mu);
  return cache.emplace(base, std::move(m)).first->second;
}

}  // namespace

std::optional<std::filesystem::path> ghidra_root() {
  std::lock_guard lock(g_init_mutex);
  return g_root;
}

std::vector<LanguageSummary> list_languages() {
  require_initialized();
  auto globals = lock_ghidra_globals();
  std::vector<LanguageSummary> out;
  for (const ghidra::LanguageDescription &d : ghidra::SleighArchitecture::getDescriptions()) {
    LanguageSummary s{d.getId(), d.getProcessor(), d.isBigEndian(), d.getSize(),
                      d.getVariant(), d.getDescription(), d.isDeprecated(), {}};
    for (ghidra::int4 i = 0; i < d.numCompilers(); ++i) s.compilers.push_back(d.getCompiler(i).getId());
    out.push_back(std::move(s));
  }
  std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) { return a.id < b.id; });
  return out;
}

bool language_exists(const std::string &language) {
  require_initialized();
  auto globals = lock_ghidra_globals();
  const ghidra::LanguageDescription *desc = find_language(language);
  if (desc == nullptr) return false;
  if (base_language(language) == language) return true;
  const std::string compiler = language.substr(language.rfind(':') + 1);
  for (ghidra::int4 i = 0; i < desc->numCompilers(); ++i)
    if (desc->getCompiler(i).getId() == compiler) return true;
  return false;
}

std::optional<std::filesystem::path> processor_data_dir(const std::string &language) {
  require_initialized();
  auto globals = lock_ghidra_globals();
  const ghidra::LanguageDescription *desc = find_language(language);
  if (desc == nullptr) return std::nullopt;
  // .../data/languages/<file>.sla
  return std::filesystem::path(find_spec_file(desc->getSlaFile())).parent_path().parent_path();
}

std::vector<ProcessorSymbol> processor_symbols(const std::string &language) {
  require_initialized();
  // The XML parser is one of Ghidra's globals.
  auto globals = lock_ghidra_globals();
  const ghidra::LanguageDescription *desc = find_language(language);
  if (desc == nullptr) return {};
  const std::string pspec = find_spec_file(desc->getProcessorSpec());
  std::vector<ProcessorSymbol> out;
  try {
    ghidra::DocumentStorage store;
    ghidra::Element *root = store.openDocument(pspec)->getRoot();
    for (const ghidra::Element *child : root->getChildren()) {
      if (child->getName() != "default_symbols") continue;
      for (const ghidra::Element *sym : child->getChildren()) {
        if (sym->getName() != "symbol") continue;
        ProcessorSymbol p;
        for (int i = 0; i < sym->getNumAttributes(); ++i) {
          const std::string &name = sym->getAttributeName(i), &value = sym->getAttributeValue(i);
          if (name == "name") {
            p.name = value;
          } else if (name == "entry") {
            p.entry = value == "true";
          } else if (name == "type") {
            p.code_ptr = value == "code_ptr";
          } else if (name == "address") {
            // "ram:0x1c", or a bare offset in the default space.
            std::string off = value;
            if (auto colon = value.find(':'); colon != std::string::npos) {
              p.space = value.substr(0, colon);
              off = value.substr(colon + 1);
            }
            // "next" (after the previous symbol) and the like: not an
            // address of its own; such symbols are registers, not entries.
            char *end = nullptr;
            p.address = std::strtoull(off.c_str(), &end, 0);
            if (off.empty() || end != off.c_str() + off.size()) p.name.clear();
          }
        }
        if (!p.name.empty()) out.push_back(std::move(p));
      }
    }
  } catch (const ghidra::DecoderError &e) {
    throw LiftError("reading " + pspec + ": " + e.explain);
  }
  return out;
}

std::vector<VolatileRange> processor_volatile_ranges(const std::string &language) {
  require_initialized();
  auto globals = lock_ghidra_globals();
  const ghidra::LanguageDescription *desc = find_language(language);
  if (desc == nullptr) return {};
  const std::string pspec = find_spec_file(desc->getProcessorSpec());
  std::vector<VolatileRange> out;
  try {
    ghidra::DocumentStorage store;
    ghidra::Element *root = store.openDocument(pspec)->getRoot();
    for (const ghidra::Element *child : root->getChildren()) {
      if (child->getName() != "volatile") continue;
      for (const ghidra::Element *range : child->getChildren()) {
        if (range->getName() != "range") continue;
        VolatileRange r;
        bool first = false, last = false;
        for (int i = 0; i < range->getNumAttributes(); ++i) {
          const std::string &name = range->getAttributeName(i), &value = range->getAttributeValue(i);
          if (name == "space") r.space = value;
          else if (name == "first") r.first = std::strtoull(value.c_str(), nullptr, 0), first = true;
          else if (name == "last") r.last = std::strtoull(value.c_str(), nullptr, 0), last = true;
        }
        if (!r.space.empty() && first && last && r.first <= r.last) out.push_back(std::move(r));
      }
    }
  } catch (const ghidra::DecoderError &e) {
    throw LiftError("reading " + pspec + ": " + e.explain);
  }
  return out;
}

namespace {

// Spare engines (docs/memory.md "SLEIGH engines"): an engine's decoded
// .sla is most of its memory (35 MB for x86-64) and of its build time, and
// depends on the language alone. A Lifter that lets its engine go (park(),
// a rebuild, its end) leaves it here, its program's image and context
// detached (Sleigh::reset); the next Lifter of that language (any program's)
// takes it and attaches its own, as Ghidra does for a new program
// (Sleigh::reset, then initialize() reregisters the context variables). A
// few per language are kept; one engine is used by one Lifter at a time.
//
// Keyed by the .sla and the language's space truncations, not the .sla
// alone: languages sharing one .sla (x86-64 and its compat32 variant) may
// truncate its spaces differently, and a truncation stays in the engine.
// What else differs between them (the .pspec's context) is painted afresh
// on every build.
struct SpareEngines {
  std::mutex mu;
  std::map<std::string, std::vector<std::unique_ptr<Engine>>> by_key;
  std::size_t count = 0;
};
SpareEngines &spares() {
  static auto *s = new SpareEngines;  // never destroyed: engines may outlive static teardown order
  return *s;
}
constexpr std::size_t kSparesPerLanguage = 2;

std::unique_ptr<Engine> take_spare(const std::string &key) {
  SpareEngines &s = spares();
  std::lock_guard lock(s.mu);
  auto it = s.by_key.find(key);
  if (it == s.by_key.end() || it->second.empty()) return nullptr;
  std::unique_ptr<Engine> e = std::move(it->second.back());
  it->second.pop_back();
  --s.count;
  return e;
}

void give_spare(const std::string &key, std::unique_ptr<Engine> e) {
  // Nothing of the program it served stays reachable from it.
  e->reset(nullptr, nullptr);
  SpareEngines &s = spares();
  {
    std::lock_guard lock(s.mu);
    auto &v = s.by_key[key];
    if (v.size() < kSparesPerLanguage) {
      v.push_back(std::move(e));
      ++s.count;
      return;
    }
  }
  e.reset();  // over the limit: freed, outside the lock
}

// Processor specs, parsed once: their <context_data> paints each engine's
// context database when it is built.
const ghidra::Element *pspec_root(const std::string &path) {
  struct Doc {
    std::unique_ptr<ghidra::DocumentStorage> store;
    const ghidra::Element *root = nullptr;
  };
  static std::mutex mu;
  static auto *docs = new std::map<std::string, Doc>;
  std::lock_guard lock(mu);
  Doc &d = (*docs)[path];
  if (!d.store) {
    d.store = std::make_unique<ghidra::DocumentStorage>();
    d.root = d.store->openDocument(path)->getRoot();
  }
  return d.root;
}

}  // namespace

EngineStats engine_stats() {
  SpareEngines &s = spares();
  std::lock_guard lock(s.mu);
  return {g_engines_live.load(), s.count};
}

void trim_spare_engines() {
  std::map<std::string, std::vector<std::unique_ptr<Engine>>> gone;
  SpareEngines &s = spares();
  {
    std::lock_guard lock(s.mu);
    gone.swap(s.by_key);
    s.count = 0;
  }
}

struct Lifter::Impl {
  struct Setting {
    std::string name;
    std::uint32_t value;
    std::uint64_t start;
    std::optional<std::uint64_t> end;
  };

  std::shared_ptr<const loader::Image> image;
  std::string language;
  std::string sla_path;
  std::string pspec_path;
  std::vector<ghidra::TruncationTag> truncations;
  std::string spare_key;  // the spares this language's engines share (SpareEngines)
  std::vector<Setting> settings;

  std::unique_ptr<loader::GhidraLoadImage> loadimage;
  std::unique_ptr<WindowLoadImage> window;
  // Declared before `sleigh` so the engine is destroyed first.
  std::unique_ptr<ghidra::ContextInternal> context;
  std::string built_context;  // the context database as built, encoded
  std::unique_ptr<Engine> sleigh;
  std::unique_ptr<detail::GhidraText> printer;
  bool stale = true;

  // SLEIGH caches decoded instructions and context lookups, and its context
  // database can't take new variables once populated, so any context change
  // rebuilds the engine: reset with a fresh context database (its decoded
  // .sla kept), or a spare one of the language, or a new one.
  Engine &engine() {
    if (stale) {
      try {
        build();
      } catch (const ghidra::LowlevelError &e) {
        throw LiftError("loading SLEIGH spec for " + language + ": " + e.explain);
      } catch (const ghidra::DecoderError &e) {
        throw LiftError("loading SLEIGH spec for " + language + ": " + e.explain);
      }
    }
    return *sleigh;
  }

  // Lets the engine go to the spares (park(), a rebuild, the end).
  void release_engine() {
    printer.reset();
    if (sleigh) give_spare(spare_key, std::move(sleigh));
    stale = true;
  }
  ~Impl() { release_engine(); }

  void build() {
    auto globals = lock_ghidra_globals();
    printer.reset();
    std::unique_ptr<Engine> reused = std::move(sleigh);
    if (!reused) reused = take_spare(spare_key);
    // The old database goes after the engine stops pointing at it.
    std::unique_ptr<ghidra::ContextInternal> old = std::move(context);
    context = std::make_unique<ghidra::ContextInternal>();

    ghidra::DocumentStorage store;
    std::istringstream sla("<sleigh>" + sla_path + "</sleigh>");
    ghidra::Element *root = store.parseDocument(sla)->getRoot();
    store.registerTag(root);
    if (reused) {
      // A decoded .sla: attach this program's bytes and a fresh context
      // database (initialize() only reregisters the context variables).
      reused->reset(window.get(), context.get());
      sleigh = std::move(reused);
      old.reset();
      sleigh->initialize(store);
    } else {
      old.reset();
      sleigh = std::make_unique<Engine>(window.get(), context.get());
      // Decoding the .sla file is most of the cost and touches no global
      // state (as for ImageArchitecture), so engines build in parallel.
      globals.unlock();
      struct Relock {
        std::unique_lock<std::shared_mutex> &lock;
        ~Relock() { lock.lock(); }
      } relock{globals};
      try {
        sleigh->initialize(store);
      } catch (...) {
        sleigh.reset();  // half decoded: neither reused nor a spare
        throw;
      }
    }
    for (const ghidra::TruncationTag &t : truncations) sleigh->truncateSpace(t);
    window->attach(sleigh->getDefaultCodeSpace());
    printer = std::make_unique<detail::GhidraText>(*sleigh);

    apply_pspec_context();

    ghidra::AddrSpace *code = sleigh->getDefaultCodeSpace();
    for (const Setting &s : settings) {
      if (s.start > code->getHighest()) continue;
      ghidra::Address end;  // invalid = to the top of the space
      if (s.end && *s.end <= code->getHighest()) end = ghidra::Address(code, *s.end);
      context->setVariableRegion(s.name, ghidra::Address(code, s.start), end, s.value);
    }
    built_context = encode_context();
    stale = false;
  }

  std::string encode_context() const {
    std::ostringstream out;
    ghidra::XmlEncode encoder(out);
    context->encode(encoder);
    return out.str();
  }

  // The language's default context (e.g. x86-64 longMode, ARM TMode) lives in
  // <context_data> of its .pspec, as for a Ghidra Architecture.
  void apply_pspec_context() {
    const ghidra::Element *root = pspec_root(pspec_path);
    if (root == nullptr) return;
    for (const ghidra::Element *child : root->getChildren()) {
      if (child->getName() != "context_data") continue;
      ghidra::XmlDecode decoder(sleigh.get(), child);
      context->decodeFromSpec(decoder);
    }
  }
};

Lifter::Lifter(std::shared_ptr<const loader::Image> image, const std::string &language)
    : impl_(std::make_unique<Impl>()) {
  require_initialized();
  if (!image) throw LiftError("no image");
  {
    auto globals = lock_ghidra_globals();
    const ghidra::LanguageDescription *desc = find_language(language);
    if (desc == nullptr) throw LiftError("unknown language " + language);
    impl_->language = desc->getId();
    impl_->sla_path = find_spec_file(desc->getSlaFile());
    impl_->pspec_path = find_spec_file(desc->getProcessorSpec());
    for (ghidra::int4 i = 0; i < desc->numTruncations(); ++i) impl_->truncations.push_back(desc->getTruncation(i));
  }
  impl_->spare_key = impl_->sla_path;
  for (const ghidra::TruncationTag &t : impl_->truncations)
    impl_->spare_key += "\n" + t.getName() + ":" + std::to_string(t.getSize());
  impl_->image = std::move(image);
  impl_->loadimage = std::make_unique<loader::GhidraLoadImage>(impl_->image, impl_->language);
  impl_->window = std::make_unique<WindowLoadImage>(*impl_->loadimage);
  impl_->engine();
}

Lifter::~Lifter() = default;

const std::string &Lifter::language() const { return impl_->language; }

std::string Lifter::register_name(std::uint64_t offset, std::uint32_t size) {
  Engine &sleigh = impl_->engine();
  ghidra::AddrSpace *reg = sleigh.getSpaceByName("register");
  if (reg == nullptr) return {};
  return sleigh.getExactRegisterName(reg, offset, static_cast<ghidra::int4>(size));
}

std::optional<Varnode> Lifter::register_varnode(const std::string &name) {
  Engine &sleigh = impl_->engine();
  try {
    const ghidra::VarnodeData &v = sleigh.getRegister(name);
    return Varnode{v.space->getName(), v.offset, v.size, {}};
  } catch (const ghidra::LowlevelError &) {
    return std::nullopt;
  }
}

std::vector<RegisterDef> Lifter::registers() {
  Engine &sleigh = impl_->engine();
  std::map<ghidra::VarnodeData, std::string> all;
  sleigh.getAllRegisters(all);
  std::vector<RegisterDef> out;
  out.reserve(all.size());
  for (const auto &[vn, name] : all)
    out.push_back({name, vn.offset, static_cast<std::uint32_t>(vn.size), vn.space->getName()});
  std::sort(out.begin(), out.end(), [](const RegisterDef &a, const RegisterDef &b) {
    if (a.space != b.space) return a.space == "register" || (b.space != "register" && a.space < b.space);
    if (a.offset != b.offset) return a.offset < b.offset;
    if (a.size != b.size) return a.size > b.size;
    return a.name < b.name;
  });
  return out;
}

std::vector<std::string> Lifter::userops() {
  Engine &sleigh = impl_->engine();
  std::vector<std::string> out;
  sleigh.getUserOpNames(out);
  return out;
}

std::vector<SpaceDef> Lifter::spaces() {
  Engine &sleigh = impl_->engine();
  std::vector<SpaceDef> out;
  for (ghidra::int4 i = 0; i < sleigh.numSpaces(); ++i) {
    ghidra::AddrSpace *space = sleigh.getSpace(i);
    SpaceDef d;
    if (space == nullptr) {
      out.push_back(d);
      continue;
    }
    d.name = space->getName();
    switch (space->getType()) {
      case ghidra::IPTR_CONSTANT: d.kind = SpaceDef::Kind::constant; break;
      case ghidra::IPTR_PROCESSOR: d.kind = SpaceDef::Kind::processor; break;
      case ghidra::IPTR_INTERNAL: d.kind = SpaceDef::Kind::unique; break;
      default: d.kind = SpaceDef::Kind::other; break;
    }
    if (dynamic_cast<ghidra::OtherSpace *>(space) != nullptr) d.kind = SpaceDef::Kind::other;
    d.address_size = static_cast<std::uint32_t>(space->getAddrSize());
    d.wordsize = static_cast<std::uint32_t>(space->getWordSize());
    d.big_endian = space->isBigEndian();
    d.is_register = d.name == "register";
    d.is_default = space == sleigh.getDefaultCodeSpace();
    out.push_back(std::move(d));
  }
  return out;
}

bool Lifter::big_endian() { return impl_->engine().isBigEndian(); }

unsigned Lifter::alignment() { return static_cast<unsigned>(impl_->engine().getAlignment()); }

std::string Lifter::code_space_name() { return impl_->engine().getDefaultCodeSpace()->getName(); }

std::vector<std::string> Lifter::memory_spaces() {
  Engine &sleigh = impl_->engine();
  std::vector<std::string> out;
  for (ghidra::int4 i = 0; i < sleigh.numSpaces(); ++i) {
    ghidra::AddrSpace *space = sleigh.getSpace(i);
    if (space == nullptr || space->getType() != ghidra::IPTR_PROCESSOR) continue;
    if (space->getName() == "register" || dynamic_cast<ghidra::OtherSpace *>(space) != nullptr) continue;
    out.push_back(space->getName());
  }
  return out;
}

bool Lifter::has_context(const std::string &name) const {
  impl_->engine();
  try {
    const ghidra::ContextDatabase &db = *impl_->context;  // base API; ContextInternal hides it
    db.getDefaultValue(name);                             // throws for unknown names
    return true;
  } catch (const ghidra::LowlevelError &) {
    return false;
  }
}

void Lifter::set_context(const std::string &name, std::uint32_t value, std::uint64_t start,
                         std::optional<std::uint64_t> end) {
  if (end && *end <= start) return;
  // Validate the name now, against the context database of the engine last
  // built (its variables are the language's, whatever was set since); the
  // rebuild itself waits for the next decode, so many settings cost one
  // rebuild, not one each.
  // (A parked Lifter keeps that database: no engine is taken back for this.)
  if (!impl_->context) impl_->engine();
  try {
    const ghidra::ContextDatabase &db = *impl_->context;  // base API; ContextInternal hides it
    db.getDefaultValue(name);                             // throws for unknown names
  } catch (const ghidra::LowlevelError &e) {
    throw LiftError("setting context " + name + ": " + e.explain);
  }
  impl_->settings.push_back({name, value, start, end});
  impl_->stale = true;
}

std::uint32_t Lifter::context_at(const std::string &name, std::uint64_t address) {
  Engine &sleigh = impl_->engine();
  try {
    const ghidra::ContextDatabase &db = *impl_->context;  // base API; ContextInternal hides it
    return static_cast<std::uint32_t>(db.getVariable(name, ghidra::Address(sleigh.getDefaultCodeSpace(), address)));
  } catch (const ghidra::LowlevelError &e) {
    throw LiftError("context " + name + ": " + e.explain);
  }
}

std::optional<Instruction> Lifter::lift(std::uint64_t address, bool in_delay_slot) {
  Engine &sleigh = impl_->engine();
  ghidra::AddrSpace *code = sleigh.getDefaultCodeSpace();
  if (address > code->getHighest() || !impl_->image->memory.is_mapped(address)) return std::nullopt;
  return decode(address, in_delay_slot);
}

std::optional<Instruction> Lifter::lift_pcode(std::uint64_t address, bool in_delay_slot) {
  Engine &sleigh = impl_->engine();
  ghidra::AddrSpace *code = sleigh.getDefaultCodeSpace();
  if (address > code->getHighest() || !impl_->image->memory.is_mapped(address)) return std::nullopt;
  return decode(address, in_delay_slot, Text::none);
}

std::optional<Instruction> Lifter::lift(std::uint64_t address, std::span<const std::byte> bytes,
                                        bool in_delay_slot) {
  return lift_window(address, bytes, in_delay_slot, Text::all);
}

std::optional<Instruction> Lifter::lift_pcode(std::uint64_t address, std::span<const std::byte> bytes,
                                              bool in_delay_slot) {
  return lift_window(address, bytes, in_delay_slot, Text::none);
}

std::optional<Instruction> Lifter::lift_mnemonic(std::uint64_t address, std::span<const std::byte> bytes,
                                                 bool in_delay_slot) {
  return lift_window(address, bytes, in_delay_slot, Text::mnemonic);
}

std::optional<Instruction> Lifter::lift_window(std::uint64_t address, std::span<const std::byte> bytes,
                                               bool in_delay_slot, Text text) {
  Engine &sleigh = impl_->engine();
  ghidra::AddrSpace *code = sleigh.getDefaultCodeSpace();
  if (bytes.empty() || address > code->getHighest()) return std::nullopt;
  if (bytes.size() - 1 > code->getHighest() - address) bytes = bytes.first(code->getHighest() - address + 1);
  // SLEIGH caches parses by address; anything cached there may have come
  // from other bytes, and what we parse now mustn't outlive the window.
  // An instruction and its delay slots span far less than this.
  constexpr std::size_t kMaxParseSpan = 64;
  auto forget = [&] {
    for (std::uint64_t i = 0; i < std::min(bytes.size(), kMaxParseSpan); ++i)
      sleigh.forget(ghidra::Address(code, address + i));
  };
  forget();
  impl_->window->set_window(address, bytes);
  // A window decode depends on the bytes and the set context only: its
  // context commits (ARM's LRset after mov lr,pc, TMode at a blx target)
  // are not applied, or a later decode would depend on this one.
  sleigh.allowContextSet(false);
  std::optional<Instruction> insn;
  try {
    insn = decode(address, in_delay_slot, text);
  } catch (...) {
    sleigh.allowContextSet(true);
    impl_->window->clear_window();
    forget();
    throw;
  }
  sleigh.allowContextSet(true);
  impl_->window->clear_window();
  forget();
  return insn;
}

bool Lifter::park() {
  if (!impl_->sleigh) return true;
  if (context_changed()) return false;  // decoding committed context a rebuild would lose
  impl_->release_engine();
  return true;
}

bool Lifter::parked() const { return !impl_->sleigh; }

bool Lifter::context_changed() const {
  return !impl_->stale && impl_->context && impl_->encode_context() != impl_->built_context;
}

std::optional<InstructionExtent> Lifter::measure(std::uint64_t address, bool in_delay_slot) {
  Engine &sleigh = impl_->engine();
  ghidra::AddrSpace *code = sleigh.getDefaultCodeSpace();
  if (address > code->getHighest() || !impl_->image->memory.is_mapped(address)) return std::nullopt;
  ghidra::Address addr(code, address);
  // decode() step by step: print (which decides whether there is an
  // instruction), walk the operands (no side effects), then emit p-code,
  // which applies the context commits first and finds the delay slots.
  InstructionExtent extent;
  try {
    NullAssembly assembly;
    extent.length = static_cast<std::uint32_t>(sleigh.printAssembly(assembly, addr));
  } catch (const ghidra::LowlevelError &) {  // BadDataError, UnimplError, DataUnavailError
    return std::nullopt;
  }
  if (extent.length == 0) return std::nullopt;
  const ghidra::int4 align = sleigh.getAlignment();
  if (align > 1 && address % static_cast<std::uint64_t>(align) != 0) return extent;  // oneInstruction refuses it
  try {
    ghidra::ParserContext *pos = sleigh.for_pcode(addr);
    if (pos->getDelaySlot() > 0) {
      std::optional<Instruction> insn = decode(address, in_delay_slot);
      if (!insn) return std::nullopt;
      return InstructionExtent{insn->length, insn->delay_slot};
    }
    pos->applyCommits();
  } catch (const ghidra::LowlevelError &) {
    // decode() gets the same error resolving the operands and emits nothing.
  }
  return extent;
}

std::optional<Instruction> Lifter::decode(std::uint64_t address, bool in_delay_slot, Text text) {
  Engine &sleigh = impl_->engine();
  ghidra::AddrSpace *code = sleigh.getDefaultCodeSpace();
  ghidra::Address addr(code, address);

  Instruction insn;
  insn.address = address;
  if (text != Text::all) {
    // Resolving the constructors is what fails on bytes that don't decode;
    // printing them adds nothing that can.
    try {
      insn.length = static_cast<std::uint32_t>(sleigh.instructionLength(addr));
      if (text == Text::mnemonic && insn.length != 0) {
        insn.mnemonic = sleigh.mnemonic(addr);
        if (in_delay_slot) insn.mnemonic = "_" + insn.mnemonic;
      }
    } catch (const ghidra::LowlevelError &) {
      return std::nullopt;
    }
    if (insn.length == 0) return std::nullopt;
    emit_pcode(insn);
    return insn;
  }
  try {
    AssemblyCollector assembly;
    insn.length = static_cast<std::uint32_t>(sleigh.printAssembly(assembly, addr));
    insn.mnemonic = assembly.mnemonic;
    insn.text = assembly.operands.empty() ? assembly.mnemonic : assembly.mnemonic + " " + assembly.operands;
  } catch (const ghidra::BadDataError &) {
    return std::nullopt;
  } catch (const ghidra::UnimplError &) {
    return std::nullopt;
  } catch (const ghidra::LowlevelError &) {
    return std::nullopt;  // e.g. DataUnavailError
  }
  if (insn.length == 0) return std::nullopt;

  if (in_delay_slot) insn.mnemonic = "_" + insn.mnemonic;  // as Java's getMnemonic()
  // Prefer Ghidra's Java formatting; keep the C++ text if the tree won't walk.
  try {
    insn.tokens = impl_->printer->tokens(sleigh.parsed(addr), insn.mnemonic);
    insn.text.clear();
    for (const Token &t : insn.tokens) insn.text += t.text;
  } catch (const ghidra::LowlevelError &) {
    insn.tokens.clear();
    if (in_delay_slot) insn.text = "_" + insn.text;
  }

  emit_pcode(insn);
  return insn;
}

void Lifter::emit_pcode(Instruction &insn) {
  Engine &sleigh = impl_->engine();
  ghidra::Address addr(sleigh.getDefaultCodeSpace(), insn.address);
  try {
    PcodeCollector collector(insn.pcode);
    ghidra::int4 fall = sleigh.oneInstruction(collector, addr);
    collector.mark_dynamic_spaces();
    if (fall > static_cast<ghidra::int4>(insn.length)) insn.delay_slot = static_cast<std::uint32_t>(fall) - insn.length;
  } catch (const ghidra::UnimplError &) {
    insn.pcode.clear();
    insn.unimplemented = true;
  } catch (const ghidra::BadDataError &) {
    // Can happen when a delay slot doesn't decode.
    insn.pcode.clear();
    insn.unimplemented = true;
  } catch (const ghidra::LowlevelError &) {
    insn.pcode.clear();
    insn.unimplemented = true;
  }
}

std::vector<Instruction> Lifter::lift_range(std::uint64_t start, std::uint64_t end) {
  std::vector<Instruction> out;
  const std::uint64_t step = std::max(1u, alignment());
  std::uint64_t a = start;
  std::uint64_t delay_end = start;  // bytes before this are a delay slot
  while (a < end) {
    std::optional<Instruction> insn = lift(a, a < delay_end);
    std::uint64_t advance = insn ? insn->length : step;
    if (insn && insn->delay_slot != 0) delay_end = a + insn->length + insn->delay_slot;
    if (insn) out.push_back(std::move(*insn));
    if (advance > UINT64_MAX - a) break;
    a += advance;
  }
  return out;
}

std::vector<AddressRange> Lifter::flow_body(std::uint64_t entry, std::size_t max_instructions) {
  const loader::Region *region = impl_->image->memory.find(entry);
  if (region == nullptr || !region->perms.exec) return {};
  const std::string ram = code_space_name();

  std::map<std::uint64_t, std::uint64_t> seen;  // address -> length
  std::vector<std::uint64_t> work{entry};
  while (!work.empty() && seen.size() < max_instructions) {
    std::uint64_t a = work.back();
    work.pop_back();
    while (region->contains(a) && !seen.contains(a) && seen.size() < max_instructions) {
      std::optional<Instruction> insn = lift(a);
      if (!insn) break;
      seen[a] = insn->length;
      // Delay-slot instructions belong to the body too.
      for (std::uint64_t d = a + insn->length; d < a + insn->length + insn->delay_slot;) {
        std::optional<Instruction> slot = lift(d, true);
        if (!slot) break;
        seen[d] = slot->length;
        d += slot->length;
      }

      bool falls_through = true;
      if (!insn->pcode.empty()) {
        const PcodeOp &last = insn->pcode.back();
        // A BRANCH into the const space is a jump within the instruction's own p-code.
        bool internal = !last.inputs.empty() && last.inputs[0].space == "const";
        if ((last.opcode == "BRANCH" && !internal) || last.opcode == "BRANCHIND" || last.opcode == "RETURN")
          falls_through = false;
      }
      for (const PcodeOp &op : insn->pcode) {
        if ((op.opcode == "BRANCH" || op.opcode == "CBRANCH") && !op.inputs.empty() &&
            op.inputs[0].space == ram && region->contains(op.inputs[0].offset))
          work.push_back(op.inputs[0].offset);
      }
      if (insn->unimplemented || !falls_through) break;
      a += insn->length + insn->delay_slot;
    }
  }

  std::vector<AddressRange> ranges;
  for (const auto &[addr, len] : seen) {
    std::uint64_t last = addr + (len - 1);
    if (!ranges.empty() && ranges.back().second + 1 >= addr) ranges.back().second = std::max(ranges.back().second, last);
    else ranges.emplace_back(addr, last);
  }
  return ranges;
}

}  // namespace revkit::lift
