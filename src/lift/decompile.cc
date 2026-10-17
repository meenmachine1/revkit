#include "revkit/lift/decompile.hh"
#include "revkit/lift/format_string.hh"

#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"

#include "crc32.hh"
#include "dynamic.hh"
#include "funcdata.hh"
#include "printc.hh"
#include "xml.hh"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>

#include <malloc.h>
#include <unistd.h>

namespace revkit::lift {
namespace {

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t) { return std::chrono::duration<double>(Clock::now() - t).count(); }

ghidra::uint4 comment_type(CommentFacts::Kind k) {
  switch (k) {
    case CommentFacts::eol: return ghidra::Comment::user1;
    case CommentFacts::pre: return ghidra::Comment::user2;
    case CommentFacts::post: return ghidra::Comment::user3;
    case CommentFacts::plate: return ghidra::Comment::header;
  }
  return ghidra::Comment::user2;
}

ghidra::uint4 override_type(const std::string &kind) {
  if (kind == "BRANCH") return ghidra::Override::BRANCH;
  if (kind == "CALL") return ghidra::Override::CALL;
  if (kind == "CALL_RETURN") return ghidra::Override::CALL_RETURN;
  if (kind == "RETURN") return ghidra::Override::RETURN;
  return ghidra::Override::NONE;
}

bool is_composite(const DecompElement &t) {
  if (t.tag != "type") return false;
  const auto *meta = t.attr("metatype");
  if (meta == nullptr || !std::holds_alternative<std::string>(*meta)) return false;
  const std::string &m = std::get<std::string>(*meta);
  return m == "struct" || m == "union";
}

std::optional<std::uint64_t> type_id(const DecompElement &t) {
  const auto *id = t.attr("id");
  if (id == nullptr) return std::nullopt;
  if (const auto *u = std::get_if<std::uint64_t>(id)) return *u;
  if (const auto *i = std::get_if<std::int64_t>(id)) return static_cast<std::uint64_t>(*i);
  return std::nullopt;
}

// Ids of named types an encoding refers to (typeref, or nested named types).
void referenced_ids(const DecompElement &t, std::set<std::uint64_t> &out, bool top = true) {
  if (!top && (t.tag == "typeref" || t.tag == "type" || t.tag == "def"))
    if (auto id = type_id(t)) out.insert(*id);
  for (const DecompElement &c : t.children) referenced_ids(c, out, false);
}

}  // namespace

// IllegalCharCppTransformer, which DecompileResults.getDecompiledFunction
// applies to function, variable, type, field and label tokens: characters
// that can't appear in a C++ identifier become '_' ("main.cold" ->
// "main_cold").
std::string legal_cpp_name(const std::string &in) {
  enum : unsigned { after_first = 1, templ = 2, op = 4, first = 8 };
  auto legal = [](unsigned char c) -> unsigned {
    if (c == '_') return after_first | templ | op | first;
    if (c >= '0' && c <= '9') return after_first | templ | op;
    switch (c) {
      case '*': case '(': case ')': case '[': case ']': case '&': return templ | op;
      case ':': case ',': return templ;
      case '+': case '-': case '|': case '=': case '!': case '/': case '%': case '^': return op;
      case '~': return templ | op | first;
      default: return 0;
    }
  };
  std::string out = in;
  int depth = 0;
  for (std::size_t i = 0; i < in.size(); ++i) {
    auto c = static_cast<unsigned char>(in[i]);
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80) continue;  // letters (non-ASCII kept)
    if (c == '<') {
      ++depth;
      continue;
    }
    if (c == '>') {
      depth = std::max(0, depth - 1);
      continue;
    }
    unsigned v = legal(c);
    if (v != 0) {
      if ((v & after_first) && i > 0) continue;
      if ((v & first) && i == 0) continue;
      if ((v & templ) && depth > 0) continue;
      if ((v & op) && i >= 8 && i <= 10 && in.starts_with("operator")) continue;
    }
    out[i] = '_';
  }
  return out;
}

namespace {

// The stock pretty printer with Java's name clean-up applied to tokens.
class LegalNameEmit : public ghidra::EmitPrettyPrint {
 public:
  void tagVariable(const std::string &name, syntax_highlight hl, const ghidra::Varnode *vn,
                   const ghidra::PcodeOp *op) override {
    ghidra::EmitPrettyPrint::tagVariable(hl == const_color ? name : legal_cpp_name(name), hl, vn, op);
  }
  void tagFuncName(const std::string &name, syntax_highlight hl, const ghidra::Funcdata *fd,
                   const ghidra::PcodeOp *op) override {
    ghidra::EmitPrettyPrint::tagFuncName(legal_cpp_name(name), hl, fd, op);
  }
  void tagType(const std::string &name, syntax_highlight hl, const ghidra::Datatype *ct) override {
    ghidra::EmitPrettyPrint::tagType(legal_cpp_name(name), hl, ct);
  }
  void tagField(const std::string &name, syntax_highlight hl, const ghidra::Datatype *ct, ghidra::int4 off,
                const ghidra::PcodeOp *op) override {
    ghidra::EmitPrettyPrint::tagField(legal_cpp_name(name), hl, ct, off, op);
  }
  void tagBitField(const std::string &name, syntax_highlight hl, const ghidra::Datatype *ct, ghidra::int4 id,
                   const ghidra::PcodeOp *op) override {
    ghidra::EmitPrettyPrint::tagBitField(legal_cpp_name(name), hl, ct, id, op);
  }
  void tagLabel(const std::string &name, syntax_highlight hl, const ghidra::AddrSpace *spc, ghidra::uintb off) override {
    ghidra::EmitPrettyPrint::tagLabel(legal_cpp_name(name), hl, spc, off);
  }
};

class LegalNamePrintC : public ghidra::PrintC {
 public:
  explicit LegalNamePrintC(ghidra::Architecture *arch) : ghidra::PrintC(arch, "c-language") {
    delete emit;  // PrintLanguage owns `emit`
    emit = new LegalNameEmit();
  }
};

// Moves every top-level <addr> of a <mapsym> encoding to `space`.
void set_space(DecompElement &mapsym, const std::string &space) {
  for (DecompElement &c : mapsym.children) {
    if (c.tag != "addr") continue;
    for (auto &[k, v] : c.attrs)
      if (k == "space") v = space;
  }
}

// Renames space `from` to `to` in every <addr> and storage of an encoding:
// the encoders write the default space as "ram", which is "code" on AVR
// and "CODE" on the 8051.
void rename_space(DecompElement &e, const std::string &from, const std::string &to) {
  for (auto &[k, v] : e.attrs)
    if (k == "space")
      if (auto *s = std::get_if<std::string>(&v); s != nullptr && *s == from) *s = to;
  for (DecompElement &c : e.children) rename_space(c, from, to);
}

}  // namespace

// ---- an index over fixed inputs -------------------------------------------

namespace {

class InputsLookup final : public FactLookup {
 public:
  InputsLookup(std::shared_ptr<const DecompilerInputs> inputs, const loader::Image *image)
      : in_(std::move(inputs)) {
    const DecompilerInputs &in = *in_;
    for (const FunctionFacts &f : in.functions) {
      functions_.emplace(f.entry, &f);
      for (const auto &[first, last] : f.body) bodies_.push_back({first, last, &f});
    }
    std::sort(bodies_.begin(), bodies_.end(), [](const Body &a, const Body &b) { return a.first < b.first; });
    for (const DataFacts &d : in.data) {
      data_.emplace_back(Key{intern(d.space), d.addr}, &d);
      longest_data_ = std::max<std::uint64_t>(longest_data_, d.length);
    }
    std::sort(data_.begin(), data_.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
    for (const ExternalRefFacts &x : in.external_refs) externals_.emplace(Key{intern(x.space), x.addr}, &x);
    for (const LabelFacts &l : in.labels) labels_.emplace(Key{intern(l.space), l.addr}, &l);
    for (const LabelFacts &l : in.code_labels) code_labels_.emplace(Key{intern(l.space), l.addr}, l.name);
    for (const BlockFacts &b : in.memory) {
      Mutability m = b.is_volatile ? Mutability::is_volatile : !b.write ? Mutability::constant : Mutability::normal;
      blocks_.push_back({Key{intern(b.space), b.start}, b.end, m});
    }
    if (in.memory.empty() && image != nullptr)
      for (const loader::Block &b : image->blocks)
        blocks_.push_back({Key{intern(std::string()), b.start}, b.start + (b.size - 1),
                           b.perms.write ? Mutability::normal : Mutability::constant});
    std::sort(blocks_.begin(), blocks_.end(), [](const Block &a, const Block &b) { return a.first < b.first; });
    for (const CommentFacts &c : in.comments)
      if (auto b = body_containing(c.addr)) comments_[b->function->entry].push_back(&c);
    for (const auto &[addr, kind] : in.flow_overrides) overrides_.emplace_back(addr, kind);
    for (const DecompElement &t : in.types)
      if (auto id = type_id(t)) types_.emplace(*id, &t);
  }

  const FunctionFacts *function_at(std::uint64_t entry) override {
    auto it = functions_.find(entry);
    return it == functions_.end() ? nullptr : it->second;
  }
  std::optional<Body> body_containing(std::uint64_t a) override {
    auto it = std::upper_bound(bodies_.begin(), bodies_.end(), a,
                               [](std::uint64_t x, const Body &r) { return x < r.first; });
    // Bodies of different functions can overlap; check the nearest few.
    for (int n = 0; it != bodies_.begin() && n < 64; ++n) {
      --it;
      if (it->last >= a) return *it;
    }
    return std::nullopt;
  }
  const DataFacts *data_containing(const std::string &sp, std::uint64_t a) override {
    const Key k{space(sp), a};
    auto it = std::upper_bound(data_.begin(), data_.end(), k,
                               [](const Key &x, const std::pair<Key, const DataFacts *> &d) { return x < d.first; });
    while (it != data_.begin()) {
      --it;
      if (it->first.space != k.space) break;
      if (it->second->addr + it->second->length > k.off) return it->second;
      if (k.off - it->second->addr >= longest_data_) break;
    }
    return nullptr;
  }
  const ExternalRefFacts *external_at(const std::string &sp, std::uint64_t a) override {
    auto it = externals_.find(Key{space(sp), a});
    return it == externals_.end() ? nullptr : it->second;
  }
  const LabelFacts *label_at(const std::string &sp, std::uint64_t a) override {
    auto it = labels_.find(Key{space(sp), a});
    return it == labels_.end() ? nullptr : it->second;
  }
  std::optional<std::string> code_label_at(const std::string &sp, std::uint64_t a) override {
    auto it = code_labels_.find(Key{space(sp), a});
    if (it == code_labels_.end()) return std::nullopt;
    return it->second;
  }
  std::optional<Mutability> block_at(const std::string &sp, std::uint64_t a) override {
    const Key k{space(sp), a};
    auto it = std::upper_bound(blocks_.begin(), blocks_.end(), k, [](const Key &x, const Block &b) { return x < b.first; });
    if (it == blocks_.begin()) return std::nullopt;
    --it;
    if (it->first.space != k.space || it->last < k.off) return std::nullopt;
    return it->mutability;
  }
  const DecompElement *type(std::uint64_t id) override {
    auto it = types_.find(id);
    return it == types_.end() ? nullptr : it->second;
  }
  std::vector<std::uint64_t> all_types() override {
    std::vector<std::uint64_t> out;
    for (const auto &[id, t] : types_) out.push_back(id);
    return out;
  }
  std::vector<const CommentFacts *> comments(std::uint64_t entry) override {
    auto it = comments_.find(entry);
    return it == comments_.end() ? std::vector<const CommentFacts *>{} : it->second;
  }
  // Every override, as each function the Java side builds gets them all.
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t) override { return overrides_; }
  std::vector<TrackedFacts> tracked(std::uint64_t entry) override {
    auto it = in_->tracked.find(entry);
    return it == in_->tracked.end() ? std::vector<TrackedFacts>{} : it->second;
  }
  bool stable() const override { return true; }

 private:
  struct Key {
    int space;
    std::uint64_t off;
    bool operator==(const Key &o) const { return space == o.space && off == o.off; }
    bool operator<(const Key &o) const { return space != o.space ? space < o.space : off < o.off; }
  };
  struct KeyHash {
    std::size_t operator()(const Key &k) const {
      return std::hash<std::uint64_t>()(k.off) ^ (static_cast<std::size_t>(k.space) << 48);
    }
  };
  struct Block {
    Key first;
    std::uint64_t last;
    Mutability mutability;
  };
  // Spaces are numbered while the index is built; a lookup in a space
  // the inputs never name finds nothing (-1). Lookups change nothing, so
  // threads may share the index.
  int intern(const std::string &name) {
    auto it = spaces_.find(name);
    if (it == spaces_.end()) it = spaces_.emplace(name, static_cast<int>(spaces_.size())).first;
    return it->second;
  }
  int space(const std::string &name) const {
    auto it = spaces_.find(name);
    return it == spaces_.end() ? -1 : it->second;
  }

  std::shared_ptr<const DecompilerInputs> in_;
  std::map<std::string, int> spaces_;
  std::unordered_map<std::uint64_t, const FunctionFacts *> functions_;
  std::vector<Body> bodies_;  // default space, sorted by first
  std::vector<std::pair<Key, const DataFacts *>> data_;
  std::uint64_t longest_data_ = 1;
  std::unordered_map<Key, const ExternalRefFacts *, KeyHash> externals_;
  std::unordered_map<Key, const LabelFacts *, KeyHash> labels_;
  std::unordered_map<Key, std::string, KeyHash> code_labels_;
  std::vector<Block> blocks_;
  std::unordered_map<std::uint64_t, std::vector<const CommentFacts *>> comments_;
  std::vector<std::pair<std::uint64_t, std::string>> overrides_;
  std::unordered_map<std::uint64_t, const DecompElement *> types_;
};

}  // namespace

std::unique_ptr<FactLookup> lookup_inputs(std::shared_ptr<const DecompilerInputs> inputs,
                                          const loader::Image *image) {
  return std::make_unique<InputsLookup>(std::move(inputs), image);
}

// ---- the decompiler ---------------------------------------------------------

struct InputDecompiler::State {
  std::shared_ptr<FactLookup> lookup;
  std::string prefix;  // address prefix of dynamic names
  std::uint64_t current = 0;  // entry of the function being decompiled
  // The function being decompiled when the lookup has none at its entry:
  // decompiled as Ghidra would one without a signature.
  std::unique_ptr<FunctionFacts> temp;
  // The function being analysed and printed: its recovered jump tables
  // name their cases (switch_label).
  ghidra::Funcdata *fd = nullptr;
  // Copies with dynamic storage assigned and extrapop filled in, by the
  // facts they were made from (kept across runs only for a stable lookup).
  std::vector<std::unique_ptr<FunctionFacts>> owned;
  std::unordered_map<const FunctionFacts *, const FunctionFacts *> prepared;
  std::unordered_map<const FunctionFacts *, const FunctionFacts *> stored;
  // Element trees already built from the type encodings, by id.
  std::unordered_map<std::uint64_t, std::unique_ptr<ghidra::Element>> type_elements;
  bool persistent_types = false;  // types kept across functions (see install_types)
  std::size_t runs = 0;
  std::set<std::uint64_t> tracked_entries;  // entries given a tracked set
  // The run's equates (RunHooks::equates), placed on their constants: the
  // function being decompiled has them in its local scope.
  std::vector<EquateSymbolFacts> equates;
};

namespace {

// The raw p-code ops of one instruction: opcode and inputs.
class OpCollector final : public ghidra::PcodeEmit {
 public:
  struct Op {
    ghidra::OpCode opc;
    std::vector<ghidra::VarnodeData> in;
  };
  std::vector<Op> ops;
  void dump(const ghidra::Address &, ghidra::OpCode opc, ghidra::VarnodeData *, ghidra::VarnodeData *vars,
            ghidra::int4 isize) override {
    ops.push_back({opc, std::vector<ghidra::VarnodeData>(vars, vars + isize)});
  }
};

// DynamicHash.matchWithPossibleExtension: whether a constant of `size`
// bytes holding `val` is `extendval`, zero- or sign-extended.
bool match_with_extension(std::uint64_t val, int size, std::uint64_t extendval) {
  if (static_cast<std::int64_t>(extendval) >= 0) return val == extendval;
  if (size <= 0 || size > 8) return false;
  const std::uint64_t mask = ~std::uint64_t{0} >> ((8 - size) * 8);
  const auto maskcomp = static_cast<std::uint64_t>(static_cast<std::int64_t>(~mask) >> 1);
  if ((extendval & maskcomp) != maskcomp) return false;
  return val == (mask & extendval);
}

// DynamicHash(op, slot): the level-0 hash of a constant input of a raw
// p-code op, which the decompiler's DynamicHash computes the same for the
// constant varnode it reads (method 0: the varnode and that op).
std::uint64_t constant_hash(const ghidra::Address &at, ghidra::OpCode opc, int slot, std::uint64_t value, int size) {
  const ghidra::uint4 code = ghidra::DynamicHash::transtable[opc];
  if (code == 0) return 0;  // a skipped op: no edge, no hash
  ghidra::uint4 reg = 0x3ba0fe06;
  reg = ghidra::crc_update(reg, static_cast<ghidra::uint4>(size));
  std::uint64_t v = value;
  for (int i = 0; i < size; ++i) {
    reg = ghidra::crc_update(reg, static_cast<ghidra::uint4>(v));
    v >>= 8;
  }
  reg = ghidra::crc_update(reg, static_cast<ghidra::uint4>(slot));
  reg = ghidra::crc_update(reg, code);
  std::uint64_t a = at.getOffset();
  for (int i = 0; i < at.getAddrSize(); ++i) {
    reg = ghidra::crc_update(reg, static_cast<ghidra::uint4>(a));
    a >>= 8;
  }
  std::uint64_t hash = 0;  // attached op, method 0
  hash <<= 7;
  hash |= code;
  hash <<= 5;
  hash |= static_cast<std::uint64_t>(slot & 0x1f);
  hash <<= 32;
  hash |= reg;
  return hash;
}

}  // namespace

InputDecompiler::InputDecompiler(const DecompileConfig &config)
    : InputDecompiler(config, [](ghidra::Architecture *arch) { return new LegalNamePrintC(arch); }) {}

InputDecompiler::InputDecompiler(const DecompileConfig &config,
                                 const std::function<ghidra::PrintLanguage *(ghidra::Architecture *)> &make_printer)
    : config_(config), errors_(std::make_unique<std::ostringstream>()), state_(std::make_unique<State>()) {
  if (!config_.inputs) config_.inputs = std::make_shared<DecompilerInputs>();
  ArchitectureOptions opts;
  opts.image_symbols = false;
  opts.java_strings = true;
  opts.memory = config_.memory;
  opts.context = config_.context;
  if (config_.memory) {
    // The source has the patched bytes.
  } else if (config_.patches) {
    opts.shared_patches = config_.patches;
  } else {
    opts.patches = config_.inputs->patches;
    opts.patches.insert(opts.patches.end(), config_.inputs->synthesized_memory.begin(),
                        config_.inputs->synthesized_memory.end());
  }
  // No read-only ranges from the image: as on the Java side, mutability
  // comes with each symbol or hole the scope resolves.
  opts.readonly.emplace();
  {
    auto globals = lock_ghidra_globals();
    arch_ = std::make_unique<ImageArchitecture>(config_.image, "image", config_.language_id, errors_.get(),
                                                std::move(opts));
    // Before init(), which configures the printer.
    ghidra::PrintLanguage *printer = make_printer(arch_.get());
    arch_->printlist.push_back(printer);
    arch_->print = printer;
  }
  arch_->init_image();
  // DecompInterface.setOptions: reset, then what grabFromProgram changes
  // from the defaults ("readonly on"); simplification style "decompile".
  arch_->resetDefaults();
  arch_->readonlypropagate = true;
  arch_->allacts.setCurrent(config_.action);
  // DecompileOptions.encode: <currentaction> decompile unreachable off.
  if (!config_.eliminate_unreachable) arch_->allacts.toggleAction("decompile", "unreachable", false);
  budget_.install(*arch_);
  install();
}

InputDecompiler::~InputDecompiler() {
  arch_.reset();  // writes to errors_ until destroyed
}

// Types are fetched when the decompiler first needs one (TypeFactoryGhidra
// asks Java the same way) and dropped after each function, so a type's
// warnings appear only in functions that use it.
void InputDecompiler::install_types() {
  arch_->type_factory().set_resolver([this](const std::string &name, std::uint64_t id) { return fetch_type(name, id); });
  // Ghidra's decompiler forgets its types after every function and asks
  // again, which is costly for programs whose structures reference most of
  // their types. The only visible effect of forgetting is a type's warning
  // (an enum with duplicate names, say), issued only in functions that
  // fetch it. So when no type has a warning, decode them all once and keep
  // them; otherwise fetch lazily and forget per function, like Java.
  std::vector<std::uint64_t> ids = state_->lookup->all_types();
  if (ids.empty()) return;
  for (std::uint64_t id : ids) {
    const DecompElement *t = state_->lookup->type(id);
    const auto *name = t != nullptr ? t->attr("name") : nullptr;
    arch_->type_factory().fetch(
        name != nullptr && std::holds_alternative<std::string>(*name) ? std::get<std::string>(*name) : std::string(), id);
    if (arch_->types->beginWarnings() != arch_->types->endWarnings()) break;
  }
  state_->persistent_types = arch_->types->beginWarnings() == arch_->types->endWarnings();
  if (!state_->persistent_types) arch_->types->clearNoncore();
  warnings_.clear();  // problems surface again when a function needs the type
}

ghidra::Datatype *InputDecompiler::fetch_type(const std::string &name, std::uint64_t id) {
  static const DecompElement kDefault{"type",
                                      {{"name", std::string("undefined")},
                                       {"id", std::uint64_t{0xc000000000000000ULL}},
                                       {"metatype", std::string("unknown")},
                                       {"size", std::int64_t{1}}},
                                      {}};
  const DecompElement *t = state_->lookup->type(id);
  if (t == nullptr && id == 0xc000000000000000ULL) t = &kDefault;
  if (t == nullptr) return nullptr;
  std::unique_ptr<ghidra::Element> &root = state_->type_elements[id];
  if (!root || !state_->lookup->stable()) root.reset(to_element(*t));
  try {
    ghidra::XmlDecode decoder(arch_.get(), root.get());
    return arch_->types->decodeType(decoder);
  } catch (const ghidra::LowlevelError &err) {
    warnings_.push_back("type " + name + ": " + err.explain);
  } catch (const ghidra::DecoderError &err) {
    warnings_.push_back("type " + name + ": " + err.explain);
  }
  return nullptr;
}

ghidra::Scope *InputDecompiler::scope_for(const NamespacePath &ns) {
  ghidra::Scope *scope = arch_->symboltab->getGlobalScope();
  for (const auto &[id, name] : ns) scope = arch_->symboltab->findCreateScope(id, name, scope);
  return scope;
}

ghidra::Symbol *InputDecompiler::add_symbol(const DecompElement &e, const NamespacePath &ns, const std::string &what) {
  std::unique_ptr<ghidra::Element> root;
  if (const std::string &code = arch_->getDefaultCodeSpace()->getName(); code != "ram" && arch_->getSpaceByName("ram") == nullptr) {
    DecompElement renamed = e;
    rename_space(renamed, "ram", code);
    root.reset(to_element(renamed));
  } else {
    root.reset(to_element(e));
  }
  ghidra::Symbol *sym = nullptr;
  try {
    ghidra::Scope *scope = scope_for(ns);
    ghidra::XmlDecode decoder(arch_.get(), root.get());
    try {
      sym = scope->addMapSym(decoder);
    } catch (const ghidra::DuplicateFunctionError &err) {
      // The function is cached already, under a smaller symbol than this
      // query needs (ScopeGhidra::dump2Cache): use it.
      if (err.address.isInvalid()) throw;
      ghidra::Funcdata *fd = scope->findFunction(err.address);
      if (fd == nullptr) throw;
      return fd->getSymbol();
    }
    // ScopeGhidraNamespace::addMapInternal: a namespace owns the addresses
    // of its symbols, so lookups find them there.
    if (sym != nullptr && scope != arch_->symboltab->getGlobalScope())
      if (ghidra::SymbolEntry *entry = sym->getFirstWholeMap())
        arch_->symboltab->addRange(scope, entry->getAddr().getSpace(), entry->getFirst(), entry->getLast());
  } catch (const ghidra::LowlevelError &err) {
    warnings_.push_back(what + ": " + err.explain);
  } catch (const ghidra::DecoderError &err) {
    warnings_.push_back(what + ": " + err.explain);
  }
  return sym;
}

void InputDecompiler::install() {
  State &st = *state_;
  st.lookup = config_.lookup ? config_.lookup : std::shared_ptr<FactLookup>(lookup_inputs(config_.inputs, config_.image.get()));
  st.prefix = config_.inputs->address_prefix;
  install_types();
  ImageScope &scope = arch_->global_scope();
  // The processor spec's default symbols (RISC-V CSRs, ...) reach Ghidra's
  // decompiler as the program's own labels, asked for like any other.
  scope.reset();
  scope.snapshot_properties();
  if (JavaStringManager *strings = arch_->java_strings())
    strings->set_defined([this](const ghidra::Address &a) { return defined_string(a); });
  scope.set_resolvers([this](const ghidra::Address &a, ImageScope::Hole &hole) { return resolve(a, hole); },
                      [this](const ghidra::Address &a) { return code_label(a); },
                      [this](const ghidra::Address &a) { return external_function(a); });
}

// Inputs name the space of an address outside Java's default space,
// which is the code space (on AVR and PIC the data space is another).
std::string InputDecompiler::space_name(const ghidra::Address &addr) const {
  return addr.getSpace() == arch_->getDefaultCodeSpace() ? std::string() : addr.getSpace()->getName();
}

// Getting the facts of a function ready for the decompiler: storage where
// it is dynamic, an unknown extrapop from the default convention.
const FunctionFacts *InputDecompiler::prepared(const FunctionFacts *f) {
  if (f == nullptr) return nullptr;
  if (auto it = state_->prepared.find(f); it != state_->prepared.end()) return it->second;
  const FunctionFacts *use = f->dynamic_storage ? with_storage(*f) : f;
  if (!use->extrapop && config_.default_extrapop) {
    auto copy = std::make_unique<FunctionFacts>(*use);
    copy->extrapop = arch_->defaultfp != nullptr ? arch_->defaultfp->getExtraPop() : 0;
    use = copy.get();
    state_->owned.push_back(std::move(copy));
  }
  state_->prepared.emplace(f, use);
  return use;
}

std::optional<FactLookup::Body> InputDecompiler::body_containing(std::uint64_t a) {
  if (state_->temp && a == state_->temp->entry) return FactLookup::Body{a, a, state_->temp.get()};
  std::optional<FactLookup::Body> b = state_->lookup->body_containing(a);
  if (b) b->function = prepared(b->function);
  return b;
}

void InputDecompiler::set_context(std::uint64_t entry) {
  const FunctionFacts *f = state_->lookup->function_at(entry);
  if (f == nullptr) return;
  // Each function is decoded under the image's context and its own,
  // whatever was decompiled before: what decoding other code set over this
  // function's (a BL or BLX to it from the other instruction set, as data
  // read as code has them; an IT block's state) is undone first.
  auto each = [&](auto &&fn) {
    for (const auto &[first, last] : f->body)
      if (last != ~std::uint64_t{0}) fn(first, last);
    for (const auto &[first, last] : f->context_reach)
      if (last != ~std::uint64_t{0}) fn(first, last);
  };
  each([&](std::uint64_t first, std::uint64_t last) { arch_->reset_context(first, last + 1); });
  for (const auto &[name, value] : f->context)
    each([&](std::uint64_t first, std::uint64_t last) {
      try {
        arch_->set_context_region(name, first, last + 1, value);
      } catch (const ghidra::LowlevelError &) {
        // not a context variable of this language
      }
    });
}

void InputDecompiler::set_tracked(std::uint64_t entry) {
  ghidra::AddrSpace *code = arch_->getDefaultCodeSpace();
  if (entry >= code->getHighest()) return;
  std::vector<TrackedFacts> sets = state_->lookup->tracked(entry);
  if (sets.empty() && !state_->tracked_entries.contains(entry)) return;
  state_->tracked_entries.insert(entry);
  // The language's own tracked values (the pspec's tracked_set, x86 DF)
  // stay unless a fact sets the same register.
  const ghidra::TrackedSet inherited = arch_->context->getTrackedDefault();
  ghidra::TrackedSet &ts = arch_->context->createSet(ghidra::Address(code, entry), ghidra::Address(code, entry + 1));
  ts = inherited;
  auto put = [&ts](const ghidra::TrackedContext &tc) {
    for (ghidra::TrackedContext &old : ts)
      if (old.loc.space == tc.loc.space && old.loc.offset == tc.loc.offset && old.loc.size == tc.loc.size) {
        old.val = tc.val;
        return;
      }
    ts.push_back(tc);
  };
  for (const TrackedFacts &t : sets) {
    ghidra::TrackedContext tc;
    if (!t.register_name.empty()) {
      try {
        tc.loc = arch_->translate->getRegister(t.register_name);
      } catch (const ghidra::LowlevelError &) {
        continue;
      }
    } else {
      ghidra::AddrSpace *spc = arch_->getSpaceByName(t.reg.space);
      if (spc == nullptr) continue;
      tc.loc.space = spc;
      tc.loc.offset = t.reg.offset;
      tc.loc.size = static_cast<ghidra::uint4>(t.reg.size);
    }
    tc.val = t.value;
    put(tc);
  }
}

// A copy of `f` with its parameters' and return value's storage assigned
// by its calling convention (Java's dynamic storage: FunctionDB and
// PrototypeModel.getStorageLocations mirror ProtoModel::assignParameterStorage).
// The copy is owned by the state; on failure, `f` itself.
const FunctionFacts *InputDecompiler::with_storage(const FunctionFacts &f) {
  if (auto it = state_->stored.find(&f); it != state_->stored.end()) return it->second;
  std::optional<FunctionFacts> assigned = assign_storage(f);
  if (!assigned) return &f;
  auto copy = std::make_unique<FunctionFacts>(std::move(*assigned));
  const FunctionFacts *result = copy.get();
  state_->owned.push_back(std::move(copy));
  state_->stored.emplace(&f, result);
  return result;
}

std::optional<FunctionFacts> InputDecompiler::assign_storage(const FunctionFacts &f) {
  ghidra::ProtoModel *model = arch_->defaultfp;
  if (f.convention && *f.convention != "default" && *f.convention != "unknown")
    if (ghidra::ProtoModel *m = arch_->getModel(*f.convention)) model = m;
  if (model == nullptr) return std::nullopt;
  auto decode = [&](const DecompElement &e) -> ghidra::Datatype * {
    std::unique_ptr<ghidra::Element> root(to_element(e));
    ghidra::XmlDecode decoder(arch_.get(), root.get());
    return arch_->types->decodeType(decoder);
  };
  auto copy = std::make_unique<FunctionFacts>(f);
  // An unknown convention stays unknown (not model-locked), with the
  // default model's storage, as Java's dynamic storage does.
  if (!f.convention || *f.convention == "default") copy->convention = model->getName();
  copy->extrapop = model->getExtraPop();
  try {
    ghidra::PrototypePieces pieces;
    pieces.model = model;
    pieces.name = f.name;
    pieces.outtype = decode(f.ret.type);
    for (const ParamFacts &p : f.params) {
      pieces.intypes.push_back(decode(p.type));
      pieces.innames.push_back(p.name);
    }
    pieces.firstVarArgSlot = f.varargs ? static_cast<int>(f.params.size()) : -1;
    std::vector<ghidra::ParameterPieces> res;
    model->assignParameterStorage(pieces, res, true);
    auto storage = [&](const ghidra::ParameterPieces &pp) {
      std::vector<StorageVarnode> out;
      if (pp.addr.isInvalid()) return out;
      int size = (pp.flags & ghidra::ParameterPieces::indirectstorage) != 0
                     ? static_cast<int>(pp.addr.getSpace()->getAddrSize())
                     : pp.type->getSize();
      if (pp.addr.getSpace()->getType() == ghidra::IPTR_JOIN) {
        ghidra::JoinRecord *join = arch_->findJoin(pp.addr.getOffset());
        for (int i = 0; i < static_cast<int>(join->numPieces()); ++i) {
          const ghidra::VarnodeData &v = join->getPiece(i);
          out.push_back({v.space->getName(), v.offset, static_cast<int>(v.size)});
        }
        return out;
      }
      out.push_back({pp.addr.getSpace()->getName(), pp.addr.getOffset(), size});
      return out;
    };
    // Output.
    if (res.empty()) return std::nullopt;
    const ghidra::ParameterPieces &out = res[0];
    copy->ret.size = out.type != nullptr ? out.type->getSize() : 0;
    if (out.type == nullptr || out.type->getMetatype() == ghidra::TYPE_VOID) {
      copy->ret.storage = std::vector<StorageVarnode>{};
      copy->ret.void_storage = true;
      copy->ret.size = 0;
    } else {
      copy->ret.storage = storage(out);
      copy->ret.void_storage = false;
    }
    // Inputs: an auto parameter for a hidden return pointer comes first.
    std::vector<ParamFacts> params;
    std::size_t next = 0;
    for (std::size_t i = 1; i < res.size(); ++i) {
      ParamFacts p;
      if (res[i].flags & ghidra::ParameterPieces::hiddenretparm) {
        p.name = "__return_storage_ptr__";
        p.auto_kind = "RETURN_STORAGE_PTR";
        DecompElement ptr{"type",
                          {{"metatype", std::string("ptr")},
                           {"name", std::string()},
                           {"size", std::int64_t{res[i].type->getSize()}}},
                          {f.ret.type}};
        p.type = std::move(ptr);
      } else {
        if (next >= f.params.size()) break;
        p = f.params[next++];
      }
      p.storage = storage(res[i]);
      p.valid = !p.storage.empty();
      p.stack = !p.storage.empty() && p.storage[0].space == arch_->getStackSpace()->getName();
      params.push_back(std::move(p));
    }
    copy->params = std::move(params);
  } catch (const ghidra::LowlevelError &err) {
    warnings_.push_back("storage for " + f.name + ": " + err.explain);
    return std::nullopt;
  } catch (const ghidra::DecoderError &err) {
    warnings_.push_back("storage for " + f.name + ": " + err.explain);
    return std::nullopt;
  }
  copy->dynamic_storage = false;
  return std::move(*copy);
}

DecompilerInputs InputDecompiler::resolved_inputs() {
  DecompilerInputs out = *config_.inputs;
  for (FunctionFacts &f : out.functions)
    if (f.dynamic_storage) f = *with_storage(f);
  for (ExternalRefFacts &x : out.external_refs)
    if (x.function && x.function->dynamic_storage) x.function = *with_storage(*x.function);
  return out;
}

// LocalSymbolMap.grabEquates: each equate on the constants of its
// instruction's p-code holding its value (DynamicHash.calcConstantHash),
// or on the one its hash names.
void InputDecompiler::place_equates(const std::vector<EquateFacts> &equates) {
  ghidra::AddrSpace *code = arch_->getDefaultCodeSpace();
  std::map<std::uint64_t, OpCollector> decoded;
  for (const EquateFacts &e : equates) {
    if (e.addr > code->getHighest()) continue;
    const ghidra::Address at(code, e.addr);
    if (e.hash != 0) {
      state_->equates.push_back({e.name, e.format, e.value, e.addr, e.hash});
      continue;
    }
    auto [it, fresh] = decoded.try_emplace(e.addr);
    if (fresh) try {
        arch_->translate->oneInstruction(it->second, at);
      } catch (const ghidra::LowlevelError &) {  // UnimplError, BadDataError
        it->second.ops.clear();
      }
    std::set<std::uint64_t> hashes;
    for (const OpCollector::Op &op : it->second.ops)
      for (std::size_t i = 0; i < op.in.size(); ++i) {
        const ghidra::VarnodeData &vn = op.in[i];
        if (vn.space == nullptr || vn.space->getType() != ghidra::IPTR_CONSTANT) continue;
        if (!match_with_extension(vn.offset, static_cast<int>(vn.size), e.value)) continue;
        if (std::uint64_t h = constant_hash(at, op.opc, static_cast<int>(i), vn.offset, static_cast<int>(vn.size)); h != 0)
          hashes.insert(h);
      }
    for (std::uint64_t h : hashes) state_->equates.push_back({e.name, e.format, e.value, e.addr, h});
  }
}

// DecompileCallback.getMappedSymbols: what Ghidra's Java side answers when
// the decompiler asks about an address.
ghidra::Symbol *InputDecompiler::resolve(const ghidra::Address &addr, ImageScope::Hole &hole) {
  FactLookup &look = *state_->lookup;
  const std::uint64_t a = addr.getOffset();
  const std::string space = space_name(addr);
  const bool ram = space.empty();
  // A pointer with an external reference (an import slot).
  if (const ExternalRefFacts *x = look.external_at(space, a))
    return add_symbol(encode_external_ref(a, x->label), {}, "external " + x->label);
  // A function's body: the function near its entry, else a read-only hole.
  if (std::optional<FactLookup::Body> r = ram ? body_containing(a) : std::nullopt) {
    const FunctionFacts &f = *r->function;
    if (a >= f.entry && a - f.entry < 8)
      return add_symbol(encode_function_symbol(f, f.entry, f.entry == state_->current, static_cast<int>(a - f.entry + 1),
                                               f.entry == state_->current ? &state_->equates : nullptr),
                        f.ns, "function " + f.name);
    hole = {r->first, r->last, true, false};
    return nullptr;
  }
  // A register: no symbol, the decompiler uses the register's name.
  const std::optional<Mutability> b = look.block_at(space, a);
  const Mutability m = b.value_or(Mutability::normal);
  if (arch_->register_starts_at(addr)) {
    hole = {a, a, m == Mutability::constant, m == Mutability::is_volatile};
    return nullptr;
  }
  // Defined data, or undefined bytes with a symbol.
  if (const DataFacts *d = look.data_containing(space, a)) {
    DecompElement e = encode_data_symbol(*d);
    if (!ram) set_space(e, addr.getSpace()->getName());
    return add_symbol(e, d->ns, "data " + d->name);
  }
  if (const LabelFacts *l = look.label_at(space, a)) {
    DecompElement e = encode_label_symbol(*l);
    if (!ram) set_space(e, addr.getSpace()->getName());
    return add_symbol(e, l->ns, "label " + l->name);
  }
  // Undefined bytes: Java names them dynamically (UNK_ without references),
  // but only sends a symbol when they aren't plain writable memory.
  auto dynamic = [&](const char *prefix) {
    std::string name =
        std::string(prefix) + (ram ? state_->prefix : addr.getSpace()->getName() + "_") + ghidra_offset_text(addr);
    DecompElement e = encode_undefined_symbol(a, name, m);
    if (!ram) set_space(e, addr.getSpace()->getName());
    return add_symbol(e, {}, name);
  };
  if (config_.default_names && b) return dynamic("DAT_");  // no symbol table: assume a reference
  if (b && m != Mutability::normal) return dynamic("UNK_");
  hole = {a, a, m == Mutability::constant, m == Mutability::is_volatile};
  return nullptr;
}

// DecompileCallback.getCodeLabel: the primary symbol's name.
std::string InputDecompiler::code_label(const ghidra::Address &addr) {
  FactLookup &look = *state_->lookup;
  const std::uint64_t a = addr.getOffset();
  const std::string space = space_name(addr);
  if (space.empty()) {
    const FunctionFacts *f = state_->temp && state_->temp->entry == a ? state_->temp.get() : look.function_at(a);
    if (f != nullptr) return f->label.empty() || f->entry == state_->current ? f->name : f->label;
  }
  std::optional<std::string> l = look.code_label_at(space, a);
  // A switch case's label replaces the default one (DecompilerSwitchAnalysisCmd)
  // where revkit's own references decide the labels (default names, no
  // synthesized LAB_); Ghidra's exported labels already have them.
  if (space.empty() && config_.default_names && !config_.default_labels && (!l || l->starts_with("LAB_")))
    if (std::optional<std::string> s = switch_label(a)) return *s;
  if (l) return *l;
  if (const LabelFacts *l = look.label_at(space, a)) return l->name;
  if (const DataFacts *d = look.data_containing(space, a); d != nullptr && d->addr == a) return d->name;
  if (config_.default_names && config_.default_labels && space.empty() && body_containing(a))
    return "LAB_" + state_->prefix + ghidra_offset_text(addr);
  return {};
}

// DecompilerSwitchAnalysisCmd.labelSwitch: a target of one of the current
// function's recovered jump tables is <switchD_<jump>>::caseD_<value> (the
// first case going there), or ::default for the case without a value or
// with the decompiler's default value; getCodeLabel joins the namespace with
// an underscore.
std::optional<std::string> InputDecompiler::switch_label(std::uint64_t a) {
  ghidra::Funcdata *fd = state_->fd;
  if (fd == nullptr) return std::nullopt;
  constexpr std::uint32_t kDefaultCase = 0xbad1abe1;  // DecompilerSwitchAnalysisCmd.DEFAULT_CASE_VALUE
  for (int t = 0; t < fd->numJumpTables(); ++t) {
    ghidra::JumpTable *jt = fd->getJumpTable(t);
    if (jt == nullptr || !jt->isRecovered()) continue;
    const int n = jt->numEntries();
    // Java's label table: the entries that have a label, in order.
    std::vector<std::uint32_t> labels;
    // (Recovered labels pad the table with NO_LABEL.)
    if (jt->isLabelled())
      for (int i = 0; i < n; ++i)
        if (const ghidra::uintb v = jt->getLabelByIndex(i); v != ghidra::JumpValues::NO_LABEL)
          labels.push_back(static_cast<std::uint32_t>(v));
    for (int i = 0; i < n; ++i) {
      const ghidra::Address dest = jt->getAddressByIndex(i);
      if (dest.getSpace() != fd->getAddress().getSpace() || dest.getOffset() != a) continue;
      const std::size_t k = static_cast<std::size_t>(i);
      const bool is_default = k == labels.size() || (k < labels.size() && labels[k] == kDefaultCase);
      std::string name = "switchD_" + state_->prefix + ghidra_offset_text(jt->getOpAddress()) + "_";
      if (is_default) return name + "default";
      char buf[32];
      std::snprintf(buf, sizeof buf, "caseD_%x", k < labels.size() ? labels[k] : static_cast<std::uint32_t>(k));
      return name + buf;
    }
  }
  return std::nullopt;
}

// The value of defined string data containing an address (Java's
// StringDataInstance, offcut by the byte offset).
std::optional<std::string> InputDecompiler::defined_string(const ghidra::Address &addr) {
  const DataFacts *d = state_->lookup->data_containing(space_name(addr), addr.getOffset());
  if (d == nullptr || !d->string) return std::nullopt;
  const std::uint64_t diff = addr.getOffset() - d->addr;
  if (diff == 0) return d->string;
  if (diff >= d->string->size()) return std::string();
  return d->string->substr(diff);
}

// DecompileCallback.getExternalRef: the external function, mapped at the slot.
ghidra::Funcdata *InputDecompiler::external_function(const ghidra::Address &slot) {
  const ExternalRefFacts *x = state_->lookup->external_at(space_name(slot), slot.getOffset());
  if (x == nullptr || !x->function) return nullptr;
  FunctionFacts f = x->function->dynamic_storage ? *with_storage(*x->function) : *x->function;
  if (!f.extrapop && config_.default_extrapop && arch_->defaultfp != nullptr) f.extrapop = arch_->defaultfp->getExtraPop();
  auto *sym = dynamic_cast<ghidra::FunctionSymbol *>(
      add_symbol(encode_function_symbol(f, slot.getOffset(), false, 2), f.ns, "external function " + f.name));
  return sym != nullptr ? sym->getFunction() : nullptr;
}

namespace {

// A varnode's constant value through copies, casts and PTRSUB(0, c), as the
// decompiler leaves a string's address.
std::optional<std::uint64_t> constant_value(const ghidra::Varnode *vn) {
  for (int depth = 0; vn != nullptr && depth < 8; ++depth) {
    if (vn->isConstant()) return vn->getOffset();
    if (!vn->isWritten()) return std::nullopt;
    const ghidra::PcodeOp *op = vn->getDef();
    switch (op->code()) {
      case ghidra::CPUI_COPY:
      case ghidra::CPUI_CAST:
        vn = op->getIn(0);
        break;
      case ghidra::CPUI_PTRSUB:
      case ghidra::CPUI_INT_ADD:
        if (op->getIn(0)->isConstant() && op->getIn(1)->isConstant())
          return (op->getIn(0)->getOffset() + op->getIn(1)->getOffset()) & ghidra::calc_mask(vn->getSize());
        return std::nullopt;
      default:
        return std::nullopt;
    }
  }
  return std::nullopt;
}

// The index of a varargs prototype's format parameter: a pointer to
// characters named like a format (glibc's __format and __fmt, mingw's
// _Format, Ghidra's archives' names).
int format_parameter(const ghidra::PrototypePieces &p) {
  for (std::size_t i = 0; i < p.innames.size() && i < p.intypes.size(); ++i) {
    std::string n = p.innames[i];
    for (char &c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (n.find("format") == std::string::npos && n.find("fmt") == std::string::npos) continue;
    const ghidra::Datatype *t = p.intypes[i];
    if (t == nullptr || t->getMetatype() != ghidra::TYPE_PTR) continue;
    const ghidra::Datatype *target = static_cast<const ghidra::TypePointer *>(t)->getPtrTo();
    if (target->getSize() == 1 || target->getSize() == 2 || target->getSize() == 4) return static_cast<int>(i);
  }
  return -1;
}

}  // namespace

// Call-site prototypes for calls to printf- and scanf-like functions with
// a constant format (DecompileConfig::format_strings), by call address.
std::map<std::uint64_t, ghidra::PrototypePieces> InputDecompiler::format_overrides(ghidra::Funcdata &fd) {
  std::map<std::uint64_t, ghidra::PrototypePieces> out;
  ghidra::TypeFactory &tf = *arch_->types;
  ghidra::AddrSpace *data = arch_->getDefaultDataSpace();
  FormatModel model;
  model.int_size = tf.getSizeOfInt();
  model.long_size = tf.getSizeOfLong();
  model.pointer_size = tf.getSizeOfPointer();
  model.wchar_size = tf.getSizeOfWChar();
  model.long_double_size = model.pointer_size == 8 ? 16 : 12;
  model.windows = config_.image && config_.image->format == loader::Format::pe;
  if (model.windows) model.long_double_size = 8;
  for (int i = 0; i < fd.numCalls(); ++i) {
    ghidra::FuncCallSpecs *fc = fd.getCallSpecs(i);
    if (fc == nullptr || !fc->isDotdotdot() || !fc->isInputLocked()) continue;
    ghidra::PcodeOp *op = fc->getOp();
    if (op == nullptr || op->code() != ghidra::CPUI_CALL) continue;
    ghidra::PrototypePieces pieces;
    fc->getPieces(pieces);
    const int k = format_parameter(pieces);
    if (k < 0 || op->numInput() <= k + 1) continue;
    std::optional<std::uint64_t> at = constant_value(op->getIn(k + 1));
    if (!at || *at > data->getHighest()) continue;
    const int unit = static_cast<const ghidra::TypePointer *>(pieces.intypes[k])->getPtrTo()->getSize();
    // The format's text: the data facts' string, else the bytes.
    std::string text;
    if (unit == 1)
      if (std::optional<std::string> s = defined_string(ghidra::Address(data, *at))) text = *s;
    if (text.empty()) {
      bool done = false;
      std::uint8_t buf[64];
      for (std::uint64_t off = 0; off < 1024 && !done; off += sizeof buf) {
        try {
          arch_->loader->loadFill(buf, sizeof buf, ghidra::Address(data, *at + off));
        } catch (const ghidra::DataUnavailError &) {
          break;
        }
        for (std::size_t j = 0; j + unit <= sizeof buf; j += unit) {
          std::uint32_t c = 0;
          for (int b = 0; b < unit; ++b) {
            const int shift = data->isBigEndian() ? 8 * (unit - 1 - b) : 8 * b;
            c |= std::uint32_t(buf[j + b]) << shift;
          }
          if (c == 0) {
            done = true;
            break;
          }
          text += c < 0x80 ? static_cast<char>(c) : '?';
        }
      }
      if (!done) continue;
    }
    std::string name = fc->getName();
    const bool scan = name.find("scanf") != std::string::npos;
    std::optional<std::vector<FormatArg>> args = scan ? scanf_arguments(text, model) : printf_arguments(text, model);
    if (!args) continue;
    // The named parameters, then one per conversion: not varargs, so the
    // call passes exactly those.
    pieces.intypes.resize(k + 1);
    pieces.innames.resize(k + 1);
    for (const FormatArg &a : *args) {
      ghidra::Datatype *t = nullptr;
      switch (a.kind) {
        case FormatArg::Kind::integer: t = tf.getBase(a.size, a.is_signed ? ghidra::TYPE_INT : ghidra::TYPE_UINT); break;
        case FormatArg::Kind::floating: t = tf.getBase(a.size, ghidra::TYPE_FLOAT); break;
        case FormatArg::Kind::string:
          t = tf.getTypePointer(model.pointer_size, tf.getTypeChar(a.size), data->getWordSize());
          break;
        case FormatArg::Kind::pointer:
          t = tf.getTypePointer(model.pointer_size, tf.getTypeVoid(), data->getWordSize());
          break;
        case FormatArg::Kind::int_ptr:
          t = tf.getTypePointer(model.pointer_size, tf.getBase(a.size, a.is_signed ? ghidra::TYPE_INT : ghidra::TYPE_UINT),
                                data->getWordSize());
          break;
        case FormatArg::Kind::float_ptr:
          t = tf.getTypePointer(model.pointer_size, tf.getBase(a.size, ghidra::TYPE_FLOAT), data->getWordSize());
          break;
      }
      if (t == nullptr) break;
      pieces.intypes.push_back(t);
      pieces.innames.push_back("");
    }
    if (pieces.intypes.size() != static_cast<std::size_t>(k + 1) + args->size()) continue;
    pieces.firstVarArgSlot = -1;
    out.emplace(op->getAddr().getOffset(), std::move(pieces));
  }
  return out;
}

std::optional<ghidra::PrototypePieces> InputDecompiler::call_pieces(const FunctionFacts &f) {
  ghidra::ProtoModel *model = arch_->defaultfp;
  if (f.convention && *f.convention != "default" && *f.convention != "unknown")
    if (ghidra::ProtoModel *m = arch_->getModel(*f.convention)) model = m;
  if (model == nullptr) return std::nullopt;
  auto decode = [&](const DecompElement &e) -> ghidra::Datatype * {
    std::unique_ptr<ghidra::Element> root(to_element(e));
    ghidra::XmlDecode decoder(arch_.get(), root.get());
    return arch_->types->decodeType(decoder);
  };
  try {
    ghidra::PrototypePieces pieces;
    pieces.model = model;
    pieces.name = f.name;
    pieces.outtype = decode(f.ret.type);
    for (const ParamFacts &p : f.params) {
      pieces.intypes.push_back(decode(p.type));
      pieces.innames.push_back(p.name);
    }
    if (pieces.outtype == nullptr) return std::nullopt;
    for (ghidra::Datatype *t : pieces.intypes)
      if (t == nullptr) return std::nullopt;
    pieces.firstVarArgSlot = f.varargs ? static_cast<int>(f.params.size()) : -1;
    return pieces;
  } catch (const ghidra::LowlevelError &) {
  } catch (const ghidra::DecoderError &) {
  }
  return std::nullopt;
}

DecompileResult InputDecompiler::decompile(std::uint64_t entry, const RunHooks *hooks) {
  const auto started = Clock::now();
  DecompileResult r;
  r.entry = entry;
  ghidra::AddrSpace *code = arch_->getDefaultCodeSpace();
  ImageScope &scope = arch_->global_scope();
  if (entry > code->getHighest()) {
    r.error = "entry outside the code space";
    return r;
  }
  const ghidra::Address addr(code, entry);
  FactLookup &look = *state_->lookup;
  state_->current = entry;
  warnings_.clear();
  if (look.function_at(entry) == nullptr) {
    auto temp = std::make_unique<FunctionFacts>();
    temp->entry = entry;
    arch_->nameFunction(addr, temp->name);
    temp->convention = "unknown";
    temp->ret.type = DecompElement{"void", {}, {}};
    temp->ret.storage = std::vector<StorageVarnode>{};
    temp->ret.void_storage = true;
    if (arch_->defaultfp != nullptr) temp->extrapop = arch_->defaultfp->getExtraPop();
    temp->body.emplace_back(entry, entry);
    state_->temp = std::move(temp);
  }

  ghidra::Funcdata *fd = nullptr;
  budget_.start(hooks != nullptr && hooks->limits != nullptr ? *hooks->limits : config_.limits);
  try {
    set_tracked(entry);
    set_context(entry);
    std::vector<std::pair<std::uint64_t, ghidra::uint4>> overrides;
    // "PCODE_<kind>": applied to the p-code as it is emitted (as Java's
    // PcodeOverride does), for instructions Funcdata::overrideFlow can't
    // change (conditional computed jumps).
    std::map<std::uint64_t, std::uint32_t> pcode_overrides;
    // Fallthrough overrides (FactLookup::flow_overrides): applied to the
    // p-code too, as Java's PcodeEmit does.
    std::map<std::uint64_t, std::uint64_t> falls;
    std::set<std::uint64_t> stops;
    for (const auto &[a, kind] : look.flow_overrides(entry)) {
      if (std::optional<FallthroughKind> ft = parse_fallthrough_kind(kind)) {
        if (ft->to > code->getHighest()) continue;
        if (ft->falls) falls[a] = ft->to;
        else stops.insert(ft->to);
      } else if (kind.starts_with("PCODE_")) {
        if (ghidra::uint4 t = override_type(kind.substr(6)); t != ghidra::Override::NONE) pcode_overrides[a] = t;
      } else if (ghidra::uint4 t = override_type(kind); t != ghidra::Override::NONE && a <= code->getHighest()) {
        overrides.emplace_back(a, t);
      }
    }
    arch_->set_pcode_overrides(std::move(pcode_overrides));
    arch_->set_fallthroughs(std::move(falls), std::move(stops));
    if (hooks != nullptr)
      for (const auto &[a, kind] : hooks->flow_overrides)
        if (ghidra::uint4 t = override_type(kind); t != ghidra::Override::NONE && a <= code->getHighest())
          overrides.emplace_back(a, t);

    // Call-site prototypes from constant format strings (format_overrides),
    // and the user's signature overrides (RunHooks::call_protos).
    std::map<std::uint64_t, ghidra::PrototypePieces> format_protos, user_protos;
    if (hooks != nullptr)
      for (const auto &[a, f] : hooks->call_protos) {
        if (a > code->getHighest()) continue;
        if (std::optional<ghidra::PrototypePieces> p = call_pieces(f)) user_protos.emplace(a, std::move(*p));
        else {
          char buf[64];
          std::snprintf(buf, sizeof buf, "the signature override at 0x%llx has a type the decompiler can't use",
                        static_cast<unsigned long long>(a));
          warnings_.push_back(buf);
        }
      }
    // `tables`: computed jumps to give recovered tables to.
    auto analyse = [&](const std::set<std::uint64_t> &tables) {
      if (fd != nullptr) {
        // A fresh function: flow overrides can't be removed from one, and
        // nothing of the first run should remain.
        arch_->clearAnalysis(fd);
        scope.reset();
        arch_->commentdb->clear();
      }
      fd = scope.queryFunction(addr);
      if (fd == nullptr) throw ghidra::LowlevelError("no function at the entry");
      state_->fd = fd;
      for (const auto &[a, type] : overrides) fd->getOverride().insertFlowOverride(ghidra::Address(code, a), type);
      for (const auto &[a, pieces] : user_protos) {
        auto proto = std::make_unique<ghidra::FuncProto>();
        proto->setInternal(pieces.model != nullptr ? pieces.model : arch_->defaultfp, arch_->types->getTypeVoid());
        proto->setPieces(pieces);
        fd->getOverride().insertProtoOverride(ghidra::Address(code, a), proto.release());
      }
      for (const auto &[a, pieces] : format_protos) {
        if (user_protos.contains(a)) continue;  // the user's own
        auto proto = std::make_unique<ghidra::FuncProto>();
        proto->setInternal(pieces.model != nullptr ? pieces.model : arch_->defaultfp, arch_->types->getTypeVoid());
        proto->setPieces(pieces);
        fd->getOverride().insertProtoOverride(ghidra::Address(code, a), proto.release());
      }
      std::set<std::uint64_t> install = tables;
      if (hooks != nullptr) {
        // The user's call references on computed calls, and the jump
        // tables the user's references make (RunHooks).
        for (const auto &[at, to] : hooks->call_targets)
          if (at <= code->getHighest() && to <= code->getHighest())
            fd->getOverride().insertIndirectOverride(ghidra::Address(code, at), ghidra::Address(code, to));
        for (std::uint64_t at : hooks->forced_tables)
          if (hooks->jump_tables.contains(at)) install.insert(at);
      }
      for (std::uint64_t at : install) {
        std::vector<ghidra::Address> dests;
        for (std::uint64_t t : hooks->jump_tables.at(at))
          if (t <= code->getHighest()) dests.emplace_back(code, t);
        fd->installJumpTable(ghidra::Address(code, at))->setOverride(dests, ghidra::Address(), 0, 0);
      }
      ghidra::Action *act = arch_->allacts.getCurrent();
      act->reset(*fd);
      return act->perform(*fd);
    };
    state_->equates.clear();
    if (hooks != nullptr && !hooks->equates.empty()) place_equates(hooks->equates);
    analyse({});
    if (hooks != nullptr && !hooks->jump_tables.empty()) {
      // Where the decompiler couldn't recover a table (it then treats the
      // jump as a call or a return), run again with the one given.
      std::set<std::uint64_t> unrecovered;
      for (auto it = arch_->commentdb->beginComment(addr); it != arch_->commentdb->endComment(addr); ++it) {
        const ghidra::Comment &c = **it;
        if ((c.getType() & ghidra::Comment::warning) &&
            c.getText().find("Treating indirect jump as") != std::string::npos &&
            hooks->jump_tables.contains(c.getAddr().getOffset()))
          unrecovered.insert(c.getAddr().getOffset());
      }
      if (!unrecovered.empty()) analyse(unrecovered);
    }
    if (config_.format_strings && fd->isProcComplete()) {
      format_protos = format_overrides(*fd);
      for (const auto &[a, p] : user_protos) format_protos.erase(a);
      if (!format_protos.empty()) {
        // Again with the calls' prototypes (and any table the last run used).
        std::set<std::uint64_t> tables;
        if (hooks != nullptr)
          for (int t = 0; t < fd->numJumpTables(); ++t)
            if (const ghidra::JumpTable *jt = fd->getJumpTable(t); jt != nullptr && jt->isOverride() &&
                                                                 hooks->jump_tables.contains(jt->getOpAddress().getOffset()))
              tables.insert(jt->getOpAddress().getOffset());
        analyse(tables);
      }
    }
    if (!fd->isProcComplete()) throw ghidra::LowlevelError("decompilation did not complete");
    // The Java side's comments reach the decompiler when the printer first
    // asks for them, after the analysis has added its warnings; their order
    // in the header follows from that.
    for (const CommentFacts *c : look.comments(entry))
      arch_->commentdb->addComment(comment_type(c->kind), addr, ghidra::Address(code, c->addr), c->text);
    if (hooks != nullptr)
      for (const CommentFacts &c : hooks->comments)
        if (c.addr <= code->getHighest())
          arch_->commentdb->addComment(comment_type(c.kind), addr, ghidra::Address(code, c.addr), c.text);
    if (hooks != nullptr && hooks->printing) hooks->printing(true);
    try {
      if (hooks != nullptr && hooks->print) {
        auto globals = share_ghidra_globals();
        hooks->print(*fd);
      } else {
        std::ostringstream out;
        // Exclusively: besides the C printer's shared operator tables, the
        // pretty printer numbers its tokens from a static counter
        // (TokenSplit::countbase) that concurrent printers would race on.
        auto globals = lock_ghidra_globals();
        arch_->print->setOutputStream(&out);
        arch_->print->docFunction(fd);
        arch_->print->setOutputStream(nullptr);
        r.c = out.str();
      }
    } catch (...) {
      if (hooks != nullptr && hooks->printing) hooks->printing(false);
      throw;
    }
    if (hooks != nullptr && hooks->printing) hooks->printing(false);
    r.ok = true;
  } catch (const DecompileStopped &err) {
    r.error = err.explain;
  } catch (const ghidra::LowlevelError &err) {
    r.error = err.explain;
  } catch (const ghidra::DecoderError &err) {
    r.error = err.explain;
  } catch (const std::exception &err) {
    r.error = err.what();
  }
  if (budget_.stopped() != DecompileStop::none) {
    // Stopped, perhaps inside a step that caught the stop and went on:
    // whatever the run produced, it is over its limits.
    r.ok = false;
    r.c.clear();
    r.stopped = budget_.stopped();
    r.error = budget_.message();
    spoiled_ = true;
  }
  r.varnodes = budget_.peak_varnodes();
  if (std::string failed = end_run(); !failed.empty()) {
    if (r.error.empty()) r.error = failed;
    r.ok = false;
  }
  r.input_errors.swap(warnings_);
  r.milliseconds = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
  return r;
}

// Runs between refreshes of kept types (end_run).
constexpr std::size_t kTypeRefresh = 1024;

// FlushNative: nothing survives to the next function.
std::string InputDecompiler::end_run() {
  std::string failed;
  try {
    arch_->global_scope().reset();
    if (!state_->persistent_types) {
      arch_->types->clearNoncore();
    } else if (++state_->runs % kTypeRefresh == 0) {
      // Kept types also gather what analysis made (pointers, arrays,
      // partial structs), every function's: start again from the inputs'
      // now and then, or an instance decompiling a whole large program
      // grows by hundreds of megabytes.
      std::vector<std::string> run_warnings = std::move(warnings_);  // this run's, reported by decompile()
      arch_->types->clearNoncore();
      install_types();
      warnings_ = std::move(run_warnings);
    }
    arch_->commentdb->clear();
    arch_->stringManager->clear();
  } catch (const ghidra::LowlevelError &err) {
    failed = "cleanup: " + err.explain;
  }
  state_->temp.reset();
  // Kept across runs for a stable lookup, but not without bound: an
  // instance that decompiles a whole large program would otherwise hold a
  // prepared copy of every function any of them called.
  constexpr std::size_t kMaxCached = 4096;
  if (!state_->lookup->stable() || state_->owned.size() > kMaxCached || state_->prepared.size() > kMaxCached ||
      state_->type_elements.size() > kMaxCached) {
    state_->prepared.clear();
    state_->stored.clear();
    state_->owned.clear();
    state_->type_elements.clear();
  }
  state_->lookup->reset();
  return failed;
}

namespace {

std::size_t resident_bytes() {
  std::ifstream statm("/proc/self/statm");
  std::size_t pages = 0, resident = 0;
  statm >> pages >> resident;
  return resident * static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
}

// What a function's run is expected to hold at its peak, from its body's
// size: varnodes per byte of code at kBytesPerVarnode each (ops, covers
// and heritage included), never less than kMinRun. Measured on cmake's
// largest functions (15 to 26 KB of code): 15 to 19 varnodes per byte at
// their peak, 700 to 760 bytes of resident memory per varnode; small
// functions have far fewer, about 2 per byte.
constexpr std::size_t kBytesPerVarnode = 1024;
constexpr std::size_t kVarnodesPerByte = 24;
constexpr std::size_t kMinRun = std::size_t{4} << 20;

std::size_t estimate(std::uint64_t body_bytes) {
  // Varnodes per byte grow with the function: about 2 for a few hundred
  // bytes, 15 to 19 for 15 to 26 KB.
  const std::uint64_t per_byte = std::min<std::uint64_t>(kVarnodesPerByte, 2 + body_bytes / 1024);
  return std::max<std::size_t>(kMinRun, static_cast<std::size_t>(body_bytes * per_byte) * kBytesPerVarnode);
}

// Hands out functions largest first. With a memory budget, a function
// starts only while the estimates of those running plus its own fit in
// what the budget leaves beside the process's baseline; when the next
// largest doesn't fit, the smallest that does runs instead, and when
// nothing is running, the next largest runs anyway (one at a time, its
// varnode bound keeps it within the budget).
class Scheduler {
 public:
  Scheduler(std::vector<std::size_t> order, std::vector<std::size_t> cost, std::size_t budget)
      : order_(std::move(order)), cost_(std::move(cost)), budget_(budget), back_(order_.size()) {}

  void set_baseline(std::size_t bytes) {
    std::lock_guard lock(mu_);
    baseline_ = bytes;
  }
  void cap(std::size_t bytes) {
    std::lock_guard lock(mu_);
    for (std::size_t &c : cost_) c = std::min(c, bytes);
  }
  std::size_t peak_rss() const { return peak_rss_.load(); }
  bool over() {
    std::lock_guard lock(mu_);
    return over_;
  }

  // The next function to run (an index into the entries), or nullopt when
  // every one has been handed out.
  std::optional<std::size_t> take() {
    std::unique_lock lock(mu_);
    for (;;) {
      if (front_ >= back_) return std::nullopt;
      if (budget_ == 0) return start(order_[front_++]);
      const std::size_t room = budget_ > baseline_ + reserved_ ? budget_ - baseline_ - reserved_ : 0;
      if (running_ == 0) return start(order_[front_++]);
      if (!over_ && cost_[order_[front_]] <= room) return start(order_[front_++]);
      // The smallest left, if it fits (it nearly always does).
      if (cost_[order_[back_ - 1]] <= (over_ ? kMinRun : room)) return start(order_[--back_]);
      cv_.wait(lock);
    }
  }

  void done(std::size_t k) {
    std::size_t rss = resident_bytes();
    peak_rss_.store(std::max(peak_rss_.load(), rss));
    std::lock_guard lock(mu_);
    reserved_ -= cost_[k];
    --running_;
    if (budget_ != 0) {
      // glibc keeps freed memory; a large run's is worth giving back.
      if (rss > budget_ / 10 * 9 || cost_[k] > budget_ / 16) {
        malloc_trim(0);
        rss = resident_bytes();
      }
      // Measured memory over the budget: only the smallest until it isn't
      // (a large run is bounded by its varnode limit on its own).
      over_ = rss > budget_;
    }
    cv_.notify_all();
  }

 private:
  std::size_t start(std::size_t k) {
    reserved_ += cost_[k];
    ++running_;
    return k;
  }

  std::vector<std::size_t> order_;
  std::vector<std::size_t> cost_;
  const std::size_t budget_;
  std::size_t front_ = 0, back_;
  std::size_t baseline_ = 0, reserved_ = 0, running_ = 0;
  bool over_ = false;
  std::atomic<std::size_t> peak_rss_{0};
  std::mutex mu_;
  std::condition_variable cv_;
};

}  // namespace

std::vector<DecompileResult> decompile_functions(const DecompileConfig &config,
                                                 const std::vector<std::uint64_t> &entries, DecompileStats *stats,
                                                 const std::function<void(std::size_t, DecompileResult &)> &on_result) {
  std::mutex result_mu;
  const auto started = Clock::now();
  std::vector<DecompileResult> results(entries.size());
  if (entries.empty()) return results;
  unsigned threads = config.threads != 0 ? config.threads : std::max(1u, std::thread::hardware_concurrency());
  threads = static_cast<unsigned>(std::min<std::size_t>(threads, entries.size()));

  // Biggest functions first, so the slowest ones don't straggle at the end.
  std::vector<std::size_t> order(entries.size());
  std::vector<std::uint64_t> bytes(entries.size(), 0);
  for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
  if (config.inputs) {
    std::unordered_map<std::uint64_t, std::uint64_t> size;
    for (const FunctionFacts &f : config.inputs->functions) {
      std::uint64_t n = 0;
      for (const auto &[a, b] : f.body) n += b - a + 1;
      size[f.entry] = n;
    }
    for (std::size_t i = 0; i < entries.size(); ++i)
      if (auto it = size.find(entries[i]); it != size.end()) bytes[i] = it->second;
    if (!config.in_order)
      std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return bytes[a] > bytes[b]; });
  }
  std::vector<std::size_t> cost(entries.size());
  for (std::size_t i = 0; i < entries.size(); ++i) cost[i] = estimate(bytes[i]);
  Scheduler schedule(order, std::move(cost), config.memory_budget);

  // Instances first, then the baseline the budget leaves room beside, and
  // the bound on one function. Instances share one index over the inputs
  // and one copy of their patches (relocations: tens of megabytes each on
  // a large program).
  DecompileConfig run_config = config;
  if (config.inputs && !config.lookup)
    run_config.lookup = std::shared_ptr<FactLookup>(lookup_inputs(config.inputs, config.image.get()));
  if (config.inputs && !config.patches) {
    auto patches = std::make_shared<ArchitectureOptions::Patches>(config.inputs->patches);
    patches->insert(patches->end(), config.inputs->synthesized_memory.begin(), config.inputs->synthesized_memory.end());
    run_config.patches = std::move(patches);
  }
  std::vector<std::unique_ptr<InputDecompiler>> instances(threads);
  std::vector<std::string> failure(threads);
  std::atomic<double> setup_max{0};
  auto build = [&](unsigned index) {
    const auto t0 = Clock::now();
    try {
      instances[index] = std::make_unique<InputDecompiler>(run_config);
    } catch (const ghidra::LowlevelError &e) {
      failure[index] = e.explain;
    } catch (const ghidra::DecoderError &e) {
      failure[index] = e.explain;
    } catch (const std::exception &e) {
      failure[index] = e.what();
    }
    double s = seconds_since(t0);
    double cur = setup_max.load();
    while (s > cur && !setup_max.compare_exchange_weak(cur, s)) {
    }
  };
  {
    std::vector<std::thread> pool;
    for (unsigned t = 1; t < threads; ++t) pool.emplace_back(build, t);
    build(0);
    for (std::thread &t : pool) t.join();
  }
  std::vector<std::string> warnings;
  if (instances[0]) warnings = instances[0]->warnings();
  if (config.memory_budget != 0) {
    const std::size_t baseline = resident_bytes();
    schedule.set_baseline(baseline);
    // A quarter of the budget for one function: from the budget alone, so
    // which functions stop doesn't depend on the run.
    if (run_config.limits.max_varnodes == 0)
      run_config.limits.max_varnodes = std::max<std::size_t>(config.memory_budget / 4 / kBytesPerVarnode, 1 << 16);
    // No run can hold more than its varnode bound lets it.
    schedule.cap(run_config.limits.max_varnodes * kBytesPerVarnode);

  }

  std::atomic<std::size_t> stopped{0}, rebuilt{0};
  std::vector<std::size_t> since_rebuild(threads, 0);
  auto work = [&](unsigned index) {
    std::unique_ptr<InputDecompiler> &d = instances[index];
    while (std::optional<std::size_t> next = schedule.take()) {
      const std::size_t k = *next;
      if (!d && failure[index].empty()) build(index);  // replaced after a stopped run
      if (!d) {
        results[k].entry = entries[k];
        results[k].error = "decompiler unavailable: " + failure[index];
        schedule.done(k);
        continue;
      }
      RunHooks hooks;
      hooks.limits = &run_config.limits;
      static const bool trace = std::getenv("REVKIT_DECOMPILE_TRACE") != nullptr;
      if (trace) std::fprintf(stderr, "start %llx %llu bytes rss %zu MB\n", static_cast<unsigned long long>(entries[k]),
                              static_cast<unsigned long long>(bytes[k]), resident_bytes() >> 20);
      results[k] = d->decompile(entries[k], &hooks);
      if (trace)
        std::fprintf(stderr, "done %llx %.0f ms %zu varnodes rss %zu MB%s\n", static_cast<unsigned long long>(entries[k]),
                     results[k].milliseconds, results[k].varnodes, resident_bytes() >> 20,
                     results[k].stopped != DecompileStop::none ? " stopped" : "");
      if (on_result) {
        std::lock_guard lock(result_mu);
        on_result(k, results[k]);
        std::string().swap(results[k].c);
      }
      if (d->spoiled()) {
        // Stopped mid-analysis: a fresh instance for the next function.
        ++stopped;
        d.reset();
        ++rebuilt;
      }
      schedule.done(k);
      if (d && schedule.over() && ++since_rebuild[index] >= 256) {
        // Over the budget, and malloc can't give back what an instance
        // holds between functions: build it afresh now and then.
        since_rebuild[index] = 0;
        d.reset();
        ++rebuilt;
        malloc_trim(0);
      }
    }
  };
  std::vector<std::thread> pool;
  for (unsigned t = 1; t < threads; ++t) pool.emplace_back(work, t);
  work(0);
  for (std::thread &t : pool) t.join();
  if (stats) {
    stats->threads = threads;
    stats->setup_seconds = setup_max.load();
    stats->total_seconds = seconds_since(started);
    stats->warnings = std::move(warnings);
    stats->stopped = stopped.load();
    stats->rebuilt = rebuilt.load();
    stats->peak_rss = schedule.peak_rss();
    stats->max_varnodes = run_config.limits.max_varnodes;
  }
  return results;
}

}  // namespace revkit::lift
