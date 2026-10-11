// SleighDecoder: a SLEIGH engine over caller-supplied bytes and context.

#include "revkit/lift/sleigh_decoder.hh"

#include "ghidra_text.hh"
#include "libdecomp.hh"
#include "sleigh.hh"
#include "sleigh_arch.hh"

#include <algorithm>
#include <map>
#include <sstream>

namespace revkit::lift {

namespace {

// Serves the bytes of the current decode; everything else reads as zero, and
// a request that misses them entirely is unavailable (as unmapped memory).
class BufferLoadImage : public ghidra::LoadImage {
 public:
  BufferLoadImage() : ghidra::LoadImage("revkit-buffer") {}
  void set(std::uint64_t start, std::span<const std::byte> bytes) {
    start_ = start;
    bytes_ = bytes;
  }
  void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address &addr) override {
    if (size <= 0) return;
    std::fill(ptr, ptr + size, ghidra::uint1{0});
    const std::uint64_t at = addr.getOffset();
    bool any = false;
    for (ghidra::int4 i = 0; i < size; ++i) {
      const std::uint64_t a = at + static_cast<std::uint64_t>(i);
      if (a < at) break;
      if (a >= start_ && a - start_ < bytes_.size()) {
        ptr[i] = std::to_integer<ghidra::uint1>(bytes_[a - start_]);
        any = true;
      }
    }
    if (!any) throw ghidra::DataUnavailError("no bytes supplied at this address");
  }
  std::string getArchType() const override { return "revkit-buffer"; }
  void adjustVma(long) override {}

 private:
  std::uint64_t start_ = 0;
  std::span<const std::byte> bytes_;
};

// The context database the engine reads: every address has the context
// words of the current decode. Variable layouts are recorded as the engine
// registers them.
class FixedContext : public ghidra::ContextInternal {
 public:
  void registerVariable(const std::string &nm, ghidra::int4 sbit, ghidra::int4 ebit) override {
    ghidra::ContextInternal::registerVariable(nm, sbit, ebit);
    ghidra::ContextBitRange r(sbit, ebit);
    vars_[nm] = ContextVariable{nm, r.getWord(), r.getShift(), r.getMask()};
  }
  const ghidra::uintm *getContext(const ghidra::Address &) const override { return fixed_.data(); }
  const ghidra::uintm *getContext(const ghidra::Address &addr, ghidra::uintb &first,
                                  ghidra::uintb &last) const override {
    first = 0;
    last = addr.getSpace()->getHighest();
    return fixed_.data();
  }
  // The words before any override: the spec's defaults.
  std::vector<std::uint32_t> defaults(const ghidra::Address &addr) const {
    const ghidra::uintm *w = ghidra::ContextInternal::getContext(addr);
    return std::vector<std::uint32_t>(w, w + getContextSize());
  }
  void set_fixed(std::span<const std::uint32_t> words) {
    fixed_.assign(std::max<std::size_t>(getContextSize(), 1), 0);
    for (std::size_t i = 0; i < fixed_.size() && i < words.size(); ++i) fixed_[i] = words[i];
  }
  const std::map<std::string, ContextVariable> &vars() const { return vars_; }

 private:
  std::vector<ghidra::uintm> fixed_ = std::vector<ghidra::uintm>(8, 0);
  std::map<std::string, ContextVariable> vars_;
};

class Engine : public ghidra::Sleigh {
 public:
  using ghidra::Sleigh::Sleigh;
  ghidra::ParserContext *at(const ghidra::Address &addr, ghidra::int4 state) const {
    return obtainContext(addr, state);
  }
  void forget(const ghidra::Address &addr) const {
    obtainContext(addr, ghidra::ParserContext::uninitialized)->setParserState(ghidra::ParserContext::uninitialized);
  }
};

class Collector : public ghidra::AssemblyEmit {
 public:
  void dump(const ghidra::Address &, const std::string &mnem, const std::string &body) override {
    mnemonic = mnem;
    operands = body;
  }
  std::string mnemonic, operands;
};

// "x86:LE:64:default:gcc" -> "x86:LE:64:default"
std::string base_language(const std::string &id) {
  if (std::count(id.begin(), id.end(), ':') >= 4) return id.substr(0, id.rfind(':'));
  return id;
}

void walk(ghidra::ParserWalker &w, std::vector<const ghidra::Constructor *> &out) {
  const ghidra::Constructor *ct = w.getConstructor();
  if (ct == nullptr) return;
  out.push_back(ct);
  for (int i = 0; i < ct->getNumOperands(); ++i) {
    const ghidra::OperandSymbol *sym = ct->getOperand(i);
    const ghidra::TripleSymbol *t = sym->getDefiningSymbol();
    if (t == nullptr || t->getType() != ghidra::SleighSymbol::subtable_symbol) continue;
    w.pushOperand(i);
    walk(w, out);
    w.popOperand();
  }
}

}  // namespace

struct SleighDecoder::Impl {
  std::string language;
  BufferLoadImage image;
  std::unique_ptr<FixedContext> context;
  std::unique_ptr<Engine> sleigh;
  std::unique_ptr<detail::GhidraText> printer;
  std::vector<std::uint32_t> defaults;
};

SleighDecoder::SleighDecoder(const std::string &language) : impl_(std::make_unique<Impl>()) {
  if (!ghidra_root()) throw LiftError("revkit::lift::initialize() was not called");
  std::string sla, pspec;
  std::vector<ghidra::TruncationTag> truncations;
  auto globals = lock_ghidra_globals();
  {
    const std::string base = base_language(language);
    const ghidra::LanguageDescription *desc = nullptr;
    for (const ghidra::LanguageDescription &d : ghidra::SleighArchitecture::getDescriptions())
      if (d.getId() == base) desc = &d;
    if (desc == nullptr) throw LiftError("unknown language " + language);
    impl_->language = desc->getId();
    ghidra::SleighArchitecture::specpaths.findFile(sla, desc->getSlaFile());
    ghidra::SleighArchitecture::specpaths.findFile(pspec, desc->getProcessorSpec());
    if (sla.empty() || pspec.empty()) throw LiftError("cannot find the spec files of " + language);
    for (ghidra::int4 i = 0; i < desc->numTruncations(); ++i) truncations.push_back(desc->getTruncation(i));
  }
  try {
    impl_->context = std::make_unique<FixedContext>();
    impl_->sleigh = std::make_unique<Engine>(&impl_->image, impl_->context.get());
    ghidra::DocumentStorage store;
    std::istringstream doc("<sleigh>" + sla + "</sleigh>");
    ghidra::Element *root = store.parseDocument(doc)->getRoot();
    store.registerTag(root);
    impl_->sleigh->initialize(store);
    for (const ghidra::TruncationTag &t : truncations) impl_->sleigh->truncateSpace(t);
    impl_->printer = std::make_unique<detail::GhidraText>(*impl_->sleigh);
    ghidra::DocumentStorage spec;
    ghidra::Element *proot = spec.openDocument(pspec)->getRoot();
    for (const ghidra::Element *child : proot->getChildren()) {
      if (child->getName() != "context_data") continue;
      ghidra::XmlDecode decoder(impl_->sleigh.get(), child);
      impl_->context->decodeFromSpec(decoder);
    }
    impl_->sleigh->allowContextSet(false);
  } catch (const ghidra::LowlevelError &e) {
    throw LiftError("loading SLEIGH spec for " + language + ": " + e.explain);
  } catch (const ghidra::DecoderError &e) {
    throw LiftError("loading SLEIGH spec for " + language + ": " + e.explain);
  }
  impl_->defaults = impl_->context->defaults(ghidra::Address(impl_->sleigh->getDefaultCodeSpace(), 0));
  impl_->context->set_fixed(impl_->defaults);
}

SleighDecoder::~SleighDecoder() = default;

const std::string &SleighDecoder::language() const { return impl_->language; }
const ghidra::SleighBase &SleighDecoder::sleigh() const { return *impl_->sleigh; }
bool SleighDecoder::big_endian() const { return impl_->sleigh->isBigEndian(); }
unsigned SleighDecoder::alignment() const { return static_cast<unsigned>(impl_->sleigh->getAlignment()); }
unsigned SleighDecoder::word_size() const {
  return static_cast<unsigned>(impl_->sleigh->getDefaultCodeSpace()->getWordSize());
}
unsigned SleighDecoder::address_size() const {
  return static_cast<unsigned>(impl_->sleigh->getDefaultCodeSpace()->getAddrSize());
}
const std::vector<std::uint32_t> &SleighDecoder::default_context() const { return impl_->defaults; }

std::vector<ContextVariable> SleighDecoder::context_variables() const {
  std::vector<ContextVariable> out;
  for (const auto &[name, v] : impl_->context->vars()) out.push_back(v);
  return out;
}

std::optional<ContextVariable> SleighDecoder::context_variable(const std::string &name) const {
  auto it = impl_->context->vars().find(name);
  if (it == impl_->context->vars().end()) return std::nullopt;
  return it->second;
}

bool SleighDecoder::set_context(std::vector<std::uint32_t> &words, const std::string &name,
                                std::uint32_t value) const {
  auto v = context_variable(name);
  if (!v) return false;
  if (words.size() <= static_cast<std::size_t>(v->word)) words.resize(v->word + 1, 0);
  words[v->word] = (words[v->word] & ~(v->mask << v->shift)) | ((value & v->mask) << v->shift);
  return true;
}

std::optional<std::uint32_t> SleighDecoder::get_context(std::span<const std::uint32_t> words,
                                                        const std::string &name) const {
  auto v = context_variable(name);
  if (!v || static_cast<std::size_t>(v->word) >= words.size()) return std::nullopt;
  return (words[v->word] >> v->shift) & v->mask;
}

std::optional<SleighDecoder::Decoded> SleighDecoder::decode(std::uint64_t address, std::span<const std::byte> bytes,
                                                            std::span<const std::uint32_t> context,
                                                            bool in_delay_slot) {
  Engine &sleigh = *impl_->sleigh;
  ghidra::AddrSpace *code = sleigh.getDefaultCodeSpace();
  if (bytes.empty() || address > code->getHighest()) return std::nullopt;
  if (bytes.size() - 1 > code->getHighest() - address) bytes = bytes.first(code->getHighest() - address + 1);
  const ghidra::Address addr(code, address);
  constexpr std::size_t kMaxParseSpan = 64;
  auto forget = [&] {
    for (std::uint64_t i = 0; i < kMaxParseSpan && i <= code->getHighest() - address; ++i)
      sleigh.forget(ghidra::Address(code, address + i));
  };
  forget();
  impl_->image.set(address, bytes);
  impl_->context->set_fixed(context);
  struct Reset {
    Impl &impl;
    std::function<void()> forget;
    ~Reset() {
      impl.image.set(0, {});
      forget();
    }
  } reset{*impl_, forget};

  Decoded out;
  Instruction &insn = out.insn;
  insn.address = address;
  try {
    Collector assembly;
    insn.length = static_cast<std::uint32_t>(sleigh.printAssembly(assembly, addr));
    insn.mnemonic = assembly.mnemonic;
    insn.text = assembly.operands.empty() ? assembly.mnemonic : assembly.mnemonic + " " + assembly.operands;
  } catch (const ghidra::LowlevelError &) {
    return std::nullopt;
  }
  if (insn.length == 0) return std::nullopt;
  if (in_delay_slot) insn.mnemonic = "_" + insn.mnemonic;
  try {
    ghidra::ParserContext *pos = sleigh.at(addr, ghidra::ParserContext::pcode);
    insn.tokens = impl_->printer->tokens(*pos, insn.mnemonic);
    insn.text.clear();
    for (const Token &t : insn.tokens) insn.text += t.text;
    ghidra::ParserWalker w(pos);
    w.baseState();
    walk(w, out.tree);
  } catch (const ghidra::LowlevelError &) {
    insn.tokens.clear();
    if (in_delay_slot) insn.text = "_" + insn.text;
    try {
      ghidra::ParserContext *pos = sleigh.at(addr, ghidra::ParserContext::disassembly);
      ghidra::ParserWalker w(pos);
      w.baseState();
      walk(w, out.tree);
    } catch (const ghidra::LowlevelError &) {
      return std::nullopt;
    }
  }
  return out;
}

std::optional<FidInstruction> SleighDecoder::fid(std::uint64_t address, std::span<const std::byte> bytes,
                                                 std::span<const std::uint32_t> context) {
  Engine &sleigh = *impl_->sleigh;
  ghidra::AddrSpace *code = sleigh.getDefaultCodeSpace();
  if (bytes.empty() || address > code->getHighest()) return std::nullopt;
  if (bytes.size() - 1 > code->getHighest() - address) bytes = bytes.first(code->getHighest() - address + 1);
  const ghidra::Address addr(code, address);
  constexpr std::size_t kMaxParseSpan = 64;
  auto forget = [&] {
    for (std::uint64_t i = 0; i < kMaxParseSpan && i <= code->getHighest() - address; ++i)
      sleigh.forget(ghidra::Address(code, address + i));
  };
  forget();
  impl_->image.set(address, bytes);
  impl_->context->set_fixed(context);
  struct Reset {
    Impl &impl;
    std::function<void()> forget;
    ~Reset() {
      impl.image.set(0, {});
      forget();
    }
  } reset{*impl_, forget};
  FidInstruction out;
  try {
    Collector assembly;
    if (sleigh.printAssembly(assembly, addr) <= 0) return std::nullopt;
    ghidra::ParserContext *pos = sleigh.at(addr, ghidra::ParserContext::pcode);
    impl_->printer->fid(*pos, out);
  } catch (const ghidra::LowlevelError &) {
    return std::nullopt;
  }
  if (out.length == 0) return std::nullopt;
  return out;
}

}  // namespace revkit::lift
