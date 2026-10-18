#include "revkit/lift/image_arch.hh"

#include "revkit/lift/context.hh"
#include "revkit/lift/functions.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/ghidra_loadimage.hh"

#include "funcdata.hh"
#include "spec_xml.hh"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>
#include <tuple>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sstream>

namespace revkit::lift {

namespace {

// SLEIGH over the image, where bytes that can't be read make a bad
// instruction. Ghidra's Java side answers a p-code request it can't satisfy
// (no memory, EXTERNAL block) with nothing, which the decompiler treats as
// bad data; the stock C++ path would abandon the whole function instead.
// The context database. SLEIGH's ContextCache keeps the last region it
// read and trusts it until a context is set through it; regions painted
// later (a Thumb function's TMode, set_context_region) go to the database
// directly. Reporting each address as a region of its own keeps the cache
// from ever covering an address it didn't read: a map lookup per decode.
class ImageContext : public ghidra::ContextInternal {
 public:
  const ghidra::uintm *getContext(const ghidra::Address &addr, ghidra::uintb &first, ghidra::uintb &last) const override {
    const ghidra::uintm *c = ghidra::ContextInternal::getContext(addr, first, last);
    first = last = addr.getOffset();
    return c;
  }
  // Beside the language's variables, one over each whole word of the
  // context, so a region can be set back to what it was at once
  // (ImageArchitecture::reset_context).
  void registerVariable(const std::string &nm, ghidra::int4 sbit, ghidra::int4 ebit) override {
    ghidra::ContextInternal::registerVariable(nm, sbit, ebit);
    constexpr ghidra::int4 kBits = 8 * sizeof(ghidra::uintm);
    for (; words_ <= sbit / kBits; ++words_)
      ghidra::ContextInternal::registerVariable(word_name(words_), words_ * kBits, words_ * kBits + kBits - 1);
  }
  int words() const { return words_; }
  static std::string word_name(int k) { return "\x01word" + std::to_string(k); }
  // Whether one context holds over the whole of `space` (nothing set a
  // part of it apart).
  bool uniform(ghidra::AddrSpace *space) const {
    ghidra::uintb first = 0, last = 0;
    ghidra::ContextInternal::getContext(ghidra::Address(space, 0), first, last);
    return first == 0 && last == space->getHighest();
  }

 private:
  int words_ = 0;
};

class ImageSleigh : public ghidra::Sleigh {
 public:
  // `init_lock` is the global lock init_image() holds while this is built.
  ImageSleigh(ghidra::LoadImage *loader, ghidra::ContextDatabase *context,
              std::unique_lock<std::shared_mutex> *const *init_lock)
      : ghidra::Sleigh(loader, context), init_lock_(init_lock) {}

  // Decoding the .sla file is most of an architecture's setup and touches
  // no global state, so other threads may use Ghidra meanwhile.
  void initialize(ghidra::DocumentStorage &store) override {
    std::unique_lock<std::shared_mutex> *lock = init_lock_ != nullptr ? *init_lock_ : nullptr;
    if (lock == nullptr || !lock->owns_lock()) {
      ghidra::Sleigh::initialize(store);
      return;
    }
    lock->unlock();
    struct Relock {
      std::unique_lock<std::shared_mutex> *lock;
      ~Relock() { lock->lock(); }
    } relock{lock};
    ghidra::Sleigh::initialize(store);
  }

  ghidra::int4 oneInstruction(ghidra::PcodeEmit &emit, const ghidra::Address &baseaddr) const override {
    try {
      // Where a fallthrough override leaves no instruction (Ghidra's
      // decompiler finds none in the listing there): flow stops.
      if (!stops_.empty() && stops_.contains(baseaddr.getOffset()))
        throw ghidra::BadDataError("no instruction after a fallthrough override");
      const auto fall = falls_.empty() ? falls_.end() : falls_.find(baseaddr.getOffset());
      std::optional<FallthroughEmit> fallthrough;
      if (fall != falls_.end()) fallthrough.emplace(emit, baseaddr, fall->second);
      ghidra::PcodeEmit &out = fallthrough ? static_cast<ghidra::PcodeEmit &>(*fallthrough) : emit;
      ghidra::int4 length;
      auto it = overrides_.empty() ? overrides_.end() : overrides_.find(baseaddr.getOffset());
      if (it != overrides_.end()) {
        OverrideEmit rewrite(out, it->second);
        length = ghidra::Sleigh::oneInstruction(rewrite, baseaddr);
      } else {
        length = ghidra::Sleigh::oneInstruction(out, baseaddr);
      }
      if (fallthrough) fallthrough->finish(baseaddr.getOffset() + static_cast<std::uint64_t>(length));
      return length;
    } catch (const ghidra::DataUnavailError &e) {
      throw ghidra::BadDataError(e.explain);
    }
  }

  std::map<std::uint64_t, std::uint32_t> overrides_;
  std::map<std::uint64_t, std::uint64_t> falls_;
  std::set<std::uint64_t> stops_;

 private:
  // Passes p-code on, changing the instruction's computed jump as a flow
  // override says.
  class OverrideEmit : public ghidra::PcodeEmit {
   public:
    OverrideEmit(ghidra::PcodeEmit &to, std::uint32_t kind) : to_(to), kind_(kind) {}
    void dump(const ghidra::Address &addr, ghidra::OpCode opc, ghidra::VarnodeData *outvar, ghidra::VarnodeData *vars,
              ghidra::int4 isize) override {
      // A call that doesn't return: the call, then a RETURN.
      if ((opc == ghidra::CPUI_CALL || opc == ghidra::CPUI_CALLIND) && kind_ == ghidra::Override::CALL_RETURN) {
        to_.dump(addr, opc, outvar, vars, isize);
        dump_return(addr);
        return;
      }
      // A direct jump that is a tail call.
      if (opc == ghidra::CPUI_BRANCH && vars[0].space != addr.getSpace()->getManager()->getConstantSpace() &&
          (kind_ == ghidra::Override::CALL || kind_ == ghidra::Override::CALL_RETURN)) {
        to_.dump(addr, ghidra::CPUI_CALL, outvar, vars, isize);
        if (kind_ == ghidra::Override::CALL_RETURN) dump_return(addr);
        return;
      }
      if (opc == ghidra::CPUI_BRANCHIND || (opc == ghidra::CPUI_CALLIND && kind_ == ghidra::Override::RETURN)) {
        if (kind_ == ghidra::Override::RETURN) {
          to_.dump(addr, ghidra::CPUI_RETURN, outvar, vars, isize);
          return;
        }
        if (kind_ == ghidra::Override::CALL || kind_ == ghidra::Override::CALL_RETURN) {
          to_.dump(addr, ghidra::CPUI_CALLIND, outvar, vars, isize);
          if (kind_ == ghidra::Override::CALL_RETURN) dump_return(addr);
          return;
        }
      }
      to_.dump(addr, opc, outvar, vars, isize);
    }

   private:
    void dump_return(const ghidra::Address &addr) {
      ghidra::VarnodeData zero;
      zero.space = addr.getSpace()->getManager()->getConstantSpace();
      zero.offset = 0;
      zero.size = 1;
      to_.dump(addr, ghidra::CPUI_RETURN, nullptr, &zero, 1);
    }

    ghidra::PcodeEmit &to_;
    std::uint32_t kind_;
  };

  // Holds an instruction's p-code back, then passes it on with its
  // fallthrough going to the override's address, as Ghidra's PcodeEmit
  // applies a fallthrough override: a BRANCH or CBRANCH to the next
  // instruction goes there instead, and a BRANCH there ends the p-code (so
  // the last op, or a relative branch past it, doesn't fall through).
  class FallthroughEmit : public ghidra::PcodeEmit {
   public:
    FallthroughEmit(ghidra::PcodeEmit &to, const ghidra::Address &at, std::uint64_t target)
        : to_(to), at_(at), target_(target) {}
    void dump(const ghidra::Address &addr, ghidra::OpCode opc, ghidra::VarnodeData *outvar, ghidra::VarnodeData *vars,
              ghidra::int4 isize) override {
      Op op{addr, opc, outvar != nullptr, outvar != nullptr ? *outvar : ghidra::VarnodeData{}, {}};
      op.in.assign(vars, vars + isize);
      ops_.push_back(std::move(op));
    }
    // `next`: where the instruction (and its delay slots) ends.
    void finish(std::uint64_t next) {
      ghidra::AddrSpace *code = at_.getSpace();
      for (Op &op : ops_) {
        if ((op.opc == ghidra::CPUI_BRANCH || op.opc == ghidra::CPUI_CBRANCH) && !op.in.empty() &&
            op.in[0].space == code && op.in[0].offset == next)
          op.in[0].offset = target_;
        to_.dump(op.addr, op.opc, op.has_out ? &op.out : nullptr, op.in.data(), static_cast<ghidra::int4>(op.in.size()));
      }
      ghidra::VarnodeData dest;
      dest.space = code;
      dest.offset = target_;
      dest.size = static_cast<ghidra::uint4>(code->getAddrSize());
      to_.dump(at_, ghidra::CPUI_BRANCH, nullptr, &dest, 1);
    }

   private:
    struct Op {
      ghidra::Address addr;
      ghidra::OpCode opc;
      bool has_out;
      ghidra::VarnodeData out;
      std::vector<ghidra::VarnodeData> in;
    };
    ghidra::PcodeEmit &to_;
    ghidra::Address at_;
    std::uint64_t target_;
    std::vector<Op> ops_;
  };

 public:

  // Ghidra's Java side names storage only after a register that starts
  // there (RegisterManager.getRegister(addr, size): the smallest one at
  // least that big; for big-endian, ending there); SLEIGH's own lookup also
  // accepts a register that merely contains it. So the upper half of RSI is
  // "in_register_00000034", not "in_RSI".
  std::string getRegisterName(ghidra::AddrSpace *base, ghidra::uintb off, ghidra::int4 size) const override {
    if (java_names_.empty()) {
      std::map<ghidra::VarnodeData, std::string> regs;
      getAllRegisters(regs);
      std::vector<std::pair<ghidra::VarnodeData, std::string>> bysize(regs.begin(), regs.end());
      std::stable_sort(bysize.begin(), bysize.end(),
                       [](const auto &a, const auto &b) { return a.first.size > b.first.size; });
      for (const auto &[v, name] : bysize) {
        for (ghidra::uint4 i = 1; i <= v.size; ++i) {
          ghidra::uintb at = v.space->isBigEndian() ? v.offset + (v.size - i) : v.offset;
          java_names_[{v.space, at, static_cast<ghidra::int4>(i)}] = name;  // smaller registers win
        }
      }
      if (java_names_.empty()) java_names_[{nullptr, 0, 0}] = "";
    }
    auto it = java_names_.find({base, off, size});
    return it == java_names_.end() ? std::string() : it->second;
  }

  // Java's register name map also holds each name in lower and in upper
  // case (RegisterBuilder.addRegisterToNameMap), and compiler specs rely on
  // it: V850.cspec names "ctbp", which the language defines as CTBP.
  const ghidra::VarnodeData &getRegister(const std::string &nm) const override {
    try {
      return ghidra::Sleigh::getRegister(nm);
    } catch (const ghidra::SleighError &) {
      if (case_names_.empty()) {
        std::map<ghidra::VarnodeData, std::string> regs;
        getAllRegisters(regs);
        for (const auto &[v, name] : regs) {
          std::string lower = name, upper = name;
          for (char &c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          for (char &c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
          case_names_.emplace(std::move(lower), v);
          case_names_.emplace(std::move(upper), v);
        }
        if (case_names_.empty()) case_names_.emplace(std::string(), ghidra::VarnodeData{});
      }
      auto it = nm.empty() ? case_names_.end() : case_names_.find(nm);
      if (it == case_names_.end()) throw;
      return it->second;
    }
  }

  // RegisterManager.getRegister(addr): some register starts here.
  bool register_starts_at(ghidra::AddrSpace *base, ghidra::uintb off) const {
    if (starts_.empty()) {
      std::map<ghidra::VarnodeData, std::string> regs;
      getAllRegisters(regs);
      for (const auto &[v, name] : regs) starts_.insert({v.space, v.offset});
      if (starts_.empty()) starts_.insert({nullptr, 0});
    }
    return starts_.contains({base, off});
  }

  // Points every slot of the disassembly cache at a placeholder address in
  // the constant space (nothing decodes there), so each real address is
  // decoded afresh. obtainContext with the uninitialized state only
  // claims the slot; it reads no bytes.
  void flush_cache() const {
    ghidra::AddrSpace *cs = getConstantSpace();
    for (ghidra::uintb i = 0; i < 512; ++i) obtainContext(ghidra::Address(cs, i), ghidra::ParserContext::uninitialized);
  }

  ghidra::int4 instructionLength(const ghidra::Address &baseaddr) const override {
    try {
      return ghidra::Sleigh::instructionLength(baseaddr);
    } catch (const ghidra::DataUnavailError &e) {
      throw ghidra::BadDataError(e.explain);
    }
  }

 private:
  std::unique_lock<std::shared_mutex> *const *init_lock_;
  mutable std::map<std::tuple<ghidra::AddrSpace *, ghidra::uintb, ghidra::int4>, std::string> java_names_;
  mutable std::set<std::pair<ghidra::AddrSpace *, ghidra::uintb>> starts_;
  mutable std::map<std::string, ghidra::VarnodeData> case_names_;
};

// The image's bytes with patches laid over them, and read-only ranges that
// can be given explicitly.
class ImageLoadImage : public loader::GhidraLoadImage {
 public:
  ImageLoadImage(std::shared_ptr<const loader::Image> image, std::string arch_type, const ArchitectureOptions &options)
      : loader::GhidraLoadImage(std::move(image), std::move(arch_type)), options_(options) {
    for (const auto &[addr, bytes] : options_.patches)
      if (!bytes.empty()) patches_.push_back({addr, &bytes});
    if (options_.shared_patches)
      for (const auto &[addr, bytes] : *options_.shared_patches)
        if (!bytes.empty()) patches_.push_back({addr, &bytes});
    std::sort(patches_.begin(), patches_.end(), [](const Patch &a, const Patch &b) { return a.addr < b.addr; });
    for (const Patch &p : patches_) longest_ = std::max<std::uint64_t>(longest_, p.bytes->size());
  }

  void attach_space(ghidra::AddrSpace *s) {
    space_ = s;
    attach(s);
  }

  void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const ghidra::Address &addr) override {
    if (options_.memory && size > 0) {
      const std::optional<std::uint64_t> key = key_of(addr);
      if (!key) {
        std::fill(ptr, ptr + size, ghidra::uint1{0});
        throw ghidra::DataUnavailError("no data in space " + addr.getSpace()->getName());
      }
      if (options_.memory->read(*key, std::span<std::uint8_t>(ptr, static_cast<std::size_t>(size))) == 0) {
        std::ostringstream s;
        s << "unable to load " << size << " bytes at ";
        addr.printRaw(s);
        throw ghidra::DataUnavailError(s.str());
      }
      return;
    }
    if (patches_.empty() || size <= 0) {
      loader::GhidraLoadImage::loadFill(ptr, size, addr);
      return;
    }
    bool mapped = true;
    try {
      loader::GhidraLoadImage::loadFill(ptr, size, addr);
    } catch (const ghidra::DataUnavailError &) {
      if (!key_of(addr)) throw;
      std::fill(ptr, ptr + size, ghidra::uint1{0});
      mapped = false;
    }
    const std::uint64_t first = *key_of(addr);
    const std::uint64_t end = first + static_cast<std::uint64_t>(size);
    // Patches starting before `first` can still overlap it.
    const std::uint64_t from = first >= longest_ ? first - longest_ : 0;
    auto it = std::lower_bound(patches_.begin(), patches_.end(), from,
                               [](const Patch &p, std::uint64_t a) { return p.addr < a; });
    for (; it != patches_.end() && it->addr < end; ++it) {
      for (std::size_t i = 0; i < it->bytes->size(); ++i) {
        const std::uint64_t a = it->addr + i;
        if (a >= first && a < end) {
          ptr[a - first] = (*it->bytes)[i];
          mapped = true;
        }
      }
    }
    if (!mapped) loader::GhidraLoadImage::loadFill(ptr, size, addr);  // rethrows DataUnavailError
  }

  void getReadonly(ghidra::RangeList &list) const override {
    if (!options_.readonly) {
      loader::GhidraLoadImage::getReadonly(list);
      return;
    }
    if (space_ == nullptr) return;
    for (const auto &[first, last] : *options_.readonly) {
      const ghidra::Address at = address_of(first);
      if (first > last || at.isInvalid()) continue;
      const std::uint64_t end = at.getOffset() + (last - first);
      if (end >= at.getOffset() && end <= at.getSpace()->getHighest()) list.insertRange(at.getSpace(), at.getOffset(), end);
    }
  }

 private:
  struct Patch {
    std::uint64_t addr;
    const std::vector<std::uint8_t> *bytes;
  };
  const ArchitectureOptions &options_;
  std::vector<Patch> patches_;
  std::uint64_t longest_ = 0;
  ghidra::AddrSpace *space_ = nullptr;
};

// Appends code point `cp` as UTF-8.
void put_utf8(std::vector<ghidra::uint1> &out, std::uint32_t cp) {
  if (cp < 0x80) {
    out.push_back(static_cast<ghidra::uint1>(cp));
  } else if (cp < 0x800) {
    out.push_back(static_cast<ghidra::uint1>(0xc0 | (cp >> 6)));
    out.push_back(static_cast<ghidra::uint1>(0x80 | (cp & 0x3f)));
  } else if (cp < 0x10000) {
    out.push_back(static_cast<ghidra::uint1>(0xe0 | (cp >> 12)));
    out.push_back(static_cast<ghidra::uint1>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<ghidra::uint1>(0x80 | (cp & 0x3f)));
  } else {
    out.push_back(static_cast<ghidra::uint1>(0xf0 | (cp >> 18)));
    out.push_back(static_cast<ghidra::uint1>(0x80 | ((cp >> 12) & 0x3f)));
    out.push_back(static_cast<ghidra::uint1>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<ghidra::uint1>(0x80 | (cp & 0x3f)));
  }
}

std::string hex_name(const char *prefix, std::uint64_t addr) {
  char buf[48];
  std::snprintf(buf, sizeof buf, "%s%08llx", prefix, static_cast<unsigned long long>(addr));
  return buf;
}

}  // namespace

// DecompileCallback.getStringData: a defined string's own value if the
// address is in one, else the bytes decoded as Ghidra's terminated string
// types do (US-ASCII for 1-byte characters, UTF-16 and UTF-32 otherwise),
// rejected if any character doesn't decode or there is no terminator
// within the limit.
const std::vector<ghidra::uint1> &JavaStringManager::getStringData(const ghidra::Address &addr, ghidra::Datatype *charType,
                                                                   bool &isTrunc) {
  if (auto it = stringMap.find(addr); it != stringMap.end()) {
    isTrunc = it->second.isTruncated;
    return it->second.byteData;
  }
  StringData &data = stringMap[addr];
  data.isTruncated = false;
  isTrunc = false;
  std::vector<std::uint32_t> chars;
  bool ok = false;
  if (defined_) {
    if (std::optional<std::string> v = defined_(addr)) {
      // UTF-8 back to code points (Java counts UTF-16 units; close enough).
      const std::string &t = *v;
      for (std::size_t i = 0; i < t.size();) {
        auto c = static_cast<unsigned char>(t[i]);
        int n = c < 0x80 ? 1 : c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
        std::uint32_t cp = n == 1 ? c : n == 2 ? c & 0x1f : n == 3 ? c & 0x0f : c & 0x07;
        for (int k = 1; k < n && i + k < t.size(); ++k) cp = (cp << 6) | (static_cast<unsigned char>(t[i + k]) & 0x3f);
        chars.push_back(cp);
        i += static_cast<std::size_t>(n);
      }
      ok = true;
    }
  }
  if (!ok && charType != nullptr && !charType->isOpaqueString()) {
    const int cs = charType->getSize();
    if (cs == 1 || cs == 2 || cs == 4) {
      std::vector<ghidra::uint1> buf(static_cast<std::size_t>(cs));
      const bool big = addr.isBigEndian();
      bool terminated = false;
      bool valid = true;
      std::uint32_t pending_high = 0;
      try {
        for (int n = 0; n <= maximumChars; ++n) {
          glb_->loader->loadFill(buf.data(), cs, addr + static_cast<ghidra::uintb>(n) * cs);
          std::uint32_t v = 0;
          for (int k = 0; k < cs; ++k) v |= static_cast<std::uint32_t>(buf[big ? cs - 1 - k : k]) << (8 * k);
          if (v == 0) {
            terminated = true;
            break;
          }
          if (cs == 1) {
            if (v >= 0x80) valid = false;  // not US-ASCII
            chars.push_back(v);
          } else if (cs == 2) {
            if (v >= 0xd800 && v < 0xdc00) {
              if (pending_high != 0) valid = false;
              pending_high = v;
              continue;
            }
            if (v >= 0xdc00 && v < 0xe000) {
              if (pending_high == 0) valid = false;
              else chars.push_back(0x10000 + ((pending_high - 0xd800) << 10) + (v - 0xdc00));
              pending_high = 0;
              continue;
            }
            if (pending_high != 0) valid = false;
            chars.push_back(v);
          } else {
            if (v > 0x10ffff || (v >= 0xd800 && v < 0xe000)) valid = false;
            chars.push_back(v);
          }
          if (!valid) break;
        }
      } catch (const ghidra::DataUnavailError &) {
        terminated = false;
      }
      ok = terminated && valid && pending_high == 0 && static_cast<int>(chars.size()) <= maximumChars;
    }
  }
  // isValidChars: a replacement character means something didn't decode.
  if (ok && std::find(chars.begin(), chars.end(), 0xfffdu) != chars.end()) ok = false;
  if (!ok) {
    isTrunc = false;
    return data.byteData;  // empty: not a string
  }
  if (static_cast<int>(chars.size()) > maximumChars) {
    chars.resize(static_cast<std::size_t>(maximumChars));
    data.isTruncated = true;
  }
  for (std::uint32_t c : chars) put_utf8(data.byteData, c);
  data.byteData.push_back(0);  // DecompileProcess adds a terminator
  isTrunc = data.isTruncated;
  return data.byteData;
}

ImageArchitecture::ImageArchitecture(std::shared_ptr<const loader::Image> image, const std::string &name,
                                     const std::string &language_id, std::ostream *errors,
                                     ArchitectureOptions options)
    : ghidra::SleighArchitecture(name, language_id, errors),
      image_(std::move(image)),
      language_id_(language_id),
      options_(std::move(options)) {}

ImageArchitecture::~ImageArchitecture() {
  // If init() threw after buildTranslator(), Architecture::restoreFromSpec
  // already deleted the translator through its own unique_ptr.
  if (translator && translate != translator.get()) (void)translator.release();
}

void ImageArchitecture::init_image() {
  {
    auto globals = lock_ghidra_globals();
    init_lock_ = &globals;
    try {
      init(store_);
    } catch (...) {
      init_lock_ = nullptr;
      throw;
    }
    init_lock_ = nullptr;
  }
  if (options_.image_symbols) add_image_symbols();
  else add_image_context();
}

ImageScope &ImageArchitecture::global_scope() const {
  return *static_cast<ImageScope *>(symboltab->getGlobalScope());
}

void ImageArchitecture::buildLoader(ghidra::DocumentStorage &) {
  collectSpecFiles(*errorstream);
  // Architecture owns `loader` and deletes it in its destructor.
  loader = new ImageLoadImage(image_, language_id_, options_);
}

ghidra::Translate *ImageArchitecture::buildTranslator(ghidra::DocumentStorage &) {
  // Never SleighArchitecture's shared static instance; see the class comment.
  // The static map stays empty, so isTranslateReused() is false and the .sla
  // file is loaded for every instance.
  translator = std::make_unique<ImageSleigh>(loader, context, &init_lock_);
  return translator.get();
}

void ImageArchitecture::buildTypegrp(ghidra::DocumentStorage &) { types = new ImageTypeFactory(this); }

void ImageArchitecture::buildStringManager(ghidra::DocumentStorage &store) {
  if (!options_.java_strings) {
    ghidra::SleighArchitecture::buildStringManager(store);
    return;
  }
  stringManager = new JavaStringManager(this, 2048);
}

bool ImageArchitecture::register_starts_at(const ghidra::Address &addr) const {
  return static_cast<const ImageSleigh *>(translator.get())->register_starts_at(addr.getSpace(), addr.getOffset());
}

JavaStringManager *ImageArchitecture::java_strings() const { return dynamic_cast<JavaStringManager *>(stringManager); }

ImageTypeFactory &ImageArchitecture::type_factory() const { return *static_cast<ImageTypeFactory *>(types); }

ghidra::Datatype *ImageTypeFactory::findById(const std::string &n, ghidra::uint8 id, ghidra::int4 sz) {
  ghidra::Datatype *ct = ghidra::TypeFactory::findById(n, id, sz);
  if (ct != nullptr || !resolver_ || id == 0) return ct;
  // A type can be asked for again while it is being decoded (a typedef of a
  // structure whose fields point back to the typedef); structures add
  // themselves before their fields, so that terminates. Bound pathological
  // inputs anyway.
  if (depth_ >= 64) return nullptr;
  ++depth_;
  try {
    ct = resolver_(n, id);
  } catch (...) {
    --depth_;
    throw;
  }
  --depth_;
  return ct;
}

void ImageTypeFactory::java_long_size(long cspec_long_size) {
  if (cspec_long_size != 4) return;
  // TypeFactory::setupSizes' default for a "long" nobody declared.
  const int size = getSizeOfInt() == 4 ? 8 : getSizeOfInt();
  ghidra::Element org(nullptr);
  org.setName("data_organization");
  auto *el = new ghidra::Element(&org);
  el->setName("long_size");
  el->addAttribute("value", std::to_string(size));
  org.addChild(el);
  ghidra::XmlDecode decoder(glb, &org);
  decodeDataOrganization(decoder);
}

ghidra::Scope *ImageArchitecture::buildDatabase(ghidra::DocumentStorage &) {
  symboltab = new ghidra::Database(this, true);
  ghidra::Scope *global = new ImageScope(this);
  symboltab->attachScope(global, nullptr);
  return global;
}

void ImageArchitecture::buildCoreTypes(ghidra::DocumentStorage &store) {
  if (store.getTag("coretypes") != nullptr) {
    ghidra::SleighArchitecture::buildCoreTypes(store);
    return;
  }
  // PcodeDataTypeManager.generateCoreTypes: one integer type per size, named
  // by the data organization; ids are Ghidra's built-in data type ids.
  // AbstractIntegerDataType.getSignedDataTypes: the type of each size up to
  // 8 is the C type of that size, taken in the order long long, long, short,
  // int, the later one winning: where int has 2 bytes (AVR, MSP430, x86-16)
  // a 2-byte integer is "int" and a 4-byte one "long".
  const ghidra::Element *cspec = store.getTag("compiler_spec");
  const ghidra::Element *org = nullptr;
  if (cspec != nullptr)
    for (const ghidra::Element *el : cspec->getChildren())
      if (el->getName() == "data_organization") org = el;
  const long long_size = spec_xml::org_value(org, "long_size").value_or(4);
  const long short_size = spec_xml::org_value(org, "short_size").value_or(2);
  const long int_size = spec_xml::org_value(org, "integer_size").value_or(4);
  const long long_long_size = spec_xml::org_value(org, "long_long_size").value_or(8);
  const long wchar_size = spec_xml::org_value(org, "wchar_size").value_or(2);
  const long long_double_size = spec_xml::org_value(org, "long_double_size").value_or(8);
  const bool char_signed = spec_xml::org_value(org, "char_type", "signed").value_or(1) != 0;
  type_factory().java_long_size(long_size);

  struct Core {
    const char *name;
    long size;
    const char *meta;
    bool is_char;
    bool utf;
    std::uint64_t id;  // low bits of Ghidra's built-in id
  };
  std::vector<Core> core = {
      {"void", 0, "void", false, false, 0xc9},
      {"undefined1", 1, "unknown", false, false, 0xb4}, {"undefined2", 2, "unknown", false, false, 0xb5},
      {"undefined3", 3, "unknown", false, false, 0xb6}, {"undefined4", 4, "unknown", false, false, 0xb7},
      {"undefined5", 5, "unknown", false, false, 0xb8}, {"undefined6", 6, "unknown", false, false, 0xb9},
      {"undefined7", 7, "unknown", false, false, 0xba}, {"undefined8", 8, "unknown", false, false, 0xbb},
      {"int16", 16, "int", false, false, 0x90}, {"uint16", 16, "uint", false, false, 0xbf},
      {"float2", 2, "float", false, false, 0x86}, {"float", 4, "float", false, false, 0x8a},
      {"double", 8, "float", false, false, 0x82}, {"float16", 16, "float", false, false, 0x85},
      {"bool", 1, "bool", false, false, 0x79},
      {"char", 1, char_signed ? "int" : "uint", true, false, 0x7b},
  };
  struct Named {
    const char *name;
    std::uint64_t id;
  };
  // A size no C type has keeps its fixed-size type (Ghidra's
  // SignedDWordDataType): 4 bytes in Go's specs, whose int and long are 8.
  Named signed_of[8] = {{"sbyte", 0xa9}, {"short", 0xa8}, {"int3", 0x91}, {"sdword", 0xab},
                        {"int5", 0x92},  {"int6", 0x93},  {"int7", 0x94}, {"longlong", 0x9a}};
  Named unsigned_of[8] = {{"byte", 0x7a},  {"ushort", 0xc8}, {"uint3", 0xc0}, {"dword", 0x7f},
                          {"uint5", 0xc1}, {"uint6", 0xc2},  {"uint7", 0xc3}, {"ulonglong", 0xc7}};
  const auto c_type = [&](long size, Named s, Named u) {
    if (size < 1 || size > 8) return;
    signed_of[size - 1] = s;
    unsigned_of[size - 1] = u;
  };
  c_type(long_long_size, {"longlong", 0x9a}, {"ulonglong", 0xc7});
  c_type(long_size, {"long", 0x97}, {"ulong", 0xc6});
  c_type(short_size, {"short", 0xa8}, {"ushort", 0xc8});
  c_type(int_size, {"int", 0x95}, {"uint", 0xc4});
  for (long size = 1; size <= 8; ++size) {
    core.push_back({signed_of[size - 1].name, size, "int", false, false, signed_of[size - 1].id});
    core.push_back({unsigned_of[size - 1].name, size, "uint", false, false, unsigned_of[size - 1].id});
  }
  if (long_double_size == 10) core.push_back({"longdouble", 10, "float", false, false, 0x99});
  else core.push_back({"float10", 10, "float", false, false, 0x84});
  core.push_back({"wchar_t", wchar_size, "int", false, true, 0xcd});
  if (wchar_size != 2) core.push_back({"wchar16", 2, "int", false, true, 0xcb});
  if (wchar_size != 4) core.push_back({"wchar32", 4, "int", false, true, 0xcc});

  ghidra::Element root(nullptr);
  root.setName("coretypes");
  auto add = [&](const std::string &name, long size, const std::string &meta, bool is_char, bool utf,
                 std::uint64_t id) {
    auto *el = new ghidra::Element(&root);
    el->setName("type");
    el->addAttribute("name", name);
    el->addAttribute("size", std::to_string(size));
    el->addAttribute("metatype", meta);
    if (is_char) el->addAttribute("char", "true");
    if (utf) el->addAttribute("utf", "true");
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(id));
    el->addAttribute("id", buf);
    root.addChild(el);
  };
  constexpr std::uint64_t kBuiltin = 0xc000000000000000ULL;
  for (const Core &c : core) add(c.name, c.size, c.meta, c.is_char, c.utf, kBuiltin | c.id);
  add("code", 1, "code", false, false, 0xe000000000000001ULL);
  ghidra::XmlDecode decoder(this, &root);
  types->decodeCoreTypes(decoder);
}

std::string ghidra_offset_text(const ghidra::Address &addr) {
  const ghidra::AddrSpace *spc = addr.getSpace();
  const int ws = spc != nullptr ? spc->getWordSize() : 1;
  const unsigned long long off = static_cast<unsigned long long>(ws > 1 ? addr.getOffset() / ws : addr.getOffset());
  const int digits = spc != nullptr ? std::min(8, std::max(1, 2 * static_cast<int>(spc->getAddrSize()))) : 8;
  char buf[32];
  std::snprintf(buf, sizeof buf, "%0*llx", digits, off);
  return buf;
}

bool ghidra_qualifies_names(const ghidra::AddrSpaceManager &spaces) {
  int memory = 0;
  for (ghidra::int4 i = 0; i < spaces.numSpaces(); ++i) {
    ghidra::AddrSpace *spc = spaces.getSpace(i);
    if (spc == nullptr || spc->getType() != ghidra::IPTR_PROCESSOR || spc->getName() == "register") continue;
    if (dynamic_cast<ghidra::OtherSpace *>(spc) != nullptr) continue;
    ++memory;
  }
  return memory > 1;
}

void ImageArchitecture::nameFunction(const ghidra::Address &addr, std::string &name) const {
  if (addr.getSpace() != nullptr && addr.getSpace()->getWordSize() == 1 && !ghidra_qualifies_names(*this)) {
    name = hex_name("FUN_", addr.getOffset());
    return;
  }
  name = "FUN_" + (ghidra_qualifies_names(*this) ? addr.getSpace()->getName() + "_" : std::string()) +
         ghidra_offset_text(addr);
}

void ImageArchitecture::resolveArchitecture() {
  archid = language_id_;
  ghidra::SleighArchitecture::resolveArchitecture();
}

void ImageArchitecture::postSpecFile() {
  ghidra::Architecture::postSpecFile();
  static_cast<ImageLoadImage *>(loader)->attach_space(getDefaultCodeSpace());
}

void ImageArchitecture::flush_decode_cache() {
  static_cast<const ImageSleigh *>(translator.get())->flush_cache();
}

std::vector<JoinFacts> ImageArchitecture::joins_from(std::uint64_t &offset) const {
  std::vector<JoinFacts> out;
  for (;;) {
    ghidra::JoinRecord *rec = nullptr;
    try {
      rec = findJoin(offset);
    } catch (const ghidra::LowlevelError &) {
      break;
    }
    JoinFacts j;
    for (int i = 0; i < rec->numPieces(); ++i) {
      const ghidra::VarnodeData &v = rec->getPiece(i);
      j.pieces.push_back({v.space->getName(), v.offset, static_cast<int>(v.size)});
    }
    if (rec->isFloatExtension()) j.logical_size = static_cast<int>(rec->getUnified().size);
    out.push_back(std::move(j));
    offset += (rec->getUnified().size + 15) & ~std::uint64_t{15};  // AddrSpaceManager::findAddJoin's rounding
  }
  return out;
}

void ImageArchitecture::add_join(const JoinFacts &join) {
  std::vector<ghidra::VarnodeData> pieces;
  for (const StorageVarnode &p : join.pieces) {
    ghidra::AddrSpace *spc = getSpaceByName(p.space);
    if (spc == nullptr) throw ghidra::LowlevelError("join piece in unknown space " + p.space);
    ghidra::VarnodeData v;
    v.space = spc;
    v.offset = p.offset;
    v.size = static_cast<ghidra::uint4>(p.size);
    pieces.push_back(v);
  }
  findAddJoin(pieces, static_cast<ghidra::uint4>(join.logical_size));
}

void ImageArchitecture::add_image_context() {
  ghidra::AddrSpace *code = getDefaultCodeSpace();
  // The language's context (its processor spec's <context_set>: ARM
  // Cortex's TMode is 1), before the image's is painted over it.
  if (auto *db = dynamic_cast<ImageContext *>(context); db != nullptr && db->uniform(code)) {
    language_context_.emplace();
    for (int k = 0; k < db->words(); ++k)
      language_context_->push_back(
          static_cast<std::uint32_t>(context->getVariable(ImageContext::word_name(k), ghidra::Address(code, 0))));
  }
  image_context_ = options_.context ? *options_.context : image_context(*image_);
  std::stable_sort(image_context_.begin(), image_context_.end(),
                   [](const ContextRegion &a, const ContextRegion &b) { return a.start < b.start; });
  image_context_reach_.clear();
  std::uint64_t reach = 0;
  for (const ContextRegion &c : image_context_) {
    reach = std::max(reach, c.end);
    image_context_reach_.push_back(reach);
    if (c.start > code->getHighest()) continue;
    ghidra::Address end;
    if (c.end <= code->getHighest()) end = ghidra::Address(code, c.end);
    context->setVariableRegion(c.name, ghidra::Address(code, c.start), end, c.value);
  }
}

void ImageArchitecture::set_context_region(const std::string &name, std::uint64_t first, std::uint64_t end,
                                           std::uint32_t value) {
  ghidra::AddrSpace *code = getDefaultCodeSpace();
  if (first > code->getHighest()) return;
  ghidra::Address stop;  // invalid: to the top of the space
  if (end != 0 && end <= code->getHighest()) stop = ghidra::Address(code, end);
  context->setVariableRegion(name, ghidra::Address(code, first), stop, value);
}

void ImageArchitecture::reset_context(std::uint64_t first, std::uint64_t end) {
  ghidra::AddrSpace *code = getDefaultCodeSpace();
  if (!language_context_ || first > code->getHighest() || (end != 0 && end <= first)) return;
  for (std::size_t k = 0; k < language_context_->size(); ++k)
    set_context_region(ImageContext::word_name(static_cast<int>(k)), first, end, (*language_context_)[k]);
  // The image's regions that reach into it, in the order they were painted
  // (by start): those from the first one that ends after `first`.
  const std::uint64_t stop = end == 0 ? ~std::uint64_t{0} : end;  // exclusive, except at the top
  std::size_t i = static_cast<std::size_t>(
      std::upper_bound(image_context_reach_.begin(), image_context_reach_.end(), first) - image_context_reach_.begin());
  for (; i < image_context_.size(); ++i) {
    const ContextRegion &c = image_context_[i];
    if (c.start >= stop) break;
    if (c.end <= first) continue;
    try {
      set_context_region(c.name, std::max(first, c.start), end == 0 ? c.end : std::min(end, c.end), c.value);
    } catch (const ghidra::LowlevelError &) {
      // not a context variable of this language
    }
  }
}

void ImageArchitecture::buildContext(ghidra::DocumentStorage &) { context = new ImageContext(); }

void ImageArchitecture::set_pcode_overrides(std::map<std::uint64_t, std::uint32_t> overrides) {
  if (auto *sleigh = dynamic_cast<const ImageSleigh *>(translate))
    const_cast<ImageSleigh *>(sleigh)->overrides_ = std::move(overrides);
}

void ImageArchitecture::set_fallthroughs(std::map<std::uint64_t, std::uint64_t> falls, std::set<std::uint64_t> stops) {
  if (auto *sleigh = dynamic_cast<const ImageSleigh *>(translate)) {
    const_cast<ImageSleigh *>(sleigh)->falls_ = std::move(falls);
    const_cast<ImageSleigh *>(sleigh)->stops_ = std::move(stops);
  }
}

void ImageArchitecture::add_image_symbols() {
  add_image_context();
  ghidra::AddrSpace *code = getDefaultCodeSpace();
  ghidra::Scope *global = symboltab->getGlobalScope();
  for (const FunctionSymbol &f : function_symbols(*image_)) {
    if (f.entry > code->getHighest()) continue;
    ghidra::Address a(code, f.entry);
    if (global->findFunction(a) == nullptr) global->addFunction(a, f.name);
  }
}

// ---------------------------------------------------------------------------

ImageScope::ImageScope(ghidra::Architecture *arch) : ghidra::ScopeInternal(0, "", arch) {}

void ImageScope::set_resolvers(Resolver symbols, LabelResolver labels, ExternalResolver externals) {
  global_spaces_.assign(static_cast<std::size_t>(glb->numSpaces()), false);
  for (auto it = getRangeTree().begin(); it != getRangeTree().end(); ++it) {
    int index = it->getSpace()->getIndex();
    if (index >= 0 && static_cast<std::size_t>(index) < global_spaces_.size()) global_spaces_[static_cast<std::size_t>(index)] = true;
  }
  resolver_ = std::move(symbols);
  label_resolver_ = std::move(labels);
  external_resolver_ = std::move(externals);
}

ghidra::Symbol *ImageScope::add_mapsym(const ghidra::Element &mapsym, std::string *error) {
  try {
    ghidra::XmlDecode decoder(glb, &mapsym);
    return addMapSym(decoder);
  } catch (const ghidra::LowlevelError &e) {
    if (error) *error = e.explain;
  } catch (const ghidra::DecoderError &e) {
    if (error) *error = e.explain;
  }
  return nullptr;
}

void ImageScope::snapshot_properties() {
  default_properties_ = glb->symboltab->getProperties();
  properties_dirty_ = false;
}

void ImageScope::reset() {
  clear();
  glb->symboltab->deleteSubScopes(this);
  holes_.clear();
  if (properties_dirty_) {
    glb->symboltab->setProperties(default_properties_);
    properties_dirty_ = false;
  }
}

// ScopeGhidra::removeQuery and dump2Cache: ask once per address, remember
// holes, and make the answer's memory properties known.
ghidra::Symbol *ImageScope::query(const ghidra::Address &addr) const {
  if (!resolver_ || busy_) return nullptr;
  // ScopeGhidra only asks about spaces the global scope covers.
  const int index = addr.getSpace()->getIndex();
  if (index < 0 || static_cast<std::size_t>(index) >= global_spaces_.size() || !global_spaces_[static_cast<std::size_t>(index)])
    return nullptr;
  if (holes_.inRange(addr, 1)) return nullptr;
  busy_ = true;
  Hole hole{addr.getOffset(), addr.getOffset(), false, false};
  ghidra::Symbol *sym = nullptr;
  try {
    sym = resolver_(addr, hole);
  } catch (...) {
    busy_ = false;
    throw;
  }
  busy_ = false;
  if (sym == nullptr) {
    holes_.insertRange(addr.getSpace(), hole.first, hole.last);
    ghidra::uint4 flags = (hole.readonly ? ghidra::Varnode::readonly : 0) | (hole.is_volatile ? ghidra::Varnode::volatil : 0);
    if (flags != 0) {
      glb->symboltab->setPropertyRange(flags, ghidra::Range(addr.getSpace(), hole.first, hole.last));
      properties_dirty_ = true;
    }
    return nullptr;
  }
  if (ghidra::SymbolEntry *entry = sym->getFirstWholeMap()) {
    if (sym->getScope() != this) {
      // In a namespace scope, which this cache doesn't search: don't ask again.
      holes_.insertRange(entry->getAddr().getSpace(), entry->getFirst(), entry->getLast());
    }
    ghidra::uint4 props = sym->getFlags() & (ghidra::Varnode::readonly | ghidra::Varnode::volatil);
    if (props != 0) {
      glb->symboltab->setPropertyRange(props, ghidra::Range(entry->getAddr().getSpace(), entry->getFirst(), entry->getLast()));
      properties_dirty_ = true;
    }
  }
  return sym;
}

ghidra::SymbolEntry *ImageScope::findAddr(const ghidra::Address &addr, const ghidra::Address &usepoint) const {
  ghidra::SymbolEntry *entry = ghidra::ScopeInternal::findAddr(addr, usepoint);
  if (entry == nullptr && resolving() && !busy_) {
    if (ghidra::ScopeInternal::findContainer(addr, 1, ghidra::Address()) != nullptr)
      return nullptr;  // queried before, but no symbol starts here
    if (ghidra::Symbol *sym = query(addr)) entry = sym->getMapEntry(addr);
  }
  if (entry != nullptr && entry->getAddr() == addr) return entry;
  return nullptr;
}

ghidra::SymbolEntry *ImageScope::findContainer(const ghidra::Address &addr, ghidra::int4 size,
                                               const ghidra::Address &usepoint) const {
  if (!resolving() || busy_) return ghidra::ScopeInternal::findContainer(addr, size, usepoint);
  ghidra::SymbolEntry *entry = ghidra::ScopeInternal::findClosestFit(addr, size, usepoint);
  if (entry == nullptr)
    if (ghidra::Symbol *sym = query(addr)) entry = sym->getMapEntry(addr);
  if (entry != nullptr) {
    ghidra::uintb last = entry->getAddr().getOffset() + entry->getSize() - 1;
    if (last >= addr.getOffset() + size - 1) return entry;
  }
  return nullptr;
}

ghidra::Funcdata *ImageScope::findFunction(const ghidra::Address &addr) const {
  ghidra::Funcdata *fd = ghidra::ScopeInternal::findFunction(addr);
  if (fd == nullptr && resolving() && !busy_ &&
      ghidra::ScopeInternal::findContainer(addr, 1, ghidra::Address()) == nullptr) {
    if (auto *sym = dynamic_cast<ghidra::FunctionSymbol *>(query(addr))) fd = sym->getFunction();
  }
  return fd;
}

ghidra::ExternRefSymbol *ImageScope::findExternalRef(const ghidra::Address &addr) const {
  ghidra::ExternRefSymbol *sym = ghidra::ScopeInternal::findExternalRef(addr);
  if (sym == nullptr && resolving() && !busy_ &&
      ghidra::ScopeInternal::findContainer(addr, 1, ghidra::Address()) == nullptr)
    sym = dynamic_cast<ghidra::ExternRefSymbol *>(query(addr));
  return sym;
}

ghidra::LabSymbol *ImageScope::findCodeLabel(const ghidra::Address &addr) const {
  ghidra::LabSymbol *sym = ghidra::ScopeInternal::findCodeLabel(addr);
  if (sym == nullptr && label_resolver_ && !busy_ &&
      ghidra::ScopeInternal::findAddr(addr, ghidra::Address()) == nullptr) {
    std::string name = label_resolver_(addr);
    if (!name.empty()) sym = const_cast<ImageScope *>(this)->addCodeLabel(addr, name);
  }
  return sym;
}

ghidra::Funcdata *ImageScope::resolveExternalRefFunction(ghidra::ExternRefSymbol *sym) const {
  ghidra::Funcdata *fd = ghidra::ScopeInternal::resolveExternalRefFunction(sym);
  if (fd == nullptr && external_resolver_ && !busy_) {
    busy_ = true;
    try {
      fd = external_resolver_(sym->getFirstWholeMap()->getAddr());
    } catch (...) {
      busy_ = false;
      throw;
    }
    busy_ = false;
  }
  return fd;
}

}  // namespace revkit::lift
