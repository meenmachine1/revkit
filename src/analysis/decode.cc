// Bytes through the engine, pooled SLEIGH decoders, and p-code reading.

#include "internal.h"

#include "revkit/lift/abi.hh"

#include <algorithm>
#include <map>
#include <mutex>

namespace revkit::analysis::detail {

using namespace std::string_view_literals;

// ---- ByteReader ----

const ByteReader::Page &ByteReader::page(std::uint64_t index) {
  if (last_ != nullptr && last_index_ == index) return *last_;
  auto it = pages_.find(index);
  if (it != pages_.end()) {
    last_index_ = index;
    last_ = &it->second;
    return it->second;
  }
  Page p{ctx_.get<facts::MemoryPage>(facts::PageKey{space_, index})};
  p.data = p.bytes.get();
  // Memory-map regions' bytes (ProgramInfo::sources) laid over the page:
  // zeros, or a file's bytes from the space they are staged in.
  const std::uint64_t first = index * facts::kPageSize, last = first + (facts::kPageSize - 1);
  auto s = std::upper_bound(sources_.begin(), sources_.end(), first,
                            [](std::uint64_t a, const ProgramInfo::SourceRange &b) { return a < b.range.first; });
  if (s != sources_.begin() && std::prev(s)->range.last >= first) --s;
  if (s != sources_.end() && s->range.first <= last) {
    std::string out = *p.bytes;
    out.resize(facts::kPageSize, '\0');
    for (; s != sources_.end() && s->range.first <= last; ++s) {
      const std::uint64_t lo = std::max(first, s->range.first), hi = std::min(last, s->range.last);
      if (s->space == 0) {
        std::fill(out.begin() + static_cast<std::ptrdiff_t>(lo - first),
                  out.begin() + static_cast<std::ptrdiff_t>(hi - first + 1), '\0');
        continue;
      }
      for (std::uint64_t a = lo; a <= hi;) {
        const std::uint64_t at = s->offset + (a - s->range.first);
        auto src = ctx_.get<facts::MemoryPage>(facts::PageKey{s->space, at / facts::kPageSize});
        const std::uint64_t in = at % facts::kPageSize;
        const std::uint64_t take = std::min(hi - a + 1, facts::kPageSize - in);
        for (std::uint64_t i = 0; i < take; ++i)
          out[static_cast<std::size_t>(a - first + i)] =
              in + i < src->size() ? (*src)[static_cast<std::size_t>(in + i)] : '\0';
        a += take;
      }
    }
    p.data = &composed_.emplace(index, std::move(out)).first->second;
  }
  // Patches over unmapped bytes are ignored: no gate to read there. (An
  // added region's bytes are mapped: patches lay over them.)
  if (!p.data->empty()) p.patched = *ctx_.get<facts::PatchedPage>(facts::PageKey{space_, index});
  last_index_ = index;
  last_ = &pages_.emplace(index, std::move(p)).first->second;
  return *last_;
}

const facts::PatchSpan::Value &ByteReader::span(std::uint64_t index) {
  auto it = spans_.find(index);
  if (it == spans_.end()) it = spans_.emplace(index, ctx_.get<facts::PatchSpan>({space_, index})).first;
  return *it->second;
}

std::span<const std::byte> ByteReader::read(std::uint64_t addr, std::size_t n) {
  buf_.clear();
  bool patched = false;
  while (buf_.size() < n) {
    std::uint64_t off = addr + buf_.size();
    if (off < addr) break;  // wrapped
    const Page &p = page(off / facts::kPageSize);
    std::size_t in_page = off % facts::kPageSize;
    if (p.data->size() <= in_page) break;
    patched = patched || p.patched;
    std::size_t take = std::min(n - buf_.size(), p.data->size() - in_page);
    const auto *src = reinterpret_cast<const std::byte *>(p.data->data() + in_page);
    buf_.insert(buf_.end(), src, src + take);
  }
  // A patch over what was read overlaps one of the pages read, whose gate
  // then says so. Without one, no span is read (nor depended on).
  if (!patched) return buf_;
  // The patches over what was read (patches_overlapping, through this
  // reader's spans): those starting up to kMaxPatchBytes - 1 before it.
  const std::uint64_t last = addr + (buf_.size() - 1);
  const std::uint64_t from = addr >= facts::kMaxPatchBytes - 1 ? addr - (facts::kMaxPatchBytes - 1) : 0;
  std::vector<const std::pair<std::string, std::pair<std::uint64_t, std::string>> *> found;
  for (std::uint64_t i = from >> facts::kSpanShift;; ++i) {
    for (const auto &e : span(i)) {
      const std::uint64_t at = e.second.first, end = at + (e.second.second.size() - 1);
      if (end >= addr && at <= last) found.push_back(&e);
    }
    if (i == last >> facts::kSpanShift) break;
  }
  std::sort(found.begin(), found.end(), [](const auto *a, const auto *b) { return a->first < b->first; });
  for (const auto *e : found)
    for (std::size_t i = 0; i < e->second.second.size(); ++i) {
      const std::uint64_t a = e->second.first + i;
      if (a >= addr && a <= last) buf_[a - addr] = static_cast<std::byte>(e->second.second[i]);
    }
  return buf_;
}

std::optional<std::uint64_t> ByteReader::uint(std::uint64_t addr, unsigned size, bool big_endian) {
  if (size == 0 || size > 8) return std::nullopt;
  auto b = read(addr, size);
  if (b.size() != size) return std::nullopt;
  std::uint64_t v = 0;
  for (unsigned i = 0; i < size; ++i) {
    unsigned shift = big_endian ? 8 * (size - 1 - i) : 8 * i;
    v |= std::uint64_t{std::to_integer<std::uint8_t>(b[i])} << shift;
  }
  return v;
}

// ---- Decoder pool ----

namespace {

// Idle SLEIGH engines by language and context. Building one parses the
// .sla (tens of milliseconds), so they are reused across queries; each is
// used by one thread at a time.
class LifterPool {
 public:
  std::unique_ptr<lift::Lifter> take(const std::string &key, const ProgramInfo &info, bool thumb) {
    std::unique_ptr<lift::Lifter> l;
    {
      std::lock_guard lock(mu_);
      auto &idle = idle_[key];
      if (!idle.empty()) {
        l = std::move(idle.back());
        idle.pop_back();
        return l;
      }
      // One built ahead (prepare()), never used: as new.
      if (auto f = fresh_.find(info.language); f != fresh_.end() && !f->second.empty()) {
        l = std::move(f->second.back());
        f->second.pop_back();
      }
    }
    if (!l) l = make(info.language);
    for (const ContextSetting &c : info.context) {
      std::optional<std::uint64_t> end;
      if (c.range.last != ~std::uint64_t{0}) end = c.range.last + 1;
      l->set_context(c.name, c.value, c.range.first, end);
    }
    // Interworking: tagged keys decode as Thumb wherever they are.
    if (thumb) l->set_context(info.isa_context, 1, 0);
    return l;
  }
  // Builds `n` engines for `language` on `threads`, for take() to hand
  // out before it builds any.
  void prepare(const std::string &language, unsigned n, facts::ThreadPool &threads) {
    std::vector<std::unique_ptr<lift::Lifter>> made(n);
    threads.parallel_for(n, [&](std::size_t i) { made[i] = make(language); });
    std::lock_guard lock(mu_);
    auto &fresh = fresh_[language];
    for (auto &l : made) fresh.push_back(std::move(l));
  }
  void clear(facts::ThreadPool *threads) {
    std::map<std::string, std::vector<std::unique_ptr<lift::Lifter>>> gone;
    {
      std::lock_guard lock(mu_);
      gone.swap(idle_);
      for (auto &[language, fresh] : fresh_)
        for (auto &l : fresh) gone[language].push_back(std::move(l));
      fresh_.clear();
    }
    if (threads == nullptr) return;
    std::vector<std::unique_ptr<lift::Lifter>> engines;
    for (auto &[key, idle] : gone)
      for (auto &l : idle) engines.push_back(std::move(l));
    threads->parallel_for(engines.size(), [&](std::size_t i) { engines[i].reset(); });
  }
  void give(const std::string &key, std::unique_ptr<lift::Lifter> l) {
    constexpr std::size_t kMaxIdle = 64;
    std::lock_guard lock(mu_);
    auto &idle = idle_[key];
    if (idle.size() < kMaxIdle) idle.push_back(std::move(l));
  }

 private:
  static std::unique_ptr<lift::Lifter> make(const std::string &language) {
    // The image only supplies symbols, which window decoding never reads.
    static const auto empty = std::make_shared<const loader::Image>();
    return std::make_unique<lift::Lifter>(empty, language);
  }

  std::mutex mu_;
  std::map<std::string, std::vector<std::unique_ptr<lift::Lifter>>> idle_;
  std::map<std::string, std::vector<std::unique_ptr<lift::Lifter>>> fresh_;  // by language, from prepare()
};

LifterPool &pool() {
  static LifterPool *p = new LifterPool;  // never destroyed: engines may outlive static teardown order
  return *p;
}

}  // namespace

void pool_clear(facts::ThreadPool *threads) { pool().clear(threads); }
void pool_prepare(const std::string &language, unsigned n, facts::ThreadPool &threads) {
  pool().prepare(language, n, threads);
}

namespace {
// The Decoders alive on this thread, innermost last.
thread_local std::vector<const Decoder *> t_decoders;
}  // namespace

Decoder::Decoder(const ProgramInfo &info) : info_(info) {
  key_ = info.language;
  for (const ContextSetting &c : info.context)
    key_ += "|" + c.name + "=" + std::to_string(c.value) + "@" + std::to_string(c.range.first) + "-" +
            std::to_string(c.range.last);
  for (auto it = t_decoders.rbegin(); it != t_decoders.rend() && !lifter_; ++it)
    if ((*it)->key_ == key_) lifter_ = (*it)->lifter_;
  if (!lifter_) {
    owned_ = pool().take(key_, info, false);
    lifter_ = owned_.get();
  }
  t_decoders.push_back(this);
}

Decoder::~Decoder() {
  // Innermost first, so normally the last one.
  if (auto it = std::find(t_decoders.rbegin(), t_decoders.rend(), this); it != t_decoders.rend())
    t_decoders.erase(std::next(it).base());
  if (owned_) pool().give(key_, std::move(owned_));
  if (thumb_) pool().give(key_ + "|thumb", std::move(thumb_));
}

bool Decoder::two_instruction_sets() { return analysis::two_instruction_sets(info_); }

std::uint64_t Decoder::step() {
  return std::max(1u, lifter_->alignment());
}

std::optional<lift::Instruction> Decoder::decode(std::uint64_t addr, ByteReader &bytes, bool thumb) {
  lift::Lifter *lifter = lifter_;
  if (thumb && !info_.isa_context.empty()) {
    if (!thumb_) thumb_ = pool().take(key_ + "|thumb", info_, true);
    lifter = thumb_.get();
  }
  // Longer than any instruction plus delay slots on the supported machines.
  constexpr std::size_t kWindow = 32;
  std::size_t n = kWindow;
  auto it = std::upper_bound(info_.code.begin(), info_.code.end(), addr,
                             [](std::uint64_t x, const Range &r) { return x < r.first; });
  if (it == info_.code.begin() || !std::prev(it)->contains(addr)) return std::nullopt;
  std::uint64_t room = std::prev(it)->last - addr;  // bytes after addr in this code range
  if (room < n - 1) n = static_cast<std::size_t>(room) + 1;
  auto window = bytes.read(addr, n);
  if (window.empty()) return std::nullopt;
  std::vector<std::byte> copy(window.begin(), window.end());  // read() reuses its buffer
  std::optional<lift::Instruction> insn = lifter->lift_pcode(addr, copy);  // flow needs lengths and p-code, not text
  if (insn && (info_.spaces.size() > 1 || !info_.register_memory.empty())) key_spaces(*insn, info_);
  return insn;
}

void key_spaces(lift::Instruction &insn, const ProgramInfo &info) {
  auto key = [&](lift::Varnode &v) {
    if (v.space == "const"sv || v.space == "register"sv || v.space == "unique"sv || v.space == "space"sv) return;
    std::optional<std::uint64_t> k = info.space_key(v.space, v.offset);
    if (!k) return;
    v.space = info.code_space;
    v.offset = *k;
    // Registers mapped into memory (AVR's R0-R31) are registers.
    const std::uint64_t last = v.offset + (v.size ? v.size - 1 : 0);
    auto r = std::upper_bound(info.register_memory.begin(), info.register_memory.end(), v.offset,
                              [](std::uint64_t x, const Range &rr) { return x < rr.first; });
    if (r != info.register_memory.begin() && std::prev(r)->contains(v.offset) && std::prev(r)->contains(last))
      v.space = "register";
  };
  for (lift::PcodeOp &op : insn.pcode) {
    if (op.output) key(*op.output);
    for (lift::Varnode &v : op.inputs) key(v);
  }
}

// ---- classify ----

namespace {

// Whether an instruction's CBRANCH to the next instruction is taken, when
// its condition comes from constants the instruction's own p-code writes
// (SPARC's didrestore flag: cleared, then set by a restore in the delay
// slot). nullopt when it isn't settled that way.
std::optional<bool> settled_skip(const lift::Instruction &insn, std::uint64_t next, const std::string &code_space) {
  std::map<std::pair<std::string, std::uint64_t>, std::uint64_t> known;  // (space, offset) -> value
  auto value = [&](const lift::Varnode &v) -> std::optional<std::uint64_t> {
    if (v.space == "const"sv) return v.offset;
    auto it = known.find({v.space, v.offset});
    return it == known.end() ? std::nullopt : std::optional(it->second);
  };
  for (const lift::PcodeOp &op : insn.pcode) {
    const std::string &o = op.opcode;
    if (o == "CBRANCH"sv && op.inputs.size() == 2 && op.inputs[0].space == code_space && op.inputs[0].offset == next) {
      auto c = value(op.inputs[1]);
      if (!c) return std::nullopt;
      return *c != 0;
    }
    if (!op.output) continue;
    std::optional<std::uint64_t> v;
    if (o == "COPY"sv && op.inputs.size() == 1) v = value(op.inputs[0]);
    else if ((o == "INT_EQUAL"sv || o == "INT_NOTEQUAL"sv) && op.inputs.size() == 2) {
      auto a = value(op.inputs[0]), b = value(op.inputs[1]);
      if (a && b) v = (o == "INT_EQUAL"sv) == (*a == *b);
    } else if (o == "BOOL_NEGATE"sv && op.inputs.size() == 1) {
      if (auto a = value(op.inputs[0])) v = *a == 0;
    }
    if (v) known[{op.output->space, op.output->offset}] = *v;
    else known.erase({op.output->space, op.output->offset});
  }
  return std::nullopt;
}

}  // namespace

InsnFlow classify(const lift::Instruction &insn, const std::string &code_space) {
  InsnFlow f;
  if (insn.pcode.empty()) return f;
  bool ret = false, jump_ind = false, call_ind = false, call = false, jump = false, branch = false;
  for (const lift::PcodeOp &op : insn.pcode) {
    const std::string &o = op.opcode;
    const bool direct = !op.inputs.empty() && op.inputs[0].space == code_space;
    if (o == "RETURN"sv) ret = true;
    else if (o == "BRANCHIND"sv) jump_ind = true;
    else if (o == "CALLIND"sv) call_ind = true;
    else if (o == "CALL"sv && direct) {
      call = true;
      f.targets.push_back(op.inputs[0].offset);
    } else if (o == "BRANCH"sv && direct) {
      jump = true;
      f.targets.push_back(op.inputs[0].offset);
    } else if (o == "CBRANCH"sv && direct) {
      branch = true;
      f.targets.push_back(op.inputs[0].offset);
    }
  }
  // Whether control can reach the next instruction: not when the last op
  // transfers control unconditionally. (A BRANCH into the const space is a
  // jump within the instruction's own p-code.) A conditional instruction
  // (ARM's bxne lr, ldrls pc, ...) skips to its end with an internal
  // CBRANCH: then it falls through when the condition fails.
  const lift::PcodeOp &last = insn.pcode.back();
  const bool internal = !last.inputs.empty() && last.inputs[0].space == "const"sv;
  const std::uint64_t next = insn.address + insn.length + insn.delay_slot;
  if ((last.opcode == "BRANCH"sv && !internal) || last.opcode == "BRANCHIND"sv || last.opcode == "RETURN"sv) {
    f.falls_through = false;
    for (std::size_t i = 0; i < insn.pcode.size(); ++i) {
      const lift::PcodeOp &op = insn.pcode[i];
      if (op.opcode != "CBRANCH"sv || op.inputs.empty()) continue;
      if (op.inputs[0].space == code_space) {
        // ARM skips a conditional instruction by branching to the next one.
        if (op.inputs[0].offset == next) f.falls_through = true;
        continue;
      }
      if (op.inputs[0].space != "const"sv) continue;
      const auto rel = static_cast<std::int64_t>(op.inputs[0].offset << (64 - 8 * op.inputs[0].size)) >>
                       (64 - 8 * op.inputs[0].size);
      if (static_cast<std::int64_t>(i) + rel >= static_cast<std::int64_t>(insn.pcode.size())) f.falls_through = true;
    }
  }
  // A conditional branch to the next instruction is the fallthrough, not a
  // target (unless the instruction is a plain conditional branch there).
  if (f.falls_through && (ret || jump_ind || call_ind || jump))
    std::erase(f.targets, next);

  // A call that returns too, but only under a condition the instruction
  // itself settles (SPARC's "call f; if (didrestore == 0) goto next;
  // return [o7]": a call, or with a restore in its delay slot a tail
  // call): a call, falling through unless the condition says return.
  if (ret && call && !jump_ind && !call_ind) {
    if (std::optional<bool> skips = settled_skip(insn, next, code_space)) {
      f.kind = FlowKind::call;
      f.falls_through = *skips;
      f.tail_call = !*skips;
      std::vector<std::uint64_t> callee;
      for (const lift::PcodeOp &op : insn.pcode)
        if (op.opcode == "CALL"sv && !op.inputs.empty() && op.inputs[0].space == code_space)
          callee.push_back(op.inputs[0].offset);
      f.targets = std::move(callee);
      return f;
    }
  }
  if (ret) f.kind = FlowKind::ret;
  else if (jump_ind) f.kind = FlowKind::jump_indirect;
  else if (call_ind) f.kind = FlowKind::call_indirect;
  else if (call) f.kind = FlowKind::call;
  else if (jump && !f.falls_through) f.kind = FlowKind::jump;
  else if (jump || branch) f.kind = FlowKind::branch;
  // Calls are followed by their own logic; keep only the callee.
  if (f.kind == FlowKind::call) {
    std::vector<std::uint64_t> callee;
    for (const lift::PcodeOp &op : insn.pcode)
      if (op.opcode == "CALL"sv && !op.inputs.empty() && op.inputs[0].space == code_space)
        callee.push_back(op.inputs[0].offset);
    f.targets = std::move(callee);
  }
  std::sort(f.targets.begin(), f.targets.end());
  f.targets.erase(std::unique(f.targets.begin(), f.targets.end()), f.targets.end());
  return f;
}

// ---- Evaluator ----

namespace {

std::uint64_t mask(std::uint32_t size) {
  return size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * size)) - 1;
}

std::int64_t sext(std::uint64_t v, std::uint32_t size) {
  if (size >= 8) return static_cast<std::int64_t>(v);
  unsigned bits = 8 * size;
  std::uint64_t m = std::uint64_t{1} << (bits - 1);
  v &= mask(size);
  return static_cast<std::int64_t>((v ^ m) - m);
}

}  // namespace

void Evaluator::clobber_at_call() {
  // The callee may write any memory, and returns with the link register
  // (and the stack it pushed a return address on) as it pleases.
  memory_writes_.clear();
  if (info_->link_register) write(lift::Varnode{"register", info_->link_register->first, info_->link_register->second, {}}, {});
}

Evaluator Evaluator::fork() const {
  Evaluator e(*info_, memory_);
  e.code_only_ = code_only_;
  e.calls_clobber_ = calls_clobber_;
  e.keep_slots_ = keep_slots_;
  e.state_ = state_;
  e.indirect_ = indirect_;
  e.condition_ = condition_;
  e.memory_writes_ = memory_writes_;
  e.next_base_ = next_base_;
  e.incoming_ = incoming_;
  return e;
}

void Evaluator::set_register(std::uint64_t offset, std::uint32_t size, std::optional<std::uint64_t> value) {
  state_[{true, offset}] = Slot{size, value ? Sym::constant(*value & mask(size)) : Sym{}};
}

bool Evaluator::set_memory(const FreeMemory &slot, std::optional<std::uint64_t> value) {
  auto it = state_.find({true, slot.reg});
  if (it == state_.end()) {
    // Not read yet: name its incoming value now, as read() would.
    Sym incoming = Sym::relative(next_base_++, 0);
    incoming_[incoming.base] = slot.reg;
    it = state_.emplace(std::make_pair(true, slot.reg), Slot{info_->pointer_size, incoming}).first;
  }
  if (it->second.value.kind != Sym::Kind::relative && it->second.value.kind != Sym::Kind::constant) {
    // Some unknown pointer: name it, so later reads through it agree.
    it->second.value = Sym::relative(next_base_++, 0);
    incoming_[it->second.value.base] = slot.reg;
  }
  const Sym &r = it->second.value;
  Sym addr = r;
  addr.value += slot.disp;
  store(addr, slot.size, value ? Sym::constant(*value & mask(slot.size)) : Sym{});
  return true;
}

std::optional<std::uint64_t> Evaluator::incoming_register(const Sym &s) const {
  if (s.kind != Sym::Kind::relative || s.value != 0) return std::nullopt;
  auto it = incoming_.find(s.base);
  if (it == incoming_.end()) return std::nullopt;
  return it->second;
}

std::optional<std::uint64_t> Evaluator::register_value(std::uint64_t offset, std::uint32_t size) const {
  auto it = state_.find({true, offset});
  if (it == state_.end() || !it->second.value.known() || it->second.size < size) return std::nullopt;
  return it->second.value.value & mask(size);
}

bool Evaluator::saved(std::uint64_t reg) const {
  for (const auto &[at, slot] : memory_writes_) {
    if (at.first == 0 || slot.value.kind != Sym::Kind::relative || slot.value.value != 0) continue;
    if (auto it = incoming_.find(slot.value.base); it != incoming_.end() && it->second == reg) return true;
  }
  return false;
}

std::optional<std::int64_t> Evaluator::saved_above(std::uint64_t reg, std::uint64_t stack) const {
  auto sp = state_.find({true, stack});
  if (sp == state_.end() || sp->second.value.kind != Sym::Kind::relative) return std::nullopt;
  const Sym &now = sp->second.value;
  for (const auto &[at, slot] : memory_writes_) {
    if (at.first != now.base || slot.value.kind != Sym::Kind::relative || slot.value.value != 0) continue;
    if (auto it = incoming_.find(slot.value.base); it != incoming_.end() && it->second == reg)
      return static_cast<std::int64_t>(at.second - now.value);
  }
  return std::nullopt;
}

std::optional<std::int64_t> Evaluator::moved(std::uint64_t reg) const {
  auto it = state_.find({true, reg});
  if (it == state_.end()) return 0;  // never written: as it came in
  const Sym &v = it->second.value;
  if (v.kind != Sym::Kind::relative) return std::nullopt;
  auto in = incoming_.find(v.base);
  if (in == incoming_.end() || in->second != reg) return std::nullopt;
  return static_cast<std::int64_t>(v.value);
}

bool Evaluator::register_known(std::uint64_t offset, std::uint32_t size) const {
  auto it = state_.find({true, offset});
  return it != state_.end() && it->second.size >= size && it->second.value.known();
}

Sym Evaluator::load(std::uint64_t addr, std::uint32_t size) {
  if (auto it = memory_writes_.find({0, addr}); it != memory_writes_.end())
    return it->second.size == size ? it->second.value : Sym{};
  if (!memory_) return Sym::loaded(addr);
  if (code_only_ && (!info_->is_code(addr) || info_->import_at(addr))) return Sym::loaded(addr);
  if (auto v = memory_->uint(addr, size, info_->big_endian)) {
    loads_.push_back({addr, size});
    return Sym::constant(*v);
  }
  return {};
}

void Evaluator::store(const Sym &addr, std::uint32_t size, Sym value) {
  if (addr.kind == Sym::Kind::constant || addr.kind == Sym::Kind::relative) {
    std::uint32_t base = addr.kind == Sym::Kind::constant ? 0 : addr.base;
    // Overlapping slots of the same base are stale now.
    for (auto it = memory_writes_.lower_bound({base, addr.value > 16 ? addr.value - 16 : 0});
         it != memory_writes_.end() && it->first.first == base && it->first.second < addr.value + size;) {
      std::uint64_t o = it->first.second;
      bool overlaps = o != addr.value && o < addr.value + size && addr.value < o + it->second.size;
      it = overlaps ? memory_writes_.erase(it) : std::next(it);
    }
    memory_writes_[{base, addr.value}] = Slot{size, value};
  } else if (keep_slots_) {
    // Taken to miss the slots known: stores through a computed pointer
    // don't touch the stack slots that hold saved registers.
  } else {
    memory_writes_.clear();  // could alias anything
  }
}

Sym Evaluator::read(const lift::Varnode &v) {
  if (v.space == "const"sv) return Sym::constant(v.offset & mask(v.size));
  if (v.space == "register"sv || v.space == "unique"sv) {
    const bool reg = v.space == "register"sv;
    if (reg) reads_.emplace_back(v.offset, v.size);
    auto it = state_.find({reg, v.offset});
    // A value written in narrower pieces (AVR's Z read whole after its
    // halves R30 and R31 were written): put together from the pieces when
    // each is known and they cover it exactly.
    if (reg && v.size > 1 && v.size <= 8 && (it == state_.end() || it->second.size < v.size)) {
      std::uint64_t value = 0;
      std::uint32_t at = 0;
      bool whole = true;
      while (whole && at < v.size) {
        auto p = state_.find({true, v.offset + at});
        if (p == state_.end() || !p->second.value.known() || at + p->second.size > v.size) {
          whole = false;
          break;
        }
        const std::uint32_t n = p->second.size;
        const std::uint64_t piece = p->second.value.value & mask(n);
        const std::uint32_t shift = info_->big_endian ? 8 * (v.size - at - n) : 8 * at;
        value |= piece << shift;
        at += n;
      }
      if (whole && at == v.size && (it == state_.end() || it->second.size < v.size)) {
        reads_.emplace_back(v.offset, v.size);
        return Sym::constant(value);
      }
    }
    if (it != state_.end()) {
      const Slot &s = it->second;
      if (s.size == v.size) return s.value;
      if (!s.value.known()) return {};
      // Same offset, different size: the low part (little-endian), or the
      // zero-extended value when a narrower write is read wider.
      if (info_->big_endian && s.size > v.size) return {};
      return Sym::constant(s.value.value & mask(v.size));
    }
    if (!reg) return {};
    free_.emplace_back(v.offset, v.size);
    // Name the incoming value so arithmetic on it (stack and frame
    // pointers) still addresses the same memory.
    Sym incoming = Sym::relative(next_base_++, 0);
    incoming_[incoming.base] = v.offset;
    state_[{true, v.offset}] = Slot{v.size, incoming};
    return incoming;
  }
  if (!v.referenced_space.empty()) return {};
  return load(v.offset, v.size);  // a direct memory operand
}

void Evaluator::write(const lift::Varnode &v, Sym s) {
  if (v.space != "register"sv && v.space != "unique"sv) return;
  if (s.known()) s.value &= mask(v.size);
  const bool reg = v.space == "register"sv;
  // A write clobbers anything overlapping it at other offsets.
  if (reg) {
    for (auto it = state_.lower_bound({true, v.offset > 16 ? v.offset - 16 : 0});
         it != state_.end() && it->first.first && it->first.second < v.offset + v.size;) {
      std::uint64_t o = it->first.second;
      bool overlaps = o != v.offset && o < v.offset + v.size && v.offset < o + it->second.size;
      it = overlaps ? state_.erase(it) : std::next(it);
    }
  }
  state_[{reg, v.offset}] = Slot{v.size, s};
}

Sym Evaluator::apply(const lift::PcodeOp &op) {
  const std::string &o = op.opcode;
  const std::uint32_t out = op.output ? op.output->size : 0;
  auto in = [&](std::size_t i) { return i < op.inputs.size() ? read(op.inputs[i]) : Sym{}; };
  if (o == "COPY"sv) return in(0);
  if (o == "LOAD"sv) {
    Sym a = in(1);
    if (a.kind == Sym::Kind::relative) {
      auto it = memory_writes_.find({a.base, a.value});
      if (it != memory_writes_.end()) return it->second.size == out ? it->second.value : Sym{};
      if (auto reg = incoming_.find(a.base); reg != incoming_.end())
        free_memory_.push_back({reg->second, a.value, out});
      return {};
    }
    if (!a.known()) return Sym{};
    // The pointer counts in the units of the space the LOAD names.
    if (!op.inputs.empty() && !op.inputs[0].referenced_space.empty()) {
      auto k = info_->pointer_key(op.inputs[0].referenced_space, a.value);
      return k ? load(*k, out) : Sym{};
    }
    return load(a.value, out);
  }
  Sym a = in(0);
  if (o == "INT_ZEXT"sv) return a.known() ? Sym::constant(a.value & mask(op.inputs[0].size)) : Sym{};
  if (o == "INT_SEXT"sv)
    return a.known() ? Sym::constant(static_cast<std::uint64_t>(sext(a.value, op.inputs[0].size))) : Sym{};
  if (o == "INT_NEGATE"sv) return a.known() ? Sym::constant(~a.value) : Sym{};
  if (o == "INT_2COMP") return a.known() ? Sym::constant(~a.value + 1) : Sym{};
  if (o == "BOOL_NEGATE"sv) return a.known() ? Sym::constant(a.value == 0 ? 1 : 0) : Sym{};
  if (op.inputs.size() < 2) return {};
  Sym b = in(1);
  // An address loaded from a slot survives the masking RISC-V's jalr does
  // ((target + 0) & ~1) and additions of zero.
  if (a.kind == Sym::Kind::loaded && b.known()) {
    if (o == "INT_ADD"sv && b.value == 0) return a;
    if (o == "INT_AND"sv && (b.value | 1) == mask(out)) return a;
  }
  // An incoming value with its low bits cleared stays that value (ARM
  // clears a return address's mode bits before jumping to it).
  if (a.kind == Sym::Kind::relative && b.known() && o == "INT_AND"sv && (b.value | 3) == mask(out)) return a;
  // Incoming values plus or minus constants (frame and stack addresses).
  if (a.kind == Sym::Kind::relative && b.known() && (o == "INT_ADD"sv || o == "INT_SUB"sv))
    return Sym::relative(a.base, o == "INT_ADD"sv ? a.value + b.value : a.value - b.value);
  if (b.kind == Sym::Kind::relative && a.known() && o == "INT_ADD"sv) return Sym::relative(b.base, a.value + b.value);
  if (a.kind == Sym::Kind::relative && b.kind == Sym::Kind::relative && a.base == b.base && o == "INT_SUB"sv)
    return Sym::constant(a.value - b.value);
  if (o == "SUBPIECE"sv) return a.known() && b.known() && b.value < 8 ? Sym::constant(a.value >> (8 * b.value)) : Sym{};
  // Whatever the value: shifted out entirely, or masked or multiplied by 0.
  if (b.known() && (o == "INT_LEFT"sv || o == "INT_RIGHT"sv) && b.value >= 8 * std::uint64_t{op.inputs[0].size})
    return Sym::constant(0);
  if (b.known() && b.value == 0 && (o == "INT_AND"sv || o == "INT_MULT"sv)) return Sym::constant(0);
  if (!a.known() || !b.known()) return {};
  const std::uint32_t isz = op.inputs[0].size;
  const std::uint64_t x = a.value, y = b.value;
  if (o == "INT_ADD"sv) return Sym::constant(x + y);
  if (o == "INT_SUB"sv) return Sym::constant(x - y);
  if (o == "INT_MULT"sv) return Sym::constant(x * y);
  if (o == "INT_AND"sv) return Sym::constant(x & y);
  if (o == "INT_OR"sv) return Sym::constant(x | y);
  if (o == "INT_XOR"sv) return Sym::constant(x ^ y);
  if (o == "INT_LEFT"sv) return Sym::constant(y >= 64 ? 0 : x << y);
  if (o == "INT_RIGHT"sv) return Sym::constant(y >= 64 ? 0 : (x & mask(isz)) >> y);
  if (o == "INT_SRIGHT"sv)
    return Sym::constant(static_cast<std::uint64_t>(sext(x, isz) >> std::min<std::uint64_t>(y, 63)));
  if (o == "INT_DIV"sv) return y == 0 ? Sym{} : Sym::constant((x & mask(isz)) / (y & mask(isz)));
  if (o == "INT_REM"sv) return y == 0 ? Sym{} : Sym::constant((x & mask(isz)) % (y & mask(isz)));
  if (o == "PIECE"sv) return Sym::constant((x << (8 * op.inputs[1].size)) | (y & mask(op.inputs[1].size)));
  if (o == "INT_EQUAL"sv) return Sym::constant((x & mask(isz)) == (y & mask(isz)));
  if (o == "INT_NOTEQUAL"sv) return Sym::constant((x & mask(isz)) != (y & mask(isz)));
  if (o == "INT_LESS"sv) return Sym::constant((x & mask(isz)) < (y & mask(isz)));
  if (o == "INT_LESSEQUAL"sv) return Sym::constant((x & mask(isz)) <= (y & mask(isz)));
  if (o == "INT_SLESS"sv) return Sym::constant(sext(x, isz) < sext(y, isz));
  if (o == "INT_SLESSEQUAL"sv) return Sym::constant(sext(x, isz) <= sext(y, isz));
  if (o == "INT_CARRY"sv) return Sym::constant(((x & mask(isz)) + (y & mask(isz))) & ~mask(isz) ? 1 : 0);
  if (o == "INT_SCARRY"sv) {
    std::int64_t r = sext(x + y, isz);
    return Sym::constant((sext(x, isz) >= 0) == (sext(y, isz) >= 0) && (r >= 0) != (sext(x, isz) >= 0));
  }
  if (o == "INT_SBORROW"sv) {
    std::int64_t r = sext(x - y, isz);
    return Sym::constant((sext(x, isz) >= 0) != (sext(y, isz) >= 0) && (r >= 0) != (sext(x, isz) >= 0));
  }
  if (o == "BOOL_AND"sv) return Sym::constant((x != 0) && (y != 0));
  if (o == "BOOL_OR"sv) return Sym::constant((x != 0) || (y != 0));
  if (o == "BOOL_XOR"sv) return Sym::constant((x != 0) != (y != 0));
  return {};
}

bool Evaluator::step(const lift::Instruction &insn) {
  indirect_.reset();
  condition_.reset();
  completed_ = false;
  bool pure = !insn.unimplemented;
  const auto &ops = insn.pcode;
  // Ops run in order, honouring branches within the instruction's p-code
  // (relative targets in the const space); an unknown internal condition
  // leaves whatever the skipped ops would write unknown.
  constexpr std::size_t kMaxSteps = 512;
  std::size_t i = 0;
  for (std::size_t steps = 0; i < ops.size() && steps < kMaxSteps; ++steps) {
    const lift::PcodeOp &op = ops[i];
    const std::string &o = op.opcode;
    const bool internal = !op.inputs.empty() && op.inputs[0].space == "const"sv;
    if ((o == "BRANCH"sv || o == "CBRANCH"sv) && internal) {
      bool take = true;
      if (o == "CBRANCH"sv) {
        Sym c = op.inputs.size() > 1 ? read(op.inputs[1]) : Sym{};
        if (!c.known()) {
          // Both ways are possible: what either path writes is unknown.
          for (std::size_t j = i + 1; j < ops.size(); ++j)
            if (ops[j].output) write(*ops[j].output, {});
          return false;
        }
        take = c.value != 0;
      }
      if (take) {
        std::int64_t rel = sext(op.inputs[0].offset, op.inputs[0].size);
        std::int64_t next = static_cast<std::int64_t>(i) + rel;
        if (next < 0 || next > static_cast<std::int64_t>(ops.size())) return false;
        i = static_cast<std::size_t>(next);
      } else {
        ++i;
      }
      continue;
    }
    if (o == "CBRANCH"sv) {
      condition_ = op.inputs.size() > 1 ? read(op.inputs[1]) : Sym{};
      // A conditional instruction that skips itself (ARM: CBRANCH to the
      // next instruction) when its condition holds: the rest doesn't run.
      if (!op.inputs.empty() && op.inputs[0].space == info_->code_space &&
          op.inputs[0].offset == insn.address + insn.length + insn.delay_slot && i + 1 < ops.size()) {
        if (!condition_->known()) {
          // It may or may not run: what it writes is unknown.
          for (std::size_t j = i + 1; j < ops.size(); ++j)
            if (ops[j].output) write(*ops[j].output, {});
          return false;
        }
        if (condition_->value != 0) {
          completed_ = true;
          return pure;
        }
      }
    } else if (o == "BRANCHIND"sv || o == "CALLIND"sv) {
      indirect_ = op.inputs.empty() ? Sym{} : read(op.inputs[0]);
      // A target value counts in the code space's units (AVR's words).
      if (indirect_->known() && info_->code_wordsize() > 1) indirect_->value *= info_->code_wordsize();
      if (o == "CALLIND"sv) {
        pure = false;
        if (calls_clobber_) clobber_at_call();
      }
    } else if (o == "STORE"sv) {
      pure = false;
      if (op.inputs.size() >= 3) store(read(op.inputs[1]), op.inputs[2].size, read(op.inputs[2]));
    } else if (o == "CALL"sv || o == "CALLOTHER"sv) {
      pure = false;
      if (op.output) write(*op.output, {});
      if (o == "CALL"sv && calls_clobber_) clobber_at_call();
    } else if (o == "RETURN"sv) {
      indirect_ = op.inputs.empty() ? Sym{} : read(op.inputs[0]);
    } else if (o == "BRANCH"sv) {
      // control transfer out of the instruction; nothing to compute
    } else if (op.output) {
      write(*op.output, apply(op));
    }
    ++i;
  }
  completed_ = true;
  return pure;
}

}  // namespace revkit::analysis::detail

namespace revkit::analysis {

void release_idle_decoders(facts::ThreadPool *pool) { detail::pool_clear(pool); }

void prepare_decoders(const std::string &language, facts::ThreadPool &pool) {
  std::string base = language;
  if (std::count(base.begin(), base.end(), ':') >= 4) base = base.substr(0, base.rfind(':'));
  detail::pool_prepare(base, pool.size() + 1, pool);
}

std::optional<RegisterSlot> detail::stack_register(const ProgramInfo &info) {
  static std::mutex mu;
  static std::map<std::pair<std::string, std::string>, std::optional<RegisterSlot>> cache;
  std::lock_guard lock(mu);
  auto it = cache.find({info.language, info.compiler});
  if (it == cache.end()) {
    std::optional<RegisterSlot> slot;
    try {
      const std::string name = lift::read_abi(info.language, info.compiler).stack_pointer;
      lift::Lifter plain(std::make_shared<const loader::Image>(), info.language);
      if (auto v = name.empty() ? std::nullopt : plain.register_varnode(name)) slot = RegisterSlot{v->offset, v->size};
    } catch (const lift::LiftError &) {
    }
    it = cache.emplace(std::make_pair(info.language, info.compiler), slot).first;
  }
  return it->second;
}

bool two_instruction_sets(const ProgramInfo &info) {
  if (info.isa_context.empty()) return false;
  // What the language decodes as where nothing is painted, once a language.
  static std::mutex mu;
  static std::map<std::string, bool> cache;
  std::lock_guard lock(mu);
  auto it = cache.find(info.language);
  if (it == cache.end()) {
    bool two = false;
    try {
      lift::Lifter plain(std::make_shared<const loader::Image>(), info.language);
      two = plain.context_at(info.isa_context, 0) == 0;
    } catch (const lift::LiftError &) {
    }
    it = cache.emplace(info.language, two).first;
  }
  return it->second;
}

}  // namespace revkit::analysis

namespace revkit::analysis {

struct CodeReader::Impl {
  Impl(facts::QueryContext &ctx, const ProgramInfo &info) : bytes(ctx, info), decoder(info) {}
  detail::ByteReader bytes;
  detail::Decoder decoder;
};

CodeReader::CodeReader(facts::QueryContext &ctx, const ProgramInfo &info) : impl_(std::make_unique<Impl>(ctx, info)) {}
CodeReader::~CodeReader() = default;

std::optional<lift::Instruction> CodeReader::decode(std::uint64_t address, bool tagged) {
  return impl_->decoder.decode(address, impl_->bytes, tagged);
}

std::span<const std::byte> CodeReader::bytes(std::uint64_t address, std::size_t n) {
  return impl_->bytes.read(address, n);
}

}  // namespace revkit::analysis
