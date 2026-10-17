#include "revkit/decompd/builder.h"

#include "revkit/inputs/codec.h"
#include "revkit/lift/context.hh"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>

namespace revkit::decompd {

// ---- ProgramImage -----------------------------------------------------------------

ProgramImage::ProgramImage(std::shared_ptr<const loader::Image> image, std::string language_id,
                           const lift::ArchitectureOptions::Patches &patches,
                           std::optional<std::vector<lift::ContextRegion>> context)
    : image_(std::move(image)), language_id_(std::move(language_id)) {
  // Compact: 16 bytes a patch and one arena (libLLVM has 800K relocations).
  patches_.reserve(patches.size());
  for (const auto &[addr, bytes] : patches) {
    if (bytes.empty()) continue;
    patches_.push_back({addr, static_cast<std::uint32_t>(bytes_.size()), static_cast<std::uint32_t>(bytes.size())});
    bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
  }
  std::stable_sort(patches_.begin(), patches_.end(), [](const Patch &a, const Patch &b) { return a.addr < b.addr; });
  for (const Patch &p : patches_) longest_ = std::max<std::uint64_t>(longest_, p.size);
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
  for (const loader::Region &r : image_->memory.regions())
    if (r.size != 0) ranges.emplace_back(r.start, r.last());
  for (const Patch &p : patches_) ranges.emplace_back(p.addr, p.addr + (p.size - 1));
  std::sort(ranges.begin(), ranges.end());
  for (const auto &r : ranges) {
    if (!mapped_.empty() && (r.first <= mapped_.back().second || r.first == mapped_.back().second + 1))
      mapped_.back().second = std::max(mapped_.back().second, r.second);
    else
      mapped_.push_back(r);
  }
  context_ = context ? std::move(*context) : lift::image_context(*image_);
}

bool ProgramImage::mapped_at(std::uint64_t a) const {
  auto it = std::upper_bound(mapped_.begin(), mapped_.end(), a,
                             [](std::uint64_t x, const std::pair<std::uint64_t, std::uint64_t> &r) { return x < r.first; });
  if (it == mapped_.begin()) return false;
  return a <= std::prev(it)->second;
}

bool ProgramImage::mapped_in(std::uint64_t first, std::uint64_t last) const {
  auto it = std::lower_bound(mapped_.begin(), mapped_.end(), first,
                             [](const std::pair<std::uint64_t, std::uint64_t> &r, std::uint64_t x) { return r.second < x; });
  return it != mapped_.end() && it->first <= last;
}

std::size_t ProgramImage::read(std::uint64_t addr, std::span<std::uint8_t> out) const {
  image_->memory.read(addr, std::span<std::byte>(reinterpret_cast<std::byte *>(out.data()), out.size()));
  const std::uint64_t end = addr + out.size();
  const std::uint64_t from = addr >= longest_ ? addr - longest_ : 0;
  auto it = std::lower_bound(patches_.begin(), patches_.end(), from, [](const Patch &p, std::uint64_t a) { return p.addr < a; });
  for (; it != patches_.end() && it->addr < end; ++it)
    for (std::size_t i = 0; i < it->size; ++i) {
      const std::uint64_t a = it->addr + i;
      if (a >= addr && a < end) out[a - addr] = bytes_[it->offset + i];
    }
  std::size_t mapped = 0;
  for (std::size_t i = 0; i < out.size(); ++i)
    if (mapped_at(addr + i)) ++mapped;
    else out[i] = 0;
  return mapped;
}

std::string ProgramImage::chunk(std::uint64_t index) const {
  std::string s(kChunk, '\0');
  read(index * kChunk, std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(s.data()), s.size()));
  return s;
}

Bundle ProgramImage::bundle(Mode mode, std::uint64_t entry) const {
  Bundle b;
  b.mode = mode;
  b.language_id = language_id_;
  b.entry = entry;
  b.format = image_->format;
  b.bits = image_->bits;
  b.image_blocks = image_->blocks;
  b.mapped = mapped_;
  b.context = context_;
  return b;
}

// ---- prediction ---------------------------------------------------------------------

namespace {

bool is_memory_space(const std::string &s) {
  return s != "const" && s != "register" && s != "unique" && s != "space" && !s.empty();
}

}  // namespace

Prediction predict(lift::Lifter &lifter, const ProgramImage &program, std::uint64_t entry,
                   const std::vector<std::pair<std::uint64_t, std::uint64_t>> &body,
                   const std::vector<lift::BlockFacts> &blocks,
                   const std::vector<std::pair<std::uint64_t, std::uint64_t>> &seeds) {
  Prediction p;
  const std::string code_space = lifter.code_space_name();
  const unsigned ptr = program.pointer_size();
  const bool x86 = program.language_id().starts_with("x86:");
  auto space_of = [&](const std::string &s) { return s == code_space ? std::string() : s; };
  auto in_body = [&](std::uint64_t a) {
    return std::any_of(body.begin(), body.end(), [a](const auto &r) { return a >= r.first && a <= r.second; });
  };
  // Memory the decompiler is told about: the image's, and blocks no file
  // backs (ELF's EXTERNAL block, where relocated slots point).
  auto known = [&](std::uint64_t a) {
    if (program.mapped_at(a)) return true;
    return std::any_of(blocks.begin(), blocks.end(),
                       [a](const lift::BlockFacts &b) { return b.space.empty() && a >= b.start && a <= b.end; });
  };
  auto read_pointer = [&](std::uint64_t a) -> std::optional<std::uint64_t> {
    std::uint8_t buf[8] = {};
    if (program.read(a, std::span<std::uint8_t>(buf, ptr)) != ptr) return std::nullopt;
    std::uint64_t v = 0;
    const bool big = program.image().endian == loader::Endian::big;
    for (unsigned i = 0; i < ptr; ++i) v |= std::uint64_t{buf[big ? ptr - 1 - i : i]} << (8 * i);
    return v;
  };
  auto address = [&](const std::string &space, std::uint64_t a) {
    if (!p.addresses.insert({space, a}).second || !space.empty()) return;
    p.chunks.insert(a / kChunk);
    p.chunks.insert(a / kChunk + 1);
  };
  // A data address: it, and the pointer stored there (a GOT or IAT slot,
  // a pointer table the decompiler folds as constant).
  auto data_address = [&](std::uint64_t a) {
    address({}, a);
    if (auto v = read_pointer(a); v && *v != 0 && known(*v)) address({}, *v);
  };
  address({}, entry);
  address({}, 0);  // null pointers are looked up all the time
  bool computed_jump = false;
  // Page-plus-offset address formation (AArch64 adrp/add, RISC-V
  // auipc/addi): constants that land in memory, from the last few
  // instructions, plus small immediates.
  std::deque<std::pair<std::uint64_t, int>> pages;  // (constant, instructions since)
  // Where the decompiler's flow may leave the body (a cold part jumping
  // back, a body that stops short): followed for a while.
  std::vector<std::uint64_t> away;
  std::set<std::uint64_t> seen;
  // Decodes one instruction and notes what it names; returns its length
  // (0: undecodable) and whether flow falls through.
  // Constants folded through registers within a block (RISC-V auipc and
  // gp, AArch64 adrp, MIPS lui pairs): registers and temporaries whose
  // value is known, seeded with the registers the function's entry tracks.
  std::map<std::pair<std::string, std::uint64_t>, std::uint64_t> values;
  auto reseed = [&] {
    values.clear();
    for (const auto &[reg, v] : seeds) values[{"register", reg}] = v;
  };
  reseed();
  for (const auto &[reg, v] : seeds) data_address(v);  // the decompiler names it (__global_pointer$)
  auto value_of = [&](const lift::Varnode &v) -> std::optional<std::uint64_t> {
    if (v.space == "const") return v.offset;
    if (v.space == "register" || v.space == "unique") {
      auto it = values.find({v.space, v.offset});
      if (it != values.end()) return it->second;
    }
    return std::nullopt;
  };
  auto mask = [](std::uint64_t x, std::uint32_t size) {
    return size >= 8 ? x : x & ((std::uint64_t{1} << (8 * size)) - 1);
  };
  auto fold = [&](const lift::PcodeOp &op) {
    if (!op.output || (op.output->space != "register" && op.output->space != "unique")) return;
    const std::pair<std::string, std::uint64_t> key{op.output->space, op.output->offset};
    std::optional<std::uint64_t> r;
    auto in = [&](std::size_t i) { return i < op.inputs.size() ? value_of(op.inputs[i]) : std::nullopt; };
    if (op.opcode == "COPY" || op.opcode == "INT_ZEXT") r = in(0);
    else if (op.opcode == "INT_SEXT" && op.inputs.size() == 1) {
      if (auto x = in(0)) {
        const std::uint32_t bits = op.inputs[0].size * 8;
        r = bits < 64 && ((*x >> (bits - 1)) & 1) ? (*x | (~std::uint64_t{0} << bits)) : *x;
      }
    } else if (op.opcode == "INT_ADD" || op.opcode == "INT_SUB" || op.opcode == "INT_OR" || op.opcode == "INT_LEFT") {
      auto x = in(0), y = in(1);
      if (x && y) {
        if (op.opcode == "INT_ADD") r = *x + *y;
        else if (op.opcode == "INT_SUB") r = *x - *y;
        else if (op.opcode == "INT_OR") r = *x | *y;
        else if (*y < 64) r = *x << *y;
      }
    }
    if (op.opcode == "LOAD" && op.inputs.size() >= 2)
      if (auto at = value_of(op.inputs[1]); at && known(*at)) data_address(*at);
    if (r) {
      values[key] = mask(*r, op.output->size);
      if (op.output->size >= std::min(4u, ptr) && values[key] >= 0x1000 && known(values[key])) data_address(values[key]);
    } else {
      values.erase(key);
    }
  };
  auto visit = [&](std::uint64_t a, bool &falls) -> std::uint32_t {
    falls = true;
    std::optional<lift::Instruction> insn = lifter.lift_pcode(a);
    if (!insn || insn->length == 0) return 0;
    if (p.code_labels.contains({{}, a})) reseed();  // a block start: values from elsewhere
    for (const lift::PcodeOp &op : insn->pcode) fold(op);
    // Every block start may become a goto target, which the printer labels
    // (asking about the address and its code label): the instruction after
    // a conditional branch, and after one that doesn't fall through.
    bool ends_block = false;
    for (const lift::PcodeOp &op : insn->pcode)
      if (op.opcode == "CBRANCH" || op.opcode == "BRANCH" || op.opcode == "BRANCHIND" || op.opcode == "RETURN")
        ends_block = true;
    if (ends_block && in_body(a + insn->length)) {
      address({}, a + insn->length);
      p.code_labels.insert({{}, a + insn->length});
    }
    if (ends_block) reseed();
    for (std::uint64_t c = a / kChunk; c <= (a + insn->length + 15) / kChunk; ++c) p.chunks.insert(c);
    std::vector<std::uint64_t> small;
    for (const lift::PcodeOp &op : insn->pcode) {
      const bool flow = op.opcode == "BRANCH" || op.opcode == "CBRANCH" || op.opcode == "CALL";
      if (op.opcode == "BRANCH" || op.opcode == "BRANCHIND" || op.opcode == "RETURN") falls = false;
      if (op.opcode == "BRANCHIND") computed_jump = true;
      for (std::size_t i = 0; i < op.inputs.size(); ++i) {
        const lift::Varnode &v = op.inputs[i];
        if (v.space == "const") {
          if (v.offset < 0x8000) small.push_back(v.offset);
          if (v.size >= std::min(4u, ptr) && v.offset >= 0x1000 && known(v.offset)) {
            data_address(v.offset);
            pages.emplace_back(v.offset, 0);
          }
        } else if (is_memory_space(v.space)) {
          const std::string space = space_of(v.space);
          if (space.empty() && flow && i == 0) {
            address({}, v.offset);
            if (op.opcode == "CALL") p.calls.insert(v.offset);
            if (op.opcode != "CALL") {
              if (in_body(v.offset)) p.code_labels.insert({{}, v.offset});
              else away.push_back(v.offset);
            }
          } else if (space.empty()) {
            data_address(v.offset);
          } else {
            address(space, v.offset);
          }
        }
      }
      if (op.output && is_memory_space(op.output->space)) {
        const std::string space = space_of(op.output->space);
        if (space.empty()) data_address(op.output->offset);
        else address(space, op.output->offset);
      }
    }
    if (!x86)
      for (const auto &[page, age] : pages)
        for (std::uint64_t k : small)
          if (program.mapped_at(page + k)) data_address(page + k);
    for (auto &pa : pages) ++pa.second;
    while (!pages.empty() && pages.front().second > 4) pages.pop_front();
    while (pages.size() > 8) pages.pop_front();
    return insn->length;
  };
  if (body.empty()) away.push_back(entry);
  for (const auto &[first, last] : body) {
    std::uint64_t a = first;
    bool falls = true;
    while (a <= last) {
      seen.insert(a);
      const std::uint32_t n = visit(a, falls);
      if (n == 0) {
        a += std::max(1u, lifter.alignment());
        continue;
      }
      a += n;
    }
    if (falls && !in_body(a)) away.push_back(a);
  }
  // At most this many instructions outside the body, in all.
  int budget = body.empty() ? 20000 : 256;
  while (!away.empty() && budget > 0) {
    std::uint64_t a = away.back();
    away.pop_back();
    while (budget > 0 && !in_body(a) && seen.insert(a).second && program.mapped_at(a)) {
      --budget;
      bool falls = true;
      const std::uint32_t n = visit(a, falls);
      if (n == 0 || !falls) break;
      a += n;
    }
  }
  // A computed jump through a table the decompiler will recover: guess the
  // table among the constants the function names (offsets from the table,
  // as position-independent x86-64 switches have them, or absolute
  // pointers) and predict the destinations that land in the body.
  if (computed_jump && !body.empty()) {
    std::vector<std::uint64_t> tables;
    for (const auto &[space, a] : p.addresses)
      if (space.empty() && a != 0 && !in_body(a) && program.mapped_at(a)) tables.push_back(a);
    for (std::uint64_t t : tables) {
      for (int width : {4, static_cast<int>(ptr)}) {
        std::vector<std::uint64_t> dests;
        for (std::uint64_t k = 0; k < 2048; ++k) {
          std::uint8_t buf[8] = {};
          if (program.read(t + k * static_cast<std::uint64_t>(width), std::span<std::uint8_t>(buf, width)) != static_cast<std::size_t>(width)) break;
          std::uint64_t v = 0;
          const bool big = program.image().endian == loader::Endian::big;
          for (int i = 0; i < width; ++i) v |= std::uint64_t{buf[big ? width - 1 - i : i]} << (8 * i);
          std::uint64_t dest = v;
          if (width == 4 && ptr == 8) dest = t + static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(v)));
          if (!in_body(dest)) break;
          dests.push_back(dest);
        }
        if (dests.size() < 2) continue;
        for (std::uint64_t d : dests) {
          p.addresses.insert({{}, d});
          p.code_labels.insert({{}, d});
        }
        for (std::uint64_t c = t / kChunk; c <= (t + dests.size() * static_cast<std::uint64_t>(width)) / kChunk; ++c)
          p.chunks.insert(c);
      }
    }
  }
  // Chunks outside the image hold nothing to send.
  for (auto it = p.chunks.begin(); it != p.chunks.end();) {
    it = program.mapped_in(*it * kChunk, *it * kChunk + (kChunk - 1)) ? std::next(it) : p.chunks.erase(it);
  }
  return p;
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> tracked_seeds(lift::Lifter &lifter,
                                                                   const std::vector<lift::TrackedFacts> &tracked) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
  for (const lift::TrackedFacts &t : tracked) {
    if (!t.register_name.empty()) {
      if (auto v = lifter.register_varnode(t.register_name)) out.emplace_back(v->offset, t.value);
    } else if (t.reg.space == "register") {
      out.emplace_back(t.reg.offset, t.value);
    }
  }
  return out;
}

LifterPool::LifterPool(std::shared_ptr<const loader::Image> image, std::string language, unsigned per_context)
    : image_(std::move(image)),
      language_(std::count(language.begin(), language.end(), ':') >= 4 ? language.substr(0, language.rfind(':'))
                                                                        : std::move(language)),
      per_context_(std::max(1u, per_context)) {}

LifterPool::~LifterPool() = default;

LifterPool::Lease::~Lease() {
  if (!lifter || owner == nullptr) return;
  std::lock_guard lock(owner->mu_);
  owner->last_use_ = std::chrono::steady_clock::now();
  owner->idle_[context].push_back(std::move(lifter));
  owner->cv_.notify_all();
}

std::size_t LifterPool::park_idle(std::chrono::steady_clock::duration idle_for) {
  std::lock_guard lock(mu_);
  if (std::chrono::steady_clock::now() - last_use_ < idle_for) return 0;
  std::size_t n = 0;
  for (auto &[context, idle] : idle_)
    for (auto &l : idle)
      if (!l->parked() && l->park()) ++n;
  return n;
}

LifterPool::Lease LifterPool::take(const Context &context) {
  std::unique_lock lock(mu_);
  cv_.wait(lock, [&] { return !idle_[context].empty() || made_[context] < per_context_; });
  last_use_ = std::chrono::steady_clock::now();
  Lease out;
  out.owner = this;
  out.context = context;
  if (auto &v = idle_[context]; !v.empty()) {
    out.lifter = std::move(v.back());
    v.pop_back();
    return out;
  }
  ++made_[context];
  lock.unlock();
  try {
    auto l = std::make_unique<lift::Lifter>(image_, language_);
    for (const lift::ContextRegion &c : lift::image_context(*image_)) l->set_context(c.name, c.value, c.start, c.end);
    for (const auto &[name, value] : context) {
      try {
        l->set_context(name, value, 0);
      } catch (const lift::LiftError &) {
        // not a context variable of this language
      }
    }
    out.lifter = std::move(l);
  } catch (...) {
    lock.lock();
    --made_[context];
    cv_.notify_all();
    throw;
  }
  return out;
}

BundleStats bundle_stats(const Bundle &b, std::size_t encoded_size) {
  BundleStats s;
  s.bytes = encoded_size;
  s.chunks = b.chunks.size();
  s.addresses = b.lift.addresses.size();
  s.types = b.lift.types.size();
  return s;
}

// ---- LiftBundleBuilder -----------------------------------------------------------------

namespace {

std::optional<std::uint64_t> element_id(const lift::DecompElement &t) {
  const auto *id = t.attr("id");
  if (id == nullptr) return std::nullopt;
  if (const auto *u = std::get_if<std::uint64_t>(id)) return *u;
  if (const auto *i = std::get_if<std::int64_t>(id)) return static_cast<std::uint64_t>(*i);
  return std::nullopt;
}

// Ids of the named types an encoding refers to.
void type_ids(const lift::DecompElement &t, std::set<std::uint64_t> &out) {
  if (t.tag == "typeref" || t.tag == "type" || t.tag == "def")
    if (auto id = element_id(t)) out.insert(*id);
  for (const lift::DecompElement &c : t.children) type_ids(c, out);
}

void type_ids(const lift::FunctionFacts &f, std::set<std::uint64_t> &out) {
  type_ids(f.ret.type, out);
  for (const lift::ParamFacts &p : f.params) type_ids(p.type, out);
  for (const lift::LocalFacts &l : f.locals) type_ids(l.type, out);
}

}  // namespace

LiftBundleBuilder::LiftBundleBuilder(const ProgramImage &program, Mode mode, std::uint64_t entry,
                                     lift::FactLookup &facts, std::vector<lift::BlockFacts> blocks,
                                     std::string address_prefix)
    : program_(program), mode_(mode), entry_(entry), facts_(facts) {
  lift_.blocks = std::move(blocks);
  lift_.address_prefix = std::move(address_prefix);
}

void LiftBundleBuilder::set_naming(bool default_names, bool default_labels, bool default_extrapop) {
  lift_.default_names = default_names;
  lift_.default_labels = default_labels;
  lift_.default_extrapop = default_extrapop;
}

void LiftBundleBuilder::set_hooks(std::map<std::uint64_t, std::vector<std::uint64_t>> jump_tables,
                                  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides,
                                  std::vector<lift::CommentFacts> comments) {
  lift_.jump_tables = std::move(jump_tables);
  lift_.hook_flow_overrides = std::move(flow_overrides);
  lift_.hook_comments = std::move(comments);
}

void LiftBundleBuilder::set_user_hooks(std::vector<lift::EquateFacts> equates,
                                       std::map<std::uint64_t, std::uint64_t> call_targets,
                                       std::set<std::uint64_t> forced_tables) {
  lift_.hook_equates = std::move(equates);
  lift_.hook_call_targets = std::move(call_targets);
  lift_.hook_forced_tables.assign(forced_tables.begin(), forced_tables.end());
}

template <class T>
std::int32_t LiftBundleBuilder::intern(std::vector<T> &table, std::map<std::string, std::int32_t> &index,
                                       const T &value) {
  std::string key = facts::encode_to_string(value);
  auto [it, inserted] = index.try_emplace(std::move(key), static_cast<std::int32_t>(table.size()));
  if (inserted) table.push_back(value);
  return it->second;
}

bool LiftBundleBuilder::add_address(const std::string &space, std::uint64_t a) {
  if (lift_.addresses.contains({space, a})) return false;
  AddressAnswer r;
  if (space.empty()) {
    if (const lift::FunctionFacts *f = facts_.function_at(a)) r.starts = intern(lift_.functions, function_ix_, *f);
    if (std::optional<lift::FactLookup::Body> b = facts_.body_containing(a)) {
      r.contains = intern(lift_.functions, function_ix_, *b->function);
      r.body_first = b->first;
      r.body_last = b->last;
    }
  }
  const lift::DataFacts *d = facts_.data_containing(space, a);
  if (d != nullptr) r.data = intern(lift_.data, data_ix_, *d);
  if (const lift::ExternalRefFacts *x = facts_.external_at(space, a)) r.external = intern(lift_.externals, external_ix_, *x);
  if (const lift::LabelFacts *l = facts_.label_at(space, a)) r.label = intern(lift_.labels, label_ix_, *l);
  r.block = facts_.block_at(space, a);
  const bool says = r.starts >= 0 || r.contains >= 0 || r.data >= 0 || r.external >= 0 || r.label >= 0 ||
                    r.block != lift_.default_block(space, a);
  lift_.addresses.emplace(SpaceAddr{space, a}, r);
  // An address inside data: the decompiler asks about the data's start too.
  if (d != nullptr && d->addr != a && d->space == space) add_address(space, d->addr);
  return says;
}

bool LiftBundleBuilder::add_code_label(const std::string &space, std::uint64_t a) {
  if (lift_.code_labels.contains({space, a})) return false;
  std::optional<std::string> l = facts_.code_label_at(space, a);
  const bool says = l.has_value();
  lift_.code_labels.emplace(SpaceAddr{space, a}, std::move(l));
  return says;
}

bool LiftBundleBuilder::add_chunk(std::uint64_t index) {
  if (chunks_.contains(index)) return false;
  chunks_.emplace(index, chunk_hook_ ? chunk_hook_(index, program_.chunk(index)) : program_.chunk(index));
  // The worker read missing bytes as unreadable: always a different answer.
  return true;
}

std::shared_ptr<const TypeCache::Entry> TypeCache::get(std::uint64_t id, lift::FactLookup &facts) {
  {
    std::lock_guard lock(mu_);
    if (auto it = entries_.find(id); it != entries_.end()) return it->second;
  }
  auto e = std::make_shared<Entry>();
  if (const lift::DecompElement *t = facts.type(id)) {
    e->encoded = facts::encode_to_string(*t);
    std::set<std::uint64_t> refs;
    type_ids(*t, refs);
    e->refs.assign(refs.begin(), refs.end());
  }
  std::lock_guard lock(mu_);
  return entries_.emplace(id, std::move(e)).first->second;
}

void LiftBundleBuilder::add_types() {
  // Ghidra's DEFAULT type ("undefined"), which the decompiler gives the
  // symbols it makes for undefined bytes, besides what the facts reference.
  std::set<std::uint64_t> want{0xc000000000000000ULL};
  for (const lift::FunctionFacts &f : lift_.functions) type_ids(f, want);
  for (const auto &[call, f] : lift_.hook_call_protos) type_ids(f, want);
  for (const lift::DataFacts &d : lift_.data) type_ids(d.type, want);
  for (const lift::ExternalRefFacts &x : lift_.externals)
    if (x.function) type_ids(*x.function, want);
  while (!want.empty()) {
    const std::uint64_t id = *want.begin();
    want.erase(want.begin());
    if (!type_done_.insert(id).second) continue;
    std::shared_ptr<const TypeCache::Entry> e = types_->get(id, facts_);
    lift_.types[id] = e->encoded;
    for (std::uint64_t m : e->refs)
      if (!type_done_.contains(m)) want.insert(m);
  }
}

void LiftBundleBuilder::add(const Prediction &p) {
  if (!entry_done_) {
    entry_done_ = true;
    add_address({}, entry_);
    for (const lift::CommentFacts *c : facts_.comments(entry_)) lift_.comments.push_back(*c);
    lift_.flow_overrides = facts_.flow_overrides(entry_);
    lift_.tracked = facts_.tracked(entry_);
    for (const auto &[jump, targets] : lift_.jump_tables)
      for (std::uint64_t t : targets) {
        add_address({}, t);
        add_code_label({}, t);
      }
    // A call override's target: the function the decompiler asks for.
    for (const auto &[call, target] : lift_.hook_call_targets) add_address({}, target);
  }
  for (const auto &[space, a] : p.addresses) add_address(space, a);
  for (const auto &[space, a] : p.code_labels) add_code_label(space, a);
  for (std::uint64_t c : p.chunks) add_chunk(c);
  add_types();
}

bool LiftBundleBuilder::fill(const std::vector<Miss> &misses) {
  bool changed = false;
  static const bool trace = std::getenv("REVKIT_DECOMPD_TRACE_MISSES") != nullptr;
  for (const Miss &m : misses) {
    switch (m.kind) {
      case Miss::address: {
        const bool c = add_address(m.space, m.value);
        if (trace && c) {
          const AddressAnswer &a = lift_.addresses.at({m.space, m.value});
          std::fprintf(stderr, "changed %llx address %s%llx: f%d b%d d%d x%d l%d\n", (unsigned long long)entry_,
                       m.space.c_str(), (unsigned long long)m.value, a.starts, a.contains, a.data, a.external, a.label);
        }
        changed |= c;
        break;
      }
      case Miss::code_label: {
        const bool c = add_code_label(m.space, m.value);
        if (trace && c) std::fprintf(stderr, "changed %llx label %llx\n", (unsigned long long)entry_, (unsigned long long)m.value);
        changed |= c;
        break;
      }
      case Miss::chunk:
        if (trace) std::fprintf(stderr, "changed %llx chunk %llx\n", (unsigned long long)entry_, (unsigned long long)(m.value * kChunk));
        changed |= add_chunk(m.value);
        // Flow that ran into a chunk tends to run on through the next ones:
        // a few more now, rather than a run for each.
        for (std::uint64_t c = m.value + 1; c <= m.value + 3; ++c)
          if (program_.mapped_in(c * kChunk, c * kChunk + (kChunk - 1))) add_chunk(c);
        break;
      case Miss::type:
        if (!type_done_.contains(m.value)) {
          // The type and every type it reaches.
          std::shared_ptr<const TypeCache::Entry> e = types_->get(m.value, facts_);
          if (trace && !e->encoded.empty())
            std::fprintf(stderr, "changed %llx type %llx\n", (unsigned long long)entry_, (unsigned long long)m.value);
          changed |= !e->encoded.empty();
          std::set<std::uint64_t> want{m.value};
          while (!want.empty()) {
            const std::uint64_t id = *want.begin();
            want.erase(want.begin());
            if (!type_done_.insert(id).second) continue;
            std::shared_ptr<const TypeCache::Entry> t = types_->get(id, facts_);
            lift_.types[id] = t->encoded;
            for (std::uint64_t r : t->refs)
              if (!type_done_.contains(r)) want.insert(r);
          }
        }
        break;
      default:
        // Another function's comments, overrides or registers, or an
        // observe-mode query: never asked in a lift mode.
        break;
    }
  }
  add_types();
  return changed;
}

Bundle LiftBundleBuilder::bundle() {
  Bundle b = program_.bundle(mode_, entry_);
  b.chunks = chunks_;
  b.joins = joins_;
  b.lift = lift_;
  b.extra = extra_;
  // Canonical tables: sorted by encoding, indexes remapped.
  auto canon = [](auto &table) {
    std::vector<std::pair<std::string, std::int32_t>> keyed;
    for (std::size_t i = 0; i < table.size(); ++i)
      keyed.emplace_back(facts::encode_to_string(table[i]), static_cast<std::int32_t>(i));
    std::sort(keyed.begin(), keyed.end());
    std::vector<std::int32_t> remap(table.size());
    std::remove_reference_t<decltype(table)> sorted;
    for (std::size_t k = 0; k < keyed.size(); ++k) {
      remap[static_cast<std::size_t>(keyed[k].second)] = static_cast<std::int32_t>(k);
      sorted.push_back(std::move(table[static_cast<std::size_t>(keyed[k].second)]));
    }
    table = std::move(sorted);
    return remap;
  };
  const auto fr = canon(b.lift.functions), dr = canon(b.lift.data), xr = canon(b.lift.externals),
             lr = canon(b.lift.labels);
  auto map = [](std::int32_t i, const std::vector<std::int32_t> &r) { return i < 0 ? i : r[static_cast<std::size_t>(i)]; };
  for (auto &[k, a] : b.lift.addresses) {
    a.starts = map(a.starts, fr);
    a.contains = map(a.contains, fr);
    a.data = map(a.data, dr);
    a.external = map(a.external, xr);
    a.label = map(a.label, lr);
  }
  // Flow overrides only matter where the decompiler decodes, which is
  // within the bytes the bundle holds (a decode elsewhere is a miss).
  std::erase_if(b.lift.flow_overrides, [&](const auto &o) { return !chunks_.contains(o.first / kChunk); });
  return b;
}

}  // namespace revkit::decompd
