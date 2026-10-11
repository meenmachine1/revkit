#include "revkit/plugins/queries.h"

// Discovery's pooled SLEIGH decoder over store bytes (src/analysis).
#include "internal.h"

#include <algorithm>

namespace revkit::plugins {

// ---- inputs ----------------------------------------------------------------

void Block::encode(facts::Encoder &e) const {
  e.bytes(name);
  e.varint(start);
  e.varint(size);
  e.u8(perms);
  e.u8(initialized ? 1 : 0);
}

Block Block::decode(facts::Decoder &d) {
  Block b;
  b.name = d.bytes();
  b.start = d.varint();
  b.size = d.varint();
  b.perms = d.u8();
  b.initialized = d.u8() != 0;
  return b;
}

const Block *ProgramFacts::block_at(std::uint64_t a) const {
  auto it = std::upper_bound(blocks.begin(), blocks.end(), a, [](std::uint64_t x, const Block &b) { return x < b.start; });
  if (it == blocks.begin()) return nullptr;
  --it;
  return a - it->start < it->size ? &*it : nullptr;
}

void ProgramFacts::encode(facts::Encoder &e) const {
  facts::encode(e, blocks);
  facts::encode(e, entry);
  e.varint(file_space);
  e.varint(file_size);
}

ProgramFacts ProgramFacts::decode(facts::Decoder &d) {
  ProgramFacts p;
  p.blocks = facts::decode<std::vector<Block>>(d);
  p.entry = facts::decode<std::optional<std::uint64_t>>(d);
  p.file_space = facts::decode<facts::SpaceId>(d);
  p.file_size = d.varint();
  return p;
}

ProgramFacts describe(const loader::Image &image, facts::SpaceId file_space, std::uint64_t file_size) {
  ProgramFacts pf;
  for (const loader::Block &b : image.blocks) {
    if (b.size == 0) continue;
    Block out;
    out.name = b.name;
    out.start = b.start;
    out.size = b.size;
    out.perms = static_cast<std::uint8_t>((b.perms.read ? abi::kRead : 0) | (b.perms.write ? abi::kWrite : 0) |
                                          (b.perms.exec ? abi::kExec : 0));
    out.initialized = b.initialized;
    pf.blocks.push_back(std::move(out));
  }
  std::sort(pf.blocks.begin(), pf.blocks.end(), [](const Block &a, const Block &b) { return a.start < b.start; });
  // Overlapping blocks (rare: ELF sections sharing addresses) would make
  // block_at ambiguous; keep the first of each.
  std::vector<Block> disjoint;
  for (Block &b : pf.blocks)
    if (disjoint.empty() || b.start > disjoint.back().start + (disjoint.back().size - 1)) disjoint.push_back(std::move(b));
  pf.blocks = std::move(disjoint);
  pf.entry = image.entry;
  pf.file_space = file_space;
  pf.file_size = file_space ? file_size : 0;
  return pf;
}

void stage_program(facts::FactDb::Transaction &tx, const analysis::ProgramKey &program, const loader::Image &image,
                   facts::SpaceId file_space, std::uint64_t file_size) {
  tx.set<Program>(program, describe(image, file_space, file_size));
}

// ---- fact blobs ---------------------------------------------------------------

ProgramInfoBlob::Value ProgramInfoBlob::compute(facts::QueryContext &ctx, const Key &key) {
  auto info = ctx.get<analysis::Program>(key);
  auto pf = ctx.get<Program>(key);
  abi::Writer w;
  auto rec = w.begin();
  w.str(info->language);
  w.str(info->compiler);
  w.u8(info->pointer_size);
  w.u8(info->big_endian ? 1 : 0);
  w.u8(pf->entry ? 1 : 0);
  w.u64(pf->entry.value_or(0));
  w.u64(pf->file_size);
  // The memory map as edited (docs/memory-map.md), else the loader's blocks.
  std::vector<Block> blocks = pf->blocks;
  if (auto map = ctx.get<analysis::MemoryMap>(key); map->edited) {
    blocks.clear();
    for (const analysis::MemoryBlock &m : map->blocks)
      blocks.push_back({m.name, m.range.first, m.range.last - m.range.first + 1,
                        static_cast<std::uint8_t>((m.read ? abi::kRead : 0) | (m.write ? abi::kWrite : 0) | (m.exec ? abi::kExec : 0)),
                        m.initialized});
  }
  auto list = w.begin();
  for (const Block &b : blocks) {
    auto br = w.begin();
    w.str(b.name);
    w.u64(b.start);
    w.u64(b.size);
    w.u8(b.perms);
    w.u8(b.initialized ? 1 : 0);
    w.end_record(br);
  }
  w.end_list(list, static_cast<std::uint32_t>(blocks.size()));
  w.end_record(rec);
  return std::move(w).take();
}

namespace {

void write_ranges(abi::Writer &w, const facts::AddressSet &body) {
  auto list = w.begin();
  for (const facts::AddressRange &r : body.ranges()) {
    w.u64(r.first.offset);
    w.u64(r.last.offset);
  }
  w.end_list(list, static_cast<std::uint32_t>(body.ranges().size()));
}

std::uint32_t function_flags(const analysis::FunctionInfo &f) {
  std::uint32_t flags = 0;
  if (f.no_return != analysis::NoReturnReason::none) flags |= 1;
  if (f.flags & analysis::kFunctionThunk) flags |= 2;
  if (f.flags & analysis::kFunctionDiscovered) flags |= 4;
  if (f.flags & analysis::kFunctionAssertedEntry) flags |= 8;
  return flags;
}

void write_varnode(abi::Writer &w, const lift::Varnode &v) {
  auto rec = w.begin();
  w.str(v.referenced_space.empty() ? v.space : v.referenced_space);
  w.u64(v.offset);
  w.u32(v.size);
  w.end_record(rec);
}

}  // namespace

FunctionsBlob::Value FunctionsBlob::compute(facts::QueryContext &ctx, const Key &key) {
  auto functions = ctx.get<analysis::Functions>(key);
  abi::Writer w;
  auto list = w.begin();
  for (const analysis::FunctionInfo &f : functions->functions) {
    auto rec = w.begin();
    w.u64(f.entry.offset);
    w.str(*ctx.get<Name>(analysis::Location{key, f.entry.offset}));
    w.u32(function_flags(f));
    write_ranges(w, f.body);
    w.end_record(rec);
  }
  w.end_list(list, static_cast<std::uint32_t>(functions->functions.size()));
  return std::move(w).take();
}

CodeBlob::Value CodeBlob::compute(facts::QueryContext &ctx, const Key &key) {
  auto f = ctx.get<analysis::Function>(key);
  if (f->body.empty()) return {};
  auto info = ctx.get<analysis::Program>(key.program);
  analysis::detail::ByteReader bytes(ctx, *info);
  analysis::detail::Decoder decoder(*info);
  abi::Writer w;
  auto rec = w.begin();
  w.u64(key.address);
  auto list = w.begin();
  std::uint32_t count = 0;
  constexpr std::uint32_t kMaxInstructions = 200'000;
  for (const facts::AddressRange &r : f->body.ranges()) {
    for (std::uint64_t a = r.first.offset; a <= r.last.offset && count < kMaxInstructions;) {
      auto insn = decoder.decode(a, bytes);
      if (!insn || insn->length == 0) break;
      auto ir = w.begin();
      w.u64(insn->address);
      w.u32(insn->length + insn->delay_slot);
      w.str(insn->mnemonic);
      w.str(insn->text);
      auto ops = w.begin();
      for (const lift::PcodeOp &op : insn->pcode) {
        auto orec = w.begin();
        w.str(op.opcode);
        w.u8(op.output ? 1 : 0);
        if (op.output) write_varnode(w, *op.output);
        auto ins = w.begin();
        for (const lift::Varnode &v : op.inputs) write_varnode(w, v);
        w.end_list(ins, static_cast<std::uint32_t>(op.inputs.size()));
        w.end_record(orec);
      }
      w.end_list(ops, static_cast<std::uint32_t>(insn->pcode.size()));
      w.end_record(ir);
      ++count;
      const std::uint64_t next = a + insn->length + insn->delay_slot;
      if (next <= a) break;
      a = next;
    }
  }
  w.end_list(list, count);
  w.end_record(rec);
  return std::move(w).take();
}

Name::Value Name::compute(facts::QueryContext &ctx, const Key &key) {
  auto info = ctx.get<analysis::Program>(key.program);
  const facts::Address at{info->space, key.address};
  for (const facts::FactKey &k : facts::asserted_at(ctx, facts::FactKind::Name, at)) {
    if (!k.sub.empty()) continue;  // locals: "local:<storage>"
    auto v = ctx.get<facts::AssertedFact>(k);
    if (const auto *s = std::get_if<std::string>(v.get()); s && !s->empty()) return *s;
  }
  return ctx.get<analysis::Function>(key)->name;
}

// ---- analyzers ---------------------------------------------------------------

void AnalyzeKey::encode(facts::Encoder &e) const {
  e.bytes(plugin);
  e.bytes(fingerprint);
  program.encode(e);
  e.u8(static_cast<std::uint8_t>(scope));
  e.varint(address);
}

AnalyzeKey AnalyzeKey::decode(facts::Decoder &d) {
  AnalyzeKey k;
  k.plugin = d.bytes();
  k.fingerprint = d.bytes();
  k.program = analysis::ProgramKey::decode(d);
  k.scope = static_cast<abi::Scope>(d.u8());
  k.address = d.varint();
  return k;
}

std::string Analyze::describe(const Key &k) {
  std::string s = k.plugin + ", " + k.program.id;
  if (k.scope == abi::Scope::function) s += ":" + analysis::describe(analysis::Location{k.program, k.address}).substr(k.program.id.size() + 1);
  return s;
}

void AnalyzeOutput::encode(facts::Encoder &e) const {
  e.u8(static_cast<std::uint8_t>(failure));
  e.bytes(error);
  e.varint(facts.size());
  for (const DerivedItem &f : facts) {
    e.u8(static_cast<std::uint8_t>(f.kind));
    e.varint(f.address);
    e.bytes(f.text);
    e.bytes(f.sub);
  }
  e.varint(fuel);
  facts::encode(e, log);
}

AnalyzeOutput AnalyzeOutput::decode(facts::Decoder &d) {
  AnalyzeOutput o;
  o.failure = static_cast<Failure>(d.u8());
  o.error = d.bytes();
  std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    DerivedItem f;
    f.kind = static_cast<abi::FactKind>(d.u8());
    f.address = d.varint();
    f.text = d.bytes();
    f.sub = d.bytes();
    o.facts.push_back(std::move(f));
  }
  o.fuel = d.varint();
  o.log = facts::decode<std::vector<std::string>>(d);
  return o;
}

Analyze::Value Analyze::compute(facts::QueryContext &ctx, const Key &key) {
  auto plugin = find_by_fingerprint(key.fingerprint);
  if (!plugin) throw std::runtime_error("plugin " + key.plugin + " (module " + key.fingerprint + ") is not loaded");
  StoreFacts<facts::QueryContext> facts(ctx, key.program);
  AnalyzeOutput out;
  CallResult r = run_analyzer(*plugin, key.scope, key.address, facts, out.facts);
  // Wall-clock time isn't a function of the inputs: don't memoize it.
  if (r.failure == Failure::timeout) throw std::runtime_error("plugin " + key.plugin + " timed out: " + r.error);
  out.failure = r.failure;
  out.error = std::move(r.error);
  out.fuel = r.fuel_consumed;
  out.log = std::move(r.log);
  if (!r.ok()) ctx.set_confidence(facts::Confidence::Uncertain);
  return out;
}

std::vector<AnalyzeKey> analyze_keys(const facts::Snapshot &snap, const Plugin &p, const analysis::ProgramKey &program,
                                     std::uint64_t first, std::uint64_t last) {
  std::vector<AnalyzeKey> keys;
  if (p.manifest().kind != Kind::analyzer) return keys;
  if (!p.manifest().function_scope) {
    keys.push_back({p.id(), p.fingerprint(), program, abi::Scope::program, 0});
    return keys;
  }
  auto functions = snap.get<analysis::Functions>(program);
  for (const analysis::FunctionInfo &f : functions->functions)
    if (f.entry.offset >= first && f.entry.offset <= last)
      keys.push_back({p.id(), p.fingerprint(), program, abi::Scope::function, f.entry.offset});
  return keys;
}

void register_queries(facts::Engine &engine) {
  engine.add_input<Program>();
  engine.add_query<ProgramInfoBlob>();
  engine.add_query<FunctionsBlob>();
  engine.add_query<CodeBlob>();
  engine.add_query<Name>();
  engine.add_query<Analyze>();
}

}  // namespace revkit::plugins
