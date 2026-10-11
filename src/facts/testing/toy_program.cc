#include "toy_program.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <optional>

namespace revkit::facts::toy {

namespace {

constexpr std::uint64_t kMaxFunctionBytes = 1 << 20;

std::uint32_t le32(std::string_view b, std::size_t at) {
  std::uint32_t v = 0;
  for (std::size_t i = 0; i < 4; ++i) v |= std::uint32_t{static_cast<unsigned char>(b[at + i])} << (8 * i);
  return v;
}

void put_le32(std::string &out, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>(v >> (8 * i)));
}

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%llx", static_cast<unsigned long long>(v));
  return buf;
}

// splitmix64: tiny, and unlike <random> distributions, identical everywhere.
struct Rng {
  std::uint64_t s;
  std::uint64_t next() {
    std::uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
  }
  std::uint64_t below(std::uint64_t n) { return n ? next() % n : 0; }
};

bool has_reg(std::uint8_t op) { return op >= kAlu && op <= kLoadField; }
bool has_operand(std::uint8_t op) { return op >= kMovImm && op <= kJump; }

}  // namespace

int length_of(std::uint8_t opcode) {
  switch (opcode) {
    case kAlu: return 2;
    case kMovImm: return 6;
    case kLoad: return 6;
    case kLoadField: return 7;
    case kCall: return 5;
    case kJump: return 2;
    case kRet: return 1;
    default: return -1;
  }
}

// Per insn: one byte holding the opcode (0 for invalid) and a "gap follows"
// bit, then only the fields that opcode has. Offsets are implied by lengths.
void InsnList::encode(Encoder &e) const {
  facts::encode(e, start);
  facts::encode(e, truncated);
  e.varint(insns.size());
  std::uint64_t expect = 0;
  for (const Insn &in : insns) {
    std::uint8_t code = in.op == kInvalid ? 0 : in.op;
    bool gap = in.offset != expect;
    e.u8(static_cast<std::uint8_t>(code | (gap ? 0x80 : 0)));
    if (gap) e.varint(in.offset - expect);
    if (has_reg(in.op)) e.u8(in.reg);
    if (has_operand(in.op)) e.varint(in.operand);
    if (in.op == kLoadField) e.u8(in.field);
    expect = in.offset + in.len;
  }
}

InsnList InsnList::decode(Decoder &d) {
  InsnList l;
  l.start = facts::decode<Address>(d);
  l.truncated = facts::decode<bool>(d);
  std::size_t n = d.count();
  l.insns.reserve(n);
  std::uint64_t expect = 0;
  for (std::size_t i = 0; i < n; ++i) {
    Insn in;
    std::uint8_t b = d.u8();
    std::uint8_t code = b & 0x7f;
    if (code > kRet) throw DecodeError("bad toy opcode");
    in.op = code == 0 ? std::uint8_t{kInvalid} : code;
    in.len = static_cast<std::uint8_t>(code == 0 ? 1 : length_of(code));
    in.offset = expect + ((b & 0x80) ? d.varint() : 0);
    if (has_reg(in.op)) in.reg = d.u8();
    if (has_operand(in.op)) in.operand = facts::decode<std::uint32_t>(d);
    if (in.op == kLoadField) in.field = d.u8();
    expect = in.offset + in.len;
    l.insns.push_back(in);
  }
  return l;
}

void Xref::encode(Encoder &e) const {
  facts::encode(e, from);
  facts::encode(e, to);
  facts::encode(e, kind);
  e.u8(field);
}

Xref Xref::decode(Decoder &d) {
  Xref x;
  x.from = facts::decode<Address>(d);
  x.to = facts::decode<Address>(d);
  x.kind = facts::decode<XrefKind>(d);
  if (x.kind > XrefKind::Field) throw DecodeError("bad xref kind");
  x.field = d.u8();
  return x;
}

void Field::encode(Encoder &e) const {
  e.bytes(name);
  e.bytes(type);
  e.varint(offset);
  e.varint(size);
}

Field Field::decode(Decoder &d) {
  Field f;
  f.name = d.bytes();
  f.type = d.bytes();
  f.offset = facts::decode<std::uint32_t>(d);
  f.size = facts::decode<std::uint32_t>(d);
  return f;
}

const Field *Layout::at(std::uint32_t offset) const {
  for (const Field &f : fields)
    if (offset >= f.offset && offset < f.offset + f.size) return &f;
  return nullptr;
}

void Layout::encode(Encoder &e) const {
  facts::encode(e, fields);
  e.varint(size);
}

Layout Layout::decode(Decoder &d) {
  Layout l;
  l.fields = facts::decode<std::vector<Field>>(d);
  l.size = facts::decode<std::uint32_t>(d);
  return l;
}

Layout parse_layout(std::string_view def) {
  Layout l;
  std::uint32_t align = 1;
  while (!def.empty()) {
    auto semi = def.find(';');
    std::string_view item = def.substr(0, semi);
    def = semi == std::string_view::npos ? std::string_view() : def.substr(semi + 1);
    if (item.find_first_not_of(' ') == std::string_view::npos) continue;
    auto colon = item.find(':');
    auto trim = [](std::string_view v) {
      while (!v.empty() && v.front() == ' ') v.remove_prefix(1);
      while (!v.empty() && v.back() == ' ') v.remove_suffix(1);
      return std::string(v);
    };
    Field f;
    f.name = trim(item.substr(0, colon));
    f.type = colon == std::string_view::npos ? "int" : trim(item.substr(colon + 1));
    f.size = f.type == "char" ? 1 : f.type == "short" ? 2 : (f.type == "ptr" || f.type == "long") ? 8 : 4;
    f.offset = (l.size + f.size - 1) / f.size * f.size;
    l.size = f.offset + f.size;
    align = std::max(align, f.size);
    l.fields.push_back(std::move(f));
  }
  l.size = (l.size + align - 1) / align * align;
  return l;
}

InsnList DecodeFunction::compute(QueryContext &ctx, const Address &entry) {
  InsnList out;
  out.start = entry;
  auto bounds = ctx.get<AssertedFact>(FactKey::function(entry));
  const auto *body = std::get_if<AddressSet>(bounds.get());
  if (!body || body->empty()) {
    ctx.set_confidence(Confidence::Uncertain);
    return out;
  }
  out.start = *body->min();
  for (const AddressRange &r : body->ranges()) {
    std::uint64_t len = r.span() + 1;
    if (r.span() >= kMaxFunctionBytes) {
      len = kMaxFunctionBytes;
      out.truncated = true;
    }
    std::string bytes = read_bytes(ctx, r.first, static_cast<std::size_t>(len));
    if (bytes.size() < len) out.truncated = true;
    std::size_t p = 0;
    while (p < bytes.size()) {
      Insn in;
      in.offset = r.first.offset + p - out.start.offset;
      auto opcode = static_cast<std::uint8_t>(bytes[p]);
      int l = length_of(opcode);
      if (l < 0) {
        in.op = kInvalid;
        in.len = 1;
      } else {
        if (p + static_cast<std::size_t>(l) > bytes.size()) {
          out.truncated = true;
          break;
        }
        in.op = opcode;
        in.len = static_cast<std::uint8_t>(l);
        if (has_reg(opcode)) in.reg = static_cast<std::uint8_t>(bytes[p + 1]);
        if (opcode == kCall) in.operand = le32(bytes, p + 1);
        else if (opcode == kJump) in.operand = static_cast<std::uint8_t>(bytes[p + 1]);
        else if (has_operand(opcode)) in.operand = le32(bytes, p + 2);
        if (opcode == kLoadField) in.field = static_cast<std::uint8_t>(bytes[p + 6]);
      }
      out.insns.push_back(in);
      p += in.len;
    }
  }
  return out;
}

std::vector<Xref> FunctionXrefs::compute(QueryContext &ctx, const Address &entry) {
  auto insns = ctx.get<DecodeFunction>(entry);
  std::vector<Xref> out;
  for (const Insn &in : insns->insns) {
    Address from{insns->start.space, insns->start.offset + in.offset};
    Address to{insns->start.space, in.operand};
    if (in.op == kCall) out.push_back({from, to, XrefKind::Call, 0});
    else if (in.op == kLoad) out.push_back({from, to, XrefKind::Data, 0});
    else if (in.op == kLoadField) out.push_back({from, to, XrefKind::Field, in.field});
  }
  return out;
}

Layout StructLayout::compute(QueryContext &ctx, const std::string &type_name) {
  auto def = ctx.get<AssertedFact>(FactKey::type_def(type_name));
  if (const auto *s = std::get_if<std::string>(def.get())) return parse_layout(*s);
  ctx.set_confidence(Confidence::Uncertain);
  return {};
}

std::string FunctionSummary::compute(QueryContext &ctx, const Address &entry) {
  std::map<Address, std::string> names;
  auto name_of = [&](Address a) -> const std::string & {
    auto it = names.find(a);
    if (it != names.end()) return it->second;
    auto v = ctx.get<AssertedFact>(FactKey::name(a));
    const auto *s = std::get_if<std::string>(v.get());
    return names.emplace(a, s ? *s : "sub_" + hex(a.offset)).first->second;
  };
  std::map<Address, Ref<FactValue>> types;
  std::map<std::string, Ref<Layout>> layouts;

  auto xrefs = ctx.get<FunctionXrefs>(entry);
  std::string out = name_of(entry) + "() {\n";
  for (const Xref &x : *xrefs) {
    if (x.kind == XrefKind::Call) {
      out += "  " + name_of(x.to) + "();\n";
    } else if (x.kind == XrefKind::Field) {
      auto &t = types[x.to];
      if (!t) t = ctx.get<AssertedFact>(FactKey::type(x.to));
      std::string field = "+" + std::to_string(x.field);
      if (const auto *tn = std::get_if<std::string>(t.get())) {
        auto &l = layouts[*tn];
        if (!l) l = ctx.get<StructLayout>(*tn);
        if (const Field *f = l->at(x.field)) field = f->name;
      }
      out += "  " + name_of(x.to) + "." + field + ";\n";
    }
  }
  return out + "}\n";
}

void register_queries(Engine &engine) {
  engine.add_query<DecodeFunction>();
  engine.add_query<FunctionXrefs>();
  engine.add_query<StructLayout>();
  engine.add_query<FunctionSummary>();
}

std::string struct_name(std::uint32_t i) { return "S" + std::to_string(i); }

std::string struct_def(std::uint32_t i) {
  std::string def;
  for (std::uint32_t f = 0; f < 2 + i % 6; ++f) def += "f" + std::to_string(f) + ":int;";
  return def;
}

namespace {

struct FunctionPlan {
  std::uint64_t seed;
  std::uint32_t count;
};

FunctionPlan plan(const ProgramSpec &spec, std::uint64_t i) {
  Rng r{spec.seed * 0x100000001b3ULL ^ (i + 1)};
  std::uint32_t n = spec.insns_per_function;
  std::uint32_t count = std::max<std::uint32_t>(1, n / 2 + static_cast<std::uint32_t>(r.below(n + 1)));
  return {r.next(), count};
}

std::uint8_t pick_op(Rng &kinds) {
  std::uint64_t k = kinds.below(100);
  return k < 35 ? kAlu : k < 55 ? kMovImm : k < 70 ? kLoad : k < 82 ? kLoadField : k < 92 ? kCall : kJump;
}

std::uint64_t function_size(const FunctionPlan &p) {
  Rng kinds{p.seed};
  std::uint64_t size = 1;  // ret
  for (std::uint32_t j = 0; j + 1 < p.count; ++j) size += length_of(pick_op(kinds));
  return size;
}

}  // namespace

Program generate(FactDb &db, const ProgramSpec &spec,
                 const std::function<void(std::uint64_t)> &progress) {
  Program prog;
  for (std::uint32_t s = 0; s < spec.structs; ++s) prog.structs.push_back(struct_name(s));
  for (std::uint32_t g = 0; g < spec.globals; ++g) {
    prog.globals.push_back(Address{spec.space, spec.data_base + 16 * std::uint64_t{g}});
    prog.global_struct.push_back(spec.structs ? g % spec.structs : 0);
  }

  // Pass 1: sizes, hence entry points, so calls can target any function.
  prog.functions.reserve(spec.functions);
  std::uint64_t at = spec.text_base;
  for (std::uint64_t i = 0; i < spec.functions; ++i) {
    prog.functions.push_back(Address{spec.space, at});
    at += function_size(plan(spec, i));
  }
  prog.text_bytes = at - spec.text_base;

  std::optional<FactDb::Transaction> tx(db.begin());
  for (std::uint32_t s = 0; s < spec.structs; ++s)
    tx->assert_fact(kImporter, FactKey::type_def(struct_name(s)), struct_def(s));
  for (std::uint32_t g = 0; g < spec.globals; ++g) {
    tx->assert_fact(kImporter, FactKey::name(prog.globals[g]), "g" + std::to_string(g));
    if (spec.structs)
      tx->assert_fact(kImporter, FactKey::type(prog.globals[g]), struct_name(prog.global_struct[g]));
  }
  prog.assertions += spec.structs + spec.globals * (spec.structs ? 2 : 1);

  // Pass 2: bytes and assertions, committed in batches.
  std::string buf;
  std::uint64_t buf_start = spec.text_base;
  Rng names{spec.seed ^ 0x5eed};
  for (std::uint64_t i = 0; i < spec.functions; ++i) {
    FunctionPlan p = plan(spec, i);
    Rng kinds{p.seed};
    Rng ops{p.seed ^ 0xa5a5a5a5a5a5a5a5ULL};
    std::size_t begin = buf.size();
    for (std::uint32_t j = 0; j + 1 < p.count; ++j) {
      std::uint8_t op = pick_op(kinds);
      buf.push_back(static_cast<char>(op));
      if (has_reg(op)) buf.push_back(static_cast<char>(ops.below(16)));
      if (op == kMovImm) {
        put_le32(buf, static_cast<std::uint32_t>(ops.next()));
      } else if (op == kLoad || op == kLoadField) {
        std::uint64_t g = ops.below(std::max<std::uint32_t>(1, spec.globals));
        put_le32(buf, static_cast<std::uint32_t>(spec.data_base + 16 * g));
        if (op == kLoadField) {
          std::uint32_t nfields = spec.structs ? 2 + prog.global_struct[g] % 6 : 2;
          buf.push_back(static_cast<char>(4 * ops.below(nfields)));
        }
      } else if (op == kCall) {
        put_le32(buf, static_cast<std::uint32_t>(prog.functions[ops.below(spec.functions)].offset));
      } else if (op == kJump) {
        buf.push_back(static_cast<char>(ops.below(256)));
      }
    }
    buf.push_back(static_cast<char>(kRet));
    prog.instructions += p.count;

    Address entry = prog.functions[i];
    auto body = AddressRange::sized(entry, buf.size() - begin);
    tx->assert_fact(kImporter, FactKey::function(entry), AddressSet(*body));
    ++prog.assertions;
    if (names.below(100) < spec.named_percent) {
      tx->assert_fact(kImporter, FactKey::name(entry), "fn_" + std::to_string(i));
      ++prog.assertions;
    }

    bool last = i + 1 == spec.functions;
    if (last || (i + 1) % spec.functions_per_commit == 0) {
      tx->write_bytes(Address{spec.space, buf_start}, buf);
      buf_start += buf.size();
      buf.clear();
      tx->commit();
      tx.reset();
      if (!last) tx.emplace(db.begin());
      if (progress) progress(i + 1);
    }
  }
  if (tx) tx->commit();
  return prog;
}

}  // namespace revkit::facts::toy
