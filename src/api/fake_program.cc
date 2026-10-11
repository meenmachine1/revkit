#include "fake_program.h"

#include <algorithm>
#include <cstdio>
#include <utility>

namespace revkit::api::fake_internal {
namespace {

using Op = pb::PcodeOpcode;

struct RegInfo {
  const char *name;
  std::uint64_t offset;
  std::uint32_t size;
};

// Ghidra x86-64 register offsets.
constexpr RegInfo kRegisters[] = {
    {"RAX", 0x0, 8},   {"EAX", 0x0, 4},  {"RCX", 0x8, 8},    {"ECX", 0x8, 4},
    {"RDX", 0x10, 8},  {"EDX", 0x10, 4}, {"RBX", 0x18, 8},   {"RSP", 0x20, 8},
    {"RBP", 0x28, 8},  {"EBP", 0x28, 4}, {"RSI", 0x30, 8},   {"ESI", 0x30, 4},
    {"RDI", 0x38, 8},  {"EDI", 0x38, 4}, {"RIP", 0x288, 8},  {"CF", 0x200, 1},
    {"ZF", 0x206, 1},  {"SF", 0x207, 1}, {"OF", 0x20b, 1},
};

VN R(const char *name) { return *RegisterVarnode(name); }
VN C(std::uint64_t value, std::uint32_t size) { return {"const", value, size, {}}; }
VN U(std::uint64_t offset, std::uint32_t size) { return {"unique", offset, size, {}}; }
VN Ram(std::uint64_t offset, std::uint32_t size) { return {"ram", offset, size, {}}; }
// LOAD/STORE name their space with a constant holding the space id; Ghidra's
// x86-64 ram space id is 0x1b8 in printed p-code, and clients only display it.
VN RamSpace() { return C(0x1b8, 8); }

PcodeDef P(Op op, std::optional<VN> out, std::vector<VN> in) {
  return {op, std::move(out), std::move(in)};
}

// Flag updates shared by logical ops (XOR, TEST, AND).
void LogicFlags(std::vector<PcodeDef> &p, const VN &result, std::uint32_t size) {
  p.push_back(P(Op::PCODE_OPCODE_COPY, R("CF"), {C(0, 1)}));
  p.push_back(P(Op::PCODE_OPCODE_COPY, R("OF"), {C(0, 1)}));
  p.push_back(P(Op::PCODE_OPCODE_INT_SLESS, R("SF"), {result, C(0, size)}));
  p.push_back(P(Op::PCODE_OPCODE_INT_EQUAL, R("ZF"), {result, C(0, size)}));
}

std::vector<PcodeDef> Push(const VN &value) {
  return {P(Op::PCODE_OPCODE_INT_SUB, R("RSP"), {R("RSP"), C(8, 8)}),
          P(Op::PCODE_OPCODE_STORE, std::nullopt, {RamSpace(), R("RSP"), value})};
}

std::vector<PcodeDef> Call(std::uint64_t ret, std::uint64_t target) {
  auto p = Push(C(ret, 8));
  p.push_back(P(Op::PCODE_OPCODE_CALL, std::nullopt, {Ram(target, 8)}));
  return p;
}

std::vector<PcodeDef> Ret() {
  return {P(Op::PCODE_OPCODE_LOAD, R("RIP"), {RamSpace(), R("RSP")}),
          P(Op::PCODE_OPCODE_INT_ADD, R("RSP"), {R("RSP"), C(8, 8)}),
          P(Op::PCODE_OPCODE_RETURN, std::nullopt, {R("RIP")})};
}

std::vector<PcodeDef> Xor32(const char *dst, const char *src, const char *dst64) {
  std::vector<PcodeDef> p;
  p.push_back(P(Op::PCODE_OPCODE_INT_XOR, R(dst), {R(dst), R(src)}));
  p.push_back(P(Op::PCODE_OPCODE_INT_ZEXT, R(dst64), {R(dst)}));
  LogicFlags(p, R(dst), 4);
  return p;
}

std::vector<PcodeDef> Mov32Imm(const char *dst, const char *dst64, std::uint64_t imm) {
  return {P(Op::PCODE_OPCODE_COPY, R(dst), {C(imm, 4)}),
          P(Op::PCODE_OPCODE_INT_ZEXT, R(dst64), {R(dst)})};
}

std::vector<PcodeDef> Add64(const VN &dst, const VN &src) {
  return {P(Op::PCODE_OPCODE_INT_CARRY, R("CF"), {dst, src}),
          P(Op::PCODE_OPCODE_INT_SCARRY, R("OF"), {dst, src}),
          P(Op::PCODE_OPCODE_INT_ADD, dst, {dst, src}),
          P(Op::PCODE_OPCODE_INT_SLESS, R("SF"), {dst, C(0, 8)}),
          P(Op::PCODE_OPCODE_INT_EQUAL, R("ZF"), {dst, C(0, 8)})};
}

std::string Hex8(std::uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%08llx", static_cast<unsigned long long>(v));
  return buf;
}

// Decompiler template helpers.
TokDef Kw(std::string t) { return {pb::CODE_TOKEN_KIND_KEYWORD, std::move(t)}; }
TokDef Sp() { return {pb::CODE_TOKEN_KIND_WHITESPACE, " "}; }
TokDef Pu(std::string t, std::uint64_t addr = 0) {
  TokDef d{pb::CODE_TOKEN_KIND_PUNCTUATION, std::move(t)};
  d.addr = addr;
  return d;
}
TokDef Opr(std::string t, std::uint64_t addr, std::vector<std::uint32_t> vns = {}) {
  TokDef d{pb::CODE_TOKEN_KIND_OPERATOR, std::move(t)};
  d.addr = addr;
  d.vns = std::move(vns);
  return d;
}
TokDef Var(int var, std::uint64_t addr, std::vector<std::uint32_t> vns) {
  TokDef d{pb::CODE_TOKEN_KIND_LOCAL_VARIABLE, {}};
  d.var = var;
  d.addr = addr;
  d.vns = std::move(vns);
  return d;
}
TokDef Num(std::uint64_t value, std::string text, std::uint64_t addr,
           std::vector<std::uint32_t> vns = {}) {
  TokDef d{pb::CODE_TOKEN_KIND_CONSTANT, std::move(text)};
  d.addr = addr;
  d.vns = std::move(vns);
  d.value = value;
  return d;
}
TokDef Fn(std::uint64_t target, std::uint64_t addr) {
  TokDef d{pb::CODE_TOKEN_KIND_FUNCTION_NAME, {}};
  d.target = target;
  d.addr = addr;
  return d;
}

}  // namespace

std::optional<VN> RegisterVarnode(const std::string &name) {
  for (const auto &r : kRegisters)
    if (name == r.name) return VN{"register", r.offset, r.size, r.name};
  return std::nullopt;
}

std::string FakeHash(const std::string &text) {
  std::uint64_t h = 0xcbf29ce484222325ull;
  for (unsigned char c : text) {
    h ^= c;
    h *= 0x100000001b3ull;
  }
  char buf[32];
  std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(h));
  return buf;
}

const SyntheticProgram &SyntheticProgram::Get() {
  static const SyntheticProgram program;
  return program;
}

SyntheticProgram::SyntheticProgram() {
  using K = pb::XrefKind;
  using F = pb::FlowKind;
  const std::uint64_t kHello = 0x402000, kResult = 0x403000;

  // --- .text --------------------------------------------------------------
  // entry: 0x401000..0x401009
  insns.push_back({0x401000, {0x31, 0xed}, "XOR", {{"EBP"}, {"EBP"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   Xor32("EBP", "EBP", "RBP")});
  insns.push_back({0x401002, {0xe8, 0x09, 0x00, 0x00, 0x00}, "CALL", {{"{}", 0x401010}},
                   F::FLOW_KIND_CALL, {0x401010}, {{0x401010, K::XREF_KIND_CALL, 0}},
                   Call(0x401007, 0x401010)});
  insns.push_back({0x401007, {0x89, 0xc7}, "MOV", {{"EDI"}, {"EAX"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_COPY, R("EDI"), {R("EAX")}),
                    P(Op::PCODE_OPCODE_INT_ZEXT, R("RDI"), {R("EDI")})}});
  insns.push_back({0x401009, {0xf4}, "HLT", {}, F::FLOW_KIND_TERMINATOR, {}, {},
                   {P(Op::PCODE_OPCODE_CALLOTHER, std::nullopt, {C(0, 4)})}});

  // main: 0x401010..0x40102e
  insns.push_back({0x401010, {0x55}, "PUSH", {{"RBP"}}, F::FLOW_KIND_FALL_THROUGH, {}, {}, Push(R("RBP"))});
  insns.push_back({0x401011, {0x48, 0x89, 0xe5}, "MOV", {{"RBP"}, {"RSP"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_COPY, R("RBP"), {R("RSP")})}});
  insns.push_back({0x401014, {0x48, 0x8d, 0x3d, 0xe5, 0x0f, 0x00, 0x00}, "LEA", {{"RDI"}, {"[{}]", kHello}},
                   F::FLOW_KIND_FALL_THROUGH, {}, {{kHello, K::XREF_KIND_DATA_POINTER, 1}},
                   {P(Op::PCODE_OPCODE_COPY, R("RDI"), {C(kHello, 8)})}});
  insns.push_back({0x40101b, {0xbe, 0x05, 0x00, 0x00, 0x00}, "MOV", {{"ESI"}, {"0x5"}},
                   F::FLOW_KIND_FALL_THROUGH, {}, {}, Mov32Imm("ESI", "RSI", 5)});
  insns.push_back({0x401020, {0xe8, 0x1b, 0x00, 0x00, 0x00}, "CALL", {{"{}", 0x401040}},
                   F::FLOW_KIND_CALL, {0x401040}, {{0x401040, K::XREF_KIND_CALL, 0}},
                   Call(0x401025, 0x401040)});
  insns.push_back({0x401025, {0x89, 0x05, 0xd5, 0x1f, 0x00, 0x00}, "MOV",
                   {{"dword ptr [{}]", kResult}, {"EAX"}}, F::FLOW_KIND_FALL_THROUGH, {},
                   {{kResult, K::XREF_KIND_DATA_WRITE, 0}},
                   {P(Op::PCODE_OPCODE_STORE, std::nullopt, {RamSpace(), C(kResult, 8), R("EAX")})}});
  insns.push_back({0x40102b, {0x31, 0xc0}, "XOR", {{"EAX"}, {"EAX"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   Xor32("EAX", "EAX", "RAX")});
  insns.push_back({0x40102d, {0x5d}, "POP", {{"RBP"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_LOAD, R("RBP"), {RamSpace(), R("RSP")}),
                    P(Op::PCODE_OPCODE_INT_ADD, R("RSP"), {R("RSP"), C(8, 8)})}});
  insns.push_back({0x40102e, {0xc3}, "RET", {}, F::FLOW_KIND_RETURN, {}, {}, Ret()});

  // checksum (FNV-1a): 0x401040..0x40106a
  {
    std::vector<PcodeDef> test;
    test.push_back(P(Op::PCODE_OPCODE_INT_AND, U(0x100, 8), {R("RSI"), R("RSI")}));
    LogicFlags(test, U(0x100, 8), 8);
    insns.push_back({0x401040, {0x48, 0x85, 0xf6}, "TEST", {{"RSI"}, {"RSI"}}, F::FLOW_KIND_FALL_THROUGH,
                     {}, {}, test});
  }
  insns.push_back({0x401043, {0x74, 0x20}, "JZ", {{"{}", 0x401065}}, F::FLOW_KIND_CONDITIONAL_BRANCH,
                   {0x401065}, {{0x401065, K::XREF_KIND_CONDITIONAL_JUMP, 0}},
                   {P(Op::PCODE_OPCODE_CBRANCH, std::nullopt, {Ram(0x401065, 8), R("ZF")})}});
  insns.push_back({0x401045, {0x48, 0x89, 0xfa}, "MOV", {{"RDX"}, {"RDI"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_COPY, R("RDX"), {R("RDI")})}});
  insns.push_back({0x401048, {0x48, 0x01, 0xfe}, "ADD", {{"RSI"}, {"RDI"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   Add64(R("RSI"), R("RDI"))});
  insns.push_back({0x40104b, {0xb8, 0xc5, 0x9d, 0x1c, 0x81}, "MOV", {{"EAX"}, {"0x811c9dc5"}},
                   F::FLOW_KIND_FALL_THROUGH, {}, {}, Mov32Imm("EAX", "RAX", 0x811c9dc5)});
  insns.push_back({0x401050, {0x0f, 0xb6, 0x0a}, "MOVZX", {{"ECX"}, {"byte ptr [RDX]"}},
                   F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_LOAD, U(0x200, 1), {RamSpace(), R("RDX")}),
                    P(Op::PCODE_OPCODE_INT_ZEXT, R("ECX"), {U(0x200, 1)}),
                    P(Op::PCODE_OPCODE_INT_ZEXT, R("RCX"), {R("ECX")})}});
  insns.push_back({0x401053, {0x31, 0xc8}, "XOR", {{"EAX"}, {"ECX"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   Xor32("EAX", "ECX", "RAX")});
  insns.push_back({0x401055, {0x69, 0xc0, 0x93, 0x01, 0x00, 0x01}, "IMUL", {{"EAX"}, {"EAX"}, {"0x1000193"}},
                   F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_INT_MULT, R("EAX"), {R("EAX"), C(0x1000193, 4)}),
                    P(Op::PCODE_OPCODE_INT_ZEXT, R("RAX"), {R("EAX")})}});
  insns.push_back({0x40105b, {0x48, 0x83, 0xc2, 0x01}, "ADD", {{"RDX"}, {"0x1"}}, F::FLOW_KIND_FALL_THROUGH,
                   {}, {}, Add64(R("RDX"), C(1, 8))});
  insns.push_back({0x40105f, {0x48, 0x39, 0xf2}, "CMP", {{"RDX"}, {"RSI"}}, F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_INT_LESS, R("CF"), {R("RDX"), R("RSI")}),
                    P(Op::PCODE_OPCODE_INT_SBORROW, R("OF"), {R("RDX"), R("RSI")}),
                    P(Op::PCODE_OPCODE_INT_SUB, U(0x300, 8), {R("RDX"), R("RSI")}),
                    P(Op::PCODE_OPCODE_INT_SLESS, R("SF"), {U(0x300, 8), C(0, 8)}),
                    P(Op::PCODE_OPCODE_INT_EQUAL, R("ZF"), {U(0x300, 8), C(0, 8)})}});
  insns.push_back({0x401062, {0x75, 0xec}, "JNZ", {{"{}", 0x401050}}, F::FLOW_KIND_CONDITIONAL_BRANCH,
                   {0x401050}, {{0x401050, K::XREF_KIND_CONDITIONAL_JUMP, 0}},
                   {P(Op::PCODE_OPCODE_BOOL_NEGATE, U(0x400, 1), {R("ZF")}),
                    P(Op::PCODE_OPCODE_CBRANCH, std::nullopt, {Ram(0x401050, 8), U(0x400, 1)})}});
  insns.push_back({0x401064, {0xc3}, "RET", {}, F::FLOW_KIND_RETURN, {}, {}, Ret()});
  insns.push_back({0x401065, {0xb8, 0xc5, 0x9d, 0x1c, 0x81}, "MOV", {{"EAX"}, {"0x811c9dc5"}},
                   F::FLOW_KIND_FALL_THROUGH, {}, {}, Mov32Imm("EAX", "RAX", 0x811c9dc5)});
  insns.push_back({0x40106a, {0xc3}, "RET", {}, F::FLOW_KIND_RETURN, {}, {}, Ret()});

  // helper: 0x401070..0x401073, never called
  insns.push_back({0x401070, {0x8d, 0x04, 0x3f}, "LEA", {{"EAX"}, {"[RDI + RDI*0x1]"}},
                   F::FLOW_KIND_FALL_THROUGH, {}, {},
                   {P(Op::PCODE_OPCODE_INT_ADD, U(0x500, 8), {R("RDI"), R("RDI")}),
                    P(Op::PCODE_OPCODE_SUBPIECE, R("EAX"), {U(0x500, 8), C(0, 4)}),
                    P(Op::PCODE_OPCODE_INT_ZEXT, R("RAX"), {R("EAX")})}});
  insns.push_back({0x401073, {0xc3}, "RET", {}, F::FLOW_KIND_RETURN, {}, {}, Ret()});

  // --- data ---------------------------------------------------------------
  data.push_back({kHello, 6, "char[6]", "s_hello_00402000", "\"hello\""});
  data.push_back({kResult, 4, "undefined4", "DAT_00403000", "0x0"});

  // --- memory map -----------------------------------------------------------
  BlockDef text{".text", 0x401000, 0x74, true, false, true, true, 0x1000, {}};
  text.bytes.assign(text.size, 0xcc);  // int3 padding between functions
  for (const auto &i : insns)
    std::copy(i.bytes.begin(), i.bytes.end(), text.bytes.begin() + (i.addr - text.start));
  BlockDef rodata{".rodata", kHello, 6, true, false, false, true, 0x2000, {'h', 'e', 'l', 'l', 'o', 0}};
  BlockDef dat{".data", kResult, 4, true, true, false, true, 0x3000, {0, 0, 0, 0}};
  BlockDef bss{".bss", 0x404000, 0x10, true, true, false, false, 0, {}};
  blocks = {std::move(text), std::move(rodata), std::move(dat), std::move(bss)};

  functions = {{0x401000, 0x401009, "entry"},
               {0x401010, 0x40102e, "main"},
               {0x401040, 0x40106a, "FUN_00401040"},
               {0x401070, 0x401073, "FUN_00401070"}};

  // --- listing rows: instructions, data, coalesced undefined runs -----------
  for (const auto &b : blocks) {
    std::uint64_t a = b.start, end = b.start + b.size;
    while (a < end) {
      RowDef row{a, 1, pb::LISTING_ROW_KIND_UNDEFINED, -1, -1, b.name};
      if (auto *i = insn_at(a)) {
        row.kind = pb::LISTING_ROW_KIND_INSTRUCTION;
        row.length = static_cast<std::uint32_t>(i->bytes.size());
        row.insn = static_cast<int>(i - insns.data());
      } else if (auto *d = data_at(a)) {
        row.kind = pb::LISTING_ROW_KIND_DATA;
        row.length = d->length;
        row.data = static_cast<int>(d - data.data());
      } else {
        std::uint64_t e = a;
        while (e < end && !insn_at(e) && !data_at(e)) ++e;
        row.length = static_cast<std::uint32_t>(e - a);
      }
      rows.push_back(row);
      a += row.length;
    }
  }

  for (const auto &i : insns)
    for (const auto &r : i.refs) {
      xrefs.push_back({i.addr, r.to, r.kind, r.operand});
      if (r.kind == K::XREF_KIND_CONDITIONAL_JUMP || r.kind == K::XREF_KIND_JUMP)
        jump_labels[r.to] = "LAB_" + Hex8(r.to);
    }

  // --- type catalog -----------------------------------------------------------
  auto add_type = [&](pb::TypeKind kind, std::string name, std::uint64_t size, std::string display) {
    pb::TypeDefinition t;
    t.set_name(std::move(name));
    t.set_kind(kind);
    t.set_size(size);
    t.set_alignment(static_cast<std::uint32_t>(std::max<std::uint64_t>(1, std::min<std::uint64_t>(size, 8))));
    t.set_display(display);
    t.set_c_definition(display);
    t.mutable_origin()->mutable_derived()->set_rule("types.builtin");
    t.mutable_origin()->mutable_derived()->set_confidence(1);
    types.push_back(std::move(t));
    return &types.back();
  };
  types.reserve(16);
  add_type(pb::TYPE_KIND_VOID, "void", 0, "void");
  add_type(pb::TYPE_KIND_UINT, "byte", 1, "byte");
  add_type(pb::TYPE_KIND_CHAR, "char", 1, "char");
  add_type(pb::TYPE_KIND_INT, "int", 4, "int");
  add_type(pb::TYPE_KIND_UINT, "uint", 4, "uint");
  add_type(pb::TYPE_KIND_INT, "long", 8, "long");
  add_type(pb::TYPE_KIND_UNDEFINED, "undefined4", 4, "undefined4");
  // Hashes of leaf types cover their kind, name and size; composite hashes
  // cover their referenced hashes, which makes the catalog a Merkle DAG.
  for (auto &t : types) t.set_hash(FakeHash(std::to_string(t.kind()) + ":" + t.name() + ":" + std::to_string(t.size())));
  {
    auto *t = add_type(pb::TYPE_KIND_TYPEDEF, "uint32_t", 4, "uint32_t");
    t->mutable_typedef_type()->set_target_hash(hash_for_display("uint"));
    t->set_c_definition("typedef uint uint32_t;");
    t->set_hash(FakeHash("typedef:uint32_t:" + t->typedef_type().target_hash()));
  }
  {
    auto *t = add_type(pb::TYPE_KIND_POINTER, "", 8, "byte *");
    t->mutable_pointer()->set_target_hash(hash_for_display("byte"));
    t->set_hash(FakeHash("ptr:" + t->pointer().target_hash()));
  }
  {
    auto *t = add_type(pb::TYPE_KIND_ARRAY, "", 6, "char[6]");
    t->mutable_array()->set_element_hash(hash_for_display("char"));
    t->mutable_array()->set_count(6);
    t->set_alignment(1);
    t->set_hash(FakeHash("array:6:" + t->array().element_hash()));
  }
  {
    auto *t = add_type(pb::TYPE_KIND_STRUCT, "fnv_state", 16, "struct fnv_state");
    auto *c = t->mutable_composite();
    auto *f = c->add_fields();
    f->set_name("h");
    f->set_offset(0);
    f->set_type_hash(hash_for_display("uint32_t"));
    f = c->add_fields();
    f->set_name("n");
    f->set_offset(8);
    f->set_type_hash(hash_for_display("long"));
    t->set_c_definition("struct fnv_state {\n  uint32_t h;\n  long n;\n};");
    t->set_hash(FakeHash("struct:fnv_state:" + c->fields(0).type_hash() + ":" + c->fields(1).type_hash()));
  }

  // --- decompiler templates ---------------------------------------------------
  // checksum. Variables: 0 param_1, 1 param_2, 2 pbVar1, 3 uVar2.
  {
    DecompDef d{0x401040, "uint", {}, {}, {}};
    d.vars = {{pb::VARIABLE_KIND_PARAMETER, "param_1", "byte *", "param:0", {R("RDI")}},
              {pb::VARIABLE_KIND_PARAMETER, "param_2", "long", "param:1", {R("RSI")}},
              {pb::VARIABLE_KIND_LOCAL, "pbVar1", "byte *", "register:RDX@0x401045", {R("RDX")}},
              {pb::VARIABLE_KIND_LOCAL, "uVar2", "uint", "register:EAX@0x40104b", {R("EAX")}}};
    d.varnodes = {{R("RDI"), 0, 0},           {R("RSI"), 1, 0},          {R("RDX"), 2, 0x401045},
                  {R("EAX"), 3, 0x40104b},    {R("EAX"), 3, 0x401055},   {R("RDX"), 2, 0x40105b},
                  {C(0x811c9dc5, 4), -1, 0},  {C(0x1000193, 4), -1, 0},  {C(0, 8), -1, 0},
                  {R("ECX"), -1, 0x401050},   {C(1, 8), -1, 0},          {R("RSI"), -1, 0x401048}};
    d.body = {
        {1, {Kw("if"), Sp(), Pu("("), Var(1, 0x401040, {1}), Sp(), Opr("==", 0x401043), Sp(),
             Num(0, "0", 0x401040, {8}), Pu(")"), Sp(), Pu("{")}},
        {2, {Kw("return"), Sp(), Num(0x811c9dc5, "0x811c9dc5", 0x401065, {6}), Pu(";")}},
        {1, {Pu("}")}},
        {1, {Var(2, 0x401045, {2}), Sp(), Opr("=", 0x401045), Sp(), Var(0, 0x401045, {0}), Pu(";")}},
        {1, {Var(3, 0x40104b, {3}), Sp(), Opr("=", 0x40104b), Sp(),
             Num(0x811c9dc5, "0x811c9dc5", 0x40104b, {6}), Pu(";")}},
        {1, {Kw("do"), Sp(), Pu("{")}},
        {2, {Var(3, 0x401055, {4}), Sp(), Opr("=", 0x401055), Sp(), Pu("("), Var(3, 0x401053, {3}), Sp(),
             Opr("^", 0x401053), Sp(), Opr("*", 0x401050), Var(2, 0x401050, {2, 9}), Pu(")"), Sp(),
             Opr("*", 0x401055), Sp(), Num(0x1000193, "0x1000193", 0x401055, {7}), Pu(";")}},
        {2, {Var(2, 0x40105b, {5}), Sp(), Opr("=", 0x40105b), Sp(), Var(2, 0x40105b, {2}), Sp(),
             Opr("+", 0x40105b), Sp(), Num(1, "1", 0x40105b, {10}), Pu(";")}},
        {1, {Pu("}"), Sp(), Kw("while"), Sp(), Pu("("), Var(2, 0x40105f, {5}), Sp(), Opr("!=", 0x401062), Sp(),
             Var(0, 0x401048, {0}), Sp(), Opr("+", 0x401048, {11}), Sp(), Var(1, 0x401048, {1}), Pu(")"),
             Pu(";")}},
        {1, {Kw("return"), Sp(), Var(3, 0x401064, {4}), Pu(";")}},
    };
    decomps.emplace(d.entry, std::move(d));
  }
  // main. Variables: 0 uVar1, 1 the string (global), 2 the result (global).
  {
    DecompDef d{0x401010, "int", {}, {}, {}};
    d.vars = {{pb::VARIABLE_KIND_LOCAL, "uVar1", "uint", "register:EAX@0x401020", {R("EAX")}},
              {pb::VARIABLE_KIND_GLOBAL, "", "char[6]", "global:0x402000", {Ram(kHello, 6)}, kHello},
              {pb::VARIABLE_KIND_GLOBAL, "", "undefined4", "global:0x403000", {Ram(kResult, 4)}, kResult}};
    d.varnodes = {{R("EAX"), 0, 0x401020}, {C(kHello, 8), 1, 0x401014}, {C(5, 4), -1, 0x40101b},
                  {Ram(kResult, 4), 2, 0x401025}, {C(0, 4), -1, 0x40102b}};
    TokDef hello = Var(1, 0x401014, {1});
    TokDef result = Var(2, 0x401025, {3});
    d.body = {
        {1, {Var(0, 0x401020, {0}), Sp(), Opr("=", 0x401020), Sp(), Fn(0x401040, 0x401020), Pu("(", 0x401020),
             hello, Pu(",", 0x401020), Num(5, "5", 0x40101b, {2}), Pu(")", 0x401020), Pu(";")}},
        {1, {result, Sp(), Opr("=", 0x401025), Sp(), Var(0, 0x401025, {0}), Pu(";")}},
        {1, {Kw("return"), Sp(), Num(0, "0", 0x40102b, {4}), Pu(";")}},
    };
    decomps.emplace(d.entry, std::move(d));
  }
  // entry
  {
    DecompDef d{0x401000, "void", {}, {}, {}};
    TokDef halt{pb::CODE_TOKEN_KIND_FUNCTION_NAME, "halt_baddata"};
    halt.addr = 0x401009;
    d.body = {{1, {Fn(0x401010, 0x401002), Pu("(", 0x401002), Pu(")", 0x401002), Pu(";")}},
              {1, {halt, Pu("("), Pu(")"), Pu(";")}}};
    decomps.emplace(d.entry, std::move(d));
  }
  // helper
  {
    DecompDef d{0x401070, "int", {}, {}, {}};
    d.vars = {{pb::VARIABLE_KIND_PARAMETER, "param_1", "int", "param:0", {R("EDI")}}};
    d.varnodes = {{R("EDI"), 0, 0}, {C(2, 4), -1, 0}};
    d.body = {{1, {Kw("return"), Sp(), Var(0, 0x401070, {0}), Sp(), Opr("*", 0x401070), Sp(),
                   Num(2, "2", 0x401070, {1}), Pu(";")}}};
    decomps.emplace(d.entry, std::move(d));
  }
}

const InsnDef *SyntheticProgram::insn_at(std::uint64_t addr) const {
  auto it = std::lower_bound(insns.begin(), insns.end(), addr,
                             [](const InsnDef &i, std::uint64_t a) { return i.addr < a; });
  return it != insns.end() && it->addr == addr ? &*it : nullptr;
}

const DataDef *SyntheticProgram::data_at(std::uint64_t addr) const {
  for (const auto &d : data)
    if (d.addr == addr) return &d;
  return nullptr;
}

const BlockDef *SyntheticProgram::block_containing(std::uint64_t addr) const {
  for (const auto &b : blocks)
    if (addr >= b.start && addr - b.start < b.size) return &b;
  return nullptr;
}

const FunctionDef *SyntheticProgram::default_function_at(std::uint64_t entry) const {
  for (const auto &f : functions)
    if (f.entry == entry) return &f;
  return nullptr;
}

std::optional<std::uint8_t> SyntheticProgram::byte_at(std::uint64_t addr) const {
  const BlockDef *b = block_containing(addr);
  if (!b || !b->initialized) return std::nullopt;
  return b->bytes[addr - b->start];
}

std::size_t SyntheticProgram::row_index_at(std::uint64_t addr) const {
  auto it = std::lower_bound(rows.begin(), rows.end(), addr,
                             [](const RowDef &r, std::uint64_t a) { return r.addr + r.length <= a; });
  return static_cast<std::size_t>(it - rows.begin());
}

std::uint64_t SyntheticProgram::run_end(std::uint64_t addr) const {
  const InsnDef *i = insn_at(addr);
  std::uint64_t last = addr;
  while (i) {
    last = i->addr + i->bytes.size() - 1;
    if (i->flow == pb::FLOW_KIND_RETURN || i->flow == pb::FLOW_KIND_TERMINATOR ||
        i->flow == pb::FLOW_KIND_UNCONDITIONAL_BRANCH)
      break;
    i = insn_at(i->addr + i->bytes.size());
  }
  return last;
}

const pb::TypeDefinition *SyntheticProgram::type_by_hash(const std::string &hash) const {
  for (const auto &t : types)
    if (t.hash() == hash) return &t;
  return nullptr;
}

std::string SyntheticProgram::hash_for_display(const std::string &display) const {
  for (const auto &t : types)
    if (t.display() == display) return t.hash();
  return {};
}

std::uint32_t SyntheticProgram::xrefs_to_count(std::uint64_t addr) const {
  return static_cast<std::uint32_t>(
      std::count_if(xrefs.begin(), xrefs.end(), [&](const XrefDef &x) { return x.to == addr; }));
}

}  // namespace revkit::api::fake_internal
