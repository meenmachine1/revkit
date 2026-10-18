#include "revkit/infer/accesses.h"

#include "funcdata.hh"

#include <algorithm>
#include <cstdio>
#include <map>
#include <unordered_map>

namespace revkit::infer {

namespace {

constexpr std::int64_t kMaxOffset = std::int64_t{1} << 20;
constexpr std::size_t kMaxVarnodes = 4096;
constexpr std::size_t kMaxAccesses = 4096;

std::int64_t signed_value(const ghidra::Varnode *vn) {
  const int bits = vn->getSize() * 8;
  std::uint64_t v = vn->getOffset();
  if (bits < 64 && ((v >> (bits - 1)) & 1)) v |= ~std::uint64_t{0} << bits;
  return static_cast<std::int64_t>(v);
}

const ghidra::Datatype *type_of(const ghidra::Varnode *vn) {
  if (vn == nullptr) return nullptr;
  if (!vn->isAnnotation()) {
    try {
      if (const ghidra::HighVariable *h = vn->getHigh()) return h->getType();
    } catch (const ghidra::LowlevelError &) {
    }
  }
  return vn->getType();
}

ValueKind kind_of(const ghidra::Datatype *t) {
  if (t == nullptr) return ValueKind::unknown;
  switch (t->getMetatype()) {
    case ghidra::TYPE_PTR:
    case ghidra::TYPE_PTRREL: return ValueKind::pointer;
    case ghidra::TYPE_FLOAT: return ValueKind::floating;
    case ghidra::TYPE_INT:
    case ghidra::TYPE_ENUM_INT: return ValueKind::signed_int;
    case ghidra::TYPE_UINT:
    case ghidra::TYPE_ENUM_UINT: return ValueKind::unsigned_int;
    case ghidra::TYPE_BOOL: return ValueKind::boolean;
    default: return ValueKind::unknown;
  }
}

bool is_float_op(ghidra::OpCode c) {
  switch (c) {
    case ghidra::CPUI_FLOAT_EQUAL:
    case ghidra::CPUI_FLOAT_NOTEQUAL:
    case ghidra::CPUI_FLOAT_LESS:
    case ghidra::CPUI_FLOAT_LESSEQUAL:
    case ghidra::CPUI_FLOAT_NAN:
    case ghidra::CPUI_FLOAT_ADD:
    case ghidra::CPUI_FLOAT_DIV:
    case ghidra::CPUI_FLOAT_MULT:
    case ghidra::CPUI_FLOAT_SUB:
    case ghidra::CPUI_FLOAT_NEG:
    case ghidra::CPUI_FLOAT_ABS:
    case ghidra::CPUI_FLOAT_SQRT:
    case ghidra::CPUI_FLOAT_FLOAT2FLOAT:
    case ghidra::CPUI_FLOAT_TRUNC:
    case ghidra::CPUI_FLOAT_CEIL:
    case ghidra::CPUI_FLOAT_FLOOR:
    case ghidra::CPUI_FLOAT_ROUND: return true;
    default: return false;
  }
}

// A loaded value used as an address (dereferenced, directly or plus a
// constant) is a pointer whatever its type says; one a float operation
// reads is a float.
ValueKind used_as(const ghidra::Varnode *vn) {
  std::vector<std::pair<const ghidra::Varnode *, int>> work{{vn, 0}};
  std::vector<const ghidra::Varnode *> seen;
  while (!work.empty()) {
    auto [v, depth] = work.back();
    work.pop_back();
    if (depth > 3 || std::find(seen.begin(), seen.end(), v) != seen.end()) continue;
    seen.push_back(v);
    for (auto it = v->beginDescend(); it != v->endDescend(); ++it) {
      const ghidra::PcodeOp *op = *it;
      const int slot = op->getSlot(v);
      switch (op->code()) {
        case ghidra::CPUI_LOAD:
        case ghidra::CPUI_STORE:
          if (slot == 1) return ValueKind::pointer;
          break;
        case ghidra::CPUI_COPY:
        case ghidra::CPUI_CAST:
        case ghidra::CPUI_PTRSUB:
        case ghidra::CPUI_PTRADD:
          if (op->getOut() != nullptr && slot == 0) work.emplace_back(op->getOut(), depth + 1);
          break;
        case ghidra::CPUI_INT_ADD:
          if (op->getOut() != nullptr && op->getIn(1 - slot)->isConstant()) work.emplace_back(op->getOut(), depth + 1);
          break;
        default:
          if (depth == 0 && is_float_op(op->code())) return ValueKind::floating;
          break;
      }
    }
  }
  return ValueKind::unknown;
}

// What a value read (forward: the LOAD's output) or written (backward: the
// STORE's input) is: its type, the other side of a cast, and for a load
// how it is used.
ValueKind classify(const ghidra::Varnode *vn, bool forward) {
  ValueKind k = kind_of(type_of(vn));
  if (k == ValueKind::unknown) {
    if (forward) {
      if (const ghidra::PcodeOp *op = vn->loneDescend(); op != nullptr && op->code() == ghidra::CPUI_CAST)
        k = kind_of(type_of(op->getOut()));
    } else if (vn->isWritten() && vn->getDef()->code() == ghidra::CPUI_CAST) {
      k = kind_of(type_of(vn->getDef()->getIn(0)));
    } else if (vn->isWritten() && is_float_op(vn->getDef()->code())) {
      k = ValueKind::floating;
    }
  }
  if (forward && (k == ValueKind::unknown || k == ValueKind::signed_int || k == ValueKind::unsigned_int)) {
    const ValueKind used = used_as(vn);
    if (used != ValueKind::unknown) k = used;
  }
  return k;
}

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

std::string storage_text(const ghidra::Funcdata &fd, const ghidra::Address &addr, int size) {
  if (addr.isInvalid()) return {};
  const ghidra::AddrSpace *spc = addr.getSpace();
  if (spc->getType() == ghidra::IPTR_SPACEBASE) {
    const int bits = spc->getAddrSize() * 8;
    std::uint64_t v = addr.getOffset();
    if (bits < 64 && ((v >> (bits - 1)) & 1)) v |= ~std::uint64_t{0} << bits;
    const auto s = static_cast<std::int64_t>(v);
    return "stack:" + (s < 0 ? "-" + hex(0 - v) : hex(v));
  }
  const std::string reg = fd.getArch()->translate->getRegisterName(addr.getSpace(), addr.getOffset(), size);
  return reg.empty() ? spc->getName() + ":" + hex(addr.getOffset()) : "register:" + reg;
}

}  // namespace

void PointerAccess::encode(facts::Encoder &e) const {
  e.svarint(offset);
  e.varint(size);
  e.u8(static_cast<std::uint8_t>(kind));
  e.u8(static_cast<std::uint8_t>(value));
  e.varint(address);
  e.varint(callee);
  e.svarint(parameter);
  e.bytes(storage);
}

PointerAccess PointerAccess::decode(facts::Decoder &d) {
  PointerAccess a;
  a.offset = d.svarint();
  a.size = static_cast<std::uint32_t>(d.varint());
  const std::uint8_t k = d.u8();
  if (k > static_cast<std::uint8_t>(AccessKind::passed)) throw facts::DecodeError("bad access kind");
  a.kind = static_cast<AccessKind>(k);
  const std::uint8_t v = d.u8();
  if (v > static_cast<std::uint8_t>(ValueKind::boolean)) throw facts::DecodeError("bad value kind");
  a.value = static_cast<ValueKind>(v);
  a.address = d.varint();
  a.callee = d.varint();
  a.parameter = static_cast<std::int32_t>(d.svarint());
  a.storage = std::string(d.bytes());
  return a;
}

std::vector<PointerAccess> pointer_accesses(const ghidra::Funcdata &fd, const ghidra::HighVariable &high, std::vector<LoadedValue> *loads,
                                            std::vector<std::int64_t> *self) {
  std::vector<const ghidra::Varnode *> roots;
  for (int i = 0; i < high.numInstances(); ++i) roots.push_back(high.getInstance(i));
  return pointer_accesses(fd, roots, loads, self);
}

std::vector<PointerAccess> pointer_accesses(const ghidra::Funcdata &fd, const std::vector<const ghidra::Varnode *> &roots,
                                            std::vector<LoadedValue> *loads, std::vector<std::int64_t> *self) {
  std::vector<PointerAccess> out;
  std::vector<std::pair<std::int64_t, const ghidra::Varnode *>> loaded;  // for `self`
  std::vector<std::pair<const ghidra::Varnode *, std::int64_t>> todo;
  std::unordered_map<const ghidra::Varnode *, std::int64_t> done;
  for (const ghidra::Varnode *vn : roots)
    if (vn != nullptr && done.emplace(vn, 0).second) todo.emplace_back(vn, 0);
  auto put = [&](const ghidra::Varnode *vn, std::int64_t off) {
    if (vn == nullptr || off < -kMaxOffset || off > kMaxOffset || done.size() >= kMaxVarnodes) return;
    if (done.emplace(vn, off).second) todo.emplace_back(vn, off);
  };
  for (std::size_t next = 0; next < todo.size() && out.size() < kMaxAccesses; ++next) {
    const auto [vn, off] = todo[next];
    for (auto it = vn->beginDescend(); it != vn->endDescend(); ++it) {
      ghidra::PcodeOp *op = *it;
      if (op->isDead()) continue;
      const int slot = op->getSlot(vn);
      ghidra::Varnode *result = op->getOut();
      switch (op->code()) {
        case ghidra::CPUI_INT_ADD:
          if (op->numInput() == 2 && op->getIn(1 - slot)->isConstant()) put(result, off + signed_value(op->getIn(1 - slot)));
          break;
        case ghidra::CPUI_INT_SUB:
          if (slot == 0 && op->getIn(1)->isConstant()) put(result, off - signed_value(op->getIn(1)));
          break;
        case ghidra::CPUI_PTRADD:
          if (slot == 0 && op->getIn(1)->isConstant() && op->getIn(2)->isConstant())
            put(result, off + signed_value(op->getIn(1)) * static_cast<std::int64_t>(op->getIn(2)->getOffset()));
          break;
        case ghidra::CPUI_PTRSUB:
          if (slot == 0 && op->getIn(1)->isConstant()) put(result, off + signed_value(op->getIn(1)));
          break;
        case ghidra::CPUI_COPY:
        case ghidra::CPUI_CAST:
        case ghidra::CPUI_MULTIEQUAL:
        case ghidra::CPUI_SEGMENTOP:
          put(result, off);
          break;
        case ghidra::CPUI_INDIRECT:
          if (slot == 0) put(result, off);
          break;
        case ghidra::CPUI_LOAD:
          if (slot == 1 && result != nullptr) {
            PointerAccess a;
            a.offset = off;
            a.size = static_cast<std::uint32_t>(result->getSize());
            a.kind = AccessKind::load;
            a.value = classify(result, true);
            a.address = op->getAddr().getOffset();
            out.push_back(std::move(a));
            if (loads != nullptr && off >= 0 && loads->size() < kMaxAccesses) loads->push_back({off, result});
            if (self != nullptr && off >= 0) loaded.emplace_back(off, result);
          }
          break;
        case ghidra::CPUI_STORE:
          if (slot == 1 && op->numInput() > 2) {
            PointerAccess a;
            a.offset = off;
            a.size = static_cast<std::uint32_t>(op->getIn(2)->getSize());
            a.kind = AccessKind::store;
            a.value = classify(op->getIn(2), false);
            a.address = op->getAddr().getOffset();
            out.push_back(std::move(a));
          }
          break;
        case ghidra::CPUI_CALL:
        case ghidra::CPUI_CALLIND: {
          if (slot < 1) break;
          PointerAccess a;
          a.offset = off;
          a.kind = AccessKind::passed;
          a.address = op->getAddr().getOffset();
          a.parameter = slot - 1;
          if (const ghidra::FuncCallSpecs *fc = fd.getCallSpecs(op)) {
            if (!fc->getEntryAddress().isInvalid()) a.callee = fc->getEntryAddress().getOffset();
            if (slot - 1 < fc->numParams()) {
              const ghidra::ProtoParameter *p = fc->getParam(slot - 1);
              a.storage = storage_text(fd, p->getAddress(), p->getSize());
            }
          }
          out.push_back(std::move(a));
          break;
        }
        default:
          break;
      }
    }
  }
  if (self != nullptr)
    for (const auto &[off, value] : loaded) {
      // The loaded value is the variable itself (reached from it at offset
      // 0), or is copied or joined into it.
      bool back = false;
      if (auto it = done.find(value); it != done.end() && it->second == 0) back = true;
      for (auto it = value->beginDescend(); !back && it != value->endDescend(); ++it) {
        const ghidra::PcodeOp *op = *it;
        switch (op->code()) {
          case ghidra::CPUI_COPY:
          case ghidra::CPUI_CAST:
          case ghidra::CPUI_MULTIEQUAL:
          case ghidra::CPUI_INDIRECT:
            if (op->getOut() != nullptr)
              if (auto d = done.find(op->getOut()); d != done.end() && d->second == 0) back = true;
            break;
          default:
            break;
        }
      }
      if (back && std::find(self->begin(), self->end(), off) == self->end()) self->push_back(off);
    }
  return out;
}

std::string field_name(std::uint64_t offset) { return "field_" + hex(offset); }

StructurePlan compose_structure(const std::vector<PointerAccess> &accesses, const ComposeOptions &options,
                                const std::vector<ExistingField> &existing, std::uint64_t existing_size) {
  struct Votes {
    std::map<std::uint32_t, std::uint32_t> sizes;                             // size -> accesses
    std::map<std::pair<std::uint32_t, ValueKind>, std::uint32_t> values;     // (size, kind) -> accesses
    std::uint32_t total = 0;
    bool reference = false;
  };
  const std::uint64_t limit = std::max(options.max_offset, existing_size);
  std::map<std::uint64_t, Votes> at;
  std::uint64_t end = existing_size;
  for (const PointerAccess &a : accesses) {
    if (a.offset < 0) continue;
    const auto off = static_cast<std::uint64_t>(a.offset);
    if (off > limit) continue;
    if (a.kind == AccessKind::passed) {
      if (off == 0) continue;  // the whole structure, followed into the callee
      at[off].reference = true;
      end = std::max(end, off + 1);
      continue;
    }
    if (a.size == 0) continue;
    Votes &v = at[off];
    ++v.sizes[a.size];
    ++v.values[{a.size, a.value}];
    ++v.total;
    end = std::max(end, off + a.size);
  }
  auto valid = [&](ValueKind k, std::uint32_t size) {
    switch (k) {
      case ValueKind::pointer: return size == options.pointer_size;
      case ValueKind::floating: return size == 4 || size == 8 || size == 10 || size == 12 || size == 16;
      case ValueKind::signed_int:
      case ValueKind::unsigned_int: return size == 1 || size == 2 || size == 4 || size == 8;
      case ValueKind::boolean: return size == 1;
      default: return true;
    }
  };
  std::vector<PlannedField> fields;
  for (const auto &[off, v] : at) {
    PlannedField f;
    f.offset = off;
    f.accesses = v.total;
    f.name = field_name(off);
    if (v.sizes.empty()) {
      f.size = 1;
      fields.push_back(std::move(f));
      continue;
    }
    std::uint32_t best = 0, best_n = 0;
    for (const auto &[size, n] : v.sizes)
      if (n > best_n || (n == best_n && size > best)) best = size, best_n = n;
    f.size = best;
    // A pointer if anything says so, else a float, else the integer the
    // most accesses agree on.
    std::map<ValueKind, std::uint32_t> votes;
    for (const auto &[key, n] : v.values)
      if (key.first == best) votes[key.second] += n;
    if (votes[ValueKind::pointer] > 0) f.value = ValueKind::pointer;
    else if (votes[ValueKind::floating] > 0) f.value = ValueKind::floating;
    else {
      const std::uint32_t s = votes[ValueKind::signed_int], u = votes[ValueKind::unsigned_int], b = votes[ValueKind::boolean];
      if (s > u && s >= b && s > 0) f.value = ValueKind::signed_int;
      else if (u > s && u >= b && u > 0) f.value = ValueKind::unsigned_int;
      else if (b > s && b > u) f.value = ValueKind::boolean;
    }
    if (!valid(f.value, f.size)) f.value = ValueKind::unknown;
    fields.push_back(std::move(f));
  }
  if (options.keep_wide) {
    std::vector<PlannedField> kept;
    for (std::size_t i = 0; i < fields.size(); ++i) {
      PlannedField f = fields[i];
      std::size_t j = i + 1;
      std::uint32_t inside = 0;
      while (j < fields.size() && fields[j].offset < f.offset + f.size && fields[j].offset + fields[j].size <= f.offset + f.size)
        inside += fields[j++].accesses;
      const bool overlaps_next = j < fields.size() && fields[j].offset < f.offset + f.size;
      const auto &sizes = at.at(f.offset).sizes;
      const auto wide = sizes.find(f.size);
      if (j > i + 1 && !overlaps_next && wide != sizes.end() && inside < 2 * wide->second) {
        f.accesses += inside;
        kept.push_back(std::move(f));
        i = j - 1;
        continue;
      }
      kept.push_back(std::move(f));
    }
    fields = std::move(kept);
  }
  // Never into the next field: an 8-byte store over two 4-byte fields is
  // two fields.
  auto truncate = [](PlannedField &f, std::uint64_t next) {
    if (f.offset + f.size <= next) return;
    f.size = static_cast<std::uint32_t>(next - f.offset);
    f.truncated = true;
    f.value = ValueKind::unknown;
  };
  for (std::size_t i = 0; i + 1 < fields.size(); ++i) truncate(fields[i], fields[i + 1].offset);

  StructurePlan plan;
  plan.size = end;
  if (existing.empty()) {
    plan.fields = std::move(fields);
    return plan;
  }
  std::vector<ExistingField> old = existing;
  std::sort(old.begin(), old.end(), [](const ExistingField &a, const ExistingField &b) { return a.offset < b.offset; });
  for (const ExistingField &e : old) {
    PlannedField f;
    f.offset = e.offset;
    f.size = e.size;
    f.existing = true;
    f.name = e.name;
    plan.fields.push_back(std::move(f));
  }
  for (PlannedField &f : fields) {
    // Inside an existing field: that field stays.
    bool inside = false;
    std::uint64_t next = UINT64_MAX;
    for (const ExistingField &e : old) {
      const std::uint64_t e_end = e.offset + std::max<std::uint32_t>(e.size, 1);
      if (f.offset >= e.offset && f.offset < e_end) inside = true;
      if (e.offset > f.offset) next = std::min(next, e.offset);
    }
    if (inside) continue;
    truncate(f, next);
    plan.fields.push_back(std::move(f));
  }
  // Existing fields that accesses start in count those accesses.
  for (PlannedField &p : plan.fields) {
    if (!p.existing) continue;
    if (auto it = at.find(p.offset); it != at.end()) p.accesses = it->second.total;
  }
  std::sort(plan.fields.begin(), plan.fields.end(),
            [](const PlannedField &a, const PlannedField &b) { return a.offset < b.offset; });
  return plan;
}

}  // namespace revkit::infer
