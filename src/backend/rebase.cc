#include "rebase.h"

#include "data_settings.h"

#include "revkit/analysis/memory.h"
#include "revkit/analysis/user_refs.h"
#include "revkit/v1/assertion.pb.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/reflection.h>

#include <cstdio>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
using facts::FactKind;
using google::protobuf::FieldDescriptor;
using google::protobuf::Message;

std::optional<std::uint64_t> Hex(std::string_view s) {
  if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
  if (s.empty() || s.size() > 16) return std::nullopt;
  std::uint64_t v = 0;
  for (char c : s) {
    const int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    if (d < 0) return std::nullopt;
    v = v << 4 | static_cast<std::uint64_t>(d);
  }
  return v;
}

class BackendRelocator final : public facts::Relocator {
 public:
  bool moves(const facts::FactKey &k) const override {
    // (A type's default data settings are the program's, at 0: not an address.)
    return k.kind != FactKind::TypeDef && k.kind != FactKind::MemoryRegion && k.kind != FactKind::Rebase &&
           k.kind != FactKind::Language && !(k.kind == FactKind::Note && k.sub.starts_with(kDataTypeSettingsPrefix));
  }

  std::optional<std::string> sub(const facts::FactKey &k, const facts::Shift &shift) const override {
    if (k.kind == FactKind::Reference) {
      // "<operand>:<hex to>" or "i:<hex to>"
      const auto colon = k.sub.find(':');
      if (colon == std::string::npos) return std::nullopt;
      auto to = Hex(std::string_view(k.sub).substr(colon + 1));
      if (!to) return std::nullopt;
      const std::string_view op = std::string_view(k.sub).substr(0, colon);
      int operand = -1;
      if (op != "i") {
        operand = 0;
        for (char c : op) {
          if (c < '0' || c > '9') return std::nullopt;
          operand = operand * 10 + (c - '0');
        }
      }
      return analysis::user_ref_sub(operand, shift.apply(*to));
    }
    if (k.kind == FactKind::MemoryRegion && k.sub.starts_with(analysis::kBlockSubPrefix)) {
      auto start = Hex(std::string_view(k.sub).substr(analysis::kBlockSubPrefix.size()));
      if (!start) return std::nullopt;
      return analysis::block_sub(shift.apply(*start));
    }
    return std::nullopt;
  }

  std::optional<std::string> value(const facts::FactKey &k, std::string_view value,
                                   const facts::Shift &shift) const override {
    if (k.kind != FactKind::MemoryRegion || !k.sub.starts_with(analysis::kRegionSubPrefix) || value.empty())
      return std::nullopt;
    std::optional<analysis::RegionSpec> r = analysis::decode_region(value);
    if (!r) return std::nullopt;
    r->start = shift.apply(r->start);
    return analysis::encode_region(*r);
  }

  std::optional<std::string> meta(const facts::FactKey &, std::string_view meta,
                                  const facts::Shift &shift) const override {
    if (meta.empty()) return std::nullopt;
    pb::Assertion a;
    if (!a.ParseFromString(std::string(meta)) || !a.has_body()) return std::nullopt;
    ShiftAddresses(*a.mutable_body(), shift);
    std::string out;
    google::protobuf::io::StringOutputStream os(&out);
    google::protobuf::io::CodedOutputStream cos(&os);
    cos.SetSerializationDeterministic(true);
    a.SerializeToCodedStream(&cos);
    cos.Trim();
    return out;
  }
};

void Walk(Message &m, const facts::Shift &shift, int depth) {
  if (depth > 32) return;
  const google::protobuf::Descriptor *d = m.GetDescriptor();
  const google::protobuf::Reflection *r = m.GetReflection();
  if (d == pb::Address::descriptor()) {
    auto &a = static_cast<pb::Address &>(m);
    if (a.space().empty()) a.set_offset(shift.apply(a.offset()));
    return;
  }
  if (d == pb::MemoryRegionEdit::descriptor()) {
    // The region's (or the image block's) start, spelled as a number.
    auto &e = static_cast<pb::MemoryRegionEdit &>(m);
    if (!e.removed()) e.set_start(shift.apply(e.start()));
  }
  std::vector<const FieldDescriptor *> fields;
  r->ListFields(m, &fields);
  for (const FieldDescriptor *f : fields) {
    if (f->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE) continue;
    if (f->is_repeated()) {
      for (int i = 0; i < r->FieldSize(m, f); ++i) Walk(*r->MutableRepeatedMessage(&m, f, i), shift, depth + 1);
    } else {
      Walk(*r->MutableMessage(&m, f), shift, depth + 1);
    }
  }
}

}  // namespace

std::shared_ptr<const facts::Relocator> Relocator() {
  static const auto r = std::make_shared<const BackendRelocator>();
  return r;
}

facts::FactKey RebaseKey(facts::SpaceId space) { return {FactKind::Rebase, {space, 0}, {}}; }

facts::FactKey LanguageKey(facts::SpaceId space) { return {FactKind::Language, {space, 0}, {}}; }

std::pair<std::string, std::string> LanguageOf(const facts::FactValue &v) {
  const auto *t = std::get_if<std::string>(&v);
  if (!t || t->empty()) return {};
  const auto bar = t->find('|');
  if (bar == std::string::npos) return {*t, {}};
  return {t->substr(0, bar), t->substr(bar + 1)};
}

facts::Shift ShiftAt(const facts::Snapshot &snap, facts::SpaceId space) {
  facts::FactValue v = *snap.get<facts::AssertedFact>(RebaseKey(space));
  if (const auto *t = std::get_if<std::string>(&v))
    if (auto s = facts::Shift::parse(*t)) return *s;
  return {};
}

void ShiftAddresses(Message &m, const facts::Shift &shift) {
  if (shift.identity()) return;
  Walk(m, shift, 0);
}

facts::Op ShiftedOp(facts::Op op, const facts::Shift &shift) {
  if (shift.identity() || op.key.kind == FactKind::Rebase) return op;
  const facts::Relocator &r = *Relocator();
  op.value = facts::shifted_value(&r, op.key, op.value, shift);
  if (auto m = r.meta(op.key, op.meta, shift)) op.meta = std::move(*m);
  op.key = facts::shifted_key(&r, op.key, shift);
  return op;
}

}  // namespace revkit::backend
