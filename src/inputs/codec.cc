#include "revkit/inputs/codec.h"

namespace revkit::facts {

using namespace lift;

void Codec<DecompElement>::encode(Encoder &e, const DecompElement &v) {
  e.bytes(v.tag);
  e.varint(v.attrs.size());
  for (const auto &[k, val] : v.attrs) {
    e.bytes(k);
    facts::encode(e, val);
  }
  facts::encode(e, v.children);
}
DecompElement Codec<DecompElement>::decode(Decoder &d) {
  DecompElement v;
  v.tag = std::string(d.bytes());
  const std::size_t n = d.count();
  for (std::size_t i = 0; i < n; ++i) {
    std::string k(d.bytes());
    v.attrs.emplace_back(std::move(k), facts::decode<DecompElement::Value>(d));
  }
  v.children = facts::decode<std::vector<DecompElement>>(d);
  return v;
}

void Codec<StorageVarnode>::encode(Encoder &e, const StorageVarnode &v) {
  e.bytes(v.space);
  e.varint(v.offset);
  e.svarint(v.size);
}
StorageVarnode Codec<StorageVarnode>::decode(Decoder &d) {
  StorageVarnode v;
  v.space = std::string(d.bytes());
  v.offset = d.varint();
  v.size = static_cast<int>(d.svarint());
  return v;
}

void Codec<ParamFacts>::encode(Encoder &e, const ParamFacts &v) {
  e.bytes(v.name);
  facts::encode(e, v.valid);
  facts::encode(e, v.storage);
  facts::encode(e, v.stack);
  facts::encode(e, v.type);
  e.bytes(v.auto_kind);
  e.varint(v.id);
}
ParamFacts Codec<ParamFacts>::decode(Decoder &d) {
  ParamFacts v;
  v.name = std::string(d.bytes());
  v.valid = facts::decode<bool>(d);
  v.storage = facts::decode<std::vector<StorageVarnode>>(d);
  v.stack = facts::decode<bool>(d);
  v.type = facts::decode<DecompElement>(d);
  v.auto_kind = std::string(d.bytes());
  v.id = d.varint();
  return v;
}

void Codec<LocalFacts>::encode(Encoder &e, const LocalFacts &v) {
  e.bytes(v.name);
  facts::encode(e, v.undefined);
  e.svarint(v.first_use);
  facts::encode(e, v.hash);
  facts::encode(e, v.storage);
  facts::encode(e, v.type);
  facts::encode(e, v.is_float);
  e.svarint(v.type_size);
  e.svarint(v.size);
  e.varint(v.id);
  e.bytes(v.source_type);
}
LocalFacts Codec<LocalFacts>::decode(Decoder &d) {
  LocalFacts v;
  v.name = std::string(d.bytes());
  v.undefined = facts::decode<bool>(d);
  v.first_use = static_cast<int>(d.svarint());
  v.hash = facts::decode<std::optional<std::uint64_t>>(d);
  v.storage = facts::decode<std::vector<StorageVarnode>>(d);
  v.type = facts::decode<DecompElement>(d);
  v.is_float = facts::decode<bool>(d);
  v.type_size = static_cast<int>(d.svarint());
  v.size = static_cast<int>(d.svarint());
  v.id = d.varint();
  v.source_type = std::string(d.bytes());
  return v;
}

void Codec<FunctionFacts>::encode(Encoder &e, const FunctionFacts &v) {
  e.varint(v.entry);
  e.bytes(v.name);
  facts::encode(e, v.body);
  e.u8(static_cast<std::uint8_t>(v.signature_source));
  facts::encode(e, v.convention);
  facts::encode(e, v.has_this);
  facts::encode(e, v.extrapop);
  e.bytes(v.call_fixup);
  facts::encode(e, v.call_fixup_noreturn);
  facts::encode(e, v.varargs);
  facts::encode(e, v.is_inline);
  facts::encode(e, v.noreturn);
  facts::encode(e, v.custom_storage);
  facts::encode(e, v.dynamic_storage);
  facts::encode(e, v.ret.type);
  facts::encode(e, v.ret.is_default);
  facts::encode(e, v.ret.storage);
  facts::encode(e, v.ret.void_storage);
  e.svarint(v.ret.size);
  facts::encode(e, v.params);
  facts::encode(e, v.locals);
  e.varint(v.id);
  facts::encode(e, v.ns);
  e.bytes(v.label);
  e.bytes(v.source_type);
  e.bytes(v.source_name);
  facts::encode(e, v.context);
  facts::encode(e, v.context_reach);
  facts::encode(e, v.this_guessed);
  facts::encode(e, v.demangled);
}
FunctionFacts Codec<FunctionFacts>::decode(Decoder &d) {
  FunctionFacts v;
  v.entry = d.varint();
  v.name = std::string(d.bytes());
  v.body = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  const std::uint8_t src = d.u8();
  if (src > static_cast<std::uint8_t>(SignatureSource::user_defined)) throw DecodeError("bad signature source");
  v.signature_source = static_cast<SignatureSource>(src);
  v.convention = facts::decode<std::optional<std::string>>(d);
  v.has_this = facts::decode<bool>(d);
  v.extrapop = facts::decode<std::optional<int>>(d);
  v.call_fixup = std::string(d.bytes());
  v.call_fixup_noreturn = facts::decode<bool>(d);
  v.varargs = facts::decode<bool>(d);
  v.is_inline = facts::decode<bool>(d);
  v.noreturn = facts::decode<bool>(d);
  v.custom_storage = facts::decode<bool>(d);
  v.dynamic_storage = facts::decode<bool>(d);
  v.ret.type = facts::decode<DecompElement>(d);
  v.ret.is_default = facts::decode<bool>(d);
  v.ret.storage = facts::decode<std::optional<std::vector<StorageVarnode>>>(d);
  v.ret.void_storage = facts::decode<bool>(d);
  v.ret.size = static_cast<int>(d.svarint());
  v.params = facts::decode<std::vector<ParamFacts>>(d);
  v.locals = facts::decode<std::vector<LocalFacts>>(d);
  v.id = d.varint();
  v.ns = facts::decode<NamespacePath>(d);
  v.label = std::string(d.bytes());
  v.source_type = std::string(d.bytes());
  v.source_name = std::string(d.bytes());
  v.context = facts::decode<std::vector<std::pair<std::string, std::uint32_t>>>(d);
  v.context_reach = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
  v.this_guessed = facts::decode<bool>(d);
  v.demangled = facts::decode<bool>(d);
  return v;
}

void Codec<Mutability>::encode(Encoder &e, const Mutability &v) { e.u8(static_cast<std::uint8_t>(v)); }
Mutability Codec<Mutability>::decode(Decoder &d) {
  const std::uint8_t m = d.u8();
  if (m > static_cast<std::uint8_t>(Mutability::is_volatile)) throw DecodeError("bad mutability");
  return static_cast<Mutability>(m);
}

void Codec<DataFacts>::encode(Encoder &e, const DataFacts &v) {
  e.bytes(v.space);
  e.varint(v.addr);
  e.bytes(v.name);
  e.varint(v.length);
  facts::encode(e, v.type);
  facts::encode(e, v.mutability);
  e.varint(v.id);
  facts::encode(e, v.ns);
  facts::encode(e, v.string);
  e.bytes(v.source_type);
  e.bytes(v.source_name);
}
DataFacts Codec<DataFacts>::decode(Decoder &d) {
  DataFacts v;
  v.space = std::string(d.bytes());
  v.addr = d.varint();
  v.name = std::string(d.bytes());
  v.length = d.varint();
  v.type = facts::decode<DecompElement>(d);
  v.mutability = facts::decode<Mutability>(d);
  v.id = d.varint();
  v.ns = facts::decode<NamespacePath>(d);
  v.string = facts::decode<std::optional<std::string>>(d);
  v.source_type = std::string(d.bytes());
  v.source_name = std::string(d.bytes());
  return v;
}

void Codec<ExternalRefFacts>::encode(Encoder &e, const ExternalRefFacts &v) {
  e.bytes(v.space);
  e.varint(v.addr);
  e.bytes(v.label);
  facts::encode(e, v.function);
}
ExternalRefFacts Codec<ExternalRefFacts>::decode(Decoder &d) {
  ExternalRefFacts v;
  v.space = std::string(d.bytes());
  v.addr = d.varint();
  v.label = std::string(d.bytes());
  v.function = facts::decode<std::optional<FunctionFacts>>(d);
  return v;
}

void Codec<LabelFacts>::encode(Encoder &e, const LabelFacts &v) {
  e.bytes(v.space);
  e.varint(v.addr);
  e.bytes(v.name);
  facts::encode(e, v.ns);
}
LabelFacts Codec<LabelFacts>::decode(Decoder &d) {
  LabelFacts v;
  v.space = std::string(d.bytes());
  v.addr = d.varint();
  v.name = std::string(d.bytes());
  v.ns = facts::decode<NamespacePath>(d);
  return v;
}

void Codec<CommentFacts>::encode(Encoder &e, const CommentFacts &v) {
  e.varint(v.addr);
  e.u8(static_cast<std::uint8_t>(v.kind));
  e.bytes(v.text);
}
CommentFacts Codec<CommentFacts>::decode(Decoder &d) {
  CommentFacts v;
  v.addr = d.varint();
  const std::uint8_t k = d.u8();
  if (k > CommentFacts::plate) throw DecodeError("bad comment kind");
  v.kind = static_cast<CommentFacts::Kind>(k);
  v.text = std::string(d.bytes());
  return v;
}

void Codec<EquateFacts>::encode(Encoder &e, const EquateFacts &v) {
  e.varint(v.addr);
  e.varint(v.value);
  e.bytes(v.name);
  e.u8(static_cast<std::uint8_t>(v.format));
  e.varint(v.hash);
}
EquateFacts Codec<EquateFacts>::decode(Decoder &d) {
  EquateFacts v;
  v.addr = d.varint();
  v.value = d.varint();
  v.name = std::string(d.bytes());
  v.format = d.u8();
  if (v.format > 5) throw DecodeError("bad equate format");
  v.hash = d.varint();
  return v;
}

void Codec<TrackedFacts>::encode(Encoder &e, const TrackedFacts &v) {
  facts::encode(e, v.reg);
  e.bytes(v.register_name);
  e.varint(v.value);
}
TrackedFacts Codec<TrackedFacts>::decode(Decoder &d) {
  TrackedFacts v;
  v.reg = facts::decode<StorageVarnode>(d);
  v.register_name = std::string(d.bytes());
  v.value = d.varint();
  return v;
}

void Codec<BlockFacts>::encode(Encoder &e, const BlockFacts &v) {
  e.bytes(v.name);
  e.varint(v.start);
  e.varint(v.end);
  const std::uint8_t flags = (v.write ? 1 : 0) | (v.execute ? 2 : 0) | (v.initialized ? 4 : 0) |
                             (v.is_volatile ? 8 : 0) | (v.external ? 16 : 0);
  e.u8(flags);
  e.bytes(v.space);
}
BlockFacts Codec<BlockFacts>::decode(Decoder &d) {
  BlockFacts v;
  v.name = std::string(d.bytes());
  v.start = d.varint();
  v.end = d.varint();
  const std::uint8_t f = d.u8();
  v.write = f & 1;
  v.execute = f & 2;
  v.initialized = f & 4;
  v.is_volatile = f & 8;
  v.external = f & 16;
  v.space = std::string(d.bytes());
  return v;
}

void Codec<DecompilerInputs>::encode(Encoder &e, const DecompilerInputs &v) {
  e.bytes(v.language);
  e.bytes(v.compiler);
  e.bytes(v.default_convention);
  e.bytes(v.address_prefix);
  facts::encode(e, v.memory);
  facts::encode(e, v.synthesized_memory);
  facts::encode(e, v.patches);
  facts::encode(e, v.functions);
  facts::encode(e, v.data);
  facts::encode(e, v.external_refs);
  facts::encode(e, v.labels);
  facts::encode(e, v.code_labels);
  facts::encode(e, v.comments);
  facts::encode(e, v.tracked);
  facts::encode(e, v.flow_overrides);
  facts::encode(e, v.types);
}
DecompilerInputs Codec<DecompilerInputs>::decode(Decoder &d) {
  DecompilerInputs v;
  v.language = std::string(d.bytes());
  v.compiler = std::string(d.bytes());
  v.default_convention = std::string(d.bytes());
  v.address_prefix = std::string(d.bytes());
  v.memory = facts::decode<std::vector<BlockFacts>>(d);
  v.synthesized_memory = facts::decode<std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>>>(d);
  v.patches = facts::decode<std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>>>(d);
  v.functions = facts::decode<std::vector<FunctionFacts>>(d);
  v.data = facts::decode<std::vector<DataFacts>>(d);
  v.external_refs = facts::decode<std::vector<ExternalRefFacts>>(d);
  v.labels = facts::decode<std::vector<LabelFacts>>(d);
  v.code_labels = facts::decode<std::vector<LabelFacts>>(d);
  v.comments = facts::decode<std::vector<CommentFacts>>(d);
  v.tracked = facts::decode<std::map<std::uint64_t, std::vector<TrackedFacts>>>(d);
  v.flow_overrides = facts::decode<std::map<std::uint64_t, std::string>>(d);
  v.types = facts::decode<std::vector<DecompElement>>(d);
  return v;
}

void Codec<inputs::FunctionInputs>::encode(Encoder &e, const inputs::FunctionInputs &v) {
  facts::encode(e, v.locals);
  facts::encode(e, v.flow_overrides);
  facts::encode(e, v.code_labels);
}
inputs::FunctionInputs Codec<inputs::FunctionInputs>::decode(Decoder &d) {
  inputs::FunctionInputs v;
  v.locals = facts::decode<std::vector<LocalFacts>>(d);
  v.flow_overrides = facts::decode<std::vector<std::pair<std::uint64_t, std::string>>>(d);
  v.code_labels = facts::decode<std::vector<LabelFacts>>(d);
  return v;
}

void Codec<CommittedSignature>::encode(Encoder &e, const CommittedSignature &v) {
  e.u8(static_cast<std::uint8_t>(v.status));
  e.bytes(v.detail);
  e.bytes(v.convention);
  facts::encode(e, v.varargs);
  facts::encode(e, v.custom_storage);
  facts::encode(e, v.return_committed);
  facts::encode(e, v.ret.type);
  facts::encode(e, v.ret.is_default);
  facts::encode(e, v.ret.storage);
  facts::encode(e, v.ret.void_storage);
  e.svarint(v.ret.size);
  facts::encode(e, v.params);
}
CommittedSignature Codec<CommittedSignature>::decode(Decoder &d) {
  CommittedSignature v;
  const std::uint8_t status = d.u8();
  if (status > static_cast<std::uint8_t>(CommittedSignature::Status::skipped)) throw DecodeError("bad param-id status");
  v.status = static_cast<CommittedSignature::Status>(status);
  v.detail = std::string(d.bytes());
  v.convention = std::string(d.bytes());
  v.varargs = facts::decode<bool>(d);
  v.custom_storage = facts::decode<bool>(d);
  v.return_committed = facts::decode<bool>(d);
  v.ret.type = facts::decode<DecompElement>(d);
  v.ret.is_default = facts::decode<bool>(d);
  v.ret.storage = facts::decode<std::optional<std::vector<StorageVarnode>>>(d);
  v.ret.void_storage = facts::decode<bool>(d);
  v.ret.size = static_cast<int>(d.svarint());
  v.params = facts::decode<std::vector<ParamFacts>>(d);
  return v;
}

}  // namespace revkit::facts

namespace revkit::inputs {

void StaticInputs::encode(facts::Encoder &e) const {
  facts::encode(e, memory);
  facts::encode(e, patches);
  facts::encode(e, external);
  facts::encode(e, imports);
  facts::encode(e, thread);
  e.varint(symbols.size());
  for (const Symbol &s : symbols) {
    e.varint(s.address);
    e.bytes(s.name);
    e.varint(s.size);
    facts::encode(e, s.data);
    facts::encode(e, s.mutability);
  }
  e.varint(slots.size());
  for (const Slot &s : slots) {
    e.varint(s.address);
    e.varint(s.value);
    facts::encode(e, s.mutability);
    facts::encode(e, s.mapped);
  }
  facts::encode(e, external_names);
}

StaticInputs StaticInputs::decode(facts::Decoder &d) {
  StaticInputs v;
  v.memory = facts::decode<std::vector<lift::BlockFacts>>(d);
  v.patches = facts::decode<std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>>>(d);
  v.external = facts::decode<lift::DecompilerInputs>(d);
  v.imports = facts::decode<lift::DecompilerInputs>(d);
  v.thread = facts::decode<lift::DecompilerInputs>(d);
  for (std::size_t n = d.count(); n > 0; --n) {
    Symbol s;
    s.address = d.varint();
    s.name = std::string(d.bytes());
    s.size = d.varint();
    s.data = facts::decode<bool>(d);
    s.mutability = facts::decode<lift::Mutability>(d);
    v.symbols.push_back(std::move(s));
  }
  for (std::size_t n = d.count(); n > 0; --n) {
    Slot s;
    s.address = d.varint();
    s.value = d.varint();
    s.mutability = facts::decode<lift::Mutability>(d);
    s.mapped = facts::decode<bool>(d);
    v.slots.push_back(s);
  }
  v.external_names = facts::decode<std::vector<std::pair<std::uint64_t, std::string>>>(d);
  return v;
}

}  // namespace revkit::inputs
