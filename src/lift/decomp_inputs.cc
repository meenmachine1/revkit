#include "revkit/lift/decomp_inputs.hh"

#include "revkit/lift/image_arch.hh"

#include "funcdata.hh"
#include "xml.hh"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <set>
#include <sstream>
#include <unordered_map>

namespace revkit::lift {

const DecompElement::Value *DecompElement::attr(const std::string &name) const {
  for (const auto &[k, v] : attrs)
    if (k == name) return &v;
  return nullptr;
}

namespace {

using Attrs = std::vector<std::pair<std::string, DecompElement::Value>>;

DecompElement el(std::string tag, Attrs attrs = {}, std::vector<DecompElement> children = {}) {
  return DecompElement{std::move(tag), std::move(attrs), std::move(children)};
}

std::int64_t i64(long long v) { return static_cast<std::int64_t>(v); }

std::string format_value(const DecompElement::Value &v) {
  struct Visitor {
    std::string operator()(const std::string &s) const { return s; }
    std::string operator()(std::int64_t i) const { return std::to_string(i); }
    std::string operator()(std::uint64_t u) const {
      char buf[24];
      std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(u));
      return buf;
    }
    std::string operator()(bool b) const { return b ? "true" : "false"; }
  };
  return std::visit(Visitor{}, v);
}

void xml_escape(std::ostream &os, const std::string &s) {
  for (char c : s) {
    switch (c) {
      case '<': os << "&lt;"; break;
      case '>': os << "&gt;"; break;
      case '&': os << "&amp;"; break;
      case '"': os << "&quot;"; break;
      default: os << c;
    }
  }
}

void write_xml(std::ostream &os, const DecompElement &e, int depth) {
  os << std::string(static_cast<std::size_t>(depth) * 2, ' ') << '<' << e.tag;
  const std::string *content = nullptr;
  std::string content_text;
  for (const auto &[k, v] : e.attrs) {
    if (k == "content") {
      content_text = format_value(v);
      content = &content_text;
      continue;
    }
    os << ' ' << k << "=\"";
    xml_escape(os, format_value(v));
    os << '"';
  }
  if (e.children.empty() && content == nullptr) {
    os << "/>\n";
    return;
  }
  os << '>';
  if (content != nullptr) xml_escape(os, *content);
  if (!e.children.empty()) {
    os << '\n';
    for (const DecompElement &c : e.children) write_xml(os, c, depth + 1);
    os << std::string(static_cast<std::size_t>(depth) * 2, ' ');
  }
  os << "</" << e.tag << ">\n";
}

ghidra::Element *build_element(const DecompElement &e, ghidra::Element *parent) {
  auto *x = new ghidra::Element(parent);
  x->setName(e.tag);
  for (const auto &[k, v] : e.attrs) {
    std::string text = format_value(v);
    if (k == "content") x->addContent(text.data(), 0, static_cast<ghidra::int4>(text.size()));
    else x->addAttribute(k, text);
  }
  for (const DecompElement &c : e.children) x->addChild(build_element(c, x));
  return x;
}

// ---- encodings, after Ghidra's Java encoders ------------------------------

constexpr std::uint64_t kIdBase = 0x4000000000000000ULL;  // HighSymbol.ID_BASE

// AddressXML.encode(encoder, Varnode[], logicalsize).
DecompElement encode_storage(const std::vector<StorageVarnode> &vns, long logical_size = 0) {
  if (vns.empty()) return el("addr");
  if (vns.size() == 1 && logical_size == 0)
    return el("addr", {{"space", vns[0].space}, {"offset", vns[0].offset}, {"size", i64(vns[0].size)}});
  Attrs a{{"space", std::string("join")}};
  for (std::size_t i = 0; i < vns.size(); ++i) {
    char buf[96];
    std::snprintf(buf, sizeof buf, "%s:0x%llx:%d", vns[i].space.c_str(), static_cast<unsigned long long>(vns[i].offset),
                  vns[i].size);
    a.emplace_back("piece" + std::to_string(i + 1), std::string(buf));
  }
  if (logical_size != 0) a.emplace_back("logicalsize", static_cast<std::uint64_t>(logical_size));
  return el("addr", std::move(a));
}

// SymbolEntry.encodeRangelist: the single use point, if any.
DecompElement encode_rangelist(std::optional<std::uint64_t> pc) {
  if (!pc) return el("rangelist");
  return el("rangelist", {}, {el("range", {{"space", std::string("ram")}, {"first", *pc}, {"last", *pc}})});
}

struct SymbolHeader {
  std::uint64_t id = 0;
  std::string name;
  bool typelock = false;
  bool namelock = false;
  Mutability mutability = Mutability::normal;
  bool this_ptr = false;
  bool hidden = false;
  int category = -1;
  int index = -1;
};

// HighSymbol.encodeHeader.
Attrs header_attrs(const SymbolHeader &h) {
  Attrs a;
  if (h.id != 0 && (h.id >> 56) != (kIdBase >> 56)) a.emplace_back("id", h.id);
  a.emplace_back("name", h.name);
  a.emplace_back("typelock", h.typelock);
  a.emplace_back("namelock", h.namelock);
  if (h.mutability == Mutability::constant) a.emplace_back("readonly", true);
  else if (h.mutability == Mutability::is_volatile) a.emplace_back("volatile", true);
  if (h.typelock) a.emplace_back("merge", false);  // isIsolated() is the type lock
  if (h.this_ptr) a.emplace_back("thisptr", true);
  if (h.hidden) a.emplace_back("hiddenretparm", true);
  a.emplace_back("cat", i64(h.category));
  if (h.index >= 0) a.emplace_back("index", static_cast<std::uint64_t>(h.index));
  return a;
}

std::string space_of_ram() { return "ram"; }

// java.util.HashMap<Long, ...> iteration order, which is the order Java's
// LocalSymbolMap writes its symbols in.
template <typename T>
std::vector<T> hashmap_order(std::vector<std::pair<std::uint64_t, T>> items) {
  std::size_t n = 16;
  while (items.size() > n * 3 / 4) n *= 2;
  auto bucket = [n](std::uint64_t key) {
    auto h = static_cast<std::uint32_t>(key ^ (key >> 32));
    h ^= h >> 16;
    return h & (n - 1);
  };
  std::stable_sort(items.begin(), items.end(),
                   [&](const auto &a, const auto &b) { return bucket(a.first) < bucket(b.first); });
  std::vector<T> out;
  out.reserve(items.size());
  for (auto &it : items) out.push_back(std::move(it.second));
  return out;
}

bool is_user_defined_name(const std::string &name) {
  return !(name.starts_with("local_") || name.starts_with("param_"));
}

// FunctionPrototype.grabFromFunction + encodePrototype.
DecompElement encode_prototype(const FunctionFacts &f) {
  const bool sig_set = f.signature_source != SignatureSource::default_;
  std::string model = f.convention.value_or("unknown");
  const bool modellock = f.convention.has_value() && *f.convention != "unknown";
  bool outputlock = sig_set && !f.ret.is_default;
  DecompElement rtype = f.ret.type;
  std::optional<std::vector<StorageVarnode>> rstore = f.ret.storage;
  if (!rstore) {  // invalid storage: unlocked void
    outputlock = false;
    rstore = std::vector<StorageVarnode>{};
    rtype = el("void");
  }
  const bool voidlock = sig_set && f.params.empty();
  const bool noreturn = f.noreturn || f.call_fixup_noreturn;

  Attrs a;
  if (f.extrapop) a.emplace_back("extrapop", i64(*f.extrapop));
  else a.emplace_back("extrapop", std::string("unknown"));
  a.emplace_back("model", model);
  if (modellock) a.emplace_back("modellock", true);
  if (f.varargs) a.emplace_back("dotdotdot", true);
  if (voidlock) a.emplace_back("voidlock", true);
  if (f.is_inline) a.emplace_back("inline", true);
  if (noreturn) a.emplace_back("noreturn", true);
  if (f.custom_storage) a.emplace_back("custom", true);

  Attrs ra;
  if (outputlock) ra.emplace_back("typelock", true);
  int sz = f.ret.size < 0 ? 1 : f.ret.size;
  DecompElement raddr = el("addr");
  if (!rstore->empty() && !f.ret.void_storage) {
    int storage_size = 0;
    for (const auto &v : *rstore) storage_size += v.size;
    raddr = encode_storage(*rstore, sz != storage_size ? sz : 0);
  }
  std::vector<DecompElement> kids{el("returnsym", std::move(ra), {std::move(raddr), std::move(rtype)})};
  if (!f.call_fixup.empty()) kids.push_back(el("inject", {{"content", f.call_fixup}}));
  return el("prototype", std::move(a), std::move(kids));
}

std::uint64_t function_scope_id(const FunctionFacts &f, std::uint64_t at) {
  if (f.id != 0) return f.id;
  // Unique per address, and unlike the ids Ghidra's database hands out
  // (small) or the decompiler gives its temporary functions (0x57AB12CD
  // in the high half, e.g. while recovering a jump table).
  return (std::uint64_t{0x5245564B} << 32) | (at & 0xffffffffULL);
}

}  // namespace

std::string to_xml(const DecompElement &e) {
  std::ostringstream os;
  write_xml(os, e, 0);
  return os.str();
}

ghidra::Element *to_element(const DecompElement &e) { return build_element(e, nullptr); }

// HighFunctionSymbol.encode via HighFunction.encode, with the local symbol
// map of LocalSymbolMap.grabFromFunction.
DecompElement encode_function_symbol(const FunctionFacts &f, std::uint64_t at, bool include_default_names, int size,
                                     const std::vector<EquateSymbolFacts> *equates) {
  std::vector<std::pair<std::uint64_t, DecompElement>> syms;
  std::uint64_t next_id = 0;
  auto key_of = [&](std::uint64_t id) { return id != 0 ? id : kIdBase + next_id++; };

  for (const LocalFacts &l : f.locals) {
    SymbolHeader h;
    h.name = l.name;
    h.typelock = !l.undefined;
    // A variable committed without a name (a retype; Java always has one)
    // is named by the decompiler.
    h.namelock = !l.name.empty();
    h.id = key_of(l.id);
    std::vector<DecompElement> kids;
    kids.push_back(el("symbol", header_attrs(h), {l.type}));
    if (l.hash) {
      kids.push_back(el("hash", {{"val", *l.hash}}));
      kids.push_back(encode_rangelist(f.entry + static_cast<std::uint64_t>(static_cast<std::int64_t>(l.first_use))));
    } else {
      int storage_size = 0;
      for (const auto &v : l.storage) storage_size += v.size;
      long logical = (l.is_float && l.type_size != storage_size) ? l.type_size : 0;
      kids.push_back(encode_storage(l.storage, logical));
      std::optional<std::uint64_t> pc;
      if (!l.storage.empty() && l.storage[0].space != "stack" && l.storage[0].space != "ram")
        pc = f.entry + static_cast<std::uint64_t>(static_cast<std::int64_t>(l.first_use));
      kids.push_back(encode_rangelist(pc));
    }
    syms.emplace_back(h.id, el("mapsym", {}, std::move(kids)));
  }

  const bool lock = f.signature_source != SignatureSource::default_;
  bool internal_invalid = false;
  for (const ParamFacts &p : f.params)
    if (!p.valid) internal_invalid = true;
  for (std::size_t i = 0; i < f.params.size(); ++i) {
    const ParamFacts &p = f.params[i];
    if (!p.valid) break;
    SymbolHeader h;
    h.name = p.name;
    h.namelock = include_default_names || is_user_defined_name(p.name);
    h.typelock = lock && !internal_invalid;
    h.category = 0;
    h.index = static_cast<int>(i);
    h.this_ptr = p.auto_kind == "THIS";
    h.hidden = p.auto_kind == "RETURN_STORAGE_PTR";
    h.id = key_of(p.id);
    std::optional<std::uint64_t> pc;
    if (!p.stack) pc = f.entry - 1;
    std::vector<DecompElement> kids;
    kids.push_back(el("symbol", header_attrs(h), {p.type}));
    kids.push_back(encode_storage(p.storage));
    kids.push_back(encode_rangelist(pc));
    syms.emplace_back(h.id, el("mapsym", {}, std::move(kids)));
  }

  // LocalSymbolMap.grabEquates: an EquateSymbol per constant (a
  // DynamicEntry: its hash and the instruction), name-locked when it has a
  // name, else a conversion (EquateSymbol.encode's format).
  if (equates != nullptr)
    for (const EquateSymbolFacts &q : *equates) {
      SymbolHeader h;
      h.name = q.name;
      h.namelock = !q.name.empty();
      h.category = 1;
      h.id = key_of(0);
      Attrs a = header_attrs(h);
      static const char *kFormats[] = {"", "hex", "dec", "oct", "bin", "char"};
      if (q.format >= 1 && q.format <= 5) a.emplace_back("format", std::string(kFormats[q.format]));
      std::vector<DecompElement> kids;
      kids.push_back(el("equatesymbol", std::move(a), {el("value", {{"content", q.value}})}));
      kids.push_back(el("hash", {{"val", q.hash}}));
      kids.push_back(encode_rangelist(q.addr));
      syms.emplace_back(h.id, el("mapsym", {}, std::move(kids)));
    }

  const std::uint64_t parent = f.ns.empty() ? 0 : f.ns.back().first;
  DecompElement scope = el("scope", {{"name", f.name}},
                           {el("parent", {{"id", parent}}), el("rangelist"),
                            el("symbollist", {}, hashmap_order(std::move(syms)))});
  DecompElement localdb = el("localdb", {{"lock", false}, {"main", std::string("stack")}}, {std::move(scope)});

  Attrs fa{{"id", function_scope_id(f, at)}, {"name", f.name}, {"size", i64(size)}};
  if (f.is_inline) fa.emplace_back("inline", true);
  if (f.noreturn) fa.emplace_back("noreturn", true);
  DecompElement func = el("function", std::move(fa),
                          {el("addr", {{"space", space_of_ram()}, {"offset", at}}), std::move(localdb),
                           encode_prototype(f)});
  return el("mapsym", {},
            {std::move(func), el("addr", {{"space", space_of_ram()}, {"offset", at}, {"size", i64(size)}}),
             el("rangelist")});
}

// HighCodeSymbol for defined (or symbol-carrying undefined) data.
DecompElement encode_data_symbol(const DataFacts &d) {
  SymbolHeader h;
  h.id = d.id;
  h.name = d.name;
  h.typelock = true;
  h.namelock = true;
  h.mutability = d.mutability;
  return el("mapsym", {},
            {el("symbol", header_attrs(h), {d.type}),
             el("addr", {{"space", space_of_ram()}, {"offset", d.addr}, {"size", i64(static_cast<long long>(d.length))}}),
             el("rangelist")});
}

// HighLabelSymbol.
DecompElement encode_label_symbol(const LabelFacts &l) {
  SymbolHeader h;
  h.name = l.name;
  h.typelock = true;
  h.namelock = true;
  return el("mapsym", {},
            {el("labelsym", header_attrs(h)),
             el("addr", {{"space", space_of_ram()}, {"offset", l.addr}, {"size", i64(1)}}), el("rangelist")});
}

// HighExternalSymbol: resolves at the slot itself.
DecompElement encode_external_ref(std::uint64_t slot, const std::string &label) {
  Attrs a;
  if (!label.empty()) a.emplace_back("name", label + "_exref");
  return el("mapsym", {},
            {el("externrefsymbol", std::move(a), {el("addr", {{"space", space_of_ram()}, {"offset", slot}})}),
             el("addr", {{"space", space_of_ram()}, {"offset", slot}, {"size", i64(1)}}), el("rangelist")});
}

DecompElement encode_undefined_symbol(std::uint64_t addr, const std::string &name, Mutability mutability) {
  DataFacts d;
  d.addr = addr;
  d.name = name;
  d.length = 1;
  d.type = el("typeref", {{"name", std::string("undefined")}, {"id", std::uint64_t{0xc000000000000000ULL}}});
  d.mutability = mutability;
  return encode_data_symbol(d);
}

}  // namespace revkit::lift
