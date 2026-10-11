#include "inputs_json.hh"

#include <cstdint>

namespace rklift {

namespace lift = revkit::lift;

namespace {

std::uint64_t addr(const Json &j) { return parse_hex_string(j.str()); }

lift::DecompElement element(const Json &j) {
  const Json::Array &a = j.array();
  if (a.empty()) throw JsonError("empty type element");
  lift::DecompElement e;
  e.tag = a[0].str();
  if (a.size() > 1) {
    for (const auto &[k, v] : a[1].object()) {
      if (v.is_string()) e.attrs.emplace_back(k, v.str());
      else if (v.is_bool()) e.attrs.emplace_back(k, v.boolean());
      else if (v.is_number()) {
        // Values above INT64_MAX (type ids) stay unsigned; they're written
        // as hex, everything else in decimal.
        std::uint64_t u = v.uint64();
        if (u > static_cast<std::uint64_t>(INT64_MAX)) e.attrs.emplace_back(k, u);
        else e.attrs.emplace_back(k, v.int64());
      }
    }
  }
  if (a.size() > 2)
    for (const Json &c : a[2].array()) e.children.push_back(element(c));
  return e;
}

std::vector<lift::StorageVarnode> storage(const Json &j) {
  std::vector<lift::StorageVarnode> out;
  for (const Json &v : j.array()) {
    const Json::Array &t = v.array();
    out.push_back({t.at(0).str(), addr(t.at(1)), static_cast<int>(t.at(2).int64())});
  }
  return out;
}

std::string space(const Json &rec) {
  const Json *s = rec.find("space");
  return s != nullptr && s->is_string() ? s->str() : std::string();
}

lift::NamespacePath namespace_path(const Json *j) {
  lift::NamespacePath out;
  if (j == nullptr || !j->is_array()) return out;
  for (const Json &e : j->array()) out.emplace_back(e.array().at(0).uint64(), e.array().at(1).str());
  return out;
}

lift::SignatureSource source(const std::string &s) {
  if (s == "ANALYSIS") return lift::SignatureSource::analysis;
  if (s == "IMPORTED") return lift::SignatureSource::imported;
  if (s == "USER_DEFINED") return lift::SignatureSource::user_defined;
  return lift::SignatureSource::default_;
}

std::vector<std::pair<std::uint64_t, std::uint64_t>> body(const Json &j) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
  for (const Json &r : j.array()) out.emplace_back(addr(r.array().at(0)), addr(r.array().at(1)));
  return out;
}

lift::FunctionFacts function(const Json &j) {
  lift::FunctionFacts f;
  if (const Json *e = j.find("entry"); e && e->is_string()) f.entry = addr(*e);
  f.name = j["name"].str();
  if (const Json *b = j.find("body")) f.body = body(*b);
  if (const Json *s = j.find("signature_source"); s && s->is_string()) f.signature_source = source(s->str());
  if (const Json *c = j.find("convention"); c && c->is_string()) f.convention = c->str();
  if (const Json *b = j.find("has_this")) f.has_this = b->boolean();
  if (const Json *x = j.find("extrapop"); x && x->is_number()) f.extrapop = static_cast<int>(x->int64());
  if (const Json *c = j.find("call_fixup"); c && c->is_string()) f.call_fixup = c->str();
  if (const Json *c = j.find("call_fixup_noreturn")) f.call_fixup_noreturn = c->boolean();
  if (const Json *id = j.find("id")) f.id = id->uint64();
  f.ns = namespace_path(j.find("namespace"));
  if (const Json *l = j.find("label"); l && l->is_string()) f.label = l->str();
  if (const Json *b = j.find("varargs")) f.varargs = b->boolean();
  if (const Json *b = j.find("inline")) f.is_inline = b->boolean();
  if (const Json *b = j.find("noreturn")) f.noreturn = b->boolean();
  if (const Json *b = j.find("custom_storage")) f.custom_storage = b->boolean();
  if (const Json *b = j.find("dynamic_storage")) f.dynamic_storage = b->boolean();
  if (const Json *c = j.find("context"); c && c->is_object())
    for (const auto &[name, v] : c->object()) f.context.emplace_back(name, static_cast<std::uint32_t>(v.uint64()));
  if (const Json *b = j.find("context_reach")) f.context_reach = body(*b);
  if (const Json *r = j.find("return")) {
    f.ret.type = element((*r)["type"]);
    if (const Json *d = r->find("default")) f.ret.is_default = d->boolean();
    if (const Json *s = r->find("storage"); s && s->is_array()) f.ret.storage = storage(*s);
    if (const Json *v = r->find("void_storage")) f.ret.void_storage = v->boolean();
    if (const Json *n = r->find("size")) f.ret.size = static_cast<int>(n->int64());
  } else {
    f.ret.type = {"void", {}, {}};
    f.ret.storage = std::vector<lift::StorageVarnode>{};
    f.ret.void_storage = true;
  }
  if (const Json *ps = j.find("params")) {
    for (const Json &p : ps->array()) {
      lift::ParamFacts q;
      q.name = p["name"].str();
      if (const Json *v = p.find("valid")) q.valid = v->boolean();
      if (q.valid) {
        q.storage = storage(p["storage"]);
        if (const Json *s = p.find("stack")) q.stack = s->boolean();
        q.type = element(p["type"]);
      }
      if (const Json *a = p.find("auto"); a && a->is_string()) q.auto_kind = a->str();
      if (const Json *id = p.find("id")) q.id = id->uint64();
      f.params.push_back(std::move(q));
    }
  }
  if (const Json *ls = j.find("locals")) {
    for (const Json &l : ls->array()) {
      lift::LocalFacts v;
      v.name = l["name"].str();
      if (const Json *u = l.find("undefined")) v.undefined = u->boolean();
      if (const Json *u = l.find("first_use")) v.first_use = static_cast<int>(u->int64());
      if (const Json *h = l.find("hash"); h && h->is_string()) {
        v.hash = addr(*h);
        if (const Json *n = l.find("size")) v.size = static_cast<int>(n->int64());
      } else {
        v.storage = storage(l["storage"]);
      }
      v.type = element(l["type"]);
      if (const Json *b = l.find("float")) v.is_float = b->boolean();
      if (const Json *n = l.find("type_size")) v.type_size = static_cast<int>(n->int64());
      if (const Json *id = l.find("id")) v.id = id->uint64();
      f.locals.push_back(std::move(v));
    }
  }
  return f;
}

lift::Mutability mutability(const Json &j) {
  if (!j.is_string()) return lift::Mutability::normal;
  if (j.str() == "constant") return lift::Mutability::constant;
  if (j.str() == "volatile") return lift::Mutability::is_volatile;
  return lift::Mutability::normal;
}

std::vector<std::uint8_t> hex_bytes(const std::string &s) {
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i + 1 < s.size(); i += 2)
    out.push_back(static_cast<std::uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
  return out;
}

void binary_info(const Json &doc, lift::DecompilerInputs &in) {
  const Json &b = doc["binary"];
  if (const Json *l = b.find("language"); l && l->is_string()) in.language = l->str();
  if (const Json *c = b.find("compiler"); c && c->is_string()) in.compiler = c->str();
  if (const Json *c = b.find("default_convention"); c && c->is_string()) in.default_convention = c->str();
  if (const Json *p = b.find("address_prefix"); p && p->is_string()) in.address_prefix = p->str();
}

}  // namespace

lift::DecompilerInputs inputs_from_export(const Json &doc) {
  lift::DecompilerInputs in;
  binary_info(doc, in);
  for (const Json &b : doc["memory"].array()) {
    lift::BlockFacts m;
    m.name = b["name"].str();
    m.start = addr(b["start"]);
    m.end = addr(b["end"]);
    const std::string &perms = b["perms"].str();
    m.write = perms.size() > 1 && perms[1] == 'w';
    m.execute = perms.size() > 2 && perms[2] == 'x';
    if (const Json *v = b.find("initialized")) m.initialized = v->boolean();
    if (const Json *v = b.find("volatile")) m.is_volatile = v->boolean();
    if (const Json *v = b.find("external")) m.external = v->boolean();
    if (const Json *v = b.find("space"); v && v->is_string()) m.space = v->str();
    in.memory.push_back(std::move(m));
  }
  if (const Json *ps = doc.find("patches"))
    for (const Json &p : ps->array()) in.patches.emplace_back(addr(p["addr"]), hex_bytes(p["bytes"].str()));
  if (const Json *ms = doc.find("synthesized_memory"))
    for (const Json &m : ms->array()) in.synthesized_memory.emplace_back(addr(m["addr"]), hex_bytes(m["bytes"].str()));
  for (const Json &f : doc["functions"].array()) in.functions.push_back(function(f));
  for (const Json &d : doc["data"].array()) {
    lift::DataFacts x;
    x.space = space(d);
    x.addr = addr(d["addr"]);
    x.name = d["name"].str();
    x.length = d["length"].uint64();
    x.type = element(d["type"]);
    x.mutability = mutability(d["mutability"]);
    if (const Json *id = d.find("id")) x.id = id->uint64();
    x.ns = namespace_path(d.find("namespace"));
    if (const Json *t = d.find("string"); t && t->is_string()) x.string = t->str();
    in.data.push_back(std::move(x));
  }
  if (const Json *xs = doc.find("external_refs")) {
    for (const Json &x : xs->array()) {
      lift::ExternalRefFacts e;
      e.space = space(x);
      e.addr = addr(x["addr"]);
      e.label = x["label"].str();
      if (const Json *f = x.find("function"); f && f->is_object()) e.function = function(*f);
      in.external_refs.push_back(std::move(e));
    }
  }
  for (const char *key : {"labels", "code_labels"}) {
    auto &list = std::string(key) == "labels" ? in.labels : in.code_labels;
    if (const Json *ls = doc.find(key))
      for (const Json &l : ls->array())
        list.push_back({space(l), addr(l["addr"]), l["name"].str(), namespace_path(l.find("namespace"))});
  }
  if (const Json *cs = doc.find("comments")) {
    for (const Json &c : cs->array()) {
      lift::CommentFacts x;
      x.addr = addr(c["addr"]);
      const std::string &k = c["kind"].str();
      x.kind = k == "eol" ? lift::CommentFacts::eol
               : k == "post" ? lift::CommentFacts::post
               : k == "plate" ? lift::CommentFacts::plate
                              : lift::CommentFacts::pre;
      x.text = c["text"].str();
      in.comments.push_back(std::move(x));
    }
  }
  if (const Json *ts = doc.find("tracked"); ts && ts->is_object()) {
    for (const auto &[entry, sets] : ts->object()) {
      auto &list = in.tracked[parse_hex_string(entry)];
      for (const Json &s : sets.array()) {
        const Json::Array &t = s.array();
        lift::TrackedFacts x;
        if (t.at(2).int64() == 0) x.register_name = t.at(1).str();  // revkit's: by register name
        else x.reg = {t.at(0).str(), addr(t.at(1)), static_cast<int>(t.at(2).int64())};
        x.value = addr(t.at(3));
        list.push_back(std::move(x));
      }
    }
  }
  if (const Json *fo = doc.find("flow_overrides"))
    for (const Json &o : fo->array()) in.flow_overrides.emplace(addr(o["addr"]), o["kind"].str());
  if (const Json *ts = doc.find("types"))
    for (const Json &t : ts->array()) in.types.push_back(element(t));
  return in;
}

lift::DecompilerInputs inputs_from_reference(const Json &doc) {
  lift::DecompilerInputs in;
  binary_info(doc, in);
  for (const Json &j : doc["functions"].array()) {
    lift::FunctionFacts f;
    f.entry = addr(j["entry"]);
    f.name = j["name"].str();
    if (const Json *b = j.find("body")) f.body = body(*b);
    f.convention = "unknown";
    f.ret.type = {"void", {}, {}};
    f.ret.storage = std::vector<lift::StorageVarnode>{};
    f.ret.void_storage = true;
    in.functions.push_back(std::move(f));
  }
  return in;
}

namespace {

Json to_json(const lift::DecompElement &e) {
  Json::Object attrs;
  for (const auto &[k, v] : e.attrs) {
    if (const auto *str = std::get_if<std::string>(&v)) attrs.emplace(k, *str);
    else if (const auto *i = std::get_if<std::int64_t>(&v)) attrs.emplace(k, *i);
    else if (const auto *u = std::get_if<std::uint64_t>(&v)) attrs.emplace(k, *u);
    else if (const auto *b = std::get_if<bool>(&v)) attrs.emplace(k, *b);
  }
  Json::Array out{e.tag, std::move(attrs)};
  if (!e.children.empty()) {
    Json::Array kids;
    for (const lift::DecompElement &c : e.children) kids.push_back(to_json(c));
    out.push_back(std::move(kids));
  }
  return out;
}

Json storage_json(const std::vector<lift::StorageVarnode> &vs) {
  Json::Array out;
  for (const lift::StorageVarnode &v : vs) out.push_back(Json::Array{v.space, hex(v.offset), v.size});
  return out;
}

Json ns_json(const lift::NamespacePath &ns) {
  Json::Array out;
  for (const auto &[id, name] : ns) out.push_back(Json::Array{id, name});
  return out;
}

std::string hex_bytes_string(const std::vector<std::uint8_t> &b) {
  static const char digits[] = "0123456789abcdef";
  std::string s;
  for (std::uint8_t c : b) {
    s.push_back(digits[c >> 4]);
    s.push_back(digits[c & 0xf]);
  }
  return s;
}

const char *source_name(lift::SignatureSource s) {
  switch (s) {
    case lift::SignatureSource::analysis: return "ANALYSIS";
    case lift::SignatureSource::imported: return "IMPORTED";
    case lift::SignatureSource::user_defined: return "USER_DEFINED";
    default: return "DEFAULT";
  }
}

const char *mutability_name(lift::Mutability m) {
  switch (m) {
    case lift::Mutability::constant: return "constant";
    case lift::Mutability::is_volatile: return "volatile";
    default: return "normal";
  }
}

Json function_json(const lift::FunctionFacts &f) {
  Json::Object o;
  o.emplace("entry", hex(f.entry));
  o.emplace("name", f.name);
  Json::Array body;
  for (const auto &[a, b] : f.body) body.push_back(Json::Array{hex(a), hex(b)});
  o.emplace("body", std::move(body));
  o.emplace("signature_source", source_name(f.signature_source));
  if (f.convention) o.emplace("convention", *f.convention);
  o.emplace("has_this", f.has_this);
  if (f.extrapop) o.emplace("extrapop", static_cast<std::int64_t>(*f.extrapop));
  else o.emplace("extrapop", "unknown");
  if (!f.call_fixup.empty()) o.emplace("call_fixup", f.call_fixup);
  if (f.call_fixup_noreturn) o.emplace("call_fixup_noreturn", true);
  if (f.id != 0) o.emplace("id", f.id);
  if (!f.ns.empty()) o.emplace("namespace", ns_json(f.ns));
  if (!f.label.empty()) o.emplace("label", f.label);
  o.emplace("varargs", f.varargs);
  o.emplace("inline", f.is_inline);
  o.emplace("noreturn", f.noreturn);
  o.emplace("custom_storage", f.custom_storage);
  if (f.dynamic_storage) o.emplace("dynamic_storage", true);
  if (!f.context.empty()) {
    Json::Object c;
    for (const auto &[name, v] : f.context) c.emplace(name, static_cast<std::uint64_t>(v));
    o.emplace("context", std::move(c));
  }
  if (!f.context_reach.empty()) {
    Json::Array reach;
    for (const auto &[a, b] : f.context_reach) reach.push_back(Json::Array{hex(a), hex(b)});
    o.emplace("context_reach", std::move(reach));
  }
  Json::Object ret;
  ret.emplace("type", to_json(f.ret.type));
  ret.emplace("default", f.ret.is_default);
  ret.emplace("storage", f.ret.storage ? storage_json(*f.ret.storage) : Json(nullptr));
  ret.emplace("void_storage", f.ret.void_storage);
  ret.emplace("size", static_cast<std::int64_t>(f.ret.size));
  o.emplace("return", std::move(ret));
  Json::Array params;
  for (const lift::ParamFacts &p : f.params) {
    Json::Object q;
    q.emplace("name", p.name);
    q.emplace("valid", p.valid);
    if (p.valid) {
      q.emplace("storage", storage_json(p.storage));
      q.emplace("stack", p.stack);
      q.emplace("type", to_json(p.type));
    }
    if (!p.auto_kind.empty()) q.emplace("auto", p.auto_kind);
    if (p.id != 0) q.emplace("id", p.id);
    params.push_back(std::move(q));
  }
  o.emplace("params", std::move(params));
  Json::Array locals;
  for (const lift::LocalFacts &l : f.locals) {
    Json::Object v;
    v.emplace("name", l.name);
    v.emplace("undefined", l.undefined);
    v.emplace("first_use", static_cast<std::int64_t>(l.first_use));
    if (l.hash) {
      v.emplace("hash", hex(*l.hash));
      v.emplace("size", static_cast<std::int64_t>(l.size));
    } else {
      v.emplace("storage", storage_json(l.storage));
    }
    v.emplace("type", to_json(l.type));
    v.emplace("float", l.is_float);
    v.emplace("type_size", static_cast<std::int64_t>(l.type_size));
    if (l.id != 0) v.emplace("id", l.id);
    locals.push_back(std::move(v));
  }
  o.emplace("locals", std::move(locals));
  return Json(std::move(o));
}

}  // namespace

Json inputs_to_json(const lift::DecompilerInputs &in, bool synthesize_names) {
  Json::Object doc;
  doc.emplace("format", "revkit-decompiler-inputs");
  doc.emplace("format_version", 1);
  doc.emplace("producer", "revkit");
  doc.emplace("symbols_complete", !synthesize_names);
  doc.emplace("binary", Json::Object{{"language", in.language},
                                     {"compiler", in.compiler},
                                     {"default_convention", in.default_convention},
                                     {"address_prefix", in.address_prefix}});
  Json::Array memory;
  for (const lift::BlockFacts &b : in.memory) {
    std::string perms = std::string("r") + (b.write ? "w" : "-") + (b.execute ? "x" : "-");
    Json::Object m{{"name", b.name}, {"start", hex(b.start)}, {"end", hex(b.end)}, {"perms", perms},
                   {"initialized", b.initialized}, {"volatile", b.is_volatile}, {"external", b.external}};
    if (!b.space.empty()) m.emplace("space", b.space);
    memory.push_back(std::move(m));
  }
  doc.emplace("memory", std::move(memory));
  Json::Array patches, synthesized;
  for (const auto &[a, b] : in.patches) patches.push_back(Json::Object{{"addr", hex(a)}, {"bytes", hex_bytes_string(b)}});
  for (const auto &[a, b] : in.synthesized_memory)
    synthesized.push_back(Json::Object{{"addr", hex(a)}, {"bytes", hex_bytes_string(b)}});
  doc.emplace("patches", std::move(patches));
  doc.emplace("synthesized_memory", std::move(synthesized));
  Json::Array functions;
  for (const lift::FunctionFacts &f : in.functions) functions.push_back(function_json(f));
  doc.emplace("functions", std::move(functions));
  Json::Array data;
  for (const lift::DataFacts &d : in.data) {
    Json::Object o{{"addr", hex(d.addr)}, {"name", d.name}, {"length", d.length}, {"type", to_json(d.type)},
                   {"mutability", mutability_name(d.mutability)}};
    if (!d.space.empty()) o.emplace("space", d.space);
    if (d.id != 0) o.emplace("id", d.id);
    if (!d.ns.empty()) o.emplace("namespace", ns_json(d.ns));
    if (d.string) o.emplace("string", *d.string);
    data.push_back(std::move(o));
  }
  doc.emplace("data", std::move(data));
  Json::Array externals;
  for (const lift::ExternalRefFacts &x : in.external_refs) {
    Json::Object o{{"addr", hex(x.addr)}, {"label", x.label}};
    if (!x.space.empty()) o.emplace("space", x.space);
    if (x.function) o.emplace("function", function_json(*x.function));
    externals.push_back(std::move(o));
  }
  doc.emplace("external_refs", std::move(externals));
  for (const char *key : {"labels", "code_labels"}) {
    const auto &list = std::string(key) == "labels" ? in.labels : in.code_labels;
    Json::Array out;
    for (const lift::LabelFacts &l : list) {
      Json::Object o{{"addr", hex(l.addr)}, {"name", l.name}};
      if (!l.space.empty()) o.emplace("space", l.space);
      if (!l.ns.empty()) o.emplace("namespace", ns_json(l.ns));
      out.push_back(std::move(o));
    }
    doc.emplace(key, std::move(out));
  }
  Json::Array comments;
  for (const lift::CommentFacts &c : in.comments) {
    const char *kind = c.kind == lift::CommentFacts::eol    ? "eol"
                       : c.kind == lift::CommentFacts::post ? "post"
                       : c.kind == lift::CommentFacts::plate ? "plate"
                                                             : "pre";
    comments.push_back(Json::Object{{"addr", hex(c.addr)}, {"kind", kind}, {"text", c.text}});
  }
  doc.emplace("comments", std::move(comments));
  Json::Object tracked;
  for (const auto &[entry, list] : in.tracked) {
    Json::Array sets;
    for (const lift::TrackedFacts &t : list) {
      if (!t.register_name.empty()) sets.push_back(Json::Array{"register", t.register_name, 0, hex(t.value)});
      else sets.push_back(Json::Array{t.reg.space, hex(t.reg.offset), t.reg.size, hex(t.value)});
    }
    tracked.emplace(hex(entry), std::move(sets));
  }
  doc.emplace("tracked", std::move(tracked));
  Json::Array overrides;
  for (const auto &[a, kind] : in.flow_overrides) overrides.push_back(Json::Object{{"addr", hex(a)}, {"kind", kind}});
  doc.emplace("flow_overrides", std::move(overrides));
  Json::Array types;
  for (const lift::DecompElement &t : in.types) types.push_back(to_json(t));
  doc.emplace("types", std::move(types));
  return Json(std::move(doc));
}

}  // namespace rklift
