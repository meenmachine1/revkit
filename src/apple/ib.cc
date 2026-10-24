// Interface Builder's compiled nibs and NSKeyedArchiver archives.
// Ported in part from rea (https://github.com/morluto/rea), MIT License,
// Copyright (c) 2026 morluto: the NIBArchive layout and checks follow
// src/artifacts/apple/NibArchive.ts, and the connections' key names
// (UISource, UIDestination, UILabel, UIEventMask; NSSource, NSDestination,
// NSLabel) and class swappers follow src/domain/apple/
// interfaceBuilderKeyedArchive.ts and src/artifacts/apple/
// InterfaceBuilderAnalysis.ts. Written in C++ for revkit; the format is
// also described in public write-ups of NIBArchive. THIRD_PARTY_NOTICES.md.

#include "revkit/apple/ib.hh"

#include "text.hh"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <set>

namespace revkit::apple {

// ---- NIBArchive -------------------------------------------------------------

const NibValue *NibObject::get(std::string_view key) const {
  for (const auto &[k, v] : values)
    if (k == key) return &v;
  return nullptr;
}

bool is_nib_archive(std::span<const std::byte> head) {
  return head.size() >= 14 && std::memcmp(head.data(), "NIBArchive", 10) == 0;
}

namespace {

constexpr std::size_t kHeader = 50;

struct NibReader {
  std::span<const std::byte> b;
  std::size_t at = 0;
  std::size_t end = 0;

  std::uint8_t u8() {
    if (at >= end) throw Error("a NIBArchive table runs past its end");
    return static_cast<std::uint8_t>(b[at++]);
  }
  // NIBArchive's variable integers: 7 bits a byte, low first, the last
  // byte with its high bit set.
  std::uint32_t varint() {
    std::uint64_t v = 0;
    for (int i = 0; i < 5; ++i) {
      const std::uint8_t c = u8();
      v |= static_cast<std::uint64_t>(c & 0x7f) << (7 * i);
      if (c & 0x80) {
        if (v > 0x7fffffff) throw Error("a NIBArchive variable integer out of range");
        return static_cast<std::uint32_t>(v);
      }
    }
    throw Error("a NIBArchive variable integer too long");
  }
  void need(std::size_t n) {
    if (n > end - at) throw Error("a NIBArchive table runs past its end");
  }
  std::uint64_t le(unsigned n) {
    need(n);
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(b[at + i])) << (8 * i);
    at += n;
    return v;
  }
  std::string bytes(std::size_t n) {
    need(n);
    std::string s(reinterpret_cast<const char *>(b.data() + at), n);
    at += n;
    return s;
  }
};

std::uint32_t le32(std::span<const std::byte> b, std::size_t at) {
  return static_cast<std::uint32_t>(b[at]) | static_cast<std::uint32_t>(b[at + 1]) << 8 |
         static_cast<std::uint32_t>(b[at + 2]) << 16 | static_cast<std::uint32_t>(b[at + 3]) << 24;
}

}  // namespace

NibArchive parse_nib_archive(std::span<const std::byte> b, const Limits &limits) {
  if (b.size() > limits.max_input) throw LimitError("a nib larger than " + std::to_string(limits.max_input >> 20) + " MiB");
  if (b.size() < kHeader || !is_nib_archive(b)) throw Error("not a NIBArchive");
  NibArchive out;
  out.format_version = le32(b, 10);
  out.coder_version = le32(b, 14);
  if (out.format_version != 1) throw Error("NIBArchive format version " + std::to_string(out.format_version) + " isn't read");
  const std::uint32_t n_objects = le32(b, 18), o_off = le32(b, 22), n_keys = le32(b, 26), k_off = le32(b, 30),
                      n_values = le32(b, 34), v_off = le32(b, 38), n_classes = le32(b, 42), c_off = le32(b, 46);
  // The tables are in this order, inside the file; a count can't pass the
  // bytes its table has (each record takes at least one byte).
  std::size_t prev = kHeader;
  for (std::uint32_t off : {o_off, k_off, v_off, c_off}) {
    if (off < prev || off > b.size()) throw Error("NIBArchive table offsets out of order or outside the file");
    prev = off;
  }
  if (n_objects > k_off - o_off || n_keys > v_off - k_off || n_values > c_off - v_off || n_classes > b.size() - c_off)
    throw Error("NIBArchive counts larger than their tables");
  if (static_cast<std::uint64_t>(n_objects) + n_values > limits.max_values)
    throw LimitError("a nib with more than " + std::to_string(limits.max_values) + " objects and values");
  std::uint64_t charged = 0;
  auto charge = [&](std::uint64_t n) {
    charged += n;
    if (charged > limits.max_value_bytes) throw LimitError("a nib's strings and data pass the limit");
  };
  // Classes.
  std::vector<std::string> classes;
  classes.reserve(n_classes);
  {
    NibReader r{b, c_off, b.size()};
    for (std::uint32_t i = 0; i < n_classes; ++i) {
      const std::uint32_t len = r.varint(), extra = r.varint();
      if (extra > 16) throw Error("a NIBArchive class with too many extra values");
      r.need(std::size_t{extra} * 4);
      r.at += std::size_t{extra} * 4;
      std::string name = r.bytes(len);
      while (!name.empty() && name.back() == '\0') name.pop_back();
      charge(name.size());
      classes.push_back(detail::valid_utf8(name));
    }
  }
  // Keys.
  std::vector<std::string> keys;
  keys.reserve(n_keys);
  {
    NibReader r{b, k_off, v_off};
    for (std::uint32_t i = 0; i < n_keys; ++i) {
      const std::uint32_t len = r.varint();
      std::string k = r.bytes(len);
      charge(k.size());
      keys.push_back(detail::valid_utf8(k));
    }
  }
  // Values.
  std::vector<std::pair<std::uint32_t, NibValue>> values;
  values.reserve(n_values);
  {
    NibReader r{b, v_off, c_off};
    for (std::uint32_t i = 0; i < n_values; ++i) {
      const std::uint32_t key = r.varint();
      if (key >= n_keys) throw Error("a NIBArchive value with a key past the key table");
      NibValue v;
      const std::uint8_t type = r.u8();
      switch (type) {
        case 0: v.type = NibValue::Type::integer; v.integer = static_cast<std::int8_t>(r.le(1)); break;
        case 1: v.type = NibValue::Type::integer; v.integer = static_cast<std::int16_t>(r.le(2)); break;
        case 2: v.type = NibValue::Type::integer; v.integer = static_cast<std::int32_t>(r.le(4)); break;
        case 3: v.type = NibValue::Type::integer; v.integer = static_cast<std::int64_t>(r.le(8)); break;
        case 4: v.type = NibValue::Type::boolean; v.boolean = true; break;
        case 5: v.type = NibValue::Type::boolean; v.boolean = false; break;
        case 6: {
          v.type = NibValue::Type::real;
          const std::uint32_t bits = static_cast<std::uint32_t>(r.le(4));
          float f;
          std::memcpy(&f, &bits, 4);
          v.real = f;
          break;
        }
        case 7: {
          v.type = NibValue::Type::real;
          const std::uint64_t bits = r.le(8);
          std::memcpy(&v.real, &bits, 8);
          break;
        }
        case 8: {
          v.type = NibValue::Type::data;
          const std::uint32_t len = r.varint();
          v.data = r.bytes(len);
          charge(v.data.size());
          break;
        }
        case 9: v.type = NibValue::Type::nil; break;
        case 10:
          v.type = NibValue::Type::ref;
          v.ref = static_cast<std::uint32_t>(r.le(4));
          if (v.ref >= n_objects) throw Error("a NIBArchive reference past the object table");
          break;
        default: throw Error("a NIBArchive value of unknown type " + std::to_string(type));
      }
      values.emplace_back(key, std::move(v));
    }
  }
  // Objects.
  out.objects.reserve(n_objects);
  {
    NibReader r{b, o_off, k_off};
    for (std::uint32_t i = 0; i < n_objects; ++i) {
      const std::uint32_t cls = r.varint(), start = r.varint(), count = r.varint();
      if (cls >= n_classes || start > n_values || count > n_values - start)
        throw Error("NIBArchive object " + std::to_string(i) + " names a class or values past their tables");
      NibObject o;
      o.class_name = classes[cls];
      o.values.reserve(count);
      for (std::uint32_t k = start; k < start + count; ++k) o.values.emplace_back(keys[values[k].first], values[k].second);
      charge(16 * std::uint64_t{count});
      out.objects.push_back(std::move(o));
    }
  }
  return out;
}

// ---- NSKeyedArchiver -----------------------------------------------------------

bool KeyedArchive::is_keyed_archive(const Value &v) {
  const Value *a = v.get("$archiver");
  const Value *o = v.get("$objects");
  const Value *t = v.get("$top");
  return a && a->as_string() && o && o->is(Value::Type::array) && t && t->is(Value::Type::dict);
}

KeyedArchive::KeyedArchive(const Value &v) {
  if (!is_keyed_archive(v)) throw Error("not an NSKeyedArchiver archive ($archiver, $objects, $top)");
  objects_ = &v.get("$objects")->array;
  top_ = v.get("$top");
}

std::optional<std::uint64_t> KeyedArchive::top(std::string_view key) const {
  const Value *x = top_->get(key);
  if (!x) return std::nullopt;
  if (x->is(Value::Type::uid)) return x->uid;
  // An XML archive's UID: {"CF$UID": n}.
  if (const Value *u = x->get("CF$UID"); u && u->as_int()) return static_cast<std::uint64_t>(*u->as_int());
  return std::nullopt;
}

const Value *KeyedArchive::object(std::uint64_t uid) const {
  return uid < objects_->size() ? &(*objects_)[static_cast<std::size_t>(uid)] : nullptr;
}

namespace {

std::optional<std::uint64_t> uid_of(const Value *x) {
  if (!x) return std::nullopt;
  if (x->is(Value::Type::uid)) return x->uid;
  if (x->is(Value::Type::dict) && x->dict.size() == 1)
    if (const Value *u = x->get("CF$UID"); u && u->as_int() && *u->as_int() >= 0) return static_cast<std::uint64_t>(*u->as_int());
  return std::nullopt;
}

}  // namespace

std::string KeyedArchive::class_name(std::uint64_t uid) const {
  const Value *o = object(uid);
  if (!o || !o->is(Value::Type::dict)) return "";
  auto c = uid_of(o->get("$class"));
  if (!c) return "";
  const Value *cls = object(*c);
  return cls ? cls->string_at("$classname") : "";
}

const Value *KeyedArchive::field(std::uint64_t uid, std::string_view key) const {
  const Value *o = object(uid);
  return o ? o->get(key) : nullptr;
}

std::optional<std::uint64_t> KeyedArchive::ref(std::uint64_t uid, std::string_view key) const {
  auto r = uid_of(field(uid, key));
  if (r && *r == 0) return std::nullopt;  // $null
  return r;
}

std::optional<std::string> KeyedArchive::string_of(std::uint64_t uid) const {
  const Value *o = object(uid);
  if (!o) return std::nullopt;
  if (const std::string *s = o->as_string()) {
    if (uid == 0 && *s == "$null") return std::nullopt;
    return *s;
  }
  if (o->is(Value::Type::dict)) {
    if (const Value *s = o->get("NS.string"); s && s->as_string()) return *s->as_string();
    if (const Value *s = o->get("NS.bytes"); s && (s->is(Value::Type::data) || s->is(Value::Type::string)))
      return detail::valid_utf8(s->bytes);
  }
  return std::nullopt;
}

std::optional<std::string> KeyedArchive::string(std::uint64_t uid, std::string_view key) const {
  const Value *f = field(uid, key);
  if (!f) return std::nullopt;
  if (const std::string *s = f->as_string()) return *s;
  if (auto r = uid_of(f)) return string_of(*r);
  return std::nullopt;
}

std::vector<std::uint64_t> KeyedArchive::array_of(std::uint64_t uid) const {
  std::vector<std::uint64_t> out;
  const Value *o = object(uid);
  if (!o) return out;
  const Value *items = o->get("NS.objects");
  if (!items || !items->is(Value::Type::array)) return out;
  for (const Value &x : items->array)
    if (auto r = uid_of(&x)) out.push_back(*r);
  return out;
}

std::vector<std::uint64_t> KeyedArchive::array(std::uint64_t uid, std::string_view key) const {
  auto r = ref(uid, key);
  return r ? array_of(*r) : std::vector<std::uint64_t>{};
}

Value KeyedArchive::resolve(std::uint64_t max_values) const {
  std::vector<bool> expanded(objects_->size(), false);
  std::uint64_t count = 0;
  auto ref_value = [&](std::uint64_t uid) {
    Value r;
    r.type = Value::Type::dict;
    Value u;
    u.type = Value::Type::uid;
    u.uid = uid;
    r.dict.push_back(DictEntry{"$ref", u});
    if (std::string c = class_name(uid); !c.empty()) r.dict.push_back(DictEntry{"$class", Value::make_string(c)});
    return r;
  };
  std::function<Value(const Value &, unsigned)> value;
  std::function<Value(std::uint64_t, unsigned)> obj = [&](std::uint64_t uid, unsigned depth) -> Value {
    const Value *o = object(uid);
    if (!o) return ref_value(uid);
    if (uid == 0) return Value{};  // $null
    if (expanded[static_cast<std::size_t>(uid)] || depth > 96 || count >= max_values) return ref_value(uid);
    expanded[static_cast<std::size_t>(uid)] = true;
    if (!o->is(Value::Type::dict) || !o->get("$class")) return value(*o, depth + 1);
    const std::string cls = class_name(uid);
    // Collections as what they hold.
    const Value *keys = o->get("NS.keys");
    const Value *objs = o->get("NS.objects");
    if (keys && objs && keys->is(Value::Type::array) && objs->is(Value::Type::array)) {
      Value d;
      d.type = Value::Type::dict;
      for (std::size_t i = 0; i < keys->array.size() && i < objs->array.size(); ++i) {
        std::string k;
        if (auto ku = uid_of(&keys->array[i])) k = string_of(*ku).value_or("$" + std::to_string(*ku));
        else if (const std::string *s = keys->array[i].as_string()) k = *s;
        d.dict.push_back(DictEntry{k, value(objs->array[i], depth + 1)});
      }
      detail::dedupe(d.dict);
      return d;
    }
    if (objs && objs->is(Value::Type::array) && !o->get("NS.keys")) {
      Value a;
      a.type = Value::Type::array;
      for (const Value &x : objs->array) a.array.push_back(value(x, depth + 1));
      return a;
    }
    if (auto s = string_of(uid); s && (cls == "NSString" || cls == "NSMutableString")) return Value::make_string(*s);
    Value d;
    d.type = Value::Type::dict;
    d.dict.push_back(DictEntry{"$class", Value::make_string(cls)});
    for (const DictEntry &e : o->dict)
      if (e.key != "$class") d.dict.push_back(DictEntry{e.key, value(e.value, depth + 1)});
    return d;
  };
  value = [&](const Value &v, unsigned depth) -> Value {
    ++count;
    if (auto u = uid_of(&v)) return obj(*u, depth + 1);
    if (v.is(Value::Type::array)) {
      Value a;
      a.type = Value::Type::array;
      for (const Value &x : v.array) a.array.push_back(value(x, depth + 1));
      return a;
    }
    if (v.is(Value::Type::dict)) {
      Value d;
      d.type = Value::Type::dict;
      for (const DictEntry &e : v.dict) d.dict.push_back(DictEntry{e.key, value(e.value, depth + 1)});
      return d;
    }
    return v;
  };
  Value top;
  top.type = Value::Type::dict;
  for (const DictEntry &e : top_->dict) top.dict.push_back(DictEntry{e.key, value(e.value, 0)});
  Value out;
  out.type = Value::Type::dict;
  out.dict.push_back(DictEntry{"$top", std::move(top)});
  return out;
}

// ---- Interface Builder documents -------------------------------------------------

const IbObject *IbDocument::object(std::uint32_t id) const {
  for (const IbObject &o : objects)
    if (o.id == id) return &o;
  return nullptr;
}

std::vector<std::string> control_event_names(std::uint64_t mask) {
  static const std::pair<unsigned, const char *> kEvents[] = {
      {0, "touchDown"},          {1, "touchDownRepeat"},       {2, "touchDragInside"},     {3, "touchDragOutside"},
      {4, "touchDragEnter"},     {5, "touchDragExit"},         {6, "touchUpInside"},       {7, "touchUpOutside"},
      {8, "touchCancel"},        {12, "valueChanged"},         {13, "primaryActionTriggered"}, {14, "menuActionTriggered"},
      {16, "editingDidBegin"},   {17, "editingChanged"},       {18, "editingDidEnd"},      {19, "editingDidEndOnExit"}};
  std::vector<std::string> out;
  std::uint64_t rest = mask;
  for (const auto &[bit, name] : kEvents)
    if (mask & (std::uint64_t{1} << bit)) {
      out.push_back(name);
      rest &= ~(std::uint64_t{1} << bit);
    }
  if (rest) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(rest));
    out.push_back(buf);
  }
  return out;
}

namespace {

constexpr std::size_t kMaxIbObjects = 1u << 18;

// Classes that hold a nib's plumbing, not its interface.
bool plumbing(std::string_view c) {
  static const std::set<std::string_view> kPlumbing = {
      "NSObject", "NSString", "NSMutableString", "NSArray", "NSMutableArray", "NSSet", "NSMutableSet",
      "NSDictionary", "NSMutableDictionary", "NSNumber", "NSData", "NSMutableData", "NSNull", "NSIBObjectData",
      "UIRuntimeOutletConnection", "UIRuntimeEventConnection", "UIRuntimeOutletCollectionConnection",
      "NSNibControlConnector", "NSNibOutletConnector", "NSNibAuxiliaryActionConnector", "NSNibBindingConnector",
      "NSIBUserDefinedRuntimeAttributesConnector", "NSNibConnector", "NSColor", "NSFont", "UIColor", "UIFont",
      "NSURL", "NSLocale", "NSValue", "UIImageNibPlaceholder"};
  return kPlumbing.contains(c);
}

const char *kLabelKeys[] = {"UIAccessibilityLabel", "UIText", "UITitle", "UIPlaceholder", "UIAccessibilityIdentifier",
                            "UIStoryboardIdentifier", "UIRestorationIdentifier", "NSTitle", "NSContents",
                            "NSLabel", "NSPlaceholderString", "NSToolTip", "NSStoryboardIdentifier"};

class NibDocumentReader {
 public:
  explicit NibDocumentReader(const NibArchive &a) : a_(a) {}

  IbDocument run() {
    IbDocument d;
    d.format = "nib:archive";
    const std::uint32_t n = static_cast<std::uint32_t>(a_.objects.size());
    if (n > kMaxIbObjects) throw LimitError("a nib with more than " + std::to_string(kMaxIbObjects) + " objects");
    // The root: object 0, else the first with UINibConnectionsKey.
    std::optional<std::uint32_t> root;
    for (std::uint32_t i = 0; i < n && !root; ++i)
      if (a_.objects[i].get("UINibConnectionsKey")) root = i;
    std::vector<std::uint32_t> conns;
    if (root)
      if (auto r = ref(*root, "UINibConnectionsKey")) conns = array(*r);
    if (conns.empty())
      for (std::uint32_t i = 0; i < n; ++i)
        if (a_.objects[i].class_name.starts_with("UIRuntime") && a_.objects[i].class_name.ends_with("Connection"))
          conns.push_back(i);
    // The interface's objects, with their parents.
    std::map<std::uint32_t, std::uint32_t> parents;
    for (std::uint32_t i = 0; i < n; ++i) {
      if (auto p = ref(i, "UISuperview")) parents.emplace(i, *p);
      if (auto s = ref(i, "UISubviews"))
        for (std::uint32_t c : array(*s)) parents.emplace(c, i);
    }
    for (std::uint32_t i = 0; i < n; ++i) {
      const NibObject &o = a_.objects[i];
      if (plumbing(o.class_name)) continue;
      IbObject x;
      x.id = i;
      x.class_name = o.class_name;
      x.custom_class = o.class_name;
      if (o.class_name == "UIClassSwapper") {
        if (auto c = string(i, "UIClassName")) x.custom_class = *c;
        if (auto c = string(i, "UIOriginalClassName")) x.original_class = *c;
      }
      if (o.class_name == "UIProxyObject") {
        const std::string ident = string(i, "UIProxiedObjectIdentifier").value_or("");
        x.placeholder = ident == "IBFilesOwner" ? "files-owner" : ident == "IBFirstResponder" ? "first-responder" : ident;
        x.label = ident;
      }
      for (const char *k : kLabelKeys)
        if (x.label.empty())
          if (auto s = string(i, k)) x.label = *s;
      x.nib_name = string(i, "UINibName").value_or("");
      x.storyboard_identifier = string(i, "UIStoryboardIdentifier").value_or("");
      if (auto p = parents.find(i); p != parents.end()) x.parent = p->second;
      d.objects.push_back(std::move(x));
    }
    for (std::uint32_t c : conns) {
      const NibObject &o = a_.objects[c];
      IbConnection k;
      k.id = c;
      if (o.class_name == "UIRuntimeEventConnection") k.kind = IbConnection::Kind::action;
      else if (o.class_name.find("Outlet") != std::string::npos) k.kind = IbConnection::Kind::outlet;
      else continue;
      k.label = string(c, "UILabel").value_or("");
      k.source = ref(c, "UISource");
      k.destination = ref(c, "UIDestination");
      if (const NibValue *m = o.get("UIEventMask"); m && m->type == NibValue::Type::integer)
        k.event_mask = static_cast<std::uint64_t>(m->integer);
      k.events = control_event_names(k.event_mask);
      if (!k.source) d.warnings.push_back("connection " + std::to_string(c) + " (" + k.label + ") has no source");
      d.connections.push_back(std::move(k));
    }
    return d;
  }

 private:
  std::optional<std::uint32_t> ref(std::uint32_t obj, std::string_view key) const {
    const NibValue *v = a_.objects[obj].get(key);
    if (!v || v->type != NibValue::Type::ref) return std::nullopt;
    return v->ref;
  }
  // An NSString object's text (NS.bytes), or a value's data as text.
  std::optional<std::string> string(std::uint32_t obj, std::string_view key) const {
    const NibValue *v = a_.objects[obj].get(key);
    if (!v) return std::nullopt;
    if (v->type == NibValue::Type::data) return detail::valid_utf8(v->data);
    if (v->type != NibValue::Type::ref) return std::nullopt;
    const NibObject &s = a_.objects[v->ref];
    if (s.class_name != "NSString" && s.class_name != "NSMutableString" && s.class_name != "NSLocalizableString")
      return std::nullopt;
    const NibValue *bytes = s.get("NS.bytes");
    if (!bytes || bytes->type != NibValue::Type::data) return std::nullopt;
    return detail::valid_utf8(bytes->data);
  }
  // An NSArray's (or NSSet's) elements: its UINibEncoderEmptyKey refs.
  std::vector<std::uint32_t> array(std::uint32_t obj) const {
    std::vector<std::uint32_t> out;
    for (const auto &[k, v] : a_.objects[obj].values)
      if (k == "UINibEncoderEmptyKey" && v.type == NibValue::Type::ref) out.push_back(v.ref);
    return out;
  }

  const NibArchive &a_;
};

IbDocument keyed_document(const KeyedArchive &ka) {
  IbDocument d;
  d.format = "nib:keyed";
  auto data = ka.top("IB.objectdata");
  if (!data) data = ka.top("root");
  if (!data) throw Error("a keyed archive without IB.objectdata (not a nib)");
  if (ka.size() > kMaxIbObjects) throw LimitError("a nib with more than " + std::to_string(kMaxIbObjects) + " objects");
  const auto owner = ka.ref(*data, "NSRoot");
  // Objects: NSObjectsKeys with NSObjectsValues their parents; the owner.
  const auto keys = ka.array(*data, "NSObjectsKeys");
  const auto vals = ka.array(*data, "NSObjectsValues");
  std::map<std::uint64_t, std::uint64_t> parents;
  for (std::size_t i = 0; i < keys.size() && i < vals.size(); ++i) parents.emplace(keys[i], vals[i]);
  std::vector<std::uint64_t> ids = keys;
  if (owner && std::find(ids.begin(), ids.end(), *owner) == ids.end()) ids.insert(ids.begin(), *owner);
  const auto conns = ka.array(*data, "NSConnections");
  // Objects only reached through connections are listed too.
  for (std::uint64_t c : conns)
    for (const char *k : {"NSSource", "NSDestination"})
      if (auto r = ka.ref(c, k); r && std::find(ids.begin(), ids.end(), *r) == ids.end()) ids.push_back(*r);
  for (std::uint64_t id : ids) {
    const std::string cls = ka.class_name(id);
    if (cls.empty() || plumbing(cls)) continue;
    IbObject x;
    x.id = static_cast<std::uint32_t>(id);
    x.class_name = cls;
    x.custom_class = cls;
    if (cls == "NSCustomObject" || cls == "NSCustomView" || cls == "NSClassSwapper") {
      if (auto c = ka.string(id, "NSClassName")) x.custom_class = *c;
      if (auto c = ka.string(id, "NSOriginalClassName")) x.original_class = *c;
    }
    if (cls == "NSWindowTemplate")
      if (auto c = ka.string(id, "NSWindowClass")) x.custom_class = *c;
    if (owner && id == *owner) x.placeholder = "files-owner";
    else if (x.custom_class == "FirstResponder") x.placeholder = "first-responder";
    else if (cls == "NSCustomObject" && x.custom_class == "NSApplication") x.placeholder = "application";
    for (const char *k : kLabelKeys)
      if (x.label.empty())
        if (auto s = ka.string(id, k)) x.label = *s;
    if (auto p = parents.find(id); p != parents.end() && p->second != id) x.parent = static_cast<std::uint32_t>(p->second);
    d.objects.push_back(std::move(x));
  }
  for (std::uint64_t c : conns) {
    const std::string cls = ka.class_name(c);
    IbConnection k;
    k.id = static_cast<std::uint32_t>(c);
    if (cls == "NSNibControlConnector" || cls == "NSNibAuxiliaryActionConnector") k.kind = IbConnection::Kind::action;
    else if (cls == "NSNibOutletConnector") k.kind = IbConnection::Kind::outlet;
    else continue;
    k.label = ka.string(c, "NSLabel").value_or("");
    if (auto s = ka.ref(c, "NSSource")) k.source = static_cast<std::uint32_t>(*s);
    if (auto s = ka.ref(c, "NSDestination")) k.destination = static_cast<std::uint32_t>(*s);
    d.connections.push_back(std::move(k));
  }
  return d;
}

}  // namespace

IbDocument read_interface_builder(std::span<const std::byte> bytes, const Limits &limits) {
  if (is_nib_archive(bytes)) return NibDocumentReader(parse_nib_archive(bytes, limits)).run();
  if (!sniff(bytes)) throw Error("not a compiled nib (NIBArchive or a keyed archive)");
  const Parsed p = parse(bytes, limits);
  const KeyedArchive ka(p.root);
  return keyed_document(ka);
}

}  // namespace revkit::apple
