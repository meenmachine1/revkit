// The metadata as markup: objc4's structures typed and named with clang's
// own symbol names, strings for what they point to, a function at every
// method's implementation with the type encoding's prototype, and Swift's
// descriptors, accessors and vtable entries.

#include "revkit/objc/objc.h"

#include "reader.h"

#include <algorithm>
#include <set>

namespace revkit::objc {

namespace {

using detail::Reader;

class Builder {
 public:
  Builder(const loader::Image &image, msvc::Markup &out, const MarkupOptions &o)
      : r(image), out(out), o(o), p(r.pointer()) {}

  Reader r;
  msvc::Markup &out;
  const MarkupOptions &o;
  unsigned p;
  std::string pass = "objc";

  types::TypeStore &st() { return out.store; }
  types::TypeId u32() { return st().int_type(4, false, types::IntRank::Int); }
  types::TypeId i32() { return st().int_type(4, true, types::IntRank::Int); }
  types::TypeId uptr() { return st().int_type(p, false, p == 8 ? types::IntRank::Long : types::IntRank::Int); }
  types::TypeId chr() { return st().int_type(1, true, types::IntRank::PlainChar); }
  types::TypeId charp() { return ptr(chr()); }
  types::TypeId voidp() { return ptr(st().void_type()); }
  types::TypeId ptr(types::TypeId to) { return st().pointer_to(to, p); }
  types::TypeId fwd(const std::string &name) {
    types::AggregateType a;
    a.name = name;
    a.complete = false;
    return st().intern(types::Type(std::move(a)));
  }
  struct F {
    std::string name;
    types::TypeId type;
  };
  types::TypeId struct_(const std::string &name, const std::vector<F> &fields) {
    types::AggregateType a;
    a.name = name;
    std::uint64_t at = 0;
    std::uint32_t align = 1;
    for (const F &f : fields) {
      const std::uint32_t al = std::max<std::uint32_t>(1, st().align_of(f.type));
      at = (at + al - 1) / al * al;
      a.fields.push_back({f.name, f.type, at * 8, 0});
      at += st().size_of(f.type);
      align = std::max(align, al);
    }
    a.size = (at + align - 1) / align * align;
    return st().intern(types::Type(std::move(a)));
  }

  bool claim(std::uint64_t a, std::uint64_t size) {
    if (size == 0 || a + (size - 1) < a || !r.mapped(a, size)) return false;
    const std::uint64_t last = a + (size - 1);
    auto it = claimed_.lower_bound(a);
    if (it != claimed_.end() && it->first <= last) return false;
    if (it != claimed_.begin() && std::prev(it)->second >= a) return false;
    claimed_.emplace(a, last);
    return true;
  }
  bool data(std::uint64_t a, types::TypeId t, std::string name = {}, std::uint64_t count = 0, bool collapsed = false) {
    const std::uint64_t size = st().size_of(t) * (count == 0 ? 1 : count);
    if (!claim(a, size)) return false;
    out.data.push_back({a, t, count, std::move(name), collapsed, false, pass});
    return true;
  }
  // The NUL-terminated string at `a` as char[n].
  bool string(std::uint64_t a) {
    if (a == 0 || strings_.contains(a)) return false;
    auto s = r.cstr(a, 4096);
    if (!s) return false;
    strings_.insert(a);
    const std::uint64_t n = s->size() + 1;
    if (!claim(a, n)) return false;
    out.data.push_back({a, st().array_of(chr(), n), 0, {}, true, true, pass});
    return true;
  }
  // The string a pointer field points to.
  void string_at(std::uint64_t field) {
    if (auto a = r.ptr(field); a && *a != 0) string(*a);
  }
  void label(std::uint64_t a, std::string name) {
    if (a != 0 && !name.empty()) out.labels.push_back({a, std::move(name), pass});
  }
  void function(std::uint64_t entry, std::string name, types::TypeId proto, std::string why) {
    if (entry == 0 || !r.executable(entry)) return;
    msvc::FunctionDef f;
    f.entry = entry;
    f.name = std::move(name);
    f.prototype = proto;
    f.why = std::move(why);
    f.pass = pass;
    out.functions.push_back(std::move(f));
  }

 private:
  std::map<std::uint64_t, std::uint64_t> claimed_;  // first -> last
  std::set<std::uint64_t> strings_;
};

// Objective-C type encodings (objc4's runtime.h _C_* letters) as types:
// the scalars, pointers, id, Class, SEL; nullopt for what isn't a scalar or
// a pointer (a struct, union, array or bit field by value).
class Encoding {
 public:
  Encoding(Builder &b, std::string_view s) : b_(b), s_(s) {}

  std::optional<types::TypeId> next() {
    skip_qualifiers();
    if (i_ >= s_.size()) return std::nullopt;
    const char c = s_[i_++];
    types::TypeStore &st = b_.st();
    switch (c) {
      case 'c': return st.int_type(1, true, types::IntRank::Char);  // also BOOL on x86-64
      case 'C': return st.int_type(1, false, types::IntRank::Char);
      case 's': return st.int_type(2, true, types::IntRank::Short);
      case 'S': return st.int_type(2, false, types::IntRank::Short);
      case 'i': return st.int_type(4, true, types::IntRank::Int);
      case 'I': return st.int_type(4, false, types::IntRank::Int);
      case 'l': return st.int_type(4, true, types::IntRank::Int);  // long is 32-bit in encodings
      case 'L': return st.int_type(4, false, types::IntRank::Int);
      case 'q': return st.int_type(8, true, types::IntRank::LongLong);
      case 'Q': return st.int_type(8, false, types::IntRank::LongLong);
      case 'f': return st.float_type(4, types::FloatKind::Float);
      case 'd': return st.float_type(8, types::FloatKind::Double);
      case 'B': return st.bool_type(1);
      case 'v': return st.void_type();
      case '*': return b_.charp();
      case ':': return sel();
      case '#': return cls();
      case '@': {
        // @"NSString" (a class), @? (a block): an id either way.
        if (i_ < s_.size() && s_[i_] == '?') ++i_;
        else if (i_ < s_.size() && s_[i_] == '"') {
          const std::size_t end = s_.find('"', i_ + 1);
          if (end == std::string_view::npos) return std::nullopt;
          i_ = end + 1;
        }
        return id();
      }
      case '^': {
        // A pointer: to what the encoding says, else void.
        const std::size_t at = i_;
        if (auto to = next()) return b_.ptr(*to);
        i_ = at;
        if (!skip_one()) return std::nullopt;
        return b_.voidp();
      }
      default: return std::nullopt;
    }
  }
  // The decimal stack offset after a type (or the frame size after the
  // return type).
  void number() {
    while (i_ < s_.size() && (std::isdigit(static_cast<unsigned char>(s_[i_])) || s_[i_] == '-')) ++i_;
  }
  bool done() const { return i_ >= s_.size(); }

  types::TypeId id() { return b_.st().typedef_of("id", b_.ptr(b_.fwd("objc_object"))); }
  types::TypeId sel() { return b_.st().typedef_of("SEL", b_.ptr(b_.fwd("objc_selector"))); }
  types::TypeId cls() { return b_.st().typedef_of("Class", b_.ptr(b_.fwd("objc_class"))); }

 private:
  void skip_qualifiers() {
    while (i_ < s_.size() && std::string_view("rnNoORVA").find(s_[i_]) != std::string_view::npos) ++i_;
  }
  // One type of any kind (for ^ of a struct: skip to its end).
  bool skip_one() {
    skip_qualifiers();
    if (i_ >= s_.size()) return false;
    const char c = s_[i_];
    const char close = c == '{' ? '}' : c == '(' ? ')' : c == '[' ? ']' : 0;
    if (close == 0) {
      ++i_;
      return true;
    }
    int depth = 0;
    for (; i_ < s_.size(); ++i_) {
      if (s_[i_] == c) ++depth;
      else if (s_[i_] == close && --depth == 0) {
        ++i_;
        return true;
      }
    }
    return false;
  }

  Builder &b_;
  std::string_view s_;
  std::size_t i_ = 0;
};

// The prototype of a method: ret (self, _cmd, args...), self typed `self`.
std::optional<types::TypeId> prototype(Builder &b, const std::string &types, std::optional<types::TypeId> self) {
  if (types.empty()) return std::nullopt;
  Encoding e(b, types);
  auto ret = e.next();
  if (!ret) return std::nullopt;
  e.number();
  types::FunctionType f;
  f.ret = *ret;
  for (int n = 0; !e.done() && n < 64; ++n) {
    auto t = e.next();
    if (!t) return std::nullopt;
    e.number();
    std::string name = n == 0 ? "self" : n == 1 ? "_cmd" : "";
    if (n == 0 && self) *t = *self;
    f.params.push_back({std::move(name), *t});
  }
  if (f.params.size() < 2) return std::nullopt;
  return b.st().function(std::move(f));
}

// An ivar's type as a field: the encoding's scalar or pointer of the ivar's
// size, else undefined bytes.
types::TypeId ivar_type(Builder &b, const Ivar &v) {
  Encoding e(b, v.type);
  if (auto t = e.next(); t && e.done() && b.st().size_of(*t) == v.size) return *t;
  return v.size == 0 ? b.st().undefined(1) : b.st().array_of(b.st().undefined(1), v.size);
}

}  // namespace

msvc::Markup markup(const loader::Image &image, const Metadata &md, const MarkupOptions &o) {
  msvc::Markup out;
  if (image.format != loader::Format::macho) return out;
  Builder b(image, out, o);
  types::TypeStore &st = b.st();
  const unsigned p = b.p;
  Encoding names(b, "");

  // ---- objc4's structures (Ghidra's names) ----
  const types::TypeId class_fwd = b.fwd("class_t");
  // (A selector is its name's C string: char *, so a message send's
  // selector reads as the string.)
  const types::TypeId method_t = b.struct_("method_t", {{"name", b.charp()}, {"types", b.charp()}, {"imp", b.voidp()}});
  const types::TypeId method_small_t =
      b.struct_("method_small_t", {{"name", b.i32()}, {"types", b.i32()}, {"imp", b.i32()}});
  const types::TypeId method_list_t = b.struct_("method_list_t", {{"entsizeAndFlags", b.u32()}, {"count", b.u32()}});
  const types::TypeId ivar_t = b.struct_("ivar_t", {{"offset", b.ptr(p == 8 ? b.u32() : b.u32())},
                                                    {"name", b.charp()},
                                                    {"type", b.charp()},
                                                    {"alignment_raw", b.u32()},
                                                    {"size", b.u32()}});
  const types::TypeId ivar_list_t = b.struct_("ivar_list_t", {{"entsize", b.u32()}, {"count", b.u32()}});
  const types::TypeId property_t = b.struct_("property_t", {{"name", b.charp()}, {"attributes", b.charp()}});
  const types::TypeId property_list_t = b.struct_("property_list_t", {{"entsize", b.u32()}, {"count", b.u32()}});
  const types::TypeId protocol_list_t = b.struct_("protocol_list_t", {{"count", b.uptr()}});
  std::vector<Builder::F> ro_fields{{"flags", b.u32()}, {"instanceStart", b.u32()}, {"instanceSize", b.u32()}};
  if (p == 8) ro_fields.push_back({"reserved", b.u32()});
  for (const char *f : {"ivarLayout", "name"}) ro_fields.push_back({f, b.charp()});
  ro_fields.push_back({"baseMethods", b.ptr(method_list_t)});
  ro_fields.push_back({"baseProtocols", b.ptr(protocol_list_t)});
  ro_fields.push_back({"ivars", b.ptr(ivar_list_t)});
  ro_fields.push_back({"weakIvarLayout", b.charp()});
  ro_fields.push_back({"baseProperties", b.ptr(property_list_t)});
  const types::TypeId class_ro_t = b.struct_("class_ro_t", ro_fields);
  const types::TypeId class_t = b.struct_("class_t", {{"isa", b.ptr(class_fwd)},
                                                      {"superclass", b.ptr(class_fwd)},
                                                      {"cache", b.voidp()},
                                                      {"vtable", b.voidp()},
                                                      {"data", b.ptr(class_ro_t)}});
  const types::TypeId category_t = b.struct_("category_t", {{"name", b.charp()},
                                                            {"cls", b.ptr(class_t)},
                                                            {"instanceMethods", b.ptr(method_list_t)},
                                                            {"classMethods", b.ptr(method_list_t)},
                                                            {"protocols", b.ptr(protocol_list_t)},
                                                            {"instanceProperties", b.ptr(property_list_t)}});
  const types::TypeId protocol_t = b.struct_("protocol_t", {{"isa", b.voidp()},
                                                            {"name", b.charp()},
                                                            {"protocols", b.ptr(protocol_list_t)},
                                                            {"instanceMethods", b.ptr(method_list_t)},
                                                            {"classMethods", b.ptr(method_list_t)},
                                                            {"optionalInstanceMethods", b.ptr(method_list_t)},
                                                            {"optionalClassMethods", b.ptr(method_list_t)},
                                                            {"instanceProperties", b.ptr(property_list_t)},
                                                            {"size", b.u32()},
                                                            {"flags", b.u32()}});
  const types::TypeId image_info = b.struct_("objc_image_info", {{"version", b.u32()}, {"flags", b.u32()}});

  auto method_list = [&](const std::optional<MethodList> &m, const std::string &name) {
    if (!m) return;
    b.data(m->address, method_list_t, name);
    const types::TypeId elem = m->relative ? method_small_t : method_t;
    if (m->entsize == st.size_of(elem) && !m->methods.empty())
      b.data(m->address + 8, elem, {}, m->methods.size(), true);
    for (std::size_t i = 0; i < m->methods.size(); ++i) {
      const std::uint64_t e = m->address + 8 + i * m->entsize;
      if (!m->relative) {
        b.string_at(e);
        b.string_at(e + p);
      } else if (auto t = b.r.relative(e + 4)) {
        b.string(*t);
      }
    }
  };
  auto list_pair = [&](std::uint64_t list, types::TypeId head, types::TypeId elem, std::size_t n, const std::string &name) {
    if (list == 0) return;
    b.data(list, head, name);
    if (n != 0) b.data(list + 8, elem, {}, n, true);
  };
  auto properties = [&](std::uint64_t list, const std::vector<Property> &v, const std::string &name) {
    list_pair(list, property_list_t, property_t, v.size(), name);
    for (std::size_t i = 0; list != 0 && i < v.size(); ++i) {
      b.string_at(list + 8 + i * 2 * p);
      b.string_at(list + 8 + i * 2 * p + p);
    }
  };
  auto protocol_list = [&](std::uint64_t list, std::size_t n, const std::string &name) {
    if (list == 0) return;
    b.data(list, protocol_list_t, name);
    if (n != 0) b.data(list + p, b.ptr(protocol_t), {}, n, true);
  };
  std::size_t methods = 0;

  // ---- classes: the struct `self` points to, then the structures ----
  std::map<std::string, types::TypeId> self_types;
  for (const Class &c : md.classes) {
    // isa, then the ivars at their offsets, as large as instanceSize.
    types::AggregateType a;
    a.name = c.name;
    a.fields.push_back({"isa", names.cls(), 0, 0});
    std::uint64_t end = p;
    std::vector<Ivar> ivs = c.ivars;
    std::sort(ivs.begin(), ivs.end(), [](const Ivar &x, const Ivar &y) { return x.offset < y.offset; });
    for (const Ivar &v : ivs) {
      // (A root class lists isa itself, at 0; an ivar over another, or of
      // no size, has no field.)
      if (v.offset < end || v.size == 0) continue;
      a.fields.push_back({v.name, ivar_type(b, v), std::uint64_t{v.offset} * 8, 0});
      end = std::uint64_t{v.offset} + v.size;
    }
    a.size = std::max<std::uint64_t>(end, c.instance_size);
    if (c.instance_size <= (1u << 20)) self_types[c.name] = st.intern(types::Type(std::move(a)));
  }
  for (const Class &c : md.classes) {
    b.data(c.address, class_t, "_OBJC_CLASS_$_" + c.name);
    b.data(c.ro, class_ro_t, "__OBJC_CLASS_RO_$_" + c.name);
    b.string_at(c.ro + (p == 8 ? 16 : 12) + p);
    if (c.metaclass) {
      b.data(c.metaclass, class_t, "_OBJC_METACLASS_$_" + c.name);
      b.data(c.meta_ro, class_ro_t, "__OBJC_METACLASS_RO_$_" + c.name);
    }
    method_list(c.instance_methods, "__OBJC_$_INSTANCE_METHODS_" + c.name);
    method_list(c.class_methods, "__OBJC_$_CLASS_METHODS_" + c.name);
    list_pair(c.ivar_list, ivar_list_t, ivar_t, c.ivars.size(), "__OBJC_$_INSTANCE_VARIABLES_" + c.name);
    for (std::size_t i = 0; c.ivar_list != 0 && i < c.ivars.size(); ++i) {
      const std::uint64_t e = c.ivar_list + 8 + i * st.size_of(ivar_t);
      b.string_at(e + p);
      b.string_at(e + 2 * p);
      const Ivar &v = c.ivars[i];
      if (v.offset_address) b.data(v.offset_address, b.u32(), "_OBJC_IVAR_$_" + c.name + "." + v.name);
    }
    properties(c.property_list, c.properties, "__OBJC_$_PROP_LIST_" + c.name);
    protocol_list(c.protocol_list, c.protocols.size(), "__OBJC_CLASS_PROTOCOLS_$_" + c.name);
    auto self = self_types.find(c.name);
    for (const auto *list : {&c.instance_methods, &c.class_methods})
      if (*list)
        for (const Method &m : (*list)->methods) {
          // An instance method's self is the class; a class method's, Class.
          std::optional<types::TypeId> s;
          if (!m.class_method && self != self_types.end()) s = b.ptr(self->second);
          else if (m.class_method) s = names.cls();
          b.function(m.imp, method_name(c.name, {}, m), prototype(b, m.types, s).value_or(types::TypeId()), "objc_method");
          ++methods;
        }
  }

  // ---- categories ----
  for (const Category &k : md.categories) {
    const std::string tag = k.class_name + "_$_" + k.name;
    b.data(k.address, category_t, "__OBJC_$_CATEGORY_" + tag);
    b.string_at(k.address);
    method_list(k.instance_methods, "__OBJC_$_CATEGORY_INSTANCE_METHODS_" + tag);
    method_list(k.class_methods, "__OBJC_$_CATEGORY_CLASS_METHODS_" + tag);
    properties(k.property_list, k.properties, "__OBJC_$_PROP_LIST_" + tag);
    protocol_list(k.protocol_list, k.protocols.size(), "__OBJC_CATEGORY_PROTOCOLS_$_" + tag);
    auto self = self_types.find(k.class_name);
    for (const auto *list : {&k.instance_methods, &k.class_methods})
      if (*list)
        for (const Method &m : (*list)->methods) {
          std::optional<types::TypeId> s;
          if (!m.class_method && self != self_types.end()) s = b.ptr(self->second);
          else if (m.class_method) s = names.cls();
          b.function(m.imp, method_name(k.class_name, k.name, m), prototype(b, m.types, s).value_or(types::TypeId()),
                     "objc_method");
          ++methods;
        }
  }

  // ---- protocols ----
  for (const Protocol &x : md.protocols) {
    b.data(x.address, protocol_t, "__OBJC_PROTOCOL_$_" + x.name);
    b.string_at(x.address + p);
    method_list(x.instance_methods, "__OBJC_$_PROTOCOL_INSTANCE_METHODS_" + x.name);
    method_list(x.class_methods, "__OBJC_$_PROTOCOL_CLASS_METHODS_" + x.name);
    method_list(x.optional_instance_methods, "__OBJC_$_PROTOCOL_INSTANCE_METHODS_OPT_" + x.name);
    method_list(x.optional_class_methods, "__OBJC_$_PROTOCOL_CLASS_METHODS_OPT_" + x.name);
    properties(x.property_list, x.properties, "__OBJC_$_PROP_LIST_" + x.name);
    protocol_list(x.protocol_list, x.protocols.size(), "__OBJC_$_PROTOCOL_REFS_" + x.name);
  }

  // ---- references: pointers to the selectors (char *, in read-only
  // blocks, so a message send shows its selector), classes, protocols ----
  for (const auto &[slot, s] : md.selector_refs) {
    b.data(slot, b.charp());
    b.string_at(slot);
  }
  for (const auto &[slot, name] : md.class_refs) b.data(slot, b.ptr(class_t));
  for (const auto &[slot, name] : md.protocol_refs) b.data(slot, b.ptr(protocol_t));
  for (const loader::Section *s : b.r.sections("__objc_classlist"))
    b.data(s->addr, b.ptr(class_t), {}, s->size / p, true);
  for (const loader::Section *s : b.r.sections("__objc_catlist"))
    b.data(s->addr, b.ptr(category_t), {}, s->size / p, true);
  for (const loader::Section *s : b.r.sections("__objc_protolist"))
    b.data(s->addr, b.ptr(protocol_t), {}, s->size / p, true);
  if (md.image_info) b.data(*md.image_info, image_info);
  out.counts["objc_classes"] = md.classes.size();
  out.counts["objc_categories"] = md.categories.size();
  out.counts["objc_protocols"] = md.protocols.size();
  out.counts["objc_methods"] = methods;
  out.counts["objc_selector_refs"] = md.selector_refs.size();

  // ---- Swift ----
  b.pass = "swift";
  for (const SwiftType &t : md.swift_types) {
    const std::string qualified = t.parent.empty() ? t.name : t.parent + "." + t.name;
    b.label(t.descriptor, qualified + " nominal type descriptor");
    if (t.accessor) b.function(t.accessor, "type metadata accessor for " + qualified, {}, "swift_accessor");
    for (std::uint64_t impl : t.vtable)
      if (impl) b.function(impl, {}, {}, "swift_vtable");
  }
  out.counts["swift_types"] = md.swift_types.size();

  for (const std::string &w : md.warnings) out.warnings.push_back(w);
  // Sorted, one function per entry, as revkit::msvc::analyze leaves them.
  std::sort(out.data.begin(), out.data.end(), [](const msvc::DataDef &x, const msvc::DataDef &y) { return x.address < y.address; });
  std::stable_sort(out.labels.begin(), out.labels.end(),
                   [](const msvc::LabelDef &x, const msvc::LabelDef &y) { return x.address < y.address; });
  out.labels.erase(std::unique(out.labels.begin(), out.labels.end(),
                               [](const msvc::LabelDef &x, const msvc::LabelDef &y) { return x.address == y.address; }),
                   out.labels.end());
  std::stable_sort(out.functions.begin(), out.functions.end(),
                   [](const msvc::FunctionDef &x, const msvc::FunctionDef &y) { return x.entry < y.entry; });
  out.functions.erase(std::unique(out.functions.begin(), out.functions.end(),
                                  [](const msvc::FunctionDef &x, const msvc::FunctionDef &y) { return x.entry == y.entry; }),
                      out.functions.end());
  return out;
}

}  // namespace revkit::objc
