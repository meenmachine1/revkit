// Objective-C 2 metadata (Ghidra's Objc2TypeMetadata): the lists in
// __objc_classlist, __objc_catlist and __objc_protolist, and the
// references in __objc_selrefs, __objc_classrefs, __objc_superrefs and
// __objc_protorefs, as objc4's runtime lays them out.

#include "revkit/objc/objc.h"

#include "reader.h"

#include <algorithm>
#include <cstdio>
#include <set>

namespace revkit::objc {

namespace {

using detail::Reader;

// Caps on what one image is read for.
constexpr std::uint32_t kMaxListEntries = 1 << 16;
constexpr std::size_t kMaxRecords = 1 << 20;

constexpr std::uint32_t kSmallMethodList = 0x80000000;  // method_list_t: relative (int32) entries
constexpr std::uint32_t kEntsizeMask = 0x0000fffc;

// The class name a bound class reference names: "_OBJC_CLASS_$_NSObject"
// and "_OBJC_METACLASS_$_NSObject" are NSObject.
std::string bound_class(const std::string &symbol) {
  for (std::string_view p : {"_OBJC_CLASS_$_", "_OBJC_METACLASS_$_"})
    if (symbol.starts_with(p)) return symbol.substr(p.size());
  return symbol;
}

const std::initializer_list<std::string_view> kData = {"__DATA", "__DATA_CONST", "__DATA_DIRTY", "__AUTH",
                                                        "__AUTH_CONST", "__OBJC_CONST"};

class Scanner {
 public:
  explicit Scanner(const loader::Image &image) : r_(image), p_(r_.pointer()) {}

  Metadata run() {
    // Protocols first: classes and categories name them.
    each_pointer("__objc_protolist", [&](std::uint64_t, std::uint64_t a) { protocol(a); });
    each_pointer("__objc_classlist", [&](std::uint64_t, std::uint64_t a) { cls(a); });
    each_pointer("__objc_nlclslist", [&](std::uint64_t, std::uint64_t a) { cls(a); });
    resolve_supers();  // the superclasses defined here, once all are read
    std::set<std::uint64_t> cats;
    for (const char *list : {"__objc_catlist", "__objc_nlcatlist"})
      each_pointer(list, [&](std::uint64_t, std::uint64_t a) {
        if (cats.insert(a).second) category(a);
      });
    each_pointer("__objc_selrefs", [&](std::uint64_t slot, std::uint64_t a) {
      if (auto s = cstr(a, 1024)) out_.selector_refs[slot] = *s;
    });
    for (const char *refs : {"__objc_classrefs", "__objc_superrefs"})
      for (const loader::Section *s : r_.sections(refs))
        for (std::uint64_t slot = s->addr; slot + p_ <= s->addr + s->size && budget(); slot += p_) {
          const std::string b = r_.bound(slot);
          if (!b.empty()) {
            out_.class_refs[slot] = bound_class(b);
          } else if (auto a = r_.ptr(slot); a && *a != 0) {
            if (const Class *c = class_at(*a)) out_.class_refs[slot] = c->name;
          }
        }
    each_pointer("__objc_protorefs", [&](std::uint64_t slot, std::uint64_t a) {
      if (auto it = protocol_names_.find(a); it != protocol_names_.end()) out_.protocol_refs[slot] = it->second;
    });
    if (const loader::Section *s = r_.section("__objc_imageinfo", kData)) out_.image_info = s->addr;
    std::sort(out_.classes.begin(), out_.classes.end(), [](const Class &a, const Class &b) { return a.address < b.address; });
    return std::move(out_);
  }

 private:
  // Records, and the bytes of the names they copy: many records may name
  // one long string (bug scrub part 3: 1M methods of one 4 KiB name made
  // 5 GiB), so both are budgeted.
  bool budget() { return ++records_ <= kMaxRecords && bytes_ <= kMaxBytes; }
  std::optional<std::string> cstr(std::uint64_t a, std::size_t max) {
    if (bytes_ > kMaxBytes) return std::nullopt;
    std::optional<std::string> s = r_.cstr(a, max);
    if (s) bytes_ += s->size();
    return s;
  }
  std::uint64_t bytes_ = 0;
  static constexpr std::uint64_t kMaxBytes = 128u << 20;

  // Each pointer of every section named `name` (null ones skipped).
  template <class F>
  void each_pointer(const char *name, F &&f) {
    for (const loader::Section *s : r_.sections(name))
      for (std::uint64_t slot = s->addr; slot + p_ <= s->addr + s->size && budget(); slot += p_)
        if (auto a = r_.ptr(slot); a && *a != 0) f(slot, *a);
  }

  const Class *class_at(std::uint64_t a) const {
    auto it = class_index_.find(a);
    return it == class_index_.end() ? nullptr : &out_.classes[it->second];
  }

  std::string str(std::uint64_t field) {
    auto a = r_.ptr(field);
    if (!a || *a == 0) return {};
    return cstr(*a, 4096).value_or("");
  }

  std::optional<MethodList> methods(std::uint64_t list, bool class_methods) {
    if (list == 0) return std::nullopt;
    auto head = r_.u32(list), count = r_.u32(list + 4);
    if (!head || !count) return std::nullopt;
    MethodList m;
    m.address = list;
    m.relative = (*head & kSmallMethodList) != 0;
    m.entsize = *head & kEntsizeMask;
    const std::uint32_t want = m.relative ? 12 : 3 * p_;
    if (m.entsize < want || *count > kMaxListEntries) {
      warn("method list at " + hex(list) + " has entry size " + std::to_string(m.entsize));
      return std::nullopt;
    }
    for (std::uint32_t i = 0; i < *count && budget(); ++i) {
      const std::uint64_t e = list + 8 + std::uint64_t{i} * m.entsize;
      Method x;
      x.class_method = class_methods;
      if (m.relative) {
        // name: to a selector reference (whose pointer is the name); types:
        // to the string; imp: to the code.
        if (auto sel = r_.relative(e)) {
          if (auto n = r_.ptr(*sel); n && *n != 0) x.selector = cstr(*n, 1024).value_or("");
        }
        if (auto t = r_.relative(e + 4)) x.types = cstr(*t, 4096).value_or("");
        if (auto imp = r_.relative(e + 8)) x.imp = *imp;
      } else {
        x.selector = str(e);
        x.types = str(e + p_);
        x.imp = r_.ptr(e + 2 * p_).value_or(0);
      }
      if (x.imp != 0 && r_.image().machine == 12) x.imp &= ~std::uint64_t{1};  // Thumb
      if (!x.selector.empty()) m.methods.push_back(std::move(x));
    }
    return m;
  }

  std::vector<Property> properties(std::uint64_t list) {
    std::vector<Property> out;
    if (list == 0) return out;
    auto entsize = r_.u32(list), count = r_.u32(list + 4);
    if (!entsize || !count || *entsize < 2 * p_ || *count > kMaxListEntries) return out;
    for (std::uint32_t i = 0; i < *count && budget(); ++i) {
      const std::uint64_t e = list + 8 + std::uint64_t{i} * *entsize;
      Property x{str(e), str(e + p_)};
      if (!x.name.empty()) out.push_back(std::move(x));
    }
    return out;
  }

  std::vector<std::string> protocol_names(std::uint64_t list) {
    std::vector<std::string> out;
    if (list == 0) return out;
    auto count = r_.uint(list, p_);
    if (!count || *count > kMaxListEntries) return out;
    for (std::uint64_t i = 0; i < *count && budget(); ++i) {
      const std::uint64_t slot = list + p_ * (1 + i);
      auto a = r_.ptr(slot);
      if (!a) break;
      if (auto it = protocol_names_.find(*a); it != protocol_names_.end()) out.push_back(it->second);
      else if (const std::string b = r_.bound(slot); !b.empty()) out.push_back(b);
      else if (*a != 0)
        if (auto n = r_.ptr(*a + p_); n && *n) out.push_back(cstr(*n, 1024).value_or(""));
    }
    return out;
  }

  // class_ro_t: flags, instanceStart, instanceSize, [reserved], ivarLayout,
  // name, baseMethods, baseProtocols, ivars, weakIvarLayout, baseProperties.
  struct Ro {
    std::uint32_t flags = 0, start = 0, size = 0;
    std::string name;
    std::uint64_t methods = 0, protocols = 0, ivars = 0, properties = 0;
  };
  std::optional<Ro> ro(std::uint64_t a) {
    const std::uint64_t f = p_ == 8 ? 16 : 12;  // the first pointer field
    if (!r_.mapped(a, f + 6 * p_)) return std::nullopt;
    Ro x;
    x.flags = *r_.u32(a);
    x.start = *r_.u32(a + 4);
    x.size = *r_.u32(a + 8);
    x.name = str(a + f + p_);
    x.methods = r_.ptr(a + f + 2 * p_).value_or(0);
    x.protocols = r_.ptr(a + f + 3 * p_).value_or(0);
    x.ivars = r_.ptr(a + f + 4 * p_).value_or(0);
    x.properties = r_.ptr(a + f + 6 * p_).value_or(0);
    return x;
  }

  // The data pointer's low bits are flags (FAST_DATA_MASK; Swift's 1 and 2).
  std::uint64_t data_of(std::uint64_t cls_t, bool &swift) {
    const std::uint64_t d = r_.ptr(cls_t + 4 * p_).value_or(0);
    swift = (d & 3) != 0;
    return d & ~static_cast<std::uint64_t>(p_ == 8 ? 7 : 3);
  }

  void cls(std::uint64_t a) {
    if (class_index_.contains(a) || !r_.mapped(a, 5 * p_)) return;
    Class c;
    c.address = a;
    const std::uint64_t data = data_of(a, c.swift);
    auto x = ro(data);
    if (!x || x->name.empty()) {
      warn("class at " + hex(a) + " has no readable class_ro_t");
      return;
    }
    c.ro = data;
    c.name = x->name;
    c.flags = x->flags;
    c.instance_start = x->start;
    c.instance_size = x->size;
    c.instance_methods = methods(x->methods, false);
    c.ivar_list = x->ivars;
    c.property_list = x->properties;
    c.protocol_list = x->protocols;
    c.properties = properties(x->properties);
    c.protocols = protocol_names(x->protocols);
    ivars(c, x->ivars);
    // The superclass: a local class_t, or a bind to another image's.
    const std::string sup = r_.bound(a + p_);
    if (!sup.empty()) c.superclass = bound_class(sup);
    else if (auto s = r_.ptr(a + p_); s && *s != 0) c.superclass_address = *s;
    // The metaclass (isa): its ro's methods are the class methods.
    if (r_.bound(a).empty())
      if (auto m = r_.ptr(a); m && *m != 0 && r_.mapped(*m, 5 * p_)) {
        bool sw = false;
        const std::uint64_t md = data_of(*m, sw);
        if (auto mx = ro(md)) {
          c.metaclass = *m;
          c.meta_ro = md;
          c.class_methods = methods(mx->methods, true);
        }
      }
    class_index_[a] = out_.classes.size();
    out_.classes.push_back(std::move(c));
  }

  void resolve_supers() {
    for (Class &c : out_.classes)
      if (c.superclass.empty() && c.superclass_address != 0) {
        auto it = class_index_.find(c.superclass_address);
        if (it != class_index_.end()) c.superclass = out_.classes[it->second].name;
        else if (auto x = ro(data_of_copy(c.superclass_address))) c.superclass = x->name;
      }
  }
  std::uint64_t data_of_copy(std::uint64_t a) {
    bool sw = false;
    return data_of(a, sw);
  }

  // ivar_list_t: entsize, count, then ivar_t: offset*, name, type,
  // alignment_raw, size.
  void ivars(Class &c, std::uint64_t list) {
    if (list == 0) return;
    auto entsize = r_.u32(list), count = r_.u32(list + 4);
    if (!entsize || !count || *entsize < 3 * p_ + 8 || *count > kMaxListEntries) return;
    for (std::uint32_t i = 0; i < *count && budget(); ++i) {
      const std::uint64_t e = list + 8 + std::uint64_t{i} * *entsize;
      Ivar v;
      v.offset_address = r_.ptr(e).value_or(0);
      v.name = str(e + p_);
      v.type = str(e + 2 * p_);
      v.alignment = r_.u32(e + 3 * p_).value_or(0);
      v.size = r_.u32(e + 3 * p_ + 4).value_or(0);
      if (v.offset_address != 0) v.offset = r_.u32(v.offset_address).value_or(0);
      if (!v.name.empty()) c.ivars.push_back(std::move(v));
    }
  }

  // category_t: name, cls, instanceMethods, classMethods, protocols,
  // instanceProperties.
  void category(std::uint64_t a) {
    if (!r_.mapped(a, 6 * p_)) return;
    Category k;
    k.address = a;
    k.name = str(a);
    const std::string b = r_.bound(a + p_);
    if (!b.empty()) {
      k.class_name = bound_class(b);
    } else if (auto c = r_.ptr(a + p_); c && *c != 0) {
      k.class_address = *c;
      if (const Class *x = class_at(*c)) k.class_name = x->name;
    }
    k.instance_methods = methods(r_.ptr(a + 2 * p_).value_or(0), false);
    k.class_methods = methods(r_.ptr(a + 3 * p_).value_or(0), true);
    k.protocol_list = r_.ptr(a + 4 * p_).value_or(0);
    k.property_list = r_.ptr(a + 5 * p_).value_or(0);
    k.protocols = protocol_names(k.protocol_list);
    k.properties = properties(k.property_list);
    if (k.name.empty()) return;
    out_.categories.push_back(std::move(k));
  }

  // protocol_t: isa, name, protocols, instanceMethods, classMethods,
  // optionalInstanceMethods, optionalClassMethods, instanceProperties, ...
  void protocol(std::uint64_t a) {
    if (protocol_names_.contains(a) || !r_.mapped(a, 8 * p_)) return;
    Protocol x;
    x.address = a;
    x.name = str(a + p_);
    if (x.name.empty()) return;
    protocol_names_[a] = x.name;
    x.protocol_list = r_.ptr(a + 2 * p_).value_or(0);
    x.instance_methods = methods(r_.ptr(a + 3 * p_).value_or(0), false);
    x.class_methods = methods(r_.ptr(a + 4 * p_).value_or(0), true);
    x.optional_instance_methods = methods(r_.ptr(a + 5 * p_).value_or(0), false);
    x.optional_class_methods = methods(r_.ptr(a + 6 * p_).value_or(0), true);
    x.property_list = r_.ptr(a + 7 * p_).value_or(0);
    x.properties = properties(x.property_list);
    x.protocols = protocol_names(x.protocol_list);
    out_.protocols.push_back(std::move(x));
  }

  void warn(std::string w) {
    if (out_.warnings.size() < 32) out_.warnings.push_back(std::move(w));
  }
  static std::string hex(std::uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
  }

  Reader r_;
  unsigned p_;
  Metadata out_;
  std::size_t records_ = 0;
  std::map<std::uint64_t, std::size_t> class_index_;
  std::map<std::uint64_t, std::string> protocol_names_;
};

}  // namespace

const Class *Metadata::class_at(std::uint64_t address) const {
  auto it = std::lower_bound(classes.begin(), classes.end(), address,
                             [](const Class &c, std::uint64_t a) { return c.address < a; });
  return it != classes.end() && it->address == address ? &*it : nullptr;
}

void scan_swift(const loader::Image &image, Metadata &out);  // swift.cc

Metadata scan(const loader::Image &image) {
  if (image.format != loader::Format::macho) return {};
  Metadata m = Scanner(image).run();
  scan_swift(image, m);
  return m;
}

std::string method_name(const std::string &class_name, const std::string &category, const Method &m) {
  std::string out = m.class_method ? "+[" : "-[";
  out += class_name;
  if (!category.empty()) out += "(" + category + ")";
  out += " " + m.selector + "]";
  return out;
}

std::string count_pass(const std::string &what) { return what.starts_with("swift") ? "swift" : "objc"; }

}  // namespace revkit::objc
