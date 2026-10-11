#include "revkit/types/describe.h"

#include "revkit/types/print.h"
#include "revkit/types/transform.h"

#include <cstdio>
#include <map>
#include <vector>

namespace revkit::types {

std::string json_quote(std::string_view s) {
  std::string out = "\"";
  char buf[8];
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20 || c >= 0x7f) {
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out += char(c);
        }
    }
  }
  return out + "\"";
}

std::string named_key(const TypeStore &store, TypeId id) {
  const Type &t = store.get(id);
  if (const auto *a = t.as<AggregateType>()) {
    if (a->name.empty()) return {};
    const char *kw = a->kind == AggregateKind::Union ? "union " : a->kind == AggregateKind::Class ? "class " : "struct ";
    return kw + a->name;
  }
  if (const auto *e = t.as<EnumType>()) return e->name.empty() ? std::string() : "enum " + e->name;
  if (const auto *d = t.as<TypedefType>()) return "typedef " + d->name;
  return {};
}

std::string layout_json(TypeStore &store, TypeId id) {
  WithoutTypedefsOptions o;
  o.name_anonymous_tags = true;
  const TypeId flat = without_typedefs(store, id, o);
  const Type t = store.get(id);
  std::string out = "{\"key\":" + json_quote(named_key(store, id));
  const TypeId shape = store.strip_typedefs(id, true);
  const Type &st = store.get(shape);
  const char *kind = "other";
  if (const auto *a = st.as<AggregateType>())
    kind = a->kind == AggregateKind::Union ? "union" : a->kind == AggregateKind::Class ? "class" : "struct";
  else if (st.as<EnumType>()) kind = "enum";
  out += ",\"kind\":\"" + std::string(kind) + "\"";
  out += ",\"size\":" + std::to_string(store.size_of(id));
  out += ",\"hash\":\"" + store.hash(id).hex() + "\"";
  out += ",\"flat_hash\":\"" + store.hash(flat).hex() + "\"";
  if (const auto *a = st.as<AggregateType>()) {
    out += ",\"tag\":" + json_quote(a->name);
    out += ",\"complete\":" + std::string(a->complete ? "true" : "false");
    out += ",\"packed\":" + std::string(a->packed ? "true" : "false");
    out += ",\"alignment\":" + std::to_string(a->alignment);
    out += ",\"fields\":[";
    for (std::size_t i = 0; i < a->fields.size(); ++i) {
      const Field &f = a->fields[i];
      if (i) out += ",";
      out += "{\"name\":" + json_quote(f.name) + ",\"bit_offset\":" + std::to_string(f.bit_offset) +
             ",\"bit_size\":" + std::to_string(f.bit_size) + ",\"type\":" + json_quote(type_name(store, f.type)) + "}";
    }
    out += "]";
  } else if (const auto *e = st.as<EnumType>()) {
    out += ",\"complete\":" + std::string(e->complete ? "true" : "false");
    out += ",\"signed\":" + std::string(e->is_signed ? "true" : "false");
    out += ",\"values\":[";
    for (std::size_t i = 0; i < e->values.size(); ++i) {
      if (i) out += ",";
      out += "[" + json_quote(e->values[i].name) + "," + std::to_string(e->values[i].value) + "]";
    }
    out += "]";
  } else {
    out += ",\"type\":" + json_quote(type_name(store, shape));
  }
  (void)t;
  return out + "}";
}

}  // namespace revkit::types

namespace revkit::types {

std::string deep_dump(const TypeStore &store, TypeId root) {
  std::map<TypeId, std::size_t> seen;
  std::vector<TypeId> order{root};
  seen[root] = 0;
  std::string out;
  for (std::size_t i = 0; i < order.size() && i < 20000; ++i) {
    Type t = store.get(order[i]);
    std::vector<std::size_t> refs;
    for_each_ref(t, [&](TypeId &r, EdgeKind) {
      auto [it, fresh] = seen.try_emplace(r, order.size());
      if (fresh) order.push_back(r);
      refs.push_back(it->second);
      r = TypeId();
    });
    out += "#" + std::to_string(i) + " ";
    std::visit(
        [&](const auto &d) {
          using D = std::decay_t<decltype(d)>;
          if constexpr (std::is_same_v<D, VoidType>) out += "void";
          else if constexpr (std::is_same_v<D, BoolType>) out += "bool " + std::to_string(d.size);
          else if constexpr (std::is_same_v<D, IntType>)
            out += "int " + std::to_string(d.size) + (d.is_signed ? " s" : " u") + " rank" + std::to_string(int(d.rank));
          else if constexpr (std::is_same_v<D, FloatType>)
            out += "float " + std::to_string(d.size) + " kind" + std::to_string(int(d.kind)) + (d.complex ? " complex" : "");
          else if constexpr (std::is_same_v<D, PointerType>)
            out += "ptr " + std::to_string(d.size) + " k" + std::to_string(int(d.kind));
          else if constexpr (std::is_same_v<D, ArrayType>) out += "array " + std::to_string(d.count);
          else if constexpr (std::is_same_v<D, AggregateType>) {
            out += "agg k" + std::to_string(int(d.kind)) + " '" + d.name + "' size " + std::to_string(d.size) +
                   " align " + std::to_string(d.alignment) + (d.packed ? " packed" : "") +
                   (d.complete ? "" : " incomplete");
            for (const Field &f : d.fields)
              out += " | " + f.name + "@" + std::to_string(f.bit_offset) + ":" + std::to_string(f.bit_size);
          } else if constexpr (std::is_same_v<D, EnumType>) {
            out += "enum '" + d.name + "' " + std::to_string(d.size) + (d.is_signed ? " s" : " u") +
                   (d.complete ? "" : " incomplete");
            for (const Enumerator &e : d.values) out += " " + e.name + "=" + std::to_string(e.value);
          } else if constexpr (std::is_same_v<D, TypedefType>) out += "typedef '" + d.name + "'";
          else if constexpr (std::is_same_v<D, QualifiedType>) out += "qual " + std::to_string(d.quals);
          else if constexpr (std::is_same_v<D, FunctionType>) {
            out += "func cc" + std::to_string(int(d.cc)) + (d.varargs ? " varargs" : "");
            for (const Param &p : d.params) out += " (" + p.name + ")";
          } else if constexpr (std::is_same_v<D, UndefinedType>) out += "undefined " + std::to_string(d.size);
        },
        t.data);
    out += " ->";
    for (std::size_t r : refs) out += " #" + std::to_string(r);
    out += "\n";
  }
  return out;
}

}  // namespace revkit::types
