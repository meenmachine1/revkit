// The type model: a closed set of C-level type kinds whose references are
// TypeIds into a TypeStore (or, while building, into a TypeGraph).
#pragma once

#include <compare>
#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

namespace revkit::types {

// Index of a type. Store ids are dense from 0; graph-local ids (handed out
// by TypeGraph while a batch of possibly-cyclic types is being built) carry
// a tag bit so the two can be mixed in one Type and told apart at intern time.
class TypeId {
 public:
  static constexpr std::uint32_t kInvalid = 0xffffffffu;
  static constexpr std::uint32_t kLocalBit = 0x80000000u;

  constexpr TypeId() = default;
  static constexpr TypeId store(std::uint32_t index) { return TypeId(index); }
  static constexpr TypeId local(std::uint32_t index) { return TypeId(index | kLocalBit); }

  constexpr bool valid() const { return raw_ != kInvalid; }
  constexpr bool is_local() const { return valid() && (raw_ & kLocalBit) != 0; }
  constexpr std::uint32_t index() const { return raw_ & ~kLocalBit; }
  constexpr std::uint32_t raw() const { return raw_; }

  friend constexpr auto operator<=>(TypeId, TypeId) = default;

 private:
  constexpr explicit TypeId(std::uint32_t raw) : raw_(raw) {}
  std::uint32_t raw_ = kInvalid;
};

enum class Kind : std::uint8_t {
  Void, Bool, Int, Float, Pointer, Array, Aggregate, Enum, Typedef, Qualified, Function, Undefined,
};

struct VoidType {
  friend bool operator==(const VoidType &, const VoidType &) = default;
};

struct BoolType {
  std::uint32_t size = 1;
  friend bool operator==(const BoolType &, const BoolType &) = default;
};

// The C spelling of an integer type. Two integers of the same size and
// signedness but different rank (long vs long long on LP64) are distinct C
// types, so the rank is part of the type's identity. Fixed is for types with
// no C spelling (analysis results, other languages) and prints as intN_t.
enum class IntRank : std::uint8_t {
  Fixed, PlainChar, Char, Short, Int, Long, LongLong, Int128, WChar, Char8, Char16, Char32,
};

struct IntType {
  std::uint32_t size = 4;
  bool is_signed = true;
  IntRank rank = IntRank::Fixed;
  friend bool operator==(const IntType &, const IntType &) = default;
};

enum class FloatKind : std::uint8_t { Half, Float, Double, LongDouble, Float128 };

struct FloatType {
  std::uint32_t size = 8;  // storage size, e.g. 16 for x86-64 long double
  FloatKind kind = FloatKind::Double;
  bool complex = false;
  friend bool operator==(const FloatType &, const FloatType &) = default;
};

enum class PointerKind : std::uint8_t { Pointer, LValueRef, RValueRef };

struct PointerType {
  TypeId target;
  std::uint32_t size = 8;
  PointerKind kind = PointerKind::Pointer;
  friend bool operator==(const PointerType &, const PointerType &) = default;
};

struct ArrayType {
  TypeId element;
  std::uint64_t count = 0;  // 0: unknown bound or flexible array member
  friend bool operator==(const ArrayType &, const ArrayType &) = default;
};

struct Field {
  std::string name;  // empty for anonymous members
  TypeId type;
  std::uint64_t bit_offset = 0;  // from the start of the aggregate
  std::uint32_t bit_size = 0;    // non-zero only for bitfields
  friend bool operator==(const Field &, const Field &) = default;
};

enum class AggregateKind : std::uint8_t { Struct, Class, Union };

struct AggregateType {
  AggregateKind kind = AggregateKind::Struct;
  std::string name;  // empty if anonymous; may be qualified (ns::name)
  std::uint64_t size = 0;
  std::uint32_t alignment = 0;  // explicit alignment, 0 = natural
  bool packed = false;
  bool complete = true;  // false for a forward declaration
  std::vector<Field> fields;
  friend bool operator==(const AggregateType &, const AggregateType &) = default;
};

struct Enumerator {
  std::string name;
  std::int64_t value = 0;
  friend bool operator==(const Enumerator &, const Enumerator &) = default;
};

struct EnumType {
  std::string name;
  std::uint32_t size = 4;  // underlying size
  bool is_signed = false;
  bool complete = true;
  std::vector<Enumerator> values;
  friend bool operator==(const EnumType &, const EnumType &) = default;
};

struct TypedefType {
  std::string name;
  TypeId target;
  friend bool operator==(const TypedefType &, const TypedefType &) = default;
};

enum Qualifier : std::uint8_t { kConst = 1, kVolatile = 2, kRestrict = 4, kAtomic = 8 };

struct QualifiedType {
  TypeId target;
  std::uint8_t quals = 0;  // Qualifier bits
  friend bool operator==(const QualifiedType &, const QualifiedType &) = default;
};

enum class CallConv : std::uint8_t {
  Default, Cdecl, Stdcall, Fastcall, Thiscall, Vectorcall, Pascal, Ms64, SysV, Regcall, Other,
};

struct Param {
  std::string name;  // empty if unnamed
  TypeId type;
  friend bool operator==(const Param &, const Param &) = default;
};

struct FunctionType {
  TypeId ret;  // a Void type for void functions
  std::vector<Param> params;
  bool varargs = false;
  CallConv cc = CallConv::Default;
  friend bool operator==(const FunctionType &, const FunctionType &) = default;
};

struct UndefinedType {
  std::uint32_t size = 1;
  friend bool operator==(const UndefinedType &, const UndefinedType &) = default;
};

// Alternatives are in Kind order.
using TypeData = std::variant<VoidType, BoolType, IntType, FloatType, PointerType, ArrayType,
                              AggregateType, EnumType, TypedefType, QualifiedType, FunctionType,
                              UndefinedType>;

struct Type {
  TypeData data;

  Type() = default;
  template <class T>
  Type(T alt) : data(std::move(alt)) {}  // NOLINT: implicit by design

  Kind kind() const { return static_cast<Kind>(data.index()); }
  template <class T> const T *as() const { return std::get_if<T>(&data); }
  template <class T> T *as() { return std::get_if<T>(&data); }
  friend bool operator==(const Type &, const Type &) = default;
};

// How a reference edge contributes to a type's layout: Contains edges are
// by-value (fields, array elements, typedef and qualifier targets) and must
// not form cycles; Pointer and Signature edges may.
enum class EdgeKind : std::uint8_t { Contains, Pointer, Signature };

// Calls f(TypeId&, EdgeKind) for every reference in t, in a fixed order.
template <class T, class F>
void for_each_ref(T &t, F &&f) {
  std::visit(
      [&](auto &d) {
        using D = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<D, PointerType>) f(d.target, EdgeKind::Pointer);
        else if constexpr (std::is_same_v<D, ArrayType>) f(d.element, EdgeKind::Contains);
        else if constexpr (std::is_same_v<D, AggregateType>) {
          for (auto &fld : d.fields) f(fld.type, EdgeKind::Contains);
        } else if constexpr (std::is_same_v<D, TypedefType>) f(d.target, EdgeKind::Contains);
        else if constexpr (std::is_same_v<D, QualifiedType>) f(d.target, EdgeKind::Contains);
        else if constexpr (std::is_same_v<D, FunctionType>) {
          f(d.ret, EdgeKind::Signature);
          for (auto &p : d.params) f(p.type, EdgeKind::Signature);
        }
      },
      t.data);
}

}  // namespace revkit::types

template <>
struct std::hash<revkit::types::TypeId> {
  std::size_t operator()(revkit::types::TypeId id) const noexcept { return id.raw(); }
};
