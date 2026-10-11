// CodeView type records (TPI/IPI streams) and their import into a
// TypeGraph (internal).
#pragma once

#include "cursor.h"
#include "revkit/debuginfo/dwarf.h"
#include "revkit/types/store.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace revkit::debuginfo::pdb {

// A numeric leaf (cvinfo.h LF_CHAR ... LF_UQUADWORD, or a literal below
// 0x8000). Non-integral leaves (reals, strings) are skipped and read as 0.
struct Numeric {
  std::uint64_t bits = 0;  // two's complement for signed values
  bool is_signed = false;
  bool integral = true;
};
Numeric read_numeric(Cursor &c);

// A NUL-terminated name. Records written by old toolchains may end without
// the NUL; then the name runs to the end of the record.
std::string_view read_name(Cursor &c);

struct TypeRecord {
  std::uint16_t kind = 0;  // 0 if the index is not in the stream
  std::span<const std::uint8_t> data;  // payload after the kind
};

// The records of a TPI or IPI stream, indexed by type index.
class TypeStream {
 public:
  TypeStream() = default;
  // Throws FormatError on a bad header. Records after a damaged one are
  // dropped and described in `warning`.
  static TypeStream parse(std::vector<std::uint8_t> bytes, std::string *warning);

  std::uint32_t begin() const { return begin_; }
  std::uint32_t end() const { return begin_ + std::uint32_t(entries_.size()); }
  bool contains(std::uint32_t ti) const { return ti >= begin_ && ti - begin_ < entries_.size(); }
  TypeRecord record(std::uint32_t ti) const;
  std::size_t byte_size() const { return bytes_.size(); }

 private:
  struct Entry {
    std::uint32_t offset;  // of the payload in bytes_
    std::uint32_t size;
    std::uint16_t kind;
  };
  std::vector<std::uint8_t> bytes_;
  std::uint32_t begin_ = 0x1000;
  std::vector<Entry> entries_;
};

// Imports TPI records into a TypeGraph. Type indices map to graph-local
// nodes (or store ids for simple types); finish() interns the batch.
class TypeImporter {
 public:
  TypeImporter(const TypeStream &tpi, types::TypeStore &store, unsigned pointer_size,
               bool resolve_forward_refs, std::vector<Diagnostic> &diagnostics);

  // The type for a type index. Never fails: unknown or malformed records
  // become "undefined" types and a diagnostic.
  types::TypeId type(std::uint32_t ti);
  // The function type of an LF_PROCEDURE or LF_MFUNCTION (whose implicit
  // `this` becomes the first parameter, as in DWARF), or nullopt.
  std::optional<types::FunctionType> function(std::uint32_t ti);
  types::TypeId add(types::Type t) { return g_.add(std::move(t)); }
  // The tag name of a struct, class, union or enum record (empty for an
  // anonymous one or another kind of type).
  std::string_view tag(std::uint32_t ti);

  // Every type record in the stream (field and argument lists excepted).
  void import_all();

  // Builds pending nodes, infers packing, breaks invalid cycles and interns.
  // Returns the store id for each graph-local index.
  std::vector<types::TypeId> finish();

 private:
  struct Aggregate {
    std::uint16_t kind = 0;
    std::uint16_t count = 0;
    std::uint16_t props = 0;
    std::uint32_t fields = 0;
    std::uint32_t underlying = 0;  // LF_ENUM
    std::uint64_t size = 0;
    std::string_view name;
    std::string_view unique_name;
  };

  types::TypeId simple(std::uint32_t ti);
  std::uint32_t resolve(std::uint32_t ti);
  void index_definitions();
  std::optional<Aggregate> aggregate_header(const TypeRecord &r) const;
  std::string definition_key(const Aggregate &a) const;
  std::uint64_t byte_size(std::uint32_t ti, int depth = 0);
  bool is_signed_integer(std::uint32_t ti, int depth = 0);
  types::Type build(std::uint32_t ti);
  types::Type build_pointer(Cursor &c);
  types::Type build_aggregate(std::uint32_t ti, const Aggregate &a);
  types::Type build_enum(const Aggregate &a);
  void drain();
  void warn(std::uint32_t ti, const std::string &msg);
  // Charges one parameter, field or enumerator to the budget; false once it
  // is spent (each record re-expands the lists it names, so lists shared by
  // many records multiplied: 1e9 parameters from a 1 MB stream).
  bool charge(std::uint32_t ti);

  const TypeStream &tpi_;
  types::TypeStore &store_;
  unsigned pointer_size_;
  bool resolve_forward_refs_;
  std::vector<Diagnostic> &diags_;
  types::TypeGraph g_;
  std::unordered_map<std::uint32_t, types::TypeId> memo_;
  std::vector<std::uint32_t> work_;
  std::unordered_map<std::string, std::uint32_t> definitions_;  // key -> ti, 0 if ambiguous
  bool indexed_ = false;
  std::vector<std::pair<types::TypeId, std::uint32_t>> aggregates_;
  std::size_t warnings_ = 0;
  std::uint64_t budget_ = 0;
};

}  // namespace revkit::debuginfo::pdb
