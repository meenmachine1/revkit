// Data analysis as queries over the fact engine: the data Ghidra's
// analyzers define in a program, so the decompiler is told about strings,
// pointers and accessed data as Ghidra's would be.
//
// Inputs: the program's bytes and ProgramInfo (as for discovery), and
// DataProgram, what the loader knows about memory that discovery doesn't
// need (blocks with their permissions, relocated locations, the wide
// character size), set once at import by stage_image.
//
//   analysis.data()   the program's defined data, laid down in the order
//                     Ghidra's analyzers do (below), from every flow's
//                     data references (FlowGraph::data_refs: loads and
//                     stores at constant addresses with their sizes, and
//                     address constants, as Ghidra's constant propagation
//                     finds them while analysis.flow decodes)
//
// Order, each step only over what the steps before left undefined
// (instructions and earlier data are obstacles; `undefinedN` data is
// "undefined stuff" later steps may replace, as Ghidra clears it):
//
//   1. accesses     ConstantPropagationContextEvaluator.createData: an
//                   `undefinedN` of the access size (1..8) where code loads
//                   or stores at a constant address
//   2. references   OperandReferenceAnalyzer, per referenced address in
//                   order of the referring code: an ASCII string (at least
//                   5 characters to a NUL), a UTF-16 string (at least 4,
//                   PE), or a pointer (to mapped memory, not offcut, at a
//                   relocated location when the program is relocatable);
//                   a pointer's own target is processed in turn
//   3. strings      StringsAnalyzer: NUL-terminated ASCII, and UTF-16 or
//                   UTF-32 (the wide character size), of at least 5
//                   characters, scored by Ghidra's string n-gram model
//                   (Ghidra/Features/Base/data/stringngrams/StringModel.sng
//                   in the Ghidra install, read once), padded with zero
//                   bytes to 4-byte alignment
//
// Names and decompiler types are given in revkit::inputs, which knows the
// labels pointers are named after (PTR_s_..., PTR_FUN_...).
//
// Purity: both queries read only the store (bytes, inputs, discovery's
// queries). The n-gram model is a fixed resource of the Ghidra install,
// like the start patterns; without it step 3 finds nothing. An edit that
// changes discovery re-runs the flows it changed and then data.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/analysis/units.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::analysis {

// ---- input ----

struct DataBlock {
  std::string name;
  Range range;
  bool read = false, write = false, exec = false;
  bool initialized = true;
  bool is_volatile = false;  // memory-mapped I/O (encoded only when set)

  void encode(facts::Encoder &e) const;
  static DataBlock decode(facts::Decoder &d);
  friend bool operator==(const DataBlock &, const DataBlock &) = default;
};

// What data analysis takes from the loader besides ProgramInfo.
struct DataProgramInfo {
  bool present = false;  // staged (an older project may lack it: no data)
  bool pe = false;
  std::uint8_t wide_char = 4;  // wchar_t's size: 2 on Windows, else 4
  std::vector<DataBlock> blocks;  // sorted by start
  // Whether pointers in memory must be at relocated locations (Ghidra's
  // RelocationTable.isRelocatable: a PIE or shared object, a PE with base
  // relocations), and those locations, sorted.
  bool relocatable = false;
  std::vector<std::uint64_t> relocations;
  // Defined by the loader before analysis runs (PE headers, exception
  // table and import slots, relocated pointer slots): obstacles, never
  // replaced. Sorted, disjoint.
  std::vector<Range> defined;
  // Pointers the loader lays down whose targets are in memory (relocated
  // slots): (slot, target), sorted. Their targets are data references.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> pointers;
  // Pointers the loader marks up besides relocated slots (each entry of an
  // ELF .got section, ElfDefaultGotPltMarkup), as (address, value): pointer
  // data in the result, whatever they hold. Sorted.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> loader_pointers;
  // ELF object symbols: undefinedN data the loader lays down (its size, or
  // 1 above 8 bytes), which analysis may replace. (address, size), sorted.
  std::vector<std::pair<std::uint64_t, std::uint32_t>> symbols;

  const DataBlock *block(std::uint64_t a) const;
  bool has_relocation(std::uint64_t a) const;
  void encode(facts::Encoder &e) const;
  static DataProgramInfo decode(facts::Decoder &d);
  friend bool operator==(const DataProgramInfo &, const DataProgramInfo &) = default;
};

// Input: what the loader says (describe_data()), set by stage_image.
struct LoadedDataProgram {
  static constexpr std::string_view name = "analysis.data_program.loaded";
  using Key = ProgramKey;
  using Value = DataProgramInfo;
  static std::string describe(const Key &k) { return k.id; }
};

// LoadedDataProgram with the memory map's edits: its blocks are the
// effective map's (memory.h); unchanged without edits. Named as the input
// it replaced.
struct DataProgram {
  static constexpr std::string_view name = "analysis.data_program";
  static constexpr std::uint32_t version = 1;
  using Key = ProgramKey;
  using Value = DataProgramInfo;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
};

// DataProgramInfo for a loaded image; `bytes` as describe()'s.
DataProgramInfo describe_data(const loader::Image &image, const ByteSource &bytes = {});

// ---- data ----

enum class DataKind : std::uint8_t {
  undefined,  // undefinedN: `length` bytes some code accesses
  string,     // NUL-terminated char string (Ghidra's "string"/TerminatedCString)
  unicode,    // UTF-16 (Ghidra's "unicode")
  unicode32,  // UTF-32 (Ghidra's "unicode32")
  pointer,    // a pointer-sized address
  label,      // no data: undefined bytes something refers to, which get a
              // dynamic label (DAT_) as a reference target; length 1
  defined,    // a user's data definition other than a string or a pointer
              // (units.h): integers, floats, structs, arrays; `type` says what
};

enum DataOrigin : std::uint8_t {
  kDataAccess = 1,     // step 1
  kDataReference = 2,  // step 2
  kDataSearch = 3,     // step 3
  kDataLabel = 4,      // what references leave undefined
  kDataLoader = 5,     // the loader's markup (DataProgramInfo::loader_pointers)
  kDataUser = 6,       // a user's data definition (CODE_UNIT "data", units.h)
};

struct DataItem {
  std::uint64_t address = 0;
  std::uint32_t length = 0;  // bytes, terminator and padding included
  DataKind kind = DataKind::undefined;
  std::uint8_t origin = 0;   // DataOrigin
  std::string text;          // strings: the characters before the terminator, as UTF-8
  std::uint64_t value = 0;   // pointers: the address held
  // Code writes inside it (at a constant address): in read-only memory
  // Ghidra then doesn't take it for a constant
  // (MappedEntry.getMutabilityOfAddress).
  bool written = false;
  // It lies in a literal pool: words the code loads from constant addresses
  // inside code (FlowGraph::literals), constants by construction.
  bool literal = false;
  // kDataUser only: the definition (units.h: its type, layout and fields)
  // and the pointers in it with the addresses they hold, (slot, target),
  // where the target is mapped: references from data.
  DataSpec spec;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> refs;

  std::uint64_t last() const { return address + length - 1; }
  void encode(facts::Encoder &e) const;
  static DataItem decode(facts::Decoder &d);
  friend bool operator==(const DataItem &, const DataItem &) = default;
};

struct DataList {
  std::vector<DataItem> items;  // sorted by address, disjoint

  const DataItem *at(std::uint64_t a) const;          // starting at a
  const DataItem *containing(std::uint64_t a) const;  // a in [address, last]
  void encode(facts::Encoder &e) const;
  static DataList decode(facts::Decoder &d);
  friend bool operator==(const DataList &, const DataList &) = default;
};

struct Data {
  static constexpr std::string_view name = "analysis.data";
  static constexpr std::uint32_t version = 8;  // 2: labels; 3: memory operands; 4: GOT; 5: written;
                                               // 6: patches through patch.page; 7: literal, written anywhere inside;
                                               // 8: the listing's edits (units.h)
  using Key = ProgramKey;
  using Value = DataList;
  static Value compute(facts::QueryContext &ctx, const Key &key);
  static std::string describe(const Key &k) { return k.id; }
  static std::size_t weight(const Value &v);
};

void register_data_queries(facts::Engine &engine);  // called by register_queries

// ---- strings (exposed for tests) ----

// Ghidra's string n-gram model (NGramUtils): whether `text` (the found
// characters) scores above the threshold for its length. False when the
// model can't be read.
bool ngram_valid_string(std::string_view text);
// Whether the model was found in the Ghidra install.
bool ngram_model_available();

// The label Ghidra makes from a string's value (StringDataInstance
// .makeStringLabel): `prefix` and up to 32 displayable characters, runs of
// others as one underscore.
std::string string_label(std::string_view prefix, std::string_view utf8);

}  // namespace revkit::analysis
