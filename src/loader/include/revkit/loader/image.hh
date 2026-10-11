// In-memory model of a loaded executable: headers, symbols, and a memory
// image built from the loadable parts of the file.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::loader {

// Every malformed-input condition is reported with this exception.
class LoadError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// raw: a flat image (firmware, a ROM dump) loaded at a chosen base, with
// optional extra regions; see RawOptions.
enum class Format : std::uint8_t { elf, pe, raw };
enum class Endian : std::uint8_t { little, big };

struct Perms {
  bool read = false;
  bool write = false;
  bool exec = false;

  std::string str() const;  // "r-x" style
  friend bool operator==(const Perms &, const Perms &) = default;
};

using Bytes = std::vector<std::byte>;

// A contiguous mapped address range. The first `file_size` bytes come from
// the file at `file_offset`; the rest (e.g. .bss) read as zero.
struct Region {
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  std::uint64_t file_offset = 0;
  std::uint64_t file_size = 0;
  Perms perms;

  bool contains(std::uint64_t addr) const { return addr >= start && addr - start < size; }
  std::uint64_t last() const { return start + (size - 1); }
};

// Sparse address space backed by the file bytes. Regions never overlap and
// never wrap past the top of the 64-bit space.
class Memory {
 public:
  Memory() = default;
  explicit Memory(std::shared_ptr<const Bytes> file) : file_(std::move(file)) {}

  // Throws LoadError if the region is empty, wraps, overlaps an existing
  // region, or its file-backed part lies outside the file.
  void add(const Region &region);
  // The same, with the region's bytes from `bytes` instead of the file
  // (file_offset and file_size then index `bytes`): memory added from
  // another file (docs/memory-map.md).
  void add(const Region &region, std::shared_ptr<const Bytes> bytes);
  // Sets the permissions of the region starting at `start`, if any.
  void set_perms(std::uint64_t start, Perms perms);
  // Sets the permissions of the mapped bytes in [start, start + size),
  // splitting the regions that run past either end where their
  // permissions differ (an ELF section's own inside its segment). The
  // pieces keep their bytes. size 0 does nothing.
  void set_perms(std::uint64_t start, std::uint64_t size, Perms perms);

  const Region *find(std::uint64_t addr) const;
  bool is_mapped(std::uint64_t addr) const { return find(addr) != nullptr; }

  // Copies bytes into `out`. Unmapped bytes are zero-filled; returns the
  // number of bytes that were mapped.
  std::size_t read(std::uint64_t addr, std::span<std::byte> out) const;

  const std::vector<Region> &regions() const { return regions_; }

 private:
  std::shared_ptr<const Bytes> file_;
  std::vector<Region> regions_;  // sorted by start
  // Each region's bytes when they aren't the file's (by index in regions_);
  // empty while no region has its own.
  std::vector<std::shared_ptr<const Bytes>> own_;
};

// A named memory block, as a user would see it (sections, or segments when
// there are no sections). Blocks are what reference-format `memory` lists.
struct Block {
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  Perms perms;
  bool initialized = true;
  bool is_volatile = false;  // memory-mapped I/O (raw images' declared regions)
};

// ELF program header. Unused for PE.
struct Segment {
  std::uint32_t type = 0;
  std::uint32_t flags = 0;
  std::uint64_t offset = 0;
  std::uint64_t vaddr = 0;
  std::uint64_t paddr = 0;
  std::uint64_t file_size = 0;
  std::uint64_t mem_size = 0;
  std::uint64_t align = 0;
};

// ELF section header or PE section header, normalised. For PE, `type` is 0,
// `flags` holds the characteristics and `addr` is a virtual address.
struct Section {
  std::string name;
  std::uint32_t type = 0;
  std::uint64_t flags = 0;
  std::uint64_t addr = 0;
  std::uint64_t offset = 0;
  std::uint64_t size = 0;       // size in memory
  std::uint64_t file_size = 0;  // bytes present in the file
  std::uint32_t link = 0;
  std::uint32_t info = 0;
  std::uint64_t addralign = 0;
  std::uint64_t entsize = 0;
  bool alloc = false;  // occupies memory at run time
  Perms perms;
  // PE VirtualSize: the section's real length, without file-alignment
  // padding (`size` is the larger of this and the raw size). 0 for ELF.
  std::uint64_t virtual_size = 0;
};

enum class SymbolType : std::uint8_t { notype, object, func, section, file, common, tls, ifunc, other };
enum class SymbolBind : std::uint8_t { local, global, weak, other };
enum class SymbolSource : std::uint8_t { symtab, dynsym, pe_export };

struct Symbol {
  std::string name;
  std::uint64_t value = 0;
  std::uint64_t size = 0;
  SymbolType type = SymbolType::notype;
  SymbolBind bind = SymbolBind::local;
  SymbolSource source = SymbolSource::symtab;
  bool defined = false;  // false for undefined (imported) ELF symbols
  std::uint32_t section_index = 0;
};

struct Import {
  std::string library;
  std::string name;  // empty when imported by ordinal only
  std::optional<std::uint16_t> ordinal;
  std::uint64_t iat_address = 0;
};

struct Export {
  std::string name;  // empty when exported by ordinal only
  std::uint32_t ordinal = 0;
  std::uint64_t address = 0;
  std::string forwarder;  // non-empty for forwarded exports ("DLL.Func")
};

// A function extent known from the file's own metadata: PE .pdata, or ELF
// .eh_frame FDEs (which survive stripping).
struct FunctionRange {
  std::uint64_t start = 0;
  std::uint64_t end = 0;  // exclusive
};

// A PE debug directory's CodeView record: which PDB the image was linked
// with. An RSDS record identifies the PDB by GUID and age; an older NB10
// record by a 32-bit signature (time stamp) and age.
struct CodeViewRecord {
  std::string pdb_path;
  bool rsds = false;
  std::array<std::uint8_t, 16> guid{};  // RSDS: GUID in file byte order
  std::uint32_t signature = 0;          // NB10 only
  std::uint32_t age = 0;
};

// What an ELF relocation does, for the types analysis cares about. Types
// this doesn't name are `other`; `type` always holds the raw r_type.
enum class RelocationKind : std::uint8_t {
  other,
  relative,   // R_*_RELATIVE: load base + addend
  irelative,  // R_*_IRELATIVE: the result of calling the resolver at base + addend
  jump_slot,  // R_*_JUMP_SLOT: a PLT's GOT slot for `symbol`
  glob_dat,   // R_*_GLOB_DAT: a GOT slot holding the address of `symbol`
  absolute,   // R_X86_64_64, R_AARCH64_ABS64, R_RISCV_64, ...: symbol + addend
};

// One ELF relocation (RELA, REL or RELR): dynamic ones, and in object files
// static ones. Nothing is applied to `Image::memory`; consumers decide.
struct Relocation {
  std::uint64_t address = 0;  // the location patched, at the image's load address
  std::uint32_t type = 0;     // r_type as in the file
  RelocationKind kind = RelocationKind::other;
  std::string symbol;         // empty when the relocation has no symbol
  // Explicit for RELA; for REL and RELR, the word stored at `address`.
  std::int64_t addend = 0;
  // relative/irelative: the address the dynamic linker computes, at this
  // image's load address (it moves with the image base like everything else).
  std::optional<std::uint64_t> target;
};

// A procedure linkage table section (.plt, .plt.sec, .plt.got, .iplt): an
// optional header (the lazy-binding resolver stub), then fixed-size stubs.
// `entry_size` is 0 when the machine's layout isn't known.
struct PltSection {
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  std::uint64_t header_size = 0;
  std::uint64_t entry_size = 0;
};

// Code the dynamic linker runs around main: DT_INIT/DT_FINI and the
// DT_PREINIT_ARRAY/DT_INIT_ARRAY/DT_FINI_ARRAY entries (or the
// .preinit_array/.init_array/.fini_array sections when there is no dynamic
// table). Array entries are the stored pointers with relative relocations
// applied; 0 and -1 entries are dropped.
struct InitFini {
  std::optional<std::uint64_t> init;
  std::optional<std::uint64_t> fini;
  std::vector<std::uint64_t> preinit_array;
  std::vector<std::uint64_t> init_array;
  std::vector<std::uint64_t> fini_array;
};

// Address keys. revkit stores every address as one 64-bit key. In the
// language's default space (where code is) a key is the byte offset
// itself. A block in another memory space (AVR's data space "mem", the
// 8051's INTMEM, SFR and EXTMEM, PIC's DATA) is keyed by its space's base
// plus the byte offset; bases are multiples of 2^kSpaceKeyShift, so on
// processors whose spaces are at most 40 bits wide no key of one space is
// another's (images of 64-bit languages keep a single space). A
// word-addressed space (AVR's and PIC's code: 2-byte words) is keyed by
// byte offset too, as SLEIGH's addresses and Ghidra's Address.getOffset()
// are; only display divides by the word size (code:0x1234 is byte 0x2468).
inline constexpr unsigned kSpaceKeyShift = 40;

struct AddressSpace {
  std::string name;        // the SLEIGH space name: "mem", "INTMEM"
  std::uint64_t base = 0;  // the key of offset 0
  // A byte-mapped view of the default space (AVR's "codebyte" is the
  // code space's bytes, byte-addressed): keys are the default space's,
  // and `base` is 0.
  bool alias_of_default = false;
  // Bytes per addressable unit (AVR's code space: 2) and the hex digits
  // Ghidra pads offsets to in default names (the space's size, at most 8).
  std::uint32_t wordsize = 1;
  std::uint32_t digits = 8;

  friend bool operator==(const AddressSpace &, const AddressSpace &) = default;
};

struct Image {
  Format format = Format::elf;
  Endian endian = Endian::little;
  unsigned bits = 64;              // pointer size in bits
  std::uint32_t machine = 0;       // e_machine or IMAGE_FILE_HEADER.Machine
  std::uint32_t flags = 0;         // e_flags (ELF) or file characteristics (PE)
  std::uint16_t elf_type = 0;      // e_type; 0 for PE
  std::optional<std::uint64_t> entry;
  std::uint64_t image_base = 0;    // lowest PT_LOAD vaddr (ELF) or ImageBase (PE)
  std::uint64_t file_base = 0;     // the same as the file has it, before LoadOptions rebased it

  std::vector<Segment> segments;
  std::vector<Section> sections;
  std::vector<Symbol> symbols;
  std::vector<Import> imports;
  std::vector<Export> exports;
  std::vector<FunctionRange> function_ranges;  // sorted by start
  std::string pdb_path;  // same as codeview->pdb_path
  std::optional<CodeViewRecord> codeview;

  // Dynamic linking. `needed`: the libraries the file asks the loader for,
  // in its order (ELF DT_NEEDED; PE the import directory's DLLs, each once).
  // `soname`: its own name as a library (ELF DT_SONAME; PE the export
  // directory's DLL name). `runpath`: where it says to look (ELF DT_RUNPATH,
  // else DT_RPATH, split on ':'; "$ORIGIN" left as it is). `build_id`: the
  // GNU build ID note (NT_GNU_BUILD_ID) in lower-case hex; empty for PE.
  std::vector<std::string> needed;
  std::string soname;
  std::vector<std::string> runpath;
  std::string build_id;

  // ELF only.
  std::vector<Relocation> relocations;  // sorted by address (stable)
  std::vector<PltSection> plt_sections;  // sorted by start
  InitFini init_fini;

  std::vector<Block> blocks;  // sorted by start (key)
  Memory memory;
  std::vector<std::string> warnings;  // recoverable oddities, in discovery order

  std::shared_ptr<const Bytes> file;

  // The memory spaces other than the default one that blocks live in, in
  // the order they were added (see AddressSpace and the keys above).
  std::vector<AddressSpace> spaces;
  // The default space, when the language's memory was applied (its name
  // is empty otherwise): name, word size and digits; base 0.
  AddressSpace default_space;
};

// The space named `name`, or null. "" (the default space) is null too.
const AddressSpace *find_space(const Image &image, std::string_view name);
// Adds a space for blocks to live in (an alias of the default space when
// `alias_of_default`) and returns it; an existing one is returned as is.
// `base` (a multiple of 2^kSpaceKeyShift) is the language's for the space
// (LanguageMemory); without one the next free base is taken. Throws
// LoadError for an image of a 64-bit language, whose addresses leave no
// room for space bases.
const AddressSpace &add_space(Image &image, std::string_view name, bool alias_of_default = false,
                              std::optional<std::uint64_t> base = std::nullopt);

// What a language says about memory beyond the default space, as the
// loaders lay it out: its other memory spaces with the base each is keyed
// at (the SLEIGH space index << kSpaceKeyShift, so a language's keys are
// the same however the image was loaded), and the blocks its processor
// spec creates in every program (<default_memory_blocks>: AVR's register
// file, I/O and SRAM in "mem"; the 8051's register banks, INTMEM and SFR).
struct DefaultBlock {
  std::string name;
  std::string space;         // "" for the default space
  std::uint64_t start = 0;   // byte offset in the space
  std::uint64_t size = 0;    // bytes
  bool initialized = false;  // zero-filled; else no contents
  Perms perms{true, true, false};
  bool is_volatile = false;
};
// A label the processor spec puts on memory (<default_symbols> without
// entry="true": AVR's PORTB at mem:0x25, the 8051's SP at SFR:0x81).
struct DefaultLabel {
  std::string name;
  std::string space;  // "" for the default space
  std::uint64_t offset = 0;  // bytes
};
struct LanguageMemory {
  AddressSpace code;                 // the default space (base 0)
  std::vector<AddressSpace> spaces;  // other memory spaces, in SLEIGH's order
  std::vector<DefaultBlock> blocks;
  std::vector<DefaultLabel> labels;
};
// Where the loaders learn a language's LanguageMemory: revkit::lift
// installs a provider reading the install's SLEIGH and processor specs
// (lift::initialize). Without one (or for an unknown language) images get
// no default blocks and spaces are numbered as blocks need them.
using LanguageMemoryProvider = std::function<std::optional<LanguageMemory>(std::string_view language)>;
void set_language_memory_provider(LanguageMemoryProvider provider);
std::optional<LanguageMemory> language_memory(std::string_view language);
// Registers the language's spaces in an image (before its blocks are
// keyed) and, with `blocks`, adds its default blocks where nothing is
// mapped yet and its labels as weak data symbols where memory is mapped
// (Ghidra's "Apply Processor Defined Labels"). Nothing for 64-bit images.
void apply_language_memory(Image &image, const LanguageMemory &memory, bool blocks);
// The key of `offset` (bytes) in space `name` ("" for the default space,
// whose own name the image doesn't know); nullopt when the image has no
// such space or the offset doesn't fit below the next base.
std::optional<std::uint64_t> space_key(const Image &image, std::string_view name, std::uint64_t offset);
// The space a key is in (null: the default space) and its byte offset there.
struct SpaceOffset {
  const AddressSpace *space = nullptr;
  std::uint64_t offset = 0;
};
SpaceOffset split_key(const Image &image, std::uint64_t key);
// The address part of Ghidra's default names (FUN_<this>): "00101000", or
// "ram_00101000" with `qualifier` "ram_" (what a caller knows of a
// language whose other spaces the image doesn't key: RISC-V's csreg); in
// an image with other spaces, the key's space and its offset in that
// space's units, padded to its size: "code_003a", "mem_0100".
std::string name_address(const Image &image, std::uint64_t key, std::string_view qualifier = {});

struct LoadOptions {
  // Load at this base instead of the file's preferred one. All addresses
  // (segments, sections, symbols, entry) move by the same delta. Relocations
  // are not applied to memory (Image::relocations lists them).
  std::optional<std::uint64_t> image_base;

  // Mimic Ghidra's default: position-independent ELF images whose lowest
  // segment is at 0 load at 0x100000 (64-bit) or 0x10000 (32-bit), so our
  // addresses match a default Ghidra import. Ignored if image_base is set.
  bool ghidra_image_base = false;
};

// A memory region a raw image declares beside the file's bytes: RAM the
// code uses, memory-mapped I/O, a boot ROM. An uninitialized region has
// no bytes (reads as zero, and nothing treats its contents as known); an
// initialized one is zero-filled unless it takes `file_size` bytes of the
// file from `file_offset`.
struct RawRegion {
  std::string name;
  std::uint64_t start = 0;
  std::uint64_t size = 0;
  Perms perms{true, true, false};
  bool initialized = false;
  // Memory-mapped I/O: every access is a side effect (Ghidra's "volatile"
  // block). The decompiler never folds or merges reads of it.
  bool is_volatile = false;
  std::uint64_t file_offset = 0;
  std::uint64_t file_size = 0;
  // The memory space it is in (AVR's "mem", the 8051's "EXTMEM"); empty:
  // the language's default space. `start` is a byte offset in it.
  std::string space;

  friend bool operator==(const RawRegion &, const RawRegion &) = default;
};

// What a raw image's file holds: the bytes themselves, or a text format
// MCU toolchains write (Intel HEX, Motorola S-records), whose records give
// their own addresses and possibly an entry point. `detect` tells them
// apart by content: a file that parses as HEX or S-records throughout is
// one, anything else is binary.
enum class RawContainer : std::uint8_t { detect, binary, ihex, srec };

// How to load a flat binary (Ghidra's "Raw Binary" loader): `length` bytes
// of the file from `offset` (skipping a header) at `base`, as one block,
// read/write/execute by default as Ghidra's raw loader makes it; plus any
// extra regions. The language fixes endianness and pointer size. An Intel
// HEX or S-record file (RawContainer) gives a block per contiguous run of
// its data at the records' addresses plus `base`, `offset` and `length`
// unused, and its start address as the entry unless `entry` is set.
struct RawOptions {
  std::string language;  // "proc:endian:size:variant[:compiler]", required
  std::uint64_t base = 0;
  std::uint64_t offset = 0;              // file offset of the first loaded byte
  std::optional<std::uint64_t> length;   // bytes loaded; default: to the end of the file
  std::string block_name = "ram";
  Perms perms{true, true, true};
  std::optional<std::uint64_t> entry;
  std::vector<RawRegion> regions;
  // The space the image is loaded in ("" the default space, where code
  // is; "EXTMEM" for an 8051 data dump). `base` and `entry` are byte
  // offsets there (a word-addressed space's word address times its size).
  std::string space;
  RawContainer container = RawContainer::detect;

  friend bool operator==(const RawOptions &, const RawOptions &) = default;
};

}  // namespace revkit::loader
