// The emulator's internals, shared by its translation units.
#pragma once

#include "wide.hh"

#include "revkit/emu/emulator.hh"
#include "revkit/lift/abi.hh"
#include "revkit/lift/lifter.hh"

#include <array>
#include <deque>
#include <functional>
#include <set>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace revkit::emu {

namespace detail {

constexpr std::uint64_t kPageSize = 4096;

struct Page {
  std::array<std::uint8_t, kPageSize> bytes{};
};

// A sparse byte store in 4 KiB pages. Pages are shared until written, so a
// copy of a store is cheap (the debugger's snapshots, later).
class PageStore {
 public:
  // The page, or null if never written.
  const Page *find(std::uint64_t index) const;
  // The page, writable, created (by `fill`, else zeroed) if missing.
  // `created` reports a new page (it counts against the memory bound).
  template <class Fill>
  Page *writable(std::uint64_t index, Fill &&fill, bool &created) {
    created = false;
    auto it = pages_.find(index);
    if (it == pages_.end()) {
      auto page = std::make_shared<Page>();
      fill(*page);
      it = pages_.emplace(index, std::move(page)).first;
      created = true;
    } else if (it->second.use_count() > 1) {
      it->second = std::make_shared<Page>(*it->second);
    }
    last_index_ = index;
    last_ = it->second.get();
    return last_;
  }
  void erase(std::uint64_t index);
  std::size_t size() const { return pages_.size(); }
  void clear();

 private:
  std::unordered_map<std::uint64_t, std::shared_ptr<Page>> pages_;
  mutable std::uint64_t last_index_ = ~std::uint64_t{0};
  mutable Page *last_ = nullptr;
};

struct Region {
  RegionInfo info;
  std::uint64_t last() const { return info.start + (info.size - 1); }
};

// Where a varnode lives, resolved once per decoded instruction.
enum class SpaceKind : std::uint8_t { constant, ram, registers, unique, other_memory, pseudo };

struct Space {
  std::string name;
  SpaceKind kind = SpaceKind::pseudo;
  std::uint64_t mask = ~std::uint64_t{0};  // offsets wrap to the space's size
  std::uint32_t wordsize = 1;
};

struct Vn {
  std::int32_t space = -1;  // index into Impl::spaces
  std::uint32_t size = 0;
  std::uint64_t offset = 0;
};

struct Op {
  int opcode = 0;  // ghidra::OpCode
  bool has_out = false;
  Vn out;
  std::vector<Vn> in;
};

struct Decoded {
  std::uint64_t address = 0;
  bool thumb = false;
  std::uint32_t length = 0;
  std::uint32_t fall = 0;  // length plus delay slots
  std::vector<std::uint8_t> bytes;
  std::string text;
  std::vector<Op> ops;
  bool unimplemented = false;
  bool has_call = false;
  bool has_return = false;
  bool reads_nzcv = false, writes_nzcv = false;  // AArch64's NZCV system register
  // Thumb-2: an IT instruction (its ITSTATE byte), and 16-bit data-processing
  // encodings that set the flags outside an IT block but not inside one.
  bool it = false;
  std::uint8_t it_state = 0;
  bool it_flags16 = false;
  // A machine's CPU model's classification (machine_impl.hh SysBits).
  std::uint32_t sys = 0;
  std::uint8_t sys_reg = 0;
};

// Thrown from inside an instruction; the instruction's effects are undone.
struct Fault {
  StopKind kind;
  std::uint64_t address = 0;
  std::string detail;
  bool has_address = false;
};

struct UndoEntry {
  std::int32_t space;
  std::uint64_t offset;
  std::vector<std::uint8_t> old;
};

class MachineRuntime;

struct StubEntry {
  std::string name;
  Emulator::StubHandler handler;
  bool import = false;
};

struct Watch {
  int id;
  std::uint64_t start, last;
  bool read, write;
};

// The Linux system call convention of a language.
struct SyscallAbi {
  std::string userop;           // the CALLOTHER that makes the call
  std::optional<std::uint64_t> userop_arg;  // its required input (x86 INT 0x80)
  std::string number;           // register with the call number
  std::vector<std::string> args;
  std::string result;
  std::string table;            // "x86_64", "i386", "generic", "arm"
};

}  // namespace detail

struct Emulator::Impl {
  Emulator *self = nullptr;
  std::shared_ptr<const loader::Image> image;
  Options options;
  std::string language;  // with compiler
  Os os = Os::none;
  bool raw = false;
  bool big_endian = false;
  unsigned pointer_size = 8;

  // Decoding: ARM gets a second engine with TMode set for Thumb code.
  std::unique_ptr<lift::Lifter> lifter;
  std::unique_ptr<lift::Lifter> thumb_lifter;
  bool has_thumb = false;
  bool thumb = false;
  std::optional<lift::RegisterDef> tb_register;  // ARM's TB (ISA mode mirror)
  // AArch64 keeps the flags in NG, ZR, CY and OV but MRS/MSR NZCV move a
  // separate register: it is composed before an instruction reads it and
  // split after one writes it.
  std::optional<RegisterInfo> nzcv;
  std::vector<std::string> userops;
  lift::Abi abi;

  std::vector<detail::Space> spaces;
  std::int32_t ram_space = -1, register_space = -1, unique_space = -1, const_space = -1;
  std::unordered_map<std::string, std::int32_t> space_index;
  std::uint64_t code_mask = ~std::uint64_t{0};

  std::vector<RegisterInfo> registers;
  std::unordered_map<std::string, std::size_t> register_by_name;  // lower case
  std::map<std::pair<std::uint64_t, std::uint32_t>, std::size_t> register_by_storage;
  std::vector<std::string> display;
  RegisterInfo pc_reg, sp_reg;

  // State.
  std::uint64_t pc = 0;
  std::vector<std::uint8_t> regs;  // the register space, flat
  detail::PageStore ram;           // written pages of the default space
  // Pages read from Options::backing, as it was when first touched (clean).
  mutable detail::PageStore fetched;
  mutable std::uint64_t pages_fetched = 0;
  detail::PageStore unique;
  std::map<std::int32_t, detail::PageStore> other;  // other memory spaces
  std::map<std::uint64_t, detail::Region> regions;  // by start
  std::uint64_t used = 0;          // bytes allocated (pages, registers)
  std::uint64_t steps = 0;
  Stop last_stop;

  // Decoding cache, dropped when code is written.
  std::unordered_map<std::uint64_t, std::shared_ptr<const detail::Decoded>> decoded, decoded_thumb;
  std::unordered_map<std::uint64_t, std::uint32_t> code_pages;  // pages holding decoded code

  // Breakpoints, watchpoints, hooks.
  std::set<std::uint64_t> breakpoints;
  std::vector<detail::Watch> watches;
  int next_watch = 1;
  std::unordered_map<std::string, UseropHandler> userop_handlers;
  SyscallHandler syscall_handler;
  MmioHandler mmio_handler;
  std::map<std::uint64_t, detail::StubEntry> stubs;  // by address
  std::map<std::string, std::uint64_t> import_stubs;  // import name -> address
  std::optional<std::uint64_t> stub_base;
  std::uint64_t stub_next = 0;
  std::optional<std::uint64_t> return_trap, exit_trap;
  std::optional<detail::SyscallAbi> syscall_abi;

  // Linux process state.
  std::uint64_t brk_start = 0, brk = 0;
  std::uint64_t mmap_hint = 0;
  std::uint64_t stdin_pos = 0;
  std::uint64_t heap_next = 0, heap_end = 0;  // malloc stub's arena

  std::string out, err;
  Trace trace;
  std::deque<MmioAccess> mmio_log;

  // Per instruction.
  std::vector<detail::UndoEntry> undo;
  bool recording = false;  // fill `entry`
  bool in_step = false;    // exec_one is running: hooks' memory writes belong to `entry`
  TraceEntry entry;
  std::optional<std::uint64_t> watch_hit;
  bool mmio_read_this_step = false;
  std::string step_event;
  std::size_t step_reads = 0, step_writes = 0;
  std::optional<std::int64_t> pending_exit;  // a syscall ended the program
  int call_depth = 0;                        // CALL minus RETURN ops executed, for step_out
  // Thumb-2 ITSTATE: the condition and mask of the IT block being executed.
  std::uint8_t itstate = 0;
  // Firmware: the board around the CPU (machine.cc); null for a plain emulator.
  std::unique_ptr<detail::MachineRuntime> machine;

  Impl(Emulator *self, std::shared_ptr<const loader::Image> image, Options options);
  // Lays options.patches over bytes read from the image at `at`.
  void overlay_patches(std::uint64_t at, std::span<std::byte> span) const;

  // --- setup (emulator.cc) ---
  void init_language();
  void init_memory();
  void init_imports();
  std::uint64_t alloc_stub(const std::string &name, StubHandler handler, bool import);

  // --- registers and memory (state.cc) ---
  const RegisterInfo &reg(std::string_view name) const;
  std::optional<std::size_t> find_reg(std::string_view name) const;
  detail::Wide get_reg(const RegisterInfo &r) const;
  void set_reg(const RegisterInfo &r, const detail::Wide &v);
  std::uint64_t get_reg_u64(std::string_view name) const;
  void set_reg_u64(std::string_view name, std::uint64_t v);
  const detail::Region *region_at(std::uint64_t addr) const;
  bool mapped(std::uint64_t addr, std::uint64_t size) const;
  // What memory nothing wrote holds: the backing's (fetched once), else the image's with patches.
  void base_read(std::uint64_t at, std::span<std::byte> out) const;
  // Raw byte access to the default space, no checks; unmapped bytes read 0.
  void ram_read(std::uint64_t addr, std::uint8_t *out, std::uint64_t size) const;
  void ram_write(std::uint64_t addr, const std::uint8_t *in, std::uint64_t size);
  void charge(std::uint64_t bytes);
  void map_region(RegionInfo info);
  std::uint64_t word(const std::uint8_t *bytes, std::uint32_t size) const;
  void put_word(std::uint8_t *bytes, std::uint32_t size, std::uint64_t v) const;

  std::string register_name(std::uint64_t offset, std::uint32_t size) const;

  // --- the interpreter (interp.cc) ---
  std::shared_ptr<const detail::Decoded> decode(std::uint64_t address);
  detail::Wide read_vn(const detail::Vn &vn);
  void write_vn(const detail::Vn &vn, const detail::Wide &v);
  detail::Wide load(std::int32_t space, std::uint64_t offset, std::uint32_t size);
  void store(std::int32_t space, std::uint64_t offset, const detail::Wide &v);
  void mem_read(std::uint64_t addr, std::uint8_t *out, std::uint32_t size);
  void mem_write(std::uint64_t addr, const std::uint8_t *in, std::uint32_t size);
  // One instruction (or stub). Returns a stop, or nullopt to go on.
  std::optional<Stop> exec_one();
  std::optional<Stop> exec_stub(const detail::StubEntry &stub);
  void exec_userop(const detail::Op &op);
  bool builtin_userop(const std::string &name, const UseropCall &call, const detail::Op &op);
  std::optional<std::uint64_t> cpuid_block;
  void undo_all();
  void finish_entry(const detail::Decoded *d, bool record);
  Stop make_stop(StopKind kind, std::string detail = {});
  Stop run_loop(const RunOptions &options, const std::function<bool()> &done, bool first_free);

  // --- calls (emulator.cc) ---
  std::uint64_t call_arg(unsigned index) const;
  void set_return_value(std::uint64_t v);
  // Leaves the function being called: pops the return address (and `pop`
  // more bytes), sets pc. Throws Fault when the slot is unmapped.
  void return_from_call(std::uint32_t pop);
  void setup_call(std::uint64_t entry, std::span<const std::uint64_t> args, std::uint64_t return_to);
  std::uint64_t ensure_stack();
  void setup_process(std::uint64_t entry);
  void apply_isa(std::uint64_t &target);
  // Thumb-2 IT blocks (interp.cc): whether the condition `cond` holds.
  bool condition_holds(unsigned cond) const;

  Impl(const Impl &) = delete;
  ~Impl();
};

// A checkpoint's contents (Emulator::checkpoint).
struct CheckpointState {
  const Emulator::Impl *owner = nullptr;
  std::uint64_t pc = 0;
  std::vector<std::uint8_t> regs;
  detail::PageStore ram;
  std::map<std::int32_t, detail::PageStore> other;
  std::map<std::uint64_t, detail::Region> regions;
  std::uint64_t used = 0, steps = 0;
  Stop last_stop;
  std::uint64_t brk_start = 0, brk = 0, mmap_hint = 0, stdin_pos = 0, heap_next = 0, heap_end = 0;
  std::size_t out_size = 0, err_size = 0;
  bool thumb = false;
  std::uint8_t itstate = 0;
  int call_depth = 0;
  std::optional<std::int64_t> pending_exit;
  std::optional<std::uint64_t> cpuid_block;
};

// Library stubs (stubs.cc).
void install_library_stubs(Emulator::Impl &impl);
std::optional<detail::SyscallAbi> linux_syscall_abi(const std::string &language);
// x86-64's RFLAGS from its flag registers (what SYSCALL leaves in R11).
std::uint64_t x86_rflags(const Emulator::Impl &impl);

// Floating point (float.cc): p-code float ops on values of any of the
// encodings SLEIGH uses (2, 4, 8, 10 and 16 bytes).
namespace detail {
Wide float_op(int opcode, const Wide &a, const Wide *b, std::uint32_t out_size);
}

}  // namespace revkit::emu
