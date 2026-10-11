// Setting up a machine (language, memory, imports, the stack of a process
// or a call), the run loops, and the public API.
#include "impl.hh"
#include "machine_impl.hh"

#include "revkit/lift/context.hh"

#include "opcodes.hh"
#include "revkit/loader/load.hh"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

namespace revkit::emu {

using detail::Fault;
using detail::kPageSize;
using detail::SpaceKind;
using detail::Wide;

namespace {

std::string hexs(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

std::string lower(std::string_view s) {
  std::string out(s);
  for (char &c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::uint64_t align_up(std::uint64_t v, std::uint64_t a) { return (v + a - 1) & ~(a - 1); }

std::string ghidra_opname(int opcode) { return ghidra::get_opname(static_cast<ghidra::OpCode>(opcode)); }

// The registers a person wants to see, per processor; names that don't
// exist in the language are dropped.

}  // namespace

std::vector<std::string> display_register_names(const std::string &language, unsigned pointer_size) {
  const std::string proc = language.substr(0, language.find(':'));
  std::vector<std::string> out;
  auto range = [&](const char *prefix, int first, int last) {
    for (int i = first; i <= last; ++i) out.push_back(prefix + std::to_string(i));
  };
  if (proc == "x86" && pointer_size == 8) {
    out = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP"};
    range("R", 8, 15);
    out.insert(out.end(), {"RIP", "CF", "PF", "AF", "ZF", "SF", "DF", "OF", "FS_OFFSET"});
  } else if (proc == "x86") {
    out = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "CF", "PF", "AF", "ZF", "SF", "DF", "OF"};
  } else if (proc == "AARCH64") {
    range("x", 0, 30);
    out.insert(out.end(), {"sp", "pc", "NG", "ZR", "CY", "OV"});
  } else if (proc == "ARM") {
    range("r", 0, 12);
    out.insert(out.end(), {"sp", "lr", "pc", "NG", "ZR", "CY", "OV", "TB"});
  } else if (proc == "RISCV") {
    out = {"ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1"};
    range("a", 0, 7);
    range("s", 2, 11);
    range("t", 3, 6);
    out.push_back("pc");
  } else if (proc == "MIPS") {
    out = {"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3"};
    range("t", 0, 9);
    range("s", 0, 8);
    out.insert(out.end(), {"k0", "k1", "gp", "sp", "ra", "pc", "hi", "lo"});
  } else if (proc == "PowerPC") {
    range("r", 0, 31);
    out.insert(out.end(), {"pc", "LR", "CTR", "cr0", "xer_ca"});
  }
  return out;
}

std::string_view to_string(StopKind kind) {
  switch (kind) {
    case StopKind::none: return "none";
    case StopKind::stepped: return "stepped";
    case StopKind::step_limit: return "step_limit";
    case StopKind::breakpoint: return "breakpoint";
    case StopKind::until: return "until";
    case StopKind::returned: return "returned";
    case StopKind::exited: return "exited";
    case StopKind::halted: return "halted";
    case StopKind::unmapped: return "unmapped";
    case StopKind::protection: return "protection";
    case StopKind::decode: return "decode";
    case StopKind::unimplemented: return "unimplemented";
    case StopKind::userop: return "userop";
    case StopKind::syscall: return "syscall";
    case StopKind::watchpoint: return "watchpoint";
    case StopKind::hook: return "hook";
    case StopKind::divide_by_zero: return "divide_by_zero";
    case StopKind::memory_limit: return "memory_limit";
    case StopKind::time_limit: return "time_limit";
    case StopKind::cancelled: return "cancelled";
    case StopKind::exception: return "exception";
    case StopKind::idle: return "idle";
  }
  return "none";
}

std::optional<StopKind> stop_kind(std::string_view name) {
  for (int k = 0; k <= static_cast<int>(StopKind::idle); ++k)
    if (to_string(static_cast<StopKind>(k)) == name) return static_cast<StopKind>(k);
  return std::nullopt;
}

// --- Construction ---

Emulator::Impl::Impl(Emulator *s, std::shared_ptr<const loader::Image> img, Options opts)
    : self(s), image(std::move(img)), options(std::move(opts)), trace(options.trace_capacity) {
  if (!image) throw EmuError("no image");
  raw = image->format == loader::Format::raw;
  os = options.os ? *options.os : (image->format == loader::Format::elf ? Os::linux : Os::none);
  init_language();
  init_memory();
}

void Emulator::Impl::init_language() {
  std::string base, compiler;
  if (!options.language.empty()) {
    const auto colons = std::count(options.language.begin(), options.language.end(), ':');
    if (colons == 4) {
      base = options.language.substr(0, options.language.rfind(':'));
      compiler = options.language.substr(options.language.rfind(':') + 1);
    } else if (colons == 3) {
      base = options.language;
    } else {
      throw EmuError("language must be proc:endian:size:variant[:compiler], not " + options.language);
    }
  } else if (auto guess = loader::guess_language(*image)) {
    base = guess->language;
    compiler = guess->compiler;
  } else {
    throw EmuError(raw ? "a raw image needs a language" : "no Ghidra language for machine " + std::to_string(image->machine) + "; give one");
  }
  if (!lift::language_exists(base)) throw EmuError("unknown language " + base);
  abi = lift::read_abi(base, compiler);
  language = compiler.empty() ? base : base + ":" + compiler;
  lifter = std::make_unique<lift::Lifter>(image, base);
  big_endian = lifter->big_endian();

  const std::vector<lift::SpaceDef> defs = lifter->spaces();
  for (std::size_t i = 0; i < defs.size(); ++i) {
    const lift::SpaceDef &d = defs[i];
    detail::Space sp;
    sp.name = d.name;
    sp.wordsize = std::max<std::uint32_t>(1, d.wordsize);
    if (d.address_size > 0 && d.address_size < 8) sp.mask = (std::uint64_t{1} << (8 * d.address_size)) - 1;
    switch (d.kind) {
      case lift::SpaceDef::Kind::constant: sp.kind = SpaceKind::constant; const_space = static_cast<std::int32_t>(i); break;
      case lift::SpaceDef::Kind::unique: sp.kind = SpaceKind::unique; unique_space = static_cast<std::int32_t>(i); break;
      case lift::SpaceDef::Kind::processor:
        if (d.is_register) {
          sp.kind = SpaceKind::registers;
          register_space = static_cast<std::int32_t>(i);
        } else if (d.is_default) {
          sp.kind = SpaceKind::ram;
          ram_space = static_cast<std::int32_t>(i);
          code_mask = sp.mask;
          pointer_size = d.address_size;
        } else {
          sp.kind = SpaceKind::other_memory;
        }
        break;
      default: sp.kind = SpaceKind::pseudo; break;
    }
    if (!sp.name.empty()) space_index.emplace(sp.name, static_cast<std::int32_t>(i));
    spaces.push_back(std::move(sp));
  }
  if (ram_space < 0 || register_space < 0) throw EmuError("language " + language + " has no default or register space");

  std::uint64_t reg_bytes = 0;
  for (const lift::RegisterDef &r : lifter->registers()) {
    RegisterInfo info{r.name, r.offset, r.size};
    const std::size_t index = registers.size();
    registers.push_back(info);
    register_by_name.emplace(lower(r.name), index);
    register_by_storage.emplace(std::make_pair(r.offset, r.size), index);
    reg_bytes = std::max<std::uint64_t>(reg_bytes, r.offset + r.size);
  }
  if (reg_bytes > (64ull << 20)) throw EmuError("register space of " + language + " is too large");
  charge(reg_bytes);
  regs.assign(reg_bytes, 0);
  userops = lifter->userops();

  if (!abi.program_counter.empty())
    if (auto i = find_reg(abi.program_counter)) pc_reg = registers[*i];
  if (!abi.stack_pointer.empty())
    if (auto i = find_reg(abi.stack_pointer)) sp_reg = registers[*i];

  // ARM: Thumb code decodes with TMode set; TB tracks the current set.
  if (base.rfind("ARM:", 0) == 0) {
    try {
      auto t = std::make_unique<lift::Lifter>(image, base);
      t->set_context("TMode", 1, 0);
      thumb_lifter = std::move(t);
      has_thumb = true;
      if (auto i = find_reg("TB")) tb_register = lift::RegisterDef{registers[*i].name, registers[*i].offset, registers[*i].size};
      else if (auto j = find_reg("ISAModeSwitch"))
        tb_register = lift::RegisterDef{registers[*j].name, registers[*j].offset, registers[*j].size};
    } catch (const lift::LiftError &) {
      has_thumb = false;  // a variant without Thumb
    }
  }

  if (base.rfind("AARCH64", 0) == 0 && find_reg("nzcv") && find_reg("NG") && find_reg("ZR") && find_reg("CY") &&
      find_reg("OV"))
    nzcv = registers[*find_reg("nzcv")];
  // DC ZVA zeroes 64-byte blocks (DCZID_EL0.BS = 4).
  if (base.rfind("AARCH64", 0) == 0)
    if (auto i = find_reg("dczid_el0")) set_reg(registers[*i], Wide::of(registers[*i].size, 4));
  // x86 user code runs with interrupts enabled (PUSHF shows IF).
  if (base.rfind("x86", 0) == 0)
    if (auto i = find_reg("IF")) set_reg(registers[*i], Wide::of(registers[*i].size, 1));

  for (const std::string &name : display_register_names(base, pointer_size))
    if (auto i = find_reg(name)) display.push_back(registers[*i].name);
  if (display.empty()) {
    // Unknown processor: pc, sp, the call registers, then pointer-sized
    // registers that aren't part of a larger one.
    auto add = [&](const std::string &n) {
      if (auto i = find_reg(n); i && std::find(display.begin(), display.end(), registers[*i].name) == display.end())
        display.push_back(registers[*i].name);
    };
    add(abi.program_counter);
    add(abi.stack_pointer);
    for (const std::string &n : abi.int_returns) add(n);
    for (const std::string &n : abi.int_params) add(n);
    std::uint64_t covered_until = 0;
    for (const RegisterInfo &r : registers) {
      if (display.size() >= 40) break;
      const bool inside = r.offset < covered_until;
      covered_until = std::max(covered_until, r.offset + r.size);
      if (!inside && r.size == pointer_size) add(r.name);
    }
  }
}

void Emulator::Impl::init_memory() {
  if (options.backing) {
    // A debugger's process: its memory map, not the image's segments.
    for (RegionInfo r : options.backing->regions) map_region(std::move(r));
    return;
  }
  const auto &segments = image->memory.regions();
  for (std::size_t i = 0; i < segments.size(); ++i) {
    const loader::Region &seg = segments[i];
    RegionInfo info;
    info.start = seg.start;
    info.size = seg.size;
    info.perms = seg.perms;
    info.kind = RegionInfo::Kind::image;
    for (const loader::Block &b : image->blocks) {
      if (b.start + b.size <= seg.start || b.start > seg.last()) continue;
      if (info.name.empty() && b.start <= seg.start) info.name = b.name;
      if (b.is_volatile) info.kind = RegionInfo::Kind::mmio;
    }
    if (info.name.empty()) info.name = "segment_" + hexs(seg.start).substr(2);
    if (image->format != loader::Format::raw) {
      // A process maps whole pages: code may read past a segment's end
      // within its last page (word-at-a-time string functions do).
      const std::uint64_t prev_end = regions.empty() ? 0 : std::prev(regions.end())->second.last() + 1;
      std::uint64_t start = std::max(seg.start & ~(kPageSize - 1), prev_end);
      std::uint64_t end = seg.last() + 1;  // exclusive; 0 when it reaches the top
      if (end != 0) {
        std::uint64_t rounded = align_up(end, kPageSize);
        if (rounded == 0 || rounded < end) rounded = end;
        if (i + 1 < segments.size()) rounded = std::min(rounded, segments[i + 1].start & ~(kPageSize - 1));
        end = std::max(end, rounded);
      }
      if (start > seg.start) start = seg.start;
      info.start = start;
      info.size = end - start;
    }
    map_region(std::move(info));
  }
}

std::uint64_t Emulator::Impl::alloc_stub(const std::string &name, StubHandler handler, bool import) {
  if (!stub_base) {
    const std::uint64_t size = 0x10000;
    // Near the top of the space, where nothing is loaded.
    std::uint64_t hint = (code_mask - 0x1000000) & ~std::uint64_t{0xffff};
    if (pointer_size >= 8) hint = 0xfffffffff0000000ull & code_mask;
    auto at = self->find_free(size, hint, 0x10000);
    if (!at) at = self->find_free(size, 0x10000, 0x10000);
    if (!at) throw EmuError("no room for the stub region");
    RegionInfo info;
    info.name = "stubs";
    info.start = *at;
    info.size = size;
    info.perms = {true, false, true};
    info.kind = RegionInfo::Kind::stub;
    map_region(info);
    stub_base = *at;
    stub_next = *at;
  }
  if (stub_next + 16 > *stub_base + 0x10000) throw EmuError("too many stubs");
  const std::uint64_t addr = stub_next;
  stub_next += 16;
  stubs[addr] = detail::StubEntry{name, std::move(handler), import};
  return addr;
}

namespace {

// What a call to an import does when nothing better is known: return the
// configured value (unless its prototype returns nothing), popping its
// stack parameters if it is a callee-pops (stdcall) function.
Emulator::StubHandler skip_handler(std::string name) {
  return [name](Emulator &emu, StubCall &call) {
    std::optional<ImportPrototype> proto;
    if (emu.options().prototypes) proto = emu.options().prototypes(name);
    call.return_value = emu.options().import_return;
    if (proto) {
      call.returns_value = proto->returns_value;
      if (proto->callee_pops) call.stack_pop = proto->parameters * emu.pointer_size();
    }
    call.note = "skipped " + name + (call.returns_value ? " = " + hexs(call.return_value) : "");
    return HookAction::proceed;
  };
}

}  // namespace

void Emulator::Impl::init_imports() {
  if (options.backing) return;  // the process bound its own imports
  const unsigned ptr = pointer_size;
  auto import_stub = [&](const std::string &name) -> std::uint64_t {
    if (auto it = import_stubs.find(name); it != import_stubs.end()) return it->second;
    const std::uint64_t addr = alloc_stub(name, skip_handler(name), true);
    import_stubs[name] = addr;
    return addr;
  };
  std::vector<std::uint8_t> word(ptr);
  auto put = [&](std::uint64_t at, std::uint64_t value) {
    if (!mapped(at, ptr)) return;
    put_word(word.data(), ptr, value);
    ram_write(at, word.data(), ptr);
  };
  if (image->format == loader::Format::elf) {
    std::map<std::string, std::uint64_t, std::less<>> defined;
    for (const loader::Symbol &s : image->symbols)
      if (s.defined && !s.name.empty() && s.type != loader::SymbolType::section && s.type != loader::SymbolType::file)
        defined.emplace(s.name, s.value);
    for (const loader::Relocation &r : image->relocations) {
      switch (r.kind) {
        case loader::RelocationKind::relative:
          if (r.target) put(r.address, *r.target);
          break;
        case loader::RelocationKind::jump_slot:
        case loader::RelocationKind::glob_dat:
        case loader::RelocationKind::absolute: {
          if (r.symbol.empty()) break;
          std::string name = r.symbol.substr(0, r.symbol.find('@'));
          const std::uint64_t addend = r.kind == loader::RelocationKind::absolute ? static_cast<std::uint64_t>(r.addend) : 0;
          if (auto it = defined.find(name); it != defined.end()) put(r.address, it->second + addend);
          else put(r.address, import_stub(name) + addend);
          break;
        }
        default: break;
      }
    }
  } else if (image->format == loader::Format::pe) {
    for (const loader::Import &imp : image->imports) {
      if (imp.iat_address == 0) continue;
      std::string name = !imp.name.empty() ? imp.name
                         : imp.ordinal    ? imp.library + "#" + std::to_string(*imp.ordinal)
                                          : imp.library + "#?";
      put(imp.iat_address, import_stub(name));
    }
  }
  if (options.library_stubs) install_library_stubs(*this);
}

// --- Calls ---

std::uint64_t Emulator::Impl::call_arg(unsigned index) const {
  if (index < abi.int_params.size()) return get_reg_u64(abi.int_params[index]);
  const unsigned j = index - static_cast<unsigned>(abi.int_params.size());
  std::uint64_t sp = sp_reg.name.empty() ? 0 : get_reg(sp_reg).lo();
  // Stack parameters sit above the return address when the call pushed it.
  if (abi.return_register.empty()) sp += static_cast<std::uint64_t>(abi.stack_shift);
  std::vector<std::uint8_t> b(pointer_size);
  const std::uint64_t at = sp + static_cast<std::uint64_t>(j) * pointer_size;
  if (!mapped(at, pointer_size)) return 0;
  ram_read(at, b.data(), pointer_size);
  return word(b.data(), pointer_size);
}

void Emulator::Impl::set_return_value(std::uint64_t v) {
  if (abi.int_returns.empty()) return;
  set_reg_u64(abi.int_returns[0], v);
}

void Emulator::Impl::return_from_call(std::uint32_t pop) {
  std::uint64_t ra = 0;
  if (!abi.return_register.empty()) {
    ra = get_reg_u64(abi.return_register);
    if (pop != 0) {
      const std::uint64_t sp = get_reg(sp_reg).lo();
      store(register_space, sp_reg.offset, Wide::of(sp_reg.size, sp + pop));
    }
  } else {
    const std::uint64_t sp = get_reg(sp_reg).lo();
    const std::uint32_t size = abi.return_size != 0 ? abi.return_size : pointer_size;
    std::uint8_t b[8] = {};
    const std::uint64_t at = sp + static_cast<std::uint64_t>(abi.return_stack_offset.value_or(0));
    mem_read(at, b, std::min<std::uint32_t>(size, 8));
    ra = word(b, std::min<std::uint32_t>(size, 8));
    const std::uint64_t shift = abi.stack_shift != 0 ? static_cast<std::uint64_t>(abi.stack_shift) : size;
    store(register_space, sp_reg.offset, Wide::of(sp_reg.size, sp + shift + pop));
  }
  --call_depth;
  pc = ra & code_mask;
  apply_isa(pc);
}

std::uint64_t Emulator::Impl::ensure_stack() {
  for (const auto &[start, r] : regions)
    if (r.info.name == "stack") return r.last() + 1;
  const std::uint64_t space = code_mask;
  std::uint64_t size = 8ull << 20;
  if (space < 0xffffffffull) size = std::min<std::uint64_t>(size, (space + 1) / 16);
  std::optional<std::uint64_t> at;
  if (pointer_size >= 8) at = self->find_free(size, 0x7ffffff00000ull - size);
  else if (space >= 0xffffffffull) at = self->find_free(size, 0xbf000000ull - size);
  if (!at) at = self->find_free(size, (space / 2) & ~(kPageSize - 1));
  if (!at) at = self->find_free(size, 0x1000);
  if (!at) throw EmuError("no room for a stack");
  RegionInfo info;
  info.name = "stack";
  info.start = *at;
  info.size = size;
  info.perms = {true, true, false};
  info.kind = RegionInfo::Kind::ram;
  map_region(info);
  return *at + size;
}

void Emulator::Impl::setup_call(std::uint64_t entry, std::span<const std::uint64_t> args, std::uint64_t return_to) {
  const std::uint64_t top = ensure_stack();
  std::uint64_t base = (top - 256) & ~std::uint64_t{15};
  const std::size_t in_regs = std::min(args.size(), abi.int_params.size());
  for (std::size_t i = 0; i < in_regs; ++i) set_reg_u64(abi.int_params[i], args[i]);
  const std::size_t on_stack = args.size() - in_regs;
  base -= align_up(on_stack * pointer_size, 16);
  std::vector<std::uint8_t> w(pointer_size);
  for (std::size_t j = 0; j < on_stack; ++j) {
    put_word(w.data(), pointer_size, args[in_regs + j]);
    ram_write(base + j * pointer_size, w.data(), pointer_size);
  }
  std::uint64_t sp = base;
  if (!abi.return_register.empty()) {
    set_reg_u64(abi.return_register, return_to);
  } else {
    const std::uint32_t size = abi.return_size != 0 ? abi.return_size : pointer_size;
    sp -= abi.stack_shift != 0 ? static_cast<std::uint64_t>(abi.stack_shift) : size;
    std::vector<std::uint8_t> r(size);
    put_word(r.data(), size, return_to);
    ram_write(sp + static_cast<std::uint64_t>(abi.return_stack_offset.value_or(0)), r.data(), size);
  }
  if (!sp_reg.name.empty()) set_reg(sp_reg, Wide::of(sp_reg.size, sp));
  pc = entry & code_mask;
  apply_isa(pc);
}

void Emulator::Impl::setup_process(std::uint64_t entry) {
  const std::uint64_t top = ensure_stack();
  const unsigned ptr = pointer_size;
  std::uint64_t at = top - 16;
  auto push_bytes = [&](const void *data, std::size_t n) {
    at -= n;
    ram_write(at, static_cast<const std::uint8_t *>(data), n);
    return at;
  };
  auto push_string = [&](const std::string &s) { return push_bytes(s.c_str(), s.size() + 1); };
  std::vector<std::uint64_t> argv, envp;
  for (const std::string &a : options.argv) argv.push_back(push_string(a));
  for (const std::string &e : options.envp) envp.push_back(push_string(e));
  std::uint8_t random[16];
  for (int i = 0; i < 16; ++i) random[i] = static_cast<std::uint8_t>(0x10 + i);  // deterministic AT_RANDOM
  const std::uint64_t random_at = push_bytes(random, 16);
  const std::string platform = language.substr(0, language.find(':'));
  const std::uint64_t platform_at = push_string(platform);
  at &= ~std::uint64_t{15};

  // Where the program headers are: PT_PHDR, else the first PT_LOAD at
  // file offset 0 plus e_phoff.
  std::uint64_t phdr = 0, phnum = 0;
  const std::uint64_t phent = ptr == 8 ? 56 : 32;
  for (const loader::Segment &s : image->segments) {
    ++phnum;
    if (s.type == 6) phdr = s.vaddr;
  }
  if (phdr == 0 && image->file) {
    const loader::Bytes &f = *image->file;
    std::uint64_t phoff = 0;
    const std::size_t off = ptr == 8 ? 0x20 : 0x1c;
    if (f.size() >= off + ptr)
      phoff = word(reinterpret_cast<const std::uint8_t *>(f.data() + off), ptr);
    for (const loader::Segment &s : image->segments)
      if (s.type == 1 && s.offset == 0) phdr = s.vaddr + phoff;
  }

  std::vector<std::uint64_t> words;
  words.push_back(argv.size());
  for (std::uint64_t a : argv) words.push_back(a);
  words.push_back(0);
  for (std::uint64_t e : envp) words.push_back(e);
  words.push_back(0);
  const std::pair<std::uint64_t, std::uint64_t> auxv[] = {
      {3, phdr}, {4, phent}, {5, phnum}, {6, 4096}, {7, 0}, {8, 0}, {9, entry & ~std::uint64_t{1}},
      {11, 1000}, {12, 1000}, {13, 1000}, {14, 1000}, {16, 0}, {17, 100}, {23, 0}, {25, random_at},
      {15, platform_at}, {0, 0}};
  for (const auto &[k, v] : auxv) {
    words.push_back(k);
    words.push_back(v);
  }
  std::uint64_t sp = (at - words.size() * ptr) & ~std::uint64_t{15};
  std::vector<std::uint8_t> w(ptr);
  for (std::size_t i = 0; i < words.size(); ++i) {
    put_word(w.data(), ptr, words[i]);
    ram_write(sp + i * ptr, w.data(), ptr);
  }
  if (!sp_reg.name.empty()) set_reg(sp_reg, Wide::of(sp_reg.size, sp));

  // The program break starts after the highest loaded byte.
  std::uint64_t end = 0;
  for (const auto &[start, r] : regions)
    if (r.info.kind == RegionInfo::Kind::image) end = std::max(end, r.last() + 1);
  brk_start = brk = align_up(end, kPageSize);
  mmap_hint = ptr >= 8 ? 0x7f0000000000ull : 0x40000000ull;
  pc = entry & code_mask;
  apply_isa(pc);
}

Stop Emulator::Impl::run_loop(const RunOptions &o, const std::function<bool()> &done, bool) {
  Stop s;
  std::uint64_t n = 0;
  try {
    if (machine) {
      // A CPU left waiting for an interrupt waits on before it runs.
      if (auto st = machine->resume_check(o)) {
        s = *st;
        s.steps = 0;
        last_stop = s;
        return s;
      }
    }
    while (true) {
      if (n >= o.max_steps) {
        s = make_stop(StopKind::step_limit, "ran " + std::to_string(n) + " steps");
        break;
      }
      if ((n & 255) == 255) {
        if (std::chrono::steady_clock::now() >= o.deadline) {
          s = make_stop(StopKind::time_limit, "the call's time limit");
          break;
        }
        if (o.cancelled && o.cancelled()) {
          s = make_stop(StopKind::cancelled, "cancelled");
          break;
        }
      }
      if (auto r = exec_one()) {
        if (machine && r->kind == StopKind::halted && machine->can_idle()) {
          // A firmware's idle loop: wait for the next interrupt.
          machine->wait();
        } else {
          s = *r;
          if (s.kind == StopKind::exited || s.kind == StopKind::halted || s.kind == StopKind::watchpoint) ++n;
          break;
        }
      }
      ++n;
      if (machine) {
        if (auto st = machine->after_step(o)) {
          s = *st;
          break;
        }
      }
      if (done && done()) {
        s = make_stop(StopKind::stepped);
        break;
      }
      if (o.until && pc == *o.until) {
        s = make_stop(StopKind::until, "reached " + hexs(pc));
        break;
      }
      if (breakpoints.count(pc) != 0) {
        s = make_stop(StopKind::breakpoint, "breakpoint at " + hexs(pc));
        break;
      }
    }
  } catch (const Fault &f) {
    s = make_stop(f.kind, f.detail);
  }
  s.steps = n;
  last_stop = s;
  return s;
}

// --- Public API ---

Emulator::Emulator(std::shared_ptr<const loader::Image> image, Options options)
    : impl_(std::make_unique<Impl>(this, std::move(image), std::move(options))) {
  // These call back through the public API, so impl_ must be set.
  try {
    impl_->init_imports();
  } catch (const Fault &f) {
    throw EmuError(f.detail);
  }
  if (impl_->os == Os::linux) {
    impl_->syscall_abi = linux_syscall_abi(impl_->language);
    if (impl_->syscall_abi) install_linux(*this);
  }
}

Emulator::~Emulator() = default;

const std::string &Emulator::language() const { return impl_->language; }
const Options &Emulator::options() const { return impl_->options; }
Os Emulator::os() const { return impl_->os; }
const loader::Image &Emulator::image() const { return *impl_->image; }
unsigned Emulator::pointer_size() const { return impl_->pointer_size; }
bool Emulator::big_endian() const { return impl_->big_endian; }

void Emulator::start(std::uint64_t entry, StartMode mode, std::span<const std::uint64_t> args) {
  Impl &m = *impl_;
  if (mode == StartMode::automatic) {
    if (m.os == Os::linux && m.image->format == loader::Format::elf && m.image->entry &&
        (*m.image->entry & ~std::uint64_t{1}) == (entry & ~std::uint64_t{1}))
      mode = StartMode::process;
    else if (m.raw)
      mode = StartMode::bare;
    else
      mode = StartMode::call;
  }
  try {
    switch (mode) {
      case StartMode::process: m.setup_process(entry); break;
      case StartMode::call:
        if (!m.return_trap) m.return_trap = m.alloc_stub("<return>", nullptr, false);
        m.stubs.erase(*m.return_trap);  // checked by address, not run as a stub
        m.setup_call(entry, args, *m.return_trap);
        break;
      case StartMode::bare:
      case StartMode::automatic:
        m.pc = entry & m.code_mask;
        m.apply_isa(m.pc);
        break;
    }
  } catch (const Fault &f) {
    throw EmuError(f.detail);
  }
  if (!m.pc_reg.name.empty()) m.set_reg(m.pc_reg, Wide::of(m.pc_reg.size, m.pc));
}

std::optional<std::uint64_t> Emulator::return_trap() const { return impl_->return_trap; }

std::optional<std::uint64_t> Emulator::import_address(std::string_view name) const {
  auto it = impl_->import_stubs.find(std::string(name));
  if (it == impl_->import_stubs.end()) return std::nullopt;
  return it->second;
}

std::uint64_t Emulator::pc() const { return impl_->pc; }
void Emulator::set_pc(std::uint64_t pc) {
  impl_->pc = pc & impl_->code_mask;
  impl_->apply_isa(impl_->pc);
  if (!impl_->pc_reg.name.empty()) impl_->set_reg(impl_->pc_reg, Wide::of(impl_->pc_reg.size, impl_->pc));
}
bool Emulator::thumb() const { return impl_->thumb; }
void Emulator::set_thumb(bool thumb) {
  if (!impl_->has_thumb) return;
  impl_->thumb = thumb;
  if (impl_->tb_register)
    impl_->set_reg(RegisterInfo{impl_->tb_register->name, impl_->tb_register->offset, impl_->tb_register->size},
                   Wide::of(1, thumb ? 1 : 0));
}
const std::vector<RegisterInfo> &Emulator::registers() const { return impl_->registers; }
const std::vector<std::string> &Emulator::display_registers() const { return impl_->display; }
const std::string &Emulator::pc_register() const { return impl_->pc_reg.name; }
const std::string &Emulator::sp_register() const { return impl_->sp_reg.name; }

std::optional<RegisterInfo> Emulator::find_register(std::string_view name) const {
  auto i = impl_->find_reg(name);
  if (!i) return std::nullopt;
  return impl_->registers[*i];
}

std::vector<std::uint8_t> Emulator::read_register_bytes(std::string_view name) const {
  const RegisterInfo &r = impl_->reg(name);
  if (r.size > detail::kMaxValueBytes) throw EmuError("register " + r.name + " is too wide");
  std::vector<std::uint8_t> out(r.size);
  impl_->get_reg(r).to_le(out.data());
  return out;
}

void Emulator::write_register_bytes(std::string_view name, std::span<const std::uint8_t> value) {
  const RegisterInfo &r = impl_->reg(name);
  if (r.size > detail::kMaxValueBytes) throw EmuError("register " + r.name + " is too wide");
  std::uint8_t buf[detail::kMaxValueBytes] = {};
  std::memcpy(buf, value.data(), std::min<std::size_t>(value.size(), r.size));
  try {
    impl_->set_reg(r, Wide::from_le(r.size, buf));
  } catch (const Fault &f) {
    throw EmuError(f.detail);
  }
  if (r.offset == impl_->pc_reg.offset && r.size == impl_->pc_reg.size && !impl_->pc_reg.name.empty())
    impl_->pc = impl_->get_reg(r).lo() & impl_->code_mask;
  if (impl_->tb_register && r.offset == impl_->tb_register->offset) impl_->thumb = buf[0] != 0;
  if (impl_->machine && impl_->machine->cpu) {
    try {
      impl_->machine->cpu->register_written(r);
    } catch (const Fault &f) {
      throw EmuError(f.detail);
    }
  }
}

std::uint64_t Emulator::read_register(std::string_view name) const { return impl_->get_reg(impl_->reg(name)).lo(); }

void Emulator::write_register(std::string_view name, std::uint64_t value) {
  std::uint8_t b[8];
  for (int i = 0; i < 8; ++i) b[i] = static_cast<std::uint8_t>(value >> (8 * i));
  write_register_bytes(name, std::span<const std::uint8_t>(b, 8));
}

std::string Emulator::register_name(std::uint64_t offset, std::uint32_t size) const {
  if (auto it = impl_->register_by_storage.find({offset, size}); it != impl_->register_by_storage.end())
    return impl_->registers[it->second].name;
  return "register:" + hexs(offset) + ":" + std::to_string(size);
}

std::string Emulator::Impl::register_name(std::uint64_t offset, std::uint32_t size) const {
  return self->register_name(offset, size);
}

bool Emulator::read_memory(std::uint64_t address, std::span<std::uint8_t> out) const {
  if (!impl_->mapped(address, out.size())) return false;
  impl_->ram_read(address, out.data(), out.size());
  return true;
}

bool Emulator::write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) {
  if (!impl_->mapped(address, bytes.size())) return false;
  try {
    // A hook writing during an instruction (a stub's memcpy, read(2)): the
    // trace records it like the program's own writes.
    if (impl_->in_step && impl_->recording && impl_->options.trace_memory && !bytes.empty()) {
      std::vector<std::uint8_t> before(bytes.size());
      impl_->ram_read(address, before.data(), bytes.size());
      impl_->entry.writes.push_back({address, {}, std::vector<std::uint8_t>(bytes.begin(), bytes.end()), false, std::move(before)});
    }
    impl_->ram_write(address, bytes.data(), bytes.size());
  } catch (const Fault &f) {
    throw EmuError(f.detail);
  }
  return true;
}

std::optional<std::uint64_t> Emulator::read_word(std::uint64_t address, std::uint32_t size) const {
  std::uint8_t b[8] = {};
  if (size > 8 || !read_memory(address, std::span<std::uint8_t>(b, size))) return std::nullopt;
  return impl_->word(b, size);
}

bool Emulator::write_word(std::uint64_t address, std::uint32_t size, std::uint64_t value) {
  std::uint8_t b[8] = {};
  if (size > 8) return false;
  impl_->put_word(b, size, value);
  return write_memory(address, std::span<const std::uint8_t>(b, size));
}

std::string Emulator::read_cstring(std::uint64_t address, std::size_t max) const {
  std::string out;
  for (std::size_t i = 0; i < max; ++i) {
    std::uint8_t c = 0;
    if (!read_memory(address + i, std::span<std::uint8_t>(&c, 1)) || c == 0) break;
    out.push_back(static_cast<char>(c));
  }
  return out;
}

void Emulator::map(std::string name, std::uint64_t start, std::uint64_t size, loader::Perms perms, bool mmio) {
  RegionInfo info;
  info.name = std::move(name);
  info.start = start;
  info.size = size;
  info.perms = perms;
  info.kind = mmio ? RegionInfo::Kind::mmio : RegionInfo::Kind::ram;
  impl_->map_region(std::move(info));
}

void Emulator::unmap(std::uint64_t start, std::uint64_t size) {
  if (size == 0) return;
  const std::uint64_t last = start + (size - 1);
  Impl &m = *impl_;
  std::vector<detail::Region> keep;
  for (auto it = m.regions.begin(); it != m.regions.end();) {
    const detail::Region &r = it->second;
    if (r.last() < start || r.info.start > last) {
      ++it;
      continue;
    }
    if (r.info.start < start) {
      detail::Region left = r;
      left.info.size = start - r.info.start;
      keep.push_back(left);
    }
    if (r.last() > last) {
      detail::Region right = r;
      right.info.start = last + 1;
      right.info.size = r.last() - last;
      keep.push_back(right);
    }
    it = m.regions.erase(it);
  }
  for (detail::Region &r : keep) m.regions.emplace(r.info.start, std::move(r));
  for (std::uint64_t page = (start + kPageSize - 1) / kPageSize; page < (last + 1) / kPageSize && page * kPageSize >= start;
       ++page) {
    if (m.ram.find(page) != nullptr) {
      m.ram.erase(page);
      m.used -= std::min<std::uint64_t>(m.used, kPageSize);
    }
  }
}

std::vector<RegionInfo> Emulator::regions() const {
  std::vector<RegionInfo> out;
  for (const auto &[start, r] : impl_->regions) out.push_back(r.info);
  return out;
}

std::optional<std::uint64_t> Emulator::find_free(std::uint64_t size, std::uint64_t hint, std::uint64_t align) const {
  const Impl &m = *impl_;
  if (size == 0) return std::nullopt;
  std::uint64_t at = align_up(hint & m.code_mask, align);
  if (at < hint) return std::nullopt;
  for (int guard = 0; guard < 100000; ++guard) {
    const std::uint64_t last = at + (size - 1);
    if (last < at || last > m.code_mask) return std::nullopt;
    // The first region ending at or after `at`.
    auto it = m.regions.upper_bound(at);
    const detail::Region *conflict = nullptr;
    if (it != m.regions.begin()) {
      auto prev = std::prev(it);
      if (prev->second.last() >= at) conflict = &prev->second;
    }
    if (conflict == nullptr && it != m.regions.end() && it->second.info.start <= last) conflict = &it->second;
    if (conflict == nullptr) return at;
    const std::uint64_t next = conflict->last() + 1;
    if (next == 0) return std::nullopt;
    at = align_up(next, align);
    if (at < next) return std::nullopt;
  }
  return std::nullopt;
}

std::uint64_t Emulator::memory_used() const { return impl_->used; }

Stop Emulator::step() {
  RunOptions o;
  o.max_steps = 1;
  Stop s = impl_->run_loop(o, nullptr, true);
  if (s.kind == StopKind::step_limit) {
    s.kind = StopKind::stepped;
    s.detail.clear();
  }
  impl_->last_stop = s;
  return s;
}

Stop Emulator::step_over(const RunOptions &options) {
  Impl &m = *impl_;
  std::shared_ptr<const detail::Decoded> d;
  if (m.stubs.count(m.pc) == 0 && !(m.return_trap && m.pc == *m.return_trap)) {
    try {
      d = m.decode(m.pc);
    } catch (const Fault &) {
      return step();  // step reports the fault
    }
  }
  if (!d || !d->has_call) return step();
  const std::uint64_t ret = (m.pc + d->fall) & m.code_mask;
  const std::uint64_t sp0 = m.sp_reg.name.empty() ? 0 : m.get_reg(m.sp_reg).lo();
  auto done = [&m, ret, sp0] { return m.pc == ret && (m.sp_reg.name.empty() || m.get_reg(m.sp_reg).lo() >= sp0); };
  return m.run_loop(options, done, true);
}

Stop Emulator::step_out(const RunOptions &options) {
  Impl &m = *impl_;
  const int depth = m.call_depth;
  auto done = [&m, depth] { return m.call_depth < depth; };
  return m.run_loop(options, done, true);
}

Stop Emulator::run(const RunOptions &options) { return impl_->run_loop(options, nullptr, true); }

const Stop &Emulator::last_stop() const { return impl_->last_stop; }
std::uint64_t Emulator::steps() const { return impl_->steps; }

void Emulator::add_breakpoint(std::uint64_t address) { impl_->breakpoints.insert(address & impl_->code_mask); }
bool Emulator::remove_breakpoint(std::uint64_t address) { return impl_->breakpoints.erase(address & impl_->code_mask) != 0; }
void Emulator::clear_breakpoints() { impl_->breakpoints.clear(); }
const std::set<std::uint64_t> &Emulator::breakpoints() const { return impl_->breakpoints; }

int Emulator::add_watchpoint(std::uint64_t start, std::uint64_t size, bool on_read, bool on_write) {
  if (size == 0) throw EmuError("empty watchpoint");
  const int id = impl_->next_watch++;
  impl_->watches.push_back({id, start, start + (size - 1), on_read, on_write});
  return id;
}

bool Emulator::remove_watchpoint(int id) {
  auto &w = impl_->watches;
  auto it = std::find_if(w.begin(), w.end(), [&](const detail::Watch &x) { return x.id == id; });
  if (it == w.end()) return false;
  w.erase(it);
  return true;
}

void Emulator::on_userop(std::string name, UseropHandler handler) { impl_->userop_handlers[std::move(name)] = std::move(handler); }
void Emulator::on_syscall(SyscallHandler handler) { impl_->syscall_handler = std::move(handler); }
void Emulator::on_mmio(MmioHandler handler) { impl_->mmio_handler = std::move(handler); }
Emulator::SyscallHandler Emulator::syscall_hook() const { return impl_->syscall_handler; }
Emulator::MmioHandler Emulator::mmio_hook() const { return impl_->mmio_handler; }
bool Emulator::remove_userop(const std::string &name) { return impl_->userop_handlers.erase(name) != 0; }

bool Emulator::mark_mmio(std::uint64_t start, std::uint64_t size) {
  bool any = false;
  const std::uint64_t last = start + (size == 0 ? 0 : size - 1);
  for (auto &[at, r] : impl_->regions)
    if (r.info.start <= last && r.last() >= start) {
      r.info.kind = RegionInfo::Kind::mmio;
      any = true;
    }
  return any;
}

void Emulator::return_from_call(std::uint64_t value) {
  Impl &m = *impl_;
  try {
    m.set_return_value(value);
    m.return_from_call(0);
  } catch (const Fault &f) {
    m.undo.clear();
    throw EmuError(f.detail);
  }
  m.undo.clear();
  if (!m.pc_reg.name.empty()) m.set_reg(m.pc_reg, detail::Wide::of(m.pc_reg.size, m.pc));
}

void Emulator::stub(std::uint64_t address, std::string name, StubHandler handler) {
  impl_->stubs[address & impl_->code_mask] = detail::StubEntry{std::move(name), std::move(handler), false};
}

void Emulator::stub_import(std::string_view name, StubHandler handler) {
  auto it = impl_->import_stubs.find(std::string(name));
  if (it == impl_->import_stubs.end()) throw EmuError("no import " + std::string(name));
  impl_->stubs[it->second].handler = std::move(handler);
}

std::uint64_t Emulator::arg(unsigned index) const { return impl_->call_arg(index); }

std::string Emulator::disassemble(std::uint64_t address, bool pcode) {
  Impl &m = *impl_;
  std::shared_ptr<const detail::Decoded> d;
  try {
    d = m.decode(address & m.code_mask);
  } catch (const Fault &) {
    return {};
  }
  std::ostringstream o;
  o << d->text;
  if (!pcode) return o.str();
  auto vn = [&](const detail::Vn &v) {
    std::ostringstream s;
    const detail::Space &sp = m.spaces[static_cast<std::size_t>(v.space)];
    if (sp.kind == SpaceKind::constant) s << hexs(v.offset);
    else if (sp.kind == SpaceKind::registers) s << register_name(v.offset, v.size);
    else s << sp.name << ":" << hexs(v.offset);
    s << ":" << v.size;
    return s.str();
  };
  for (const detail::Op &op : d->ops) {
    o << "\n    ";
    if (op.has_out) o << vn(op.out) << " = ";
    o << ghidra_opname(op.opcode);
    for (std::size_t i = 0; i < op.in.size(); ++i) o << (i ? ", " : " ") << vn(op.in[i]);
  }
  return o.str();
}

const std::string &Emulator::stdout_data() const { return impl_->out; }
const std::string &Emulator::stderr_data() const { return impl_->err; }
std::uint64_t Checkpoint::steps() const { return state_ ? state_->steps : 0; }
std::uint64_t Checkpoint::pc() const { return state_ ? state_->pc : 0; }

Checkpoint Emulator::checkpoint() const {
  const Impl &m = *impl_;
  if (m.machine) throw std::logic_error("a machine's peripherals can't be checkpointed");
  auto c = std::make_shared<CheckpointState>();
  c->owner = &m;
  c->pc = m.pc;
  c->regs = m.regs;
  c->ram = m.ram;
  c->other = m.other;
  c->regions = m.regions;
  c->used = m.used;
  c->steps = m.steps;
  c->last_stop = m.last_stop;
  c->brk_start = m.brk_start;
  c->brk = m.brk;
  c->mmap_hint = m.mmap_hint;
  c->stdin_pos = m.stdin_pos;
  c->heap_next = m.heap_next;
  c->heap_end = m.heap_end;
  c->out_size = m.out.size();
  c->err_size = m.err.size();
  c->thumb = m.thumb;
  c->itstate = m.itstate;
  c->call_depth = m.call_depth;
  c->pending_exit = m.pending_exit;
  c->cpuid_block = m.cpuid_block;
  Checkpoint out;
  out.state_ = std::move(c);
  return out;
}

void Emulator::restore(const Checkpoint &checkpoint) {
  Impl &m = *impl_;
  const CheckpointState *c = checkpoint.state_.get();
  if (c == nullptr || c->owner != &m) throw std::logic_error("not a checkpoint of this emulator");
  m.pc = c->pc;
  m.regs = c->regs;
  m.ram = c->ram;
  m.other = c->other;
  m.regions = c->regions;
  m.used = c->used;
  m.steps = c->steps;
  m.last_stop = c->last_stop;
  m.brk_start = c->brk_start;
  m.brk = c->brk;
  m.mmap_hint = c->mmap_hint;
  m.stdin_pos = c->stdin_pos;
  m.heap_next = c->heap_next;
  m.heap_end = c->heap_end;
  if (m.out.size() > c->out_size) m.out.resize(c->out_size);
  if (m.err.size() > c->err_size) m.err.resize(c->err_size);
  m.thumb = c->thumb;
  m.itstate = c->itstate;
  m.call_depth = c->call_depth;
  m.pending_exit = c->pending_exit;
  m.cpuid_block = c->cpuid_block;
  m.unique.clear();
  m.undo.clear();
  // Code may differ from what was decoded.
  m.decoded.clear();
  m.decoded_thumb.clear();
  m.code_pages.clear();
  m.trace.truncate(c->steps);
}

Trace &Emulator::trace() { return impl_->trace; }
const Trace &Emulator::trace() const { return impl_->trace; }
const std::deque<MmioAccess> &Emulator::mmio_log() const { return impl_->mmio_log; }

}  // namespace revkit::emu
