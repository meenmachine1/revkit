// The p-code interpreter: decodes an instruction with SLEIGH (cached), runs
// its p-code ops on Wide values, and undoes the instruction's writes when
// it faults, so a stopped machine is always between instructions.
#include "impl.hh"
#include "machine_impl.hh"

#include "opcodes.hh"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace revkit::emu {

using detail::Fault;
using detail::kPageSize;
using detail::Op;
using detail::SpaceKind;
using detail::Vn;
using detail::Wide;

namespace {

constexpr std::uint32_t kFetchWindow = 32;

std::string hexs(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

std::int64_t sign_extend(std::uint64_t v, std::uint32_t size) {
  if (size >= 8) return static_cast<std::int64_t>(v);
  const unsigned shift = 64 - 8 * size;
  return static_cast<std::int64_t>(v << shift) >> shift;
}

// CALLOTHERs with no effect the emulator models: barriers, hints, cache
// maintenance. Anything else needs a handler.
bool harmless_userop(const std::string &name) {
  static const char *const kNames[] = {
      "DataMemoryBarrier", "DataSynchronizationBarrier", "InstructionSynchronizationBarrier", "HintDebug",
      "HintPreloadData", "HintPreloadDataForWrite", "HintPreloadInstruction", "HintYield", "SendEvent",
      "ClearExclusiveLocal", "setISAMode", "fence", "fence_i", "fence.i", "LOCK", "UNLOCK", "lfence", "mfence",
      "sfence", "clflush", "clflushopt", "prefetch", "prefetchw", "prefetchnta", "prefetcht0", "prefetcht1",
      "prefetcht2", "pause", "DataMemoryBarrier_ISH", "SpeculationBarrier", "ConsumptionOfSpeculativeDataBarrier",
      "PhysicalSpeculativeStoreBypassBarrier", "SpeculativeStoreBypassBarrier", "CSDB", "Hint_Prefetch",
      "Hint_Yield", "DC_CIVAC", "DC_CVAC", "DC_CVAU", "DC_IVAC", "DC_ZVA", "IC_IALLU", "IC_IALLUIS", "IC_IVAU",
      "SYNC", "sync", "isync", "eieio", "lwsync", "dcbf", "dcbst", "icbi", "dcbt", "dcbtst", "endbr64", "endbr32"};
  for (const char *n : kNames)
    if (name == n) return true;
  return false;
}

}  // namespace

Stop Emulator::Impl::make_stop(StopKind kind, std::string detail) {
  Stop s;
  s.kind = kind;
  s.pc = pc;
  s.detail = std::move(detail);
  return s;
}

std::shared_ptr<const detail::Decoded> Emulator::Impl::decode(std::uint64_t address) {
  auto &cache = thumb ? decoded_thumb : decoded;
  if (auto it = cache.find(address); it != cache.end()) return it->second;

  const detail::Region *r = region_at(address);
  if (r == nullptr) throw Fault{StopKind::unmapped, address, "fetch from unmapped memory at " + hexs(address), true};
  if (options.enforce_permissions && !raw && !r->info.perms.exec)
    throw Fault{StopKind::protection, address, "fetch from non-executable memory at " + hexs(address), true};
  // The bytes from pc to the end of the mapped run, at most a window.
  std::uint32_t n = 0;
  while (n < kFetchWindow) {
    const detail::Region *at = region_at(address + n);
    if (at == nullptr) break;
    n += static_cast<std::uint32_t>(std::min<std::uint64_t>(kFetchWindow - n, at->last() - (address + n) + 1));
  }
  std::vector<std::uint8_t> window(n);
  ram_read(address, window.data(), n);

  lift::Lifter &engine = thumb ? *thumb_lifter : *lifter;
  std::optional<lift::Instruction> insn;
  insn = engine.lift(address, std::span<const std::byte>(reinterpret_cast<const std::byte *>(window.data()), n));
  if (!insn) throw Fault{StopKind::decode, address, "no instruction decodes at " + hexs(address), true};

  auto d = std::make_shared<detail::Decoded>();
  d->address = address;
  d->thumb = thumb;
  d->length = insn->length;
  d->fall = insn->length + insn->delay_slot;
  d->bytes.assign(window.begin(), window.begin() + std::min<std::uint32_t>(n, d->length));
  d->text = insn->text;
  d->unimplemented = insn->unimplemented;
  for (const lift::PcodeOp &p : insn->pcode) {
    Op op;
    op.opcode = static_cast<int>(ghidra::get_opcode(p.opcode));
    auto convert = [&](const lift::Varnode &v) {
      Vn vn;
      const std::string &name = v.space == "space" ? v.referenced_space : v.space;
      auto it = space_index.find(name);
      if (it == space_index.end()) throw Fault{StopKind::unimplemented, address, "unknown space " + name, true};
      vn.space = it->second;
      vn.size = v.size;
      vn.offset = v.offset;
      return vn;
    };
    if (p.output) {
      op.has_out = true;
      op.out = convert(*p.output);
    }
    for (const lift::Varnode &v : p.inputs) op.in.push_back(convert(v));
    if (op.opcode == ghidra::CPUI_CALL || op.opcode == ghidra::CPUI_CALLIND) d->has_call = true;
    if (op.opcode == ghidra::CPUI_RETURN) d->has_return = true;
    if (nzcv) {
      auto touches = [&](const Vn &v) {
        return v.space == register_space && v.offset < nzcv->offset + nzcv->size && nzcv->offset < v.offset + v.size;
      };
      for (const Vn &v : op.in) d->reads_nzcv = d->reads_nzcv || touches(v);
      if (op.has_out && touches(op.out)) d->writes_nzcv = true;
    }
    d->ops.push_back(std::move(op));
  }
  if (thumb && d->length == 2 && d->bytes.size() >= 2) {
    // Thumb-2 IT blocks: the spec sets the block's conditions with context
    // (globalset) the emulator's decoder doesn't carry, so ITSTATE is
    // tracked here and the condition checked before each instruction.
    const std::uint16_t hw = big_endian ? static_cast<std::uint16_t>(d->bytes[0] << 8 | d->bytes[1])
                                        : static_cast<std::uint16_t>(d->bytes[1] << 8 | d->bytes[0]);
    if ((hw & 0xff00) == 0xbf00 && (hw & 0xf) != 0 && d->text.rfind("it", 0) == 0) {
      d->it = true;
      d->it_state = static_cast<std::uint8_t>(hw & 0xff);
    }
    // 16-bit data processing that sets the flags outside an IT block only.
    if ((hw >> 13) == 0 && (hw >> 11) != 3) d->it_flags16 = true;               // shifts by immediate
    else if ((hw >> 11) == 3) d->it_flags16 = true;                             // ADD/SUB register, imm3
    else if ((hw >> 13) == 1 && ((hw >> 11) & 3) != 1) d->it_flags16 = true;    // MOV/ADD/SUB imm8 (not CMP)
    else if ((hw >> 10) == 0x10) {                                              // ALU register forms
      const unsigned op = (hw >> 6) & 0xf;
      d->it_flags16 = op != 8 && op != 0xa && op != 0xb;                        // not TST, CMP, CMN
    }
  }
  if (machine && machine->cpu) machine->cpu->classify(*d);
  for (std::uint64_t page = address / kPageSize; page <= (address + std::max<std::uint32_t>(d->fall, 1) - 1) / kPageSize;
       ++page)
    ++code_pages[page];
  cache.emplace(address, d);
  return d;
}

// --- Memory as the program sees it ---

void Emulator::Impl::mem_read(std::uint64_t addr, std::uint8_t *out, std::uint32_t size) {
  addr &= code_mask;
  const detail::Region *r = region_at(addr);
  if (r == nullptr || !mapped(addr, size))
    throw Fault{StopKind::unmapped, addr,
                "read of " + std::to_string(size) + " bytes at " + hexs(addr) + " (unmapped)", true};
  if (options.enforce_permissions && !raw && !r->info.perms.read)
    throw Fault{StopKind::protection, addr, "read of unreadable memory at " + hexs(addr), true};
  ram_read(addr, out, size);
  const bool mmio = r->info.kind == RegionInfo::Kind::mmio;
  if (mmio) {
    MmioAccess a;
    a.pc = pc;
    a.address = addr;
    a.size = size;
    a.write = false;
    a.value = word(out, std::min<std::uint32_t>(size, 8));
    a.step = steps;
    bool answered = false;
    if (machine) {
      std::uint64_t v = 0;
      if (machine->mmio_read(addr, size, v)) {
        a.value = v;
        answered = true;
      }
    }
    if (mmio_handler) mmio_handler(*self, a);
    if (a.stop) throw Fault{StopKind::hook, addr, a.note.empty() ? "a hook stopped at a read of " + hexs(addr) : a.note, true};
    if (answered || mmio_handler) put_word(out, std::min<std::uint32_t>(size, 8), a.value);
    mmio_read_this_step = true;
    trace.count_mmio(false);
    if (options.mmio_log_capacity > 0) {
      mmio_log.push_back(a);
      while (mmio_log.size() > options.mmio_log_capacity) mmio_log.pop_front();
    }
  }
  for (const detail::Watch &w : watches)
    if (w.read && addr <= w.last && addr + size - 1 >= w.start) watch_hit = std::max(addr, w.start);
  ++step_reads;
  if (recording && options.trace_memory) entry.reads.push_back({addr, {}, std::vector<std::uint8_t>(out, out + size), mmio, {}});
}

void Emulator::Impl::mem_write(std::uint64_t addr, const std::uint8_t *in, std::uint32_t size) {
  addr &= code_mask;
  const detail::Region *r = region_at(addr);
  if (r == nullptr || !mapped(addr, size))
    throw Fault{StopKind::unmapped, addr,
                "write of " + std::to_string(size) + " bytes at " + hexs(addr) + " (unmapped)", true};
  if (options.enforce_permissions && !raw && !r->info.perms.write)
    throw Fault{StopKind::protection, addr, "write to read-only memory at " + hexs(addr), true};
  detail::UndoEntry u{ram_space, addr, std::vector<std::uint8_t>(size)};
  ram_read(addr, u.old.data(), size);
  std::vector<std::uint8_t> before;
  if (recording && options.trace_memory) before = u.old;
  undo.push_back(std::move(u));
  ram_write(addr, in, size);
  const bool mmio = r->info.kind == RegionInfo::Kind::mmio;
  if (mmio) {
    MmioAccess a;
    a.pc = pc;
    a.address = addr;
    a.size = size;
    a.write = true;
    a.value = word(in, std::min<std::uint32_t>(size, 8));
    a.step = steps;
    if (mmio_handler) {
      mmio_handler(*self, a);
      if (a.stop) throw Fault{StopKind::hook, addr, a.note.empty() ? "a hook stopped at a write of " + hexs(addr) : a.note, true};
    }
    if (machine) machine->mmio_write(addr, size, a.value);
    trace.count_mmio(true);
    if (options.mmio_log_capacity > 0) {
      mmio_log.push_back(a);
      while (mmio_log.size() > options.mmio_log_capacity) mmio_log.pop_front();
    }
  }
  for (const detail::Watch &w : watches)
    if (w.write && addr <= w.last && addr + size - 1 >= w.start) watch_hit = std::max(addr, w.start);
  ++step_writes;
  if (recording && options.trace_memory)
    entry.writes.push_back({addr, {}, std::vector<std::uint8_t>(in, in + size), mmio, std::move(before)});
}

Wide Emulator::Impl::load(std::int32_t space, std::uint64_t offset, std::uint32_t size) {
  if (size > detail::kMaxValueBytes)
    throw Fault{StopKind::unimplemented, pc, "a value of " + std::to_string(size) + " bytes", false};
  const detail::Space &sp = spaces[static_cast<std::size_t>(space)];
  std::uint8_t buf[detail::kMaxValueBytes] = {};
  switch (sp.kind) {
    case SpaceKind::constant: return Wide::of(size, offset);
    case SpaceKind::registers: {
      for (std::uint32_t i = 0; i < size; ++i) buf[i] = offset + i < regs.size() ? regs[offset + i] : 0;
      break;
    }
    case SpaceKind::ram: mem_read(offset, buf, size); break;
    case SpaceKind::unique:
    case SpaceKind::other_memory: {
      detail::PageStore &store = sp.kind == SpaceKind::unique ? unique : other[space];
      for (std::uint32_t i = 0; i < size; ++i) {
        const std::uint64_t at = (offset + i) & sp.mask;
        const detail::Page *page = store.find(at / kPageSize);
        buf[i] = page != nullptr ? page->bytes[at % kPageSize] : 0;
      }
      if (sp.kind == SpaceKind::other_memory) {
        ++step_reads;
        if (recording && options.trace_memory)
          entry.reads.push_back({offset, sp.name, std::vector<std::uint8_t>(buf, buf + size), false, {}});
      }
      break;
    }
    case SpaceKind::pseudo:
      throw Fault{StopKind::unimplemented, pc, "read of space " + sp.name, false};
  }
  if (big_endian) std::reverse(buf, buf + size);
  return Wide::from_le(size, buf);
}

void Emulator::Impl::store(std::int32_t space, std::uint64_t offset, const Wide &v) {
  const std::uint32_t size = v.size;
  if (size > detail::kMaxValueBytes)
    throw Fault{StopKind::unimplemented, pc, "a value of " + std::to_string(size) + " bytes", false};
  const detail::Space &sp = spaces[static_cast<std::size_t>(space)];
  std::uint8_t buf[detail::kMaxValueBytes] = {};
  v.to_le(buf);
  if (big_endian) std::reverse(buf, buf + size);
  switch (sp.kind) {
    case SpaceKind::constant:
    case SpaceKind::pseudo: throw Fault{StopKind::unimplemented, pc, "write to space " + sp.name, false};
    case SpaceKind::registers: {
      if (offset + size > regs.size()) {
        charge(offset + size - regs.size());
        regs.resize(offset + size, 0);
      }
      undo.push_back({space, offset, std::vector<std::uint8_t>(regs.begin() + static_cast<std::ptrdiff_t>(offset),
                                                               regs.begin() + static_cast<std::ptrdiff_t>(offset + size))});
      std::memcpy(regs.data() + offset, buf, size);
      return;
    }
    case SpaceKind::ram: mem_write(offset, buf, size); return;
    case SpaceKind::unique:
    case SpaceKind::other_memory: {
      detail::PageStore &store = sp.kind == SpaceKind::unique ? unique : other[space];
      if (sp.kind == SpaceKind::other_memory) {
        detail::UndoEntry u{space, offset, std::vector<std::uint8_t>(size)};
        for (std::uint32_t i = 0; i < size; ++i) {
          const std::uint64_t at = (offset + i) & sp.mask;
          const detail::Page *page = store.find(at / kPageSize);
          u.old[i] = page != nullptr ? page->bytes[at % kPageSize] : 0;
        }
        ++step_writes;
        if (recording && options.trace_memory)
          entry.writes.push_back({offset, sp.name, std::vector<std::uint8_t>(buf, buf + size), false, u.old});
        undo.push_back(std::move(u));
      }
      for (std::uint32_t i = 0; i < size; ++i) {
        const std::uint64_t at = (offset + i) & sp.mask;
        bool created = false;
        if (store.find(at / kPageSize) == nullptr) charge(kPageSize);
        detail::Page *page = store.writable(at / kPageSize, [](detail::Page &) {}, created);
        page->bytes[at % kPageSize] = buf[i];
      }
      return;
    }
  }
}

Wide Emulator::Impl::read_vn(const Vn &vn) { return load(vn.space, vn.offset, vn.size); }

void Emulator::Impl::write_vn(const Vn &vn, const Wide &v) { store(vn.space, vn.offset, v.resized(vn.size)); }

void Emulator::Impl::undo_all() {
  for (auto it = undo.rbegin(); it != undo.rend(); ++it) {
    const detail::Space &sp = spaces[static_cast<std::size_t>(it->space)];
    if (sp.kind == SpaceKind::registers) {
      std::memcpy(regs.data() + it->offset, it->old.data(), it->old.size());
    } else if (sp.kind == SpaceKind::ram) {
      ram_write(it->offset, it->old.data(), it->old.size());
    } else if (sp.kind == SpaceKind::other_memory) {
      detail::PageStore &store = other[it->space];
      for (std::size_t i = 0; i < it->old.size(); ++i) {
        const std::uint64_t at = (it->offset + i) & sp.mask;
        bool created = false;
        store.writable(at / kPageSize, [](detail::Page &) {}, created)->bytes[at % kPageSize] = it->old[i];
      }
    }
  }
  undo.clear();
}

// --- User ops and system calls ---

void Emulator::Impl::exec_userop(const Op &op) {
  const std::uint64_t index = op.in.empty() ? 0 : op.in[0].offset;
  const std::string name = index < userops.size() ? userops[index] : "userop_" + std::to_string(index);
  UseropCall call;
  call.name = name;
  call.index = static_cast<std::uint32_t>(index);
  for (std::size_t i = 1; i < op.in.size(); ++i) call.inputs.push_back(read_vn(op.in[i]).lo());
  call.output_size = op.has_out ? op.out.size : 0;

  if (auto it = userop_handlers.find(name); it != userop_handlers.end()) {
    trace.count_userop();
    if (it->second(*self, call) == HookAction::stop)
      throw Fault{StopKind::hook, pc, call.note.empty() ? "a hook stopped at " + name : call.note, false};
    if (call.output && op.has_out) write_vn(op.out, Wide::of(op.out.size, *call.output));
    if (!call.note.empty()) step_event = call.note;
    return;
  }

  if (machine && machine->cpu && machine->cpu->userop(name, call, op)) {
    if (call.output && op.has_out) write_vn(op.out, Wide::of(op.out.size, *call.output));
    if (!call.note.empty()) step_event = call.note;
    return;
  }

  if (syscall_abi && name == syscall_abi->userop &&
      (!syscall_abi->userop_arg || (!call.inputs.empty() && call.inputs[0] == *syscall_abi->userop_arg))) {
    trace.count_syscall();
    if (!syscall_handler)
      throw Fault{StopKind::syscall, pc, "system call " + std::to_string(get_reg_u64(syscall_abi->number)) + " with no handler",
                  false};
    Syscall sc;
    sc.number = get_reg_u64(syscall_abi->number);
    for (std::size_t i = 0; i < syscall_abi->args.size() && i < sc.args.size(); ++i)
      sc.args[i] = get_reg_u64(syscall_abi->args[i]);
    if (syscall_handler(*self, sc) == HookAction::stop)
      throw Fault{StopKind::syscall, pc, sc.note.empty() ? "system call " + std::to_string(sc.number) + " not handled" : sc.note,
                  false};
    if (sc.exited) {
      pending_exit = sc.exit_code;
    } else {
      const RegisterInfo &r = reg(syscall_abi->result);
      // Through store() so the trace and the undo log see it.
      store(register_space, r.offset, Wide::of(r.size, sc.result));
    }
    step_event = sc.note;
    return;
  }

  if (harmless_userop(name)) return;
  if (builtin_userop(name, call, op)) return;
  throw Fault{StopKind::userop, pc, "CALLOTHER " + name + " has no handler", false};
}

// Semantics the specs leave to the emulator: x86 CPUID (a baseline
// x86-64: SSE2, no AVX, so libraries pick their generic routines) and
// RDTSC (the step count), AArch64 DC ZVA (zeroes a 64-byte block, as
// DCZID_EL0 says), and exclusive monitors (one thread: always pass).
bool Emulator::Impl::builtin_userop(const std::string &name, const UseropCall &call, const Op &op) {
  if (name.rfind("cpuid", 0) == 0 && op.has_out) {
    const std::uint64_t leaf = call.inputs.empty() ? 0 : call.inputs[0] & 0xffffffffu;
    std::uint32_t r[4] = {0, 0, 0, 0};  // EAX EBX EDX ECX, the order the spec reads them
    auto str = [](const char *s) {
      std::uint32_t v = 0;
      for (int i = 0; i < 4 && s[i]; ++i) v |= std::uint32_t(static_cast<unsigned char>(s[i])) << (8 * i);
      return v;
    };
    static const char brand[49] = "revkit emulated x86-64                          ";
    switch (leaf) {
      case 0: r[0] = 0xd; r[1] = str("Genu"); r[2] = str("ineI"); r[3] = str("ntel"); break;
      case 1:
        r[0] = 0x000306c3;  // family 6
        r[1] = 0x00000800;  // CLFLUSH line size 64
        r[2] = 1u << 0 | 1u << 4 | 1u << 8 | 1u << 15 | 1u << 19 | 1u << 23 | 1u << 24 | 1u << 25 | 1u << 26;
        break;
      case 0x80000000: r[0] = 0x80000004; break;
      case 0x80000001: r[2] = 1u << 11 | 1u << 20 | 1u << 29; r[3] = 1; break;
      case 0x80000002:
      case 0x80000003:
      case 0x80000004:
        for (int i = 0; i < 4; ++i) {
          const int at = static_cast<int>((leaf - 0x80000002) * 16) + 4 * i;
          r[i == 2 ? 3 : i == 3 ? 2 : i] = str(brand + at);
        }
        break;
      default: break;
    }
    if (!cpuid_block) {
      auto at = self->find_free(0x1000, pointer_size >= 8 ? 0x7f8000000000ull : 0x3f000000ull);
      if (!at) at = self->find_free(0x1000, 0x10000);
      if (!at) return false;
      RegionInfo info;
      info.name = "cpuid";
      info.start = *at;
      info.size = 0x1000;
      info.perms = {true, false, false};
      info.kind = RegionInfo::Kind::ram;
      map_region(info);
      cpuid_block = *at;
    }
    std::uint8_t bytes[16];
    for (int i = 0; i < 4; ++i) put_word(bytes + 4 * i, 4, r[i]);
    ram_write(*cpuid_block, bytes, 16);
    write_vn(op.out, Wide::of(op.out.size, *cpuid_block));
    return true;
  }
  if ((name == "rdtsc" || name == "rdtscp") && op.has_out) {
    write_vn(op.out, Wide::of(op.out.size, steps * 4));
    return true;
  }
  // EXT: bytes from imm on of Vm:Vn (Ghidra's spec leaves it a CALLOTHER).
  if (name == "NEON_ext" && op.has_out && op.in.size() >= 4 && op.in[1].size == op.in[2].size &&
      2 * op.in[1].size <= detail::kMaxValueBytes) {
    const std::uint32_t n = op.in[1].size;
    const Wide lo = read_vn(op.in[1]).resized(2 * n), hi = read_vn(op.in[2]).resized(2 * n);
    Wide both = detail::shl(hi, 8ull * n);
    for (std::uint32_t k = 0; k < both.limbs(); ++k) both.w[k] |= lo.w[k];
    write_vn(op.out, detail::lshr(both, 8 * read_vn(op.in[3]).lo()).resized(op.out.size));
    return true;
  }
  // Pairwise and across-vector integer ops that Ghidra's AArch64 spec leaves
  // as CALLOTHERs (glibc's string functions use them): lanes of `esize`
  // bytes, the last input.
  static const char *const kPairwise[] = {"NEON_addp", "NEON_umaxp", "NEON_uminp", "NEON_smaxp", "NEON_sminp"};
  static const char *const kAcross[] = {"NEON_addv", "NEON_umaxv", "NEON_uminv", "NEON_smaxv", "NEON_sminv"};
  auto lane_op = [](const std::string &n, std::uint64_t a, std::uint64_t b, std::uint32_t esize) -> std::uint64_t {
    const unsigned bits = 8 * esize;
    const std::uint64_t mask = bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << bits) - 1;
    auto sx = [&](std::uint64_t v) { return bits >= 64 ? static_cast<std::int64_t>(v) : static_cast<std::int64_t>(v << (64 - bits)) >> (64 - bits); };
    const std::string kind = n.substr(5, n.size() - 6);  // "add", "umax", ...
    if (kind == "add") return (a + b) & mask;
    if (kind == "umax") return std::max(a, b);
    if (kind == "umin") return std::min(a, b);
    if (kind == "smax") return sx(a) >= sx(b) ? a : b;
    return sx(a) <= sx(b) ? a : b;
  };
  auto lanes = [](const Wide &v, std::uint32_t esize) {
    std::vector<std::uint64_t> out;
    for (std::uint32_t i = 0; i + esize <= v.size; i += esize) out.push_back(detail::lshr(v, 8ull * i).resized(esize).lo());
    return out;
  };
  for (const char *n : kPairwise) {
    if (name != n || !op.has_out || op.in.size() < 4) continue;
    const std::uint32_t esize = static_cast<std::uint32_t>(read_vn(op.in.back()).lo());
    if (esize == 0 || esize > 8) return false;
    std::vector<std::uint64_t> cat = lanes(read_vn(op.in[1]), esize), m = lanes(read_vn(op.in[2]), esize);
    cat.insert(cat.end(), m.begin(), m.end());
    Wide r = Wide::of(op.out.size, 0);
    for (std::uint32_t i = 0; 2 * i + 1 < cat.size() && (i + 1) * esize <= op.out.size; ++i) {
      Wide lane = Wide::of(op.out.size, lane_op(name, cat[2 * i], cat[2 * i + 1], esize));
      lane = detail::shl(lane, 8ull * i * esize);
      for (std::uint32_t k = 0; k < r.limbs(); ++k) r.w[k] |= lane.w[k];
    }
    write_vn(op.out, r);
    return true;
  }
  for (const char *n : kAcross) {
    if (name != n || !op.has_out || op.in.size() < 3) continue;
    const std::uint32_t esize = static_cast<std::uint32_t>(read_vn(op.in.back()).lo());
    if (esize == 0 || esize > 8) return false;
    const auto v = lanes(read_vn(op.in[1]), esize);
    if (v.empty()) return false;
    std::uint64_t acc = v[0];
    for (std::size_t i = 1; i < v.size(); ++i) acc = lane_op(std::string(name).replace(name.size() - 1, 1, "p"), acc, v[i], esize);
    write_vn(op.out, Wide::of(op.out.size, acc));
    return true;
  }
  // MIPS MTC0 and friends: setCopReg(cop, register, value) writes the
  // coprocessor register the spec passes by varnode.
  if ((name == "setCopReg" || name == "setCopRegH") && op.in.size() >= 4 &&
      spaces[static_cast<std::size_t>(op.in[2].space)].kind == SpaceKind::registers) {
    write_vn(op.in[2], read_vn(op.in[3]).resized(op.in[2].size));
    return true;
  }
  // One thread: exclusive stores always succeed.
  if ((name == "ExclusiveMonitorPass" || name == "hasExclusiveAccess") && op.has_out) {
    write_vn(op.out, Wide::of(op.out.size, 1));
    return true;
  }
  if (name == "ExclusiveMonitorsStatus" && op.has_out) {
    write_vn(op.out, Wide::of(op.out.size, 0));
    return true;
  }
  if (name == "DC_ZVA" && !call.inputs.empty()) {
    std::uint8_t zero[64] = {};
    mem_write(call.inputs[0] & ~std::uint64_t{63}, zero, 64);
    return true;
  }
  return false;
}

// --- One instruction ---

std::optional<Stop> Emulator::Impl::exec_one() {
  struct InStep {
    bool &flag;
    explicit InStep(bool &f) : flag(f) { flag = true; }
    ~InStep() { flag = false; }
  } in_step_guard(in_step);
  const std::uint64_t at = pc;
  undo.clear();
  watch_hit.reset();
  mmio_read_this_step = false;
  step_event.clear();
  step_reads = step_writes = 0;
  pending_exit.reset();
  recording = trace.capacity() > 0;
  if (recording) {
    entry = TraceEntry{};
    entry.index = steps;
    entry.thumb = thumb;
  }
  entry.pc = at;  // the summary counts distinct pcs even when nothing is recorded

  if (return_trap && at == *return_trap) {
    Stop s = make_stop(StopKind::returned, "returned " + hexs(abi.int_returns.empty() ? 0 : get_reg_u64(abi.int_returns[0])));
    if (!abi.int_returns.empty()) s.exit_code = static_cast<std::int64_t>(get_reg_u64(abi.int_returns[0]));
    return s;
  }
  if (exit_trap && at == *exit_trap) {
    const std::uint64_t v = abi.int_returns.empty() ? 0 : get_reg_u64(abi.int_returns[0]);
    Stop s = make_stop(StopKind::exited, "main returned " + std::to_string(static_cast<std::int32_t>(v)));
    s.exit_code = static_cast<std::int32_t>(v);
    return s;
  }
  if (auto it = stubs.find(at); it != stubs.end()) return exec_stub(it->second);

  std::shared_ptr<const detail::Decoded> d;
  std::uint64_t next = 0;
  bool returned = false;
  detail::CpuModel *cpu = machine ? machine->cpu.get() : nullptr;
  // Thumb-2: inside an IT block, the instruction runs only if the block's
  // condition for it holds; ITSTATE advances either way.
  bool it_skip = false;
  const bool in_it = thumb && (itstate & 0xf) != 0;
  std::uint8_t it_next = itstate;
  if (in_it) {
    it_skip = !condition_holds(itstate >> 4);
    it_next = (itstate & 7) == 0 ? 0 : static_cast<std::uint8_t>((itstate & 0xe0) | ((itstate << 1) & 0x1f));
  }
  try {
    d = decode(at);
    if (d->unimplemented && !it_skip) throw Fault{StopKind::unimplemented, at, "no p-code semantics for " + d->text, false};
    if (d->it && !in_it) it_next = d->it_state;
    if (!pc_reg.name.empty()) set_reg(pc_reg, Wide::of(pc_reg.size, at));
    if (d->reads_nzcv) {
      const std::uint64_t v = get_reg_u64("NG") << 31 | get_reg_u64("ZR") << 30 | get_reg_u64("CY") << 29 |
                              get_reg_u64("OV") << 28;
      set_reg(*nzcv, Wide::of(nzcv->size, v));
    }
    const bool hook = cpu != nullptr && !it_skip && (d->sys != 0 || cpu->hooks_every_instruction());
    if (hook) cpu->before(*d);
    // A 16-bit ADDS-style encoding inside an IT block is ADD: the flags stay.
    std::optional<std::array<std::uint8_t, 4>> it_flags;
    if (in_it && !it_skip && d->it_flags16) {
      std::array<std::uint8_t, 4> f{};
      const char *names[] = {"NG", "ZR", "CY", "OV"};
      for (int k = 0; k < 4; ++k)
        if (auto r = find_reg(names[k])) f[static_cast<std::size_t>(k)] = static_cast<std::uint8_t>(get_reg(registers[*r]).lo());
      it_flags = f;
    }
    next = (at + d->fall) & code_mask;
    const std::size_t count = it_skip ? 0 : d->ops.size();
    std::size_t i = 0;
    while (i < count) {
      const Op &op = d->ops[i];
      switch (op.opcode) {
        case ghidra::CPUI_BRANCH:
        case ghidra::CPUI_CBRANCH:
        case ghidra::CPUI_CALL: {
          if (op.opcode == ghidra::CPUI_CBRANCH && read_vn(op.in[1]).zero()) {
            ++i;
            continue;
          }
          const Vn &t = op.in[0];
          if (spaces[static_cast<std::size_t>(t.space)].kind == SpaceKind::constant) {
            const std::int64_t rel = sign_extend(t.offset, t.size);
            const std::int64_t to = static_cast<std::int64_t>(i) + rel;
            i = to < 0 || static_cast<std::size_t>(to) >= count ? count : static_cast<std::size_t>(to);
            continue;
          }
          next = t.offset & code_mask;
          if (op.opcode == ghidra::CPUI_CALL) ++call_depth;
          i = count;
          continue;
        }
        case ghidra::CPUI_BRANCHIND:
        case ghidra::CPUI_CALLIND:
        case ghidra::CPUI_RETURN:
          next = read_vn(op.in[0]).lo() & code_mask;
          if (op.opcode == ghidra::CPUI_CALLIND) ++call_depth;
          if (op.opcode == ghidra::CPUI_RETURN) {
            --call_depth;
            returned = true;
          }
          i = count;
          continue;
        case ghidra::CPUI_CALLOTHER: exec_userop(op); break;
        case ghidra::CPUI_COPY: write_vn(op.out, read_vn(op.in[0])); break;
        case ghidra::CPUI_LOAD: {
          const std::uint64_t ptr = read_vn(op.in[1]).lo();
          const detail::Space &sp = spaces[static_cast<std::size_t>(op.in[0].space)];
          write_vn(op.out, load(op.in[0].space, (ptr * sp.wordsize) & sp.mask, op.out.size));
          break;
        }
        case ghidra::CPUI_STORE: {
          const std::uint64_t ptr = read_vn(op.in[1]).lo();
          const detail::Space &sp = spaces[static_cast<std::size_t>(op.in[0].space)];
          store(op.in[0].space, (ptr * sp.wordsize) & sp.mask, read_vn(op.in[2]));
          break;
        }
        case ghidra::CPUI_INT_EQUAL:
        case ghidra::CPUI_INT_NOTEQUAL:
        case ghidra::CPUI_INT_LESS:
        case ghidra::CPUI_INT_LESSEQUAL:
        case ghidra::CPUI_INT_SLESS:
        case ghidra::CPUI_INT_SLESSEQUAL: {
          const Wide a = read_vn(op.in[0]), b = read_vn(op.in[1]).resized(op.in[0].size);
          bool r = false;
          switch (op.opcode) {
            case ghidra::CPUI_INT_EQUAL: r = a == b; break;
            case ghidra::CPUI_INT_NOTEQUAL: r = !(a == b); break;
            case ghidra::CPUI_INT_LESS: r = detail::ult(a, b); break;
            case ghidra::CPUI_INT_LESSEQUAL: r = !detail::ult(b, a); break;
            case ghidra::CPUI_INT_SLESS: r = detail::slt(a, b); break;
            default: r = !detail::slt(b, a); break;
          }
          write_vn(op.out, Wide::of(op.out.size, r ? 1 : 0));
          break;
        }
        case ghidra::CPUI_INT_ZEXT: write_vn(op.out, read_vn(op.in[0]).resized(op.out.size)); break;
        case ghidra::CPUI_INT_SEXT: write_vn(op.out, read_vn(op.in[0]).sext(op.out.size)); break;
        case ghidra::CPUI_INT_ADD:
          write_vn(op.out, detail::add(read_vn(op.in[0]).resized(op.out.size), read_vn(op.in[1]).resized(op.out.size)));
          break;
        case ghidra::CPUI_INT_SUB:
          write_vn(op.out, detail::sub(read_vn(op.in[0]).resized(op.out.size), read_vn(op.in[1]).resized(op.out.size)));
          break;
        case ghidra::CPUI_INT_MULT:
          write_vn(op.out, detail::mul(read_vn(op.in[0]).resized(op.out.size), read_vn(op.in[1]).resized(op.out.size)));
          break;
        case ghidra::CPUI_INT_CARRY: {
          const Wide a = read_vn(op.in[0]), b = read_vn(op.in[1]).resized(a.size);
          write_vn(op.out, Wide::of(op.out.size, detail::ult(detail::add(a, b), a) ? 1 : 0));
          break;
        }
        case ghidra::CPUI_INT_SCARRY: {
          const Wide a = read_vn(op.in[0]), b = read_vn(op.in[1]).resized(a.size);
          const Wide r = detail::add(a, b);
          const bool v = a.sign() == b.sign() && r.sign() != a.sign();
          write_vn(op.out, Wide::of(op.out.size, v ? 1 : 0));
          break;
        }
        case ghidra::CPUI_INT_SBORROW: {
          const Wide a = read_vn(op.in[0]), b = read_vn(op.in[1]).resized(a.size);
          const Wide r = detail::sub(a, b);
          const bool v = a.sign() != b.sign() && r.sign() != a.sign();
          write_vn(op.out, Wide::of(op.out.size, v ? 1 : 0));
          break;
        }
        case ghidra::CPUI_INT_2COMP: write_vn(op.out, detail::negate(read_vn(op.in[0]))); break;
        case ghidra::CPUI_INT_NEGATE: write_vn(op.out, detail::bit_not(read_vn(op.in[0]))); break;
        case ghidra::CPUI_INT_XOR:
        case ghidra::CPUI_INT_AND:
        case ghidra::CPUI_INT_OR:
        case ghidra::CPUI_BOOL_XOR:
        case ghidra::CPUI_BOOL_AND:
        case ghidra::CPUI_BOOL_OR: {
          Wide a = read_vn(op.in[0]).resized(op.out.size);
          const Wide b = read_vn(op.in[1]).resized(op.out.size);
          for (std::uint32_t k = 0; k < a.limbs(); ++k) {
            if (op.opcode == ghidra::CPUI_INT_XOR || op.opcode == ghidra::CPUI_BOOL_XOR) a.w[k] ^= b.w[k];
            else if (op.opcode == ghidra::CPUI_INT_AND || op.opcode == ghidra::CPUI_BOOL_AND) a.w[k] &= b.w[k];
            else a.w[k] |= b.w[k];
          }
          write_vn(op.out, a);
          break;
        }
        case ghidra::CPUI_BOOL_NEGATE: write_vn(op.out, Wide::of(op.out.size, (read_vn(op.in[0]).lo() & 1) ^ 1)); break;
        case ghidra::CPUI_INT_LEFT:
          write_vn(op.out, detail::shl(read_vn(op.in[0]).resized(op.out.size), read_vn(op.in[1]).clamp_u64()));
          break;
        case ghidra::CPUI_INT_RIGHT:
          write_vn(op.out, detail::lshr(read_vn(op.in[0]).resized(op.out.size), read_vn(op.in[1]).clamp_u64()));
          break;
        case ghidra::CPUI_INT_SRIGHT:
          write_vn(op.out, detail::ashr(read_vn(op.in[0]).sext(op.out.size), read_vn(op.in[1]).clamp_u64()));
          break;
        case ghidra::CPUI_INT_DIV:
        case ghidra::CPUI_INT_REM:
        case ghidra::CPUI_INT_SDIV:
        case ghidra::CPUI_INT_SREM: {
          Wide a = read_vn(op.in[0]).resized(op.out.size);
          Wide b = read_vn(op.in[1]).resized(op.out.size);
          if (op.opcode == ghidra::CPUI_INT_SDIV || op.opcode == ghidra::CPUI_INT_SREM) {
            a = read_vn(op.in[0]).sext(op.out.size);
            b = read_vn(op.in[1]).sext(op.out.size);
          }
          if (b.zero()) throw Fault{StopKind::divide_by_zero, at, "division by zero", false};
          Wide q, r;
          if (op.opcode == ghidra::CPUI_INT_DIV || op.opcode == ghidra::CPUI_INT_REM) {
            detail::udivrem(a, b, q, r);
          } else {
            const bool na = a.sign(), nb = b.sign();
            detail::udivrem(na ? detail::negate(a) : a, nb ? detail::negate(b) : b, q, r);
            if (na != nb) q = detail::negate(q);
            if (na) r = detail::negate(r);
          }
          write_vn(op.out, op.opcode == ghidra::CPUI_INT_DIV || op.opcode == ghidra::CPUI_INT_SDIV ? q : r);
          break;
        }
        case ghidra::CPUI_PIECE: {
          const Wide hi = read_vn(op.in[0]), lo = read_vn(op.in[1]);
          Wide r = detail::shl(hi.resized(op.out.size), 8ull * lo.size);
          const Wide l = lo.resized(op.out.size);
          for (std::uint32_t k = 0; k < r.limbs(); ++k) r.w[k] |= l.w[k];
          write_vn(op.out, r);
          break;
        }
        case ghidra::CPUI_SUBPIECE: {
          const Wide a = read_vn(op.in[0]);
          write_vn(op.out, detail::lshr(a, 8ull * op.in[1].offset).resized(op.out.size));
          break;
        }
        case ghidra::CPUI_POPCOUNT: write_vn(op.out, Wide::of(op.out.size, detail::popcount(read_vn(op.in[0])))); break;
        case ghidra::CPUI_LZCOUNT: write_vn(op.out, Wide::of(op.out.size, detail::lzcount(read_vn(op.in[0])))); break;
        case ghidra::CPUI_INSERT: {
          // out = in0 with bits [pos, pos+len) replaced by in1's low bits.
          const Wide a = read_vn(op.in[0]).resized(op.out.size);
          const Wide v = read_vn(op.in[1]).resized(op.out.size);
          const std::uint64_t pos = read_vn(op.in[2]).lo(), len = read_vn(op.in[3]).lo();
          Wide field = detail::shl(Wide::of(op.out.size, 1), len);
          field = detail::sub(field, Wide::of(op.out.size, 1));
          Wide keep = detail::bit_not(detail::shl(field, pos));
          Wide r = a;
          Wide ins = v;
          for (std::uint32_t k = 0; k < ins.limbs(); ++k) ins.w[k] &= field.w[k];
          ins = detail::shl(ins, pos);
          for (std::uint32_t k = 0; k < r.limbs(); ++k) r.w[k] = (r.w[k] & keep.w[k]) | ins.w[k];
          write_vn(op.out, r);
          break;
        }
        case ghidra::CPUI_ZPULL:
        case ghidra::CPUI_SPULL: {
          const Wide a = read_vn(op.in[0]);
          const std::uint64_t pos = read_vn(op.in[1]).lo(), len = read_vn(op.in[2]).lo();
          Wide r = detail::lshr(a, pos);
          Wide field = detail::sub(detail::shl(Wide::of(a.size, 1), len), Wide::of(a.size, 1));
          for (std::uint32_t k = 0; k < r.limbs(); ++k) r.w[k] &= field.w[k];
          if (op.opcode == ghidra::CPUI_SPULL && len > 0 && len < 8ull * a.size && r.bit(static_cast<std::uint32_t>(len - 1)))
            for (std::uint32_t k = static_cast<std::uint32_t>(len); k < 8 * a.size; ++k) r.w[k / 64] |= std::uint64_t{1} << (k % 64);
          write_vn(op.out, r.resized(op.out.size));
          break;
        }
        case ghidra::CPUI_PTRADD:
          write_vn(op.out, detail::add(read_vn(op.in[0]).resized(op.out.size),
                                       detail::mul(read_vn(op.in[1]).resized(op.out.size), read_vn(op.in[2]).resized(op.out.size))));
          break;
        case ghidra::CPUI_PTRSUB:
        case ghidra::CPUI_SEGMENTOP:
          if (op.opcode == ghidra::CPUI_SEGMENTOP)
            throw Fault{StopKind::unimplemented, at, "SEGMENTOP", false};
          write_vn(op.out, detail::add(read_vn(op.in[0]).resized(op.out.size), read_vn(op.in[1]).resized(op.out.size)));
          break;
        case ghidra::CPUI_FLOAT_EQUAL:
        case ghidra::CPUI_FLOAT_NOTEQUAL:
        case ghidra::CPUI_FLOAT_LESS:
        case ghidra::CPUI_FLOAT_LESSEQUAL:
        case ghidra::CPUI_FLOAT_ADD:
        case ghidra::CPUI_FLOAT_SUB:
        case ghidra::CPUI_FLOAT_MULT:
        case ghidra::CPUI_FLOAT_DIV: {
          const Wide a = read_vn(op.in[0]), b = read_vn(op.in[1]);
          write_vn(op.out, detail::float_op(op.opcode, a, &b, op.out.size));
          break;
        }
        case ghidra::CPUI_FLOAT_NAN:
        case ghidra::CPUI_FLOAT_NEG:
        case ghidra::CPUI_FLOAT_ABS:
        case ghidra::CPUI_FLOAT_SQRT:
        case ghidra::CPUI_FLOAT_INT2FLOAT:
        case ghidra::CPUI_FLOAT_FLOAT2FLOAT:
        case ghidra::CPUI_FLOAT_TRUNC:
        case ghidra::CPUI_FLOAT_CEIL:
        case ghidra::CPUI_FLOAT_FLOOR:
        case ghidra::CPUI_FLOAT_ROUND:
          write_vn(op.out, detail::float_op(op.opcode, read_vn(op.in[0]), nullptr, op.out.size));
          break;
        default:
          throw Fault{StopKind::unimplemented, at,
                      std::string("p-code op ") + ghidra::get_opname(static_cast<ghidra::OpCode>(op.opcode)), false};
      }
      ++i;
    }
    if (d->writes_nzcv) {
      const std::uint64_t v = get_reg(*nzcv).lo();
      const char *flags[] = {"NG", "ZR", "CY", "OV"};
      for (int b = 0; b < 4; ++b) {
        const RegisterInfo &r = reg(flags[b]);
        store(register_space, r.offset, Wide::of(r.size, (v >> (31 - b)) & 1));
      }
    }
    if (it_flags) {
      const char *names[] = {"NG", "ZR", "CY", "OV"};
      for (int k = 0; k < 4; ++k)
        if (auto r = find_reg(names[k]))
          store(register_space, registers[*r].offset, Wide::of(registers[*r].size, (*it_flags)[static_cast<std::size_t>(k)]));
    }
    if (hook) {
      cpu->after(*d, at, next);
      if (cpu->returned && recording) {
        entry.exception = "return";
        entry.exception_number = cpu->returned->number;
      }
    }
    if (cpu != nullptr && cpu->sync) {
      // SWI, SVC, a system call: the exception is taken as the instruction ends.
      const detail::Pending p = *cpu->sync;
      cpu->sync.reset();
      next = machine->take_now(p, next) & code_mask;
      it_next = itstate;  // entry saves and clears ITSTATE
    }
  } catch (Fault &f) {
    undo_all();
    detail::Pending p;
    std::uint64_t ret = 0;
    if (cpu != nullptr && cpu->fault_exception(f, at, p, ret)) {
      // An abort or undefined instruction the machine takes as an exception:
      // the instruction is undone and the step enters the handler instead.
      cpu->sync.reset();
      if (recording) {
        entry = TraceEntry{};
        entry.index = steps;
        entry.pc = at;
        entry.thumb = thumb;
      }
      step_reads = step_writes = 0;
      step_event.clear();
      try {
        next = machine->take_now(p, ret) & code_mask;
      } catch (Fault &f2) {
        undo_all();
        Stop s = make_stop(f2.kind, f2.detail);
        if (f2.has_address) s.address = f2.address;
        return s;
      }
      if (has_thumb && tb_register) thumb = tb_register->offset < regs.size() && regs[tb_register->offset] != 0;
      pc = next;
      if (!pc_reg.name.empty()) set_reg(pc_reg, Wide::of(pc_reg.size, pc));
      ++steps;
      finish_entry(nullptr, recording);
      return std::nullopt;
    }
    if (d && (f.kind == StopKind::unimplemented || f.kind == StopKind::userop) && f.detail.find(d->text) == std::string::npos)
      f.detail += " (" + d->text + ")";
    Stop s = make_stop(f.kind, f.detail);
    if (f.has_address) s.address = f.address;
    return s;
  }

  // ARM: the TB register mirrors the instruction set the next instruction
  // is in (BX, BLX, POP {pc} and the like set it); a target with bit 0 set
  // is Thumb too.
  if (has_thumb) {
    bool t = thumb;
    if (tb_register) {
      std::uint8_t tb = 0;
      if (tb_register->offset < regs.size()) tb = regs[tb_register->offset];
      t = tb != 0;
    }
    if (next & 1) {
      t = true;
      next &= ~std::uint64_t{1};
    }
    if (t != thumb) {
      thumb = t;
      if (tb_register) set_reg(RegisterInfo{tb_register->name, tb_register->offset, tb_register->size}, Wide::of(1, t ? 1 : 0));
    }
  }

  // An instruction that branches to itself and changes nothing is a halt
  // (x86 HLT, ARM "b .").
  bool changed = mmio_read_this_step || pending_exit.has_value();
  for (const detail::UndoEntry &u : undo) {
    if (changed) break;
    const detail::Space &sp = spaces[static_cast<std::size_t>(u.space)];
    std::vector<std::uint8_t> now(u.old.size());
    if (sp.kind == SpaceKind::registers) std::memcpy(now.data(), regs.data() + u.offset, now.size());
    else if (sp.kind == SpaceKind::ram) ram_read(u.offset, now.data(), now.size());
    else changed = true;
    if (now != u.old) changed = true;
  }

  itstate = thumb ? it_next : 0;
  pc = next;
  if (!pc_reg.name.empty()) set_reg(pc_reg, Wide::of(pc_reg.size, pc));
  ++steps;
  finish_entry(d.get(), recording);

  if (pending_exit) {
    Stop s = make_stop(StopKind::exited, "exit(" + std::to_string(*pending_exit) + ")");
    s.exit_code = *pending_exit;
    return s;
  }
  if (watch_hit) {
    Stop s = make_stop(StopKind::watchpoint, "watched memory at " + hexs(*watch_hit) + " accessed by " + hexs(at));
    s.address = *watch_hit;
    return s;
  }
  if (next == at && !changed) return make_stop(StopKind::halted, d->text + " branches to itself");
  (void)returned;
  return std::nullopt;
}

void Emulator::Impl::finish_entry(const detail::Decoded *d, bool record) {
  if (!record) {
    trace.count(entry.pc, step_reads, step_writes);
    return;
  }
  if (d != nullptr) {
    entry.bytes = d->bytes;
    entry.text = d->text;
  }
  std::vector<std::pair<std::uint64_t, std::uint32_t>> seen;
  for (const detail::UndoEntry &u : undo) {
    if (spaces[static_cast<std::size_t>(u.space)].kind != SpaceKind::registers) continue;
    const std::pair<std::uint64_t, std::uint32_t> key{u.offset, static_cast<std::uint32_t>(u.old.size())};
    if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
    seen.push_back(key);
    RegisterWrite w;
    w.name = register_name(u.offset, key.second);
    std::vector<std::uint8_t> v(regs.begin() + static_cast<std::ptrdiff_t>(u.offset),
                                regs.begin() + static_cast<std::ptrdiff_t>(u.offset + key.second));
    if (big_endian) std::reverse(v.begin(), v.end());
    w.value = std::move(v);
    entry.registers.push_back(std::move(w));
  }
  entry.event = step_event;
  trace.add(std::move(entry), step_reads, step_writes);
}

std::optional<Stop> Emulator::Impl::exec_stub(const detail::StubEntry &stub) {
  StubCall call;
  call.name = stub.name;
  call.address = pc;
  call.return_value = options.import_return;
  trace.count_stub();
  try {
    if (stub.handler(*self, call) == HookAction::stop) {
      undo_all();
      return make_stop(StopKind::hook, call.note.empty() ? "stub " + stub.name + " stopped" : call.note);
    }
    if (call.exited) {
      ++steps;
      if (recording) {
        entry.text = "<stub " + stub.name + ">";
        entry.event = call.note;
      }
      finish_entry(nullptr, recording);
      Stop s = make_stop(StopKind::exited, call.note.empty() ? stub.name + "(" + std::to_string(call.exit_code) + ")" : call.note);
      s.exit_code = call.exit_code;
      return s;
    }
    if (call.jump_to) {
      pc = *call.jump_to & code_mask;
      apply_isa(pc);
    } else {
      if (call.returns_value && !abi.int_returns.empty()) {
        const RegisterInfo &r = reg(abi.int_returns[0]);
        store(register_space, r.offset, Wide::of(r.size, call.return_value));
      }
      return_from_call(call.stack_pop);
    }
  } catch (Fault &f) {
    undo_all();
    Stop s = make_stop(f.kind, f.detail);
    if (f.has_address) s.address = f.address;
    return s;
  }
  if (!pc_reg.name.empty()) set_reg(pc_reg, Wide::of(pc_reg.size, pc));
  ++steps;
  if (recording) {
    entry.text = "<stub " + stub.name + ">";
    entry.event = call.note;
  }
  finish_entry(nullptr, recording);
  if (breakpoints.count(pc) != 0) return std::nullopt;  // the run loop reports it
  return std::nullopt;
}

bool Emulator::Impl::condition_holds(unsigned cond) const {
  auto flag = [&](const char *name) {
    auto i = find_reg(name);
    return i && get_reg(registers[*i]).lo() != 0;
  };
  const bool n = flag("NG"), z = flag("ZR"), c = flag("CY"), v = flag("OV");
  bool r = false;
  switch (cond >> 1) {
    case 0: r = z; break;
    case 1: r = c; break;
    case 2: r = n; break;
    case 3: r = v; break;
    case 4: r = c && !z; break;
    case 5: r = n == v; break;
    case 6: r = !z && n == v; break;
    default: return true;  // AL
  }
  return (cond & 1) != 0 && cond != 15 ? !r : r;
}

void Emulator::Impl::apply_isa(std::uint64_t &target) {
  if (!has_thumb) return;
  const bool t = (target & 1) != 0;
  target &= ~std::uint64_t{1};
  thumb = t;
  if (tb_register) set_reg(RegisterInfo{tb_register->name, tb_register->offset, tb_register->size}, Wide::of(1, t ? 1 : 0));
}

}  // namespace revkit::emu
