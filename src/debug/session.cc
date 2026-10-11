#include "revkit/debug/session.hh"

#include "revkit/debug/emu_target.hh"

#include "revkit/lift/lifter.hh"

#include <algorithm>
#include <cctype>
#include <map>
#include <cstring>
#include <ctime>

namespace revkit::debug {

namespace {

constexpr std::uint64_t kAtEntry = 9;
constexpr std::size_t kMaxOutput = 1u << 20;

}  // namespace

Session::Session(std::unique_ptr<Target> target, SessionOptions options)
    : target_(std::move(target)), options_(std::move(options)), timeline_(options_.timeline) {
  if (options_.language.empty()) options_.language = target_->language();
  if (options_.recorded) {
    timeline_ = std::move(*options_.recorded);
    options_.recorded.reset();
    timeline_.set_limits(options_.timeline);
  }
  refresh_mapping();
  last_ = target_->last_stop();
  if (target_->state() != TargetState::replay) record(last_);
}

Session::~Session() = default;

// --- Addresses ---

void Session::set_slide(std::int64_t slide) {
  options_.slide = slide;
  refresh_mapping();
  // Breakpoints given in program addresses move with it.
  for (Breakpoint &b : breakpoints_) {
    if (!b.program_address) continue;
    const std::uint64_t now = to_runtime(*b.program_address);
    if (now == b.address && !b.pending) continue;
    if (b.inserted) {
      try {
        target_->remove_breakpoint(b.kind, b.address, b.size);
      } catch (const DebugError &) {
      }
      b.inserted = false;
    }
    b.address = now;
    b.pending = false;
    insert(b);
  }
}

void Session::refresh_mapping() {
  AddressMapping m;
  const loader::Image *img = options_.image.get();
  if (options_.slide) {
    m = {true, *options_.slide, "given"};
  } else if (target_->kind() == "emulator") {
    m = {true, 0, "emulator"};
  } else if (img == nullptr) {
    m = {false, 0, "no program"};
  } else if (img->format == loader::Format::raw) {
    m = {true, 0, "static"};
  } else {
    // Is the program the process's executable?
    std::vector<ModuleInfo> mods;
    try {
      mods = target_->modules();
    } catch (const DebugError &) {
    }
    const ModuleInfo *main = nullptr, *named = nullptr;
    for (const ModuleInfo &mod : mods) {
      if (mod.main) main = &mod;
      if (!options_.program_name.empty() && mod.name == options_.program_name) named = named ? named : &mod;
    }
    const bool is_main = main == nullptr || main->name.empty() || options_.program_name.empty() ||
                         main->name == options_.program_name || named == main;
    const std::int64_t rebase = static_cast<std::int64_t>(img->image_base - img->file_base);
    std::map<std::uint64_t, std::uint64_t> av;
    try {
      av = target_->auxv();
    } catch (const DebugError &) {
    }
    if (is_main && img->entry && av.count(kAtEntry)) {
      m = {true, static_cast<std::int64_t>(av[kAtEntry] - *img->entry), "auxv AT_ENTRY"};
    } else if (is_main && main != nullptr && (main->load_bias != 0 || img->elf_type == 2)) {
      m = {true, static_cast<std::int64_t>(main->load_bias) - rebase, "module " + main->name};
    } else if (named != nullptr && named != main) {
      m = {true, static_cast<std::int64_t>(named->load_bias) - rebase, "module " + named->name};
    } else if (img->format == loader::Format::elf && img->elf_type == 2 && is_main) {
      m = {true, 0, "static"};  // a fixed-address executable
    } else if (img->format == loader::Format::pe && is_main && main != nullptr && main->base != 0) {
      m = {true, static_cast<std::int64_t>(main->base - img->image_base), "module " + main->name};
    } else {
      m = {false, 0, is_main ? "unknown" : "not loaded yet"};
    }
  }
  mapping_ = m;
}

std::uint64_t Session::to_runtime(std::uint64_t program_address) const {
  return program_address + static_cast<std::uint64_t>(mapping_.slide);
}

std::optional<std::uint64_t> Session::to_program(std::uint64_t runtime) const {
  if (!mapping_.known || !options_.image) return std::nullopt;
  const std::uint64_t p = runtime - static_cast<std::uint64_t>(mapping_.slide);
  if (options_.image->memory.find(p) != nullptr) return p;
  for (const loader::Block &b : options_.image->blocks)
    if (p >= b.start && p - b.start < b.size) return p;
  return std::nullopt;
}

std::vector<ModuleInfo> Session::modules() {
  std::vector<ModuleInfo> mods;
  if (target_->state() == TargetState::stopped) {
    try {
      mods = target_->modules();
    } catch (const DebugError &) {
    }
  }
  // A target without modules (a board): the program itself.
  if (mods.empty() && options_.image) {
    ModuleInfo m;
    m.name = m.path = options_.program_name;
    m.main = true;
    std::uint64_t lo = ~std::uint64_t{0}, hi = 0;
    for (const loader::Region &r : options_.image->memory.regions()) {
      lo = std::min(lo, r.start);
      hi = std::max(hi, r.start + r.size);
    }
    if (hi > lo) {
      m.base = to_runtime(lo);
      m.size = hi - lo;
    }
    m.load_bias = static_cast<std::uint64_t>(mapping_.slide);
    mods.push_back(m);
  }
  return mods;
}

std::vector<MapRegion> Session::memory_map() {
  std::vector<MapRegion> out;
  if (target_->state() == TargetState::stopped) {
    try {
      out = target_->memory_map();
    } catch (const DebugError &) {
    }
  }
  if (out.empty() && options_.image && mapping_.known) {
    // What the program's image says, moved by the slide.
    for (const loader::Block &b : options_.image->blocks) {
      MapRegion r;
      r.start = to_runtime(b.start);
      r.size = b.size;
      r.perms = b.perms.str();
      r.name = b.name;
      r.kind = b.is_volatile ? "mmio" : "image";
      out.push_back(r);
    }
  }
  return out;
}

std::optional<std::pair<ModuleInfo, std::uint64_t>> Session::module_at(std::uint64_t runtime) {
  for (const ModuleInfo &m : modules())
    if (m.size != 0 && runtime >= m.base && runtime - m.base < m.size) return std::make_pair(m, runtime - m.base);
  return std::nullopt;
}

// --- Decoding (live step over and out) ---

lift::Lifter *Session::lifter() {
  if (!options_.image || lifter_failed_) return nullptr;
  try {
    if (!lifter_) {
      lifter_ = std::make_unique<lift::Lifter>(options_.image, options_.language);
      if (options_.language.rfind("ARM:", 0) == 0) {
        thumb_lifter_ = std::make_unique<lift::Lifter>(options_.image, options_.language);
        thumb_lifter_->set_context("TMode", 1, 0);
      }
    }
  } catch (const std::exception &) {
    lifter_failed_ = true;
    return nullptr;
  }
  return target_->thumb() && thumb_lifter_ ? thumb_lifter_.get() : lifter_.get();
}

std::optional<Session::Decoded> Session::decode(std::uint64_t runtime) {
  lift::Lifter *lp = lifter();
  if (lp == nullptr) return std::nullopt;
  std::uint8_t buf[32] = {};
  if (target_->read_memory(runtime, buf) == 0) return std::nullopt;
  lift::Lifter &l = *lp;
  std::optional<lift::Instruction> insn;
  try {
    insn = l.lift_pcode(runtime, std::span<const std::byte>(reinterpret_cast<const std::byte *>(buf), sizeof buf));
  } catch (const std::exception &) {
    return std::nullopt;
  }
  if (!insn || insn->length == 0) return std::nullopt;
  Decoded d;
  d.length = insn->length + insn->delay_slot;
  for (const lift::PcodeOp &op : insn->pcode) {
    if (op.opcode == "CALL" || op.opcode == "CALLIND") d.call = true;
    if (op.opcode == "RETURN") d.ret = true;
  }
  return d;
}

// --- Operands ---

std::string Session::register_at(std::uint64_t offset, std::uint32_t size) {
  lift::Lifter *l = lifter();
  if (l == nullptr) return {};
  try {
    return l->register_name(offset, size);
  } catch (const std::exception &) {
    return {};
  }
}

std::optional<lift::Instruction> Session::disassemble(std::uint64_t runtime, std::span<const std::uint8_t> bytes) {
  lift::Lifter *l = lifter();
  if (l == nullptr || bytes.empty()) return std::nullopt;
  try {
    auto insn = l->lift(runtime, std::span<const std::byte>(reinterpret_cast<const std::byte *>(bytes.data()), bytes.size()));
    if (!insn || insn->length == 0) return std::nullopt;
    return insn;
  } catch (const std::exception &) {
    return std::nullopt;
  }
}

std::optional<std::pair<std::uint64_t, std::uint32_t>> Session::register_storage(const std::string &name) {
  lift::Lifter *l = lifter();
  if (l == nullptr) return std::nullopt;
  try {
    if (auto vn = l->register_varnode(name); vn && vn->space == "register") return std::make_pair(vn->offset, vn->size);
  } catch (const std::exception &) {
  }
  return std::nullopt;
}

std::vector<Session::MemoryAccess> Session::memory_accesses(
    std::uint64_t runtime, std::span<const std::uint8_t> bytes, const std::map<std::string, std::uint64_t> &registers,
    const std::function<std::optional<std::uint64_t>(std::uint64_t, unsigned)> &read, int operand) {
  std::vector<MemoryAccess> out;
  lift::Lifter *l = lifter();
  if (l == nullptr) return out;
  std::optional<lift::Instruction> insn;
  try {
    insn = l->lift(runtime, std::span<const std::byte>(reinterpret_cast<const std::byte *>(bytes.data()), bytes.size()));
  } catch (const std::exception &) {
    return out;
  }
  if (!insn) return out;
  const bool big = options_.language.find(":BE:") != std::string::npos;
  // The register space's bytes, from the frame's registers.
  std::map<std::uint64_t, std::uint8_t> regbytes;
  for (const auto &[name, value] : registers) {
    std::optional<lift::Varnode> vn;
    try {
      vn = l->register_varnode(name);
    } catch (const std::exception &) {
    }
    if (!vn || vn->space != "register" || vn->size == 0 || vn->size > 8) continue;
    for (std::uint32_t i = 0; i < vn->size; ++i) {
      const std::uint8_t b = static_cast<std::uint8_t>(value >> (8 * i));
      regbytes[vn->offset + (big ? vn->size - 1 - i : i)] = b;
    }
  }
  using Taint = std::vector<std::pair<std::uint64_t, std::uint32_t>>;  // register ranges read
  struct Val {
    std::optional<std::uint64_t> v;
    Taint taint;
  };
  std::map<std::uint64_t, Val> uniques;
  auto mask = [](std::uint64_t v, std::uint32_t size) { return size >= 8 ? v : v & ((1ull << (size * 8)) - 1); };
  struct Raw {
    MemoryAccess a;
    Taint taint;
  };
  std::vector<Raw> raw;
  auto get = [&](const lift::Varnode &vn) -> Val {
    Val out;
    if (vn.space == "const") {
      out.v = mask(vn.offset, vn.size);
      return out;
    }
    if (vn.space == "unique") {
      if (auto it = uniques.find(vn.offset); it != uniques.end()) return it->second;
      return out;
    }
    if (vn.space == "register") {
      out.taint.push_back({vn.offset, vn.size});
      if (vn.size > 8) return out;
      std::uint64_t v = 0;
      for (std::uint32_t i = 0; i < vn.size; ++i) {
        auto it = regbytes.find(vn.offset + (big ? i : vn.size - 1 - i));
        if (it == regbytes.end()) return out;
        v = (v << 8) | it->second;
      }
      out.v = v;
      return out;
    }
    // A direct memory reference (an absolute or pc-relative operand).
    raw.push_back({{vn.offset, vn.size, false, false}, {}});
    if (vn.size <= 8 && read) out.v = read(vn.offset, vn.size);
    return out;
  };
  auto set = [&](const lift::Varnode &vn, Val v) {
    if (v.v) v.v = mask(*v.v, vn.size);
    if (vn.space == "unique") {
      uniques[vn.offset] = std::move(v);
    } else if (vn.space == "register") {
      for (std::uint32_t i = 0; i < vn.size; ++i) {
        if (!v.v || vn.size > 8) {
          regbytes.erase(vn.offset + i);
          continue;
        }
        regbytes[vn.offset + (big ? vn.size - 1 - i : i)] = static_cast<std::uint8_t>(*v.v >> (8 * i));
      }
    } else if (vn.space != "const") {
      raw.push_back({{vn.offset, vn.size, true, false}, {}});
    }
  };
  auto merge = [](Taint a, const Taint &b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
  };
  std::size_t steps = 0;
  for (const lift::PcodeOp &op : insn->pcode) {
    if (++steps > 512) break;
    const std::string &o = op.opcode;
    if (o == "BRANCH" || o == "BRANCHIND" || o == "RETURN" || o == "CALL" || o == "CALLIND" || o == "CALLOTHER") {
      if (o == "CALLOTHER") {
        if (op.output) set(*op.output, {});
        continue;
      }
      break;
    }
    if (o == "CBRANCH") continue;  // fall through
    if (o == "LOAD" && op.inputs.size() >= 2 && op.output) {
      Val a = get(op.inputs[1]);
      Val r;
      if (a.v) {
        raw.push_back({{*a.v, op.output->size, false, false}, a.taint});
        if (op.output->size <= 8 && read) r.v = read(*a.v, op.output->size);
      }
      set(*op.output, r);
      continue;
    }
    if (o == "STORE" && op.inputs.size() >= 3) {
      Val a = get(op.inputs[1]);
      if (a.v) raw.push_back({{*a.v, op.inputs[2].size, true, false}, a.taint});
      continue;
    }
    if (!op.output) continue;
    std::vector<Val> in;
    for (const lift::Varnode &vn : op.inputs) in.push_back(get(vn));
    Val r;
    for (const Val &v : in) r.taint = merge(r.taint, v.taint);
    bool known = !in.empty();
    for (const Val &v : in) known = known && v.v.has_value();
    const std::uint32_t osz = op.output->size;
    if (known && osz <= 8) {
      const std::uint64_t a = *in[0].v;
      const std::uint64_t b = in.size() > 1 ? *in[1].v : 0;
      const std::uint32_t isz = op.inputs[0].size;
      auto sext = [](std::uint64_t v, std::uint32_t size) {
        if (size >= 8) return v;
        const std::uint64_t m = 1ull << (size * 8 - 1);
        v &= (1ull << (size * 8)) - 1;
        return (v ^ m) - m;
      };
      if (o == "COPY" || o == "INT_ZEXT" || o == "CAST") r.v = a;
      else if (o == "INT_SEXT") r.v = sext(a, isz);
      else if (o == "INT_ADD" || o == "PTRADD") r.v = o == "PTRADD" && in.size() > 2 ? a + b * *in[2].v : a + b;
      else if (o == "INT_SUB" || o == "PTRSUB") r.v = o == "PTRSUB" ? a + b : a - b;
      else if (o == "INT_MULT") r.v = a * b;
      else if (o == "INT_DIV") r.v = b ? a / b : std::optional<std::uint64_t>();
      else if (o == "INT_REM") r.v = b ? a % b : std::optional<std::uint64_t>();
      else if (o == "INT_AND" || o == "BOOL_AND") r.v = a & b;
      else if (o == "INT_OR" || o == "BOOL_OR") r.v = a | b;
      else if (o == "INT_XOR" || o == "BOOL_XOR") r.v = a ^ b;
      else if (o == "INT_LEFT") r.v = b >= 64 ? 0 : a << b;
      else if (o == "INT_RIGHT") r.v = b >= 64 ? 0 : mask(a, isz) >> b;
      else if (o == "INT_SRIGHT") r.v = b >= 64 ? 0 : static_cast<std::uint64_t>(static_cast<std::int64_t>(sext(a, isz)) >> b);
      else if (o == "INT_2COMP") r.v = 0 - a;
      else if (o == "INT_NEGATE") r.v = ~a;
      else if (o == "BOOL_NEGATE") r.v = a == 0;
      else if (o == "SUBPIECE") r.v = b >= 8 ? 0 : a >> (8 * b);
      else if (o == "PIECE" && op.inputs.size() > 1 && op.inputs[1].size < 8) r.v = (a << (8 * op.inputs[1].size)) | mask(b, op.inputs[1].size);
      else if (o == "INT_EQUAL") r.v = mask(a, isz) == mask(b, isz);
      else if (o == "INT_NOTEQUAL") r.v = mask(a, isz) != mask(b, isz);
      else if (o == "INT_LESS") r.v = mask(a, isz) < mask(b, isz);
      else if (o == "INT_LESSEQUAL") r.v = mask(a, isz) <= mask(b, isz);
      else if (o == "INT_SLESS") r.v = static_cast<std::int64_t>(sext(a, isz)) < static_cast<std::int64_t>(sext(b, isz));
      else if (o == "INT_SLESSEQUAL") r.v = static_cast<std::int64_t>(sext(a, isz)) <= static_cast<std::int64_t>(sext(b, isz));
    }
    set(*op.output, r);
  }
  // Which access is the operand's: one its registers or its address computed.
  Taint want;
  std::optional<std::uint64_t> want_address;
  for (const lift::Token &t : insn->tokens) {
    if (t.operand != operand || operand < 0) continue;
    if (t.kind == lift::Token::Kind::reg && t.reg.space == "register") want.push_back({t.reg.offset, t.reg.size});
    if (t.kind == lift::Token::Kind::address) want_address = t.value;
  }
  auto overlaps = [&](const Taint &taint) {
    for (const auto &[o1, s1] : taint)
      for (const auto &[o2, s2] : want)
        if (o1 < o2 + s2 && o2 < o1 + s1) return true;
    return false;
  };
  std::optional<std::size_t> pick;
  if (operand >= 0) {
    for (std::size_t i = 0; i < raw.size() && !pick; ++i)
      if (!want.empty() && overlaps(raw[i].taint)) pick = i;
    for (std::size_t i = 0; i < raw.size() && !pick; ++i)
      if (want_address && raw[i].a.address == *want_address) pick = i;
    if (!pick && raw.size() == 1) pick = 0;
  }
  if (pick) {
    raw[*pick].a.operand = true;
    out.push_back(raw[*pick].a);
  }
  for (std::size_t i = 0; i < raw.size(); ++i)
    if (!pick || i != *pick) out.push_back(raw[i].a);
  return out;
}

// --- The call stack ---

bool Session::after_call(std::uint64_t runtime) {
  // Variable-length ISAs: a call of each possible length ending here.
  for (std::uint64_t n : {5, 2, 3, 4, 6, 7}) {
    if (runtime < n) continue;
    if (auto d = decode(runtime - n); d && d->call && d->length == n) return true;
  }
  return false;
}

std::vector<Frame> Session::backtrace(const BacktraceOptions &o) {
  auto arch = UnwindArch::for_language(options_.language);
  if (!arch) throw DebugError("no call-stack unwinding for " + (options_.language.empty() ? std::string("this target") : options_.language));
  const std::uint64_t now = current_snapshot();
  const bool live = (!o.snapshot || *o.snapshot == now) && target_->state() == TargetState::stopped;
  const std::uint64_t snap = o.snapshot.value_or(now);
  if (!live && timeline_.find(snap) == nullptr) throw DebugError("snapshot " + std::to_string(snap) + " is not recorded");
  std::map<std::string, std::vector<std::uint8_t>> recorded;
  if (!live) recorded = timeline_.registers_at(snap);
  if (o.cfi && !cfi_ && options_.image) cfi_ = CfiTable::from_image(*options_.image);
  // Executable memory: the target's map, else the program's image.
  std::vector<MapRegion> map = memory_map();

  UnwindSource src;
  src.reg = [&](const std::string &name) -> std::optional<std::uint64_t> {
    if (live) {
      try {
        const RegisterDesc *d = target_->find_register(name);
        if (d == nullptr) return std::nullopt;
        return to_u64(read_register(d->name));
      } catch (const DebugError &) {
        return std::nullopt;
      }
    }
    for (const auto &[n, v] : recorded)
      if (n.size() == name.size() && std::equal(n.begin(), n.end(), name.begin(), [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
          }))
        return to_u64(v);
    return std::nullopt;
  };
  const bool big = arch->big_endian;
  src.read = [&](std::uint64_t address, unsigned size) -> std::optional<std::uint64_t> {
    std::vector<std::uint8_t> buf(size);
    if (live) {
      std::vector<ByteRange> bad;
      if (read_memory(address, buf, &bad) != size || !bad.empty()) return std::nullopt;
    } else {
      std::vector<Timeline::ByteState> state;
      memory_at(snap, address, buf, state);
      for (Timeline::ByteState b : state)
        if (b == Timeline::ByteState::unknown) return std::nullopt;
    }
    std::uint64_t v = 0;
    for (unsigned i = 0; i < size; ++i) v |= static_cast<std::uint64_t>(buf[big ? size - 1 - i : i]) << (8 * i);
    return v;
  };
  src.is_code = [&](std::uint64_t address) {
    // The program's own image first; then the target's map (a stub that
    // gives no permissions counts as executable).
    if (auto p = to_program(address); p && options_.image)
      if (const loader::Region *r = options_.image->memory.find(*p)) return r->perms.exec;
    for (const MapRegion &r : map)
      if (address >= r.start && address - r.start < r.size)
        return r.perms.empty() || r.perms.find('x') != std::string::npos;
    return false;
  };
  if (o.cfi && cfi_ && cfi_->size() > 0)
    src.cfi = [&](std::uint64_t pc) -> std::optional<CfiRow> {
      if (auto p = to_program(pc)) return cfi_->row_at(*p);
      return std::nullopt;
    };
  if (options_.image) src.after_call = [&](std::uint64_t address) { return after_call(address); };
  if (options_.function_entry)
    src.at_entry = [&](std::uint64_t pc) {
      auto p = to_program(pc);
      if (!p) return false;
      auto e = options_.function_entry(*p);
      return e && *e == *p;
    };
  return unwind(*arch, src, std::clamp<std::size_t>(o.max_frames, 1, 256));
}

// --- Breakpoints ---

void Session::insert(Breakpoint &b) {
  if (b.pending || b.inserted) return;
  if (target_->state() != TargetState::stopped) return;
  try {
    target_->insert_breakpoint(b.kind, b.address, b.size);
    b.inserted = true;
    b.error.clear();
  } catch (const DebugError &e) {
    b.error = e.what();
  }
}

void Session::resolve_pending() {
  for (Breakpoint &b : breakpoints_) {
    if (b.pending && mapping_.known && b.program_address) {
      b.address = to_runtime(*b.program_address);
      b.pending = false;
    }
    if (!b.inserted && !b.pending && !b.disabled && b.error.empty()) insert(b);
  }
}

const Breakpoint &Session::add_breakpoint(BreakKind kind, std::uint64_t address, bool program, std::uint32_t size) {
  for (Breakpoint &b : breakpoints_)
    if (b.kind == kind && (program ? b.program_address == address : b.address == address) && b.size == size) return b;
  Breakpoint b;
  b.id = next_breakpoint_++;
  b.kind = kind;
  b.size = size;
  if (program) {
    b.program_address = address;
    if (mapping_.known) b.address = to_runtime(address);
    else b.pending = true;
  } else {
    b.address = address;
    b.program_address = to_program(address);
  }
  insert(b);
  breakpoints_.push_back(b);
  return breakpoints_.back();
}

bool Session::remove_breakpoint(int id) {
  auto it = std::find_if(breakpoints_.begin(), breakpoints_.end(), [&](const Breakpoint &b) { return b.id == id; });
  if (it == breakpoints_.end()) return false;
  if (it->inserted) {
    try {
      target_->remove_breakpoint(it->kind, it->address, it->size);
    } catch (const DebugError &) {
    }
  }
  breakpoints_.erase(it);
  return true;
}

bool Session::remove_breakpoint_at(std::uint64_t address, bool program) {
  bool any = false;
  for (;;) {
    auto it = std::find_if(breakpoints_.begin(), breakpoints_.end(), [&](const Breakpoint &b) {
      return program ? b.program_address == address : b.address == address;
    });
    if (it == breakpoints_.end()) return any;
    remove_breakpoint(it->id);
    any = true;
  }
}

void Session::clear_breakpoints() {
  while (!breakpoints_.empty()) remove_breakpoint(breakpoints_.front().id);
}

bool Session::update_breakpoint(int id, std::optional<std::string> condition, std::optional<std::uint64_t> ignore_count,
                                std::optional<bool> disabled) {
  auto it = std::find_if(breakpoints_.begin(), breakpoints_.end(), [&](const Breakpoint &b) { return b.id == id; });
  if (it == breakpoints_.end()) return false;
  if (condition) {
    it->condition = *condition;
    it->condition_error.clear();
  }
  if (ignore_count) it->ignore_count = *ignore_count;
  if (disabled && *disabled != it->disabled) {
    it->disabled = *disabled;
    if (it->disabled && it->inserted) {
      try {
        target_->remove_breakpoint(it->kind, it->address, it->size);
      } catch (const DebugError &) {
      }
      it->inserted = false;
    } else if (!it->disabled) {
      it->error.clear();
      insert(*it);
    }
  }
  return true;
}

bool Session::pass_over(const Stop &s) {
  if (s.kind != StopKind::breakpoint || target_->state() != TargetState::stopped) return false;
  bool ours = false, stop = false;
  for (Breakpoint &b : breakpoints_) {
    if (b.address != s.pc || (b.kind != BreakKind::software && b.kind != BreakKind::hardware) || b.disabled) continue;
    ours = true;
    if (b.hits + 1 <= b.ignore_count) continue;
    if (b.condition.empty() || !condition_check_) {
      stop = true;
      continue;
    }
    std::string error;
    bool holds = true;
    try {
      holds = condition_check_(b, error);
    } catch (const std::exception &e) {
      error = e.what();
    }
    b.condition_error = error;
    if (holds || !error.empty()) stop = true;
  }
  if (!ours || stop) return false;
  // Passed over: counted, not recorded.
  for (Breakpoint &b : breakpoints_)
    if (b.address == s.pc && (b.kind == BreakKind::software || b.kind == BreakKind::hardware) && !b.disabled) ++b.hits;
  return true;
}

// --- Execution ---

bool Session::sp_above(std::uint64_t sp, std::uint64_t than, bool or_equal) const {
  if (target_->stack_grows_down()) return or_equal ? sp >= than : sp > than;
  return or_equal ? sp <= than : sp < than;
}

Stop Session::single_step(const ResumeOptions &o) {
  ResumeOptions s = o;
  s.mode = RunMode::step_into;
  return target_->resume(s);
}

Stop Session::run_to(std::uint64_t address, const ResumeOptions &o, std::optional<std::uint64_t> sp_at_least) {
  Pending p;
  const bool user = std::any_of(breakpoints_.begin(), breakpoints_.end(), [&](const Breakpoint &b) {
    return b.inserted && b.address == address && (b.kind == BreakKind::software || b.kind == BreakKind::hardware);
  });
  if (!user) {
    target_->insert_breakpoint(BreakKind::software, address, 0);
    p.temporary.push_back(address);
  }
  ResumeOptions run = o;
  run.mode = RunMode::run;
  p.finish = [this, address, sp_at_least, run](Stop s, Clock::time_point deadline) -> Stop {
    for (int guard = 0; guard < 100000; ++guard) {
      if (s.kind == StopKind::running) return s;
      if (s.kind != StopKind::breakpoint || s.pc != address) return s;
      if (!sp_at_least || sp_above(target_->sp(), *sp_at_least, true)) {
        s.kind = StopKind::stepped;
        return s;
      }
      // A deeper call reached it first (recursion): keep going.
      ResumeOptions again = run;
      again.deadline = deadline;
      s = target_->resume(again);
    }
    return s;
  };
  pending_ = std::move(p);
  return target_->resume(run);
}

Stop Session::step_over_live(const ResumeOptions &o) {
  const std::uint64_t pc0 = target_->pc();
  const auto d = decode(pc0);
  if (!d || !d->call) return single_step(o);
  const std::uint64_t sp0 = target_->sp();
  return run_to(pc0 + d->length, o, sp0);
}

Stop Session::step_out_live(const ResumeOptions &o) {
  const std::uint64_t pc0 = target_->pc(), sp0 = target_->sp();
  // The function's returns, from the program's code.
  std::vector<std::uint64_t> sites;
  std::vector<lift::AddressRange> body;
  if (options_.function_entry && lifter_ == nullptr) decode(pc0);  // makes the lifter
  if (options_.function_entry && lifter_) {
    if (auto prog = to_program(pc0)) {
      if (auto entry = options_.function_entry(*prog)) {
        try {
          lift::Lifter &l = target_->thumb() && thumb_lifter_ ? *thumb_lifter_ : *lifter_;
          body = l.flow_body(*entry, 20000);
          for (const auto &[lo, hi] : body)
            for (const lift::Instruction &insn : l.lift_range(lo, hi + 1))
              for (const lift::PcodeOp &op : insn.pcode)
                // Returns, and indirect jumps: ARMv4T returns with `bx r1`
                // after popping the address; a switch's jump stays inside.
                if (op.opcode == "RETURN" || op.opcode == "BRANCHIND") {
                  sites.push_back(to_runtime(insn.address));
                  break;
                }
        } catch (const std::exception &) {
          sites.clear();
        }
      }
    }
  }
  auto in_body = [this, body](std::uint64_t runtime) {
    auto p = to_program(runtime);
    if (!p) return false;
    for (const auto &[lo, hi] : body)
      if (*p >= lo && *p <= hi) return true;
    return false;
  };
  const bool has_body = !body.empty();
  auto out_of_it = [this, sp0, in_body, has_body](std::uint64_t sp, std::uint64_t pc) {
    return sp_above(sp, sp0, false) || (sp_above(sp, sp0, true) && has_body && !in_body(pc));
  };
  if (!sites.empty()) {
    Pending p;
    for (std::uint64_t a : sites) {
      const bool user = std::any_of(breakpoints_.begin(), breakpoints_.end(),
                                    [&](const Breakpoint &b) { return b.inserted && b.address == a; });
      if (user) continue;
      try {
        target_->insert_breakpoint(BreakKind::software, a, 0);
        p.temporary.push_back(a);
      } catch (const DebugError &) {
      }
    }
    ResumeOptions run = o;
    run.mode = RunMode::run;
    p.finish = [this, sites, run, out_of_it](Stop s, Clock::time_point deadline) -> Stop {
      for (int guard = 0; guard < 100000; ++guard) {
        if (s.kind == StopKind::running) return s;
        if (s.kind != StopKind::breakpoint || std::find(sites.begin(), sites.end(), s.pc) == sites.end()) return s;
        ResumeOptions step = run;
        step.deadline = deadline;
        s = single_step(step);
        if (s.kind != StopKind::stepped) return s;
        if (out_of_it(target_->sp(), s.pc)) return s;
        ResumeOptions again = run;
        again.deadline = deadline;
        s = target_->resume(again);
      }
      return s;
    };
    pending_ = std::move(p);
    return target_->resume(run);
  }
  // No function bounds: step, over calls, until a return leaves the frame.
  Stop s;
  for (std::uint64_t n = 0; n < std::max<std::uint64_t>(o.max_steps, 1); ++n) {
    if (Clock::now() >= o.deadline) {
      s.kind = StopKind::time_limit;
      s.pc = target_->pc();
      s.detail = "still inside the function at the time limit";
      return s;
    }
    const std::uint64_t pc = target_->pc();
    const auto d = decode(pc);
    if (d && d->call) {
      s = run_to(pc + d->length, o, target_->sp());
      if (pending_) {
        if (s.kind == StopKind::running) return s;
        s = pending_->finish(s, o.deadline);
        if (s.kind == StopKind::running) return s;
        for (std::uint64_t a : pending_->temporary) target_->remove_breakpoint(BreakKind::software, a, 0);
        pending_.reset();
      }
      if (s.kind != StopKind::stepped) return s;
      continue;
    }
    s = single_step(o);
    if (s.kind != StopKind::stepped) return s;
    if (d && d->ret && sp_above(target_->sp(), sp0, false)) return s;
  }
  s.kind = StopKind::step_limit;
  s.pc = target_->pc();
  return s;
}

Stop Session::resume(RunMode mode, const ResumeOptions &options) {
  // A run passes over breakpoints whose ignore count or condition says so
  // (the stops in between are not recorded); steps stop where they stop.
  for (std::uint64_t passed = 0;; ++passed) {
    Stop s = resume_once(mode, options);
    if (s.kind == StopKind::running) return s;
    if (mode != RunMode::run || passed >= 10000000 || Clock::now() >= options.deadline ||
        (options.cancelled && options.cancelled()) || !pass_over(s)) {
      record(s);
      return s;
    }
  }
}

Stop Session::resume_once(RunMode mode, const ResumeOptions &options) {
  if (pending_ || target_->state() == TargetState::running) throw DebugError("the target is running; wait or interrupt it");
  if (target_->state() != TargetState::stopped)
    throw DebugError("the target is " + std::string(to_string(target_->state())));
  ResumeOptions o = options;
  o.mode = mode;
  Stop s;
  const bool native = target_->native_step_over();
  if (native || mode == RunMode::step_into || (mode == RunMode::run && !o.until)) {
    s = target_->resume(o);
  } else if (mode == RunMode::run) {
    s = run_to(*o.until, o, std::nullopt);
  } else if (mode == RunMode::step_over) {
    s = step_over_live(o);
  } else {
    s = step_out_live(o);
  }
  if (pending_) {
    s = pending_->finish(s, o.deadline);
    if (s.kind == StopKind::running) return s;
    if (target_->state() == TargetState::stopped)
      for (std::uint64_t a : pending_->temporary) {
        try {
          target_->remove_breakpoint(BreakKind::software, a, 0);
        } catch (const DebugError &) {
        }
      }
    pending_.reset();
    if (mode == RunMode::run && o.until && s.kind == StopKind::stepped) s.kind = StopKind::until;
  }
  if (s.kind == StopKind::running) running_mode_ = mode;
  return s;
}

Stop Session::wait(Clock::time_point deadline) {
  if (target_->state() != TargetState::running && !pending_) return last_;
  Stop s = target_->wait(deadline);
  // A run that went on in the background passes over breakpoints as resume() does.
  while (running_mode_ == RunMode::run && !pending_ && pass_over(s) && Clock::now() < deadline) {
    ResumeOptions o;
    o.deadline = deadline;
    s = target_->resume(o);
    if (s.kind == StopKind::running) s = target_->wait(deadline);
  }
  if (pending_) {
    s = pending_->finish(s, deadline);
    if (s.kind == StopKind::running) return s;
    if (target_->state() == TargetState::stopped)
      for (std::uint64_t a : pending_->temporary) {
        try {
          target_->remove_breakpoint(BreakKind::software, a, 0);
        } catch (const DebugError &) {
        }
      }
    pending_.reset();
  }
  if (s.kind != StopKind::running) record(s);
  return s;
}

// --- State ---

std::vector<std::uint8_t> Session::read_register(std::string_view name) { return target_->read_register(name); }

void Session::write_register(std::string_view name, std::span<const std::uint8_t> value) {
  target_->write_register(name, value);
  const RegisterDesc *d = target_->find_register(name);
  const std::string n = d != nullptr ? d->name : std::string(name);
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> regs{{n, target_->read_register(n)}};
  // A flag changes its parent, and the reverse.
  if (d != nullptr && !d->parent.empty()) regs.emplace_back(d->parent, target_->read_register(d->parent));
  for (const RegisterDesc &r : target_->registers())
    if (r.parent == n && r.display) regs.emplace_back(r.name, target_->read_register(r.name));
  record_edit("set " + n, std::move(regs), {});
}

std::size_t Session::read_memory(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *unreadable) {
  std::vector<ByteRange> holes;
  const std::size_t n = target_->read_memory(address, out, &holes);
  if (target_->state() == TargetState::replay) {
    if (unreadable != nullptr) *unreadable = std::move(holes);
    return n;
  }
  // Seen now: part of the current snapshot.
  std::size_t at = 0;
  for (const ByteRange &h : holes) {
    if (h.offset > at) timeline_.observe(current_snapshot(), address + at, out.subspan(at, h.offset - at));
    at = h.offset + h.length;
  }
  if (at < out.size()) timeline_.observe(current_snapshot(), address + at, out.subspan(at));
  if (unreadable != nullptr) *unreadable = std::move(holes);
  return n;
}

bool Session::write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> before(bytes.size());
  std::vector<ByteRange> holes;
  target_->read_memory(address, before, &holes);
  if (!target_->write_memory(address, bytes)) return false;
  MemoryRecord m;
  m.address = address;
  m.bytes.assign(bytes.begin(), bytes.end());
  if (holes.empty()) m.before = std::move(before);
  m.kind = MemoryRecord::Kind::write;
  record_edit("write " + std::to_string(bytes.size()) + " bytes at " + hex(address), {}, {std::move(m)});
  return true;
}

void Session::select_thread(const std::string &id) {
  target_->select_thread(id);
  // The registers shown are the new thread's: a snapshot of them.
  record_edit("thread " + id, display_registers(), {});
}

void Session::memory_at(std::uint64_t snapshot, std::uint64_t address, std::span<std::uint8_t> out,
                        std::vector<Timeline::ByteState> &state) {
  const bool complete = target_->complete_recording() && options_.record_steps;
  std::function<void(std::uint64_t, std::span<std::uint8_t>, std::vector<bool> &)> current;
  if (complete && target_->state() != TargetState::running) {
    current = [this](std::uint64_t at, std::span<std::uint8_t> buf, std::vector<bool> &readable) {
      std::vector<ByteRange> holes;
      target_->read_memory(at, buf, &holes);
      std::fill(readable.begin(), readable.end(), true);
      for (const ByteRange &h : holes)
        for (std::uint32_t i = 0; i < h.length && h.offset + i < readable.size(); ++i) readable[h.offset + i] = false;
    };
  }
  timeline_.memory_at(snapshot, address, out, state, complete, current);
}

std::vector<std::pair<std::string, std::vector<std::uint8_t>>> Session::display_registers() {
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> out;
  if (target_->state() != TargetState::stopped) return out;
  for (const RegisterDesc &r : target_->registers()) {
    if (!r.display) continue;
    try {
      out.emplace_back(r.name, target_->read_register(r.name));
    } catch (const DebugError &) {
    }
  }
  return out;
}

void Session::collect_output() {
  std::string more;
  try {
    more = target_->take_output();
  } catch (const DebugError &) {
  }
  if (more.empty()) return;
  output_total_ += more.size();
  output_ += more;
  if (output_.size() > kMaxOutput) output_.erase(0, output_.size() - kMaxOutput);
}

void Session::record_edit(const std::string &what, std::vector<std::pair<std::string, std::vector<std::uint8_t>>> regs,
                          std::vector<MemoryRecord> memory) {
  Snapshot s;
  s.kind = Snapshot::Kind::edit;
  if (const Snapshot *prev = timeline_.find(timeline_.last())) {
    s.pc = prev->pc;
    s.program_pc = prev->program_pc;
    s.steps = prev->steps;
    s.stop = prev->stop;
  }
  try {
    if (target_->state() == TargetState::stopped) {
      s.pc = target_->pc();
      s.program_pc = to_program(s.pc);
    }
  } catch (const DebugError &) {
  }
  s.thread = target_->current_thread();
  s.text = what;
  s.registers = std::move(regs);
  s.memory = std::move(memory);
  s.time_us = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started_).count();
  timeline_.add(std::move(s));
  checkpoint_now();
}

void Session::record(const Stop &stop) {
  collect_output();
  if (!mapping_.known && target_->state() == TargetState::stopped) refresh_mapping();
  resolve_pending();
  for (Breakpoint &b : breakpoints_)
    if (stop.kind == StopKind::breakpoint && b.address == stop.pc &&
        (b.kind == BreakKind::software || b.kind == BreakKind::hardware))
      ++b.hits;
    else if (stop.kind == StopKind::watchpoint && stop.address && b.kind >= BreakKind::watch_write &&
             *stop.address >= b.address && *stop.address < b.address + std::max<std::uint32_t>(b.size, 1))
      ++b.hits;
  const auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - started_).count();

  std::vector<StepRecord> steps;
  if (options_.record_steps) steps = target_->take_steps();
  auto memory_of = [](const StepRecord &r) {
    std::vector<MemoryRecord> out;
    for (const StepRecord::Access &a : r.memory) {
      MemoryRecord m;
      m.address = a.address;
      m.bytes = a.bytes;
      m.before = a.before;
      m.kind = a.write ? MemoryRecord::Kind::write : MemoryRecord::Kind::read;
      out.push_back(std::move(m));
    }
    return out;
  };
  std::uint64_t prev_steps = 0;
  bool have_prev = false;
  for (auto it = timeline_.snapshots().rbegin(); it != timeline_.snapshots().rend(); ++it) {
    prev_steps = it->steps;
    have_prev = true;
    break;
  }
  for (std::size_t i = 0; i + 1 < steps.size(); ++i) {
    Snapshot s;
    s.kind = Snapshot::Kind::step;
    s.pc = steps[i + 1].pc;
    s.program_pc = to_program(s.pc);
    s.thread = target_->current_thread();
    s.steps = steps[i].index + 1;
    s.text = steps[i].text;
    if (!steps[i].event.empty()) s.text += " ; " + steps[i].event;
    s.event = steps[i].exception;
    s.event_number = steps[i].exception_number;
    s.registers = steps[i].registers;
    s.memory = memory_of(steps[i]);
    s.time_us = now_us;
    s.gap = i == 0 && have_prev && steps[i].index != prev_steps;
    timeline_.add(std::move(s));
  }

  Snapshot s;
  s.kind = Snapshot::Kind::stop;
  s.stop = stop.kind;
  s.detail = stop.detail;
  s.thread = stop.thread.empty() ? target_->current_thread() : stop.thread;
  s.steps = target_->steps();
  s.time_us = now_us;
  s.keyframe = true;
  if (target_->state() == TargetState::stopped) {
    try {
      s.pc = target_->pc();
    } catch (const DebugError &) {
      s.pc = stop.pc;
    }
    s.registers = display_registers();
  } else {
    s.pc = stop.pc;
    if (const Snapshot *prev = timeline_.find(timeline_.last())) {
      // The process is gone: its last known state stays.
      auto regs = timeline_.registers_at(prev->index);
      s.registers.assign(regs.begin(), regs.end());
      s.pc = prev->pc;
    }
  }
  s.program_pc = to_program(s.pc);
  if (!steps.empty()) {
    const StepRecord &last = steps.back();
    s.text = last.text;
    if (!last.event.empty()) s.text += " ; " + last.event;
    s.event = last.exception;
    s.event_number = last.exception_number;
    s.memory = memory_of(last);
    s.gap = steps.size() == 1 && have_prev && last.index != prev_steps;
  }
  if (target_->state() == TargetState::stopped && !target_->complete_recording()) {
    // What a live target can't tell later: the code at pc and the stack.
    std::vector<std::uint8_t> code(16);
    std::vector<ByteRange> holes;
    try {
      if (target_->read_memory(s.pc, code, &holes) > 0 && holes.empty())
        s.memory.push_back({s.pc, code, {}, MemoryRecord::Kind::observed});
      if (options_.stack_bytes > 0) {
        const std::uint64_t sp = target_->sp();
        std::vector<std::uint8_t> stack(options_.stack_bytes);
        holes.clear();
        const std::uint64_t base = target_->stack_grows_down() ? sp : sp - options_.stack_bytes;
        if (target_->read_memory(base, stack, &holes) > 0) {
          std::size_t at = 0;
          for (const ByteRange &h : holes) {
            if (h.offset > at)
              s.memory.push_back({base + at, std::vector<std::uint8_t>(stack.begin() + at, stack.begin() + h.offset), {},
                                  MemoryRecord::Kind::observed});
            at = h.offset + h.length;
          }
          if (at < stack.size())
            s.memory.push_back({base + at, std::vector<std::uint8_t>(stack.begin() + at, stack.end()), {},
                                MemoryRecord::Kind::observed});
        }
      }
    } catch (const DebugError &) {
    }
  }
  timeline_.add(std::move(s));
  last_ = stop;
  checkpoint_now();
}

void Session::checkpoint_now() {
  auto *et = dynamic_cast<EmulatorTarget *>(target_.get());
  if (et == nullptr || !et->rewindable() || target_->state() != TargetState::stopped) return;
  try {
    et->checkpoint(timeline_.last());
    et->forget_checkpoints_before(timeline_.first());
  } catch (const std::exception &) {
  }
}

bool Session::can_rewind() const {
  const auto *et = dynamic_cast<const EmulatorTarget *>(target_.get());
  return et != nullptr && et->rewindable();
}

Stop Session::rewind(std::uint64_t snapshot) {
  auto *et = dynamic_cast<EmulatorTarget *>(target_.get());
  if (et == nullptr) throw DebugError("only the emulator can go back: a live target's past is a recording to look at");
  if (!et->rewindable()) throw DebugError("an emulator session on a machine can't go back (its peripherals aren't checkpointed)");
  if (pending_ || target_->state() == TargetState::running) throw DebugError("the target is running; wait or interrupt it");
  const Snapshot *at = timeline_.find(snapshot);
  if (at == nullptr) throw DebugError("snapshot " + std::to_string(snapshot) + " is not recorded");
  const Snapshot copy = *at;
  et->rewind(snapshot, copy.steps);
  timeline_.truncate_after(snapshot);
  Stop st;
  st.kind = copy.kind == Snapshot::Kind::step || copy.stop == StopKind::none ? StopKind::stepped : copy.stop;
  st.pc = target_->pc();
  st.thread = copy.thread;
  st.detail = "back at snapshot " + std::to_string(snapshot);
  last_ = st;
  et->set_last_stop(st);
  // The output as it was then.
  const auto &emu = et->emulator();
  output_ = emu.stdout_data() + emu.stderr_data();
  output_total_ = output_.size();
  if (output_.size() > kMaxOutput) output_.erase(0, output_.size() - kMaxOutput);
  return st;
}

Stop Session::step_back() {
  const std::uint64_t now = timeline_.last();
  if (now == timeline_.first()) throw DebugError("at the first recorded snapshot: nothing to go back to");
  return rewind(now - 1);
}

TraceHeader Session::header(const std::string &name, const std::string &program_id) const {
  TraceHeader h;
  h.name = name;
  h.program_id = program_id;
  h.language = options_.language;
  h.target_kind = target_->kind();
  h.target_description = target_->description();
  h.pc_register = target_->pc_register();
  h.sp_register = target_->sp_register();
  for (const RegisterDesc &r : target_->registers())
    if (r.display) h.registers.push_back(r);
  h.slide = mapping_.slide;
  h.created_unix = static_cast<std::int64_t>(std::time(nullptr));
  h.complete = target_->complete_recording() && options_.record_steps;
  return h;
}

}  // namespace revkit::debug
