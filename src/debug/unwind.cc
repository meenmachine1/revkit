#include "revkit/debug/unwind.hh"

#include <algorithm>
#include <stdexcept>

namespace revkit::debug {

namespace {

// --- Architectures -----------------------------------------------------------

UnwindArch X86_64() {
  UnwindArch a;
  a.names = {"RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP", "R8", "R9",
             "R10", "R11", "R12", "R13", "R14", "R15", "RIP"};
  a.sp = 7;
  a.fp = 6;
  a.ra = 16;
  a.pc_name = "RIP";
  return a;
}

UnwindArch X86_32() {
  UnwindArch a;
  a.names = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "EIP"};
  a.sp = 4;
  a.fp = 5;
  a.ra = 8;
  a.pc_name = "EIP";
  a.address_size = 4;
  a.ra_at = 4;
  a.cfa_at = 8;
  return a;
}

UnwindArch AArch64() {
  UnwindArch a;
  for (int i = 0; i <= 30; ++i) a.names.push_back("x" + std::to_string(i));
  a.names.push_back("sp");
  a.sp = 31;
  a.fp = 29;
  a.ra = 30;
  a.lr = 30;
  a.pc_name = "pc";
  a.insn_align = 4;
  return a;
}

UnwindArch Arm32() {
  UnwindArch a;
  for (int i = 0; i <= 12; ++i) a.names.push_back("r" + std::to_string(i));
  a.names.insert(a.names.end(), {"sp", "lr", "pc"});
  a.sp = 13;
  a.ra = 14;
  a.lr = 14;
  a.fp = -1;  // r11 in ARM code, r7 in Thumb, frame layouts differ: no FP walk
  a.pc_name = "pc";
  a.address_size = 4;
  a.insn_align = 2;
  return a;
}

UnwindArch RiscV(unsigned size) {
  UnwindArch a;
  a.names = {"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
             "a6",   "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
  a.sp = 2;
  a.fp = 8;
  a.ra = 1;
  a.lr = 1;
  a.pc_name = "pc";
  a.address_size = size;
  // s0 points at the frame's top: the return address and the caller's s0 below it.
  a.ra_at = -static_cast<std::int64_t>(size);
  a.prev_fp_at = -2 * static_cast<std::int64_t>(size);
  a.cfa_at = 0;
  a.insn_align = 2;
  return a;
}

// --- DWARF readers --------------------------------------------------------

class Reader {
 public:
  Reader(std::span<const std::uint8_t> bytes, std::size_t pos, std::size_t end, bool big)
      : b_(bytes), pos_(pos), end_(end), big_(big) {}
  std::size_t pos() const { return pos_; }
  void seek(std::size_t p) { pos_ = p; }
  bool done() const { return pos_ >= end_; }
  std::uint64_t uint(unsigned n) {
    if (n > end_ - std::min(pos_, end_)) throw std::out_of_range("CFI record runs past its end");
    std::uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) {
      const std::uint64_t byte = b_[pos_ + (big_ ? i : n - 1 - i)];
      v = (v << 8) | byte;
    }
    pos_ += n;
    return v;
  }
  std::uint64_t uleb() {
    std::uint64_t v = 0;
    for (unsigned shift = 0;; shift += 7) {
      if (shift > 63) throw std::out_of_range("LEB128 too long");
      const std::uint64_t byte = uint(1);
      v |= (byte & 0x7f) << shift;
      if (!(byte & 0x80)) return v;
    }
  }
  std::int64_t sleb() {
    std::int64_t v = 0;
    unsigned shift = 0;
    std::uint64_t byte = 0;
    do {
      if (shift > 63) throw std::out_of_range("LEB128 too long");
      byte = uint(1);
      v |= static_cast<std::int64_t>(byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) v |= -(static_cast<std::int64_t>(1) << shift);
    return v;
  }
  std::string cstr() {
    std::string s;
    while (true) {
      const char c = static_cast<char>(uint(1));
      if (c == 0) return s;
      s += c;
      if (s.size() > 64) throw std::out_of_range("augmentation string too long");
    }
  }
  std::vector<std::uint8_t> rest() {
    std::vector<std::uint8_t> out(b_.begin() + static_cast<std::ptrdiff_t>(pos_), b_.begin() + static_cast<std::ptrdiff_t>(end_));
    pos_ = end_;
    return out;
  }

 private:
  std::span<const std::uint8_t> b_;
  std::size_t pos_, end_;
  bool big_;
};

// A DW_EH_PE-encoded pointer. `here` is the field's own address (pcrel).
std::uint64_t Encoded(Reader &r, std::uint8_t enc, std::uint64_t here, unsigned address_size, std::int64_t delta,
                      bool &absolute) {
  std::uint64_t v = 0;
  switch (enc & 0x0f) {
    case 0x00: v = r.uint(address_size); break;  // absptr
    case 0x01: v = r.uleb(); break;
    case 0x02: v = r.uint(2); break;
    case 0x03: v = r.uint(4); break;
    case 0x04: v = r.uint(8); break;
    case 0x09: v = static_cast<std::uint64_t>(r.sleb()); break;
    case 0x0a: v = static_cast<std::uint64_t>(static_cast<std::int16_t>(r.uint(2))); break;
    case 0x0b: v = static_cast<std::uint64_t>(static_cast<std::int32_t>(r.uint(4))); break;
    case 0x0c: v = r.uint(8); break;
    default: throw std::out_of_range("unsupported pointer encoding");
  }
  absolute = false;
  switch (enc & 0x70) {
    case 0x00: absolute = true; return v + static_cast<std::uint64_t>(delta);
    case 0x10: return here + v;  // pcrel
    default: throw std::out_of_range("unsupported pointer base");
  }
}

}  // namespace

std::optional<UnwindArch> UnwindArch::for_language(std::string_view language) {
  auto starts = [&](std::string_view p) { return language.substr(0, p.size()) == p; };
  std::optional<UnwindArch> a;
  if (starts("x86:LE:64")) a = X86_64();
  else if (starts("x86:LE:32")) a = X86_32();
  else if (starts("AARCH64:")) a = AArch64();
  else if (starts("ARM:")) a = Arm32();
  else if (starts("RISCV:LE:64")) a = RiscV(8);
  else if (starts("RISCV:LE:32")) a = RiscV(4);
  if (a && language.find(":BE:") != std::string_view::npos) a->big_endian = true;
  return a;
}

// --- CFI tables -------------------------------------------------------------

std::shared_ptr<const CfiTable> CfiTable::from_image(const loader::Image &image) {
  auto t = std::make_shared<CfiTable>();
  if (!image.file) return t;
  const unsigned size = image.bits / 8;
  const bool big = image.endian == loader::Endian::big;
  const std::int64_t delta = static_cast<std::int64_t>(image.image_base - image.file_base);
  const auto &file = *image.file;
  for (const loader::Section &s : image.sections) {
    const bool eh = s.name == ".eh_frame";
    if (!eh && s.name != ".debug_frame") continue;
    if (s.file_size == 0 || s.offset > file.size() || s.file_size > file.size() - s.offset) continue;
    std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t *>(file.data()) + s.offset, s.file_size);
    t->add_section(bytes, eh ? s.addr : 0, eh, size, big, delta);
  }
  return t;
}

void CfiTable::add_section(std::span<const std::uint8_t> bytes, std::uint64_t address, bool eh, unsigned address_size,
                           bool big_endian, std::int64_t delta) {
  std::map<std::size_t, std::shared_ptr<Cie>> cies;
  std::size_t off = 0;
  try {
    for (std::size_t n = 0; n < (1u << 22) && off + 4 <= bytes.size(); ++n) {
      Reader r(bytes, off, bytes.size(), big_endian);
      std::uint64_t len = r.uint(4);
      if (len == 0) {
        if (eh) break;  // .eh_frame's terminator
        off += 4;
        continue;
      }
      bool wide = false;
      if (len == 0xffffffff) {
        len = r.uint(8);
        wide = true;
      }
      const std::size_t body = r.pos();
      if (len > bytes.size() - body) break;
      const std::size_t next = body + static_cast<std::size_t>(len);
      Reader c(bytes, body, next, big_endian);
      const std::size_t id_pos = c.pos();
      const std::uint64_t id = c.uint(wide ? 8 : 4);
      const bool is_cie = eh ? id == 0 : id == (wide ? 0xffffffffffffffffull : 0xffffffffull);
      if (is_cie) {
        auto cie = std::make_shared<Cie>();
        const auto version = static_cast<std::uint8_t>(c.uint(1));
        const std::string aug = c.cstr();
        if (aug.find("eh") != std::string::npos) c.uint(address_size);
        if (!eh && version >= 4) {
          c.uint(1);  // address_size
          c.uint(1);  // segment selector size
        }
        cie->code_align = c.uleb();
        cie->data_align = c.sleb();
        cie->ra = version == 1 ? static_cast<int>(c.uint(1)) : static_cast<int>(c.uleb());
        cie->fde_enc = 0;
        bool usable = true;
        cie->has_z = !aug.empty() && aug[0] == 'z';
        if (cie->has_z) {
          const std::uint64_t alen = c.uleb();
          const std::size_t aend = c.pos() + static_cast<std::size_t>(alen);
          for (std::size_t i = 1; i < aug.size(); ++i) {
            if (aug[i] == 'R') cie->fde_enc = static_cast<std::uint8_t>(c.uint(1));
            else if (aug[i] == 'L') c.uint(1);
            else if (aug[i] == 'P') {
              const auto penc = static_cast<std::uint8_t>(c.uint(1));
              bool abs = false;
              Encoded(c, penc & 0x7f, address + c.pos(), address_size, delta, abs);
            } else if (aug[i] != 'S' && aug[i] != 'B') {
              usable = false;
              break;
            }
          }
          c.seek(aend);
        } else if (!aug.empty() && aug != "eh") {
          usable = false;
        }
        if (usable) {
          cie->instructions = c.rest();
          cies[off] = cie;
        }
      } else {
        const std::size_t cie_at = eh ? id_pos - static_cast<std::size_t>(id) : static_cast<std::size_t>(id);
        auto it = cies.find(cie_at);
        if (it != cies.end()) {
          const Cie &cie = *it->second;
          Fde f;
          f.cie = it->second;
          f.address_size = address_size;
          f.big_endian = big_endian;
          bool abs = false;
          if (eh) {
            f.start = Encoded(c, cie.fde_enc, address + c.pos(), address_size, delta, abs);
            const std::uint64_t range = Encoded(c, cie.fde_enc & 0x0f, 0, address_size, 0, abs);
            f.end = f.start + range;
            // A 'z' CIE's FDEs carry augmentation data (an LSDA pointer) first.
            if (cie.has_z) c.seek(c.pos() + static_cast<std::size_t>(c.uleb()));
          } else {
            f.start = c.uint(address_size) + static_cast<std::uint64_t>(delta);
            f.end = f.start + c.uint(address_size);
          }
          f.instructions = c.rest();
          if (f.end > f.start) fdes_.push_back(std::move(f));
        }
      }
      off = next;
    }
  } catch (const std::out_of_range &) {
    // A malformed record ends this section's walk.
  }
  std::sort(fdes_.begin(), fdes_.end(), [](const Fde &a, const Fde &b) { return a.start < b.start; });
}

std::optional<CfiRow> CfiTable::row_at(std::uint64_t pc) const {
  auto it = std::upper_bound(fdes_.begin(), fdes_.end(), pc, [](std::uint64_t p, const Fde &f) { return p < f.start; });
  if (it == fdes_.begin()) return std::nullopt;
  --it;
  if (pc < it->start || pc >= it->end) {
    // Overlapping FDEs: look back a little for one that covers it.
    bool found = false;
    for (int k = 0; k < 8 && it != fdes_.begin() && !found; ++k) {
      --it;
      found = pc >= it->start && pc < it->end;
    }
    if (!found) return std::nullopt;
  }
  const Fde &f = *it;
  const Cie &cie = *f.cie;
  CfiRow row;
  row.ra = cie.ra;
  CfiRow initial;
  std::vector<CfiRow> stack;
  std::uint64_t loc = f.start;
  auto run = [&](const std::vector<std::uint8_t> &prog, bool is_cie) -> bool {
    Reader r(prog, 0, prog.size(), f.big_endian);
    try {
      while (!r.done()) {
        const auto op = static_cast<std::uint8_t>(r.uint(1));
        const std::uint8_t hi = op & 0xc0, lo = op & 0x3f;
        auto offset_rule = [&](std::uint64_t reg, std::int64_t factored) {
          row.rules[static_cast<int>(reg)] = {CfiRule::Kind::offset, factored * cie.data_align};
        };
        auto advance = [&](std::uint64_t delta) {
          loc += delta * cie.code_align;
          return loc <= pc;
        };
        if (hi == 0x40) {
          if (!is_cie && !advance(lo)) return false;
          continue;
        }
        if (hi == 0x80) {
          offset_rule(lo, static_cast<std::int64_t>(r.uleb()));
          continue;
        }
        if (hi == 0xc0) {
          if (auto i = initial.rules.find(lo); i != initial.rules.end()) row.rules[lo] = i->second;
          else row.rules.erase(lo);
          continue;
        }
        switch (op) {
          case 0x00: break;  // nop
          case 0x01: {       // set_loc
            bool abs = false;
            loc = Encoded(r, cie.fde_enc, 0, f.address_size, 0, abs);
            if (loc > pc) return false;
            break;
          }
          case 0x02: if (!is_cie && !advance(r.uint(1))) return false; break;
          case 0x03: if (!is_cie && !advance(r.uint(2))) return false; break;
          case 0x04: if (!is_cie && !advance(r.uint(4))) return false; break;
          case 0x05: { const auto reg = r.uleb(); offset_rule(reg, static_cast<std::int64_t>(r.uleb())); break; }
          case 0x06: {
            const int reg = static_cast<int>(r.uleb());
            if (auto i = initial.rules.find(reg); i != initial.rules.end()) row.rules[reg] = i->second;
            else row.rules.erase(reg);
            break;
          }
          case 0x07: row.rules[static_cast<int>(r.uleb())] = {CfiRule::Kind::undefined, 0}; break;
          case 0x08: row.rules[static_cast<int>(r.uleb())] = {CfiRule::Kind::same, 0}; break;
          case 0x09: {
            const int reg = static_cast<int>(r.uleb());
            row.rules[reg] = {CfiRule::Kind::reg, static_cast<std::int64_t>(r.uleb())};
            break;
          }
          case 0x0a: stack.push_back(row); break;
          case 0x0b:
            if (!stack.empty()) {
              // The CFA stays; the register rules come back.
              const int cr = row.cfa_reg;
              const std::int64_t co = row.cfa_offset;
              const bool ce = row.cfa_expression;
              row = stack.back();
              stack.pop_back();
              row.cfa_reg = cr;
              row.cfa_offset = co;
              row.cfa_expression = ce;
            }
            break;
          case 0x0c:
            row.cfa_reg = static_cast<int>(r.uleb());
            row.cfa_offset = static_cast<std::int64_t>(r.uleb());
            row.cfa_expression = false;
            break;
          case 0x0d: row.cfa_reg = static_cast<int>(r.uleb()); row.cfa_expression = false; break;
          case 0x0e: row.cfa_offset = static_cast<std::int64_t>(r.uleb()); break;
          case 0x0f: r.seek(r.pos() + static_cast<std::size_t>(r.uleb())); row.cfa_expression = true; break;
          case 0x10: {
            const int reg = static_cast<int>(r.uleb());
            r.seek(r.pos() + static_cast<std::size_t>(r.uleb()));
            row.rules[reg] = {CfiRule::Kind::expression, 0};
            break;
          }
          case 0x11: { const auto reg = r.uleb(); offset_rule(reg, r.sleb()); break; }
          case 0x12:
            row.cfa_reg = static_cast<int>(r.uleb());
            row.cfa_offset = r.sleb() * cie.data_align;
            row.cfa_expression = false;
            break;
          case 0x13: row.cfa_offset = r.sleb() * cie.data_align; break;
          case 0x14: {
            const int reg = static_cast<int>(r.uleb());
            row.rules[reg] = {CfiRule::Kind::val_offset, static_cast<std::int64_t>(r.uleb()) * cie.data_align};
            break;
          }
          case 0x15: {
            const int reg = static_cast<int>(r.uleb());
            row.rules[reg] = {CfiRule::Kind::val_offset, r.sleb() * cie.data_align};
            break;
          }
          case 0x16: {
            const int reg = static_cast<int>(r.uleb());
            r.seek(r.pos() + static_cast<std::size_t>(r.uleb()));
            row.rules[reg] = {CfiRule::Kind::expression, 0};
            break;
          }
          case 0x2d: break;          // AArch64 negate_ra_state (pointer authentication)
          case 0x2e: r.uleb(); break;  // GNU_args_size
          case 0x2f: {                 // GNU_negative_offset_extended
            const auto reg = r.uleb();
            offset_rule(reg, -static_cast<std::int64_t>(r.uleb()));
            break;
          }
          default: return false;  // an op this doesn't know: stop at what is known
        }
      }
    } catch (const std::out_of_range &) {
      return false;
    }
    return true;
  };
  run(cie.instructions, true);
  initial = row;
  run(f.instructions, false);
  if (row.cfa_reg < 0 && !row.cfa_expression) return std::nullopt;
  return row;
}

// --- Unwinding ----------------------------------------------------------------

std::vector<Frame> unwind(const UnwindArch &arch, const UnwindSource &src, std::size_t max_frames) {
  std::vector<Frame> frames;
  if (!src.reg) return frames;
  const std::uint64_t mask = arch.address_size >= 8 ? ~0ull : ((1ull << (8 * arch.address_size)) - 1);
  std::map<int, std::uint64_t> regs;
  for (std::size_t i = 0; i < arch.names.size(); ++i)
    if (!arch.names[i].empty())
      if (auto v = src.reg(arch.names[i])) regs[static_cast<int>(i)] = *v & mask;
  auto pc0 = src.reg(arch.pc_name);
  if (!pc0) return frames;
  std::uint64_t pc = *pc0 & mask;

  auto read = [&](std::uint64_t a) -> std::optional<std::uint64_t> {
    if (!src.read) return std::nullopt;
    auto v = src.read(a & mask, arch.address_size);
    if (v) return *v & mask;
    return std::nullopt;
  };
  auto code = [&](std::uint64_t a) { return a != 0 && (!src.is_code || src.is_code(a)); };
  auto returns_here = [&](std::uint64_t a) {
    if (!code(a)) return false;
    if (arch.insn_align > 1 && (a & (arch.insn_align - 1)) != 0 && arch.insn_align != 2) return false;
    return !src.after_call || src.after_call(a);
  };
  auto snapshot = [&](std::uint64_t at, const std::string &how) {
    Frame f;
    f.pc = at;
    f.how = how;
    if (auto it = regs.find(arch.sp); it != regs.end()) f.sp = it->second;
    f.registers.push_back({arch.pc_name, at});
    for (const auto &[n, v] : regs)
      if (n >= 0 && static_cast<std::size_t>(n) < arch.names.size() && !arch.names[static_cast<std::size_t>(n)].empty())
        f.registers.push_back({arch.names[static_cast<std::size_t>(n)], v});
    return f;
  };
  frames.push_back(snapshot(pc, "registers"));

  while (frames.size() < max_frames) {
    const bool first = frames.size() == 1;
    const std::uint64_t lookup = first ? pc : pc - 1;
    std::optional<std::uint64_t> next;
    std::map<int, std::uint64_t> caller;
    std::uint64_t cfa = 0;
    std::string how;
    bool outermost = false;

    if (src.cfi)
      if (auto row = src.cfi(lookup); row && !row->cfa_expression && row->cfa_reg >= 0) {
        if (auto r = regs.find(row->cfa_reg); r != regs.end()) {
          cfa = (r->second + static_cast<std::uint64_t>(row->cfa_offset)) & mask;
          caller = regs;
          for (const auto &[reg, rule] : row->rules) {
            switch (rule.kind) {
              case CfiRule::Kind::undefined: caller.erase(reg); break;
              case CfiRule::Kind::same: break;
              case CfiRule::Kind::offset:
                if (auto v = read(cfa + static_cast<std::uint64_t>(rule.n))) caller[reg] = *v;
                else caller.erase(reg);
                break;
              case CfiRule::Kind::val_offset: caller[reg] = (cfa + static_cast<std::uint64_t>(rule.n)) & mask; break;
              case CfiRule::Kind::reg:
                if (auto v = regs.find(static_cast<int>(rule.n)); v != regs.end()) caller[reg] = v->second;
                else caller.erase(reg);
                break;
              case CfiRule::Kind::expression: caller.erase(reg); break;
            }
          }
          const int ra = row->ra >= 0 ? row->ra : arch.ra;
          if (auto rr = row->rules.find(ra); rr != row->rules.end() && rr->second.kind == CfiRule::Kind::undefined) {
            outermost = true;  // the CFI says this is the outermost frame (_start)
          } else if (auto v = caller.find(ra); v != caller.end() && v->second != 0) {
            next = v->second;
            caller[arch.sp] = cfa;
            how = "cfi";
          }
        }
      }
    if (outermost) break;

    // At a function's first instruction its frame isn't built yet: the
    // return address is where the call left it.
    if (!next && first && src.at_entry && src.at_entry(pc)) {
      if (arch.lr >= 0) {
        if (auto l = regs.find(arch.lr); l != regs.end() && code(l->second & ~1ull)) {
          next = l->second;
          caller = regs;
          how = "entry";
        }
      } else if (auto sp = regs.find(arch.sp); sp != regs.end()) {
        if (auto ra = read(sp->second); ra && code(*ra)) {
          next = *ra;
          cfa = (sp->second + arch.address_size) & mask;
          caller = regs;
          caller[arch.sp] = cfa;
          how = "entry";
        }
      }
    }

    if (!next && arch.fp >= 0)
      if (auto f = regs.find(arch.fp); f != regs.end() && f->second != 0 && (f->second % arch.address_size) == 0) {
        const std::uint64_t fp = f->second;
        const auto sp = regs.find(arch.sp);
        const bool plausible = sp == regs.end() || (fp + 0x10000 >= sp->second && fp - sp->second < (8ull << 20));
        if (plausible) {
          auto ra = read(fp + static_cast<std::uint64_t>(arch.ra_at));
          auto prev = read(fp + static_cast<std::uint64_t>(arch.prev_fp_at));
          if (ra && returns_here(*ra)) {
            next = *ra;
            cfa = (fp + static_cast<std::uint64_t>(arch.cfa_at)) & mask;
            caller = regs;
            if (prev) caller[arch.fp] = *prev;
            else caller.erase(arch.fp);
            caller[arch.sp] = cfa;
            how = "frame pointer";
          }
        }
      }

    if (!next && first && arch.lr >= 0)
      if (auto l = regs.find(arch.lr); l != regs.end() && returns_here(l->second & ~1ull)) {
        next = l->second;
        caller = regs;
        how = "link register";
      }

    if (!next)
      if (auto sp = regs.find(arch.sp); sp != regs.end()) {
        for (unsigned k = 0; k < 512 && !next; ++k) {
          const std::uint64_t at = sp->second + k * arch.address_size;
          if (auto w = read(at); w && returns_here(*w)) {
            next = *w;
            cfa = (at + arch.address_size) & mask;
            caller = regs;
            caller[arch.sp] = cfa;
            how = "stack scan";
          }
        }
      }

    if (!next) break;
    std::uint64_t npc = *next;
    if (arch.insn_align == 2) npc &= ~1ull;  // Thumb return addresses
    const auto old_sp = regs.find(arch.sp), new_sp = caller.find(arch.sp);
    // The stack must grow toward the caller (a leaf's caller, on an ISA with
    // a link register, may share its stack pointer).
    if (old_sp != regs.end() && new_sp != caller.end() &&
        (new_sp->second < old_sp->second || (new_sp->second == old_sp->second && !first)))
      break;
    if (npc == pc && (how == "link register" || how == "entry")) break;
    if (!code(npc)) break;
    frames.back().cfa = cfa;
    regs = std::move(caller);
    pc = npc;
    frames.push_back(snapshot(pc, how));
  }
  return frames;
}

}  // namespace revkit::debug
