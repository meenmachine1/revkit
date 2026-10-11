// The firmware search: function starts in code nothing reached, by the
// language's start patterns (Ghidra's Function Start Search), where the
// bytes before them say what Ghidra's "after" conditions ask for. Code
// pointers (loaded from literal pools, or in tables of pointers) count as
// the data references "after ptr" and "after defined" accept.

#include "internal.h"

#include <algorithm>
#include <map>
#include <optional>
#include <string>

namespace revkit::analysis::detail {

using namespace std::string_view_literals;

namespace {

// Patterns that share their bytes from the start on, tried together.
struct Group {
  std::vector<std::uint8_t> value, mask;  // from the start
  std::uint32_t align = 1;
  std::int32_t isa = -1;
  std::vector<const StartPattern *> patterns;
};

}  // namespace

bool guards_prologue(const ProgramInfo &info, std::uint64_t from, std::uint64_t prologue, bool thumb, ByteReader &bytes,
                     Decoder &decoder) {
  if (from >= prologue || prologue - from > kGuardSpan) return false;
  bool exits = false;
  Evaluator eval(info, nullptr);
  std::uint64_t counted = 0;  // the guard's bytes, delay slots aside
  for (std::uint64_t a = from; a != prologue;) {
    if (a > prologue || !info.is_code(a)) return false;
    auto insn = decoder.decode(a, bytes, thumb && !info.thumb(a));
    if (!insn || insn->unimplemented || insn->pcode.empty() || zero_instruction(*insn, bytes)) return false;
    counted += insn->length;
    if (counted > kGuardBytes) return false;
    // A guard tests and loads; it doesn't store (a literal pool's words
    // before the function often decode to stores).
    for (const lift::PcodeOp &op : insn->pcode)
      if (op.opcode == "STORE"sv) return false;
    const InsnFlow f = classify(*insn, info.code_space);
    if (!f.falls_through) return false;
    eval.step(*insn);
    switch (f.kind) {
      case FlowKind::fall: break;
      case FlowKind::branch:
      case FlowKind::ret:
        for (std::uint64_t t : f.targets)
          if (t <= prologue || t - prologue > 4096) return false;
        // It tests what the function was given, not a value the bytes
        // before it set (data read as code: movs r0, #0; cbz r0, x).
        if (const auto &c = eval.branch_condition(); c && c->known()) return false;
        exits = true;
        break;
      default: return false;
    }
    a += insn->length + insn->delay_slot;
  }
  return exits;
}

// (internal.h)
bool valid_subroutine(const ProgramInfo &info, const Known &known, std::uint64_t start, bool thumb, ByteReader &bytes,
                      Decoder &decoder, std::map<std::uint64_t, std::uint32_t> *flow) {
  const Ranges &code = known.code;
  const Ranges &data = known.data;
  constexpr std::size_t kMaxInstructions = 1000;
  {
    auto first = bytes.read(start, 8);
    if (first.size() == 8 && std::all_of(first.begin(), first.end(), [](std::byte b) { return b == std::byte{0}; }))
      return false;
  }
  std::map<std::uint64_t, std::uint32_t> insns;  // address -> length
  std::vector<std::uint64_t> work{start}, jumps;
  bool terminates = false;
  std::size_t count = 0;
  while (!work.empty() && count < kMaxInstructions) {
    std::uint64_t a = work.back();
    work.pop_back();
    std::vector<std::uint8_t> last;  // the previous instruction's bytes
    unsigned repeats = 0;
    while (count < kMaxInstructions && !insns.contains(a)) {
      if (!info.is_code(a) || code.contains(a)) return false;
      auto insn = decoder.decode(a, bytes, thumb && !info.thumb(a));
      if (!insn || insn->unimplemented || zero_instruction(*insn, bytes)) return false;
      const std::uint64_t len = insn->length + insn->delay_slot;
      if (data.intersects(a, a + len - 1) || code.intersects(a, a + len - 1)) return false;
      {
        auto raw = bytes.read(a, insn->length);
        std::vector<std::uint8_t> cur;
        for (std::byte b : raw) cur.push_back(std::to_integer<std::uint8_t>(b));
        repeats = cur == last ? repeats + 1 : 0;
        if (repeats >= 4) return false;
        last = std::move(cur);
      }
      insns.emplace(a, static_cast<std::uint32_t>(len));
      ++count;
      InsnFlow f = classify(*insn, info.code_space);
      const std::uint64_t next = a + len;
      switch (f.kind) {
        case FlowKind::ret:
        case FlowKind::jump_indirect: terminates = true; break;
        case FlowKind::jump:
        case FlowKind::branch:
          for (std::uint64_t t : f.targets) {
            if (t == next && insn->delay_slot == 0 && f.falls_through) return false;
            if (code.contains(t)) {
              if (!known.at(t)) return false;  // into the middle of known code
              terminates = true;                       // a tail jump to it
              continue;
            }
            jumps.push_back(t);
            work.push_back(t);
          }
          break;
        default: break;
      }
      if (!f.falls_through) break;
      a = next;
    }
  }
  for (std::uint64_t t : jumps) {
    auto it = insns.upper_bound(t);
    if (it != insns.begin() && std::prev(it)->first != t && t - std::prev(it)->first < std::prev(it)->second)
      return false;  // into the middle of one of its instructions
  }
  if (!terminates || count <= 1) return false;
  if (flow) *flow = std::move(insns);
  return true;
}

std::map<std::uint64_t, bool> search_starts(const ProgramInfo &info, const SearchInput &in, ByteReader &bytes,
                                            Decoder &decoder, bool from_pointers) {
  std::map<std::uint64_t, bool> out;
  const Known known(in);
  const Ranges &code = known.code;
  const Ranges &data = known.data;
  const bool interwork = !info.isa_context.empty();

  std::map<std::tuple<std::vector<std::uint8_t>, std::vector<std::uint8_t>, std::uint32_t, std::int32_t>, Group> by_post;
  for (const StartPattern &p : info.patterns) {
    std::vector<std::uint8_t> v(p.value.begin() + p.pre, p.value.end()), m(p.mask.begin() + p.pre, p.mask.end());
    Group &g = by_post[{v, m, p.align, p.isa}];
    g.value = v;
    g.mask = m;
    g.align = p.align;
    g.isa = p.isa;
    g.patterns.push_back(&p);
  }

  // Tables of pointers in memory that isn't code (an ELF's data: a command
  // table of names and handlers, an ops structure): a run of words that
  // all point into the program, three or more of them into code; the code
  // they point at is a candidate as a constant code loads is, as Ghidra's
  // address-table analysis makes them. (A raw image is all code; its
  // tables only strengthen start patterns, below.)
  std::set<std::uint64_t> table_pointers;
  if (from_pointers && (info.pointer_size == 4 || info.pointer_size == 8)) {
    const unsigned word = info.pointer_size;
    for (const Range &r : info.mapped) {
      std::vector<std::uint64_t> run;  // the code pointers of the current run
      auto flush = [&] {
        if (run.size() >= 3) table_pointers.insert(run.begin(), run.end());
        run.clear();
      };
      for (std::uint64_t a = (r.first + word - 1) / word * word; a + word - 1 <= r.last && a >= r.first; a += word) {
        if (info.is_code(a)) {
          flush();
          continue;
        }
        auto v = bytes.uint(a, word, info.big_endian);
        if (!v || *v < 0x100 || !info.is_mapped(info.code_address(*v))) {
          flush();
          continue;
        }
        const std::uint64_t target = info.code_address(*v);
        const bool thumb = interwork && (*v & 1) != 0;
        if (info.is_code(target) && target % (thumb ? 2 : (interwork ? 4 : 1)) == 0)
          run.push_back(info.code_key(target, thumb));
      }
      flush();
    }
  }

  // Each code range's bytes, read once.
  for (const Range &range : info.code) {
    const std::uint64_t size = range.last - range.first + 1;
    if (size > (std::uint64_t{1} << 31)) continue;
    std::vector<std::uint8_t> buf;
    {
      auto b = bytes.read(range.first, static_cast<std::size_t>(size));
      buf.reserve(b.size());
      for (std::byte x : b) buf.push_back(std::to_integer<std::uint8_t>(x));
    }
    auto byte_at = [&](std::uint64_t a, std::uint8_t &v) {
      if (a < range.first || a - range.first >= buf.size()) return false;
      v = buf[static_cast<std::size_t>(a - range.first)];
      return true;
    };
    auto matches = [&](std::uint64_t at, const std::vector<std::uint8_t> &value, const std::vector<std::uint8_t> &mask) {
      std::uint8_t b = 0;
      for (std::size_t i = 0; i < value.size(); ++i)
        if (!byte_at(at + i, b) || (b & mask[i]) != value[i]) return false;
      return true;
    };

    // Code pointers here: what literal pools held, and tables of them
    // (three or more in a row) in what isn't code.
    std::set<std::uint64_t> pointers(in.pointers.begin(), in.pointers.end());
    const unsigned word = info.pointer_size;
    if (word == 4 || word == 8) {
      std::vector<std::uint64_t> run;
      auto flush = [&] {
        if (run.size() >= 3) pointers.insert(run.begin(), run.end());
        run.clear();
      };
      for (std::uint64_t a = (range.first + word - 1) / word * word; a + word - 1 <= range.last && a >= range.first;
           a += word) {
        if (code.intersects(a, a + word - 1)) {
          flush();
          continue;
        }
        std::uint64_t v = 0;
        for (unsigned i = 0; i < word; ++i) {
          std::uint8_t b = 0;
          byte_at(a + i, b);
          const unsigned shift = info.big_endian ? 8 * (word - 1 - i) : 8 * i;
          v |= std::uint64_t{b} << shift;
        }
        const std::uint64_t target = info.code_address(v);
        const bool thumb = interwork && (v & 1) != 0;
        if (v >= 0x100 && info.is_code(target) && target % (thumb ? 2 : (interwork ? 4 : 1)) == 0 &&
            !code.contains(target) && !data.contains(target))
          run.push_back(info.code_key(target, thumb));
        else
          flush();
      }
      flush();
    }

    // Whether instructions decode from `start`: at least `min` in a row
    // (up to `max`), each falling through to the next, until one doesn't
    // or the run reaches known code; none may overlap known data.
    auto valid_code = [&](std::uint64_t start, bool thumb, unsigned min, unsigned max) {
      if (min == 0) return true;
      if (max < min) max = min;
      std::uint64_t a = start;
      for (unsigned n = 0; n < max; ++n) {
        if (n > 0 && code.contains(a)) return true;  // joins known code
        if (!info.is_code(a)) return false;
        auto insn = decoder.decode(a, bytes, thumb && !info.thumb(a));
        if (!insn || insn->unimplemented || insn->pcode.empty()) return false;
        const std::uint64_t len = insn->length + insn->delay_slot;
        if (data.intersects(a, a + len - 1) || (n > 0 && code.intersects(a, a + len - 1))) return false;
        InsnFlow f = classify(*insn, info.code_space);
        if (!f.falls_through) return n + 1 >= min;
        a += len;
      }
      return true;
    };

    auto valid_subroutine = [&](std::uint64_t start, bool thumb) {
      return detail::valid_subroutine(info, known, start, thumb, bytes, decoder);
    };
    // A C string (what Ghidra's string analysis defines before references
    // are looked at): printable characters up to a NUL, four or more.
    auto looks_like_string = [&](std::uint64_t a) {
      auto b = bytes.read(a, 64);
      std::size_t n = 0;
      while (n < b.size()) {
        const auto c = std::to_integer<std::uint8_t>(b[n]);
        if (c == 0) break;
        if (!((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t')) return false;
        ++n;
      }
      return n >= 4 && (n < b.size() || n == 64);
    };
    // Pointer data (a table of addresses, a relocation table under .bss):
    // one of the first two words is itself an address in the image.
    auto looks_like_pointers = [&](std::uint64_t a) {
      const unsigned w = info.pointer_size;
      if (w != 4 && w != 8) return false;
      for (std::uint64_t at = (a + w - 1) / w * w; at < a + 2 * w; at += w) {
        auto v = bytes.uint(at, w, info.big_endian);
        if (v && *v >= 0x1000 && info.is_code(info.code_address(*v))) return true;
      }
      return false;
    };
    // Constants that code loads and that point into code nothing reached:
    // a function where the code there is a valid subroutine (Ghidra's
    // Reference analyzer, for every processor; the start patterns only
    // know some prologues). Tables of pointers in a raw image's code aren't
    // asked: a switch's case labels are such tables; tables in data (above)
    // are.
    std::vector<std::uint64_t> candidates(in.pointers.begin(), in.pointers.end());
    candidates.insert(candidates.end(), table_pointers.begin(), table_pointers.end());
    for (std::uint64_t p : candidates) {
      if (!from_pointers) break;
      // Masks (0xffff, 0x3fff) aren't addresses, as Ghidra suspects them.
      if (((p + 1) & p) == 0 || p < 0x100) continue;
      const std::uint64_t target = info.code_address(p);
      if (target < range.first || target > range.last || out.contains(p)) continue;
      // (An odd string address reads as a Thumb pointer: check both.)
      if (code.contains(target) || data.contains(target) || looks_like_string(target) || looks_like_string(p) ||
          looks_like_pointers(target))
        continue;
      // (Like a "possible" pattern start: dropped if another function's
      // code runs into it and nothing calls it.)
      if (starts_in_text(bytes, target) || high_entropy(bytes, target)) continue;
      if (valid_subroutine(target, info.thumb(p))) out.emplace(p, true);
    }
    // An ARM exception vector table inside the image (a second program
    // linked after a boot loader, with vectors of its own): a branch to its
    // reset code, then ldr pc, [pc, #n] for the other seven; the reset code is
    // a function start as the processor's own vectors' are. (The ldr's
    // handlers are absolute addresses, for wherever that program is linked.)
    if (!from_pointers && interwork && two_instruction_sets(info)) {
      auto word = [&](std::uint64_t a) { return bytes.uint(a, 4, info.big_endian); };
      for (std::uint64_t a = (range.first + 3) & ~std::uint64_t{3}; a + 32 <= range.last + 1; a += 4) {
        auto w0 = word(a);
        if (!w0 || (*w0 >> 24) != 0xea || code.intersects(a, a + 31) || data.intersects(a, a + 31)) continue;
        // The handlers through ldr pc, [pc, #n], all with one n (one slot,
        // the reserved one, may hold anything): eight branches in a row are
        // as likely a switch's branch table.
        unsigned loads = 0;
        std::optional<std::uint64_t> n;
        for (std::uint64_t k = 1; k < 8; ++k) {
          auto w = word(a + 4 * k);
          if (!w || (*w & 0xfffff000) != 0xe59ff000) continue;
          if (n && *n != (*w & 0xfff)) {
            loads = 0;
            break;
          }
          n = *w & 0xfff;
          ++loads;
        }
        if (loads < 6) continue;
        const auto offset = static_cast<std::int64_t>(static_cast<std::int32_t>(*w0 << 8) >> 8) * 4;
        const std::uint64_t reset = a + 8 + static_cast<std::uint64_t>(offset);
        if ((reset < a || reset >= a + 32) && info.is_code(reset) && !code.contains(reset) && !data.contains(reset))
          out[info.code_key(reset, false)] = false;
        a += 28;
      }
    }
    if (by_post.empty() || from_pointers) continue;

    // A shrink-wrapped prologue (see guards_prologue): the start is where
    // the gap before it begins, after the code or data before it.
    auto guarded_start = [&](std::uint64_t s, bool thumb, std::uint32_t align) -> std::optional<std::uint64_t> {
      std::uint64_t g = s;
      while (g > range.first && s - g < kGuardSpan && !code.contains(g - 1) && !data.contains(g - 1)) --g;
      if (g == s || (g != range.first && !code.contains(g - 1) && !data.contains(g - 1))) return std::nullopt;
      if (align > 1) g = (g + align - 1) / align * align;
      if (g >= s || !guards_prologue(info, g, s, thumb, bytes, decoder)) return std::nullopt;
      return g;
    };

    std::uint32_t step = ~std::uint32_t{0};
    for (const auto &[key, g] : by_post) step = std::min(step, g.align);
    for (std::uint64_t s = range.first; s <= range.last; ++s) {
      if (s % step != 0) continue;
      if (const Range *c = code.find(s)) {
        if (c->last >= range.last) break;
        s = c->last;  // the loop's ++ steps past it
        continue;
      }
      if (const Range *d = data.find(s)) {
        if (d->last >= range.last) break;
        s = d->last;
        continue;
      }
      for (const auto &[key, g] : by_post) {
        if (s % g.align != 0) continue;
        if (!matches(s, g.value, g.mask)) continue;
        const bool thumb = interwork && g.isa == 1;
        const std::uint64_t entry = info.code_key(s, thumb);
        if (auto it = out.find(entry); it != out.end() && !it->second) continue;  // a definite start already
        for (const StartPattern *p : g.patterns) {
          if (p->pre > s - range.first) continue;
          if (p->pre != 0 &&
              !matches(s - p->pre, std::vector<std::uint8_t>(p->value.begin(), p->value.begin() + p->pre),
                       std::vector<std::uint8_t>(p->mask.begin(), p->mask.begin() + p->pre)))
            continue;
          // What comes right before the start; a block's first byte comes
          // after nothing, which every condition accepts.
          bool after = true;
          if (s != range.first) {
            const std::uint64_t prev = s - 1;
            const bool pointed = pointers.contains(entry);
            switch (p->after) {
              case StartPattern::After::any: break;
              case StartPattern::After::defined: after = code.contains(prev) || data.contains(prev) || pointed; break;
              case StartPattern::After::function:
              case StartPattern::After::instruction: after = code.contains(prev); break;
              case StartPattern::After::data: after = data.contains(prev); break;
              case StartPattern::After::pointer: after = pointed; break;
            }
          }
          if (!after) continue;
          if (!valid_code(s, thumb, p->valid_min, p->valid_max ? p->valid_max : p->valid_min)) continue;
          const bool possible = p->kind == StartPattern::Kind::possible;
          std::uint64_t start = entry;
          if (auto at = guarded_start(s, thumb, g.align)) start = info.code_key(*at, thumb);
          auto [it, inserted] = out.emplace(start, possible);
          if (!inserted) it->second = it->second && possible;
          if (!possible) break;
        }
      }
    }
  }
  return out;
}

bool saves_return_address(const ProgramInfo &info, std::uint64_t key, ByteReader &bytes, Decoder &decoder) {
  if (!info.link_register) return false;
  const std::uint64_t start = info.code_address(key);
  Evaluator eval(info, nullptr);
  std::uint64_t a = start;
  // Up to two instructions of the prologue's own, and early exits before
  // it (a shrink-wrapped prologue: guards_prologue, which counts no delay
  // slots).
  std::uint64_t counted = 0;
  for (int n = 0; n < 2 && counted <= kGuardBytes && a - start <= kGuardSpan;) {
    if (!info.is_code(a)) return false;
    auto insn = decoder.decode(a, bytes, start != key);
    if (!insn || insn->unimplemented || insn->pcode.empty()) return false;
    counted += insn->length;
    const InsnFlow f = classify(*insn, info.code_space);
    const std::uint64_t next = a + insn->length + insn->delay_slot;
    if (!f.falls_through) return false;
    eval.step(*insn);
    if (eval.saved(info.link_register->first)) return true;
    // What comes before the save doesn't store (a literal pool's words
    // read as code often do).
    for (const lift::PcodeOp &op : insn->pcode)
      if (op.opcode == "STORE"sv) return false;
    if (f.kind == FlowKind::branch || f.kind == FlowKind::ret) {
      for (std::uint64_t t : f.targets)
        if (t <= next || t - next > 4096) return false;
      if (const auto &c = eval.branch_condition(); c && c->known()) return false;
      a = next;
      continue;
    }
    if (f.kind != FlowKind::fall) return false;
    a = next;
    ++n;
  }
  return false;
}

std::set<std::uint64_t> find_code(const ProgramInfo &info, const SearchInput &in, const std::set<std::uint64_t> &functions,
                                  ByteReader &bytes, Decoder &decoder, bool fallback) {
  std::set<std::uint64_t> out;
  const Known known(in);
  const Ranges &code = known.code;
  const Ranges &data = known.data;
  const bool interwork = !info.isa_context.empty();
  // Two instruction sets the same bytes can be read in (not Cortex-M,
  // where tagged and plain keys both decode as Thumb).
  const bool dual = interwork && decoder.two_instruction_sets();
  // In the fallback (see internal.h): byte-coded processors (6502, Z80,
  // 8051) start instructions anywhere; otherwise every second byte is
  // tried. An 8- or 16-bit processor's registers are a byte (A, X), and
  // storing one is an instruction's whole effect (sta $d020).
  const bool bytewise = fallback && !interwork && decoder.step() == 1;
  const std::uint64_t step = bytewise ? 1 : 2;
  const bool small = fallback && info.pointer_size <= 2;
  std::set<std::uint64_t> function_at;  // code addresses of known functions
  for (std::uint64_t f : functions) function_at.insert(info.code_address(f));
  std::vector<Range> taken;  // bodies accepted this round

  // Ghidra's checks (ArmAggressiveInstructionFinderAnalyzer.doValidStart,
  // PseudoDisassembler.checkValidSubroutine) on a pseudo flow from `start`.
  // `proven`: it calls or jumps to a known function, in that function's
  // instruction set (what bytes that aren't code rarely do).
  auto plausible = [&](std::uint64_t start, bool thumb, std::vector<Range> &body, bool &proven) {
    proven = false;
    auto first = bytes.read(start, 8);
    if (first.size() == 8 && std::all_of(first.begin(), first.end(), [](std::byte b) { return b == std::byte{0}; }))
      return false;
    const bool tagged = thumb && !info.thumb(start);
    std::map<std::uint64_t, std::uint32_t> insns;  // address -> length
    std::vector<std::uint64_t> work{start}, jump_targets;
    bool adds = false;
    std::size_t count = 0;
    constexpr std::size_t kMaxInstructions = 1000;
    while (!work.empty() && count < kMaxInstructions) {
      std::uint64_t a = work.back();
      work.pop_back();
      while (count < kMaxInstructions) {
        if (insns.contains(a)) break;
        // Running into a function's entry: on 8- and 16-bit processors, a
        // table before the function, decoded (nearly every byte decodes).
        if (small && a != start && function_at.contains(a)) return false;
        if (known.at(a) && a != start) break;  // runs into known code: allowed
        if (!info.is_code(a)) return false;
        auto insn = decoder.decode(a, bytes, tagged);
        if (!insn || insn->unimplemented || zero_instruction(*insn, bytes)) return false;
        const std::uint64_t len = insn->length + insn->delay_slot;
        if (data.intersects(a, a + len - 1) || code.intersects(a, a + len - 1)) return false;
        if (count == 0) {
          // Not filler (nop, mov rX, rX: no p-code but flags).
          bool effect = false;
          for (const lift::PcodeOp &op : insn->pcode)
            if (op.opcode != "COPY"sv || !op.output || op.inputs.empty() || op.output->space != "register"sv ||
                !(op.inputs[0] == *op.output))
              effect = effect || (op.output && (op.output->size > 1 || small)) || (small && op.opcode == "STORE"sv);
          if (!effect) return false;
        }
        insns.emplace(a, static_cast<std::uint32_t>(len));
        ++count;
        InsnFlow f = classify(*insn, info.code_space);
        const std::uint64_t next = a + len;
        // The instruction set a direct call or jump lands in: this one,
        // unless the instruction sets the mode register (BLX).
        bool to_thumb = thumb;
        if (interwork && info.isa_register && !f.targets.empty()) {
          Evaluator eval(info, nullptr);
          eval.step(*insn);
          if (auto v = eval.register_value(info.isa_register->first, info.isa_register->second)) to_thumb = *v != 0;
        }
        for (std::uint64_t t : f.targets) {
          const bool is_function = function_at.contains(t);
          // A known function entered in the other instruction set: not code.
          if (is_function && dual && !functions.contains(info.code_key(t, to_thumb))) return false;
          // Into the middle of a known instruction.
          if (code.contains(t) && !known.at(t)) return false;
          if (f.kind == FlowKind::call) {
            if (is_function) adds = proven = true;
            // (A call to where no code is, as data's rst 38h is, adds
            // nothing on a processor whose every byte is an instruction.)
            else if (!code.contains(t) && (!small || info.is_code(t))) adds = true;
            continue;
          }
          if (t == next && f.kind == FlowKind::jump) return false;  // a jump to the next instruction
          if (is_function) {
            adds = proven = true;
            continue;
          }
          jump_targets.push_back(t);
          work.push_back(t);
        }
        if (f.kind == FlowKind::call_indirect) adds = true;  // through a register just loaded, usually
        if (!f.falls_through) break;
        a = next;
      }
    }
    for (std::uint64_t t : jump_targets) {
      // A jump into the middle of one of its own instructions: not code.
      auto it = insns.upper_bound(t);
      if (it != insns.begin() && std::prev(it)->first != t && t - std::prev(it)->first < std::prev(it)->second)
        return false;
    }
    if (count <= 2 || !adds) return false;
    for (const auto &[a, len] : insns) {
      if (!body.empty() && body.back().last + 1 == a) body.back().last = a + len - 1;
      else body.push_back({a, a + len - 1});
    }
    // Pieces of one or two instructions (a jump away, a lone branch
    // target): what data read as code wanders into. On byte-coded
    // processors a piece can be a lone return a branch reaches (bcs done;
    // ...; done: rts), and only a start that jumps away at once is one.
    const std::uint64_t first_piece = bytewise ? 3 : 6, piece = bytewise ? 0 : 4;
    if (body.size() > 1 && body.front().last - body.front().first + 1 <= first_piece) return false;
    std::uint64_t distance = 0, last = 0;
    for (const Range &r : body) {
      if (r.first < start || r.last - r.first + 1 <= piece) return false;
      if (last) distance += r.first > last ? r.first - last : last - r.first;
      last = r.last;
    }
    if (distance > 4096) return false;
    for (const Range &r : body) {
      auto it = function_at.lower_bound(r.first);
      if (it != function_at.end() && *it <= r.last) return false;  // flows into a function
      // Text that happens to decode.
      if (text_bytes(bytes, r.first, r.last).longest >= kTextRun) return false;
    }
    return true;
  };

  for (const Range &range : info.code) {
    std::uint64_t s = range.first;
    while (s <= range.last) {
      if (const Range *c = code.find(s)) {
        if (c->last >= range.last) break;
        s = c->last + 1;
        continue;
      }
      if (const Range *d = data.find(s)) {
        if (d->last >= range.last) break;
        s = d->last + 1;
        continue;
      }
      // A gap: try the first few positions, as the AIF does, then skip to
      // the next defined thing.
      const std::uint64_t gap = s;
      // Where the gap ends: the next code or data.
      std::uint64_t end = range.last;
      if (auto c = code.next(gap); c && *c - 1 < end) end = *c - 1;
      if (auto d = data.next(gap); d && *d - 1 < end) end = *d - 1;
      // The instruction set of the code before the gap first, as the AIF
      // takes the mode of the instruction before; then the other one, which
      // must prove itself: Thumb code read as ARM (and the reverse) often
      // decodes, and calls anywhere.
      const bool before = dual && known.thumb_before(gap).value_or(false);
      // Code that starts a few instructions into the gap, after an early
      // exit that falls through to it (a shrink-wrapped prologue), starts
      // where the gap does.
      auto guarded = [&](std::uint64_t a, bool thumb) {
        const std::uint64_t align = thumb || !interwork ? step : 4;
        const std::uint64_t g = (gap + align - 1) / align * align;
        if (g < a && std::none_of(taken.begin(), taken.end(), [&](const Range &r) { return r.contains(g); }) &&
            guards_prologue(info, g, a, thumb, bytes, decoder))
          return g;
        return a;
      };
      unsigned tried = 0;
      bool any = false;
      std::uint64_t a = (gap + step - 1) / step * step;
      for (; a <= end && tried < 5; a += step, ++tried) {
        if (std::any_of(taken.begin(), taken.end(), [&](const Range &r) { return r.contains(a); })) continue;
        if (starts_in_text(bytes, a) || high_entropy(bytes, a)) continue;
        for (bool thumb : {before, !before}) {
          if (thumb && !interwork) continue;
          if (!thumb && interwork && a % 4 != 0) continue;
          std::vector<Range> body;
          bool proven = false;
          if (plausible(a, thumb, body, proven) && (!dual || thumb == before || proven)) {
            out.insert(info.code_key(guarded(a, thumb), thumb));
            taken.insert(taken.end(), body.begin(), body.end());
            any = true;
            break;
          }
        }
      }
      // Nothing where the gap starts (the words of a literal pool no known
      // code loads, a function that calls nothing: the AIF stops there too,
      // and whatever follows stays unseen): the first place further in
      // that begins as a function does, by saving its return address, and
      // calls or jumps to a function already known.
      for (; !any && info.link_register && a <= end; a += step) {
        if (std::any_of(taken.begin(), taken.end(), [&](const Range &r) { return r.contains(a); })) continue;
        for (bool thumb : {before, !before}) {
          if (thumb && !interwork) continue;
          if (!thumb && interwork && a % 4 != 0) continue;
          const std::uint64_t key = info.code_key(a, thumb);
          if (!saves_return_address(info, key, bytes, decoder)) continue;
          if (starts_in_text(bytes, a) || high_entropy(bytes, a)) continue;
          std::vector<Range> body;
          bool proven = false;
          if (plausible(a, thumb, body, proven) && proven) {
            out.insert(info.code_key(guarded(a, thumb), thumb));
            taken.insert(taken.end(), body.begin(), body.end());
            any = true;
            break;
          }
        }
      }
      if (end >= range.last) break;
      s = end + 1;
    }
  }
  return out;
}

std::set<std::uint64_t> find_called(const ProgramInfo &info, const SearchInput &in, ByteReader &bytes,
                                    Decoder &decoder) {
  std::set<std::uint64_t> out;
  if (!info.isa_context.empty()) return out;  // one instruction set (ARM has its own searches)
  const Known known(in);
  const Ranges &code = known.code;
  const Ranges &data = known.data;
  const std::uint64_t step = decoder.step();
  auto align = [&](std::uint64_t a) { return (a + step - 1) / step * step; };

  // Every direct call in what nothing reached, decoded at every place an
  // instruction can start, by target.
  struct Site {
    std::uint64_t at;
    std::uint32_t length;
  };
  std::map<std::uint64_t, std::vector<Site>> sites;
  for (const Range &range : info.code) {
    for (std::uint64_t a = align(range.first); a >= range.first && a <= range.last;) {
      const Range *known_range = code.find(a);
      if (!known_range) known_range = data.find(a);
      if (known_range) {
        if (known_range->last >= range.last) break;
        a = align(known_range->last + 1);
        continue;
      }
      auto insn = decoder.decode(a, bytes);
      if (insn && !insn->unimplemented && !insn->pcode.empty() && !zero_instruction(*insn, bytes)) {
        const InsnFlow f = classify(*insn, info.code_space);
        if (f.kind == FlowKind::call && f.targets.size() == 1) {
          const std::uint64_t t = f.targets.front();
          if (t != a && t % step == 0 && info.is_code(t) && !code.contains(t) && !data.contains(t))
            sites[t].push_back({a, static_cast<std::uint32_t>(insn->length + insn->delay_slot)});
        }
      }
      if (a + step < a) break;
      a += step;
    }
  }

  // Whether a call is in code: not in text, fill or random bytes, and its
  // flow from the call on (through its fallthrough and branches, not into
  // the callee) decodes for a while as a valid subroutine's does, or ends
  // sooner in a return, a jump, or known code.
  auto in_code = [&](const Site &s) {
    if (text_bytes(bytes, s.at, s.at + s.length - 1).total != 0 || starts_fill(s.at, s.length, bytes) ||
        high_entropy(bytes, s.at))
      return false;
    constexpr std::size_t kInstructions = 16;
    std::map<std::uint64_t, std::uint32_t> insns;
    std::vector<std::uint64_t> work{s.at}, jumps;
    std::size_t count = 0;
    while (!work.empty() && count < kInstructions) {
      std::uint64_t a = work.back();
      work.pop_back();
      std::vector<std::byte> last;
      unsigned repeats = 0;
      while (count < kInstructions && !insns.contains(a)) {
        if (known.at(a)) break;
        if (!info.is_code(a)) return false;
        auto insn = decoder.decode(a, bytes);
        if (!insn || insn->unimplemented || insn->pcode.empty() || zero_instruction(*insn, bytes)) return false;
        const std::uint64_t len = insn->length + insn->delay_slot;
        if (data.intersects(a, a + len - 1) || code.intersects(a, a + len - 1)) return false;
        {
          auto raw = bytes.read(a, insn->length);
          std::vector<std::byte> cur(raw.begin(), raw.end());
          repeats = cur == last ? repeats + 1 : 0;
          if (repeats >= 4) return false;
          last = std::move(cur);
        }
        insns.emplace(a, static_cast<std::uint32_t>(len));
        ++count;
        const InsnFlow f = classify(*insn, info.code_space);
        const std::uint64_t next = a + len;
        if (f.kind == FlowKind::jump || f.kind == FlowKind::branch)
          for (std::uint64_t t : f.targets) {
            if (t == next && f.kind == FlowKind::jump) return false;
            if (code.contains(t)) {
              if (!known.at(t)) return false;
              continue;
            }
            jumps.push_back(t);
            work.push_back(t);
          }
        if (!f.falls_through) break;
        a = next;
      }
    }
    for (std::uint64_t t : jumps) {
      auto it = insns.upper_bound(t);
      if (it != insns.begin() && std::prev(it)->first != t && t - std::prev(it)->first < std::prev(it)->second)
        return false;
    }
    return true;
  };
  // The bytes around a call: two calls of one routine from different code
  // have different ones; a table of records that happens to hold a call
  // opcode repeats them exactly.
  auto context = [&](const Site &s) {
    constexpr std::uint64_t kAround = 4;
    const std::uint64_t from = s.at >= kAround ? s.at - kAround : 0;
    auto b = bytes.read(from, static_cast<std::size_t>(s.at - from + s.length + kAround));
    return std::string(reinterpret_cast<const char *>(b.data()), b.size());
  };

  struct Candidate {
    std::uint64_t target;
    std::size_t calls;
    std::map<std::uint64_t, std::uint32_t> flow;
  };
  std::vector<Candidate> candidates;
  for (const auto &[target, all] : sites) {
    if (all.size() < 2) continue;
    std::vector<Site> calls;
    for (const Site &s : all) {
      if (!calls.empty() && s.at < calls.back().at + calls.back().length) continue;  // overlaps the last one
      if (s.at <= target && target < s.at + s.length) continue;
      if (in_code(s)) calls.push_back(s);
    }
    if (calls.size() < 2) continue;
    const std::string first = context(calls.front());
    if (std::all_of(calls.begin() + 1, calls.end(), [&](const Site &s) { return context(s) == first; })) continue;
    // Three or more evenly spaced, close together: records of a table.
    if (calls.size() >= 3 && calls[1].at - calls[0].at <= 16 &&
        std::adjacent_find(calls.begin() + 1, calls.end(), [&](const Site &x, const Site &y) {
          return y.at - x.at != calls[1].at - calls[0].at;
        }) == calls.end())
      continue;
    if (starts_in_text(bytes, target) || high_entropy(bytes, target) || starts_fill(target, 1, bytes)) continue;
    Candidate c{target, calls.size(), {}};
    if (!valid_subroutine(info, known, target, false, bytes, decoder, &c.flow)) continue;
    candidates.push_back(std::move(c));
  }
  // Where two disagree (one starts inside an instruction of the other's
  // flow), the one called more often wins.
  std::sort(candidates.begin(), candidates.end(), [](const Candidate &x, const Candidate &y) {
    return x.calls != y.calls ? x.calls > y.calls : x.target < y.target;
  });
  std::map<std::uint64_t, std::uint32_t> taken;  // accepted flows' instructions
  auto inside = [&](std::uint64_t a) {
    auto it = taken.upper_bound(a);
    return it != taken.begin() && std::prev(it)->first != a && a - std::prev(it)->first < std::prev(it)->second;
  };
  for (const Candidate &c : candidates) {
    if (inside(c.target)) continue;
    bool clash = false;
    for (const auto &[a, len] : c.flow)
      for (std::uint64_t t : out) clash = clash || (a < t && t < a + len);
    if (clash) continue;
    out.insert(c.target);
    for (const auto &[a, len] : c.flow) taken.emplace(a, len);
  }
  return out;
}

}  // namespace revkit::analysis::detail
