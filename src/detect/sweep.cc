// The sweep kernel: decode sampled windows linearly under one candidate
// and count what the instructions do. Decoding alone says little (dense
// instruction sets decode almost anything); what control flow and the
// stack pointer do is what tells code from bytes that merely decode.
#include "revkit/detect/detect.hh"

#include "revkit/lift/abi.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <algorithm>
#include <bit>
#include <chrono>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <tuple>

namespace revkit::detect {

namespace {

// An image for a Lifter that only ever decodes bytes it is handed. (Not
// through the raw loader, which wants a pointer size the image doesn't
// need: 24-bit languages would have none.)
std::shared_ptr<const loader::Image> stub_image(const std::string &language) {
  auto img = std::make_shared<loader::Image>();
  img->format = loader::Format::raw;
  img->file = std::make_shared<loader::Bytes>(16);
  img->memory = loader::Memory(img->file);
  img->endian = language.find(":BE:") != std::string::npos ? loader::Endian::big : loader::Endian::little;
  img->bits = 32;
  return img;
}

// A direct control transfer of an instruction, from its p-code.
struct Transfer {
  enum class Kind : std::uint8_t { none, jump, call, ret, indirect };
  Kind kind = Kind::none;
  std::uint64_t target = 0;  // jump, call: an address
};

Transfer transfer_of(const lift::Instruction &insn, const std::string &code_space) {
  Transfer t;
  for (const lift::PcodeOp &op : insn.pcode) {
    const bool direct = !op.inputs.empty() && op.inputs[0].space == code_space;
    if (op.opcode == "RETURN") {
      t.kind = Transfer::Kind::ret;
    } else if (op.opcode == "CALL" && direct) {
      t = {Transfer::Kind::call, op.inputs[0].offset};
    } else if (op.opcode == "CALLIND" || op.opcode == "BRANCHIND") {
      if (t.kind == Transfer::Kind::none) t.kind = Transfer::Kind::indirect;
    } else if ((op.opcode == "BRANCH" || op.opcode == "CBRANCH") && direct) {
      if (t.kind == Transfer::Kind::none) t = {Transfer::Kind::jump, op.inputs[0].offset};
    }
  }
  return t;
}

// Fill: a run of at least this many bytes of one value.
constexpr std::uint64_t kFill = 8;
// Two absolute jumps' target - place agree within this many bytes: both go
// near themselves, within a function or two.
constexpr std::uint64_t kNear = 1024;

// The target of a computed jump or call whose low bits the instruction
// holds and only its high bits come from a register: a jump within a page,
// as PIC's GOTO and CALL hold 11 (PIC16) or 9 (PIC12) bits and PCLATH or
// STATUS supplies the page. The p-code is evaluated twice, every register
// (and whatever the evaluation doesn't follow) all zeros, then all ones:
// the bits both agree on are the instruction's own. (low bits, how many),
// in the space's units; nullopt where fewer than 8 low bits are fixed (a
// jump through a register).
std::optional<std::pair<std::uint64_t, unsigned>> paged_target(const lift::Instruction &insn) {
  using Key = std::tuple<std::string, std::uint64_t, std::uint32_t>;
  auto size_mask = [](std::uint32_t size) { return size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * size)) - 1; };
  std::uint64_t got[2] = {0, 0};
  std::uint32_t got_size = 0;
  bool found = false;
  for (int pass = 0; pass < 2; ++pass) {
    std::map<Key, std::uint64_t> known;
    auto in = [&](const lift::Varnode &v) {
      if (v.space == "const") return v.offset & size_mask(v.size);
      const auto it = known.find({v.space, v.offset, v.size});
      return it != known.end() ? it->second : (pass == 0 ? 0 : size_mask(v.size));
    };
    for (const lift::PcodeOp &op : insn.pcode) {
      if ((op.opcode == "BRANCHIND" || op.opcode == "CALLIND") && !op.inputs.empty()) {
        got[pass] = in(op.inputs[0]);
        got_size = op.inputs[0].size;
        found = true;
        break;
      }
      if (!op.output) continue;
      const std::string &o = op.opcode;
      const std::uint64_t x = op.inputs.empty() ? 0 : in(op.inputs[0]), y = op.inputs.size() < 2 ? 0 : in(op.inputs[1]);
      std::uint64_t r = pass == 0 ? 0 : ~std::uint64_t{0};  // what isn't followed
      if (o == "COPY" || o == "INT_ZEXT") r = x;
      else if (o == "INT_SEXT" && !op.inputs.empty() && op.inputs[0].size < 8) {
        const std::uint64_t sign = std::uint64_t{1} << (8 * op.inputs[0].size - 1);
        r = (x ^ sign) - sign;
      }
      else if (o == "INT_AND") r = x & y;
      else if (o == "INT_OR") r = x | y;
      else if (o == "INT_XOR") r = x ^ y;
      else if (o == "INT_LEFT") r = y < 64 ? x << y : 0;
      else if (o == "INT_RIGHT") r = y < 64 ? x >> y : 0;
      else if (o == "INT_ADD") r = x + y;
      else if (o == "INT_SUB") r = x - y;
      else if (o == "INT_MULT") r = x * y;
      else if (o == "SUBPIECE") r = y < 8 ? x >> (8 * y) : 0;
      else if (o == "PIECE" && op.inputs.size() == 2) r = (x << (8 * op.inputs[1].size)) | y;
      known[{op.output->space, op.output->offset, op.output->size}] = r & size_mask(op.output->size);
    }
    if (!found) return std::nullopt;
  }
  const std::uint64_t varies = (got[0] ^ got[1]) & size_mask(got_size);
  const unsigned low = varies == 0 ? 8 * got_size : static_cast<unsigned>(std::countr_zero(varies));
  if (varies == 0 || low < 8) return std::nullopt;
  return std::pair(got[0] & ((std::uint64_t{1} << low) - 1), low);
}

void sort_unique(std::vector<std::uint64_t> &v) {
  std::sort(v.begin(), v.end());
  v.erase(std::unique(v.begin(), v.end()), v.end());
}

}  // namespace

struct Sweeper::Impl {
  std::unique_ptr<lift::Lifter> lifter;
  std::string code_space;
  std::uint64_t unit = 1;  // bytes per unit of the code space (2 for PIC's words)
  std::uint64_t mask = ~std::uint64_t{0};
  std::optional<lift::Varnode> sp;
};

Sweeper::Sweeper(const Candidate &candidate) {
  const auto started = std::chrono::steady_clock::now();
  auto impl = std::make_unique<Impl>();
  try {
    impl->lifter = std::make_unique<lift::Lifter>(stub_image(candidate.language), candidate.language);
    for (const auto &[variable, value] : candidate.context) impl->lifter->set_context(variable, value, 0);
    impl->code_space = impl->lifter->code_space_name();
    for (const lift::SpaceDef &s : impl->lifter->spaces())
      if (s.name == impl->code_space) impl->unit = std::max<std::uint32_t>(1, s.wordsize);
    for (const lift::SpaceDef &s : impl->lifter->spaces())
      if (s.is_default && s.address_size < 8) {
        // The engine's addresses are byte offsets, also where the space
        // counts in words (AVR, PIC).
        const unsigned bits = 8 * s.address_size + (s.wordsize > 1 ? std::bit_width(s.wordsize - 1) : 0);
        if (bits < 64) impl->mask = (std::uint64_t{1} << bits) - 1;
      }
    try {
      impl->sp = impl->lifter->register_varnode(lift::read_abi(candidate.language, "").stack_pointer);
    } catch (const lift::LiftError &) {
      // no stack pointer to watch
    }
  } catch (const std::exception &) {
    return;  // a language that can't be built sweeps nothing
  }
  impl_ = std::move(impl);
  seconds_ = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
}

Sweeper::~Sweeper() = default;

unsigned Sweeper::alignment() const { return impl_ ? std::max(1u, impl_->lifter->alignment()) : 1; }

Features Sweeper::sweep(std::span<const std::byte> file,
                        const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows, bool forms,
                        std::uint64_t image_size) {
  Features f;
  if (!impl_) return f;
  const auto started = std::chrono::steady_clock::now();
  lift::Lifter *lifter = impl_->lifter.get();
  const std::string &code_space = impl_->code_space;
  const std::uint64_t mask = impl_->mask;
  const std::optional<lift::Varnode> &sp = impl_->sp;
  const unsigned align = std::max(1u, lifter->alignment());
  // Addresses are file offsets (wrapped to the space's size), so a relative
  // target is the file offset it lands on whatever the base.
  const std::uint64_t space_bytes = mask == ~std::uint64_t{0} ? mask : mask + 1;
  auto touches_sp = [&](const lift::Varnode &v) {
    return sp && v.space == sp->space && v.offset < sp->offset + sp->size && sp->offset < v.offset + v.size;
  };

  std::unordered_map<std::uint64_t, std::uint32_t> call_targets;  // relative calls' targets, as file offsets
  std::vector<std::uint64_t> calls;
  std::unordered_set<std::uint64_t> starts;    // every swept instruction's offset
  std::unordered_set<std::uint64_t> absolute;  // absolute jumps' and calls' targets
  // Every decoded instruction, for the walks from where control lands.
  struct Decoded {
    std::uint64_t pos = 0, end = 0;
    bool odd = false, transfer = false;
    const std::pair<std::string, std::uint32_t> *form = nullptr;
  };
  std::vector<Decoded> decoded;
  std::unordered_map<std::uint64_t, std::size_t> decoded_at;
  std::vector<std::uint64_t> landings;  // where relative branches and calls land
  std::unordered_set<std::uint64_t> undecoded;  // where nothing decoded
  for (const auto &[w_start, w_size] : windows) {
    const std::uint64_t w_end = std::min<std::uint64_t>(w_start + w_size, file.size());
    std::vector<std::uint64_t> near_targets;
    std::vector<std::uint64_t> return_ends;  // offsets just past a return
    std::unordered_set<std::uint64_t> flow_targets;
    std::optional<std::uint64_t> last_jump;  // the last absolute jump's target - place
    std::uint64_t last_target = ~std::uint64_t{0};
    // Where the last absolute transfer ended. One right after another (or
    // after fill) is a table: words of addresses (into RAM, into the image)
    // that this candidate decodes as jumps, or a table of jumps, or of
    // another processor's vectors. None says where the code's own targets
    // lie.
    std::uint64_t abs_end = ~std::uint64_t{0};
    for (std::uint64_t pos = w_start; pos < w_end;) {
      // A run of one byte value is fill (erased flash, zeroed space), not
      // instructions: whatever it decodes to says nothing. (In shuffled
      // bytes runs are rare, so fill counted as code would be evidence
      // against chance: a return made of fill and followed by fill.)
      if (pos + kFill <= w_end) {
        std::uint64_t end = pos + 1;
        while (end < w_end && file[end] == file[pos]) ++end;
        if (end - pos >= kFill) {
          end = pos + (end - pos) / align * align;
          // An absolute transfer, fill, another: entries of a table spread
          // out (vectors every 16 bytes).
          if (abs_end == pos) abs_end = end;
          f.fill_bytes += end - pos;
          pos = end;
          continue;
        }
      }
      const std::span<const std::byte> bytes = file.subspan(pos, std::min<std::uint64_t>(64, file.size() - pos));
      auto lift_at = [&](std::uint64_t address) -> std::optional<lift::Instruction> {
        try {
          return lifter->lift_pcode(address & mask, bytes);
        } catch (const std::exception &) {
          return std::nullopt;
        }
      };
      std::optional<lift::Instruction> insn;
      if (forms) {
        try {
          insn = lifter->lift_mnemonic(pos & mask, bytes);
        } catch (const std::exception &) {
        }
      } else {
        insn = lift_at(pos);
      }
      const std::uint64_t length = insn ? std::uint64_t{insn->length} + insn->delay_slot : 0;
      if (!insn || length == 0 || pos + length > w_end + 16) {
        undecoded.insert(pos);
        ++f.invalid;
        f.bytes += align;
        pos += align;
        continue;
      }
      starts.insert(pos);
      ++f.instructions;
      f.bytes += length;
      f.valid_bytes += length;
      if (insn->unimplemented) ++f.unimplemented;

      bool callother = false, rare = false, reads_sp = false, writes_sp = false;
      for (const lift::PcodeOp &op : insn->pcode) {
        if (op.output && touches_sp(*op.output)) writes_sp = true;
        for (const lift::Varnode &in : op.inputs)
          if (touches_sp(in)) reads_sp = true;
        if (op.opcode == "CALLOTHER") callother = true;
        if (op.opcode.starts_with("FLOAT_") || op.opcode == "INT_DIV" || op.opcode == "INT_SDIV" ||
            op.opcode == "INT_REM" || op.opcode == "INT_SREM")
          rare = true;
      }
      if (callother) ++f.callother;
      if (rare) ++f.rare;
      decoded_at.emplace(pos, decoded.size());
      decoded.push_back({pos, pos + length, insn->unimplemented || callother || rare, false, nullptr});
      if (forms) {
        const auto form = f.forms.try_emplace({insn->mnemonic, static_cast<std::uint32_t>(insn->length)}, 0).first;
        ++form->second;
        decoded.back().form = &form->first;
      }
      if (reads_sp) ++f.sp_reads;
      if (writes_sp) ++f.sp_writes;

      Transfer t = transfer_of(*insn, code_space);
      const std::uint64_t here = pos & mask;
      const std::uint64_t next = (pos + length) & mask;
      // A jump or call within a page: in the page it is in.
      bool in_page = false;
      if (t.kind == Transfer::Kind::indirect)
        if (const auto paged = paged_target(*insn)) {
          const unsigned bits = paged->second + static_cast<unsigned>(std::countr_zero(impl_->unit));
          const std::uint64_t low = (std::uint64_t{1} << std::min(bits, 63u)) - 1;
          const bool call = std::any_of(insn->pcode.begin(), insn->pcode.end(),
                                        [](const lift::PcodeOp &op) { return op.opcode == "CALLIND"; });
          t = {call ? Transfer::Kind::call : Transfer::Kind::jump, ((here & ~low) | (paged->first * impl_->unit)) & mask};
          in_page = true;
        }
      // Conditional execution is a jump over the instruction's own effect
      // in p-code (ARM, x86 rep): not a jump of the program. Nor is a skip
      // over the one instruction that follows (PIC, AVR): it lands on an
      // instruction whatever the bytes are.
      if (t.kind == Transfer::Kind::jump &&
          (t.target == next || t.target == here || (t.target > next && t.target - next <= length)))
        t = {};
      decoded.back().transfer = t.kind != Transfer::Kind::none;
      // A relative transfer moves with its address; an absolute one goes to
      // the same place from anywhere. They say different things: where a
      // relative one lands in the file doesn't depend on the base, and the
      // same word repeated (in data, in another processor's code) is the
      // same absolute target every time but a different relative one.
      bool relative = false;
      std::uint64_t target = 0;  // relative: the file offset it lands on
      if (t.kind == Transfer::Kind::jump || t.kind == Transfer::Kind::call) {
        constexpr std::uint64_t kShift = 0x400;
        if (in_page) {
          // (absolute: the page is the program's to choose)
        } else if (const std::optional<lift::Instruction> moved = lift_at(pos + kShift)) {
          const Transfer m = transfer_of(*moved, code_space);
          relative = m.kind == t.kind && m.target == ((t.target + kShift) & mask);
        }
        if (relative) {
          const std::uint64_t half = (mask >> 1) + 1;
          target = pos + ((((t.target - here) & mask) ^ half) - half);  // the distance, sign-extended
        } else {
          ++f.absolute;
          absolute.insert(t.target);
          const bool tabled = pos == abs_end;
          abs_end = pos + length;
          if (!tabled && t.kind == Transfer::Kind::jump) {
            // (Two jumps to one target count once: the same bytes repeated
            // nearby, an idiom of another processor's code, would be.)
            const std::uint64_t d = (t.target - here) & mask;
            if (last_jump && t.target != last_target) {
              ++f.abs_pairs;
              const std::uint64_t apart = (d - *last_jump) & mask;
              if (std::min(apart, (mask - apart + 1) & mask) <= kNear) ++f.abs_pairs_near;
            }
            if (t.target != last_target) last_jump = d;
            last_target = t.target;
          }
          t = {};
        }
      }
      switch (t.kind) {
        case Transfer::Kind::jump:
          ++f.branches;
          if (target >= w_start && target < w_end) {
            ++f.branch_near;
            near_targets.push_back(target);
            flow_targets.insert(target);
          }
          break;
        case Transfer::Kind::call:
          ++f.calls;
          // Wherever it lands: code cut out of a program calls what was
          // around it, and two calls still meet there.
          ++call_targets[target];
          calls.push_back(target);
          if (target < file.size()) {
            ++f.call_in_file;
            flow_targets.insert(target);
          }
          break;
        case Transfer::Kind::ret:
          ++f.returns;
          return_ends.push_back(pos + length);
          break;
        case Transfer::Kind::indirect:
          ++f.indirect;
          break;
        case Transfer::Kind::none:
          break;
      }
      pos += length;
    }
    for (std::uint64_t t : near_targets)
      if (starts.contains(t)) ++f.branch_start;
    landings.insert(landings.end(), near_targets.begin(), near_targets.end());
    for (std::uint64_t end : return_ends) {
      // What follows a function's last return: another function (something
      // jumps or calls there) or fill up to the next one.
      bool start = flow_targets.contains(end);
      if (!start && end + 4 <= file.size()) {
        const std::byte b = file[end];
        start = (b == std::byte{0} || b == std::byte{0xff}) && file[end + 1] == b && file[end + 2] == b && file[end + 3] == b;
      }
      if (start) ++f.return_then_start;
    }
  }
  for (std::uint64_t t : calls)
    if (call_targets[t] >= 2) ++f.call_shared;
  landings.insert(landings.end(), calls.begin(), calls.end());
  // The code control flow vouches for: from each landing on an instruction
  // to the next transfer, each instruction once.
  constexpr int kReach = 8;
  std::vector<bool> reached(decoded.size());
  sort_unique(landings);
  for (std::uint64_t at : landings) {
    auto it = decoded_at.find(at);
    if (it == decoded_at.end()) continue;
    std::size_t i = it->second;
    for (int n = 0;; ++n, ++i) {
      if (!reached[i]) {
        reached[i] = true;
        ++f.reached;
        if (decoded[i].odd) ++f.reached_odd;
        if (decoded[i].form) ++f.reached_forms[*decoded[i].form];
      }
      if (decoded[i].transfer || n + 1 == kReach) break;
      if (i + 1 == decoded.size() || decoded[i + 1].pos != decoded[i].end) {
        // The next bytes don't decode (or the window ends there).
        if (undecoded.contains(decoded[i].end)) ++f.reached_invalid;
        break;
      }
    }
  }
  // Were the file loaded at 0, as small processors' programs are, an
  // absolute target would be a file offset. Each target counts once: a
  // word repeated through data is one target, not evidence many times.
  if (space_bytes >= (image_size != 0 ? image_size : file.size()))
    for (std::uint64_t t : absolute)
      for (const auto &[w_start, w_size] : windows)
        if (t >= w_start && t < w_start + w_size) {
          ++f.absolute_swept;
          if (starts.contains(t)) ++f.absolute_start;
          break;
        }
  f.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  return f;
}

namespace {

// A value followed through straight-line code. `relative`: it moves with
// the code (an address taken from the program counter), so decoded at file
// offsets it is a file offset; otherwise it is what the instructions say
// whatever the address: an absolute address, or just a number.
struct Value {
  std::uint64_t v = 0;
  bool relative = false;
  // The constant it was made from by adding a small offset (a device's
  // registers from its base address); 0: itself.
  std::uint64_t origin = 0;
};

// Of an addition of two numbers, the one an offset was added to: a number
// small enough to be an offset is added to one that isn't; else a negative
// offset to a positive one. Nullopt: neither.
std::optional<std::size_t> added_to(std::uint64_t x, std::uint64_t y, std::uint32_t size) {
  const std::uint64_t m = size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * size)) - 1;
  auto positive = [&](std::uint64_t v) { return (v & m) < 0x10000; };
  auto negative = [&](std::uint64_t v) { return (v & m) > m - 0x10000; };
  if (positive(y) && !positive(x)) return 0;
  if (positive(x) && !positive(y)) return 1;
  if (negative(y) && !negative(x)) return 0;
  if (negative(x) && !negative(y)) return 1;
  return std::nullopt;
}

struct VarKey {
  std::uint32_t space = 0;
  std::uint64_t offset = 0;
  std::uint32_t size = 0;
  friend bool operator==(const VarKey &, const VarKey &) = default;
};
struct VarKeyHash {
  std::size_t operator()(const VarKey &k) const {
    return std::hash<std::uint64_t>()(k.offset * 0x9e3779b97f4a7c15 ^ (std::uint64_t{k.space} << 40) ^ k.size);
  }
};

std::uint64_t mask_of(std::uint32_t size) { return size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (8 * size)) - 1; }

}  // namespace

Trace Sweeper::trace(std::span<const std::byte> file,
                     const std::vector<std::pair<std::uint64_t, std::uint64_t>> &windows) {
  Trace out;
  if (!impl_) return out;
  lift::Lifter *lifter = impl_->lifter.get();
  const std::string &code_space = impl_->code_space;
  const std::uint64_t mask = impl_->mask;
  const unsigned align = std::max(1u, lifter->alignment());
  const bool big = lifter->big_endian();
  std::uint32_t pointer_size = 4;
  for (const lift::SpaceDef &s : lifter->spaces())
    if (s.is_default) pointer_size = s.address_size;

  std::unordered_map<std::string, std::uint32_t> space_ids;
  auto space_id = [&](const std::string &name) {
    return space_ids.try_emplace(name, static_cast<std::uint32_t>(space_ids.size())).first->second;
  };
  const std::uint32_t const_space = space_id("const");
  const std::uint32_t register_space = space_id("register");
  const std::uint32_t code = space_id(code_space);
  const std::optional<lift::Varnode> &sp = impl_->sp;

  auto read_word = [&](std::uint64_t at, std::uint32_t size) {
    std::uint64_t word = 0;
    for (std::uint32_t k = 0; k < size; ++k)
      word = word << 8 | static_cast<std::uint8_t>(file[at + (big ? k : size - 1 - k)]);
    return word;
  };
  // How many low bits of an absolute jump's target the instruction holds,
  // where the rest come from its own address (MIPS j and jal keep the top
  // four): found by moving the instruction's high address bits and seeing
  // which the target follows. 0: none follow, the target is whole.
  auto region_bits = [&](std::uint64_t pos, std::span<const std::byte> bytes, const std::string &opcode,
                         std::uint64_t target) -> unsigned {
    unsigned follows = 0;
    for (unsigned bit = std::bit_width(mask); bit-- > 12;) {
      const std::uint64_t flip = std::uint64_t{1} << bit;
      if ((pos & mask) & flip) break;
      std::optional<lift::Instruction> there;
      try {
        there = lifter->lift_pcode((pos | flip) & mask, bytes);
      } catch (const std::exception &) {
        break;
      }
      bool same = false;
      if (there)
        for (const lift::PcodeOp &op : there->pcode)
          if (op.opcode == opcode && !op.inputs.empty() && op.inputs[0].space == code_space)
            same = op.inputs[0].offset == ((target | flip) & mask);
      if (!same) break;
      follows = bit;
    }
    return follows;
  };

  // What follows the end of a function (its last return, a tail call),
  // past any fill: the start of another.
  auto after_end = [&](std::uint64_t at) {
    const std::uint64_t end = at;
    while (at < file.size() && (file[at] == std::byte{0} || file[at] == std::byte{0xff}) && at < end + 64) ++at;
    at = (at + align - 1) / align * align;
    if (at < file.size()) out.function_offsets.push_back(at);
  };
  std::unordered_map<VarKey, Value, VarKeyHash> known;
  // Registers holding half an address (only its low or only its high 16
  // bits), as one instruction builds it for the next to complete: where in
  // `out.pointers` it went, and the instruction's offset.
  std::unordered_map<VarKey, std::pair<std::size_t, std::uint64_t>, VarKeyHash> halves;
  constexpr std::uint64_t kNoPointer = ~std::uint64_t{0};
  // How far the bytes move to see what moves with them: a multiple of the
  // pages that addresses are made from the program counter in (AArch64's
  // adrp, 4 KiB; a smaller step leaves the page, and the address, as it
  // was), where the address space has room.
  const std::uint64_t kShift = mask >= 0xfffff ? 0x10000 : 0x400;
  std::vector<std::uint64_t> pool_words;  // words read as literals from outside the code control flow runs through
  for (const auto &[w_start, w_size] : windows) {
    const std::uint64_t w_end = std::min<std::uint64_t>(w_start + w_size, file.size());
    known.clear(), halves.clear();
    // For the words read as literals that are code (below): the window's
    // instructions (their lengths, and whether control may leave after
    // them), where its relative branches and calls land, and its literals.
    std::vector<std::uint8_t> step(w_end - w_start);
    std::vector<bool> leaves(w_end - w_start, true);
    std::vector<std::uint64_t> landings;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> literals;  // (file offset, the word)
    auto literal = [&](std::uint64_t at, std::uint32_t size) {
      const std::uint64_t w = read_word(at, size);
      if (size == pointer_size) literals.emplace_back(at, w);
      return w;
    };
    for (std::uint64_t pos = w_start; pos < w_end;) {
      const std::span<const std::byte> bytes = file.subspan(pos, std::min<std::uint64_t>(64, file.size() - pos));
      auto lift_at = [&](std::uint64_t address) -> std::optional<lift::Instruction> {
        try {
          return lifter->lift_pcode(address & mask, bytes);
        } catch (const std::exception &) {
          return std::nullopt;
        }
      };
      const std::optional<lift::Instruction> insn = lift_at(pos);
      const std::uint64_t length = insn ? std::uint64_t{insn->length} + insn->delay_slot : 0;
      if (!insn || length == 0) {
        known.clear(), halves.clear();
        pos += align;
        continue;
      }
      ++out.instructions;
      step[pos - w_start] = static_cast<std::uint8_t>(std::min<std::uint64_t>(length, 255));
      // The same bytes one step along: what moved with them is relative.
      // Only an instruction that reads the same there can be compared.
      const std::optional<lift::Instruction> moved = lift_at(pos + kShift);
      bool comparable = moved && moved->pcode.size() == insn->pcode.size();
      for (std::size_t i = 0; comparable && i < insn->pcode.size(); ++i)
        comparable = moved->pcode[i].opcode == insn->pcode[i].opcode &&
                     moved->pcode[i].inputs.size() == insn->pcode[i].inputs.size();
      if (!comparable) {
        known.clear(), halves.clear();
        pos += length;
        continue;
      }

      bool transfers = false, calls = false, anchored = false;
      // Whether the instruction transfers control only on a condition (a
      // conditional return, a predicated branch).
      const bool conditional = std::any_of(insn->pcode.begin(), insn->pcode.end(),
                                           [](const lift::PcodeOp &op) { return op.opcode == "CBRANCH"; });
      std::unordered_set<VarKey, VarKeyHash> read;  // registers the instruction reads
      for (const lift::PcodeOp &op : insn->pcode)
        for (const lift::Varnode &v : op.inputs)
          if (v.space == "register") read.insert({register_space, v.offset, v.size});
      for (std::size_t i = 0; i < insn->pcode.size(); ++i) {
        const lift::PcodeOp &op = insn->pcode[i];
        // An input's value: a constant of the instruction, or what an
        // earlier operation left in the place it reads.
        auto value = [&](std::size_t j) -> std::optional<Value> {
          const lift::Varnode &v = op.inputs[j];
          if (v.space == "const") {
            const std::uint64_t there = moved->pcode[i].inputs[j].offset;
            return Value{v.offset, ((there - v.offset) & mask) == kShift && v.size >= 2};
          }
          if (v.space == code_space) {
            // Memory named by the instruction. Where it moves with the
            // code it is a literal next to it, and the word is in the file.
            const bool relative = ((moved->pcode[i].inputs[j].offset - v.offset) & mask) == kShift;
            if (!relative || v.size > 8 || v.offset + v.size > file.size()) return std::nullopt;
            return Value{literal(v.offset, v.size), false};
          }
          const auto it = known.find({space_id(v.space), v.offset, v.size});
          if (it == known.end()) return std::nullopt;
          return it->second;
        };
        // A memory operand named directly (x86, 68k: an address in the
        // instruction itself).
        for (std::size_t j = 0; j < op.inputs.size(); ++j) {
          const lift::Varnode &v = op.inputs[j];
          if (v.space != code_space || op.opcode == "CALL" || op.opcode == "BRANCH" || op.opcode == "CBRANCH") continue;
          if (((moved->pcode[i].inputs[j].offset - v.offset) & mask) != kShift) {
            out.accesses.push_back(v.offset);
            out.memory.push_back({v.offset, pos, v.size, false, std::nullopt, v.offset});
          }
        }
        if (op.output && op.output->space == code_space) out.accesses.push_back(op.output->offset);

        const std::string &o = op.opcode;
        std::optional<Value> result;
        if ((o == "CALL" || o == "BRANCH" || o == "CBRANCH") && !op.inputs.empty() && op.inputs[0].space == code_space) {
          transfers = true;
          const std::uint64_t target = op.inputs[0].offset;
          const bool relative = ((moved->pcode[i].inputs[0].offset - target) & mask) == kShift;
          const std::uint64_t here = pos & mask, next = (pos + length) & mask;
          if (o == "CALL") calls = true;
          if (relative) {
            const std::uint64_t half = (mask >> 1) + 1;
            const std::uint64_t at = pos + ((((target - here) & mask) ^ half) - half);
            if (at >= w_start && at < w_end) landings.push_back(at);
            if (o == "CALL") {
              if (at < file.size()) out.function_offsets.push_back(at);
            } else if (at <= pos && pos - at <= 512) {
              out.back_jumps.emplace_back(at, pos);
            }
            // Past a jump that always goes elsewhere (a tail call, the jump
            // over a loop's body back to its test is conditional) the
            // bytes are another function, or something jumped to.
            if (o == "BRANCH" && !conditional) after_end(pos + length);
          } else if (target != next && target != here) {
            if (o == "BRANCH" && !conditional) after_end(pos + length);
            if (const unsigned bits = region_bits(pos, bytes, o, target)) {
              out.region_bits = out.region_bits == 0 ? bits : std::min(out.region_bits, bits);
              out.region_targets.push_back(target);
            } else {
              out.jump_targets.push_back(target);
            }
          }
        } else if (o == "CALLIND" || o == "BRANCHIND" || o == "RETURN") {
          transfers = true;
          if (o == "CALLIND") calls = true;
          if (o == "RETURN") {
            // (A conditional return, Z80's ret nz, ends no function.)
            if (!conditional) after_end(pos + length);
          } else if (!op.inputs.empty()) {
            // A computed call or jump to a known address; or within a page,
            // to known low bits.
            if (const auto t = value(0); t && !t->relative) {
              out.jump_targets.push_back(t->v);
            } else if (const auto paged = paged_target(*insn)) {
              const unsigned bits = paged->second + static_cast<unsigned>(std::countr_zero(impl_->unit));
              out.region_bits = out.region_bits == 0 ? bits : std::min(out.region_bits, bits);
              out.region_targets.push_back(paged->first * impl_->unit);
            }
          }
        } else if (o == "COPY" && op.inputs.size() == 1) {
          result = value(0);
        } else if (o == "LOAD" && op.inputs.size() == 2 && op.output) {
          if (const auto a = value(1)) {
            if (!a->relative) {
              out.accesses.push_back(a->v);
              out.memory.push_back({a->v, pos, op.output->size, false, std::nullopt, a->origin ? a->origin : a->v});
            } else if (a->v + op.output->size <= file.size() && op.output->size <= 8) {
              // A literal pool: the word is in the file, by the code.
              result = Value{literal(a->v, op.output->size), false};
            }
          }
        } else if (o == "STORE" && op.inputs.size() == 3) {
          if (const auto a = value(1); a && !a->relative) {
            out.accesses.push_back(a->v);
            const auto stored = value(2);
            out.memory.push_back({a->v, pos, op.inputs[2].size, true,
                                  stored && !stored->relative ? std::optional(stored->v & mask_of(op.inputs[2].size))
                                                              : std::nullopt,
                                  a->origin ? a->origin : a->v});
          }
        } else if (op.inputs.size() == 2 && op.output) {
          const auto a = value(0), b = value(1);
          if (a && b) {
            const std::uint64_t x = a->v, y = b->v;
            // An address made from the program counter compared with, or
            // taken from, a constant: code that finds where it runs and
            // compares it with where it was linked to run (relocating
            // itself). The difference is base - offset.
            if (a->relative != b->relative && op.inputs[0].size == pointer_size && !anchored &&
                (o == "INT_SUB" || o == "INT_EQUAL" || o == "INT_NOTEQUAL" || o == "INT_LESS" || o == "INT_LESSEQUAL")) {
              const std::uint64_t at = a->relative ? x : y, linked = a->relative ? y : x;
              if (at < file.size() && linked >= 0x100) {
                out.anchors.push_back((linked - at) & mask);
                anchored = true;
              }
            }
            if (o == "INT_ADD") {
              result = Value{x + y, a->relative != b->relative};
              if (const auto to = added_to(x, y, op.output->size))
                result->origin = *to == 0 ? (a->origin ? a->origin : x) : (b->origin ? b->origin : y);
            }
            else if (o == "INT_SUB") result = Value{x - y, a->relative && !b->relative};
            else if (o == "INT_OR") result = Value{x | y, false};
            else if (o == "INT_XOR") result = Value{x ^ y, false};
            // Rounding an address down (the program counter, word-aligned)
            // leaves it an address.
            else if (o == "INT_AND") result = Value{x & y, a->relative != b->relative};
            else if (o == "INT_LEFT") result = Value{y < 64 ? x << y : 0, false};
            else if (o == "INT_RIGHT") result = Value{y < 64 ? x >> y : 0, false};
            else if (o == "INT_MULT") result = Value{x * y, false};
            else if (o == "SUBPIECE") result = Value{y < 8 ? x >> (8 * y) : 0, false};
            else if (o == "PIECE") result = Value{(x << (8 * op.inputs[1].size)) | y, false};
          }
        } else if (op.inputs.size() == 1 && op.output) {
          if (const auto a = value(0)) {
            if (o == "INT_ZEXT") result = *a;
            else if (o == "INT_SEXT") {
              const std::uint64_t sign = std::uint64_t{1} << (8 * op.inputs[0].size - 1);
              result = Value{(a->v ^ sign) - sign, a->relative};
            } else if (o == "INT_NEGATE") result = Value{~a->v, false};
            else if (o == "INT_2COMP") result = Value{0 - a->v, false};
          }
        }
        if (!op.output) continue;
        if (op.output->space == code_space &&
            ((moved->pcode[i].output ? moved->pcode[i].output->offset - op.output->offset : 0) & mask) != kShift)
          out.memory.push_back({op.output->offset, pos, op.output->size, true,
                                result && !result->relative ? std::optional(result->v & mask_of(op.output->size))
                                                            : std::nullopt,
                                op.output->offset});
        const VarKey key{space_id(op.output->space), op.output->offset, op.output->size};
        if (key.space == const_space || key.space == code) continue;
        if (!result) {
          known.erase(key);
          continue;
        }
        result->v &= mask_of(op.output->size);
        known[key] = *result;
        // A register left holding an address-sized number: a pointer, if
        // anything is.
        if (key.space == register_space && op.output->size == pointer_size && !result->relative && result->v >= 0x100) {
          // Half an address that this instruction completes (movw then
          // movt; lui or lis then the low half) was no pointer.
          if (const auto h = halves.find(key); h != halves.end()) {
            if (h->second.second != pos && read.contains(key)) out.pointers[h->second.first] = kNoPointer;
            halves.erase(h);
          }
          const std::uint64_t v = result->v;
          if (pointer_size >= 4 && (v < 0x10000 || (v & 0xffff) == 0)) halves[key] = {out.pointers.size(), pos};
          out.pointers.push_back(v);
        }
        // A stack set to a constant: where the stack is.
        if (sp && key.space == register_space && op.output->offset == sp->offset && op.output->size == sp->size &&
            !result->relative)
          out.stack_values.emplace_back(result->v, pos);
      }
      if (transfers) {
        // What the registers hold as control leaves: a loop's or a call's
        // set-up.
        Trace::Setup setup{pos, calls, {}};
        bool address = false;
        for (const auto &[k, v] : known)
          // (Not a return address the transfer itself leaves: the next
          // instruction's offset, with a mode bit perhaps.)
          if (k.space == register_space && k.size == pointer_size && !v.relative &&
              !(v.v >= pos && v.v <= pos + length + 1)) {
            setup.values.push_back(v.v);
            address = address || v.v >= 0x100;
          }
        sort_unique(setup.values);
        if (address && setup.values.size() >= 2) out.setups.push_back(std::move(setup));
      }
      // Past a transfer the registers are someone else's.
      if (transfers) known.clear(), halves.clear();
      // Temporaries don't outlive their instruction.
      else
        std::erase_if(known, [&](const auto &kv) { return kv.first.space != register_space; });
      leaves[pos - w_start] = transfers;
      pos += length;
    }
    // A literal pool sits where control flow doesn't run: past a return or
    // a jump. A word "read as a literal" from the middle of code that a
    // branch lands in and runs through is an instruction (an instruction
    // of data decoded as a load from the program counter read it): its
    // value is no address.
    if (!literals.empty()) {
      std::vector<bool> run(w_end - w_start);
      for (std::uint64_t at : landings)
        for (std::uint64_t p = at, n = 0; p < w_end && step[p - w_start] != 0 && !run[p - w_start] && n < 64; ++n) {
          run[p - w_start] = true;
          if (leaves[p - w_start]) break;
          p += step[p - w_start];
        }
      for (const auto &[at, word] : literals)
        (at >= w_start && at < w_end && run[at - w_start] ? out.code_words : pool_words).push_back(word);
    }
  }
  // (A word also read from a pool elsewhere is what it says.)
  sort_unique(out.code_words);
  sort_unique(pool_words);
  std::erase_if(out.code_words, [&](std::uint64_t w) { return std::binary_search(pool_words.begin(), pool_words.end(), w); });
  std::erase(out.pointers, kNoPointer);
  sort_unique(out.pointers);
  sort_unique(out.jump_targets);
  if (out.region_bits != 0)
    for (std::uint64_t &t : out.region_targets) t &= (std::uint64_t{1} << out.region_bits) - 1;
  sort_unique(out.region_targets);
  sort_unique(out.accesses);
  sort_unique(out.function_offsets);
  return out;
}

}  // namespace revkit::detect
