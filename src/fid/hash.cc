// MessageDigestFidHasher.hash, ported (Ghidra 12.1.4, Apache 2.0).

#include "revkit/fid/hash.h"

#include <algorithm>
#include <array>

namespace revkit::fid {

namespace {

constexpr std::uint32_t kFeed = 0xfeeddead;

// X86InstructionSkipper.PATTERNS
const std::vector<std::vector<std::uint8_t>> &x86_patterns() {
  static const std::vector<std::vector<std::uint8_t>> p = {
      {0x90},
      {0x8b, 0xc0},
      {0x8b, 0xc9},
      {0x8b, 0xd2},
      {0x8b, 0xdb},
      {0x8b, 0xe4},
      {0x8b, 0xed},
      {0x8b, 0xf6},
      {0x8b, 0xff},
      {0x66, 0x90},
      {0x0f, 0x1f, 0x00},
      {0x0f, 0x1f, 0x40, 0x00},
      {0x0f, 0x1f, 0x44, 0x00, 0x00},
      {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
      {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
      {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
      {0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
  };
  return p;
}

// hasRelocation: a relocation inside the operand mask's nonzero bytes.
bool has_relocation(const std::vector<std::uint8_t> &mask, std::uint64_t first, std::uint64_t last,
                    const HashOptions &o) {
  if (!o.relocated || mask.empty()) return false;
  std::size_t lo = 0;
  while (lo < mask.size() && mask[lo] == 0) ++lo;
  std::size_t hi = mask.size();
  while (hi > 0 && mask[hi - 1] == 0) --hi;
  // Java walks min up and max down independently: an all-zero mask moves
  // min past max and finds nothing.
  const std::uint64_t a = first + lo;
  const std::uint64_t b = last - (mask.size() - hi);
  if (lo == mask.size() || a > b) return false;
  return o.relocated(a, b);
}

}  // namespace

bool x86_skipped(std::span<const std::uint8_t> bytes) {
  for (const auto &p : x86_patterns())
    if (p.size() == bytes.size() && std::equal(p.begin(), p.end(), bytes.begin())) return true;
  return false;
}

bool skips_x86_nops(const std::string &language) { return language.starts_with("x86:"); }

std::optional<HashQuad> hash_function(std::span<const HashUnit> units, const HashOptions &o) {
  const int min_units = std::max(1, o.min_code_units);
  if (units.size() < static_cast<std::size_t>(min_units)) return std::nullopt;
  Fnv1a64 full, specific;
  int specific_count = 0, call_count = 0, index = -1;
  std::vector<std::uint8_t> buffer;
  for (const HashUnit &u : units) {
    ++index;
    if (index >= 32767 - 1) break;  // Short.MAX_VALUE - 1
    buffer = u.bytes;
    const std::uint64_t first = u.address;
    const std::uint64_t last = u.address + (u.bytes.empty() ? 0 : u.bytes.size() - 1);
    if (o.skip_x86_nops && x86_skipped(buffer)) {
      --index;
      continue;
    }
    if (u.insn.call) ++call_count;
    if (u.insn.masks) {
      for (std::size_t ii = 0; ii < u.insn.operands.size(); ++ii) {
        const lift::FidOperand &op = u.insn.operands[ii];
        std::uint32_t spec = static_cast<std::uint32_t>((ii + 1) * 7777);
        std::uint32_t fullu = spec;
        for (const lift::FidObject &obj : op.objects) {
          switch (obj.kind) {
            case lift::FidObject::Kind::scalar: {
              std::int64_t val = obj.value;
              if (has_relocation(op.mask, first, last, o)) {
                val = kFeed;
              } else if (op.scalar) {
                const bool address =
                    op.address || (o.address_operand && o.address_operand(u.address, static_cast<int>(ii), obj));
                if (address) val = kFeed;
                else ++specific_count;
              } else if (val >= 256 || val <= -256) {
                val = kFeed;
              } else {
                ++specific_count;
              }
              spec = spec + (static_cast<std::uint32_t>(static_cast<std::int32_t>(val)) + 1234567u) * 67999u;
              fullu += kFeed;
              break;
            }
            case lift::FidObject::Kind::reg: {
              const std::uint32_t v =
                  (static_cast<std::uint32_t>(static_cast<std::int32_t>(obj.value)) + 7654321u) * 98777u;
              fullu += v;
              spec += v;
              break;
            }
            case lift::FidObject::Kind::address:
              spec = spec + (kFeed + 1234567u) * 67999u;
              fullu += kFeed;
              break;
          }
        }
        full.update_int(fullu);
        specific.update_int(spec);
      }
      for (std::size_t i = 0; i < buffer.size(); ++i) buffer[i] &= i < u.insn.mask.size() ? u.insn.mask[i] : 0;
    } else {
      std::fill(buffer.begin(), buffer.end(), std::uint8_t{0xa5});
    }
    full.update(buffer);
    specific.update(buffer);
  }
  ++index;
  if (index < min_units) return std::nullopt;
  HashQuad q;
  q.code_units = static_cast<std::uint16_t>(static_cast<std::int16_t>(index - call_count));
  q.full = full.value();
  q.specific_extra = static_cast<std::uint8_t>(std::min(specific_count, 127));
  q.specific = specific.value();
  return q;
}

}  // namespace revkit::fid
