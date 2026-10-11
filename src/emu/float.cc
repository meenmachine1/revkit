// p-code floating point. Single and double precision compute in the host's
// float and double (IEEE 754, round to nearest even), so results are exact;
// half, x87 extended and quad precision go through long double.
#include "impl.hh"

#include "opcodes.hh"

#include <bit>
#include <cmath>
#include <limits>

namespace revkit::emu::detail {

namespace {

struct Format {
  int exp_bits;
  int frac_bits;      // stored fraction bits
  bool explicit_int;  // x87: the integer bit is stored
};

std::optional<Format> format_of(std::uint32_t size) {
  switch (size) {
    case 2: return Format{5, 10, false};
    case 4: return Format{8, 23, false};
    case 8: return Format{11, 52, false};
    case 10: return Format{15, 64, true};
    case 16: return Format{15, 112, false};
    default: return std::nullopt;
  }
}

using u128 = unsigned __int128;

u128 low128(const Wide &w) { return (static_cast<u128>(w.w[1]) << 64) | w.w[0]; }

long double decode(const Wide &v, std::uint32_t size) {
  if (size == 4) return std::bit_cast<float>(static_cast<std::uint32_t>(v.w[0]));
  if (size == 8) return std::bit_cast<double>(v.w[0]);
  const auto f = format_of(size);
  if (!f) return 0;
  const u128 bits = low128(v);
  const int total = f->exp_bits + f->frac_bits + 1;
  const bool neg = ((bits >> (total - 1)) & 1) != 0;
  const std::int64_t bias = (std::int64_t{1} << (f->exp_bits - 1)) - 1;
  const std::int64_t exp = static_cast<std::int64_t>((bits >> f->frac_bits) & ((u128{1} << f->exp_bits) - 1));
  u128 frac = bits & ((u128{1} << f->frac_bits) - 1);
  long double out;
  if (exp == (std::int64_t{1} << f->exp_bits) - 1) {
    const u128 payload = f->explicit_int ? (frac & ((u128{1} << (f->frac_bits - 1)) - 1)) : frac;
    out = payload == 0 ? std::numeric_limits<long double>::infinity() : std::numeric_limits<long double>::quiet_NaN();
  } else if (f->explicit_int) {
    out = std::ldexp(static_cast<long double>(frac), static_cast<int>((exp == 0 ? 1 : exp) - bias - (f->frac_bits - 1)));
  } else if (exp == 0) {
    out = std::ldexp(static_cast<long double>(frac), static_cast<int>(1 - bias - f->frac_bits));
  } else {
    frac |= u128{1} << f->frac_bits;
    out = std::ldexp(static_cast<long double>(frac), static_cast<int>(exp - bias - f->frac_bits));
  }
  return neg ? -out : out;
}

Wide encode(long double x, std::uint32_t size) {
  Wide r;
  r.size = size;
  if (size == 4) {
    r.w[0] = std::bit_cast<std::uint32_t>(static_cast<float>(x));
    return r;
  }
  if (size == 8) {
    r.w[0] = std::bit_cast<std::uint64_t>(static_cast<double>(x));
    return r;
  }
  const auto f = format_of(size);
  if (!f) return r;
  const int total = f->exp_bits + f->frac_bits + 1;
  const std::int64_t bias = (std::int64_t{1} << (f->exp_bits - 1)) - 1;
  const std::int64_t max_exp = (std::int64_t{1} << f->exp_bits) - 1;
  u128 bits = 0;
  const bool neg = std::signbit(x);
  if (std::isnan(x)) {
    bits = (static_cast<u128>(max_exp) << f->frac_bits) | (u128{1} << (f->frac_bits - 1));
    if (f->explicit_int) bits |= u128{1} << (f->frac_bits - 2);
  } else if (std::isinf(x)) {
    bits = static_cast<u128>(max_exp) << f->frac_bits;
    if (f->explicit_int) bits |= u128{1} << (f->frac_bits - 1);
  } else if (x != 0) {
    int e = 0;
    const long double m = std::frexp(std::fabs(x), &e);  // x = m * 2^e, 0.5 <= m < 1
    std::int64_t biased = e - 1 + bias;
    const int mant_bits = f->explicit_int ? f->frac_bits : f->frac_bits + 1;  // with the integer bit
    if (biased <= 0) {
      // Subnormal: the fraction holds x / 2^(1 - bias - frac_bits).
      const int shift = static_cast<int>(f->frac_bits - (1 - bias) + (f->explicit_int ? -1 : 0));
      const long double scaled = std::nearbyint(std::ldexp(std::fabs(x), shift));
      bits = static_cast<u128>(scaled);
      if (!f->explicit_int && (bits >> f->frac_bits) != 0) bits = (u128{1} << f->frac_bits);  // rounded up to normal
    } else {
      u128 mant = static_cast<u128>(std::nearbyint(std::ldexp(m, mant_bits)));
      if ((mant >> mant_bits) != 0) {  // rounding carried out
        mant >>= 1;
        ++biased;
      }
      if (biased >= max_exp) {
        bits = static_cast<u128>(max_exp) << f->frac_bits;
        if (f->explicit_int) bits |= u128{1} << (f->frac_bits - 1);
      } else {
        if (!f->explicit_int) mant &= (u128{1} << f->frac_bits) - 1;
        bits = (static_cast<u128>(biased) << f->frac_bits) | mant;
      }
    }
  }
  if (neg) bits |= u128{1} << (total - 1);
  r.w[0] = static_cast<std::uint64_t>(bits);
  r.w[1] = static_cast<std::uint64_t>(bits >> 64);
  r.mask();
  return r;
}

Wide boolean(bool b) { return Wide::of(1, b ? 1 : 0); }

// Signed integer of any width to long double.
long double int_value(const Wide &a) {
  if (a.size <= 8) {
    std::int64_t v = static_cast<std::int64_t>(a.w[0]);
    if (a.size < 8) v = (v << (64 - 8 * a.size)) >> (64 - 8 * a.size);
    return static_cast<long double>(v);
  }
  const bool neg = a.sign();
  const Wide mag = neg ? negate(a) : a;
  long double out = 0;
  for (std::uint32_t i = mag.limbs(); i-- > 0;) out = out * 18446744073709551616.0L + static_cast<long double>(mag.w[i]);
  return neg ? -out : out;
}

// Toward zero into a signed integer of `size` bytes; NaN and out-of-range
// values give the most negative value, as x86's "integer indefinite".
Wide trunc_to(long double x, std::uint32_t size) {
  Wide r = Wide::of(size, 0);
  const long double limit = std::ldexp(1.0L, static_cast<int>(8 * size - 1));
  // Past the signed range but inside the unsigned one: wrap. SLEIGH has no
  // unsigned truncation, so specs write AArch64's FCVTZU and RISC-V's
  // fcvt.lu.d with trunc; this gives what those instructions do.
  if (!std::isnan(x) && x >= limit && x < 2 * limit) {
    long double mag = std::trunc(x);
    for (std::uint32_t i = 0; i < r.limbs() && mag > 0; ++i) {
      const long double q = std::floor(mag / 18446744073709551616.0L);
      r.w[i] = static_cast<std::uint64_t>(mag - q * 18446744073709551616.0L);
      mag = q;
    }
    r.mask();
    return r;
  }
  if (std::isnan(x) || x >= limit || x < -limit) {
    r.w[(8 * size - 1) / 64] |= std::uint64_t{1} << ((8 * size - 1) % 64);
    return r;
  }
  const long double t = std::trunc(x);
  const bool neg = t < 0;
  long double mag = std::fabs(t);
  for (std::uint32_t i = 0; i < r.limbs() && mag > 0; ++i) {
    const long double q = std::floor(mag / 18446744073709551616.0L);
    r.w[i] = static_cast<std::uint64_t>(mag - q * 18446744073709551616.0L);
    mag = q;
  }
  r.mask();
  return neg ? negate(r) : r;
}

template <class T>
Wide arith(int opcode, T a, T b, std::uint32_t size) {
  T v{};
  switch (opcode) {
    case ghidra::CPUI_FLOAT_ADD: v = a + b; break;
    case ghidra::CPUI_FLOAT_SUB: v = a - b; break;
    case ghidra::CPUI_FLOAT_MULT: v = a * b; break;
    case ghidra::CPUI_FLOAT_DIV: v = a / b; break;
    case ghidra::CPUI_FLOAT_NEG: v = -a; break;
    case ghidra::CPUI_FLOAT_ABS: v = std::fabs(a); break;
    case ghidra::CPUI_FLOAT_SQRT: v = std::sqrt(a); break;
    case ghidra::CPUI_FLOAT_CEIL: v = std::ceil(a); break;
    case ghidra::CPUI_FLOAT_FLOOR: v = std::floor(a); break;
    case ghidra::CPUI_FLOAT_ROUND: v = std::floor(a + T(0.5)); break;  // as Ghidra's FloatFormat::opRound
    default: break;
  }
  return encode(static_cast<long double>(v), size);
}

}  // namespace

Wide float_op(int opcode, const Wide &a, const Wide *b, std::uint32_t out_size) {
  const std::uint32_t size = a.size;
  if (!format_of(size) && opcode != ghidra::CPUI_FLOAT_INT2FLOAT)
    throw Fault{StopKind::unimplemented, 0, "float of " + std::to_string(size) + " bytes"};
  switch (opcode) {
    case ghidra::CPUI_FLOAT_EQUAL: return boolean(decode(a, size) == decode(*b, size));
    case ghidra::CPUI_FLOAT_NOTEQUAL: return boolean(decode(a, size) != decode(*b, size));
    case ghidra::CPUI_FLOAT_LESS: return boolean(decode(a, size) < decode(*b, size));
    case ghidra::CPUI_FLOAT_LESSEQUAL: return boolean(decode(a, size) <= decode(*b, size));
    case ghidra::CPUI_FLOAT_NAN: return boolean(std::isnan(decode(a, size)));
    case ghidra::CPUI_FLOAT_INT2FLOAT:
      if (!format_of(out_size)) throw Fault{StopKind::unimplemented, 0, "float of " + std::to_string(out_size) + " bytes"};
      if (out_size == 4 && a.size <= 8) {
        std::int64_t v = static_cast<std::int64_t>(a.w[0]);
        if (a.size < 8) v = (v << (64 - 8 * a.size)) >> (64 - 8 * a.size);
        return encode(static_cast<float>(v), 4);  // one rounding, from the integer
      }
      if (out_size == 8 && a.size <= 8) {
        std::int64_t v = static_cast<std::int64_t>(a.w[0]);
        if (a.size < 8) v = (v << (64 - 8 * a.size)) >> (64 - 8 * a.size);
        return encode(static_cast<double>(v), 8);
      }
      return encode(int_value(a), out_size);
    case ghidra::CPUI_FLOAT_FLOAT2FLOAT:
      if (!format_of(out_size)) throw Fault{StopKind::unimplemented, 0, "float of " + std::to_string(out_size) + " bytes"};
      return encode(decode(a, size), out_size);
    case ghidra::CPUI_FLOAT_TRUNC: return trunc_to(decode(a, size), out_size);
    default: break;
  }
  const bool binary = opcode == ghidra::CPUI_FLOAT_ADD || opcode == ghidra::CPUI_FLOAT_SUB ||
                      opcode == ghidra::CPUI_FLOAT_MULT || opcode == ghidra::CPUI_FLOAT_DIV;
  if (size == 4) {
    const float x = std::bit_cast<float>(static_cast<std::uint32_t>(a.w[0]));
    const float y = binary ? std::bit_cast<float>(static_cast<std::uint32_t>(b->w[0])) : 0.0f;
    return arith<float>(opcode, x, y, 4);
  }
  if (size == 8) {
    const double x = std::bit_cast<double>(a.w[0]);
    const double y = binary ? std::bit_cast<double>(b->w[0]) : 0.0;
    return arith<double>(opcode, x, y, 8);
  }
  return arith<long double>(opcode, decode(a, size), binary ? decode(*b, size) : 0.0L, size);
}

}  // namespace revkit::emu::detail
