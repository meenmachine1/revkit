#include "die.h"

#include "dwarf_constants.h"

#include <algorithm>
#include <limits>

namespace revkit::debuginfo {
namespace {

// Bounds on loops driven by input data, so malformed input fails fast.
constexpr int kMaxIndirect = 8;
constexpr std::size_t kMaxRangeEntries = 1 << 20;

std::uint64_t all_ones(unsigned bytes) {
  return bytes >= 8 ? ~std::uint64_t(0) : (std::uint64_t(1) << (8 * bytes)) - 1;
}

bool is_address_form(std::uint16_t form) {
  switch (form) {
    case dw::FORM_addr:
    case dw::FORM_addrx:
    case dw::FORM_addrx1:
    case dw::FORM_addrx2:
    case dw::FORM_addrx3:
    case dw::FORM_addrx4:
    case dw::FORM_GNU_addr_index: return true;
    default: return false;
  }
}

std::int64_t sign_extend(std::uint64_t v, unsigned bytes) {
  if (bytes >= 8) return std::int64_t(v);
  unsigned shift = 64 - 8 * bytes;
  return std::int64_t(v << shift) >> shift;
}

}  // namespace

bool Unit::is_cxx() const {
  switch (language) {
    case dw::LANG_C_plus_plus:
    case dw::LANG_C_plus_plus_03:
    case dw::LANG_C_plus_plus_11:
    case dw::LANG_C_plus_plus_14:
    case dw::LANG_C_plus_plus_17:
    case dw::LANG_C_plus_plus_20: return true;
    default: return false;
  }
}

Dwarf::Dwarf(const Sections &sections, std::vector<Diagnostic> &diags)
    : info_(sections.get(".debug_info")),
      abbrev_(sections.get(".debug_abbrev")),
      str_(sections.get(".debug_str")),
      line_str_(sections.get(".debug_line_str")),
      str_offsets_(sections.get(".debug_str_offsets")),
      addr_(sections.get(".debug_addr")),
      rnglists_(sections.get(".debug_rnglists")),
      ranges_(sections.get(".debug_ranges")),
      line_(sections.get(".debug_line")),
      big_endian_(sections.byte_order == std::endian::big),
      diags_(diags) {
  Cursor c(info_, big_endian_);
  while (!c.at_end()) {
    std::uint64_t off = c.pos();
    try {
      parse_unit(c, off);
    } catch (const FormatError &e) {
      // The unit header itself is bad, so we can't find the next unit.
      diags_.push_back({off, std::string("unit header: ") + e.what()});
      break;
    }
  }
  for (Unit &u : units_) read_unit_bases(u);
}

void Dwarf::parse_unit(Cursor &c, std::uint64_t unit_offset) {
  Unit u;
  u.offset = unit_offset;
  std::uint64_t length = c.u32();
  if (length == 0xffffffffu) {
    length = c.u64();
    u.dwarf64 = true;
  } else if (length >= 0xfffffff0u) {
    throw FormatError("reserved unit length");
  }
  if (length > c.remaining()) throw FormatError("unit extends past end of .debug_info");
  u.end = c.pos() + length;
  // Everything after the length is bounded by the unit, so a bad unit can
  // be skipped.
  Cursor uc(info_.first(std::size_t(u.end)), big_endian_, c.pos());
  c.seek(u.end);
  try {
    u.version = uc.u16();
    if (u.version < 2 || u.version > 5) {
      diags_.push_back({unit_offset, "unsupported DWARF version " + std::to_string(u.version)});
      return;
    }
    std::uint64_t abbrev_offset;
    if (u.version >= 5) {
      u.unit_type = uc.u8();
      u.addr_size = uc.u8();
      abbrev_offset = uc.un(u.offset_size());
      switch (u.unit_type) {
        case dw::UT_type:
        case dw::UT_split_type:
          u.type_signature = uc.u64();
          u.type_offset = unit_offset + uc.un(u.offset_size());
          break;
        case dw::UT_skeleton:
        case dw::UT_split_compile: uc.u64(); break;  // dwo_id
        case dw::UT_compile:
        case dw::UT_partial: break;
        default:
          diags_.push_back({unit_offset, "unknown unit type " + std::to_string(u.unit_type)});
          return;
      }
    } else {
      u.unit_type = dw::UT_compile;
      abbrev_offset = uc.un(u.offset_size());
      u.addr_size = uc.u8();
    }
    if (u.addr_size != 1 && u.addr_size != 2 && u.addr_size != 4 && u.addr_size != 8)
      throw FormatError("bad address size " + std::to_string(u.addr_size));
    u.abbrevs = abbrevs_at(abbrev_offset);
  } catch (const FormatError &e) {
    diags_.push_back({unit_offset, std::string("unit header: ") + e.what()});
    return;
  }

  const std::uint32_t unit_index = std::uint32_t(units_.size());
  u.first_die = std::uint32_t(dies_.size());
  if (u.unit_type == dw::UT_type || u.unit_type == dw::UT_split_type)
    type_sigs_.emplace(u.type_signature, u.type_offset);
  units_.push_back(u);
  const Unit &unit = units_.back();

  std::vector<std::uint32_t> parents, last_child;
  std::uint32_t last_top = kNoDie;
  try {
    while (!uc.at_end()) {
      std::uint64_t die_offset = uc.pos();
      std::uint64_t code = uc.uleb();
      if (code == 0) {
        if (!parents.empty()) {
          parents.pop_back();
          last_child.pop_back();
        }
        continue;
      }
      auto it = unit.abbrevs->find(code);
      if (it == unit.abbrevs->end()) throw FormatError("unknown abbreviation code");
      const Abbrev &ab = it->second;
      Die d;
      d.offset = die_offset;
      d.unit = unit_index;
      d.tag = ab.tag;
      d.parent = parents.empty() ? kNoDie : parents.back();
      d.attr_begin = std::uint32_t(attrs_.size());
      for (const AttrSpec &spec : ab.attrs) attrs_.push_back(read_attr(uc, unit, spec));
      d.attr_count = std::uint16_t(ab.attrs.size());
      std::uint32_t idx = std::uint32_t(dies_.size());
      dies_.push_back(d);
      if (parents.empty()) {
        if (last_top != kNoDie) dies_[last_top].next_sibling = idx;
        last_top = idx;
      } else {
        if (last_child.back() == kNoDie) dies_[parents.back()].first_child = idx;
        else dies_[last_child.back()].next_sibling = idx;
        last_child.back() = idx;
      }
      if (ab.has_children) {
        parents.push_back(idx);
        last_child.push_back(kNoDie);
      }
    }
  } catch (const FormatError &e) {
    // Keep the DIEs read so far; their links are consistent.
    diags_.push_back({uc.pos(), std::string("DIE: ") + e.what()});
  }
  units_[unit_index].die_count = std::uint32_t(dies_.size()) - units_[unit_index].first_die;
}

const AbbrevTable *Dwarf::abbrevs_at(std::uint64_t offset) {
  if (auto it = abbrev_cache_.find(offset); it != abbrev_cache_.end()) return &it->second;
  AbbrevTable table;
  Cursor c(abbrev_, big_endian_, std::size_t(std::min<std::uint64_t>(offset, abbrev_.size())));
  if (offset > abbrev_.size()) throw FormatError("abbreviation offset past end of section");
  for (;;) {
    std::uint64_t code = c.uleb();
    if (code == 0) break;
    Abbrev ab;
    ab.tag = std::uint16_t(c.uleb());
    ab.has_children = c.u8() != 0;
    for (;;) {
      std::uint64_t at = c.uleb();
      std::uint64_t form = c.uleb();
      if (at == 0 && form == 0) break;
      std::int64_t implicit = form == dw::FORM_implicit_const ? c.sleb() : 0;
      if (ab.attrs.size() == std::numeric_limits<std::uint16_t>::max())
        throw FormatError("too many attributes in abbreviation");
      ab.attrs.push_back({std::uint16_t(at), std::uint16_t(form), implicit});
    }
    table.try_emplace(code, std::move(ab));
  }
  return &abbrev_cache_.emplace(offset, std::move(table)).first->second;
}

AttrValue Dwarf::read_attr(Cursor &c, const Unit &u, const AttrSpec &spec) {
  AttrValue v{spec.at, spec.form, 0, {}};
  auto block = [&](std::uint64_t n) {
    auto b = c.bytes(n);
    v.bytes = {reinterpret_cast<const char *>(b.data()), b.size()};
  };
  for (int hops = 0;; ++hops) {
    switch (v.form) {
      case dw::FORM_addr: v.u = c.un(u.addr_size); return v;
      case dw::FORM_block1: block(c.u8()); return v;
      case dw::FORM_block2: block(c.u16()); return v;
      case dw::FORM_block4: block(c.u32()); return v;
      case dw::FORM_block:
      case dw::FORM_exprloc: block(c.uleb()); return v;
      case dw::FORM_data1:
      case dw::FORM_flag:
      case dw::FORM_strx1:
      case dw::FORM_addrx1: v.u = c.u8(); return v;
      case dw::FORM_data2:
      case dw::FORM_strx2:
      case dw::FORM_addrx2: v.u = c.u16(); return v;
      case dw::FORM_strx3:
      case dw::FORM_addrx3: v.u = c.un(3); return v;
      case dw::FORM_data4:
      case dw::FORM_strx4:
      case dw::FORM_addrx4:
      case dw::FORM_ref_sup4: v.u = c.u32(); return v;
      case dw::FORM_data8:
      case dw::FORM_ref_sig8:
      case dw::FORM_ref_sup8: v.u = c.u64(); return v;
      case dw::FORM_data16: block(16); return v;
      case dw::FORM_string: v.bytes = c.cstr(); return v;
      case dw::FORM_sdata: v.u = std::uint64_t(c.sleb()); return v;
      case dw::FORM_udata:
      case dw::FORM_strx:
      case dw::FORM_addrx:
      case dw::FORM_loclistx:
      case dw::FORM_rnglistx:
      case dw::FORM_GNU_addr_index:
      case dw::FORM_GNU_str_index: v.u = c.uleb(); return v;
      case dw::FORM_strp:
      case dw::FORM_line_strp:
      case dw::FORM_sec_offset:
      case dw::FORM_strp_sup:
      case dw::FORM_GNU_ref_alt:
      case dw::FORM_GNU_strp_alt: v.u = c.un(u.offset_size()); return v;
      case dw::FORM_ref_addr: v.u = c.un(u.version <= 2 ? u.addr_size : u.offset_size()); return v;
      case dw::FORM_ref1: v.u = u.offset + c.u8(); return v;
      case dw::FORM_ref2: v.u = u.offset + c.u16(); return v;
      case dw::FORM_ref4: v.u = u.offset + c.u32(); return v;
      case dw::FORM_ref8: v.u = u.offset + c.u64(); return v;
      case dw::FORM_ref_udata: v.u = u.offset + c.uleb(); return v;
      case dw::FORM_flag_present: v.u = 1; return v;
      case dw::FORM_implicit_const: v.u = std::uint64_t(spec.implicit_const); return v;
      case dw::FORM_indirect:
        if (hops >= kMaxIndirect) throw FormatError("DW_FORM_indirect loop");
        v.form = std::uint16_t(c.uleb());
        if (v.form == dw::FORM_implicit_const) throw FormatError("indirect implicit_const");
        continue;
      default: throw FormatError("unknown form " + std::to_string(v.form));
    }
  }
}

void Dwarf::read_unit_bases(Unit &u) {
  if (u.die_count == 0) return;
  std::uint32_t root = u.first_die;
  u.str_offsets_base = unsigned_value(root, dw::AT_str_offsets_base);
  u.addr_base = unsigned_value(root, dw::AT_addr_base);
  u.rnglists_base = unsigned_value(root, dw::AT_rnglists_base);
  u.language = std::uint16_t(unsigned_value(root, dw::AT_language).value_or(0));
  u.base_address = address(root, dw::AT_low_pc).value_or(0);
}

const AttrValue *Dwarf::find(std::uint32_t die, std::uint16_t at) const {
  for (const AttrValue &v : attrs(die))
    if (v.at == at) return &v;
  return nullptr;
}

std::optional<std::string_view> Dwarf::str_at(std::span<const std::uint8_t> sec,
                                              std::uint64_t off) const {
  if (off >= sec.size()) return std::nullopt;
  try {
    Cursor c(sec, big_endian_, std::size_t(off));
    return c.cstr();
  } catch (const FormatError &) {
    return std::nullopt;
  }
}

std::optional<std::string_view> Dwarf::string(std::uint32_t die, std::uint16_t at) const {
  const AttrValue *v = find(die, at);
  if (!v) return std::nullopt;
  switch (v->form) {
    case dw::FORM_string: return v->bytes;
    case dw::FORM_strp: return str_at(str_, v->u);
    case dw::FORM_line_strp: return str_at(line_str_, v->u);
    case dw::FORM_strx:
    case dw::FORM_strx1:
    case dw::FORM_strx2:
    case dw::FORM_strx3:
    case dw::FORM_strx4:
    case dw::FORM_GNU_str_index: {
      const Unit &u = unit_of(die);
      if (!u.str_offsets_base) return std::nullopt;
      std::uint64_t size = u.offset_size();
      if (v->u > (std::numeric_limits<std::uint64_t>::max() - *u.str_offsets_base) / size)
        return std::nullopt;
      std::uint64_t pos = *u.str_offsets_base + v->u * size;
      if (pos > str_offsets_.size() || str_offsets_.size() - pos < size) return std::nullopt;
      Cursor c(str_offsets_, big_endian_, std::size_t(pos));
      return str_at(str_, c.un(unsigned(size)));
    }
    default: return std::nullopt;
  }
}

std::optional<std::uint64_t> Dwarf::unsigned_value(std::uint32_t die, std::uint16_t at) const {
  const AttrValue *v = find(die, at);
  if (!v) return std::nullopt;
  switch (v->form) {
    case dw::FORM_data1:
    case dw::FORM_data2:
    case dw::FORM_data4:
    case dw::FORM_data8:
    case dw::FORM_udata:
    case dw::FORM_sdata:
    case dw::FORM_implicit_const:
    case dw::FORM_flag:
    case dw::FORM_flag_present:
    case dw::FORM_sec_offset: return v->u;
    default: return std::nullopt;
  }
}

std::optional<std::int64_t> Dwarf::signed_value(std::uint32_t die, std::uint16_t at) const {
  const AttrValue *v = find(die, at);
  if (!v) return std::nullopt;
  switch (v->form) {
    case dw::FORM_data1: return sign_extend(v->u, 1);
    case dw::FORM_data2: return sign_extend(v->u, 2);
    case dw::FORM_data4: return sign_extend(v->u, 4);
    case dw::FORM_data8:
    case dw::FORM_udata:
    case dw::FORM_sdata:
    case dw::FORM_implicit_const: return std::int64_t(v->u);
    default: return std::nullopt;
  }
}

std::optional<std::uint64_t> Dwarf::addr_index(const Unit &u, std::uint64_t index) const {
  // Without DW_AT_addr_base, assume the first contribution (header size 8).
  std::uint64_t base = u.addr_base.value_or(8);
  if (index > (std::numeric_limits<std::uint64_t>::max() - base) / u.addr_size) return std::nullopt;
  std::uint64_t pos = base + index * u.addr_size;
  if (pos > addr_.size() || addr_.size() - pos < u.addr_size) return std::nullopt;
  Cursor c(addr_, big_endian_, std::size_t(pos));
  return c.un(u.addr_size);
}

std::optional<std::uint64_t> Dwarf::address(std::uint32_t die, std::uint16_t at) const {
  const AttrValue *v = find(die, at);
  if (!v) return std::nullopt;
  if (v->form == dw::FORM_addr) return v->u;
  if (is_address_form(v->form)) return addr_index(unit_of(die), v->u);
  return std::nullopt;
}

bool Dwarf::flag(std::uint32_t die, std::uint16_t at) const {
  const AttrValue *v = find(die, at);
  return v && (v->form == dw::FORM_flag_present || (v->form == dw::FORM_flag && v->u != 0));
}

std::uint32_t Dwarf::die_at(std::uint64_t offset) const {
  auto it = std::lower_bound(dies_.begin(), dies_.end(), offset,
                             [](const Die &d, std::uint64_t off) { return d.offset < off; });
  if (it == dies_.end() || it->offset != offset) return kNoDie;
  return std::uint32_t(it - dies_.begin());
}

std::uint32_t Dwarf::ref(std::uint32_t die, std::uint16_t at) const {
  const AttrValue *v = find(die, at);
  if (!v) return kNoDie;
  switch (v->form) {
    case dw::FORM_ref1:
    case dw::FORM_ref2:
    case dw::FORM_ref4:
    case dw::FORM_ref8:
    case dw::FORM_ref_udata:
    case dw::FORM_ref_addr: return die_at(v->u);
    case dw::FORM_ref_sig8: {
      auto it = type_sigs_.find(v->u);
      return it == type_sigs_.end() ? kNoDie : die_at(it->second);
    }
    default: return kNoDie;
  }
}

std::vector<AddressRange> Dwarf::ranges(std::uint32_t die) const {
  std::vector<AddressRange> out;
  const Unit &u = unit_of(die);
  if (auto lo = address(die, dw::AT_low_pc)) {
    std::optional<std::uint64_t> hi;
    if (const AttrValue *h = find(die, dw::AT_high_pc)) {
      if (is_address_form(h->form)) hi = address(die, dw::AT_high_pc);
      else if (auto len = unsigned_value(die, dw::AT_high_pc)) hi = *lo + *len;
    }
    if (hi && *hi > *lo) out.push_back({*lo, *hi});
  }
  if (const AttrValue *r = find(die, dw::AT_ranges)) {
    try {
      if (r->form == dw::FORM_rnglistx) {
        if (u.rnglists_base) {
          std::uint64_t size = u.offset_size();
          std::uint64_t pos = *u.rnglists_base + r->u * size;
          if (r->u < (std::uint64_t(1) << 56) && pos <= rnglists_.size() &&
              rnglists_.size() - pos >= size) {
            Cursor c(rnglists_, big_endian_, std::size_t(pos));
            std::vector<AddressRange> l = rnglist(u, *u.rnglists_base + c.un(unsigned(size)));
            out.insert(out.end(), l.begin(), l.end());
          }
        }
      } else if (auto off = unsigned_value(die, dw::AT_ranges)) {
        auto l = u.version >= 5 ? rnglist(u, *off) : debug_ranges(u, *off);
        out.insert(out.end(), l.begin(), l.end());
      }
    } catch (const FormatError &) {
    }
  }
  // Ranges of code the linker discarded point at a tombstone address.
  const std::uint64_t tomb = all_ones(u.addr_size);
  std::erase_if(out, [&](const AddressRange &r) { return r.begin >= tomb - 1 || r.end <= r.begin; });
  return out;
}

std::vector<AddressRange> Dwarf::rnglist(const Unit &u, std::uint64_t offset) const {
  std::vector<AddressRange> out;
  if (offset >= rnglists_.size()) return out;
  Cursor c(rnglists_, big_endian_, std::size_t(offset));
  std::uint64_t base = u.base_address;
  auto idx = [&](std::uint64_t i) {
    auto a = addr_index(u, i);
    if (!a) throw FormatError("bad address index");
    return *a;
  };
  try {
    for (std::size_t n = 0; n < kMaxRangeEntries; ++n) {
      std::uint8_t kind = c.u8();
      std::uint64_t b, e;
      switch (kind) {
        case dw::RLE_end_of_list: return out;
        case dw::RLE_base_addressx: base = idx(c.uleb()); continue;
        case dw::RLE_base_address: base = c.un(u.addr_size); continue;
        case dw::RLE_startx_endx: b = idx(c.uleb()); e = idx(c.uleb()); break;
        case dw::RLE_startx_length: b = idx(c.uleb()); e = b + c.uleb(); break;
        case dw::RLE_offset_pair: b = base + c.uleb(); e = base + c.uleb(); break;
        case dw::RLE_start_end: b = c.un(u.addr_size); e = c.un(u.addr_size); break;
        case dw::RLE_start_length: b = c.un(u.addr_size); e = b + c.uleb(); break;
        default: return out;
      }
      if (e > b) out.push_back({b, e});
    }
  } catch (const FormatError &) {
  }
  return out;
}

std::vector<AddressRange> Dwarf::debug_ranges(const Unit &u, std::uint64_t offset) const {
  std::vector<AddressRange> out;
  if (offset >= ranges_.size()) return out;
  Cursor c(ranges_, big_endian_, std::size_t(offset));
  std::uint64_t base = u.base_address;
  const std::uint64_t select = all_ones(u.addr_size);
  try {
    for (std::size_t n = 0; n < kMaxRangeEntries; ++n) {
      std::uint64_t b = c.un(u.addr_size), e = c.un(u.addr_size);
      if (b == 0 && e == 0) break;
      if (b == select) {
        base = e;
        continue;
      }
      if (e > b) out.push_back({base + b, base + e});
    }
  } catch (const FormatError &) {
  }
  return out;
}

std::optional<std::uint64_t> Dwarf::static_address(std::uint32_t die) const {
  const AttrValue *v = find(die, dw::AT_location);
  if (!v || v->bytes.empty()) return std::nullopt;
  switch (v->form) {
    case dw::FORM_exprloc:
    case dw::FORM_block:
    case dw::FORM_block1:
    case dw::FORM_block2:
    case dw::FORM_block4: break;
    default: return std::nullopt;  // a location list: not a static variable
  }
  const Unit &u = unit_of(die);
  std::span<const std::uint8_t> expr(reinterpret_cast<const std::uint8_t *>(v->bytes.data()),
                                     v->bytes.size());
  try {
    Cursor c(expr, big_endian_);
    std::uint8_t op = c.u8();
    std::optional<std::uint64_t> addr;
    if (op == dw::OP_addr) addr = c.un(u.addr_size);
    else if (op == dw::OP_addrx || op == dw::OP_GNU_addr_index) addr = addr_index(u, c.uleb());
    if (!c.at_end()) return std::nullopt;  // e.g. TLS: DW_OP_addr x; DW_OP_GNU_push_tls_address
    return addr;
  } catch (const FormatError &) {
    return std::nullopt;
  }
}

std::vector<std::string_view> Dwarf::file_names(const Unit &u) const {
  std::vector<std::string_view> out;
  if (u.first_die == kNoDie || line_.empty()) return out;
  const AttrValue *stmt = find(u.first_die, dw::AT_stmt_list);
  if (!stmt) return out;
  try {
    Cursor c(line_, big_endian_, std::size_t(stmt->u));
    std::uint64_t length = c.u32();
    unsigned offset_size = 4;
    if (length == 0xffffffffu) {
      length = c.u64();
      offset_size = 8;
    }
    const std::size_t end = c.pos() + std::size_t(std::min<std::uint64_t>(length, c.remaining()));
    const std::uint16_t version = c.u16();
    if (version < 2 || version > 5) return out;
    if (version >= 5) c.skip(2);  // address_size, segment_selector_size
    c.skip(offset_size);          // header_length
    c.skip(version >= 4 ? 5 : 4);  // min_inst_length, [max_ops], default_is_stmt, line_base, line_range
    const std::uint8_t opcode_base = c.u8();
    if (opcode_base > 0) c.skip(opcode_base - 1u);
    auto string_form = [&](std::uint64_t form) -> std::optional<std::string_view> {
      switch (form) {
        case dw::FORM_string: return c.cstr();
        case dw::FORM_line_strp: return str_at(line_str_, c.un(offset_size));
        case dw::FORM_strp: return str_at(str_, c.un(offset_size));
        default: return std::nullopt;
      }
    };
    auto skip_form = [&](std::uint64_t form) {
      switch (form) {
        case dw::FORM_string: (void)c.cstr(); break;
        case dw::FORM_line_strp:
        case dw::FORM_strp:
        case dw::FORM_sec_offset: c.skip(offset_size); break;
        case dw::FORM_udata: (void)c.uleb(); break;
        case dw::FORM_data1:
        case dw::FORM_strx1: c.skip(1); break;
        case dw::FORM_data2:
        case dw::FORM_strx2: c.skip(2); break;
        case dw::FORM_strx3: c.skip(3); break;
        case dw::FORM_data4:
        case dw::FORM_strx4: c.skip(4); break;
        case dw::FORM_data8: c.skip(8); break;
        case dw::FORM_data16: c.skip(16); break;
        case dw::FORM_block: c.skip(c.uleb()); break;
        case dw::FORM_strx: (void)c.uleb(); break;
        default: throw FormatError("unsupported line table form");
      }
    };
    if (version < 5) {
      while (c.pos() < end && !c.cstr().empty()) {}  // include_directories
      while (c.pos() < end) {
        std::string_view name = c.cstr();
        if (name.empty()) break;
        (void)c.uleb();  // directory
        (void)c.uleb();  // mtime
        (void)c.uleb();  // length
        out.push_back(name);
        if (out.size() > 100000) break;
      }
      // DW_AT_decl_file 1 is the first entry (0: none).
      out.insert(out.begin(), std::string_view{});
      return out;
    }
    // DWARF 5: entry formats, then directories and file names.
    auto read_table = [&](bool keep) {
      const std::uint8_t format_count = c.u8();
      std::vector<std::pair<std::uint64_t, std::uint64_t>> formats;
      for (unsigned i = 0; i < format_count; ++i) {
        const std::uint64_t type = c.uleb();
        formats.emplace_back(type, c.uleb());
      }
      const std::uint64_t count = c.uleb();
      for (std::uint64_t i = 0; i < count && c.pos() < end && i < 100000; ++i) {
        std::string_view path;
        for (const auto &[type, form] : formats) {
          if (type == 1 /* DW_LNCT_path */) {
            if (auto s = string_form(form)) path = *s;
            else skip_form(form);
          } else {
            skip_form(form);
          }
        }
        if (keep) out.push_back(path);
      }
    };
    read_table(false);
    read_table(true);
  } catch (const FormatError &) {
  }
  return out;
}

std::string_view Dwarf::decl_file(std::uint32_t die) const {
  auto index = unsigned_value(die, dw::AT_decl_file);
  if (!index) return {};
  const std::uint32_t unit = dies_[die].unit;
  auto it = files_.find(unit);
  if (it == files_.end()) it = files_.emplace(unit, file_names(units_[unit])).first;
  if (*index >= it->second.size()) return {};
  return it->second[std::size_t(*index)];
}

}  // namespace revkit::debuginfo
