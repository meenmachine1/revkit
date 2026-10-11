// The subset of DWARF 2-5 constants the reader uses (DWARF 5 spec, ch. 7).
#pragma once

#include <cstdint>

namespace revkit::debuginfo::dw {

enum Tag : std::uint16_t {
  TAG_array_type = 0x01, TAG_class_type = 0x02, TAG_enumeration_type = 0x04,
  TAG_formal_parameter = 0x05, TAG_lexical_block = 0x0b, TAG_member = 0x0d,
  TAG_pointer_type = 0x0f, TAG_reference_type = 0x10, TAG_compile_unit = 0x11,
  TAG_string_type = 0x12, TAG_structure_type = 0x13, TAG_subroutine_type = 0x15,
  TAG_typedef = 0x16, TAG_union_type = 0x17, TAG_unspecified_parameters = 0x18,
  TAG_variant = 0x19, TAG_inheritance = 0x1c, TAG_inlined_subroutine = 0x1d,
  TAG_ptr_to_member_type = 0x1f, TAG_set_type = 0x20, TAG_subrange_type = 0x21,
  TAG_base_type = 0x24, TAG_const_type = 0x26, TAG_enumerator = 0x28,
  TAG_file_type = 0x29, TAG_subprogram = 0x2e, TAG_variable = 0x34,
  TAG_volatile_type = 0x35, TAG_restrict_type = 0x37, TAG_namespace = 0x39,
  TAG_unspecified_type = 0x3b, TAG_partial_unit = 0x3c, TAG_type_unit = 0x41,
  TAG_rvalue_reference_type = 0x42, TAG_atomic_type = 0x47, TAG_immutable_type = 0x4b,
  TAG_skeleton_unit = 0x4a,
};

enum Attr : std::uint16_t {
  AT_sibling = 0x01, AT_location = 0x02, AT_frame_base = 0x40, AT_name = 0x03, AT_byte_size = 0x0b,
  AT_bit_offset = 0x0c, AT_bit_size = 0x0d, AT_low_pc = 0x11, AT_high_pc = 0x12,
  AT_language = 0x13, AT_comp_dir = 0x1b, AT_const_value = 0x1c, AT_inline = 0x20,
  AT_producer = 0x25, AT_prototyped = 0x27, AT_lower_bound = 0x22, AT_upper_bound = 0x2f,
  AT_abstract_origin = 0x31, AT_count = 0x37, AT_data_member_location = 0x38,
  AT_declaration = 0x3c, AT_encoding = 0x3e, AT_external = 0x3f,
  AT_calling_convention = 0x36, AT_specification = 0x47, AT_type = 0x49,
  AT_artificial = 0x34, AT_ranges = 0x55, AT_entry_pc = 0x52, AT_data_bit_offset = 0x6b,
  AT_signature = 0x69, AT_linkage_name = 0x6e, AT_alignment = 0x88, AT_noreturn = 0x87,
  AT_str_offsets_base = 0x72, AT_addr_base = 0x73, AT_rnglists_base = 0x74,
  AT_loclists_base = 0x8c, AT_MIPS_linkage_name = 0x2007, AT_decl_file = 0x3a, AT_stmt_list = 0x10,
};

enum Form : std::uint16_t {
  FORM_addr = 0x01, FORM_block2 = 0x03, FORM_block4 = 0x04, FORM_data2 = 0x05,
  FORM_data4 = 0x06, FORM_data8 = 0x07, FORM_string = 0x08, FORM_block = 0x09,
  FORM_block1 = 0x0a, FORM_data1 = 0x0b, FORM_flag = 0x0c, FORM_sdata = 0x0d,
  FORM_strp = 0x0e, FORM_udata = 0x0f, FORM_ref_addr = 0x10, FORM_ref1 = 0x11,
  FORM_ref2 = 0x12, FORM_ref4 = 0x13, FORM_ref8 = 0x14, FORM_ref_udata = 0x15,
  FORM_indirect = 0x16, FORM_sec_offset = 0x17, FORM_exprloc = 0x18,
  FORM_flag_present = 0x19, FORM_strx = 0x1a, FORM_addrx = 0x1b, FORM_ref_sup4 = 0x1c,
  FORM_strp_sup = 0x1d, FORM_data16 = 0x1e, FORM_line_strp = 0x1f, FORM_ref_sig8 = 0x20,
  FORM_implicit_const = 0x21, FORM_loclistx = 0x22, FORM_rnglistx = 0x23,
  FORM_ref_sup8 = 0x24, FORM_strx1 = 0x25, FORM_strx2 = 0x26, FORM_strx3 = 0x27,
  FORM_strx4 = 0x28, FORM_addrx1 = 0x29, FORM_addrx2 = 0x2a, FORM_addrx3 = 0x2b,
  FORM_addrx4 = 0x2c, FORM_GNU_addr_index = 0x1f01, FORM_GNU_str_index = 0x1f02,
  FORM_GNU_ref_alt = 0x1f20, FORM_GNU_strp_alt = 0x1f21,
};

enum UnitType : std::uint8_t {
  UT_compile = 1, UT_type = 2, UT_partial = 3, UT_skeleton = 4, UT_split_compile = 5,
  UT_split_type = 6,
};

enum Encoding : std::uint8_t {
  ATE_address = 1, ATE_boolean = 2, ATE_complex_float = 3, ATE_float = 4, ATE_signed = 5,
  ATE_signed_char = 6, ATE_unsigned = 7, ATE_unsigned_char = 8, ATE_UTF = 0x10,
};

enum RangeListEntry : std::uint8_t {
  RLE_end_of_list = 0, RLE_base_addressx = 1, RLE_startx_endx = 2, RLE_startx_length = 3,
  RLE_offset_pair = 4, RLE_base_address = 5, RLE_start_end = 6, RLE_start_length = 7,
};

enum Op : std::uint8_t {
  OP_addr = 0x03, OP_constu = 0x10, OP_plus_uconst = 0x23, OP_addrx = 0xa1,
  OP_GNU_addr_index = 0xfb,
};

enum Lang : std::uint16_t {
  LANG_C_plus_plus = 0x04, LANG_C_plus_plus_03 = 0x19, LANG_C_plus_plus_11 = 0x1a,
  LANG_C_plus_plus_14 = 0x21, LANG_C_plus_plus_17 = 0x2a, LANG_C_plus_plus_20 = 0x2b,
};

}  // namespace revkit::debuginfo::dw
