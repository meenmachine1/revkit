// CodeView constants: type leaf kinds, symbol kinds, simple type indices
// (internal). Names follow Microsoft's cvinfo.h.
#pragma once

#include <cstdint>

namespace revkit::debuginfo::cv {

// Type records (TPI) and id records (IPI).
enum Leaf : std::uint16_t {
  LF_VTSHAPE = 0x000a,
  LF_LABEL = 0x000e,
  LF_MODIFIER = 0x1001,
  LF_POINTER = 0x1002,
  LF_PROCEDURE = 0x1008,
  LF_MFUNCTION = 0x1009,
  LF_ARGLIST = 0x1201,
  LF_FIELDLIST = 0x1203,
  LF_BITFIELD = 0x1205,
  LF_METHODLIST = 0x1206,
  LF_BCLASS = 0x1400,
  LF_VBCLASS = 0x1401,
  LF_IVBCLASS = 0x1402,
  LF_INDEX = 0x1404,
  LF_VFUNCTAB = 0x1409,
  LF_ENUMERATE = 0x1502,
  LF_ARRAY = 0x1503,
  LF_CLASS = 0x1504,
  LF_STRUCTURE = 0x1505,
  LF_UNION = 0x1506,
  LF_ENUM = 0x1507,
  LF_ALIAS = 0x150a,
  LF_MEMBER = 0x150d,
  LF_STMEMBER = 0x150e,
  LF_METHOD = 0x150f,
  LF_NESTTYPE = 0x1510,
  LF_ONEMETHOD = 0x1511,
  LF_INTERFACE = 0x1519,
  LF_FUNC_ID = 0x1601,
  // MSVC 17.x's (Visual Studio 2022) class records: 32-bit properties.
  LF_CLASS2 = 0x1608,
  LF_STRUCTURE2 = 0x1609,
  LF_INTERFACE2 = 0x160b,
  LF_MFUNC_ID = 0x1602,
  LF_STRING_ID = 0x1605,
  LF_UDT_SRC_LINE = 0x1606,
  LF_UDT_MOD_SRC_LINE = 0x1607,

  // Numeric leaves.
  LF_NUMERIC = 0x8000,
  LF_CHAR = 0x8000,
  LF_SHORT = 0x8001,
  LF_USHORT = 0x8002,
  LF_LONG = 0x8003,
  LF_ULONG = 0x8004,
  LF_REAL32 = 0x8005,
  LF_REAL64 = 0x8006,
  LF_REAL80 = 0x8007,
  LF_REAL128 = 0x8008,
  LF_QUADWORD = 0x8009,
  LF_UQUADWORD = 0x800a,
  LF_REAL48 = 0x800b,
  LF_COMPLEX32 = 0x800c,
  LF_COMPLEX64 = 0x800d,
  LF_COMPLEX80 = 0x800e,
  LF_COMPLEX128 = 0x800f,
  LF_VARSTRING = 0x8010,
  LF_OCTWORD = 0x8017,
  LF_UOCTWORD = 0x8018,
  LF_DECIMAL = 0x8019,
  LF_DATE = 0x801a,
  LF_UTF8STRING = 0x801b,
  LF_REAL16 = 0x801c,
};

// CV_prop_t bits of LF_CLASS/LF_STRUCTURE/LF_UNION/LF_ENUM.
constexpr std::uint16_t kPropPacked = 0x0001;
constexpr std::uint16_t kPropForwardRef = 0x0080;
constexpr std::uint16_t kPropScoped = 0x0100;
constexpr std::uint16_t kPropHasUniqueName = 0x0200;

// LF_POINTER attributes.
constexpr std::uint32_t kPtrModeShift = 5;
constexpr std::uint32_t kPtrModeMask = 0x7;
constexpr std::uint32_t kPtrModePointer = 0;
constexpr std::uint32_t kPtrModeLValueRef = 1;
constexpr std::uint32_t kPtrModeDataMember = 2;
constexpr std::uint32_t kPtrModeMemberFunction = 3;
constexpr std::uint32_t kPtrModeRValueRef = 4;
constexpr std::uint32_t kPtrVolatile = 1u << 9;
constexpr std::uint32_t kPtrConst = 1u << 10;
constexpr std::uint32_t kPtrRestrict = 1u << 12;
constexpr std::uint32_t kPtrSizeShift = 13;
constexpr std::uint32_t kPtrSizeMask = 0x3f;
constexpr std::uint32_t kPtrType64 = 0x0c;  // CV_PTR_64

// LF_MODIFIER bits.
constexpr std::uint16_t kModConst = 0x1;
constexpr std::uint16_t kModVolatile = 0x2;

// CV_call_e.
constexpr std::uint8_t kCallNearC = 0x00;
constexpr std::uint8_t kCallFarC = 0x01;
constexpr std::uint8_t kCallNearPascal = 0x02;
constexpr std::uint8_t kCallFarPascal = 0x03;
constexpr std::uint8_t kCallNearFast = 0x04;
constexpr std::uint8_t kCallFarFast = 0x05;
constexpr std::uint8_t kCallNearStd = 0x07;
constexpr std::uint8_t kCallFarStd = 0x08;
constexpr std::uint8_t kCallThis = 0x0b;
constexpr std::uint8_t kCallClr = 0x16;
constexpr std::uint8_t kCallNearVector = 0x18;

// Symbol records.
enum Sym : std::uint16_t {
  S_END = 0x0006,
  S_FRAMEPROC = 0x1012,
  S_OBJNAME = 0x1101,
  S_THUNK32 = 0x1102,
  S_BLOCK32 = 0x1103,
  S_WITH32 = 0x1104,
  S_LABEL32 = 0x1105,
  S_REGISTER = 0x1106,
  S_CONSTANT = 0x1107,
  S_UDT = 0x1108,
  S_BPREL32 = 0x110b,
  S_LDATA32 = 0x110c,
  S_GDATA32 = 0x110d,
  S_PUB32 = 0x110e,
  S_LPROC32 = 0x110f,
  S_GPROC32 = 0x1110,
  S_REGREL32 = 0x1111,
  S_LTHREAD32 = 0x1112,
  S_GTHREAD32 = 0x1113,
  S_COMPILE2 = 0x1116,
  S_PROCREF = 0x1125,
  S_LPROCREF = 0x1127,
  S_SEPCODE = 0x1132,
  S_COMPILE3 = 0x113c,
  S_LOCAL = 0x113e,
  S_DEFRANGE_REGISTER = 0x1141,
  S_DEFRANGE_FRAMEPOINTER_REL = 0x1142,
  S_DEFRANGE_SUBFIELD_REGISTER = 0x1143,
  S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE = 0x1144,
  S_DEFRANGE_REGISTER_REL = 0x1145,
  S_LPROC32_ID = 0x1146,
  S_GPROC32_ID = 0x1147,
  S_INLINESITE = 0x114d,
  S_INLINESITE_END = 0x114e,
  S_PROC_ID_END = 0x114f,
  S_LPROC32_DPC = 0x1155,
  S_LPROC32_DPC_ID = 0x1156,
  S_INLINESITE2 = 0x115d,
};

// S_LOCAL flags.
constexpr std::uint16_t kLocalIsParam = 0x0001;

// S_GPROC32 flags.
constexpr std::uint8_t kProcNoReturn = 0x08;

// S_PUB32 flags.
constexpr std::uint32_t kPubCode = 0x1;
constexpr std::uint32_t kPubFunction = 0x2;

// Simple type indices (below 0x1000): mode in bits 8-11, kind in bits 0-7.
constexpr std::uint32_t kFirstNonSimple = 0x1000;
constexpr std::uint32_t kSimpleModeShift = 8;
constexpr std::uint32_t kSimpleModeMask = 0xf;
constexpr std::uint32_t kSimpleKindMask = 0xff;
constexpr std::uint32_t T_NOTYPE = 0x0000;
constexpr std::uint32_t T_VOID = 0x0003;

// DBI optional debug header stream slots.
constexpr unsigned kDbgOmapFromSrc = 4;
constexpr unsigned kDbgSectionHdr = 5;
constexpr unsigned kDbgSectionHdrOrig = 10;

constexpr std::uint32_t kPdbVersionVC70 = 20000404;
constexpr std::uint32_t kFeatureVC140 = 20140508;
constexpr std::uint32_t kSymbolSignatureC13 = 4;

}  // namespace revkit::debuginfo::cv
