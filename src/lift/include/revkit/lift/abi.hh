// What a language's processor and compiler specs say about calls, for code
// that runs machine code rather than decompiling it (revkit::emu): the
// program counter (.pspec), the stack pointer, where a call leaves its
// return address, and the default prototype's integer parameter and return
// registers (.cspec).
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace revkit::lift {

struct Abi {
  std::string program_counter;  // <programcounter register=...>
  std::string stack_pointer;    // <stackpointer register=...>
  // <returnaddress>: a register (ARM lr, AArch64 x30, RISC-V ra), or a
  // stack slot at this offset from the stack pointer after the call (x86).
  std::string return_register;
  std::optional<std::int64_t> return_stack_offset;
  std::uint32_t return_size = 0;  // bytes of the return address slot
  // The default prototype: bytes the call itself moves the stack pointer
  // (x86's pushed return address), and what the callee pops beyond it
  // (extrapop - stackshift; nullopt when the cspec says "unknown").
  std::string default_model;
  std::int64_t stack_shift = 0;
  std::optional<std::int64_t> extrapop;
  // Integer parameters in order, and the integer return register(s): the
  // default prototype's register entries that aren't float.
  std::vector<std::string> int_params;
  std::vector<std::string> int_returns;
  // The default prototype's <unaffected> registers: what a call preserves
  // (callee-saved registers, the stack pointer), floats included.
  std::vector<std::string> call_preserved;
};

// Reads `language`'s .pspec and its `compiler`'s .cspec (the language's
// first compiler when empty or unknown). Throws LiftError for an unknown
// language or unreadable specs.
Abi read_abi(const std::string &language, const std::string &compiler);

// The compiler spec's call fixups by the function names they are for
// (<callfixup name="switch8_r0"><target name="__gnu_thumb1_case_uqi"/>):
// a call to a function with such a name is replaced by the fixup's p-code,
// as Ghidra's Call-Fixup Installer sets it on functions by name. Read once
// per language and compiler; empty when the specs can't be read.
const std::map<std::string, std::string> &call_fixup_targets(const std::string &language, const std::string &compiler);

// The compiler spec's prototype model names: every <prototype> (the
// default one too) and <modelalias> ("__stdcall", "__fastcall", "MSABI"),
// what a function's calling convention may name. Read once per language
// and compiler; empty when the specs can't be read. `language` may carry
// the compiler as its last part ("x86:LE:32:default:windows").
const std::set<std::string> &prototype_models(const std::string &language, const std::string &compiler);

// A compiler spec's <data_organization> as written: each element's value by
// its name ("pointer_size", "long_double_size", ...), the size alignment
// map, plain char's signedness (<char_type signed=...>) and Microsoft
// bitfield packing. Read the same way ImageArchitecture reads it for the
// decompiler's core types. revkit::cparse turns it into layout rules.
struct DataOrganization {
  bool present = false;
  std::map<std::string, long> values;
  std::vector<std::pair<long, long>> size_alignment;
  std::optional<bool> char_signed;
  bool ms_bitfields = false;
};
DataOrganization read_data_organization(const std::string &language, const std::string &compiler);

}  // namespace revkit::lift
