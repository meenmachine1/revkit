// Crash dumps (docs/crash-dumps.md): an ELF core file (ET_CORE: PT_LOAD
// segments and PT_NOTE's NT_PRSTATUS, NT_PRPSINFO, NT_SIGINFO, NT_AUXV,
// NT_FILE) or a Windows minidump (MDMP: thread, module, memory and
// Memory64 lists, the exception stream, system and misc info, x86-64, x86
// and ARM64 thread contexts), read into one model: threads with their
// registers, memory ranges in the file, mapped files and modules, the
// signal or exception and its address. The debugger presents it as a
// stopped, read-only session (CrashTarget in revkit::debug).
//
// Every parser takes hostile bytes: offsets and counts are checked against
// the file, and what doesn't decode is a warning where the rest can be read.
// No dependency on the rest of revkit.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::crash {

using Bytes = std::span<const std::byte>;

class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

enum class Format : std::uint8_t { elf_core, minidump };
std::string_view to_string(Format f);

// A register as the dump stores it, by the name gdb uses ("rax", "x0",
// "pc", "cpsr", "eflags"): little-endian bytes.
struct Register {
  std::string name;
  std::vector<std::uint8_t> value;
  std::string group = "general";  // "general", "flags", "segment", "system"
};

struct Thread {
  std::uint64_t id = 0;  // the LWP (ELF) or thread id (minidump)
  std::vector<Register> registers;
  int signal = 0;  // ELF: pr_cursig
  std::string name;
  // Minidump: its stack's memory range (also in `memory`).
  std::uint64_t stack_start = 0, stack_size = 0;
  std::uint64_t teb = 0;
};

// Bytes of the process's memory the dump holds, at [address, address+size).
struct Segment {
  std::uint64_t address = 0;
  std::uint64_t size = 0;         // bytes in memory
  std::uint64_t file_offset = 0;  // where they start in the dump
  std::uint64_t file_size = 0;    // how many of them the dump has (the rest: not dumped)
  std::string perms;              // "r-x" (ELF; minidump memory info when present)
};

// A file mapped into the process (ELF NT_FILE).
struct MappedFile {
  std::uint64_t start = 0, end = 0;
  std::uint64_t file_offset = 0;  // bytes
  std::string path;
};

// A loaded module: an ELF NT_FILE path's mappings together, or a
// minidump module.
struct Module {
  std::string name;  // file name ("libc.so.6", "KERNEL32.DLL")
  std::string path;
  std::uint64_t base = 0;  // the lowest mapped address
  std::uint64_t size = 0;  // to the end of its last mapping
  bool main = false;       // the executable
  // Minidump: the image's header fields and debug record.
  std::uint32_t timestamp = 0, checksum = 0;
  std::string version;         // "10.0.19041.1" from VS_FIXEDFILEINFO
  std::string pdb_name;        // RSDS's PDB path
  std::string pdb_guid;        // and GUID+age, symbol-server style
  std::string build_id;        // ELF (BpEL) build ID, hex
};

struct CrashDump {
  Format format = Format::elf_core;
  // "x86-64", "x86", "AArch64", "ARM", "RISC-V"; the ELF e_machine (or the
  // minidump's processor architecture).
  std::string arch;
  std::uint16_t machine = 0;
  unsigned pointer_size = 8;
  bool big_endian = false;

  std::vector<Thread> threads;
  std::size_t crashed_thread = 0;  // index into threads

  // What stopped it. ELF: the signal (NT_SIGINFO, else the first
  // PRSTATUS's), its code and the fault address for SIGSEGV, SIGBUS,
  // SIGILL, SIGFPE, SIGTRAP. Minidump: the exception.
  int signal = 0;
  int signal_code = 0;
  std::string signal_name;  // "SIGSEGV"
  std::string code_name;    // "SEGV_MAPERR"
  std::optional<std::uint64_t> fault_address;
  std::uint32_t exception_code = 0;  // minidump
  std::uint32_t exception_flags = 0;
  std::string exception_name;  // "EXCEPTION_ACCESS_VIOLATION"
  std::optional<std::uint64_t> exception_address;
  std::vector<std::uint64_t> exception_parameters;
  std::string access;  // an access violation's "read", "write", "execute"
  // A one-line description: "SIGSEGV (SEGV_MAPERR) at 0x0".
  std::string reason;

  std::map<std::uint64_t, std::uint64_t> auxv;  // NT_AUXV
  std::vector<MappedFile> files;               // NT_FILE
  std::vector<Module> modules;
  std::vector<Segment> memory;  // sorted by address

  // The process.
  std::int64_t pid = 0, ppid = 0;
  std::uint32_t uid = 0, gid = 0;
  std::string command;  // pr_fname
  std::string args;     // pr_psargs
  // The system (minidump SystemInfo, MiscInfo).
  std::string os;   // "Windows 10.0.19045", "Linux", "Android"
  std::string cpu;  // "x86-64, 8 processors"
  std::uint32_t timestamp = 0;
  std::vector<std::string> comments;  // minidump comment streams

  std::vector<std::string> warnings;

  // The module holding an address, if any.
  const Module *module_at(std::uint64_t address) const;
  // Reads dumped memory into out; returns the bytes read, listing in
  // `missing` the [offset, length) ranges of out the dump doesn't hold.
  std::size_t read(Bytes file, std::uint64_t address, std::span<std::uint8_t> out,
                   std::vector<std::pair<std::uint32_t, std::uint32_t>> *missing = nullptr) const;
};

struct Limits {
  std::size_t max_threads = 1u << 14;
  std::size_t max_segments = 1u << 20;
  std::size_t max_files = 1u << 18;
  std::size_t max_modules = 1u << 14;
};

bool is_elf_core(Bytes head);
bool is_minidump(Bytes head);
// Either, by its header; Error when it is neither.
CrashDump parse(Bytes file, const Limits &limits = {});
CrashDump parse_elf_core(Bytes file, const Limits &limits = {});
CrashDump parse_minidump(Bytes file, const Limits &limits = {});

// Linux's signal names and si_code names; Windows's exception names.
std::string signal_name(int signal);
std::string signal_code_name(int signal, int code);
std::string exception_name(std::uint32_t code);

}  // namespace revkit::crash
