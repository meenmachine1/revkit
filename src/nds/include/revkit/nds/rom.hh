// Nintendo DS ROM images (.nds): the header, the ARM9 and ARM7 programs
// and their overlays, the autoload blocks (ITCM, DTCM) the ARM9 copies out
// at start-up, and the NitroFS file system (FNT and FAT). docs/nds.md.
//
// The format is GBATEK's "DS Cartridge Header" and "DS Cartridge NitroROM
// and NitroARC File Systems" (problemkaputt.de/gbatek.htm), with the ARM9
// module parameters (NitroSDK's `_start_ModuleParams`, found by its
// 0x2106C0DE/0xDEC00621 "nitrocode" words or the ARM9 footer) for the
// autoload list and the compressed static end. Cross-checked against
// ds-rom's reading of the same structures (MIT); no code is taken from it,
// ndstool (GPL) or dsd.
//
// Everything is bounded and checked: an offset or size past the file is
// an error for the header and a warning (the part left out) elsewhere.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace revkit::nds {

struct NdsHeader {
  std::string title;      // 12 bytes, ASCII
  std::string game_code;  // 4
  std::string maker_code; // 2
  std::uint8_t unit_code = 0;  // 0 NDS, 2 NDS+DSi, 3 DSi
  std::uint8_t rom_version = 0;
  std::uint32_t arm9_rom_offset = 0, arm9_entry = 0, arm9_ram_address = 0, arm9_size = 0;
  std::uint32_t arm7_rom_offset = 0, arm7_entry = 0, arm7_ram_address = 0, arm7_size = 0;
  std::uint32_t fnt_offset = 0, fnt_size = 0, fat_offset = 0, fat_size = 0;
  std::uint32_t arm9_overlay_offset = 0, arm9_overlay_size = 0;
  std::uint32_t arm7_overlay_offset = 0, arm7_overlay_size = 0;
  std::uint32_t banner_offset = 0;
  std::uint32_t arm9_autoload_hook = 0, arm7_autoload_hook = 0;
  std::uint32_t rom_size = 0, header_size = 0;
  std::uint16_t header_crc = 0, logo_crc = 0;
  bool header_crc_ok = false;  // CRC-16 of 0x000-0x15D
  bool logo_crc_ok = false;    // the Nintendo logo's checksum is 0xCF56
};

// A 32-byte overlay table entry (y9.bin / y7.bin).
struct NdsOverlay {
  std::uint32_t id = 0;
  std::uint32_t ram_address = 0;
  std::uint32_t ram_size = 0;   // the initialized part
  std::uint32_t bss_size = 0;
  std::uint32_t sinit_start = 0, sinit_end = 0;  // static initializers
  std::uint32_t file_id = 0;
  std::uint32_t compressed_size = 0;  // bits 0-23 of the last word
  bool compressed = false;            // bit 24
  bool authenticated = false;         // bit 25
};

// A NitroFS file: its FAT entry and, for named files, its path.
struct NdsFile {
  std::uint32_t id = 0;
  std::string path;  // "/data/menu.narc"; "" for overlays and unnamed ids
  std::uint32_t start = 0, end = 0;  // ROM offsets (end exclusive)
};

struct NdsDirectory {
  std::uint16_t id = 0xf000;
  std::string path;  // "/" for the root
};

// The ARM9's module parameters (in RAM addresses).
struct NdsModuleParams {
  std::uint32_t offset = 0;  // in the ARM9 binary
  std::uint32_t autoload_list_start = 0, autoload_list_end = 0;
  std::uint32_t autoload_start = 0;  // where the autoload blocks' data starts
  std::uint32_t bss_start = 0, bss_end = 0;
  std::uint32_t compressed_static_end = 0;  // 0: not compressed
  std::uint32_t sdk_version = 0;
};

struct NdsAutoload {
  std::uint32_t address = 0, size = 0, bss_size = 0;
  std::uint32_t sinit_start = 0;  // the 16-byte layout only
};

enum class NdsCpu : std::uint8_t { arm9, arm7 };

// One program to load: where it goes and its bytes (decompressed).
struct NdsModule {
  std::string name;  // "main", "itcm", "dtcm", "autoload_2", "ov006", "arm7", "arm7_ov000"
  NdsCpu cpu = NdsCpu::arm9;
  std::uint32_t address = 0;
  std::vector<std::uint8_t> data;
  std::uint32_t bss_size = 0;
  std::uint32_t entry = 0;      // main and arm7; 0 otherwise
  int overlay_id = -1;
  std::uint32_t sinit_start = 0, sinit_end = 0;
  bool was_compressed = false;
  std::vector<std::string> warnings;
};

struct NdsLimits {
  std::size_t max_module = 64u << 20;   // a decompressed module
  std::size_t max_files = 65536;
  std::size_t max_overlays = 4096;
  std::size_t max_total = 512u << 20;   // all modules
};

struct NdsRom {
  NdsHeader header;
  std::vector<NdsOverlay> arm9_overlays, arm7_overlays;
  std::vector<NdsFile> files;  // by id
  std::vector<NdsDirectory> directories;
  std::optional<NdsModuleParams> params;
  std::vector<NdsAutoload> autoloads;
  std::vector<NdsModule> modules;  // main, autoloads, overlays, arm7, arm7 overlays
  std::vector<std::string> warnings;
};

// Whether `data` starts like a DS ROM: a header whose offsets and sizes
// fit, with a valid header CRC or the logo checksum.
bool is_nds(std::span<const std::uint8_t> data);

// `file_size`: the whole file's, when `data` is only its first bytes
// (0: data's).
std::optional<NdsHeader> parse_nds_header(std::span<const std::uint8_t> data, std::string *error,
                                          std::uint64_t file_size = 0);

// The whole ROM: header, overlay tables, file system and, with `modules`,
// every program decompressed and split (the ARM9's autoloads cut off it).
std::optional<NdsRom> parse_nds(std::span<const std::uint8_t> data, std::string *error, bool modules = true,
                                const NdsLimits &limits = {});

// The module parameters in an ARM9 binary loaded at `ram_address`: the
// nitrocode words, else (with `footer_offset`) the ARM9 footer's pointer.
std::optional<NdsModuleParams> find_module_params(std::span<const std::uint8_t> arm9, std::uint32_t ram_address,
                                                  std::optional<std::uint32_t> footer_offset = std::nullopt);

// Splits an (uncompressed) ARM9 binary into main and its autoloads by the
// module parameters; `main` keeps the bytes up to the autoload data.
void split_autoloads(const NdsModuleParams &p, NdsModule &main, std::vector<NdsAutoload> &lists,
                     std::vector<NdsModule> &out, const NdsLimits &limits);

// The NitroFS tree from the FNT and FAT bytes (each relative to its table).
bool parse_nitrofs(std::span<const std::uint8_t> fnt, std::span<const std::uint8_t> fat, std::vector<NdsFile> &files,
                   std::vector<NdsDirectory> &dirs, std::vector<std::string> &warnings, std::size_t max_files);

// CRC-16 (polynomial 0xA001, initial 0xFFFF), as the header uses.
std::uint16_t crc16(std::span<const std::uint8_t> data, std::uint16_t crc = 0xffff);

// ---- NARC archives -------------------------------------------------------

// A NARC ("NARC" magic; BTAF file allocation, BTNF names, GMIF data).
struct NarcFile {
  std::string path;  // "/a/b.bin", or "/0003.bin" when the archive has no names
  std::uint32_t offset = 0, size = 0;  // in the archive
};

struct Narc {
  std::vector<NarcFile> files;
  std::vector<std::string> directories;
  std::vector<std::string> warnings;
};

bool is_narc(std::span<const std::uint8_t> data);
std::optional<Narc> parse_narc(std::span<const std::uint8_t> data, std::string *error, std::size_t max_files = 65536);

}  // namespace revkit::nds
