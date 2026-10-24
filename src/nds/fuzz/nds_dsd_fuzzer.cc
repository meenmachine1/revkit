// ds-decomp's text files: config.yaml (and the YAML subset), symbols.txt,
// relocs.txt, delinks.txt, and writing symbols.txt back.
#include "revkit/nds/dsd.hh"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  const std::string_view text(reinterpret_cast<const char *>(data), size);
  std::string e;
  (void)revkit::nds::parse_yaml(text, &e);
  (void)revkit::nds::parse_dsd_config(text, &e);
  auto read = [](void *, const std::string &) -> std::optional<std::string> { return std::string("base_address: 0x2000000\n"); };
  (void)revkit::nds::parse_rom_extract(text, read, nullptr, &e);
  revkit::nds::DsdSymbols syms = revkit::nds::parse_dsd_symbols(text);
  (void)revkit::nds::parse_dsd_relocs(text);
  (void)revkit::nds::parse_dsd_delinks(text);
  // Every symbol written back parses to itself.
  std::vector<revkit::nds::ExportSymbol> rk;
  for (const auto &s : syms.symbols) {
    const std::string line = revkit::nds::format_dsd_symbol(s);
    revkit::nds::DsdSymbols again = revkit::nds::parse_dsd_symbols(line);
    if (again.symbols.size() != 1 || again.symbols[0].addr != s.addr || again.symbols[0].name != s.name)
      __builtin_trap();
    revkit::nds::ExportSymbol x;
    x.addr = s.addr + 4;
    x.name = s.name + "_x";
    x.size = 4;
    rk.push_back(x);
    if (rk.size() > 64) break;
  }
  revkit::nds::SymbolsExport ex = revkit::nds::export_dsd_symbols(text, rk, nullptr, nullptr);
  (void)revkit::nds::unified_diff(text.substr(0, 4096), ex.text.substr(0, 4096), "a", "b");
  return 0;
}
