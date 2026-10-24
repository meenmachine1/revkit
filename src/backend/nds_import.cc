#include "nds_import.h"

#include "open_beneath.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace revkit::backend {

namespace fs = std::filesystem;

namespace {

constexpr const char *kArm9Language = "ARM:LE:32:v5t";
constexpr const char *kArm7Language = "ARM:LE:32:v4t";

std::string Hex(std::uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "0x%08llx", static_cast<unsigned long long>(v));
  return b;
}

struct Reader {
  const NdsPlanOptions &options;
  std::vector<std::string> *warnings;

  // The file at `p` (canonical, allowed, at most max_file bytes); nullopt
  // with a warning otherwise.
  std::optional<std::string> read(const fs::path &p, bool quiet = false) {
    std::error_code ec;
    const fs::path c = fs::weakly_canonical(p, ec);
    if (ec || !fs::is_regular_file(c, ec)) {
      if (!quiet) warnings->push_back(p.string() + ": missing");
      return std::nullopt;
    }
    if (options.allowed && !options.allowed(c.string())) {
      warnings->push_back(c.string() + ": outside the browsable roots, not read");
      return std::nullopt;
    }
    // Checked by its canonical path, then opened below its root without
    // following links (a component swapped in between is refused), as a
    // regular file (a FIFO would block the import).
    std::string why;
    std::optional<std::string> text = ReadRegularFile(c, options.roots, options.max_file, &why);
    if (!text) warnings->push_back(c.string() + ": " + why);
    return text;
  }
};

loader::SymbolBind BindOf(nds::DsdScope s) {
  switch (s) {
    case nds::DsdScope::local: return loader::SymbolBind::local;
    case nds::DsdScope::weak: return loader::SymbolBind::weak;
    case nds::DsdScope::global: break;
  }
  return loader::SymbolBind::global;
}

// The module's sections as raw regions over its file's bytes.
void Regions(NdsModulePlan &m, const nds::DsdDelinks &d) {
  const std::uint64_t file = m.bytes ? m.bytes->size() : 0;
  for (const nds::DsdSection &s : d.sections) {
    if (s.end <= s.start) continue;  // .ctor and others can be empty
    if (s.start < m.base) {
      m.warnings.push_back(s.name + " starts below the module (" + Hex(s.start) + ")");
      continue;
    }
    loader::RawRegion r;
    r.name = s.name;
    r.start = s.start;
    r.size = s.end - s.start;
    const bool bss = s.kind == "bss";
    r.perms = {true, s.kind == "data" || bss, s.kind == "code"};
    r.initialized = !bss;
    if (!bss) {
      const std::uint64_t off = s.start - m.base;
      r.file_offset = std::min<std::uint64_t>(off, file);
      r.file_size = off >= file ? 0 : std::min<std::uint64_t>(r.size, file - off);
      if (r.file_size < r.size)
        m.warnings.push_back(s.name + " runs past the module's binary; the rest reads as zero");
    }
    m.raw.regions.push_back(std::move(r));
    ++m.sections;
  }
}

// One block over the module's bytes and one for its .bss.
void PlainRegions(NdsModulePlan &m, std::uint32_t bss_start) {
  const std::uint64_t file = m.bytes ? m.bytes->size() : 0;
  if (file) {
    loader::RawRegion r;
    r.name = m.name;
    r.start = m.base;
    r.size = file;
    r.perms = {true, true, true};
    r.initialized = true;
    r.file_offset = 0;
    r.file_size = file;
    m.raw.regions.push_back(std::move(r));
  }
  if (m.bss) {
    loader::RawRegion b;
    b.name = m.name + ".bss";
    b.start = std::max<std::uint64_t>(bss_start ? bss_start : m.base + file, m.base + file);
    b.size = m.bss;
    b.perms = {true, true, false};
    b.initialized = false;
    m.raw.regions.push_back(std::move(b));
  }
}

// The DS's memory map beyond the modules (loader::platform_regions): its
// I/O ports, shared WRAM and main memory's shared area as volatile memory,
// cut around every module of the same CPU, so a polling loop reads each
// time and a call into a sibling module still finds that module (a block
// of the program's own there would hide it from the links).
void MapPlatform(NdsProjectPlan &plan) {
  // What the modules map, by CPU, before any of them gets the preset's.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> taken[2];
  for (const NdsModulePlan &o : plan.modules)
    for (const loader::RawRegion &r : o.raw.regions)
      if (r.size) taken[o.arm7].emplace_back(r.start, r.start + (r.size - 1));
  for (NdsModulePlan &m : plan.modules)
    if (auto regions = loader::platform_regions(m.arm7 ? "nds-arm7" : "nds-arm9", taken[m.arm7]))
      for (loader::RawRegion &r : *regions) m.raw.regions.push_back(std::move(r));
}

bool Mapped(const NdsModulePlan &m, std::uint64_t a) {
  for (const loader::RawRegion &r : m.raw.regions)
    if (a >= r.start && a - r.start < r.size) return true;
  return false;
}

void Symbols(NdsModulePlan &m, const nds::DsdSymbols &syms) {
  std::size_t outside = 0;
  for (const nds::DsdSymbol &s : syms.symbols) {
    if (!Mapped(m, s.addr)) {
      ++outside;
      continue;
    }
    loader::Symbol sym;
    sym.name = s.name;
    sym.value = s.addr;
    sym.bind = BindOf(s.scope);
    sym.defined = true;
    switch (s.kind) {
      case nds::DsdSymbolKind::function:
        sym.type = loader::SymbolType::func;
        sym.size = s.size;
        if (s.mode == nds::DsdMode::thumb) {
          sym.value |= 1;
          ++m.thumb_functions;
        }
        ++m.functions;
        break;
      case nds::DsdSymbolKind::label: sym.type = loader::SymbolType::notype; break;
      case nds::DsdSymbolKind::data:
      case nds::DsdSymbolKind::bss:
        sym.type = loader::SymbolType::object;
        sym.size = s.byte_size();
        ++m.data;
        break;
    }
    m.raw.symbols.push_back(std::move(sym));
    ++m.symbols;
  }
  if (outside) m.warnings.push_back(std::to_string(outside) + " symbols are outside the module's blocks");
  for (const nds::DsdLineError &e : syms.errors)
    m.warnings.push_back("symbols.txt:" + std::to_string(e.line) + ": " + e.message);
}

void Units(NdsModulePlan &m, const nds::DsdDelinks &d) {
  for (const nds::DsdDelinkFile &f : d.files) {
    if (f.sections.empty()) continue;
    std::uint32_t first = f.sections[0].start;
    for (const nds::DsdSection &s : f.sections) first = std::min(first, s.start);
    if (!Mapped(m, first)) continue;
    std::string text = "dsd: " + f.name + (f.complete ? " (complete)" : "");
    for (const nds::DsdSection &s : f.sections) text += "\n  " + s.name + " " + Hex(s.start) + "-" + Hex(s.end);
    if (!f.categories.empty()) {
      text += "\n  categories:";
      for (const std::string &c : f.categories) text += " " + c;
    }
    AnalysisAssertion c;
    c.kind = facts::FactKind::Comment;
    c.address = first;
    c.sub = "plate";
    c.value = text;
    pb::Comment *pc = c.body.mutable_comment();
    pc->mutable_address()->set_offset(first);
    pc->set_kind(pb::COMMENT_KIND_PLATE);
    pc->set_text(text);
    // Two units starting at one address (an empty section) share the plate.
    bool merged = false;
    for (AnalysisAssertion &a : m.facts.assertions)
      if (a.address == first && a.kind == facts::FactKind::Comment) {
        std::string joined = std::get<std::string>(a.value) + "\n" + text;
        a.value = joined;
        a.body.mutable_comment()->set_text(joined);
        merged = true;
      }
    if (!merged) m.facts.assertions.push_back(std::move(c));
    ++m.units;
  }
  for (const nds::DsdLineError &e : d.errors)
    m.warnings.push_back("delinks.txt:" + std::to_string(e.line) + ": " + e.message);
}

std::string ModuleName(const nds::DsdRelocModule &rm) {
  using K = nds::DsdRelocModule::Kind;
  switch (rm.kind) {
    case K::main: return "main";
    case K::itcm: return "itcm";
    case K::dtcm: return "dtcm";
    case K::overlay: {
      char b[16];
      std::snprintf(b, sizeof b, "ov%03u", rm.ids.empty() ? 0u : rm.ids[0]);
      return b;
    }
    case K::autoload: return "autoload_" + std::to_string(rm.index);
    case K::none:
    case K::overlays: break;
  }
  return "";
}

}  // namespace

bool UnderBrowseRoot(const std::string &canonical, const std::vector<std::string> &roots) {
  for (const std::string &r : roots) {
    std::error_code ec;
    const std::string root = fs::weakly_canonical(r, ec).string();
    if (ec || root.empty()) continue;
    if (canonical == root || canonical.starts_with(root.ends_with('/') ? root : root + "/")) return true;
  }
  return false;
}

std::string DsdRecord::encode() const {
  std::string out;
  // One line per field: a value with a line break or another control
  // character would add lines of its own (a forged `symbols` path), so it
  // is left out. Names and paths with them are refused at import.
  auto clean = [](const std::string &v) {
    return std::none_of(v.begin(), v.end(), [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7f; });
  };
  auto line = [&](const char *k, const std::string &v) {
    if (!v.empty() && clean(v)) out += std::string(k) + " " + v + "\n";
  };
  line("source", source);
  line("config", config);
  line("rom", rom);
  line("module", module);
  line("symbols", symbols);
  line("cpu", cpu);
  for (const auto &[m, id] : links)
    if (clean(m) && clean(id) && m.find(' ') == std::string::npos) out += "link " + m + " " + id + "\n";
  return out;
}

DsdRecord DsdRecord::decode(std::string_view text) {
  DsdRecord r;
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) end = text.size();
    std::string_view l = text.substr(start, end - start);
    start = end + 1;
    const std::size_t sp = l.find(' ');
    if (sp == std::string_view::npos) continue;
    const std::string_view k = l.substr(0, sp);
    const std::string v(l.substr(sp + 1));
    if (k == "source") r.source = v;
    else if (k == "config") r.config = v;
    else if (k == "rom") r.rom = v;
    else if (k == "module") r.module = v;
    else if (k == "symbols") r.symbols = v;
    else if (k == "cpu") r.cpu = v;
    else if (k == "link") {
      const std::size_t sp2 = v.find(' ');
      if (sp2 != std::string::npos && r.links.size() < 4096) r.links.emplace_back(v.substr(0, sp2), v.substr(sp2 + 1));
    }
  }
  return r;
}

std::optional<NdsProjectPlan> PlanDsdProject(const std::string &config_path, const NdsPlanOptions &options,
                                             std::string *error) {
  NdsProjectPlan plan;
  plan.source = "dsd";
  std::error_code ec;
  const fs::path config = fs::weakly_canonical(fs::absolute(config_path), ec);
  plan.path = config.string();
  Reader rd{options, &plan.warnings};
  std::optional<std::string> text = rd.read(config, true);
  if (!text) {
    if (error) *error = plan.warnings.empty() ? "cannot read " + config_path : plan.warnings.back();
    return std::nullopt;
  }
  std::string e;
  std::optional<nds::DsdConfig> cfg = nds::parse_dsd_config(*text, &e);
  if (!cfg) {
    if (error) *error = config_path + ": " + e;
    return std::nullopt;
  }
  const fs::path dir = config.parent_path();
  // The game's name: the directory above config/<version>/arm9, else the
  // config's own directory.
  {
    // config/<version>/arm9/config.yaml: "<project>-<version>";
    // config/arm9/config.yaml: "<project>"; else the directory's name.
    fs::path g = dir;
    if (g.filename() == "arm9") g = g.parent_path();
    if (g.filename() == "config") plan.game = g.parent_path().filename().string();
    else if (g.parent_path().filename() == "config")
      plan.game = g.parent_path().parent_path().filename().string() + "-" + g.filename().string();
    else plan.game = g.filename().string();
    if (plan.game.empty() || plan.game == "-") plan.game = "dsd";
  }
  // The extract: binaries and load addresses.
  std::optional<nds::RomExtract> extract;
  fs::path extract_dir;
  if (!cfg->rom_config.empty()) {
    const fs::path rc = (dir / cfg->rom_config).lexically_normal();
    extract_dir = rc.parent_path();
    if (std::optional<std::string> rt = rd.read(rc)) {
      struct Ctx {
        Reader *rd;
        fs::path dir;
      } ctx{&rd, extract_dir};
      auto read = [](void *c, const std::string &rel) -> std::optional<std::string> {
        auto *x = static_cast<Ctx *>(c);
        return x->rd->read((x->dir / rel).lexically_normal());
      };
      extract = nds::parse_rom_extract(*rt, read, &ctx, &e);
      if (!extract) plan.warnings.push_back(rc.string() + ": " + e);
      else
        for (const std::string &w : extract->warnings) plan.warnings.push_back("extract: " + w);
    }
  }
  auto from_extract = [&](const std::string &name) -> const nds::RomExtractModule * {
    if (!extract) return nullptr;
    for (const nds::RomExtractModule &m : extract->modules)
      if (m.name == name) return &m;
    return nullptr;
  };
  for (const nds::DsdModuleConfig &mc : cfg->modules) {
    if (!options.only.empty() && !options.only.contains(mc.name)) continue;
    NdsModulePlan m;
    m.name = mc.name;
    m.kind = std::string(nds::to_string(mc.kind));
    m.overlay_id = mc.overlay_id;
    m.language = kArm9Language;
    m.raw.language = m.language;
    // The extract names its modules main, itcm, dtcm, autoload_N, ovNNN.
    std::string ext_name = mc.kind == nds::DsdModuleKind::main     ? "main"
                           : mc.kind == nds::DsdModuleKind::itcm   ? "itcm"
                           : mc.kind == nds::DsdModuleKind::dtcm   ? "dtcm"
                           : mc.kind == nds::DsdModuleKind::autoload ? "autoload_" + std::to_string(mc.autoload_index)
                                                                     : "";
    if (mc.kind == nds::DsdModuleKind::overlay) {
      char b[16];
      std::snprintf(b, sizeof b, "ov%03d", mc.overlay_id);
      ext_name = b;
    }
    const std::optional<std::string> delinks_text = mc.delinks.empty() ? std::nullopt : rd.read(dir / mc.delinks);
    const nds::DsdDelinks delinks = delinks_text ? nds::parse_dsd_delinks(*delinks_text) : nds::DsdDelinks{};
    const nds::RomExtractModule *x = from_extract(ext_name);
    fs::path bin;
    if (x) {
      bin = (extract_dir / x->bin).lexically_normal();
      m.base = x->base_address;
      m.bss = x->bss_size;
      if (x->entry) m.raw.entry = x->entry;
    } else {
      // No extract: the built binary at the delinks' lowest address.
      bin = (dir / mc.object).lexically_normal();
      m.base = delinks.extent().first;
      if (delinks.sections.empty()) {
        plan.warnings.push_back(m.name + ": not in the extract and no delinks.txt sections to place it; left out");
        continue;
      }
      m.warnings.push_back("not in the extract: the built binary " + bin.string() + " is loaded instead");
    }
    std::optional<std::string> bytes = rd.read(bin);
    if (!bytes) {
      plan.warnings.push_back(m.name + ": no binary (" + bin.string() + "); left out");
      continue;
    }
    m.binary_path = fs::weakly_canonical(bin, ec).string();
    m.bytes = std::make_shared<loader::Bytes>(bytes->size());
    std::memcpy(m.bytes->data(), bytes->data(), bytes->size());
    m.size = static_cast<std::uint32_t>(bytes->size());
    m.raw.base = m.base;
    m.raw.length = 0;  // the regions say what is mapped
    m.raw.block_name = m.name;
    m.raw.container = loader::RawContainer::binary;
    if (!delinks.sections.empty()) Regions(m, delinks);
    if (m.raw.regions.empty()) PlainRegions(m, 0);
    if (std::optional<std::string> st = mc.symbols.empty() ? std::nullopt : rd.read(dir / mc.symbols)) {
      Symbols(m, nds::parse_dsd_symbols(*st));
      m.symbols_path = fs::weakly_canonical(dir / mc.symbols, ec).string();
    }
    Units(m, delinks);
    if (std::optional<std::string> rt = mc.relocations.empty() ? std::nullopt : rd.read(dir / mc.relocations)) {
      nds::DsdRelocs relocs = nds::parse_dsd_relocs(*rt);
      m.relocs = relocs.relocs.size();
      for (const nds::DsdReloc &r : relocs.relocs) {
        if (r.module.kind == nds::DsdRelocModule::Kind::overlays) {
          ++m.ambiguous_relocs;
          continue;
        }
        const std::string target = ModuleName(r.module);
        if (target.empty() || target == m.name) continue;
        ++m.cross_relocs;
        m.links.insert(target);
      }
      for (const nds::DsdLineError &le : relocs.errors)
        m.warnings.push_back("relocs.txt:" + std::to_string(le.line) + ": " + le.message);
    }
    if (m.warnings.size() > 64) m.warnings.resize(64);
    plan.modules.push_back(std::move(m));
  }
  // The ARM7 side, from the extract (dsd itself covers the ARM9 only).
  if (options.arm7 && extract) {
    for (const nds::RomExtractModule &x : extract->modules) {
      if (!x.arm7) continue;
      if (!options.only.empty() && !options.only.contains(x.name)) continue;
      NdsModulePlan m;
      m.name = x.name;
      m.kind = x.overlay_id >= 0 ? "arm7_overlay" : "arm7";
      m.overlay_id = x.overlay_id;
      m.arm7 = true;
      m.language = kArm7Language;
      m.raw.language = m.language;
      const fs::path bin = (extract_dir / x.bin).lexically_normal();
      std::optional<std::string> bytes = rd.read(bin);
      if (!bytes) continue;
      m.binary_path = fs::weakly_canonical(bin, ec).string();
      m.bytes = std::make_shared<loader::Bytes>(bytes->size());
      std::memcpy(m.bytes->data(), bytes->data(), bytes->size());
      m.size = static_cast<std::uint32_t>(bytes->size());
      m.base = x.base_address;
      m.bss = x.bss_size;
      m.raw.base = m.base;
      m.raw.length = 0;
      m.raw.block_name = m.name;
      m.raw.container = loader::RawContainer::binary;
      if (x.entry) m.raw.entry = x.entry;
      PlainRegions(m, 0);
      plan.modules.push_back(std::move(m));
    }
  }
  if (plan.modules.empty()) {
    if (error) *error = "no module of " + config_path + " could be loaded" +
                        (plan.warnings.empty() ? std::string() : ": " + plan.warnings.front());
    return std::nullopt;
  }
  MapPlatform(plan);
  CompleteLinks(plan);
  return plan;
}

std::optional<NdsProjectPlan> PlanNdsRom(const std::string &path, std::shared_ptr<const loader::Bytes> rom,
                                         const NdsPlanOptions &options, std::string *error) {
  if (!rom) {
    if (error) *error = "no ROM";
    return std::nullopt;
  }
  std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t *>(rom->data()), rom->size());
  std::string e;
  std::optional<nds::NdsRom> r = nds::parse_nds(bytes, &e);
  if (!r) {
    if (error) *error = e;
    return std::nullopt;
  }
  NdsProjectPlan plan;
  plan.source = "nds";
  plan.path = path;
  plan.game = r->header.title.empty() ? "nds" : r->header.title;
  if (!r->header.game_code.empty()) plan.game += " (" + r->header.game_code + ")";
  for (char &c : plan.game)
    if (c == '/' || static_cast<unsigned char>(c) < 0x20) c = '_';
  plan.warnings = r->warnings;
  for (nds::NdsModule &nm : r->modules) {
    const bool arm7 = nm.cpu == nds::NdsCpu::arm7;
    if (arm7 && !options.arm7) continue;
    if (!options.only.empty() && !options.only.contains(nm.name)) continue;
    NdsModulePlan m;
    m.name = nm.name;
    m.arm7 = arm7;
    m.overlay_id = nm.overlay_id;
    m.kind = nm.name == "main"   ? "main"
             : nm.name == "itcm" ? "itcm"
             : nm.name == "dtcm" ? "dtcm"
             : nm.name == "arm7" ? "arm7"
             : nm.overlay_id >= 0 ? (arm7 ? "arm7_overlay" : "overlay")
                                  : "autoload";
    m.language = arm7 ? kArm7Language : kArm9Language;
    m.raw.language = m.language;
    m.base = nm.address;
    m.bss = nm.bss_size;
    m.size = static_cast<std::uint32_t>(nm.data.size());
    m.bytes = std::make_shared<loader::Bytes>(nm.data.size());
    std::memcpy(m.bytes->data(), nm.data.data(), nm.data.size());
    m.raw.base = m.base;
    m.raw.length = 0;
    m.raw.block_name = m.name;
    m.raw.container = loader::RawContainer::binary;
    if (nm.entry) m.raw.entry = nm.entry;
    std::uint32_t bss_start = 0;
    if (m.kind == "main" && r->params) bss_start = r->params->bss_start;
    PlainRegions(m, bss_start);
    m.warnings = nm.warnings;
    if (nm.was_compressed) m.warnings.push_back("decompressed (BLZ)");
    if (m.raw.regions.empty()) {
      plan.warnings.push_back(m.name + ": empty; left out");
      continue;
    }
    plan.modules.push_back(std::move(m));
  }
  if (plan.modules.empty()) {
    if (error) *error = "no module could be loaded from " + path;
    return std::nullopt;
  }
  MapPlatform(plan);
  CompleteLinks(plan);
  return plan;
}

void CompleteLinks(NdsProjectPlan &plan) {
  std::set<std::string> names;
  for (const NdsModulePlan &m : plan.modules) names.insert(m.name);
  for (NdsModulePlan &m : plan.modules) {
    std::set<std::string> want;
    for (const std::string &l : m.links)
      if (names.contains(l)) want.insert(l);
    for (const NdsModulePlan &o : plan.modules) {
      if (o.name == m.name || o.arm7 != m.arm7) continue;
      // The always-loaded modules: main and the autoloads (ARM9), the ARM7.
      const bool resident = o.kind == "main" || o.kind == "itcm" || o.kind == "dtcm" || o.kind == "autoload" ||
                            o.kind == "arm7";
      if (resident) want.insert(o.name);
    }
    want.erase(m.name);
    m.links = std::move(want);
  }
}

}  // namespace revkit::backend
