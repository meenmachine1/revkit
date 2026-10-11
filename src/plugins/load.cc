#include "revkit/plugins/load.h"

#include <algorithm>

namespace revkit::plugins {

PluginImage load_with(const Plugin &plugin, std::shared_ptr<const loader::Bytes> file) {
  const std::string who = "loader " + plugin.id() + ": ";
  std::string_view bytes(reinterpret_cast<const char *>(file->data()), file->size());
  LoadResult res;
  CallResult r = run_loader(plugin, bytes, res);
  if (!r.ok()) throw loader::LoadError(who + std::string(to_string(r.failure)) + ": " + r.error);

  PluginImage out;
  out.language = res.language;
  out.compiler = res.compiler;
  loader::Image &img = out.image;
  img.file = file;
  img.memory = loader::Memory(file);
  // "proc:endian:size:variant": the endianness and pointer size.
  std::vector<std::string> parts;
  for (std::size_t start = 0;;) {
    std::size_t colon = res.language.find(':', start);
    parts.push_back(res.language.substr(start, colon - start));
    if (colon == std::string::npos) break;
    start = colon + 1;
  }
  if (parts.size() < 4 || parts.size() > 5)
    throw loader::LoadError(who + "language \"" + res.language + "\" is not proc:endian:size:variant");
  if (parts.size() == 5) {  // "proc:endian:size:variant:compiler"
    out.language = res.language.substr(0, res.language.rfind(':'));
    if (out.compiler.empty()) out.compiler = parts[4];
  }
  if (out.compiler.empty()) out.compiler = "default";
  img.endian = parts[1] == "BE" ? loader::Endian::big : loader::Endian::little;
  try {
    img.bits = static_cast<unsigned>(std::stoul(parts[2]));
  } catch (const std::exception &) {
    throw loader::LoadError(who + "language \"" + res.language + "\" has no size");
  }
  if (img.bits != 16 && img.bits != 32 && img.bits != 64) throw loader::LoadError(who + "unsupported pointer size");
  img.entry = res.entry;

  std::sort(res.blocks.begin(), res.blocks.end(), [](const LoadedBlock &a, const LoadedBlock &b) { return a.start < b.start; });
  for (const LoadedBlock &b : res.blocks) {
    loader::Region region;
    region.start = b.start;
    region.size = b.size;
    region.file_offset = b.file_offset;
    region.file_size = b.file_size;
    region.perms = {(b.perms & abi::kRead) != 0, (b.perms & abi::kWrite) != 0, (b.perms & abi::kExec) != 0};
    img.memory.add(region);  // throws LoadError on overlap
    loader::Block block;
    block.name = b.name;
    block.start = b.start;
    block.size = b.size;
    block.perms = region.perms;
    block.initialized = b.file_size > 0;
    img.blocks.push_back(block);
    if (img.blocks.size() == 1 || b.start < img.image_base) img.image_base = b.start;
  }
  for (const LoadedSymbol &s : res.symbols) {
    if (!img.memory.is_mapped(s.address)) {
      img.warnings.push_back("symbol " + s.name + " is outside every block");
      continue;
    }
    loader::Symbol sym;
    sym.name = s.name;
    sym.value = s.address;
    sym.size = s.size;
    sym.type = s.function ? loader::SymbolType::func : loader::SymbolType::object;
    sym.bind = loader::SymbolBind::global;
    sym.defined = true;
    img.symbols.push_back(std::move(sym));
  }
  if (img.entry && !img.memory.is_mapped(*img.entry)) {
    img.warnings.push_back("the entry point is outside every block");
    img.entry.reset();
  }
  for (const std::string &line : r.log) img.warnings.push_back(who + line);
  return out;
}

}  // namespace revkit::plugins
