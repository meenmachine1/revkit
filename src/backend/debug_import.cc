#include "debug_import.h"

#include "program.h"
#include "type_record.h"

#include "revkit/debuginfo/dwarf.h"
#include "revkit/debuginfo/pdb.h"
#include "revkit/types/describe.h"
#include "revkit/inputs/debug_info.h"

#include <algorithm>
#include <set>

namespace revkit::backend {

namespace {

// Names, hashed prototypes and variable types for every described function
// and global in mapped memory, plus the records the hashes reach. `delta`
// turns the reader's addresses into loaded ones.
DebugFacts Collect(const Program &program, const types::TypeStore &store, const debuginfo::DebugInfo &info,
                   std::uint64_t delta) {
  DebugFacts out;
  for (const auto &d : info.diagnostics) out.diagnostics.push_back(d.message);
  std::set<types::TypeId> roots;
  for (const debuginfo::Function &f : info.functions) {
    const std::uint64_t entry = f.entry + delta;
    if (!program.executable(entry)) continue;
    const std::string &name = f.qualified_name.empty() ? f.name : f.qualified_name;
    if (name.empty()) continue;
    // Several records can describe one entry (declaration and definition):
    // the first with a name wins, as in rk-debuginfo.
    if (!out.names.emplace(entry, name).second) continue;
    ++out.functions;
    // A prototype the compiler didn't keep (DW_CC_nocall) is not the ABI,
    // so it must not steer the decompiler.
    if (f.prototype.valid() && !f.abi_changed) {
      out.types.emplace(entry, "h:" + store.hash(f.prototype).hex());
      roots.insert(f.prototype);
    }
  }
  for (const debuginfo::Variable &v : info.variables) {
    const std::uint64_t address = v.address + delta;
    if (v.name.empty() || v.function_local || !program.image().memory.is_mapped(address) ||
        out.names.contains(address))
      continue;
    out.names.emplace(address, v.qualified_name.empty() ? v.name : v.qualified_name);
    if (v.type.valid()) {
      out.types.emplace(address, "h:" + store.hash(v.type).hex());
      roots.insert(v.type);
    }
    ++out.variables;
  }
  // Locals' types too, so a name a local's type reaches can be rebound for
  // the decompiler (own_inputs.cc).
  for (const debuginfo::Function &f : info.functions)
    for (const debuginfo::LocalVariable &l : f.locals)
      if (l.type.valid()) roots.insert(l.type);
  std::vector<types::TypeId> work(roots.begin(), roots.end());
  std::set<types::TypeId> seen(roots.begin(), roots.end());
  while (!work.empty()) {
    types::TypeId id = work.back();
    work.pop_back();
    out.records.emplace(store.hash(id).hex(), EncodeTypeRecord(store, id));
    types::Type t = store.get(id);
    types::for_each_ref(t, [&](types::TypeId &ref, types::EdgeKind) {
      if (seen.insert(ref).second) work.push_back(ref);
    });
  }
  // Each imported named type under the file that declared it, as Ghidra
  // files DWARF types under their header's name.
  for (const auto &[id, file] : info.type_files) {
    if (!seen.contains(id)) continue;
    const std::string key = types::named_key(store, id);
    const std::size_t slash = file.find_last_of("/\\");
    const std::string base = slash == std::string::npos ? file : file.substr(slash + 1);
    if (key.empty() || base.empty()) continue;
    if (auto path = NormalizeTypeCategory("/" + base)) out.categories.emplace(key, *path);
  }
  return out;
}

}  // namespace

std::optional<DebugFacts> ReadDwarf(const Program &program) {
  const auto &debug = program.debug();
  if (!debug || !debug->dwarf) return std::nullopt;
  DebugFacts out = Collect(program, debug->store, *debug->dwarf, debug->dwarf_delta);
  out.source = "dwarf";
  out.diagnostics.insert(out.diagnostics.end(), debug->warnings.begin(), debug->warnings.end());
  return out;
}

std::optional<DebugFacts> ReadPdb(const Program &program) {
  const auto &debug = program.debug();
  if (!debug || !debug->pdb) return std::nullopt;
  DebugFacts out = Collect(program, debug->store, *debug->pdb, 0);
  out.source = "pdb";
  out.file = debug->pdb_file;
  return out;
}

DebugFacts ReadPdbBytes(const Program &program, std::span<const std::uint8_t> bytes, const std::string &file) {
  types::TypeStore store;
  debuginfo::PdbOptions options;
  options.image_base = program.image().image_base;
  const debuginfo::PdbDebugInfo pdb = debuginfo::read_pdb(bytes, store, options);
  DebugFacts out = Collect(program, store, pdb, 0);
  out.source = "pdb";
  out.file = file;
  return out;
}

}  // namespace revkit::backend
