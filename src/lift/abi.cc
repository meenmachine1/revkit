#include "revkit/lift/abi.hh"

#include "revkit/lift/lifter.hh"

#include "libdecomp.hh"
#include "sleigh_arch.hh"
#include "spec_xml.hh"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>

namespace revkit::lift {

namespace {

using spec_xml::attribute;
using spec_xml::child;

// The register entries of a prototype's <input> or <output>, in order,
// through any <group>s, skipping float ones and joins.
void register_entries(const ghidra::Element *list, std::vector<std::string> &out) {
  for (const ghidra::Element *c : list->getChildren()) {
    if (c->getName() == "group") {
      register_entries(c, out);
      continue;
    }
    if (c->getName() != "pentry" || attribute(c, "metatype") == "float") continue;
    if (const ghidra::Element *reg = child(c, "register")) {
      std::string name = attribute(reg, "name");
      if (!name.empty() && std::find(out.begin(), out.end(), name) == out.end()) out.push_back(name);
    }
  }
}

// Every register a list names (<unaffected>), floats included.
void all_registers(const ghidra::Element *list, std::vector<std::string> &out) {
  for (const ghidra::Element *c : list->getChildren()) {
    if (c->getName() == "register") {
      std::string name = attribute(c, "name");
      if (!name.empty() && std::find(out.begin(), out.end(), name) == out.end()) out.push_back(name);
    } else {
      all_registers(c, out);
    }
  }
}

std::string find_file(const std::string &name) {
  std::string path;
  ghidra::SleighArchitecture::specpaths.findFile(path, name);
  if (path.empty()) throw LiftError("cannot find spec file " + name + " in the Ghidra install");
  return path;
}

// The .pspec and .cspec paths of a language and compiler (the language's
// first compiler when `compiler` is empty or unknown). Call with Ghidra's
// globals locked.
// (ghidra_root() is checked before the lock: initialize() takes them in the
// other order.)
std::pair<std::string, std::string> spec_paths(const std::string &language, const std::string &compiler) {
  std::string base = language;
  if (std::count(base.begin(), base.end(), ':') >= 4) base = base.substr(0, base.rfind(':'));
  const ghidra::LanguageDescription *desc = nullptr;
  for (const ghidra::LanguageDescription &d : ghidra::SleighArchitecture::getDescriptions())
    if (d.getId() == base) desc = &d;
  if (desc == nullptr) throw LiftError("unknown language " + language);
  if (desc->numCompilers() == 0) throw LiftError("language " + language + " has no compiler spec");
  const ghidra::CompilerTag *tag = &desc->getCompiler(0);
  for (ghidra::int4 i = 0; i < desc->numCompilers(); ++i)
    if (desc->getCompiler(i).getId() == compiler) tag = &desc->getCompiler(i);
  return {find_file(desc->getProcessorSpec()), find_file(tag->getSpec())};
}

}  // namespace

Abi read_abi(const std::string &language, const std::string &compiler) {
  if (!ghidra_root()) throw LiftError("revkit::lift::initialize() was not called");
  auto globals = lock_ghidra_globals();  // the XML parser is one of Ghidra's globals
  const auto [pspec, cspec] = spec_paths(language, compiler);
  Abi abi;
  try {
    ghidra::DocumentStorage store;
    const ghidra::Element *proc = store.openDocument(pspec)->getRoot();
    if (const ghidra::Element *pc = child(proc, "programcounter")) abi.program_counter = attribute(pc, "register");

    const ghidra::Element *root = store.openDocument(cspec)->getRoot();
    if (const ghidra::Element *sp = child(root, "stackpointer")) abi.stack_pointer = attribute(sp, "register");
    if (const ghidra::Element *ra = child(root, "returnaddress")) {
      for (const ghidra::Element *c : ra->getChildren()) {
        if (c->getName() == "register") {
          abi.return_register = attribute(c, "name");
        } else if (c->getName() == "varnode" && attribute(c, "space") == "stack") {
          abi.return_stack_offset = std::strtoll(attribute(c, "offset").c_str(), nullptr, 0);
          abi.return_size = static_cast<std::uint32_t>(std::strtoul(attribute(c, "size").c_str(), nullptr, 0));
        }
      }
    }
    if (const ghidra::Element *def = child(root, "default_proto")) {
      if (const ghidra::Element *proto = child(def, "prototype")) {
        abi.default_model = attribute(proto, "name");
        abi.stack_shift = std::strtoll(attribute(proto, "stackshift").c_str(), nullptr, 0);
        const std::string extrapop = attribute(proto, "extrapop");
        if (!extrapop.empty() && extrapop != "unknown") abi.extrapop = std::strtoll(extrapop.c_str(), nullptr, 0);
        if (const ghidra::Element *in = child(proto, "input")) register_entries(in, abi.int_params);
        if (const ghidra::Element *out = child(proto, "output")) register_entries(out, abi.int_returns);
        if (const ghidra::Element *kept = child(proto, "unaffected")) all_registers(kept, abi.call_preserved);
      }
    }
  } catch (const ghidra::DecoderError &e) {
    throw LiftError("reading the specs of " + language + ": " + e.explain);
  } catch (const ghidra::LowlevelError &e) {
    throw LiftError("reading the specs of " + language + ": " + e.explain);
  }
  return abi;
}

const std::map<std::string, std::string> &call_fixup_targets(const std::string &language,
                                                             const std::string &compiler) {
  static std::mutex mu;
  static std::map<std::pair<std::string, std::string>, std::map<std::string, std::string>> cache;
  std::string base = language, comp = compiler;
  if (std::count(base.begin(), base.end(), ':') >= 4) {
    if (comp.empty()) comp = base.substr(base.rfind(':') + 1);
    base = base.substr(0, base.rfind(':'));
  }
  std::lock_guard lock(mu);
  auto it = cache.find({base, comp});
  if (it != cache.end()) return it->second;
  std::map<std::string, std::string> out;
  if (ghidra_root()) {
    auto globals = lock_ghidra_globals();  // the XML parser is one of Ghidra's globals
    const ghidra::LanguageDescription *desc = nullptr;
    for (const ghidra::LanguageDescription &d : ghidra::SleighArchitecture::getDescriptions())
      if (d.getId() == base) desc = &d;
    if (desc != nullptr && desc->numCompilers() != 0) {
      const ghidra::CompilerTag *tag = &desc->getCompiler(0);
      for (ghidra::int4 i = 0; i < desc->numCompilers(); ++i)
        if (desc->getCompiler(i).getId() == comp) tag = &desc->getCompiler(i);
      try {
        ghidra::DocumentStorage store;
        const ghidra::Element *root = store.openDocument(find_file(tag->getSpec()))->getRoot();
        for (const ghidra::Element *fix : root->getChildren()) {
          if (fix->getName() != "callfixup") continue;
          const std::string name = attribute(fix, "name");
          if (name.empty()) continue;
          for (const ghidra::Element *t : fix->getChildren())
            if (t->getName() == "target")
              if (std::string target = attribute(t, "name"); !target.empty()) out.emplace(std::move(target), name);
        }
      } catch (const ghidra::DecoderError &) {
      } catch (const ghidra::LowlevelError &) {
      } catch (const LiftError &) {
      }
    }
  }
  return cache.emplace(std::make_pair(base, comp), std::move(out)).first->second;
}

const std::set<std::string> &prototype_models(const std::string &language, const std::string &compiler) {
  static std::mutex mu;
  static std::map<std::pair<std::string, std::string>, std::set<std::string>> cache;
  std::string base = language, comp = compiler;
  if (std::count(base.begin(), base.end(), ':') >= 4) {
    if (comp.empty()) comp = base.substr(base.rfind(':') + 1);
    base = base.substr(0, base.rfind(':'));
  }
  std::lock_guard lock(mu);
  auto it = cache.find({base, comp});
  if (it != cache.end()) return it->second;
  std::set<std::string> out;
  if (ghidra_root()) {
    auto globals = lock_ghidra_globals();  // the XML parser is one of Ghidra's globals
    try {
      ghidra::DocumentStorage store;
      const ghidra::Element *root = store.openDocument(spec_paths(base, comp).second)->getRoot();
      for (const ghidra::Element *c : root->getChildren()) {
        const ghidra::Element *proto = c->getName() == "default_proto" ? child(c, "prototype") : c;
        if (proto == nullptr) continue;
        if (proto->getName() == "prototype" || proto->getName() == "modelalias")
          if (std::string name = attribute(proto, "name"); !name.empty()) out.insert(std::move(name));
      }
    } catch (const ghidra::DecoderError &) {
    } catch (const ghidra::LowlevelError &) {
    } catch (const LiftError &) {
    }
  }
  return cache.emplace(std::make_pair(base, comp), std::move(out)).first->second;
}

DataOrganization read_data_organization(const std::string &language, const std::string &compiler) {
  if (!ghidra_root()) throw LiftError("revkit::lift::initialize() was not called");
  auto globals = lock_ghidra_globals();
  const std::string cspec = spec_paths(language, compiler).second;
  DataOrganization out;
  try {
    ghidra::DocumentStorage store;
    const ghidra::Element *root = store.openDocument(cspec)->getRoot();
    const ghidra::Element *org = child(root, "data_organization");
    if (org == nullptr) return out;
    out.present = true;
    for (const ghidra::Element *el : org->getChildren()) {
      const std::string &name = el->getName();
      if (name == "size_alignment_map") {
        for (const ghidra::Element *e : el->getChildren()) {
          const std::string size = attribute(e, "size"), align = attribute(e, "alignment");
          if (!size.empty() && !align.empty())
            out.size_alignment.emplace_back(std::strtol(size.c_str(), nullptr, 0), std::strtol(align.c_str(), nullptr, 0));
        }
      } else if (name == "bitfield_packing") {
        out.ms_bitfields = spec_xml::org_value(el, "use_MS_convention").value_or(0) != 0;
      } else if (name == "char_type") {
        if (auto v = spec_xml::org_value(org, "char_type", "signed")) out.char_signed = *v != 0;
      } else if (auto v = spec_xml::org_value(org, name)) {
        out.values[name] = *v;
      }
    }
  } catch (const ghidra::DecoderError &e) {
    throw LiftError("reading the compiler spec of " + language + ": " + e.explain);
  } catch (const ghidra::LowlevelError &e) {
    throw LiftError("reading the compiler spec of " + language + ": " + e.explain);
  }
  return out;
}

}  // namespace revkit::lift
