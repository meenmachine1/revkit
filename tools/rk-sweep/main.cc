// rk-sweep: a smoke test of one SLEIGH language end to end, for the
// processor sweep (scripts/processor_sweep.py, docs/processors.md).
//
//   rk-sweep --list                       every language in the install, one per line:
//                                         id, compiler, deprecated or -, processor (tab-separated;
//                                         ids may hold spaces, "x86:LE:16:Real Mode")
//   rk-sweep --lang <id[:compiler]> [--sample <file> --base <hex> --entry <hex>]
//            [--bytes <n>] [--seed <n>] [--steps <n>] [--ghidra <root>]
//
// Loads a flat image (a real sample, or deterministic random bytes) as the
// raw loader does, with the language's memory spaces and default blocks;
// decodes it linearly; runs function discovery from the first instruction
// that decodes; decompiles that function; and emulates a few steps from it.
// Each stage prints one JSON line when it finishes (flushed), so a crash or
// a hang shows as the stage that never reported; the driver runs this in a
// child process with a timeout.

#include "revkit/analysis/analysis.h"
#include "revkit/emu/emulator.hh"
#include "revkit/facts/fact_db.h"
#include "revkit/lift/image_arch.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"
#include "revkit/runtime/runtime.h"

#include "funcdata.hh"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#ifndef REVKIT_DEFAULT_GHIDRA_ROOT
#define REVKIT_DEFAULT_GHIDRA_ROOT ""
#endif

namespace {

namespace an = revkit::analysis;
namespace lift = revkit::lift;
namespace loader = revkit::loader;

struct Options {
  std::string ghidra_root;
  std::string language;
  std::string sample;
  std::uint64_t base = 0;
  std::optional<std::uint64_t> entry;
  std::size_t bytes = 4096;
  std::uint64_t seed = 1;
  std::uint64_t steps = 16;
  bool list = false;
};

std::string quote(const std::string &s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') out += '\\', out += c;
    else if (static_cast<unsigned char>(c) < 0x20) {
      char buf[8];
      std::snprintf(buf, sizeof buf, "\\u%04x", c);
      out += buf;
    } else out += c;
  }
  return out + "\"";
}

std::string hex(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
  return buf;
}

// One stage's line: {"stage": ..., "ok": ..., fields..., "ms": ...}.
void report(const std::string &stage, bool ok, const std::string &fields, double ms) {
  std::cout << "{\"stage\":" << quote(stage) << ",\"ok\":" << (ok ? "true" : "false");
  if (!fields.empty()) std::cout << "," << fields;
  char buf[32];
  std::snprintf(buf, sizeof buf, "%.1f", ms);
  std::cout << ",\"ms\":" << buf << "}" << std::endl;
}

double since(std::chrono::steady_clock::time_point t) {
  return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t).count();
}

// Runs a stage, reporting an exception as a failure with its message.
bool stage(const std::string &name, const std::function<std::string()> &body) {
  const auto t = std::chrono::steady_clock::now();
  try {
    const std::string fields = body();
    report(name, true, fields, since(t));
    return true;
  } catch (const std::exception &e) {
    report(name, false, "\"error\":" + quote(e.what()), since(t));
  } catch (const ghidra::LowlevelError &e) {
    report(name, false, "\"error\":" + quote(e.explain), since(t));
  } catch (const ghidra::DecoderError &e) {
    report(name, false, "\"error\":" + quote(e.explain), since(t));
  }
  return false;
}

std::optional<std::uint64_t> parse_hex(std::string_view s) {
  if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
  if (s.empty()) return std::nullopt;
  std::uint64_t v = 0;
  for (char c : s) {
    int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    if (d < 0) return std::nullopt;
    v = v << 4 | static_cast<unsigned>(d);
  }
  return v;
}

int run(const Options &o) {
  lift::initialize(o.ghidra_root);
  if (o.list) {
    for (const lift::LanguageSummary &l : lift::list_languages())
      std::cout << l.id << "\t" << (l.compilers.empty() ? "default" : l.compilers.front()) << "\t"
                << (l.deprecated ? "deprecated" : "-") << "\t" << l.processor << "\n";
    return 0;
  }
  std::string language = o.language;
  if (std::count(language.begin(), language.end(), ':') == 3)
    for (const lift::LanguageSummary &l : lift::list_languages())
      if (l.id == language) language += ":" + (l.compilers.empty() ? std::string("default") : l.compilers.front());
  const std::string base_language = language.substr(0, language.rfind(':'));

  // The image: a sample's bytes, or random ones seeded by the language.
  auto bytes = std::make_shared<loader::Bytes>();
  if (!o.sample.empty()) {
    std::ifstream in(o.sample, std::ios::binary);
    std::vector<char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    for (char c : buf) bytes->push_back(static_cast<std::byte>(c));
  } else {
    std::seed_seq seq(base_language.begin(), base_language.end());
    std::mt19937_64 rng(seq);
    rng.discard(o.seed);
    for (std::size_t i = 0; i < o.bytes; ++i) bytes->push_back(static_cast<std::byte>(rng() & 0xff));
  }
  loader::RawOptions raw;
  raw.language = language;
  raw.base = o.base;
  raw.container = loader::RawContainer::binary;

  std::shared_ptr<const loader::Image> image;
  if (!stage("load", [&] {
        image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, raw));
        std::string spaces;
        for (const loader::AddressSpace &s : image->spaces)
          spaces += (spaces.empty() ? "" : ",") + quote(s.name + (s.alias_of_default ? "=" : ""));
        return "\"blocks\":" + std::to_string(image->blocks.size()) + ",\"spaces\":[" + spaces + "],\"bytes\":" +
               std::to_string(bytes->size()) + ",\"real\":" + (o.sample.empty() ? "false" : "true");
      }))
    return 0;

  // Decode linearly; find the first instruction with p-code.
  std::optional<std::uint64_t> entry = o.entry;
  std::string code_space;
  if (!stage("lift", [&] {
        lift::Lifter lifter(image, base_language);
        code_space = lifter.code_space_name();
        std::uint32_t wordsize = 1;
        std::string spaces;
        for (const lift::SpaceDef &d : lifter.spaces()) {
          if (d.is_default) wordsize = d.wordsize;
          if (d.kind == lift::SpaceDef::Kind::processor && !d.is_register)
            spaces += (spaces.empty() ? "" : ",") + quote(d.name + (d.wordsize > 1 ? "/" + std::to_string(d.wordsize) : ""));
        }
        const std::uint64_t step = std::max(1u, lifter.alignment());
        std::uint64_t decoded = 0, unimplemented = 0, ops = 0, tried = 0, covered = 0;
        const std::uint64_t end = o.base + bytes->size();
        for (std::uint64_t a = o.base; a < end; ++tried) {
          std::optional<lift::Instruction> insn = lifter.lift(a);
          if (insn) {
            ++decoded;
            covered += insn->length;
            ops += insn->pcode.size();
            if (insn->unimplemented) ++unimplemented;
            else if (!entry && !insn->pcode.empty()) entry = a;
            a += insn->length + insn->delay_slot;
          } else {
            a += step;
          }
        }
        return "\"code_space\":" + quote(code_space) + ",\"wordsize\":" + std::to_string(wordsize) +
               ",\"memory_spaces\":[" + spaces + "],\"decoded\":" + std::to_string(decoded) +
               ",\"unimplemented\":" + std::to_string(unimplemented) + ",\"pcode_ops\":" + std::to_string(ops) +
               ",\"coverage\":" + std::to_string(bytes->empty() ? 0.0 : static_cast<double>(covered) / bytes->size()) +
               ",\"entry\":" + (entry ? quote(hex(*entry)) : std::string("null"));
      }))
    return 0;
  if (!entry) {
    report("discover", false, "\"error\":\"nothing decodes\"", 0);
    return 0;
  }

  // Discovery from that instruction (the raw image's entry point).
  raw.entry = *entry;
  image = std::make_shared<const loader::Image>(loader::parse_raw(bytes, raw));
  stage("discover", [&] {
    revkit::facts::FactDb db;
    an::register_queries(db.engine());
    an::ProgramInfo info = an::describe(*image, language);
    an::import_image(db, an::ProgramKey{}, *image, info);
    auto functions = db.snapshot().get<an::Functions>(an::ProgramKey{});
    std::size_t at_entry = 0;
    for (const an::FunctionInfo &f : functions->functions) at_entry += f.entry.offset == *entry;
    return "\"functions\":" + std::to_string(functions->functions.size()) + ",\"instructions\":" +
           std::to_string(functions->code.size()) + ",\"entry_function\":" + (at_entry ? "true" : "false") +
           ",\"name\":" + quote(an::default_name(info, *entry));
  });

  // The decompiler over the image, on that function.
  stage("decompile", [&] {
    std::unique_lock<std::shared_mutex> globals = lift::lock_ghidra_globals();
    lift::ArchitectureOptions ao;
    ao.image_symbols = false;
    lift::ImageArchitecture arch(image, "sweep", language, &std::cerr, ao);
    globals.unlock();
    arch.init_image();
    ghidra::AddrSpace *code = arch.getDefaultCodeSpace();
    ghidra::Address at(code, *entry);
    std::string name;
    arch.nameFunction(at, name);
    ghidra::Funcdata *fd = arch.symboltab->getGlobalScope()->addFunction(at, name)->getFunction();
    fd->followFlow(ghidra::Address(code, 0), ghidra::Address(code, code->getHighest()));
    ghidra::Action *pipeline = arch.allacts.getCurrent();
    pipeline->reset(*fd);
    const int r = pipeline->perform(*fd);
    std::ostringstream c;
    {
      auto shared = lift::share_ghidra_globals();
      arch.print->setOutputStream(&c);
      arch.print->docFunction(fd);
    }
    if (r < 0) throw std::runtime_error("the decompiler stopped early");
    return "\"name\":" + quote(name) + ",\"c_bytes\":" + std::to_string(c.str().size());
  });

  // A few steps of the p-code emulator from there.
  stage("emulate", [&] {
    revkit::emu::Options eo;
    eo.language = language;
    revkit::emu::Emulator e(image, eo);
    e.start(*entry, revkit::emu::StartMode::bare);
    revkit::emu::RunOptions ro;
    ro.max_steps = o.steps;
    ro.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    const revkit::emu::Stop s = e.run(ro);
    return "\"steps\":" + std::to_string(e.steps()) + ",\"stop\":" + quote(std::string(revkit::emu::to_string(s.kind))) +
           ",\"detail\":" + quote(s.detail);
  });
  return 0;
}

void usage(std::ostream &os) {
  os << "usage: rk-sweep --list | --lang <id[:compiler]> [--sample <file> --base <hex> --entry <hex>]\n"
        "                [--bytes <n>] [--seed <n>] [--steps <n>] [--ghidra <root>]\n"
        "       rk-sweep --version\n";
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-sweep")) return 0;
  Options o;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    const char *v = nullptr;
    if (a == "--list") o.list = true;
    else if (a == "--lang" && (v = value())) o.language = v;
    else if (a == "--sample" && (v = value())) o.sample = v;
    else if (a == "--ghidra" && (v = value())) o.ghidra_root = v;
    else if ((a == "--base" || a == "--entry") && (v = value())) {
      auto n = parse_hex(v);
      if (!n) return usage(std::cerr), 2;
      (a == "--base" ? o.base : o.entry.emplace()) = *n;
    } else if ((a == "--bytes" || a == "--seed" || a == "--steps") && (v = value())) {
      const std::uint64_t n = std::strtoull(v, nullptr, 0);
      if (a == "--bytes") o.bytes = n;
      else if (a == "--seed") o.seed = n;
      else o.steps = n;
    } else {
      usage(std::cerr);
      return 2;
    }
  }
  if (!o.list && o.language.empty()) {
    usage(std::cerr);
    return 2;
  }
  auto ghidra = revkit::runtime::find_ghidra(o.ghidra_root, "rk-sweep");
  if (!ghidra) return 1;
  o.ghidra_root = ghidra->string();
  try {
    return run(o);
  } catch (const std::exception &e) {
    std::cerr << "rk-sweep: " << e.what() << "\n";
    return 1;
  }
}
