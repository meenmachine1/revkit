// rk-lift: load an ELF or PE file, lift every instruction in its known
// functions to raw p-code with SLEIGH, and write the reference JSON format
// (docs/reference-format.md). Functions come from file metadata (symbols,
// exports, unwind tables), with --analyze from revkit::analysis's function
// discovery over the fact engine, or from a reference or Ghidra's exported
// decompiler inputs. With --decompile, also decompile every function in
// process (decompiled_c).
//
//   rk-lift [--ghidra <root>] [--lang <id>] [--name <label>] [--base <hex>|--file-base]
//           [--analyze] [--decompile] [--functions-from <ref.json>] [--inputs <export.json>]
//           [-j <threads>] [--in-order] [--no-instructions] [--stats <file>] [-o <out.json>]
//           [--own-facts <kinds>] [--no-own <kind>] [--no-debug-info] [--dump-inputs <file>]
//           [--timeout <s>] [--max-varnodes <n>] [--memory-budget <MB>] [--decompile-only <hex,...>]
//           [--raw [--raw-offset <hex>] [--raw-length <hex>] [--raw-perms <rwx>] [--raw-entry <hex>]
//            [--region <name:start:size[:perms][:init|uninit|volatile]>]...] <binary>
//
// With --analyze --decompile, the decompiler's inputs come from revkit
// alone (revkit::inputs: loader, discovery, debug info), not from Ghidra.

#include "detect.hh"
#include "inputs_json.hh"
#include "revkit/runtime/runtime.h"
#include "json.hh"
#include "sha256.hh"

#include "revkit/analysis/analysis.h"
#include "revkit/decompd/batch.h"
#include "revkit/decompd/param_id.h"
#include "revkit/decompd/signature.h"
#include "revkit/inputs/param_id.h"
#include "revkit/facts/fact_db.h"
#include "revkit/facts/thread_pool.h"
#include "revkit/inputs/inputs.h"
#include "revkit/inputs/ghidra_types.h"
#include "revkit/infer/infer.h"
#include "revkit/inputs/demangled.h"
#include "revkit/infer/types_bridge.h"
#include "revkit/decompd/pool.h"
#include "revkit/lift/context.hh"
#include "revkit/lift/decompile.hh"
#include "revkit/lift/functions.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <algorithm>
#include <chrono>
#include <set>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <malloc.h>
#include <sys/resource.h>

namespace {

using rklift::hex;
using rklift::Json;

struct Options {
  std::string ghidra_root;
  std::string file;
  std::string name;  // binary.path in the output
  std::string output;
  std::optional<std::string> language;  // "proc:endian:size:variant:compiler"
  std::optional<std::uint64_t> base;
  bool file_base = false;
  bool analyze = false;
  bool detect = false;           // --detect: only say what the file is
  bool detect_features = false;  // with every candidate's sweep
  bool decompile = false;
  bool instructions = true;
  std::string functions_from;  // reference file with the function list
  std::string inputs;          // ghidra_dbexport.py document
  std::string stats;           // timing JSON
  std::optional<unsigned> threads;
  bool in_order = false;
  revkit::inputs::Options own;  // with --analyze --decompile
  std::string dump_inputs;      // write the decompiler inputs as JSON
  double timeout = 30;          // seconds per function (Ghidra's default); 0: none
  std::size_t max_varnodes = 0;  // per function; 0: from the memory budget
  std::size_t memory_budget_mb = 4096;  // whole-program decompilation; 0: unbounded
  std::vector<std::uint64_t> only;  // decompile just these entries
  bool in_process = false;          // decompile in this process (debugging under gdb)
  std::string failure_bundles;      // write the bundles of failed functions here
  // --raw: a flat binary (firmware) at --base (default 0), as Ghidra's raw
  // loader; needs --lang.
  bool raw = false;
  revkit::loader::RawOptions raw_options;
  // Ghidra's Decompiler Parameter ID with --analyze --decompile: where
  // Ghidra runs it (auto), always or never.
  revkit::inputs::ParamIdMode param_id = revkit::inputs::ParamIdMode::automatic;
  double param_id_timeout = revkit::decompd::kParamIdTimeoutSeconds;
  // BSim signatures of every function (decompd mode signature) under the
  // inputs' signature profile, written as JSON.
  std::string signatures;
  std::optional<std::uint32_t> signature_settings;  // default: the language's (0x49 for 32/64-bit)
  bool signature_blocks = false;
  bool signature_import_prototypes = true;
  // revkit::infer's prototypes for the program's functions that have none
  // from the library archives (with --analyze --decompile, a program
  // without debug info, where infer knows the calling convention), as the
  // daemon's --infer-prototypes: closer to the source than the decompiler's
  // unlocked guesses (docs/decomp-quality.md).
  bool infer_prototypes = true;
  // With them, structures for the classes of passed-on pointer parameters
  // (infer::InferredStructure).
  bool infer_structures = true;
  // With --analyze --decompile: call-site prototypes from constant
  // printf/scanf formats (lift::DecompileConfig::format_strings).
  bool format_strings = true;
  // With --analyze --decompile: the fork's source-shape options
  // (lift::SourceShape::own() unless --source-shape or --no-source-shape
  // says otherwise), and with --compilable-c C a compiler accepts as well.
  std::optional<revkit::lift::SourceShape> shape;
  bool compilable = false;
};

// Sets the kinds of revkit facts named in `list` ("all", "none" or
// relocations,plt_overrides,...) to `on`.
bool set_own_facts(revkit::inputs::Options &o, std::string_view list, bool on) {
  struct Kind {
    const char *name;
    bool revkit::inputs::Options::*flag;
  };
  static const Kind kinds[] = {
      {"relocations", &revkit::inputs::Options::relocations}, {"plt_overrides", &revkit::inputs::Options::plt_overrides},
      {"no_return", &revkit::inputs::Options::no_return},     {"imports", &revkit::inputs::Options::imports},
      {"tracked", &revkit::inputs::Options::tracked},         {"labels", &revkit::inputs::Options::labels},
      {"debug_info", &revkit::inputs::Options::debug_info},   {"data", &revkit::inputs::Options::data},
      {"library_signatures", &revkit::inputs::Options::library_signatures},
      {"stack_locals", &revkit::inputs::Options::stack_locals},
      {"data_analysis", &revkit::inputs::Options::data_analysis},
      {"param_id", &revkit::inputs::Options::param_id},
      {"demangle", &revkit::inputs::Options::demangle},
  };
  while (!list.empty()) {
    std::string_view item = list.substr(0, list.find(','));
    list.remove_prefix(std::min(list.size(), item.size() + 1));
    bool found = false;
    for (const Kind &k : kinds) {
      if (item == "all" || item == "none" || item == k.name) {
        o.*k.flag = item == "none" ? !on : on;
        found = true;
      }
    }
    if (!found) {
      std::cerr << "rk-lift: unknown kind of fact: " << item << "\n";
      return false;
    }
  }
  return true;
}

void usage(std::ostream &os) {
  os << "usage: rk-lift [options] <binary>\n"
        "  --ghidra <root>  Ghidra install root (default: $GHIDRA_INSTALL_DIR, ~/.config/revkit/revkit.conf,\n"
        "                   the bundled specs, ~/ghidra*, /opt/ghidra*; docs/getting-started.md)\n"
        "  --version        print the version and exit\n"
        "  --lang <id>      language:compiler, e.g. x86:LE:64:default:gcc (default: from the file)\n"
        "  --name <label>   value for binary.path (default: the path as given)\n"
        "  --base <hex>     load at this image base\n"
        "  --file-base      keep the file's own base (default: Ghidra's, 0x100000 for 64-bit PIE)\n"
        "  -o <file>        write JSON here instead of stdout\n"
        "  --analyze        discover functions with revkit::analysis (default: file metadata only)\n"
        "  --decompile      decompile every function (decompiled_c)\n"
        "  --functions-from <ref.json>  take functions (entry, name, body) from a reference file\n"
        "  --inputs <json>  decompiler inputs exported from Ghidra (tools/ghidra-export/ghidra_dbexport.py):\n"
        "                   functions, signatures, symbols, types; implies its function list\n"
        "  -j <n>           threads for --analyze (default 1) and the decompiler (default: hardware threads)\n"
        "  --no-instructions  omit instructions and p-code\n"
        "  --in-order       decompile in address order (with -j 1: the sequence Ghidra uses)\n"
        "  --stats <file>   write timings as JSON\n"
        "  --own-facts <kinds>  with --analyze --decompile: which of revkit's facts the decompiler gets\n"
        "                   (all, none, or relocations,plt_overrides,no_return,imports,tracked,labels,data,\n"
        "                   debug_info,library_signatures,stack_locals,data_analysis,param_id,demangle; default all)\n"
        "  --no-own <kind>  leave one of them out (repeatable)\n"
        "  --no-debug-info  the same as --no-own debug_info\n"
        "  --dump-inputs <file>  write the decompiler inputs in the decompiler-inputs JSON format\n"
        "  --param-id auto|on|off  Ghidra's Decompiler Parameter ID analyzer with --analyze --decompile:\n"
        "                   where Ghidra runs it by default (a PE below 2 MiB), always, or never (default auto)\n"
        "  --param-id-timeout <s>  its per-function decompiler timeout (default 60, as Ghidra)\n"
        "  --no-infer-prototypes  with --analyze --decompile: without revkit::infer's prototypes (docs/infer.md)\n"
        "  --no-infer-structures  with them: without inference's structures for passed-on pointers\n"
        "  --no-format-strings    with --analyze --decompile: no call-site prototypes from constant printf/scanf\n"
        "                         formats (docs/types.md#format-strings)\n"
        "  --source-shape <list>  with --analyze --decompile: the decompiler options that print what the\n"
        "                         instructions encode (docs/decompiler-inputs.md), a comma list of\n"
        "                         extension|words, right|encoded, flag, compilable, all (the default:\n"
        "                         extension,right,flag) or none\n"
        "  --no-source-shape      --source-shape none: Ghidra's forms\n"
        "  --compilable-c         C a compiler accepts: no x._0_2_ pieces, no label ending a block, pointer and\n"
        "                         integer conversions cast\n"
        "                   for functions with no library ones (default: with them, over Parameter ID's, in a\n"
        "                   program without debug info where infer knows the calling convention: x86-64,\n"
        "                   AArch64, RISC-V 64)\n"
        "  --pdb-signatures ghidra|full  PDB prototypes as Ghidra applies them (default: __cdecl, param_N)\n"
        "                   or with the PDB's own parameter names (the daemon's)\n"
        "  --timeout <s>    stop a function's decompilation after <s> seconds (default 30, as Ghidra; 0: none)\n"
        "  --max-varnodes <n>  stop a function's decompilation past <n> varnodes (about 1 KB each;\n"
        "                   default: a quarter of the memory budget)\n"
        "  --memory-budget <MB>  decompile within this much resident memory (default 4096; 0: unbounded)\n"
        "  --decompile-only <hex,...>  decompile only these functions (the others are listed without C)\n"
        "  --failure-bundles <dir>  write the input bundle of each function the decompiler failed on\n"
        "                   (<dir>/<entry>.bundle; rk-decompd --bundle reproduces it)\n"
        "  --signatures <file>  BSim signatures of every function (decompd mode signature, under the\n"
        "                   inputs' signature profile) as JSON; with --analyze or --inputs\n"
        "  --signature-settings <hex>  GraphSigManager settings (default: the weights file's for the\n"
        "                   language, 0x49 for 32/64-bit; 0x4d collapses sizes)\n"
        "  --signature-blocks  also each basic block's features\n"
        "  --signature-no-import-prototypes  imports lose their library prototypes in signature bundles\n"
        "  --decompile-in-process  run the decompiler in this process instead of worker processes\n"
        "                   (debugging under gdb only: a crash ends rk-lift)\n"
        "  --detect         for a binary with no header: print what it is as JSON (the language, the load\n"
        "                   address, the image's offset in the file, each with its evidence) and do nothing\n"
        "                   else; exits 1 when there is no confident answer. -j sets the threads (default 8)\n"
        "  --detect-features  --detect, with what every candidate language's sweep measured\n"
        "  --raw            load <binary> as a flat binary at --base (default 0), read/write/execute; needs --lang\n"
        "  --raw-offset <hex>  skip this many bytes of the file (a header)\n"
        "  --raw-length <hex>  load this many bytes (default: to the end of the file)\n"
        "  --raw-perms <rwx>   the image block's permissions (default rwx, as Ghidra's raw loader)\n"
        "  --raw-entry <hex>   an entry point\n"
        "  --raw-space <name>  the memory space the image goes in (default: the code space; EXTMEM, mem, ...);\n"
        "                   --base and --raw-entry are byte offsets there (a word address times the word size)\n"
        "  --raw-format binary|ihex|srec|detect  what the file holds (default detect: Intel HEX and\n"
        "                   S-records by content, else binary)\n"
        "  --region <name:start:size[:perms][:init|uninit|volatile][:space=NAME]>  another memory region (RAM, MMIO;\n"
        "                   hex numbers; default rw-, uninitialized), repeatable\n";
}

std::optional<std::uint64_t> parse_hex(std::string_view s);

// revkit::infer over the image (its own discovery, the same as --analyze's):
// every function's inferred prototype by entry, and the structures they
// point to.
struct Inferred {
  std::map<std::uint64_t, revkit::infer::Prototype> prototypes;
  std::vector<revkit::infer::InferredStructure> structures;
};
Inferred infer_prototypes(std::shared_ptr<const revkit::loader::Image> image, const std::string &language_id,
                          const std::string &identity, unsigned threads, bool in_process, bool structures,
                          revkit::lift::SourceShape::Extension extension) {
  namespace an = revkit::analysis;
  namespace infer = revkit::infer;
  revkit::facts::FactDb db;
  an::register_queries(db.engine());
  infer::register_queries(db.engine());
  const an::ProgramKey prog{"p"};
  const an::ProgramInfo info = an::describe(*image, language_id);
  {
    auto tx = db.begin();
    an::stage_image(tx, prog, *image, info);
    infer::Options options;
    options.keep_return_width = true;  // the decompiler's callers read the whole register
    options.structures = structures;
    options.load_extension = extension;  // loads typed as the C's decompiler types them
    infer::stage_image(tx, prog, image, language_id, identity, options);
    tx.commit();
  }
  revkit::facts::ThreadPool pool(threads);
  revkit::decompd::PoolOptions po = revkit::decompd::default_pool_options();
  po.workers = threads;
  if (in_process) po.in_process = true;
  infer::DecompilerPool::set_workers(std::make_shared<revkit::decompd::WorkerPool>(po));
  revkit::facts::Snapshot snap = db.snapshot();
  std::vector<an::Location> seeds;
  for (const an::Seed &s : info.seeds) seeds.push_back({prog, s.address});
  snap.get_all<an::Flow>(seeds, &pool);
  snap.get<infer::CallGraphQuery>(prog);
  an::release_idle_decoders();
  infer::FixpointResult result = infer::run(snap, prog, &pool);
  Inferred out;
  out.prototypes.insert(result.prototypes.begin(), result.prototypes.end());
  out.structures = std::move(result.structures);
  infer::DecompilerPool::set_workers(nullptr);
  return out;
}

// Inferred prototypes as the decompiler's signatures (an ANALYSIS source,
// storage from the default model), for the functions in `eligible`, as the
// image backend overlays them (QueryLookup::with_overlay).
void apply_inferred(revkit::lift::DecompilerInputs &in, const Inferred &inferred,
                    const std::set<std::uint64_t> &eligible, const revkit::loader::Image &image,
                    const std::string &language_id) {
  const std::map<std::uint64_t, revkit::infer::Prototype> &protos = inferred.prototypes;
  namespace infer = revkit::infer;
  const infer::DataOrg org = infer::data_org(image);
  const revkit::inputs::DataOrg dorg = revkit::inputs::data_org(image, language_id);
  std::set<std::uint64_t> have;
  for (const revkit::lift::DecompElement &d : in.types)
    if (const auto *id = d.attr("id"))
      if (const auto *u = std::get_if<std::uint64_t>(id)) have.insert(*u);
  // The inferred structures, interned once: every prototype pointing to
  // one refers to the same type, defined once for the decompiler.
  revkit::types::TypeStore store;
  const infer::StructureIds structures = infer::to_types(inferred.structures, store, org);
  for (revkit::lift::FunctionFacts &f : in.functions) {
    if (!eligible.contains(f.entry)) continue;
    auto it = protos.find(f.entry);
    if (it == protos.end()) continue;
    const revkit::types::TypeId id = infer::to_type(it->second, store, org, &structures);
    const auto *fn = store.get(id).as<revkit::types::FunctionType>();
    if (fn == nullptr) continue;
    revkit::inputs::GhidraTypes enc(store, dorg, nullptr);
    f.signature_source = revkit::lift::SignatureSource::analysis;
    f.convention = "default";
    f.dynamic_storage = true;
    f.custom_storage = false;
    f.ret = revkit::lift::FunctionFacts::Return{};
    f.ret.type = enc.ref(fn->ret);
    f.ret.is_default = false;
    f.varargs = fn->varargs;
    f.params.clear();
    for (std::size_t i = 0; i < fn->params.size(); ++i) {
      revkit::lift::ParamFacts param;
      param.name = fn->params[i].name.empty() ? "param_" + std::to_string(i + 1) : fn->params[i].name;
      param.type = enc.ref(fn->params[i].type);
      f.params.push_back(std::move(param));
    }
    for (revkit::lift::DecompElement &d : enc.take_definitions())
      if (const auto *a = d.attr("id"))
        if (const auto *u = std::get_if<std::uint64_t>(a); u && have.insert(*u).second) in.types.push_back(std::move(d));
  }
}

// --signatures: every function's BSim signature under the signature
// profile, as {"language", "settings", "profile", "stats", "functions":
// [{"entry", "name", "status", "detail"?, "features": [...], "blocks"?}]}.
bool write_signatures(const Options &opt, const revkit::lift::DecompileConfig &config,
                      const std::vector<revkit::lift::Function> &functions, const std::string &language,
                      std::shared_ptr<const std::vector<std::uint64_t>> no_return, Json::Object &stats_out) {
  namespace dd = revkit::decompd;
  dd::SignatureBatchOptions so;
  so.signature.settings = opt.signature_settings.value_or(dd::default_signature_settings(language));
  so.signature.blocks = opt.signature_blocks;
  so.signature.profile.import_prototypes = opt.signature_import_prototypes;
  so.timeout_seconds = opt.timeout;
  // As the decompile phase bounds a function: a quarter of the memory budget.
  so.max_varnodes = opt.max_varnodes != 0 ? opt.max_varnodes
                    : opt.memory_budget_mb != 0 ? std::max<std::size_t>((opt.memory_budget_mb << 20) / 4 / 1024, 1 << 16)
                                                : 0;
  so.no_return = std::move(no_return);
  std::vector<std::uint64_t> entries;
  for (const revkit::lift::Function &f : functions)
    if (opt.only.empty() || std::find(opt.only.begin(), opt.only.end(), f.entry) != opt.only.end())
      entries.push_back(f.entry);
  dd::PoolOptions pool = dd::default_pool_options();
  if (opt.in_process) pool.in_process = true;
  dd::SignatureStats st;
  std::map<std::uint64_t, dd::FunctionSignature> sigs = dd::signature_functions(config, entries, so, &st, pool);
  Json::Array list;
  for (const revkit::lift::Function &f : functions) {
    auto it = sigs.find(f.entry);
    if (it == sigs.end()) continue;
    const dd::FunctionSignature &s = it->second;
    Json::Object o;
    o["entry"] = hex(f.entry);
    o["name"] = f.name;
    o["status"] = std::string(s.ok() ? "ok" : s.status == dd::FunctionSignature::Status::skipped ? "skipped" : "failed");
    if (!s.detail.empty()) o["detail"] = s.detail;
    Json::Array features;
    for (std::uint32_t h : s.features) features.push_back(static_cast<std::uint64_t>(h));
    o["features"] = std::move(features);
    if (opt.signature_blocks) {
      Json::Array blocks;
      for (const dd::BlockFeatures &b : s.blocks) {
        Json::Array bf;
        for (std::uint32_t h : b.features) bf.push_back(static_cast<std::uint64_t>(h));
        blocks.push_back(Json::Object{{"index", static_cast<std::int64_t>(b.index)}, {"start", hex(b.start)},
                                      {"features", std::move(bf)}});
      }
      o["blocks"] = std::move(blocks);
    }
    list.push_back(std::move(o));
  }
  stats_out["functions"] = static_cast<std::uint64_t>(st.functions);
  stats_out["signed"] = static_cast<std::uint64_t>(st.signed_ok);
  stats_out["failed"] = static_cast<std::uint64_t>(st.failed);
  stats_out["skipped"] = static_cast<std::uint64_t>(st.skipped);
  stats_out["seconds"] = st.seconds;
  stats_out["worker_ms"] = st.run_ms;
  stats_out["parent_ms"] = st.build_ms;
  stats_out["threads"] = static_cast<std::uint64_t>(config.threads);
  stats_out["features"] = static_cast<std::uint64_t>(st.features);
  char settings[16];
  std::snprintf(settings, sizeof settings, "0x%x", so.signature.settings);
  Json::Object doc;
  doc["language"] = language;
  doc["settings"] = std::string(settings);
  doc["profile"] = so.signature.profile.id();
  doc["stats"] = Json(stats_out);
  doc["functions"] = std::move(list);
  std::ofstream out(opt.signatures, std::ios::binary);
  Json(std::move(doc)).write_document(out);
  if (!out) {
    std::cerr << "rk-lift: cannot write " << opt.signatures << "\n";
    return false;
  }
  std::cerr << "rk-lift: signatures: " << st.signed_ok << " signed, " << st.failed << " failed, " << st.skipped
            << " skipped of " << st.functions << " in " << st.seconds << " s\n";
  std::cerr << "rk-lift: " << dd::failure_summary(st.failures);
  return true;
}

std::optional<std::uint64_t> parse_hex(std::string_view s) {
  try {
    std::size_t used = 0;
    unsigned long long v = std::stoull(std::string(s), &used, 16);
    if (used != s.size()) return std::nullopt;
    return v;
  } catch (const std::exception &) {
    return std::nullopt;
  }
}

std::optional<Options> parse_args(int argc, char **argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    const char *v = nullptr;
    if (arg == "--help" || arg == "-h") return std::nullopt;
    if (arg == "--ghidra" && (v = value())) opt.ghidra_root = v;
    else if (arg == "--lang" && (v = value())) opt.language = v;
    else if (arg == "--name" && (v = value())) opt.name = v;
    else if (arg == "-o" && (v = value())) opt.output = v;
    else if (arg == "--file-base") opt.file_base = true;
    else if (arg == "--analyze") opt.analyze = true;
    else if (arg == "--decompile") opt.decompile = true;
    else if (arg == "--no-instructions") opt.instructions = false;
    else if (arg == "--in-order") opt.in_order = true;
    else if (arg == "--functions-from" && (v = value())) opt.functions_from = v;
    else if (arg == "--inputs" && (v = value())) opt.inputs = v;
    else if (arg == "--stats" && (v = value())) opt.stats = v;
    else if (arg == "--dump-inputs" && (v = value())) opt.dump_inputs = v;
    else if (arg == "--pdb-signatures" && (v = value())) {
      if (std::string_view(v) == "full") opt.own.pdb_signatures = revkit::inputs::Options::PdbSignatures::full;
      else if (std::string_view(v) == "ghidra") opt.own.pdb_signatures = revkit::inputs::Options::PdbSignatures::ghidra;
      else {
        std::cerr << "rk-lift: --pdb-signatures takes ghidra or full\n";
        return std::nullopt;
      }
    }
    else if (arg == "--no-debug-info") opt.own.debug_info = false;
    else if (arg == "--infer-prototypes") opt.infer_prototypes = true;
    else if (arg == "--no-infer-prototypes") opt.infer_prototypes = false;
    else if (arg == "--no-infer-structures") opt.infer_structures = false;
    else if (arg == "--no-format-strings") opt.format_strings = false;
    else if (arg == "--no-source-shape") opt.shape = revkit::lift::SourceShape{};
    else if (arg == "--source-shape" && (v = value())) {
      revkit::lift::SourceShape s;
      std::string list = v, item;
      std::stringstream in(list);
      while (std::getline(in, item, ',')) {
        if (item == "all") s = revkit::lift::SourceShape::own();
        else if (item == "none") s = revkit::lift::SourceShape{};
        else if (item == "extension") s.extension = revkit::lift::SourceShape::Extension::all;
        else if (item == "words") s.extension = revkit::lift::SourceShape::Extension::words;
        else if (item == "right") s.compare = revkit::lift::SourceShape::Compare::right;
        else if (item == "encoded") s.compare = revkit::lift::SourceShape::Compare::encoded;
        else if (item == "flag") s.flag_compare = true;
        else if (item == "compilable") s.compilable = true;
        else {
          std::cerr << "rk-lift: --source-shape: unknown option " << item << "\n";
          return std::nullopt;
        }
      }
      opt.shape = s;
    }
    else if (arg == "--compilable-c") opt.compilable = true;
    else if (arg == "--param-id" && (v = value())) {
      std::optional<revkit::inputs::ParamIdMode> m = revkit::inputs::parse_param_id_mode(v);
      if (!m) {
        std::cerr << "rk-lift: --param-id takes auto, on or off\n";
        return std::nullopt;
      }
      opt.param_id = *m;
    } else if (arg == "--param-id-timeout" && (v = value())) opt.param_id_timeout = std::strtod(v, nullptr);
    else if (arg == "--own-facts" && (v = value())) {
      opt.own = revkit::inputs::Options{};
      if (!set_own_facts(opt.own, "none", true) || !set_own_facts(opt.own, v, true)) return std::nullopt;
    } else if (arg == "--no-own" && (v = value())) {
      if (!set_own_facts(opt.own, v, false)) return std::nullopt;
    }
    else if (arg == "-j" && (v = value())) opt.threads = static_cast<unsigned>(std::max(1, std::atoi(v)));
    else if (arg == "--timeout" && (v = value())) opt.timeout = std::max(0.0, std::atof(v));
    else if (arg == "--max-varnodes" && (v = value())) opt.max_varnodes = std::strtoull(v, nullptr, 10);
    else if (arg == "--memory-budget" && (v = value())) opt.memory_budget_mb = std::strtoull(v, nullptr, 10);
    else if (arg == "--decompile-in-process") opt.in_process = true;
    else if (arg == "--signatures" && (v = value())) opt.signatures = v;
    else if (arg == "--signature-settings" && (v = value())) {
      auto n = parse_hex(std::string_view(v).starts_with("0x") ? v + 2 : v);
      if (!n) {
        std::cerr << "rk-lift: bad --signature-settings: " << v << "\n";
        return std::nullopt;
      }
      opt.signature_settings = static_cast<std::uint32_t>(*n);
    }
    else if (arg == "--signature-blocks") opt.signature_blocks = true;
    else if (arg == "--signature-no-import-prototypes") opt.signature_import_prototypes = false;
    else if (arg == "--failure-bundles" && (v = value())) opt.failure_bundles = v;
    else if (arg == "--decompile-only" && (v = value())) {
      std::string_view list = v;
      while (!list.empty()) {
        std::string_view item = list.substr(0, list.find(','));
        list.remove_prefix(std::min(list.size(), item.size() + 1));
        if (item.starts_with("0x")) item.remove_prefix(2);
        auto a = parse_hex(item);
        if (!a) {
          std::cerr << "rk-lift: bad --decompile-only address: " << item << "\n";
          return std::nullopt;
        }
        opt.only.push_back(*a);
      }
    }
    else if (arg == "--raw") opt.raw = true;
    else if (arg == "--detect") opt.detect = true;
    else if (arg == "--detect-features") opt.detect = opt.detect_features = true;
    else if ((arg == "--raw-offset" || arg == "--raw-length" || arg == "--raw-entry") && (v = value())) {
      auto n = parse_hex(std::string_view(v).starts_with("0x") ? v + 2 : v);
      if (!n) {
        std::cerr << "rk-lift: bad " << arg << ": " << v << "\n";
        return std::nullopt;
      }
      if (arg == "--raw-offset") opt.raw_options.offset = *n;
      else if (arg == "--raw-length") opt.raw_options.length = *n;
      else opt.raw_options.entry = *n;
    } else if (arg == "--raw-perms" && (v = value())) {
      std::string_view p = v;
      if (p.size() != 3) {
        std::cerr << "rk-lift: bad --raw-perms: " << v << "\n";
        return std::nullopt;
      }
      opt.raw_options.perms = {p[0] == 'r', p[1] == 'w', p[2] == 'x'};
    } else if (arg == "--raw-space" && (v = value())) {
      opt.raw_options.space = v;
    } else if (arg == "--raw-format" && (v = value())) {
      auto c = revkit::loader::raw_container_from_string(v);
      if (!c) {
        std::cerr << "rk-lift: bad --raw-format: " << v << " (binary, ihex, srec or detect)\n";
        return std::nullopt;
      }
      opt.raw_options.container = *c;
    } else if (arg == "--region" && (v = value())) {
      try {
        opt.raw_options.regions.push_back(revkit::loader::parse_raw_region(v));
      } catch (const revkit::loader::LoadError &e) {
        std::cerr << "rk-lift: " << e.what() << "\n";
        return std::nullopt;
      }
    }
    else if (arg == "--base" && (v = value())) {
      opt.base = parse_hex(std::string_view(v).starts_with("0x") ? v + 2 : v);
      if (!opt.base) {
        std::cerr << "rk-lift: bad --base: " << v << "\n";
        return std::nullopt;
      }
    } else if (!arg.starts_with("-") && opt.file.empty()) {
      opt.file = arg;
    } else {
      std::cerr << "rk-lift: bad argument: " << arg << "\n";
      return std::nullopt;
    }
  }
  if (opt.file.empty()) return std::nullopt;
  if (opt.analyze && (!opt.inputs.empty() || !opt.functions_from.empty())) {
    std::cerr << "rk-lift: --analyze discovers functions itself; it doesn't combine with --inputs or --functions-from\n";
    return std::nullopt;
  }
  if (opt.raw && !opt.language) {
    std::cerr << "rk-lift: --raw needs --lang\n";
    return std::nullopt;
  }
  if (opt.raw) {
    opt.raw_options.language = *opt.language;
    opt.raw_options.base = opt.base.value_or(0);
  }
  if (opt.name.empty()) opt.name = opt.file;
  return opt;
}

// One varnode, compact, as the reference format writes it.
void append_varnode(std::string &out, const revkit::lift::Varnode &v) {
  out.push_back('[');
  if (!v.referenced_space.empty()) {
    out += "\"space\",";
    rklift::append_quoted(out, v.referenced_space);
  } else {
    rklift::append_quoted(out, v.space);
    out += ",\"";
    rklift::append_hex(out, v.offset);
    out.push_back('"');
  }
  out.push_back(',');
  out += std::to_string(v.size);
  out.push_back(']');
}

// One element of `instructions`, compact with sorted keys: what
// Json::compact() writes for it, without building the tree.
void append_instruction(std::string &out, const revkit::lift::Instruction &insn) {
  out += "{\"addr\":\"";
  rklift::append_hex(out, insn.address);
  out += "\",\"len\":";
  out += std::to_string(insn.length);
  out += ",\"mnemonic\":";
  rklift::append_quoted(out, insn.mnemonic);
  out += ",\"pcode\":[";
  bool first_op = true;
  for (const revkit::lift::PcodeOp &op : insn.pcode) {
    if (!first_op) out.push_back(',');
    first_op = false;
    out += "{\"in\":[";
    for (std::size_t k = 0; k < op.inputs.size(); ++k) {
      if (k != 0) out.push_back(',');
      append_varnode(out, op.inputs[k]);
    }
    out += "],\"op\":";
    rklift::append_quoted(out, op.opcode);
    out += ",\"out\":";
    if (op.output) append_varnode(out, *op.output);
    else out += "null";
    out.push_back('}');
  }
  out += "],\"text\":";
  rklift::append_quoted(out, insn.text);
  out.push_back('}');
}

// The addresses that start an instruction in some function body, with the
// instruction's length and whether it was decoded as a delay slot: one byte
// per address, in pages allocated as bodies touch them, so this costs about
// a byte per byte of code instead of a decoded instruction per instruction.
class InstructionStarts {
 public:
  struct Entry {
    std::uint32_t length = 0;
    std::uint32_t delay_slot = 0;  // bytes of delay-slot instructions after it
    bool in_delay_slot = false;
  };

  std::optional<Entry> find(std::uint64_t a) const {
    const std::uint8_t *page = page_for(a >> kPageBits);
    if (page == nullptr) return std::nullopt;
    std::uint8_t b = page[a & kPageMask];
    if (b == 0) return std::nullopt;
    return entry(a, b);
  }

  void add(std::uint64_t a, revkit::lift::InstructionExtent extent, bool in_delay_slot) {
    std::uint8_t *page = writable_page(a >> kPageBits);
    std::uint8_t b = extent.length < kLong ? static_cast<std::uint8_t>(extent.length) : kLong;
    if (b == kLong) long_[a] = extent.length;
    if (extent.delay_slot != 0) delay_[a] = extent.delay_slot;
    page[a & kPageMask] = static_cast<std::uint8_t>(b | (in_delay_slot ? kDelayBit : 0));
    ++count_;
  }

  // Calls f(address, entry) in address order.
  template <class F>
  void for_each(F &&f) const {
    for (const auto &[index, page] : pages_)
      for (std::uint64_t k = 0; k < kPageSize; ++k)
        if (page[k] != 0) f((index << kPageBits) | k, entry((index << kPageBits) | k, page[k]));
  }

  std::size_t size() const { return count_; }

  // Adds the instructions of `later` at addresses this doesn't have, as if
  // its walk had continued with later's functions.
  void merge(const InstructionStarts &later) {
    later.for_each([&](std::uint64_t a, const Entry &e) {
      if (!find(a)) add(a, revkit::lift::InstructionExtent{e.length, e.delay_slot}, e.in_delay_slot);
    });
  }

 private:
  std::uint8_t *writable_page(std::uint64_t index) {
    if (index == last_page_) return const_cast<std::uint8_t *>(last_);
    std::unique_ptr<std::uint8_t[]> &page = pages_[index];
    if (!page) page = std::make_unique<std::uint8_t[]>(kPageSize);  // zeroed
    last_page_ = index;
    last_ = page.get();
    return page.get();
  }

  static constexpr unsigned kPageBits = 12;
  static constexpr std::uint64_t kPageSize = std::uint64_t{1} << kPageBits;
  static constexpr std::uint64_t kPageMask = kPageSize - 1;
  static constexpr std::uint8_t kDelayBit = 0x80;
  static constexpr std::uint8_t kLong = 0x7f;  // length in long_

  const std::uint8_t *page_for(std::uint64_t index) const {
    if (index == last_page_) return last_;
    auto it = pages_.find(index);
    if (it == pages_.end()) return nullptr;
    last_page_ = index;
    last_ = it->second.get();
    return last_;
  }

  Entry entry(std::uint64_t a, std::uint8_t b) const {
    Entry e;
    e.in_delay_slot = (b & kDelayBit) != 0;
    e.length = b & ~kDelayBit;
    if (e.length == kLong) e.length = long_.at(a);
    if (auto it = delay_.find(a); it != delay_.end()) e.delay_slot = it->second;
    return e;
  }

  std::map<std::uint64_t, std::unique_ptr<std::uint8_t[]>> pages_;
  std::unordered_map<std::uint64_t, std::uint32_t> long_;
  std::unordered_map<std::uint64_t, std::uint32_t> delay_;
  std::size_t count_ = 0;
  mutable std::uint64_t last_page_ = ~std::uint64_t{0};
  mutable const std::uint8_t *last_ = nullptr;
};

// Every instruction of every body: each body range is decoded from its first
// byte, reusing instructions found earlier (bodies overlap), so an address
// starts an instruction in the output exactly when this walk decodes one
// there. Data marked by $d mapping symbols is skipped rather than decoded as
// code. `decode(address, in_delay_slot)` returns the instruction's extent.
template <class Decode>
InstructionStarts walk_bodies(const revkit::loader::Image &image, unsigned alignment,
                              std::span<const revkit::lift::Function> functions, Decode &&decode) {
  const std::vector<revkit::lift::AddressRange> data = revkit::lift::embedded_data(image);
  const std::uint64_t step = std::max(1u, alignment);
  InstructionStarts out;
  for (const revkit::lift::Function &f : functions) {
    for (const auto &[first, last] : f.body) {
      std::uint64_t a = first;
      std::uint64_t delay_end = first;  // bytes before this are a delay slot
      while (a <= last) {
        auto d = std::upper_bound(data.begin(), data.end(), a,
                                  [](std::uint64_t x, const revkit::lift::AddressRange &r) { return x < r.first; });
        if (d != data.begin() && std::prev(d)->second >= a) {
          std::uint64_t past = std::prev(d)->second;
          if (past >= last) break;
          a = past + 1;
          continue;
        }
        std::uint64_t advance = step;
        if (std::optional<InstructionStarts::Entry> known = out.find(a)) {
          advance = known->length;
          if (known->delay_slot != 0) delay_end = a + known->length + known->delay_slot;
        } else if (const bool in_delay_slot = a < delay_end;
                   std::optional<revkit::lift::InstructionExtent> e = decode(a, in_delay_slot)) {
          advance = e->length;
          if (e->delay_slot != 0) delay_end = a + e->length + e->delay_slot;
          out.add(a, *e, in_delay_slot);
        }
        if (advance > last - a) break;
        a += advance;
      }
    }
  }
  return out;
}

Json read_json_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw rklift::JsonError("cannot read " + path);
  std::ostringstream text;
  text << in.rdbuf();
  return Json::parse(text.str());
}

// Lifts the instructions in `starts` in address order and writes each as an
// element of the open `instructions` array. With several lifters (one per
// thread), batches are decoded in parallel and written in order, so the
// output doesn't depend on the thread count. Every lifter must decode as the
// first pass did: nothing changed the context (Lifter::context_changed()).
// Returns how many instructions didn't decode again (none, normally).
std::size_t write_instructions(rklift::DocumentWriter &w, const InstructionStarts &starts,
                               const std::vector<revkit::lift::Lifter *> &lifters) {
  std::size_t missing = 0;
  if (lifters.size() == 1) {
    starts.for_each([&](std::uint64_t a, const InstructionStarts::Entry &e) {
      if (std::optional<revkit::lift::Instruction> insn = lifters[0]->lift(a, e.in_delay_slot))
        append_instruction(w.element(), *insn);
      else
        ++missing;
    });
    return missing;
  }
  struct Item {
    std::uint64_t address;
    bool in_delay_slot;
  };
  const std::size_t threads = lifters.size();
  const std::size_t batch_size = 8192 * threads;
  std::vector<Item> batch;
  batch.reserve(batch_size);
  std::vector<std::string> lines;
  auto run_batch = [&] {
    lines.assign(batch.size(), std::string());
    auto work = [&](std::size_t t) {
      for (std::size_t i = t * batch.size() / threads, end = (t + 1) * batch.size() / threads; i < end; ++i)
        if (std::optional<revkit::lift::Instruction> insn = lifters[t]->lift(batch[i].address, batch[i].in_delay_slot))
          append_instruction(lines[i], *insn);
    };
    std::vector<std::thread> pool;
    for (std::size_t t = 1; t < threads; ++t) pool.emplace_back(work, t);
    work(0);
    for (std::thread &t : pool) t.join();
    for (const std::string &line : lines) {
      if (line.empty()) ++missing;
      else w.element() += line;
    }
    batch.clear();
  };
  starts.for_each([&](std::uint64_t a, const InstructionStarts::Entry &e) {
    batch.push_back({a, e.in_delay_slot});
    if (batch.size() == batch_size) run_batch();
  });
  if (!batch.empty()) run_batch();
  return missing;
}

std::uint64_t peak_rss_bytes() {
  struct rusage u {};
  getrusage(RUSAGE_SELF, &u);
  return static_cast<std::uint64_t>(u.ru_maxrss) * 1024;
}

// The kernel's peak RSS (VmHWM), which writing 5 to clear_refs resets to
// the current RSS: the peak of one phase.
void reset_peak_rss() { std::ofstream("/proc/self/clear_refs") << "5"; }
std::uint64_t phase_peak_rss_bytes() {
  std::ifstream status("/proc/self/status");
  for (std::string line; std::getline(status, line);)
    if (line.starts_with("VmHWM:")) return std::strtoull(line.c_str() + 6, nullptr, 10) * 1024;
  return 0;
}

double seconds(std::chrono::steady_clock::time_point since) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - since).count();
}

// Functions from revkit::analysis (discovery over an in-memory fact store).
std::vector<revkit::lift::Function> analyzed_functions(revkit::inputs::Analysis &analysis) {
  namespace an = revkit::analysis;
  std::vector<revkit::lift::Function> out;
  for (const an::FunctionInfo &f : analysis.functions().functions) {
    revkit::lift::Function fn{f.entry.offset, f.name, {}};
    for (const revkit::facts::AddressRange &r : f.body.ranges()) fn.body.emplace_back(r.first.offset, r.last.offset);
    if (!fn.body.empty()) out.push_back(std::move(fn));
  }
  return out;
}

int run(const Options &opt) {
  const auto started = std::chrono::steady_clock::now();
  // Every decompiling thread would get a malloc arena of its own, each
  // keeping what its functions freed: four shared ones hold less (set
  // before any thread allocates).
  if (opt.decompile && opt.memory_budget_mb != 0 && std::getenv("MALLOC_ARENA_MAX") == nullptr)
    mallopt(M_ARENA_MAX, 4);
  // Before loading: the loaders lay out a language's memory spaces and
  // default blocks from its specs.
  revkit::lift::initialize(opt.ghidra_root);
  revkit::loader::LoadOptions load_opts;
  load_opts.image_base = opt.base;
  load_opts.ghidra_image_base = !opt.file_base;
  auto image = std::make_shared<const revkit::loader::Image>(
      opt.raw ? revkit::loader::load_raw_file(opt.file, opt.raw_options) : revkit::loader::load_file(opt.file, load_opts));
  for (const std::string &w : image->warnings) std::cerr << "rk-lift: warning: " << w << "\n";

  // Decompiler inputs: Ghidra's export, or a reference file's function list.
  std::shared_ptr<revkit::lift::DecompilerInputs> inputs;
  bool exported = false;
  std::optional<bool> synthesize_labels;  // LAB_ for any address in a body
  if (!opt.inputs.empty()) {
    const Json doc = read_json_file(opt.inputs);
    inputs = std::make_shared<revkit::lift::DecompilerInputs>(rklift::inputs_from_export(doc));
    // A full export of Ghidra's symbols, unless the document says otherwise
    // (revkit's own inputs, written by --dump-inputs).
    const Json *complete = doc.find("symbols_complete");
    exported = complete == nullptr || !complete->is_bool() || complete->boolean();
    if (const Json *labels = doc.find("synthesize_labels"); labels && labels->is_bool())
      synthesize_labels = labels->boolean();
  } else if (!opt.functions_from.empty()) {
    inputs = std::make_shared<revkit::lift::DecompilerInputs>(
        rklift::inputs_from_reference(read_json_file(opt.functions_from)));
  }
  const double read_s = seconds(started);

  revkit::loader::LanguageSpec lang;
  if (opt.language) {
    const std::string &id = *opt.language;
    if (std::count(id.begin(), id.end(), ':') != 4) {
      std::cerr << "rk-lift: --lang must be proc:endian:size:variant:compiler\n";
      return 2;
    }
    auto colon = id.rfind(':');
    lang = {id.substr(0, colon), id.substr(colon + 1)};
  } else if (inputs && !inputs->language.empty() && !inputs->compiler.empty()) {
    lang = {inputs->language, inputs->compiler};  // the reference's choice (e.g. clangwindows)
  } else if (auto guess = revkit::loader::guess_language(*image)) {
    lang = *guess;
  } else {
    std::cerr << "rk-lift: no Ghidra language for machine " << image->machine << "; use --lang\n";
    return 1;
  }

  // A SLEIGH engine for the instructions and for discovering functions;
  // not needed to decompile a given function list.
  std::optional<revkit::lift::Lifter> lifter;
  if (opt.instructions || (!inputs && !opt.analyze)) {
    lifter.emplace(image, lang.language);
    for (const revkit::lift::ContextRegion &c : revkit::lift::image_context(*image))
      lifter->set_context(c.name, c.value, c.start, c.end);
  }

  std::vector<revkit::lift::Function> functions;
  std::unique_ptr<revkit::inputs::Analysis> analysis;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> thumb_ranges;  // inclusive
  std::string isa_context;  // what thumb_ranges paint (the analysis is freed before the listing pass)
  std::set<std::uint64_t> thumb_entries;  // Thumb functions (ARM interworking), reported as such
  if (inputs) {
    for (const revkit::lift::FunctionFacts &f : inputs->functions) {
      if (f.entry == 0 && f.body.empty()) continue;
      // revkit's own inputs list EXTERNAL placeholders for the decompiler,
      // not as functions of the program (Ghidra's exports do).
      auto in_external = [&](std::uint64_t a) {
        return std::any_of(inputs->memory.begin(), inputs->memory.end(), [&](const revkit::lift::BlockFacts &b) {
          return b.external && b.space.empty() && a >= b.start && a <= b.end;
        });
      };
      if (!exported && in_external(f.entry)) continue;
      functions.push_back({f.entry, f.name, f.body});
    }
    std::sort(functions.begin(), functions.end(),
              [](const revkit::lift::Function &a, const revkit::lift::Function &b) { return a.entry < b.entry; });
  } else if (opt.analyze) {
    // Flow graphs are memoized only up to 512 MB once discovery is done
    // with them (it holds them all while it runs); a whole-program
    // decompile reads each again by decoding.
    analysis = revkit::inputs::analyze(*image, lang.id(), opt.threads.value_or(1), std::size_t{512} << 20);
    functions = analyzed_functions(*analysis);
    // Thumb functions discovery found decode as Thumb (ARM interworking).
    isa_context = analysis->info().isa_context;
    if (!isa_context.empty())
      for (const revkit::analysis::FunctionInfo &f : analysis->functions().functions)
        if (f.flags & revkit::analysis::kFunctionThumb) {
          thumb_entries.insert(f.entry.offset);
          if (lifter)
            for (const revkit::facts::AddressRange &r : f.body.ranges())
              thumb_ranges.emplace_back(r.first.offset, r.last.offset);
        }
  } else {
    functions = revkit::lift::seed_functions(*image, *lifter);
  }
  const double discover_s = seconds(started);

  // Which addresses start instructions (first pass: lengths only). The
  // second pass, lifting them in address order, streams them to the output.
  //
  // Both passes can run on several SLEIGH engines. An engine costs about
  // 50 ms (built one at a time) and 35 MB, so each gets at least 400 KB of
  // bodies, about 100,000 instructions or a quarter second's work.
  InstructionStarts starts;
  bool starts_exact = true;
  std::vector<std::unique_ptr<revkit::lift::Lifter>> extra;
  std::vector<revkit::lift::Lifter *> lifters;
  if (opt.instructions) {
    std::uint64_t body_bytes = 0;
    for (const revkit::lift::Function &f : functions)
      for (const auto &[first, last] : f.body) body_bytes += last - first + 1;
    std::uint64_t per_engine = 400000;
    if (const char *env = std::getenv("RK_LIFT_BYTES_PER_ENGINE")) per_engine = std::max(1, std::atoi(env));  // tests
    const std::size_t engines =
        std::min<std::uint64_t>({opt.threads.value_or(1), 64, std::max<std::uint64_t>(1, body_bytes / per_engine)});
    lifters.push_back(&*lifter);
    for (std::size_t t = 1; t < engines; ++t) {
      extra.push_back(std::make_unique<revkit::lift::Lifter>(image, lang.language));
      for (const revkit::lift::ContextRegion &c : revkit::lift::image_context(*image))
        extra.back()->set_context(c.name, c.value, c.start, c.end);
      lifters.push_back(extra.back().get());
    }
    for (revkit::lift::Lifter *l : lifters)
      for (const auto &[first, last] : thumb_ranges) l->set_context(isa_context, 1, first, last + 1);
    // Each engine walks a contiguous slice of the functions (by body
    // bytes); merged in order, earlier slices win, as in one walk: a decode
    // depends only on its address, so where slices overlap they find the
    // same instructions, and only the delay-slot flag of the first visit
    // matters.
    std::vector<std::size_t> cut{0};
    std::uint64_t seen = 0;
    for (std::size_t i = 0; i < functions.size(); ++i) {
      for (const auto &[first, last] : functions[i].body) seen += last - first + 1;
      if (cut.size() < engines && seen * engines >= body_bytes * cut.size()) cut.push_back(i + 1);
    }
    while (cut.size() <= engines) cut.push_back(functions.size());
    std::vector<InstructionStarts> parts(engines);
    auto walk = [&](std::size_t t) {
      std::span<const revkit::lift::Function> slice(functions.data() + cut[t], cut[t + 1] - cut[t]);
      parts[t] = walk_bodies(*image, lifters[t]->alignment(), slice,
                             [&](std::uint64_t a, bool delay) { return lifters[t]->measure(a, delay); });
    };
    std::vector<std::thread> pool;
    for (std::size_t t = 1; t < engines; ++t) pool.emplace_back(walk, t);
    walk(0);
    for (std::thread &t : pool) t.join();
    starts = std::move(parts[0]);
    for (std::size_t t = 1; t < engines; ++t) {
      starts.merge(parts[t]);
      parts[t] = InstructionStarts();
    }
    // Instructions changed the context: a later decode can depend on what was
    // decoded before, so decode again in one walk in order, keeping each
    // instruction's text (languages with globalset, such as ARM).
    for (revkit::lift::Lifter *l : lifters) starts_exact = starts_exact && !l->context_changed();
  }
  const double measure_s = seconds(started);

  // Decompile every function.
  // Decompiled C by entry: where it is in the scratch file.
  std::map<std::uint64_t, std::pair<long, std::size_t>> spilled;
  std::unique_ptr<std::FILE, int (*)(std::FILE *)> spill(nullptr, &std::fclose);
  revkit::decompd::BatchStats dstats;
  std::optional<revkit::inputs::ParamIdPlan> param_id_plan;
  revkit::decompd::ParamIdStats param_id_stats;
  double param_id_seconds = 0;
  double decompile_ms_sum = 0;  // per-function times, summed over threads
  Json::Array slowest;          // [entry, ms] of the slowest functions
  Json::Array largest;           // [entry, varnodes] of the largest runs
  std::uint64_t decompile_peak_rss = 0, decompile_base_rss = 0;  // VmHWM while decompiling, RSS before
  Json::Object signature_stats;
  std::shared_ptr<const std::vector<std::uint64_t>> signature_no_return;
  revkit::lift::DecompileConfig config;
  std::set<std::uint64_t> infer_eligible;  // functions with no signature but analysis's
  std::set<std::uint64_t> infer_this;      // demangled prototypes whose `this` is a guess
  if (opt.decompile || !opt.signatures.empty()) {
    config.image = image;
    config.language_id = lang.id();
    const bool analyzed = analysis != nullptr;
    if (!inputs && analysis) {
      // Everything the decompiler is told comes from revkit.
      revkit::inputs::Program program{image, lang.id(), analysis.get(), nullptr};
      if (opt.own.debug_info) program.debug = revkit::inputs::read_debug_info(*image, opt.file);
      inputs = std::make_shared<revkit::lift::DecompilerInputs>(
          revkit::inputs::assemble(program, opt.own, opt.threads.value_or(1)));
      // Signatures see analysis's no-return functions, not the debug info's.
      if (opt.own.no_return)
        signature_no_return = std::make_shared<const std::vector<std::uint64_t>>(
            revkit::inputs::ghidra_no_return(analysis->functions(), analysis->no_return_evidence()));
      else
        signature_no_return = std::make_shared<const std::vector<std::uint64_t>>();
      // Ghidra's Decompiler Parameter ID: its call graph from discovery,
      // run below once the decompiler's configuration is complete.
      if (opt.decompile && opt.own.param_id &&
          revkit::inputs::param_id_enabled(opt.param_id, *image, inputs->memory)) {
        param_id_plan = revkit::inputs::param_id_plan(revkit::inputs::call_graph_nodes(
            analysis->functions(), analysis->info(),
            [&](std::uint64_t key) -> const revkit::analysis::FlowGraph & { return analysis->flow(key); }));
      }
      // Not with debug info: its functions have their prototypes, and the
      // rest (start-up code, a function's .cold part) gain nothing.
      if (opt.decompile && opt.infer_prototypes && program.debug == nullptr &&
          revkit::infer::supports(lang.id(), *image))
        for (const revkit::lift::FunctionFacts &f : inputs->functions) {
          if (f.signature_source == revkit::lift::SignatureSource::default_ && f.entry != 0)
            infer_eligible.insert(f.entry);
          // A demangled prototype whose `this` is a guess: inference's
          // parameter count decides it.
          if (f.this_guessed) infer_this.insert(f.entry);
        }
      // The inputs have what the decompiler needs from discovery; its
      // store (every flow graph: 2.8 GB on libLLVM) can go, back to the
      // system rather than kept by malloc.
      analysis.reset();
      revkit::analysis::release_idle_decoders();
      malloc_trim(0);
    } else if (!inputs) {
      auto own = std::make_shared<revkit::lift::DecompilerInputs>();
      for (const revkit::lift::Function &f : functions) {
        revkit::lift::FunctionFacts ff;
        ff.entry = f.entry;
        ff.name = f.name;
        ff.body = f.body;
        ff.convention = "unknown";
        ff.ret.type = {"void", {}, {}};
        ff.ret.storage = std::vector<revkit::lift::StorageVarnode>{};
        ff.ret.void_storage = true;
        own->functions.push_back(std::move(ff));
      }
      inputs = own;
    }
    config.inputs = inputs;
    config.default_names = !exported;
    config.default_labels = synthesize_labels.value_or(!(analyzed && opt.own.labels));
    config.default_extrapop = !exported;
    config.format_strings = analyzed && opt.format_strings;
    if (analyzed) config.shape = opt.shape.value_or(revkit::lift::SourceShape::own());
    if (opt.compilable) config.shape.compilable = true;
    config.threads = opt.threads.value_or(0);
    if (param_id_plan) {
      // Every function decompiled bottom-up, the signatures it finds
      // committed for its callers, then the program decompiled with them.
      revkit::decompd::ParamIdOptions po;
      po.timeout_seconds = opt.param_id_timeout;
      po.max_varnodes = opt.max_varnodes;
      revkit::decompd::PoolOptions pool = revkit::decompd::default_pool_options();
      if (opt.in_process) pool.in_process = true;
      const auto pid_started = std::chrono::steady_clock::now();
      std::map<std::uint64_t, revkit::lift::CommittedSignature> committed =
          revkit::decompd::param_id_functions(config, *param_id_plan, po, &param_id_stats, pool);
      revkit::inputs::apply_param_id(*inputs, *param_id_plan, committed);
      param_id_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - pid_started).count();
      for (const auto &[entry, sig] : committed)
        if (sig.status == revkit::lift::CommittedSignature::Status::failed)
          std::cerr << "rk-lift: param-id " << hex(entry) << ": " << sig.detail << "\n";
    }
    if (!infer_eligible.empty() || !infer_this.empty()) {
      std::error_code ec;
      const std::string identity = std::filesystem::absolute(opt.file).string() + ":" +
                                   std::to_string(std::filesystem::file_size(opt.file, ec));
      const auto protos = infer_prototypes(image, lang.id(), identity,
                                           // deterministic for any number of threads; --in-order's
                                           // one decompiler thread needn't bound it
                                           std::max(2u, opt.threads.value_or(std::thread::hardware_concurrency())),
                                           opt.in_process, opt.infer_structures, config.shape.extension);
      apply_inferred(*inputs, protos, infer_eligible, *image, lang.id());
      for (revkit::lift::FunctionFacts &f : inputs->functions)
        if (infer_this.contains(f.entry))
          if (auto it = protos.prototypes.find(f.entry); it != protos.prototypes.end())
          {
            std::vector<bool> is_float;
            for (const revkit::infer::VType &t : it->second.params) is_float.push_back(t.meta == revkit::infer::Meta::float_);
            revkit::inputs::refine_demangled_this(f, is_float);
          }
    }
    if (!opt.dump_inputs.empty()) {
      std::ofstream dump(opt.dump_inputs, std::ios::binary);
      // As the decompiler is told them: storage assigned where it is dynamic.
      revkit::lift::DecompilerInputs resolved = revkit::lift::InputDecompiler(config).resolved_inputs();
      Json::Object doc = rklift::inputs_to_json(resolved, !exported).object();
      doc["synthesize_labels"] = synthesize_labels.value_or(!(analyzed && opt.own.labels));
      Json(std::move(doc)).write_document(dump);
      if (!dump) std::cerr << "rk-lift: cannot write " << opt.dump_inputs << "\n";
    }
    if (!opt.signatures.empty() &&
        !write_signatures(opt, config, functions, lang.language, signature_no_return, signature_stats))
      return 1;
  }
  if (opt.decompile) {
    config.in_order = opt.in_order;
    config.limits.timeout_seconds = opt.timeout;
    config.limits.max_varnodes = opt.max_varnodes;
    config.memory_budget = opt.memory_budget_mb << 20;
    std::vector<std::uint64_t> entries;
    for (const revkit::lift::Function &f : functions)
      if (opt.only.empty() || std::find(opt.only.begin(), opt.only.end(), f.entry) != opt.only.end())
        entries.push_back(f.entry);
    reset_peak_rss();
    const std::uint64_t decompile_start_rss = phase_peak_rss_bytes();
    // The C text goes to a scratch file as each function is done (a large
    // program's is hundreds of megabytes) and is read back when written.
    spill.reset(std::tmpfile());
    if (!spill) {
      std::cerr << "rk-lift: cannot create a scratch file\n";
      return 1;
    }
    revkit::decompd::PoolOptions pool = revkit::decompd::default_pool_options();
    if (opt.in_process) pool.in_process = true;
    std::vector<revkit::lift::DecompileResult> results = revkit::decompd::decompile_functions(
        config, entries, &dstats,
        [&](std::size_t, revkit::lift::DecompileResult &r) {
          if (!r.ok) return;
          const long at = std::ftell(spill.get());
          std::fwrite(r.c.data(), 1, r.c.size(), spill.get());
          spilled[r.entry] = {at, r.c.size()};
        },
        pool);
    std::fflush(spill.get());
    decompile_peak_rss = phase_peak_rss_bytes();
    decompile_base_rss = decompile_start_rss;
    std::size_t failed = 0;
    for (const revkit::lift::DecompileResult &r : results) decompile_ms_sum += r.milliseconds;
    std::vector<const revkit::lift::DecompileResult *> by_time;
    for (const revkit::lift::DecompileResult &r : results) by_time.push_back(&r);
    std::sort(by_time.begin(), by_time.end(), [](auto *a, auto *b) { return a->milliseconds > b->milliseconds; });
    for (std::size_t k = 0; k < std::min<std::size_t>(10, by_time.size()); ++k)
      slowest.push_back(Json::Array{hex(by_time[k]->entry), static_cast<std::uint64_t>(by_time[k]->milliseconds),
                                    static_cast<std::uint64_t>(by_time[k]->varnodes)});
    std::sort(by_time.begin(), by_time.end(), [](auto *a, auto *b) { return a->varnodes > b->varnodes; });
    for (std::size_t k = 0; k < std::min<std::size_t>(10, by_time.size()); ++k)
      largest.push_back(Json::Array{hex(by_time[k]->entry), static_cast<std::uint64_t>(by_time[k]->varnodes),
                                    static_cast<std::uint64_t>(by_time[k]->milliseconds)});
    for (revkit::lift::DecompileResult &r : results) {
      if (!r.ok) std::cerr << "rk-lift: " << hex(r.entry) << ": " << r.error << "\n", ++failed;
      for (const std::string &e : r.input_errors) std::cerr << "rk-lift: " << hex(r.entry) << ": input: " << e << "\n";
    }
    for (const std::string &w : dstats.warnings) std::cerr << "rk-lift: inputs: " << w << "\n";
    if (failed != 0) std::cerr << "rk-lift: " << failed << " of " << results.size() << " functions did not decompile\n";
    std::cerr << "rk-lift: " << revkit::decompd::failure_summary(dstats.failures);
    if (!opt.failure_bundles.empty() && !dstats.failures.empty()) {
      std::error_code ec;
      std::filesystem::create_directories(opt.failure_bundles, ec);
      for (const revkit::decompd::Failure &f : dstats.failures) {
        auto it = dstats.failed_bundles.find(f.bundle_hash);
        if (it == dstats.failed_bundles.end()) continue;
        const std::string path = opt.failure_bundles + "/" + hex(f.function) + ".bundle";
        std::ofstream out(path, std::ios::binary);
        out << it->second;
        if (!out) std::cerr << "rk-lift: cannot write " << path << "\n";
      }
    }
  }
  const double decompile_done_s = seconds(started);

  std::ofstream file;
  std::ostream *os = &std::cout;
  if (!opt.output.empty()) {
    file.open(opt.output, std::ios::binary);
    if (!file) {
      std::cerr << "rk-lift: cannot write " << opt.output << "\n";
      return 1;
    }
    os = &file;
  }

  // The document in key order (binary, format_version, functions,
  // instructions, memory, producer), each array element written as soon as
  // it is made.
  rklift::DocumentWriter w(*os);
  w.field("binary", Json::Object{
                        {"path", opt.name},
                        {"sha256", rklift::sha256_hex(*image->file)},
                        {"language", lang.language},
                        {"compiler", lang.compiler},
                        {"image_base", hex(image->image_base)},
                    });
  w.field("format_version", 1);
  w.begin_array("functions");
  for (const revkit::lift::Function &f : functions) {
    Json::Array body;
    for (const auto &[first, last] : f.body) body.push_back(Json::Array{hex(first), hex(last)});
    Json::Object fo{{"entry", hex(f.entry)}, {"name", f.name}, {"body", std::move(body)}};
    if (thumb_entries.contains(f.entry)) fo.emplace("thumb", true);
    if (auto it = spilled.find(f.entry); it != spilled.end()) {
      std::string c(it->second.second, '\0');
      if (std::fseek(spill.get(), it->second.first, SEEK_SET) != 0 ||
          std::fread(c.data(), 1, c.size(), spill.get()) != c.size()) {
        std::cerr << "rk-lift: cannot read back decompiled C\n";
        return 1;
      }
      fo.emplace("decompiled_c", std::move(c));
    }
    w.element() += Json(std::move(fo)).compact();
  }
  w.end_array();
  std::size_t lifted = 0;
  if (opt.instructions) {
    w.begin_array("instructions");
    std::size_t missing = 0;
    if (starts_exact) {
      // Nothing changed the context, so every engine decodes as the first
      // pass did.
      missing = write_instructions(w, starts, lifters);
      lifted = starts.size() - missing;
    } else {
      revkit::lift::Lifter again(image, lang.language);
      for (const revkit::lift::ContextRegion &c : revkit::lift::image_context(*image))
        again.set_context(c.name, c.value, c.start, c.end);
      for (const auto &[first, last] : thumb_ranges) again.set_context(isa_context, 1, first, last + 1);
      std::map<std::uint64_t, std::string> lines;
      starts = walk_bodies(*image, again.alignment(), functions, [&](std::uint64_t a, bool delay) {
        std::optional<revkit::lift::InstructionExtent> e;
        if (std::optional<revkit::lift::Instruction> insn = again.lift(a, delay)) {
          e = revkit::lift::InstructionExtent{insn->length, insn->delay_slot};
          append_instruction(lines[a], *insn);
        }
        return e;
      });
      for (auto &[a, line] : lines) {
        w.element() += line;
        std::string().swap(line);
      }
      lifted = lines.size();
    }
    if (missing != 0) std::cerr << "rk-lift: " << missing << " instructions did not decode a second time\n";
    w.end_array();
  }
  w.begin_array("memory");
  for (const revkit::loader::Block &b : image->blocks) {
    // Blocks in other memory spaces as the reference format has them:
    // offsets in the space, and its name.
    const revkit::loader::SpaceOffset so = revkit::loader::split_key(*image, b.start);
    Json::Object block{
        {"name", b.name},
        {"start", hex(so.offset)},
        {"end", hex(so.offset + (b.size - 1))},
        {"perms", b.perms.str()},
    };
    if (so.space != nullptr) block.emplace("space", so.space->name);
    w.element() += Json(std::move(block)).compact();
  }
  w.end_array();
  w.field("producer", "revkit-" + std::string(revkit::runtime::git_sha()));
  const bool written = w.finish();
  const double total_s = seconds(started);

  if (!opt.stats.empty()) {
    std::ofstream st(opt.stats);
    st << Json(Json::Object{
                   {"binary", opt.name},
                   {"functions", static_cast<std::uint64_t>(functions.size())},
                   {"instructions", static_cast<std::uint64_t>(lifted)},
                   {"decompiled", static_cast<std::uint64_t>(opt.decompile ? functions.size() : 0)},
                   {"threads", dstats.threads},
                   {"read_inputs_s", read_s},
                   {"functions_s", discover_s},
                   {"measure_s", measure_s - discover_s},
                   {"decompile_setup_s", dstats.setup_seconds},
                   {"decompile_s", dstats.total_seconds},
                   {"decompile_function_s", decompile_ms_sum / 1000},
                   {"slowest_ms", std::move(slowest)},
                   {"largest_varnodes", std::move(largest)},
                   {"decompile_stopped", static_cast<std::uint64_t>(dstats.stopped)},
                   {"decompile_max_varnodes", static_cast<std::uint64_t>(dstats.max_varnodes)},
                   {"decompile_peak_rss_bytes", decompile_peak_rss},
                   {"decompile_start_rss_bytes", decompile_base_rss},
                   {"memory_budget_bytes", static_cast<std::uint64_t>(opt.memory_budget_mb << 20)},
                   {"timeout_s", opt.timeout},
                   {"decompile_bundles", static_cast<std::uint64_t>(dstats.bundles)},
                   {"decompile_reruns", static_cast<std::uint64_t>(dstats.reruns)},
                   {"decompile_missed_functions", static_cast<std::uint64_t>(dstats.missed)},
                   {"decompile_miss_queries", static_cast<std::uint64_t>(dstats.miss_queries)},
                   {"decompile_unresolved", static_cast<std::uint64_t>(dstats.unresolved)},
                   {"decompile_unresolved_functions", [&] {
                      Json::Array a;
                      for (std::uint64_t e : dstats.unresolved_functions) a.push_back(hex(e));
                      return Json(std::move(a));
                    }()},
                   {"decompile_miss_kinds", [&] {
                      Json::Object o;
                      const char *names[] = {"", "address", "code_label", "type", "chunk", "entry", "function", "import"};
                      for (std::size_t i = 1; i < 8; ++i)
                        if (dstats.miss_kinds[i] != 0) o.emplace(names[i], static_cast<std::uint64_t>(dstats.miss_kinds[i]));
                      return Json(std::move(o));
                    }()},
                   {"decompile_bundle_bytes", static_cast<std::uint64_t>(dstats.bundle_bytes)},
                   {"decompile_build_s", dstats.build_ms / 1000},
                   {"decompile_ipc_s", dstats.ipc_ms / 1000},
                   {"decompile_worker_run_s", dstats.run_ms / 1000},
                   {"decompile_workers_spawned", static_cast<std::uint64_t>(dstats.pool.spawned)},
                   {"decompile_workers_recycled", static_cast<std::uint64_t>(dstats.pool.recycled)},
                   {"decompile_peak_workers_rss_bytes", static_cast<std::uint64_t>(dstats.peak_workers_rss)},
                   {"decompile_peak_total_rss_bytes", static_cast<std::uint64_t>(dstats.peak_total_rss)},
                   {"decompile_evicted", static_cast<std::uint64_t>(dstats.evicted)},
                   {"decompile_failures", [&] {
                      Json::Array a;
                      for (const revkit::decompd::Failure &f : dstats.failures)
                        a.push_back(Json::Object{{"function", hex(f.function)},
                                                 {"kind", std::string(revkit::decompd::failure_kind_name(f.kind))},
                                                 {"detail", f.detail},
                                                 {"bundle", f.bundle_hash},
                                                 {"decompiler_build", f.decompiler_build}});
                      return Json(std::move(a));
                    }()},
                   {"param_id", Json::Object{
                                    {"enabled", param_id_plan.has_value()},
                                    {"functions", static_cast<std::uint64_t>(param_id_stats.functions)},
                                    {"decompiled", static_cast<std::uint64_t>(param_id_stats.decompiled)},
                                    {"committed", static_cast<std::uint64_t>(param_id_stats.committed)},
                                    {"failed", static_cast<std::uint64_t>(param_id_stats.failed)},
                                    {"skipped", static_cast<std::uint64_t>(param_id_stats.skipped)},
                                    {"rounds", static_cast<std::uint64_t>(param_id_stats.rounds)},
                                    {"wall_s", param_id_seconds},
                                    {"worker_run_s", param_id_stats.run_ms / 1000},
                                }},
                   {"signatures", Json(signature_stats)},
                   {"write_s", total_s - decompile_done_s},
                   {"total_s", total_s},
                   {"peak_rss_bytes", peak_rss_bytes()},
               })
              .compact()
       << "\n";
  }
  return written ? 0 : 1;
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-lift")) return 0;
  auto opt = parse_args(argc, argv);
  if (!opt) {
    usage(std::cerr);
    return 2;
  }
  auto ghidra = revkit::runtime::find_ghidra(opt->ghidra_root, "rk-lift");
  if (!ghidra) return 1;
  opt->ghidra_root = ghidra->string();
  try {
    if (opt->detect) return rklift::run_detect(opt->file, opt->ghidra_root, opt->threads.value_or(8), opt->detect_features);
    return run(*opt);
  } catch (const revkit::loader::LoadError &e) {
    std::cerr << "rk-lift: " << opt->file << ": " << e.what() << "\n";
  } catch (const revkit::lift::LiftError &e) {
    std::cerr << "rk-lift: " << e.what() << "\n";
  } catch (const rklift::JsonError &e) {
    std::cerr << "rk-lift: " << e.what() << "\n";
  }
  return 1;
}
