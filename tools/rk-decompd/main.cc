// rk-decompd: Ghidra's decompiler over self-contained bundles.
//
//   rk-decompd --bundle FILE [options]   decompile one bundle in this process
//                                        and print its output (C, tokens or
//                                        an observation): the repro for a
//                                        failure, and what decompiler patch
//                                        regression tests run
//   rk-decompd --info FILE [-v]          the bundle's header and sizes (-v: its
//                                        answers, types and chunks)
//   rk-decompd --worker [--fd N]         serve a WorkerPool on fd N (default 3);
//                                        started by revkit, not by hand
//
// Options: --ghidra ROOT (default: found as revkit::runtime says),
// --timeout S (cooperative, default none), --max-varnodes N, -o FILE (write
// the output there), --quiet (no output, status only).
//
// Exit status for --bundle: 0 decompiled; 1 the decompiler reported an
// error or stopped over its limits; 2 bad usage or an unreadable bundle;
// 4 the bundle lacked answers the decompiler asked for (listed on stderr;
// the output is then what a worker would have given before the parent
// added them). A crash ends the process with its signal, as in a worker.

#include "revkit/decompd/batch.h"
#include "revkit/decompd/bundle.h"
#include "revkit/decompd/pool.h"
#include "revkit/decompd/runner.h"
#include "revkit/lift/lifter.hh"
#include "revkit/runtime/runtime.h"

#ifdef REVKIT_DECOMPD_BACKEND
#include "revkit/backend/decompd_mode.h"
#endif
#ifdef REVKIT_DECOMPD_INFER
#include "revkit/infer/decompd_mode.h"
#endif

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace {

void usage() {
  std::cerr << "usage: rk-decompd --bundle FILE [--timeout S] [--max-varnodes N] [-o FILE] [--quiet] [--ghidra ROOT]\n"
               "       rk-decompd --info FILE [-v]\n"
               "       rk-decompd --worker [--fd N] [--ghidra ROOT]\n"
               "       rk-decompd --version\n";
}

bool read_file(const std::string &path, std::string &out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  std::ostringstream s;
  s << f.rdbuf();
  out = s.str();
  return true;
}

const char *kind_name(revkit::decompd::Miss::Kind k) {
  using M = revkit::decompd::Miss;
  switch (k) {
    case M::address: return "address";
    case M::code_label: return "code label";
    case M::type: return "type";
    case M::chunk: return "bytes";
    case M::entry: return "function facts";
    case M::function: return "function";
    case M::import: return "import slot";
  }
  return "?";
}

}  // namespace

int main(int argc, char **argv) {
  namespace dd = revkit::decompd;
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-decompd")) return 0;
  std::string ghidra;
  std::string bundle_path, info_path, output;
  bool worker = false, quiet = false, verbose = false;
  int fd = 3;
  dd::Limits limits;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    const char *v = nullptr;
    if (a == "--worker") worker = true;
    else if (a == "--fd" && (v = value())) fd = std::atoi(v);
    else if (a == "--ghidra" && (v = value())) ghidra = v;
    else if (a == "--bundle" && (v = value())) bundle_path = v;
    else if (a == "--info" && (v = value())) info_path = v;
    else if (a == "--timeout" && (v = value())) limits.timeout_seconds = std::atof(v);
    else if (a == "--max-varnodes" && (v = value())) limits.max_varnodes = std::strtoull(v, nullptr, 10);
    else if (a == "-o" && (v = value())) output = v;
    else if (a == "--quiet") quiet = true;
    else if (a == "--verbose" || a == "-v") verbose = true;
    else {
      usage();
      return 2;
    }
  }
#ifdef REVKIT_DECOMPD_BACKEND
  revkit::backend::RegisterDecompdModes();
#endif
#ifdef REVKIT_DECOMPD_INFER
  revkit::infer::register_decompd_mode();
#endif
  if (!info_path.empty()) {
    std::string bytes;
    if (!read_file(info_path, bytes)) {
      std::cerr << "rk-decompd: cannot read " << info_path << "\n";
      return 2;
    }
    try {
      const dd::Bundle b = dd::decode_bundle(bytes);
      std::printf("hash      %s\nmode      %s\nlanguage  %s\nentry     0x%llx\nbytes     %zu (%zu chunks)\n",
                  dd::bundle_hash(bytes).c_str(), dd::mode_name(b.mode), b.language_id.c_str(),
                  static_cast<unsigned long long>(b.entry), bytes.size(), b.chunks.size());
      if (b.mode != dd::Mode::observe)
        std::printf("answers   %zu addresses, %zu code labels, %zu types, %zu functions, %zu data\n",
                    b.lift.addresses.size(), b.lift.code_labels.size(), b.lift.types.size(), b.lift.functions.size(),
                    b.lift.data.size());
      if (b.joins) std::printf("joins     %zu laid out first\n", b.joins->size());
      if (b.mode != dd::Mode::observe)
        std::printf("naming    default names %d, labels %d, extrapop %d; prefix \"%s\"\n", b.lift.default_names,
                    b.lift.default_labels, b.lift.default_extrapop, b.lift.address_prefix.c_str());
      if (verbose && b.mode != dd::Mode::observe) {
        for (const auto &[k, a] : b.lift.addresses) {
          std::printf("  %s%s0x%llx:", k.first.c_str(), k.first.empty() ? "" : ":", static_cast<unsigned long long>(k.second));
          if (a.starts >= 0) std::printf(" function %s", b.lift.functions[a.starts].name.c_str());
          if (a.contains >= 0)
            std::printf(" in %s [0x%llx,0x%llx]", b.lift.functions[a.contains].name.c_str(),
                        static_cast<unsigned long long>(a.body_first), static_cast<unsigned long long>(a.body_last));
          if (a.data >= 0) std::printf(" data %s", b.lift.data[a.data].name.c_str());
          if (a.external >= 0) std::printf(" external %s", b.lift.externals[a.external].label.c_str());
          if (a.label >= 0) std::printf(" label %s", b.lift.labels[a.label].name.c_str());
          if (a.block) std::printf(" block %d", static_cast<int>(*a.block));
          std::printf("\n");
        }
        for (const auto &[k, l] : b.lift.code_labels)
          std::printf("  code label 0x%llx: %s\n", static_cast<unsigned long long>(k.second), l ? l->c_str() : "-");
        for (const auto &[id, t] : b.lift.types) std::printf("  type 0x%llx%s\n", static_cast<unsigned long long>(id), t.empty() ? " (none)" : "");
        for (const auto &[i, c] : b.chunks) std::printf("  chunk 0x%llx\n", static_cast<unsigned long long>(i * dd::kChunk));
        for (const auto &c : b.lift.comments)
          std::printf("  comment 0x%llx %d %s\n", static_cast<unsigned long long>(c.addr), static_cast<int>(c.kind), c.text.c_str());
        for (const auto &[a, k] : b.lift.flow_overrides)
          std::printf("  flow override 0x%llx %s\n", static_cast<unsigned long long>(a), k.c_str());
        for (const auto &t : b.lift.tracked)
          std::printf("  tracked %s%s:0x%llx = 0x%llx\n", t.register_name.c_str(), t.reg.space.c_str(),
                      static_cast<unsigned long long>(t.reg.offset), static_cast<unsigned long long>(t.value));
        for (const auto &bl : b.lift.blocks)
          std::printf("  block %s%s [0x%llx,0x%llx] %s%s\n", bl.space.c_str(), bl.name.c_str(),
                      static_cast<unsigned long long>(bl.start), static_cast<unsigned long long>(bl.end),
                      bl.write ? "w" : "-", bl.is_volatile ? "v" : "");
      }
    } catch (const std::exception &e) {
      std::cerr << "rk-decompd: " << info_path << ": " << e.what() << "\n";
      return 2;
    }
    return 0;
  }
  if (!worker && bundle_path.empty()) {
    usage();
    return 2;
  }
  auto root = revkit::runtime::find_ghidra(ghidra, "rk-decompd");
  if (!root) return 2;
  try {
    revkit::lift::initialize(*root);
  } catch (const std::exception &e) {
    std::cerr << "rk-decompd: " << e.what() << "\n";
    return 2;
  }
  if (worker) return dd::serve(fd);

  std::string bytes;
  if (!read_file(bundle_path, bytes)) {
    std::cerr << "rk-decompd: cannot read " << bundle_path << "\n";
    return 2;
  }
  dd::Bundle b;
  try {
    b = dd::decode_bundle(bytes);
  } catch (const std::exception &e) {
    std::cerr << "rk-decompd: " << bundle_path << ": " << e.what() << "\n";
    return 2;
  }
  dd::Runner runner;
  dd::RunResult r = runner.run(b, limits);
  if (!r.ran) {
    std::cerr << "rk-decompd: " << r.error << "\n";
    return 2;
  }
  bool ok = false;
  const std::string text = dd::print_payload(b.mode, r.payload, ok);
  if (!quiet) {
    if (output.empty()) {
      std::cout << text;
    } else {
      std::ofstream out(output, std::ios::binary);
      out << text;
    }
  }
  std::fprintf(stderr, "rk-decompd: %s 0x%llx %s in %.0f ms, %llu varnodes\n", dd::mode_name(b.mode),
               static_cast<unsigned long long>(b.entry), ok ? "decompiled" : "failed", r.milliseconds,
               static_cast<unsigned long long>(r.varnodes));
  if (verbose)
    for (const auto &[sp, a] : r.asked) std::fprintf(stderr, "asked %s %llx\n", sp.c_str(), static_cast<unsigned long long>(a));
  if (!r.misses.empty()) {
    for (const dd::Miss &m : r.misses)
      std::fprintf(stderr, "rk-decompd: missing %s %s%s0x%llx\n", kind_name(m.kind), m.space.c_str(),
                   m.space.empty() ? "" : ":", static_cast<unsigned long long>(m.value));
    return 4;
  }
  if (r.stopped != revkit::lift::DecompileStop::none || !ok) return 1;
  return 0;
}
