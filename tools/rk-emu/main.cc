// rk-emu: run a binary's machine code in revkit's p-code emulator.
//
//   rk-emu [options] <binary>
//
// Prints what the program wrote to stdout and stderr (as it runs to the
// end), then a summary on stderr: why it stopped, the steps and the
// registers. --trace writes the trace as JSON (docs/emulator.md).
#include "revkit/emu/emulator.hh"
#include "revkit/emu/machine.hh"
#include "revkit/infer/library.h"
#include "revkit/lift/context.hh"
#include "revkit/runtime/runtime.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"
#include "revkit/plugins/host.h"
#include "revkit/plugins/peripheral.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifndef REVKIT_DEFAULT_GHIDRA_ROOT
#define REVKIT_DEFAULT_GHIDRA_ROOT ""
#endif

namespace {

struct Options {
  std::string file;
  std::string ghidra_root;
  std::optional<std::string> language;
  std::optional<std::uint64_t> base;
  bool file_base = false;
  bool raw = false;
  revkit::loader::RawOptions raw_options;
  std::string entry;
  std::string mode = "auto";
  std::vector<std::string> args;
  std::uint64_t steps = 1000000;
  std::vector<std::string> breaks;
  std::optional<std::string> until;
  std::vector<std::pair<std::string, std::string>> regs;
  std::vector<std::pair<std::string, std::string>> mems;
  std::vector<std::string> watches;
  std::vector<std::pair<std::string, std::string>> mmio_values;
  std::string trace_path;
  std::size_t trace_capacity = 4096;
  std::size_t trace_entries = 0;
  bool trace_memory = true;
  std::optional<std::string> stdin_path;
  std::uint64_t import_return = 0;
  bool stubs = true;
  bool unknown_syscalls_fail = false;
  std::uint64_t max_memory_mb = 1024;
  double timeout = 0;
  bool quiet = false;
  bool step_print = false;
  bool pcode = false;
  std::string machine_path;
  std::string input;
  std::vector<std::string> break_on;
  bool events = false;
  std::string derive_path;
  std::vector<std::string> plugin_dirs;
  std::map<std::string, std::set<revkit::plugins::Capability>> plugin_grants;
};

void usage(std::ostream &os) {
  os << "usage: rk-emu [options] <binary>\n"
        "  --entry <addr|symbol>   where to start (default: the entry point; a raw image's --raw-entry)\n"
        "  --mode auto|process|call|bare  how to start (auto: a Linux process at an ELF's entry point,\n"
        "                          a call elsewhere, bare for raw images)\n"
        "  --arg <value>           an argument for --mode call (repeatable)\n"
        "  --steps <N>             stop after N instructions (default 1000000)\n"
        "  --break <addr|symbol>   stop there (repeatable)\n"
        "  --until <addr|symbol>   stop on reaching it\n"
        "  --reg <name>=<value>    set a register before running (repeatable)\n"
        "  --mem <addr>=<hexbytes> write memory before running (repeatable)\n"
        "  --watch <addr>:<size>[:r|w|rw]  stop after an access (repeatable)\n"
        "  --mmio <addr>=<value>   what reads of MMIO at addr return (repeatable; default: the last write)\n"
        "  --trace <out.json>      write the trace\n"
        "  --trace-capacity <N>    steps kept in the trace (default 4096; the summary counts all)\n"
        "  --trace-entries <N>     write only the last N entries (default: all kept)\n"
        "  --no-trace-memory       leave memory accesses out of the trace\n"
        "  --stdin <file>          what the program reads from stdin\n"
        "  --import-return <value> what skipped import calls return (default 0)\n"
        "  --no-stubs              no built-in C library stubs (every import call is skipped)\n"
        "  --enosys                unknown system calls return -ENOSYS instead of stopping\n"
        "  --max-memory <MB>       bound on the emulator's memory (default 1024)\n"
        "  --timeout <seconds>     stop after this long\n"
        "  --print-steps           print each instruction as it runs (to stderr)\n"
        "  --print-pcode           the same, with each instruction's p-code\n"
        "  --quiet                 no summary\n"
        "  --machine <board.json>  run on a machine: memory, peripherals, interrupts (docs/firmware-emulation.md);\n"
        "                          a raw file loads as the machine's image says\n"
        "  --input <text>          bytes for the console UART (after --stdin's; \\n escapes)\n"
        "  --break-on <kinds>      stop when the CPU takes these exceptions (irq,fiq,swi,svc,systick,any,irq:4,...)\n"
        "  --events                print the exceptions taken\n"
        "  --derive-machine <out.json>  write a starter machine for the (raw) file: its regions, MMIO\n"
        "                          where trial runs fault, auto-ack registers for polling loops; then exit\n"
        "  --plugin-dir <dir>      load peripheral plugins (\"plugin:NAME\" kinds) from dir (repeatable)\n"
        "  --plugin-grant <name>=<cap>[,<cap>]  grant a plugin a capability (bus: the machine's memory)\n"
        "  --ghidra <root>         Ghidra install (default: $GHIDRA_INSTALL_DIR, ~/.config/revkit/revkit.conf,\n"
        "                          the bundled specs, ~/ghidra*, /opt/ghidra*; docs/getting-started.md)\n"
        "  --version               print the version and exit\n"
        "  --lang <id>             proc:endian:size:variant[:compiler] (default: from the file)\n"
        "  --base <hex>            load at this image base\n"
        "  --file-base             keep the file's own base (default: Ghidra's, 0x100000 for 64-bit PIE)\n"
        "  --raw                   load <binary> as a flat binary at --base (default 0); needs --lang\n"
        "  --raw-offset <hex>  --raw-length <hex>  --raw-perms <rwx>  --raw-entry <hex>\n"
        "  --region <name:start:size[:perms][:init|uninit|volatile]>  another memory region (RAM, MMIO)\n"
        "Exit status: 0 when the emulation ran (whatever stopped it), 1 on a load error, 2 on bad\n"
        "options, 3 when it stopped on a fault (unmapped, decode, unimplemented, userop, syscall, ...).\n";
}

std::optional<std::uint64_t> parse_number(const std::string &s) {
  if (s.empty()) return std::nullopt;
  char *end = nullptr;
  errno = 0;
  const bool neg = s[0] == '-';
  const std::string body = neg ? s.substr(1) : s;
  std::uint64_t v = std::strtoull(body.c_str(), &end, 0);
  if (errno != 0 || end != body.c_str() + body.size()) return std::nullopt;
  return neg ? ~v + 1 : v;
}

std::optional<std::uint64_t> parse_hex(const std::string &s) {
  std::string t = s;
  if (t.rfind("0x", 0) != 0 && t.rfind("0X", 0) != 0) t = "0x" + t;
  return parse_number(t);
}

bool parse_args(int argc, char **argv, Options &opt) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    auto value = [&]() -> const char * {
      if (i + 1 >= argc) {
        std::cerr << "rk-emu: " << arg << " needs a value\n";
        return nullptr;
      }
      return argv[++i];
    };
    auto pair = [&](std::vector<std::pair<std::string, std::string>> &out) {
      const char *v = value();
      if (!v) return false;
      std::string s = v;
      auto eq = s.find('=');
      if (eq == std::string::npos) {
        std::cerr << "rk-emu: " << arg << " wants <x>=<y>, not " << s << "\n";
        return false;
      }
      out.emplace_back(s.substr(0, eq), s.substr(eq + 1));
      return true;
    };
    const char *v = nullptr;
    if (arg == "-h" || arg == "--help") {
      usage(std::cout);
      std::exit(0);
    } else if (arg == "--entry" && (v = value())) opt.entry = v;
    else if (arg == "--mode" && (v = value())) opt.mode = v;
    else if (arg == "--arg" && (v = value())) opt.args.push_back(v);
    else if (arg == "--steps" && (v = value())) {
      auto n = parse_number(v);
      if (!n) return std::cerr << "rk-emu: bad --steps\n", false;
      opt.steps = *n;
    } else if (arg == "--break" && (v = value())) opt.breaks.push_back(v);
    else if (arg == "--until" && (v = value())) opt.until = v;
    else if (arg == "--reg") {
      if (!pair(opt.regs)) return false;
    } else if (arg == "--mem") {
      if (!pair(opt.mems)) return false;
    } else if (arg == "--mmio") {
      if (!pair(opt.mmio_values)) return false;
    } else if (arg == "--watch" && (v = value())) opt.watches.push_back(v);
    else if (arg == "--trace" && (v = value())) opt.trace_path = v;
    else if ((arg == "--trace-capacity" || arg == "--trace-entries") && (v = value())) {
      auto n = parse_number(v);
      if (!n) return std::cerr << "rk-emu: bad " << arg << "\n", false;
      (arg == "--trace-capacity" ? opt.trace_capacity : opt.trace_entries) = *n;
    } else if (arg == "--no-trace-memory") opt.trace_memory = false;
    else if (arg == "--stdin" && (v = value())) opt.stdin_path = v;
    else if (arg == "--import-return" && (v = value())) {
      auto n = parse_number(v);
      if (!n) return std::cerr << "rk-emu: bad --import-return\n", false;
      opt.import_return = *n;
    } else if (arg == "--no-stubs") opt.stubs = false;
    else if (arg == "--enosys") opt.unknown_syscalls_fail = true;
    else if (arg == "--max-memory" && (v = value())) {
      auto n = parse_number(v);
      if (!n) return std::cerr << "rk-emu: bad --max-memory\n", false;
      opt.max_memory_mb = *n;
    } else if (arg == "--timeout" && (v = value())) opt.timeout = std::atof(v);
    else if (arg == "--print-steps") opt.step_print = true;
    else if (arg == "--print-pcode") opt.step_print = opt.pcode = true;
    else if (arg == "--quiet") opt.quiet = true;
    else if (arg == "--machine" && (v = value())) opt.machine_path = v;
    else if (arg == "--input" && (v = value())) {
      std::string in = v;
      for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 1 < in.size()) {
          const char c = in[++i];
          opt.input.push_back(c == 'n' ? '\n' : c == 'r' ? '\r' : c == 't' ? '\t' : c);
        } else {
          opt.input.push_back(in[i]);
        }
      }
    } else if (arg == "--break-on" && (v = value())) {
      std::istringstream in(v);
      std::string k;
      while (std::getline(in, k, ',')) if (!k.empty()) opt.break_on.push_back(k);
    } else if (arg == "--events") opt.events = true;
    else if (arg == "--plugin-dir" && (v = value())) opt.plugin_dirs.emplace_back(v);
    else if (arg == "--derive-machine" && (v = value())) opt.derive_path = v;
    else if (arg == "--plugin-grant" && (v = value())) {
      std::string g = v;
      const auto eq = g.find('=');
      if (eq == std::string::npos || eq == 0) return std::cerr << "rk-emu: --plugin-grant takes name=capability[,capability]\n", false;
      std::istringstream in(g.substr(eq + 1));
      std::string c;
      while (std::getline(in, c, ',')) {
        auto cap = revkit::plugins::capability_from_string(c);
        if (!cap) return std::cerr << "rk-emu: unknown capability \"" << c << "\"\n", false;
        opt.plugin_grants[g.substr(0, eq)].insert(*cap);
      }
    }
    else if (arg == "--ghidra" && (v = value())) opt.ghidra_root = v;
    else if (arg == "--lang" && (v = value())) opt.language = v;
    else if (arg == "--file-base") opt.file_base = true;
    else if (arg == "--base" && (v = value())) {
      auto n = parse_hex(v);
      if (!n) return std::cerr << "rk-emu: bad --base\n", false;
      opt.base = *n;
    } else if (arg == "--raw") opt.raw = true;
    else if ((arg == "--raw-offset" || arg == "--raw-length" || arg == "--raw-entry") && (v = value())) {
      auto n = parse_hex(v);
      if (!n) return std::cerr << "rk-emu: bad " << arg << "\n", false;
      if (arg == "--raw-offset") opt.raw_options.offset = *n;
      else if (arg == "--raw-length") opt.raw_options.length = *n;
      else opt.raw_options.entry = *n;
    } else if (arg == "--raw-perms" && (v = value())) {
      std::string p = v;
      if (p.size() != 3) return std::cerr << "rk-emu: bad --raw-perms: " << p << "\n", false;
      opt.raw_options.perms = {p[0] == 'r', p[1] == 'w', p[2] == 'x'};
    } else if (arg == "--region" && (v = value())) {
      try {
        opt.raw_options.regions.push_back(revkit::loader::parse_raw_region(v));
      } catch (const revkit::loader::LoadError &e) {
        std::cerr << "rk-emu: " << e.what() << "\n";
        return false;
      }
    } else if (!arg.empty() && arg[0] == '-') {
      if (v == nullptr && (arg == "--entry" || arg == "--mode")) return false;
      std::cerr << "rk-emu: unknown option " << arg << "\n";
      return false;
    } else if (opt.file.empty()) {
      opt.file = arg;
    } else {
      std::cerr << "rk-emu: more than one binary\n";
      return false;
    }
  }
  if (opt.file.empty()) {
    usage(std::cerr);
    return false;
  }
  if (opt.raw && !opt.language) {
    std::cerr << "rk-emu: --raw needs --lang\n";
    return false;
  }
  return true;
}

std::string hex(std::uint64_t v) {
  std::ostringstream o;
  o << "0x" << std::hex << v;
  return o.str();
}

// An address, or a symbol's (with its Thumb bit, which start() honours).
std::optional<std::uint64_t> resolve(const revkit::loader::Image &image, const std::string &s) {
  if (auto n = parse_number(s)) return n;
  for (const revkit::loader::Symbol &sym : image.symbols)
    if (sym.defined && sym.name == s) return sym.value;
  for (const revkit::loader::Export &e : image.exports)
    if (e.name == s) return e.address;
  return std::nullopt;
}

bool fault(revkit::emu::StopKind k) {
  using revkit::emu::StopKind;
  switch (k) {
    case StopKind::unmapped:
    case StopKind::protection:
    case StopKind::decode:
    case StopKind::unimplemented:
    case StopKind::userop:
    case StopKind::syscall:
    case StopKind::divide_by_zero:
    case StopKind::memory_limit:
    case StopKind::hook: return true;
    default: return false;
  }
}

int run(const Options &opt) {
  namespace emu = revkit::emu;
  std::shared_ptr<const revkit::loader::Image> image;
  revkit::lift::initialize(opt.ghidra_root);  // before loading: languages' memory spaces
  std::optional<emu::MachineSpec> spec;
  if (!opt.machine_path.empty()) {
    std::ifstream in(opt.machine_path, std::ios::binary);
    if (!in) {
      std::cerr << "rk-emu: cannot read " << opt.machine_path << "\n";
      return 2;
    }
    const std::string text((std::istreambuf_iterator<char>(in)), {});
    try {
      spec = emu::parse_machine(text);
    } catch (const emu::MachineError &e) {
      std::cerr << "rk-emu: " << opt.machine_path << ":" << e.what() << "\n";
      return 2;
    }
    if (opt.language) spec->language = *opt.language;
  }
  try {
    revkit::loader::LoadOptions load_opts;
    load_opts.image_base = opt.base;
    load_opts.ghidra_image_base = !opt.file_base;
    bool raw_file = opt.raw;
    if (spec && !opt.raw) {
      // A file the ELF and PE loaders take loads as itself; anything else is
      // the machine's raw image.
      try {
        image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_file(opt.file, load_opts));
      } catch (const revkit::loader::LoadError &) {
        raw_file = true;
      }
      if (raw_file) {
        if (spec->language.empty()) {
          std::cerr << "rk-emu: the machine has no language (give one there or with --lang)\n";
          return 2;
        }
        const auto size = std::filesystem::file_size(opt.file);
        revkit::loader::RawOptions raw = emu::machine_raw_options(*spec, size);
        image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_raw_file(opt.file, raw));
      }
    } else if (opt.raw) {
      revkit::loader::RawOptions raw = opt.raw_options;
      raw.language = *opt.language;
      raw.base = opt.base.value_or(0);
      image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_raw_file(opt.file, raw));
    } else {
      image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_file(opt.file, load_opts));
    }
  } catch (const revkit::loader::LoadError &e) {
    std::cerr << "rk-emu: " << e.what() << "\n";
    return 1;
  } catch (const emu::MachineError &e) {
    std::cerr << "rk-emu: " << e.what() << "\n";
    return 2;
  }
  for (const std::string &w : image->warnings) std::cerr << "rk-emu: warning: " << w << "\n";

  emu::Options eo;
  if (opt.language) eo.language = *opt.language;
  else if (spec && !spec->language.empty()) eo.language = spec->language;
  eo.max_memory = opt.max_memory_mb << 20;
  eo.trace_capacity = opt.trace_path.empty() && !opt.step_print ? 0 : opt.trace_capacity;
  if (opt.step_print && eo.trace_capacity == 0) eo.trace_capacity = 1;
  eo.trace_memory = opt.trace_memory;
  eo.import_return = opt.import_return;
  eo.library_stubs = opt.stubs;
  eo.unknown_syscalls_fail = opt.unknown_syscalls_fail;
  eo.argv = {std::filesystem::path(opt.file).filename().string()};
  if (opt.stdin_path) {
    std::ifstream in(*opt.stdin_path, std::ios::binary);
    if (!in) {
      std::cerr << "rk-emu: cannot read " << *opt.stdin_path << "\n";
      return 2;
    }
    eo.stdin_data.assign(std::istreambuf_iterator<char>(in), {});
  }
  eo.stdin_data += opt.input;
  const bool pe32 = image->format == revkit::loader::Format::pe && image->bits == 32;
  eo.prototypes = [image, pe32](std::string_view name) -> std::optional<emu::ImportPrototype> {
    auto p = revkit::infer::library_prototype(*image, name);
    if (!p) return std::nullopt;
    emu::ImportPrototype out;
    out.returns_value = !p->ret.is_void();
    out.parameters = static_cast<std::uint32_t>(p->params.size());
    out.varargs = p->varargs;
    out.callee_pops = pe32 && !p->varargs;  // WINAPI
    return out;
  };

  if (!opt.derive_path.empty()) {
    std::optional<emu::ImageSpec> is;
    if (opt.raw) {
      emu::ImageSpec x;
      x.load = opt.base.value_or(0);
      x.offset = opt.raw_options.offset;
      x.length = opt.raw_options.length;
      x.perms = opt.raw_options.perms;
      is = x;
    }
    emu::DeriveOptions dopt;
    dopt.trial_steps = opt.steps;
    if (opt.timeout > 0)
      dopt.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(static_cast<long>(opt.timeout * 1000));
    try {
      const emu::DerivedMachine d = emu::derive_machine(image, eo.language.empty() ? std::string() : eo.language, {}, is, dopt);
      std::ofstream out(opt.derive_path, std::ios::binary);
      out << d.json;
      if (!out) {
        std::cerr << "rk-emu: cannot write " << opt.derive_path << "\n";
        return 1;
      }
      for (const std::string &n : d.notes) std::cerr << "rk-emu: " << n << "\n";
    } catch (const std::exception &e) {
      std::cerr << "rk-emu: " << e.what() << "\n";
      return 1;
    }
    return 0;
  }

  std::unique_ptr<revkit::plugins::Host> plugin_host;  // outlives the machine
  std::unique_ptr<emu::Emulator> machine;
  try {
    machine = std::make_unique<emu::Emulator>(image, eo);
  } catch (const std::exception &e) {
    std::cerr << "rk-emu: " << e.what() << "\n";
    return 1;
  }
  emu::Emulator &m = *machine;

  std::uint64_t entry = 0;
  if (spec) {
    try {
      if (!opt.entry.empty()) {
        auto e = resolve(*image, opt.entry);
        if (!e) {
          std::cerr << "rk-emu: no symbol or address " << opt.entry << "\n";
          return 2;
        }
        spec->entry = *e;
      }
      for (const std::string &b : opt.break_on) spec->break_on.push_back(b);
      emu::MachineOptions mo;
      if (!opt.plugin_dirs.empty()) {
        revkit::plugins::HostOptions ho;
        ho.grants = opt.plugin_grants;
        plugin_host = std::make_unique<revkit::plugins::Host>(ho);
        for (const std::string &d : opt.plugin_dirs)
          for (const auto &r : plugin_host->load_dir(d)) std::cerr << "rk-emu: plugin " << r.path.string() << ": " << r.error << "\n";
        mo.factory = revkit::plugins::peripheral_factory(*plugin_host);
      }
      m.attach_machine(*spec, mo);
    } catch (const emu::EmuError &e) {
      std::cerr << "rk-emu: " << e.what() << "\n";
      return 2;
    }
  } else if (!opt.entry.empty()) {
    auto e = resolve(*image, opt.entry);
    if (!e) {
      std::cerr << "rk-emu: no symbol or address " << opt.entry << "\n";
      return 2;
    }
    entry = *e;
  } else if (image->entry) {
    entry = *image->entry;
  } else if (opt.raw) {
    entry = opt.base.value_or(0);
  } else {
    std::cerr << "rk-emu: the file has no entry point; use --entry\n";
    return 2;
  }
  emu::StartMode mode = emu::StartMode::automatic;
  if (opt.mode == "process") mode = emu::StartMode::process;
  else if (opt.mode == "call") mode = emu::StartMode::call;
  else if (opt.mode == "bare") mode = emu::StartMode::bare;
  else if (opt.mode != "auto") {
    std::cerr << "rk-emu: bad --mode " << opt.mode << "\n";
    return 2;
  }
  std::vector<std::uint64_t> args;
  for (const std::string &a : opt.args) {
    auto n = resolve(*image, a);
    if (!n) {
      std::cerr << "rk-emu: bad --arg " << a << "\n";
      return 2;
    }
    args.push_back(*n);
  }
  try {
    if (!spec) m.start(entry, mode, args);
    for (const auto &[name, value] : opt.regs) {
      auto v = parse_number(value);
      if (!v) {
        std::cerr << "rk-emu: bad value for register " << name << ": " << value << "\n";
        return 2;
      }
      if (!m.find_register(name)) {
        std::cerr << "rk-emu: unknown register " << name << "\n";
        return 2;
      }
      m.write_register(name, *v);
    }
    for (const auto &[addr, bytes] : opt.mems) {
      auto a = resolve(*image, addr);
      std::vector<std::uint8_t> data;
      for (std::size_t i = 0; i + 1 < bytes.size() + 1 && i < bytes.size(); i += 2)
        data.push_back(static_cast<std::uint8_t>(std::strtoul(bytes.substr(i, 2).c_str(), nullptr, 16)));
      if (!a || bytes.size() % 2 != 0 || !m.write_memory(*a, data)) {
        std::cerr << "rk-emu: bad --mem " << addr << "=" << bytes << " (unmapped, or not hex bytes)\n";
        return 2;
      }
    }
  } catch (const emu::EmuError &e) {
    std::cerr << "rk-emu: " << e.what() << "\n";
    return 2;
  }
  for (const std::string &b : opt.breaks) {
    auto a = resolve(*image, b);
    if (!a) {
      std::cerr << "rk-emu: no symbol or address " << b << "\n";
      return 2;
    }
    m.add_breakpoint(*a & ~std::uint64_t{image->machine == 40 ? 1u : 0u});
  }
  for (const std::string &w : opt.watches) {
    std::istringstream in(w);
    std::string addr, size, mode_s = "rw";
    std::getline(in, addr, ':');
    std::getline(in, size, ':');
    std::getline(in, mode_s, ':');
    auto a = resolve(*image, addr);
    auto n = parse_number(size);
    if (!a || !n || *n == 0) {
      std::cerr << "rk-emu: bad --watch " << w << "\n";
      return 2;
    }
    m.add_watchpoint(*a, *n, mode_s.find('r') != std::string::npos, mode_s.find('w') != std::string::npos);
  }
  if (!opt.mmio_values.empty()) {
    std::map<std::uint64_t, std::uint64_t> values;
    for (const auto &[addr, value] : opt.mmio_values) {
      auto a = resolve(*image, addr);
      auto v = parse_number(value);
      if (!a || !v) {
        std::cerr << "rk-emu: bad --mmio " << addr << "=" << value << "\n";
        return 2;
      }
      values[*a] = *v;
    }
    m.on_mmio([values](emu::Emulator &, emu::MmioAccess &a) {
      if (a.write) return;
      if (auto it = values.find(a.address); it != values.end()) a.value = it->second;
    });
  }

  emu::RunOptions ro;
  ro.max_steps = opt.steps;
  if (opt.until) {
    auto a = resolve(*image, *opt.until);
    if (!a) {
      std::cerr << "rk-emu: no symbol or address " << *opt.until << "\n";
      return 2;
    }
    ro.until = *a;
  }
  if (opt.timeout > 0)
    ro.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(static_cast<long>(opt.timeout * 1000));
  emu::Stop stop;
  if (opt.step_print) {
    std::uint64_t done = 0;
    while (done < ro.max_steps) {
      if (opt.pcode) std::cerr << m.disassemble(m.pc(), true) << "\n";
      stop = m.step();
      if (!m.trace().entries().empty()) {
        const emu::TraceEntry &e = m.trace().entries().back();
        std::cerr << std::setw(8) << e.index << "  " << hex(e.pc) << "  " << e.text;
        for (const emu::RegisterWrite &w : e.registers) std::cerr << "  " << w.name << "=" << emu::hex_value(w.value);
        if (!e.event.empty()) std::cerr << "  ; " << e.event;
        std::cerr << "\n";
      }
      ++done;
      if (stop.kind != emu::StopKind::stepped) break;
      if (m.breakpoints().count(m.pc()) != 0 || (ro.until && m.pc() == *ro.until)) break;
    }
  } else {
    stop = m.run(ro);
  }
  std::cout << m.stdout_data() << std::flush;
  std::cerr << m.stderr_data();

  if (!opt.trace_path.empty()) {
    std::ofstream out(opt.trace_path, std::ios::binary);
    out << emu::trace_json(m, opt.trace_entries);
    if (!out) {
      std::cerr << "rk-emu: cannot write " << opt.trace_path << "\n";
      return 1;
    }
  }
  if (!opt.quiet) {
    const emu::Stop &s = m.last_stop();
    std::cerr << "rk-emu: stopped (" << emu::to_string(s.kind) << ") at " << hex(s.pc) << " after " << m.steps()
              << " steps";
    if (!s.detail.empty()) std::cerr << ": " << s.detail;
    std::cerr << "\n";
    int col = 0;
    for (const std::string &name : m.display_registers()) {
      std::cerr << "  " << std::setw(9) << std::left << name << std::setw(18) << emu::hex_value(m.read_register_bytes(name))
                << std::right;
      if (++col % 4 == 0) std::cerr << "\n";
    }
    if (col % 4 != 0) std::cerr << "\n";
    if (const emu::Machine *mc = m.machine()) {
      const emu::MachineState ms = mc->state();
      std::cerr << "  machine: " << ms.cpu << " in " << ms.mode << ", tick " << mc->now() << ", " << mc->event_count()
                << " exceptions taken" << (ms.waiting ? ", waiting for an interrupt" : "") << "\n";
      for (const auto &d : ms.devices)
        if (!d.state.empty()) std::cerr << "    " << d.name << " (" << d.kind << "): " << d.state << "\n";
      for (const std::string &l : ms.log) std::cerr << "    " << l << "\n";
      if (opt.events)
        for (const emu::ExceptionEvent &ev : mc->events()) {
          std::cerr << "    step " << ev.step << " tick " << ev.tick << ": " << ev.kind;
          if (ev.number >= 0) std::cerr << " " << ev.number;
          std::cerr << " at " << hex(ev.pc) << " -> " << hex(ev.handler);
          if (!ev.source.empty()) std::cerr << " (" << ev.source << ")";
          if (!ev.detail.empty()) std::cerr << " " << ev.detail;
          std::cerr << "\n";
        }
    }
    const emu::TraceSummary &t = m.trace().summary();
    std::cerr << "  memory: " << t.memory_reads << " reads, " << t.memory_writes << " writes; mmio: " << t.mmio_reads
              << " reads, " << t.mmio_writes << " writes; syscalls " << t.syscalls << ", stubs " << t.stub_calls
              << "; " << t.unique_pcs << " distinct pcs\n";
  }
  return fault(m.last_stop().kind) ? 3 : 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-emu")) return 0;
  Options opt;
  if (!parse_args(argc, argv, opt)) return 2;
  auto ghidra = revkit::runtime::find_ghidra(opt.ghidra_root, "rk-emu");
  if (!ghidra) return 1;
  opt.ghidra_root = ghidra->string();
  try {
    return run(opt);
  } catch (const std::exception &e) {
    std::cerr << "rk-emu: " << e.what() << "\n";
    return 1;
  }
}
