// rk-dbg: scripted debug sessions (revkit::debug, docs/debugger.md) over
// revkit's emulator, a GDB remote stub, or a process it launches.
//
//   rk-dbg [target] [options] <binary> [-- program arguments]
//
// Commands come from -c (repeatable), -x files, then standard input; each
// prints what a person would want to see, one fact per line, so scripts
// and tests can grep it. Addresses are the program's (as the listing shows
// them) unless written *0x... (the target's own).
#include "revkit/debug/emu_target.hh"
#include "revkit/debug/expr.hh"
#include "revkit/debug/gdb_remote.hh"
#include "revkit/debug/session.hh"
#include "revkit/runtime/runtime.h"
#include "revkit/infer/library.h"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef REVKIT_DEFAULT_GHIDRA_ROOT
#define REVKIT_DEFAULT_GHIDRA_ROOT ""
#endif

namespace {

namespace dbg = revkit::debug;
namespace fs = std::filesystem;

struct Options {
  std::string file;
  std::vector<std::string> args;
  std::string ghidra_root;
  std::optional<std::string> language;
  bool raw = false;
  revkit::loader::RawOptions raw_options;
  std::optional<std::uint64_t> base;
  bool file_base = false;
  // Target.
  std::string target = "emulate";  // emulate, remote, launch, attach, qemu-system
  std::string remote;
  std::int64_t pid = 0;
  std::string qemu;
  std::vector<std::string> qemu_system;  // binary then its arguments
  std::string entry;
  std::string mode = "auto";
  std::vector<std::string> emu_args;
  std::optional<std::int64_t> slide;
  std::size_t snapshots = 10000;
  bool stops_only = false;
  std::vector<std::string> commands;
  std::vector<std::string> scripts;
  bool echo = false;
  std::uint32_t timeout_ms = 10000;
};

void usage(std::ostream &os) {
  os << "usage: rk-dbg [target] [options] <binary> [-- program arguments]\n"
        "Targets (default --emulate):\n"
        "  --emulate                revkit's p-code emulator (--entry, --mode, --arg as rk-emu)\n"
        "  --remote <host:port|unix:/path>  a GDB remote stub: gdbserver, qemu -g/-gdb, OpenOCD, J-Link\n"
        "  --launch                 start <binary> under gdbserver (qemu-user for another machine)\n"
        "  --qemu <qemu-user>       --launch under this qemu-user binary\n"
        "  --attach <pid>           attach to a running process (gdbserver --attach)\n"
        "  --qemu-system <binary> <args...> --   boot under qemu-system with its gdbstub (firmware)\n"
        "Options:\n"
        "  -c <command>             run a command (repeatable; before -x files and stdin)\n"
        "  -x <file>                run commands from a file (repeatable)\n"
        "  --echo                   print each command before its output\n"
        "  --entry <addr|symbol>  --mode auto|process|call|bare  --arg <value>   (emulator)\n"
        "  --slide <offset>         runtime = program address + offset (default: found from the target)\n"
        "  --snapshots <N>          timeline bound (default 10000)\n"
        "  --stops-only             the emulator records stops only, not every instruction\n"
        "  --timeout <ms>           how long a command waits for a running target (default 10000)\n"
        "  --ghidra <root>  --lang <id>  --base <hex>  --file-base\n"
        "  --raw  --raw-offset <hex>  --raw-length <hex>  --raw-perms <rwx>  --raw-entry <hex>\n"
        "  --region <name:start:size[:perms][:init|uninit|volatile]>\n"
        "Commands:\n"
        "  break|hbreak <loc>       a breakpoint; <loc> is a symbol, sym+off, a program address, or *runtime\n"
        "  watch|rwatch|awatch <loc> [size]   a watchpoint\n"
        "  delete [id]  info breakpoints   break <loc> if <expr>   condition <id> [expr]   ignore <id> <n>\n"
        "  disable <id>  enable <id>\n"
        "  back (one instruction back)  rewind <snapshot>   (the emulator: continue from there)\n"
        "  continue|c  step|si  next|ni  finish  until <loc>   (wait [ms], interrupt)\n"
        "  regs [names...]  set <reg> <value>  x <loc> [length]  write <loc> <hexbytes>\n"
        "  bt [frames]      the call stack (CFI, frame pointers, a stack scan)\n"
        "  print|p <expr>   a C expression: $RAX + 8, *(int *)($RBP - 0x14), counter\n"
        "  display <expr>   print it at every stop (a watch); undisplay [n]\n"
        "  disas [loc] [n]  n instructions in target memory (default: at the pc)\n"
        "  threads  thread <id>  modules  maps  mapping  output\n"
        "  timeline [from] [count]  snap <n> [names...]  xs <n> <loc> [length]   (time travel)\n"
        "  save <file.rktrace>  json <file.json>  monitor <text>  kill  detach  quit\n"
        "Exit status: 0, or 1 when a command failed, 2 for bad options.\n";
}

std::optional<std::uint64_t> parse_number(const std::string &s) {
  if (s.empty()) return std::nullopt;
  char *end = nullptr;
  errno = 0;
  const bool neg = s[0] == '-';
  const std::string body = neg ? s.substr(1) : s;
  const std::uint64_t v = std::strtoull(body.c_str(), &end, 0);
  if (errno != 0 || end != body.c_str() + body.size()) return std::nullopt;
  return neg ? ~v + 1 : v;
}

std::optional<std::uint64_t> parse_hex(const std::string &s) {
  std::string t = s;
  if (t.rfind("0x", 0) != 0 && t.rfind("0X", 0) != 0) t = "0x" + t;
  return parse_number(t);
}

bool parse_args(int argc, char **argv, Options &o) {
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto value = [&]() -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "rk-dbg: " << a << " needs a value\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };
    std::optional<std::string> v;
    if (a == "-h" || a == "--help") {
      usage(std::cout);
      std::exit(0);
    } else if (a == "--") {
      for (++i; i < argc; ++i) o.args.emplace_back(argv[i]);
    } else if (a == "--emulate") o.target = "emulate";
    else if (a == "--launch") o.target = "launch";
    else if (a == "--remote" && (v = value())) {
      o.target = "remote";
      o.remote = *v;
    } else if (a == "--attach" && (v = value())) {
      o.target = "attach";
      auto n = parse_number(*v);
      if (!n) return std::cerr << "rk-dbg: bad --attach\n", false;
      o.pid = static_cast<std::int64_t>(*n);
    } else if (a == "--qemu" && (v = value())) o.qemu = *v;
    else if (a == "--qemu-system") {
      o.target = "qemu-system";
      for (++i; i < argc && std::string(argv[i]) != "--"; ++i) o.qemu_system.emplace_back(argv[i]);
      if (o.qemu_system.empty()) return std::cerr << "rk-dbg: --qemu-system needs a binary\n", false;
    } else if (a == "-c" && (v = value())) o.commands.push_back(*v);
    else if (a == "-x" && (v = value())) o.scripts.push_back(*v);
    else if (a == "--echo") o.echo = true;
    else if (a == "--entry" && (v = value())) o.entry = *v;
    else if (a == "--mode" && (v = value())) o.mode = *v;
    else if (a == "--arg" && (v = value())) o.emu_args.push_back(*v);
    else if (a == "--slide" && (v = value())) {
      auto n = parse_number(*v);
      if (!n) return std::cerr << "rk-dbg: bad --slide\n", false;
      o.slide = static_cast<std::int64_t>(*n);
    } else if (a == "--snapshots" && (v = value())) {
      auto n = parse_number(*v);
      if (!n || *n == 0) return std::cerr << "rk-dbg: bad --snapshots\n", false;
      o.snapshots = *n;
    } else if (a == "--stops-only") o.stops_only = true;
    else if (a == "--timeout" && (v = value())) {
      auto n = parse_number(*v);
      if (!n) return std::cerr << "rk-dbg: bad --timeout\n", false;
      o.timeout_ms = static_cast<std::uint32_t>(*n);
    } else if (a == "--ghidra" && (v = value())) o.ghidra_root = *v;
    else if (a == "--lang" && (v = value())) o.language = *v;
    else if (a == "--file-base") o.file_base = true;
    else if (a == "--base" && (v = value())) {
      auto n = parse_hex(*v);
      if (!n) return std::cerr << "rk-dbg: bad --base\n", false;
      o.base = *n;
    } else if (a == "--raw") o.raw = true;
    else if ((a == "--raw-offset" || a == "--raw-length" || a == "--raw-entry") && (v = value())) {
      auto n = parse_hex(*v);
      if (!n) return std::cerr << "rk-dbg: bad " << a << "\n", false;
      if (a == "--raw-offset") o.raw_options.offset = *n;
      else if (a == "--raw-length") o.raw_options.length = *n;
      else o.raw_options.entry = *n;
    } else if (a == "--raw-perms" && (v = value())) {
      if (v->size() != 3) return std::cerr << "rk-dbg: bad --raw-perms\n", false;
      o.raw_options.perms = {(*v)[0] == 'r', (*v)[1] == 'w', (*v)[2] == 'x'};
    } else if (a == "--region" && (v = value())) {
      try {
        o.raw_options.regions.push_back(revkit::loader::parse_raw_region(*v));
      } catch (const revkit::loader::LoadError &e) {
        std::cerr << "rk-dbg: " << e.what() << "\n";
        return false;
      }
    } else if (!a.empty() && a[0] == '-') {
      if (!v && (a == "--remote" || a == "--attach" || a == "-c" || a == "-x")) return false;
      std::cerr << "rk-dbg: unknown option " << a << "\n";
      return false;
    } else if (o.file.empty()) {
      o.file = a;
    } else {
      std::cerr << "rk-dbg: more than one binary (program arguments go after --)\n";
      return false;
    }
  }
  if (o.file.empty()) {
    usage(std::cerr);
    return false;
  }
  if (o.raw && !o.language) return std::cerr << "rk-dbg: --raw needs --lang\n", false;
  return true;
}

std::string hexs(std::uint64_t v) { return dbg::hex(v); }

std::string hex_value(const std::vector<std::uint8_t> &v) {
  std::ostringstream o;
  o << "0x" << std::hex << std::setfill('0');
  bool started = false;
  for (std::size_t i = v.size(); i-- > 0;) {
    if (!started && v[i] == 0 && i > 0) continue;
    o << std::setw(started ? 2 : 1) << static_cast<unsigned>(v[i]);
    started = true;
  }
  return o.str();
}

std::vector<std::string> split(const std::string &line) {
  std::istringstream in(line);
  std::vector<std::string> out;
  std::string w;
  while (in >> w) out.push_back(w);
  return out;
}

class Cli {
 public:
  Cli(dbg::Session &s, std::shared_ptr<const revkit::loader::Image> image, const Options &o)
      : s_(s), image_(std::move(image)), o_(o) {
    // Breakpoint conditions, as `print` evaluates (an error stops).
    s_.set_condition_check([this](const dbg::Breakpoint &b, std::string &error) {
      try {
        return truth(b.condition);
      } catch (const dbg::DebugError &e) {
        error = e.what();
        return true;
      }
    });
  }
  ~Cli() { s_.set_condition_check(nullptr); }

  // False if the command failed.
  bool run(const std::string &line) {
    const auto w = split(line);
    if (w.empty() || w[0][0] == '#') return true;
    if (o_.echo) std::cout << "(rk-dbg) " << line << "\n";
    try {
      return dispatch(w);
    } catch (const dbg::DebugError &e) {
      std::cout << "error: " << e.what() << "\n";
      return false;
    }
  }
  bool quit = false;

 private:
  // A location: symbol[+off], a program address, or *runtime.
  std::optional<std::pair<std::uint64_t, bool>> loc(const std::string &text) {
    if (!text.empty() && text[0] == '*') {
      auto n = parse_number(text.substr(1));
      if (!n) return std::nullopt;
      return std::make_pair(*n, false);
    }
    if (!text.empty() && text[0] == '$') {
      return std::make_pair(dbg::to_u64(s_.read_register(text.substr(1))), false);
    }
    if (auto n = parse_number(text)) return std::make_pair(*n, true);
    std::string name = text;
    std::uint64_t off = 0;
    if (auto plus = text.find('+'); plus != std::string::npos) {
      auto n = parse_number(text.substr(plus + 1));
      if (!n) return std::nullopt;
      off = *n;
      name = text.substr(0, plus);
    }
    for (const revkit::loader::Symbol &sym : image_->symbols)
      if (sym.defined && sym.name == name) return std::make_pair(sym.value + off, true);
    for (const revkit::loader::Export &e : image_->exports)
      if (e.name == name) return std::make_pair(e.address + off, true);
    return std::nullopt;
  }
  std::uint64_t runtime(const std::pair<std::uint64_t, bool> &l) {
    if (!l.second) return l.first;
    if (!s_.mapping().known) throw dbg::DebugError("the program isn't mapped yet (" + s_.mapping().how + ")");
    return s_.to_runtime(l.first);
  }
  // "0x555555555149 (main+0x4) [program 0x101149]"
  std::string where(std::uint64_t pc) {
    std::string out = hexs(pc);
    if (auto p = s_.to_program(pc)) {
      const revkit::loader::Symbol *best = nullptr;
      for (const revkit::loader::Symbol &sym : image_->symbols)
        if (sym.defined && sym.type == revkit::loader::SymbolType::func && sym.value <= *p &&
            (best == nullptr || sym.value > best->value) && (*p - sym.value) < (sym.size != 0 ? sym.size : 0x1000))
          best = &sym;
      if (best != nullptr) out += " (" + best->name + (*p != best->value ? "+" + hexs(*p - best->value) : "") + ")";
      if (*p != pc) out += " [program " + hexs(*p) + "]";
    }
    return out;
  }
  std::vector<std::string> displays_;
  void show_displays() {
    for (std::size_t i = 0; i < displays_.size(); ++i) {
      std::cout << i + 1 << ": " << displays_[i] << " = ";
      try {
        std::cout << print(displays_[i]) << "\n";
      } catch (const dbg::DebugError &e) {
        std::cout << "<" << e.what() << ">\n";
      }
    }
  }
  void print_stop(const dbg::Stop &st) {
    std::cout << "stopped: " << dbg::to_string(st.kind);
    if (st.kind == dbg::StopKind::exited) std::cout << " status " << st.exit_code;
    else if (st.kind != dbg::StopKind::running && s_.target().state() == dbg::TargetState::stopped)
      std::cout << " at " << where(s_.target().pc());
    if (st.address) std::cout << " address " << hexs(*st.address);
    if (!st.detail.empty()) std::cout << " (" << st.detail << ")";
    std::cout << "\n";
    const std::string &out = s_.output();
    if (s_.output_size() > printed_) {
      const std::uint64_t kept_from = s_.output_size() - out.size();
      const std::uint64_t from = std::max(printed_, kept_from);
      std::cout << "output: " << out.substr(static_cast<std::size_t>(from - kept_from));
      if (out.empty() || out.back() != '\n') std::cout << "\n";
      printed_ = s_.output_size();
    }
    if (st.kind != dbg::StopKind::exited && st.kind != dbg::StopKind::running && s_.target().state() == dbg::TargetState::stopped)
      show_displays();
  }
  dbg::ResumeOptions within() const {
    dbg::ResumeOptions r;
    r.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(o_.timeout_ms);
    r.max_steps = 50000000;
    return r;
  }
  bool resume(dbg::RunMode mode, std::optional<std::uint64_t> until = std::nullopt) {
    auto r = within();
    r.until = until;
    const dbg::Stop st = s_.resume(mode, r);
    print_stop(st);
    return true;
  }
  void regs(const std::vector<std::string> &names, std::optional<std::uint64_t> snap = std::nullopt) {
    std::map<std::string, std::vector<std::uint8_t>> recorded;
    if (snap) recorded = s_.timeline().registers_at(*snap);
    auto show = [&](const std::string &n) {
      std::vector<std::uint8_t> v;
      if (snap) {
        auto it = recorded.find(n);
        if (it == recorded.end()) return;
        v = it->second;
      } else {
        try {
          v = s_.read_register(n);
        } catch (const dbg::DebugError &) {
          return;
        }
      }
      std::cout << n << " = " << hex_value(v) << "\n";
    };
    if (!names.empty()) {
      for (const std::string &n : names) {
        const dbg::RegisterDesc *d = s_.target().find_register(n);
        if (d == nullptr) throw dbg::DebugError("no register " + n);
        show(d->name);
      }
      return;
    }
    for (const dbg::RegisterDesc &d : s_.target().registers())
      if (d.display) show(d.name);
  }
  void dump(std::uint64_t at, const std::vector<std::uint8_t> &data, const std::vector<bool> &unknown) {
    for (std::size_t row = 0; row < data.size(); row += 16) {
      std::cout << hexs(at + row) << ":";
      for (std::size_t i = row; i < std::min(row + 16, data.size()); ++i) {
        if (unknown[i]) std::cout << " ??";
        else std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(data[i]) << std::dec;
      }
      std::cout << "\n";
    }
  }
  // An expression's value now: registers, the image's symbols (typeless:
  // their addresses), memory, C's built-in types.
  bool truth(const std::string &text) {
    namespace ex = dbg::expr;
    ex::Context c;
    ex::Value v = value(text, c);
    try {
      return ex::truthy(v, c.big_endian);
    } catch (const ex::ExprError &e) {
      throw dbg::DebugError(e.what());
    }
  }
  std::string print(const std::string &text) {
    namespace ex = dbg::expr;
    ex::Context c;
    ex::Value v = value(text, c);
    const ex::Formatted f = ex::format(v, c);
    return f.hex.empty() || f.hex == f.text ? f.text : f.text + " (" + f.hex + ")";
  }
  dbg::expr::Value value(const std::string &text, dbg::expr::Context &c) {
    namespace ex = dbg::expr;
    c.pointer_size = image_->bits / 8 ? image_->bits / 8 : 8;
    c.big_endian = s_.options().language.find(":BE:") != std::string::npos;
    c.read = [this](std::uint64_t a, std::span<std::uint8_t> out) {
      std::vector<dbg::ByteRange> holes;
      try {
        s_.read_memory(a, out, &holes);
      } catch (const dbg::DebugError &) {
        return std::size_t{0};
      }
      std::size_t n = out.size();
      for (const auto &h : holes) n = std::min<std::size_t>(n, h.offset);
      return n;
    };
    c.symbolize = [this](std::uint64_t a) {
      std::string w = where(a);
      auto open = w.find(" (");
      return open == std::string::npos ? std::string() : w.substr(open + 2, w.find(')', open) - open - 2);
    };
    c.lookup = [this, &c](const std::string &name, bool reg_only) -> std::optional<ex::Value> {
      if (const dbg::RegisterDesc *d = s_.target().find_register(name)) {
        ex::Value v;
        v.reg = d->name;
        try {
          v.bytes = s_.read_register(d->name);
        } catch (const dbg::DebugError &e) {
          v.unknown = e.what();
        }
        v.type = ex::undefined(v.bytes.empty() ? d->size : v.bytes.size());
        return v;
      }
      if (reg_only) return std::nullopt;
      for (const revkit::loader::Symbol &sym : image_->symbols)
        if (sym.defined && sym.name == name) {
          ex::Value v;
          v.type = ex::undefined(c.pointer_size);
          v.bytes = dbg::from_u64(s_.to_runtime(sym.value), c.pointer_size);
          if (c.big_endian) std::reverse(v.bytes.begin(), v.bytes.end());
          return v;
        }
      return std::nullopt;
    };
    ex::Value v;
    try {
      v = ex::Expression::parse(text).evaluate(c);
    } catch (const ex::ExprError &e) {
      throw dbg::DebugError(e.what());
    }
    if (!v.unknown.empty()) throw dbg::DebugError(v.unknown);
    return v;
  }

  static dbg::BreakKind kind_of(const std::string &cmd) {
    if (cmd == "hbreak") return dbg::BreakKind::hardware;
    if (cmd == "watch") return dbg::BreakKind::watch_write;
    if (cmd == "rwatch") return dbg::BreakKind::watch_read;
    if (cmd == "awatch") return dbg::BreakKind::watch_access;
    return dbg::BreakKind::software;
  }

  bool dispatch(const std::vector<std::string> &w) {
    const std::string &c = w[0];
    auto need = [&](std::size_t n) {
      if (w.size() < n + 1) throw dbg::DebugError(c + " needs " + std::to_string(n) + " argument" + (n > 1 ? "s" : ""));
    };
    auto need_loc = [&](const std::string &t) {
      auto l = loc(t);
      if (!l) throw dbg::DebugError("no symbol or address " + t);
      return *l;
    };
    if (c == "break" || c == "b" || c == "hbreak" || c == "watch" || c == "rwatch" || c == "awatch") {
      need(1);
      const auto l = need_loc(w[1]);
      std::uint32_t size = 0;
      if (w.size() > 2) size = static_cast<std::uint32_t>(parse_number(w[2]).value_or(0));
      if (size == 0 && c.find("watch") != std::string::npos) size = 4;
      // break <loc> [size] if <condition>
      std::string cond;
      for (std::size_t i = 2; i < w.size(); ++i)
        if (w[i] == "if") {
          for (std::size_t j = i + 1; j < w.size(); ++j) cond += (j > i + 1 ? " " : "") + w[j];
          if (i == 2) size = c.find("watch") != std::string::npos ? 4 : 0;
          break;
        }
      const dbg::Breakpoint &b = s_.add_breakpoint(kind_of(c == "b" ? "break" : c), l.first, l.second, size);
      if (!cond.empty()) s_.update_breakpoint(b.id, cond, std::nullopt, std::nullopt);
      std::cout << "breakpoint " << b.id << ": " << dbg::to_string(b.kind) << " at "
                << (b.pending ? "program " + hexs(*b.program_address) + " (pending)" : where(b.address));
      if (!b.error.empty()) std::cout << " (not inserted: " << b.error << ")";
      std::cout << "\n";
      return b.error.empty();
    }
    if (c == "delete" || c == "d") {
      if (w.size() == 1) s_.clear_breakpoints();
      else if (!s_.remove_breakpoint(static_cast<int>(parse_number(w[1]).value_or(0))))
        throw dbg::DebugError("no breakpoint " + w[1]);
      return true;
    }
    if (c == "info" && w.size() > 1 && (w[1] == "breakpoints" || w[1] == "b")) {
      for (const dbg::Breakpoint &b : s_.breakpoints())
        std::cout << b.id << " " << dbg::to_string(b.kind) << " " << (b.pending ? "pending" : where(b.address))
                  << " hits " << b.hits << (b.disabled ? " disabled" : b.inserted ? "" : " not inserted")
                  << (b.condition.empty() ? "" : " if " + b.condition) << (b.ignore_count ? " ignore " + std::to_string(b.ignore_count) : "")
                  << (b.condition_error.empty() ? "" : " (condition: " + b.condition_error + ")") << "\n";
      return true;
    }
    if (c == "info" && w.size() > 1 && (w[1] == "registers" || w[1] == "r")) {
      regs(std::vector<std::string>(w.begin() + 2, w.end()));
      return true;
    }
    if (c == "continue" || c == "c" || c == "run" || c == "r") return resume(dbg::RunMode::run);
    if (c == "step" || c == "si" || c == "s" || c == "stepi") return resume(dbg::RunMode::step_into);
    if (c == "next" || c == "ni" || c == "n" || c == "nexti") return resume(dbg::RunMode::step_over);
    if (c == "finish" || c == "fin") return resume(dbg::RunMode::step_out);
    if (c == "until" || c == "u" || c == "advance") {
      need(1);
      return resume(dbg::RunMode::run, runtime(need_loc(w[1])));
    }
    if (c == "wait") {
      const auto ms = w.size() > 1 ? parse_number(w[1]).value_or(o_.timeout_ms) : o_.timeout_ms;
      print_stop(s_.wait(std::chrono::steady_clock::now() + std::chrono::milliseconds(ms)));
      return true;
    }
    if (c == "interrupt") {
      s_.interrupt();
      print_stop(s_.wait(std::chrono::steady_clock::now() + std::chrono::milliseconds(o_.timeout_ms)));
      return true;
    }
    if (c == "regs" || c == "registers") {
      regs(std::vector<std::string>(w.begin() + 1, w.end()));
      return true;
    }
    if (c == "disas" || c == "disassemble" || c == "x/i") {
      // disas [loc] [count]: instructions in target memory (the pc's by default), in or out of the program.
      std::uint64_t at = s_.target().pc();
      if (w.size() > 1) at = runtime(need_loc(w[1]));
      const std::size_t n = w.size() > 2 ? parse_number(w[2]).value_or(10) : 10;
      for (std::size_t i = 0; i < n && i < 1000; ++i) {
        std::vector<std::uint8_t> bytes(32);
        std::vector<dbg::ByteRange> holes;
        s_.read_memory(at, bytes, &holes);
        std::size_t got = bytes.size();
        for (const auto &h : holes) got = std::min<std::size_t>(got, h.offset);
        bytes.resize(got);
        auto insn = s_.disassemble(at, bytes);
        std::cout << (at == s_.target().pc() ? "=> " : "   ") << where(at) << ":  ";
        if (!insn) {
          std::cout << (bytes.empty() ? "(not readable)" : "(bad)") << "\n";
          break;
        }
        std::cout << insn->text << "\n";
        at += insn->length + insn->delay_slot;
      }
      return true;
    }
    if (c == "back" || c == "rsi" || c == "reverse-stepi" || c == "rewind") {
      // back: one instruction back (the emulator); rewind <n>: to snapshot n, dropping the later ones.
      dbg::Stop st;
      if (c == "rewind") {
        need(1);
        st = s_.rewind(parse_number(w[1]).value_or(0));
      } else {
        st = s_.step_back();
      }
      std::cout << "back at snapshot " << s_.current_snapshot() << ": " << where(s_.target().pc()) << "\n";
      (void)st;
      return true;
    }
    if (c == "condition" || c == "ignore" || c == "disable" || c == "enable") {
      // condition <id> [expr] · ignore <id> <n> · disable|enable <id>
      need(1);
      const int id = static_cast<int>(parse_number(w[1]).value_or(0));
      std::string rest;
      for (std::size_t i = 2; i < w.size(); ++i) rest += (i > 2 ? " " : "") + w[i];
      bool ok = false;
      if (c == "condition") ok = s_.update_breakpoint(id, rest, std::nullopt, std::nullopt);
      else if (c == "ignore") {
        need(2);
        ok = s_.update_breakpoint(id, std::nullopt, parse_number(w[2]).value_or(0), std::nullopt);
      } else ok = s_.update_breakpoint(id, std::nullopt, std::nullopt, c == "disable");
      if (!ok) throw dbg::DebugError("no breakpoint " + w[1]);
      return true;
    }
    if (c == "display") {
      // display <expr>: printed at every stop (a watch); without one, each now.
      if (w.size() == 1) {
        show_displays();
        return true;
      }
      std::string text;
      for (std::size_t i = 1; i < w.size(); ++i) text += (i > 1 ? " " : "") + w[i];
      displays_.push_back(text);
      std::cout << displays_.size() << ": " << text << " = " << print(text) << "\n";
      return true;
    }
    if (c == "undisplay") {
      if (w.size() == 1) displays_.clear();
      else {
        const auto n = parse_number(w[1]).value_or(0);
        if (n == 0 || n > displays_.size()) throw dbg::DebugError("no display " + w[1]);
        displays_.erase(displays_.begin() + static_cast<std::ptrdiff_t>(n - 1));
      }
      return true;
    }
    if (c == "print" || c == "p") {
      // print <expr>: a C expression over registers, symbols and memory (docs/debugger.md "Expressions").
      need(1);
      std::string text;
      for (std::size_t i = 1; i < w.size(); ++i) text += (i > 1 ? " " : "") + w[i];
      std::cout << text << " = " << print(text) << "\n";
      return true;
    }
    if (c == "bt" || c == "backtrace" || c == "where") {
      // bt [N]: the call stack, at most N frames (docs/debugger.md "Call stack").
      dbg::Session::BacktraceOptions bo;
      if (w.size() > 1) bo.max_frames = static_cast<std::size_t>(parse_number(w[1]).value_or(64));
      const auto frames = s_.backtrace(bo);
      for (std::size_t i = 0; i < frames.size(); ++i)
        std::cout << "#" << i << "  " << where(frames[i].pc) << "  sp " << hexs(frames[i].sp) << "  (" << frames[i].how
                  << ")\n";
      return true;
    }
    if (c == "set") {
      need(2);
      const dbg::RegisterDesc *d = s_.target().find_register(w[1][0] == '$' ? w[1].substr(1) : w[1]);
      if (d == nullptr) throw dbg::DebugError("no register " + w[1]);
      auto v = parse_number(w[2]);
      if (!v) throw dbg::DebugError("not a number: " + w[2]);
      s_.write_register(d->name, dbg::from_u64(*v, d->size));
      std::cout << d->name << " = " << hex_value(s_.read_register(d->name)) << "\n";
      return true;
    }
    if (c == "x") {
      need(1);
      const std::uint64_t at = runtime(need_loc(w[1]));
      const std::size_t n = w.size() > 2 ? parse_number(w[2]).value_or(16) : 16;
      if (n > (1u << 20)) throw dbg::DebugError("at most 1 MiB");
      std::vector<std::uint8_t> data(n);
      std::vector<dbg::ByteRange> holes;
      s_.read_memory(at, data, &holes);
      std::vector<bool> unknown(n, false);
      for (const auto &h : holes)
        for (std::uint32_t i = 0; i < h.length; ++i) unknown[h.offset + i] = true;
      dump(at, data, unknown);
      return true;
    }
    if (c == "write") {
      need(2);
      const std::uint64_t at = runtime(need_loc(w[1]));
      auto bytes = dbg::RspClient::from_hex(w[2]);
      if (!bytes) throw dbg::DebugError("not hex bytes: " + w[2]);
      if (!s_.write_memory(at, *bytes)) throw dbg::DebugError("can't write at " + hexs(at));
      std::cout << "wrote " << bytes->size() << " bytes at " << hexs(at) << "\n";
      return true;
    }
    if (c == "threads") {
      for (const dbg::ThreadInfo &t : s_.target().threads())
        std::cout << (t.current ? "* " : "  ") << t.id << (t.name.empty() ? "" : " " + t.name)
                  << (t.pc ? " " + where(*t.pc) : "") << "\n";
      return true;
    }
    if (c == "thread") {
      need(1);
      s_.select_thread(w[1]);
      std::cout << "thread " << s_.target().current_thread() << " at " << where(s_.target().pc()) << "\n";
      return true;
    }
    if (c == "modules") {
      for (const dbg::ModuleInfo &m : s_.modules())
        std::cout << hexs(m.base) << " " << m.name << (m.size ? " size " + hexs(m.size) : "") << " bias "
                  << hexs(m.load_bias) << (m.main ? " main" : "") << "\n";
      return true;
    }
    if (c == "maps") {
      for (const dbg::MapRegion &r : s_.memory_map())
        std::cout << hexs(r.start) << "-" << hexs(r.start + r.size) << " " << r.perms << " " << r.kind << " " << r.name << "\n";
      return true;
    }
    if (c == "mapping") {
      const auto &m = s_.mapping();
      std::cout << "mapping: " << (m.known ? "known" : "unknown") << " slide " << (m.slide < 0 ? "-" : "")
                << hexs(static_cast<std::uint64_t>(m.slide < 0 ? -m.slide : m.slide)) << " (" << m.how << ")\n";
      return true;
    }
    if (c == "output") {
      std::cout << s_.output();
      printed_ = s_.output_size();
      return true;
    }
    if (c == "timeline") {
      const dbg::Timeline &t = s_.timeline();
      const std::uint64_t from = w.size() > 1 ? parse_number(w[1]).value_or(t.first()) : t.first();
      const std::uint64_t count = w.size() > 2 ? parse_number(w[2]).value_or(50) : 50;
      std::cout << "timeline: " << t.size() << " snapshots, " << t.first() << " to " << t.last() << ", dropped "
                << t.dropped() << "\n";
      std::uint64_t shown = 0;
      for (const dbg::Snapshot &snap : t.snapshots()) {
        if (snap.index < from) continue;
        if (shown++ >= count) break;
        std::cout << snap.index << " " << dbg::to_string(snap.kind) << " " << where(snap.pc);
        if (snap.kind == dbg::Snapshot::Kind::stop) std::cout << " " << dbg::to_string(snap.stop);
        if (!snap.text.empty()) std::cout << " | " << snap.text;
        const auto changed = t.changed_at(snap.index);
        if (!changed.empty()) {
          std::cout << " |";
          for (const std::string &n : changed) std::cout << " " << n;
        }
        std::cout << "\n";
      }
      return true;
    }
    if (c == "snap") {
      need(1);
      const auto n = parse_number(w[1]);
      const dbg::Snapshot *snap = n ? s_.timeline().find(*n) : nullptr;
      if (snap == nullptr) throw dbg::DebugError("no snapshot " + w[1]);
      std::cout << "snapshot " << snap->index << " " << dbg::to_string(snap->kind) << " at " << where(snap->pc) << "\n";
      regs(std::vector<std::string>(w.begin() + 2, w.end()), *n);
      return true;
    }
    if (c == "xs") {
      need(2);
      const auto n = parse_number(w[1]);
      if (!n || s_.timeline().find(*n) == nullptr) throw dbg::DebugError("no snapshot " + w[1]);
      const std::uint64_t at = runtime(need_loc(w[2]));
      const std::size_t len = w.size() > 3 ? parse_number(w[3]).value_or(16) : 16;
      if (len > (1u << 20)) throw dbg::DebugError("at most 1 MiB");
      std::vector<std::uint8_t> data(len);
      std::vector<dbg::Timeline::ByteState> state;
      s_.memory_at(*n, at, data, state);
      std::vector<bool> unknown(len);
      for (std::size_t i = 0; i < len; ++i) unknown[i] = state[i] == dbg::Timeline::ByteState::unknown;
      dump(at, data, unknown);
      return true;
    }
    if (c == "save" || c == "json") {
      need(1);
      dbg::TraceHeader h = s_.header(fs::path(w[1]).stem().string(), fs::path(o_.file).filename().string());
      try {
        h.modules = s_.modules();
      } catch (const dbg::DebugError &) {
      }
      std::ofstream out(w[1], std::ios::binary);
      out << (c == "save" ? s_.timeline().serialize(h) : s_.timeline().to_json(h));
      if (!out) throw dbg::DebugError("can't write " + w[1]);
      std::cout << "saved " << s_.timeline().size() << " snapshots to " << w[1] << "\n";
      return true;
    }
    if (c == "monitor") {
      auto *g = dynamic_cast<dbg::GdbRemoteTarget *>(&s_.target());
      if (g == nullptr) throw dbg::DebugError("monitor commands go to a GDB remote stub");
      std::string text;
      for (std::size_t i = 1; i < w.size(); ++i) text += (i > 1 ? " " : "") + w[i];
      std::cout << g->monitor(text);
      return true;
    }
    if (c == "kill") {
      s_.target().kill();
      std::cout << "killed\n";
      return true;
    }
    if (c == "detach") {
      s_.target().detach();
      std::cout << "detached\n";
      return true;
    }
    if (c == "quit" || c == "q" || c == "exit") {
      quit = true;
      return true;
    }
    throw dbg::DebugError("unknown command " + c + " (rk-dbg --help lists them)");
  }

  dbg::Session &s_;
  std::shared_ptr<const revkit::loader::Image> image_;
  const Options &o_;
  std::uint64_t printed_ = 0;
};

int run(const Options &o) {
  std::shared_ptr<const revkit::loader::Image> image;
  revkit::lift::initialize(o.ghidra_root);  // before loading: languages' memory spaces
  try {
    if (o.raw) {
      revkit::loader::RawOptions raw = o.raw_options;
      raw.language = *o.language;
      raw.base = o.base.value_or(0);
      image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_raw_file(o.file, raw));
    } else {
      revkit::loader::LoadOptions lo;
      lo.image_base = o.base;
      lo.ghidra_image_base = !o.file_base;
      image = std::make_shared<const revkit::loader::Image>(revkit::loader::load_file(o.file, lo));
    }
  } catch (const revkit::loader::LoadError &e) {
    std::cerr << "rk-dbg: " << e.what() << "\n";
    return 1;
  }
  std::string language;
  if (o.language) language = *o.language;
  else if (auto spec = revkit::loader::guess_language(*image)) language = spec->id();
  else {
    std::cerr << "rk-dbg: no language for " << o.file << "; give --lang\n";
    return 1;
  }
  const std::string name = fs::path(o.file).filename().string();

  dbg::SessionOptions so;
  so.image = image;
  so.program_name = name;
  so.language = language;
  so.timeline.max_snapshots = o.snapshots;
  so.record_steps = !o.stops_only;
  so.slide = o.slide;
  so.function_entry = [image](std::uint64_t a) -> std::optional<std::uint64_t> {
    std::optional<std::uint64_t> best;
    for (const revkit::loader::Symbol &s : image->symbols) {
      if (!s.defined || s.type != revkit::loader::SymbolType::func) continue;
      const std::uint64_t at = s.value & ~std::uint64_t{image->machine == 40 ? 1u : 0u};
      if (at <= a && (s.size == 0 || a < at + s.size) && (!best || at > *best)) best = at;
    }
    return best;
  };

  std::unique_ptr<dbg::Target> target;
  try {
    if (o.target == "emulate") {
      revkit::emu::Options eo;
      eo.language = language;
      eo.argv = {name};
      for (const std::string &a : o.args) eo.argv.push_back(a);
      const bool pe32 = image->format == revkit::loader::Format::pe && image->bits == 32;
      eo.prototypes = [image, pe32](std::string_view n) -> std::optional<revkit::emu::ImportPrototype> {
        auto p = revkit::infer::library_prototype(*image, n);
        if (!p) return std::nullopt;
        revkit::emu::ImportPrototype ip;
        ip.returns_value = !p->ret.is_void();
        ip.parameters = static_cast<std::uint32_t>(p->params.size());
        ip.varargs = p->varargs;
        ip.callee_pops = pe32 && !p->varargs;
        return ip;
      };
      auto e = std::make_unique<revkit::emu::Emulator>(image, eo);
      std::uint64_t entry = 0;
      if (!o.entry.empty()) {
        std::optional<std::uint64_t> at = parse_number(o.entry);
        if (!at)
          for (const revkit::loader::Symbol &s : image->symbols)
            if (s.defined && s.name == o.entry) at = s.value;
        if (!at) {
          std::cerr << "rk-dbg: no symbol or address " << o.entry << "\n";
          return 2;
        }
        entry = *at;
      } else if (image->entry) {
        entry = *image->entry;
      } else if (o.raw_options.entry) {
        entry = *o.raw_options.entry;
      }
      revkit::emu::StartMode mode = revkit::emu::StartMode::automatic;
      if (o.mode == "process") mode = revkit::emu::StartMode::process;
      else if (o.mode == "call") mode = revkit::emu::StartMode::call;
      else if (o.mode == "bare") mode = revkit::emu::StartMode::bare;
      std::vector<std::uint64_t> args;
      for (const std::string &a : o.emu_args) {
        auto n = parse_number(a);
        if (!n) {
          std::cerr << "rk-dbg: bad --arg " << a << "\n";
          return 2;
        }
        args.push_back(*n);
      }
      e->start(entry, mode, args);
      target = std::make_unique<dbg::EmulatorTarget>(std::move(e), name);
    } else {
      dbg::GdbRemoteOptions go;
      go.language = language;
      {
        revkit::lift::Lifter l(image, language);
        for (const revkit::lift::RegisterDef &r : l.registers()) go.sleigh_registers.push_back({r.name, r.size});
      }
      go.pointer_size = image->bits / 8;
      go.big_endian = image->endian == revkit::loader::Endian::big;
      std::unique_ptr<dbg::Transport> transport;
      if (o.target == "remote") {
        transport = dbg::connect_url(o.remote);
        go.description = "gdb remote " + o.remote;
      } else if (o.target == "qemu-system") {
        std::vector<std::string> args(o.qemu_system.begin() + 1, o.qemu_system.end());
        dbg::Launched l = dbg::launch_qemu_system(o.qemu_system[0], args);
        transport = std::move(l.transport);
        go.child = l.child;
        go.description = l.description;
      } else {
        dbg::LaunchOptions lo;
        lo.program = fs::absolute(o.file);
        lo.args = o.args;
        lo.qemu = o.qemu;
        if (o.target == "attach") lo.attach_pid = o.pid;
        dbg::Launched l = dbg::launch(lo);
        transport = std::move(l.transport);
        go.child = l.child;
        go.description = l.description;
      }
      try {
        target = std::make_unique<dbg::GdbRemoteTarget>(std::move(transport), go);
      } catch (const dbg::DebugError &e) {
        std::string out = go.child ? go.child->drain() : "";
        std::string msg = std::string(e.what()) + (out.empty() ? "" : " (" + out + ")");
        if (o.target == "attach" && !dbg::attach_hint().empty()) msg += "\n  " + dbg::attach_hint();
        throw dbg::DebugError(msg);
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "rk-dbg: " << e.what() << "\n";
    return 1;
  }

  dbg::Session session(std::move(target), so);
  std::cout << "target: " << session.target().description() << "\n";
  std::cout << "language: " << language << "\n";
  Cli cli(session, image, o);
  cli.run("mapping");
  std::cout << "at " << (session.target().state() == dbg::TargetState::stopped ? hexs(session.target().pc()) : "?") << "\n";
  bool ok = true;
  for (const std::string &c : o.commands) {
    if (cli.quit) break;
    ok = cli.run(c) && ok;
  }
  for (const std::string &f : o.scripts) {
    std::ifstream in(f);
    if (!in) {
      std::cerr << "rk-dbg: cannot read " << f << "\n";
      return 2;
    }
    std::string line;
    while (!cli.quit && std::getline(in, line)) ok = cli.run(line) && ok;
  }
  if (o.commands.empty() && o.scripts.empty()) {
    const bool tty = ::isatty(0) != 0;
    std::string line;
    while (!cli.quit) {
      if (tty) std::cout << "(rk-dbg) " << std::flush;
      if (!std::getline(std::cin, line)) break;
      ok = cli.run(line) && ok;
    }
  }
  return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char **argv) {
  if (revkit::runtime::print_version_if_asked(argc, argv, "rk-dbg")) return 0;
  Options o;
  if (!parse_args(argc, argv, o)) return 2;
  auto ghidra = revkit::runtime::find_ghidra(o.ghidra_root, "rk-dbg");
  if (!ghidra) return 1;
  o.ghidra_root = ghidra->string();
  return run(o);
}
