// Helpers for the debugger's tests: programs compiled for the test, loaded
// as the backend loads them (PIEs at Ghidra's base), and sessions over them.
#pragma once

#include "revkit/debug/emu_target.hh"
#include "revkit/debug/gdb_remote.hh"
#include "revkit/debug/session.hh"
#include "revkit/lift/lifter.hh"
#include "revkit/loader/load.hh"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace revkit::debug::testing {

namespace fs = std::filesystem;

inline bool ghidra_ready() {
  if (std::string(REVKIT_GHIDRA_ROOT).empty()) return false;
  lift::initialize(REVKIT_GHIDRA_ROOT);
  return true;
}

inline int run(const std::string &cmd) {
  const int rc = std::system(cmd.c_str());
  return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

// Compiles with `cmd` (where {out} is the output) into `out` atomically:
// ctest runs each test in its own process, and they share these files.
inline bool compile(const std::string &cmd, const fs::path &out) {
  // Built already (by another test process) from these sources: keep it,
  // so no running test's executable is replaced under it.
  std::error_code ec0;
  if (fs::exists(out, ec0)) {
    const auto built = fs::last_write_time(out, ec0);
    bool fresh = !ec0;
    std::istringstream words(cmd);
    for (std::string w; words >> w;)
      if (w.size() > 2 && w.compare(w.size() - 2, 2, ".c") == 0 && fs::exists(w) && fs::last_write_time(w) > built) fresh = false;
    if (fresh) return true;
  }
  const fs::path tmp = out.string() + ".tmp" + std::to_string(::getpid());
  std::string c = cmd;
  c.replace(c.find("{out}"), 5, tmp.string());
  if (run(c + " 2>/dev/null") != 0) return false;
  std::error_code ec;
  fs::rename(tmp, out, ec);
  return !ec;
}

inline fs::path out_dir() {
  fs::path d = fs::path(REVKIT_DEBUG_TEST_OUT);
  fs::create_directories(d);
  return d;
}

// A loaded program: the image, its language and its registers.
struct Program {
  fs::path path;
  std::shared_ptr<const loader::Image> image;
  std::string language;  // with the compiler
  std::vector<SleighRegister> sleigh;

  static Program load(const fs::path &p) {
    Program out;
    out.path = p;
    loader::LoadOptions lo;
    lo.ghidra_image_base = true;
    out.image = std::make_shared<const loader::Image>(loader::load_file(p, lo));
    auto spec = loader::guess_language(*out.image);
    if (!spec) throw std::runtime_error("no language for " + p.string());
    out.language = spec->id();
    lift::Lifter l(out.image, out.language);
    for (const lift::RegisterDef &r : l.registers()) out.sleigh.push_back({r.name, r.size});
    return out;
  }
  static Program raw(const fs::path &p, const loader::RawOptions &o) {
    Program out;
    out.path = p;
    out.image = std::make_shared<const loader::Image>(loader::load_raw_file(p, o));
    out.language = o.language;
    lift::Lifter l(out.image, out.language);
    for (const lift::RegisterDef &r : l.registers()) out.sleigh.push_back({r.name, r.size});
    return out;
  }
  std::uint64_t symbol(const std::string &name) const {
    for (const loader::Symbol &s : image->symbols)
      if (s.name == name && s.defined) return s.value;
    throw std::runtime_error("no symbol " + name);
  }
  std::uint64_t symbol_size(const std::string &name) const {
    for (const loader::Symbol &s : image->symbols)
      if (s.name == name && s.defined) return s.size;
    return 0;
  }
  GdbRemoteOptions remote_options() const {
    GdbRemoteOptions o;
    o.language = language;
    o.sleigh_registers = sleigh;
    o.pointer_size = image->bits / 8;
    o.big_endian = image->endian == loader::Endian::big;
    return o;
  }
  SessionOptions session_options() const {
    SessionOptions s;
    s.image = image;
    s.program_name = path.filename().string();
    s.language = language;
    // Function bounds from the symbol table (the backend uses its analysis).
    auto img = image;
    s.function_entry = [img](std::uint64_t a) -> std::optional<std::uint64_t> {
      for (const loader::Symbol &sym : img->symbols)
        if (sym.defined && sym.type == loader::SymbolType::func && a >= sym.value && a < sym.value + std::max<std::uint64_t>(sym.size, 1))
          return sym.value;
      return std::nullopt;
    };
    return s;
  }
};

// The program under gdbserver (or qemu-user for another machine).
inline std::unique_ptr<Session> launch_session(const Program &p, std::vector<std::string> args = {}) {
  LaunchOptions lo;
  lo.program = p.path;
  lo.args = std::move(args);
  Launched l = launch(lo);
  GdbRemoteOptions o = p.remote_options();
  o.child = l.child;
  o.description = l.description;
  std::unique_ptr<Target> t;
  try {
    t = std::make_unique<GdbRemoteTarget>(std::move(l.transport), o);
  } catch (const DebugError &e) {
    throw DebugError(std::string(e.what()) + "; output: " + (o.child ? o.child->drain() : ""));
  }
  return std::make_unique<Session>(std::move(t), p.session_options());
}

inline ResumeOptions within(int seconds) {
  ResumeOptions o;
  o.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  return o;
}

inline std::uint64_t reg(Session &s, const std::string &name) { return to_u64(s.read_register(name)); }

}  // namespace revkit::debug::testing
