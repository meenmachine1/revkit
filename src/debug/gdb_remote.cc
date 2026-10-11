#include "revkit/debug/gdb_remote.hh"

#include "xml.hh"

#include "revkit/emu/emulator.hh"

#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace revkit::debug {

namespace {

std::string lower(std::string_view s) {
  std::string out(s);
  for (char &c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string proc_of(const std::string &language) { return language.substr(0, language.find(':')); }

std::string hexnum(std::uint64_t v) {
  std::ostringstream o;
  o << std::hex << v;
  return o.str();
}

std::string sig2(int signal) {
  std::string s = hexnum(static_cast<std::uint64_t>(signal) & 0xff);
  return s.size() < 2 ? "0" + s : s;
}

std::optional<std::uint64_t> parse_hex(std::string_view s) {
  if (s.empty() || s.size() > 16) return std::nullopt;
  std::uint64_t v = 0;
  for (char c : s) {
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return std::nullopt;
    v = v << 4 | static_cast<std::uint64_t>(d);
  }
  return v;
}

const char *signal_name(int sig) {
  switch (sig) {
    case 1: return "SIGHUP";
    case 2: return "SIGINT";
    case 3: return "SIGQUIT";
    case 4: return "SIGILL";
    case 5: return "SIGTRAP";
    case 6: return "SIGABRT";
    case 7: return "SIGEMT";
    case 8: return "SIGFPE";
    case 9: return "SIGKILL";
    case 10: return "SIGBUS";
    case 11: return "SIGSEGV";
    case 12: return "SIGSYS";
    case 13: return "SIGPIPE";
    case 14: return "SIGALRM";
    case 15: return "SIGTERM";
    default: return nullptr;
  }
}

std::string signal_text(int sig) {
  const char *n = signal_name(sig);
  return n != nullptr ? std::string(n) : "signal " + std::to_string(sig);
}

// gdb's signal numbers (the protocol's) for the ones the stop kinds use.
constexpr int kSigInt = 2, kSigTrap = 5;

}  // namespace

// --- Register names ---

std::string map_register_name(const std::string &language, const std::string &stub_name, std::uint32_t size,
                              const std::vector<SleighRegister> &sleigh) {
  const std::string proc = proc_of(language);
  const bool x86_64 = proc == "x86" && language.find(":64:") != std::string::npos;
  std::string want = lower(stub_name);
  if (x86_64) {
    if (want == "eflags") want = "rflags";
    else if (want == "fs_base") want = "fs_offset";
    else if (want == "gs_base") want = "gs_offset";
    else if (want == "orig_rax") return "";
  } else if (proc == "x86") {
    if (want == "orig_eax") return "";
  } else if (proc == "AARCH64") {
    if (want.size() >= 2 && want[0] == 'v' && std::all_of(want.begin() + 1, want.end(), ::isdigit)) want = "q" + want.substr(1);
    if (want == "cpsr") return "";  // NZCV are the derived NG, ZR, CY, OV
  }
  for (const SleighRegister &r : sleigh)
    if (lower(r.name) == want && r.size >= size) return r.name;
  return "";
}

// --- The launched helper ---

ChildProcess::~ChildProcess() {
  if (pid > 0) {
    // Give it a moment to exit on its own (it does once the connection
    // closes), then make sure.
    for (int i = 0; i < 40; ++i) {
      int st = 0;
      if (::waitpid(pid, &st, WNOHANG) == pid) {
        pid = -1;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    if (pid > 0) {
      ::kill(-pid, SIGKILL);
      ::kill(pid, SIGKILL);
      int st = 0;
      ::waitpid(pid, &st, 0);
    }
  }
  if (output_fd >= 0) ::close(output_fd);
  if (!cleanup_dir.empty()) {
    std::error_code ec;
    std::filesystem::remove_all(cleanup_dir, ec);
  }
}

std::string ChildProcess::drain() {
  if (output_fd >= 0) {
    char buf[8192];
    for (;;) {
      const ssize_t n = ::read(output_fd, buf, sizeof buf);
      if (n <= 0) break;
      pending.append(buf, static_cast<std::size_t>(n));
      if (pending.size() > (4u << 20)) pending.erase(0, pending.size() - (4u << 20));
    }
  }
  // gdbserver's own lines go to the same stream as the program's output.
  static const char *chatter[] = {"Process ",          "Remote debugging using",    "stdin/stdout redirected",
                                  "Child exited with", "Child terminated with",     "Killing process(es)",
                                  "Detaching from process", "Listening on port", "Remote side has terminated",
                                  "gdbserver: ",       "Attached; pid =",           "Remote connection closed"};
  auto is_chatter = [&](std::string_view line) {
    if (what != "gdbserver") return false;
    for (const char *c : chatter)
      if (line.rfind(c, 0) == 0) return true;
    return false;
  };
  std::string out;
  std::size_t start = 0;
  for (;;) {
    const auto nl = pending.find('\n', start);
    if (nl == std::string::npos) break;
    const std::string_view line(pending.data() + start, nl - start);
    if (!is_chatter(line)) {
      out += line;
      out += '\n';
    }
    start = nl + 1;
  }
  pending.erase(0, start);
  // A partial line (a prompt) unless it may be the start of chatter.
  if (!pending.empty()) {
    bool maybe = false;
    if (what == "gdbserver")
      for (const char *c : chatter)
        if (std::string_view(c).rfind(pending.substr(0, std::strlen(c)), 0) == 0) maybe = true;
    if (!maybe) {
      out += pending;
      pending.clear();
    }
  }
  return out;
}

// --- Connecting ---

GdbRemoteTarget::GdbRemoteTarget(std::unique_ptr<Transport> transport, GdbRemoteOptions options)
    : options_(std::move(options)), rsp_(std::make_unique<RspClient>(std::move(transport))) {
  rsp_->set_timeout(options_.timeout);
  handshake();
}

GdbRemoteTarget::~GdbRemoteTarget() {
  try {
    if (state_ == TargetState::running) {
      interrupt();
      wait(Clock::now() + std::chrono::milliseconds(500));
    }
    if (state_ == TargetState::stopped) {
      // A process revkit started goes with the session; one it attached to
      // (or a board) is left running.
      if (options_.child && !options_.attach_pid) kill();
      else detach();
    }
  } catch (const DebugError &) {
  }
  rsp_->transport().close();
}

std::string GdbRemoteTarget::description() const {
  std::string d = options_.description.empty() ? rsp_->transport().describe() : options_.description;
  if (!arch_.empty()) d += " (" + arch_ + ")";
  // Process targets (gdbserver, qemu-user) say which; a machine's "process" is not one.
  if (pid_ && (features_.count("qXfer:exec-file:read") || features_.count("qXfer:libraries-svr4:read")))
    d += ", pid " + std::to_string(*pid_);
  return d;
}

void GdbRemoteTarget::handshake() {
  // Some stubs only start talking after an acknowledgement.
  rsp_->transport().write("+");
  const std::string sup = rsp_->request(
      "qSupported:multiprocess+;swbreak+;hwbreak+;no-resumed+;vContSupported+;xmlRegisters=i386,arm,mips");
  std::size_t at = 0;
  while (at <= sup.size()) {
    const auto semi = sup.find(';', at);
    const std::string item = sup.substr(at, semi == std::string::npos ? std::string::npos : semi - at);
    if (!item.empty()) {
      const auto eq = item.find('=');
      if (eq != std::string::npos) features_[item.substr(0, eq)] = item.substr(eq + 1);
      else if (item.back() == '+' || item.back() == '-' || item.back() == '?')
        features_[item.substr(0, item.size() - 1)] = std::string(1, item.back());
    }
    if (semi == std::string::npos) break;
    at = semi + 1;
  }
  if (auto it = features_.find("PacketSize"); it != features_.end())
    if (auto v = parse_hex(it->second); v && *v >= 256) packet_size_ = std::min<std::uint64_t>(*v, 1u << 20);
  multiprocess_ = features_["multiprocess"] == "+";
  if (features_["QStartNoAckMode"] == "+" && rsp_->request("QStartNoAckMode") == "OK") rsp_->set_no_ack(true);

  std::string stop;
  if (options_.attach_pid) {
    if (rsp_->request("!") != "OK") throw DebugError("the stub has no extended mode (gdbserver --multi) to attach with");
    stop = rsp_->request("vAttach;" + hexnum(static_cast<std::uint64_t>(*options_.attach_pid)),
                         Clock::now() + std::max(options_.timeout, std::chrono::milliseconds(10000)));
    if (stop.empty() || stop[0] == 'E')
      throw DebugError("attaching to process " + std::to_string(*options_.attach_pid) + " failed (" + stop + ")" +
                       (ptrace_scope() >= 1 ? "; kernel.yama.ptrace_scope is " + std::to_string(ptrace_scope()) +
                                                  ", which allows attaching only to children" : ""));
  } else {
    stop = rsp_->request("?");
  }
  const std::string vc = rsp_->request("vCont?");
  if (vc.rfind("vCont", 0) == 0) {
    vcont_ = true;
    for (std::size_t i = 5; i < vc.size(); ++i)
      if (vc[i] == ';' && i + 1 < vc.size()) vcont_actions_.insert(vc[i + 1]);
  }
  read_description();
  finish_registers();
  stepping_ = false;
  last_stop_ = parse_stop(stop, false);
  if (last_stop_.kind == StopKind::signal || last_stop_.kind == StopKind::interrupted) {
    // Where it stood when we connected: not a stop the program caused.
    last_stop_.kind = StopKind::none;
    last_stop_.detail = "stopped at connection";
    last_stop_.signal = 0;
  }
  if (thread_.empty()) {
    const std::string qc = rsp_->request("qC");
    if (qc.rfind("QC", 0) == 0) thread_ = qc.substr(2);
  }
  if (thread_.empty()) {
    auto ts = threads();
    if (!ts.empty()) thread_ = ts.front().id;
  }
  if (!pid_ && thread_.size() > 1 && thread_[0] == 'p')
    if (auto p = parse_hex(thread_.substr(1, thread_.find('.') - 1))) pid_ = static_cast<std::int64_t>(*p);
}

std::optional<std::string> GdbRemoteTarget::xfer(const std::string &object, const std::string &annex) {
  if (features_["qXfer:" + object + ":read"] != "+") return std::nullopt;
  std::string out;
  const std::size_t chunk = std::max<std::size_t>(packet_size_ > 64 ? packet_size_ - 32 : 256, 256);
  for (std::uint64_t offset = 0; offset < (64u << 20);) {
    const std::string r =
        rsp_->request("qXfer:" + object + ":read:" + annex + ":" + hexnum(offset) + "," + hexnum(chunk));
    if (r.empty()) return std::nullopt;
    if (r[0] == 'E') return out.empty() ? std::nullopt : std::optional<std::string>(out);
    out += r.substr(1);
    offset += r.size() - 1;
    if (r[0] == 'l' || r.size() == 1) break;
  }
  return out;
}

void GdbRemoteTarget::read_description() {
  auto doc = xfer("features", "target.xml");
  if (!doc) {
    builtin_description();
    return;
  }
  target_xml_ = *doc;
  std::string error;
  auto root = xml::parse(*doc, &error);
  if (!root) throw DebugError("the stub's target description doesn't parse: " + error);
  if (const xml::Node *a = root->first("architecture")) arch_ = a->text;
  int next = 0;
  std::function<void(const xml::Node &, const std::string &, int)> walk = [&](const xml::Node &n, const std::string &feature,
                                                                              int depth) {
    if (depth > 8) return;
    for (const xml::Node &c : n.children) {
      if (c.name == "xi:include" || c.name == "include") {
        const std::string href = c.attr_or("href");
        auto sub = xfer("features", href);
        if (!sub) continue;
        auto subroot = xml::parse(*sub);
        if (!subroot) continue;
        if (subroot->name == "feature") walk(*subroot, subroot->attr_or("name"), depth + 1);
        else walk(*subroot, feature, depth + 1);
      } else if (c.name == "feature") {
        walk(c, c.attr_or("name"), depth + 1);
      } else if (c.name == "reg") {
        RegisterDesc d;
        d.target_name = c.attr_or("name");
        const auto bits = xml::number(c.attr_or("bitsize", "0")).value_or(0);
        RegInfo info;
        info.bits = static_cast<std::uint32_t>(bits);
        if (auto rn = xml::number(c.attr_or("regnum", "")); rn) next = static_cast<int>(*rn);
        info.regnum = next++;
        d.size = static_cast<std::uint32_t>((bits + 7) / 8);
        std::string group = c.attr_or("group");
        const std::string type = c.attr_or("type");
        if (group.empty()) {
          if (feature.find("core") != std::string::npos) group = "general";
          else if (feature.find("fpu") != std::string::npos || feature.find("vfp") != std::string::npos) group = "float";
          else if (feature.find("sse") != std::string::npos || feature.find("avx") != std::string::npos ||
                   feature.find("neon") != std::string::npos || feature.find("sve") != std::string::npos)
            group = "vector";
          else if (feature.find("linux") != std::string::npos || feature.find("system") != std::string::npos ||
                   feature.find("m-system") != std::string::npos)
            group = "system";
          else group = "other";
        }
        d.group = group;
        if (d.size == 0 || d.target_name.empty()) continue;
        regs_.push_back(d);
        info_.push_back(info);
        if (type == "code_ptr" && pc_name_.empty()) pc_name_ = d.target_name;
        if (type == "data_ptr" && sp_name_.empty() &&
            (lower(d.target_name) == "sp" || lower(d.target_name) == "rsp" || lower(d.target_name) == "esp"))
          sp_name_ = d.target_name;
      }
    }
  };
  walk(*root, "", 0);
  if (regs_.empty()) builtin_description();
}

void GdbRemoteTarget::builtin_description() {
  // Stubs without target descriptions use gdb's classic layouts.
  regs_.clear();
  info_.clear();
  const std::string proc = proc_of(options_.language);
  auto add = [&](const std::string &name, std::uint32_t bits, int regnum, const char *group = "general") {
    RegisterDesc d;
    d.target_name = name;
    d.size = bits / 8;
    d.group = group;
    regs_.push_back(d);
    RegInfo i;
    i.regnum = regnum;
    i.bits = bits;
    info_.push_back(i);
  };
  int n = 0;
  if (proc == "x86" && options_.pointer_size == 8) {
    for (const char *r : {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"}) add(r, 64, n++);
    for (int i = 8; i < 16; ++i) add("r" + std::to_string(i), 64, n++);
    add("rip", 64, n++);
    add("eflags", 32, n++);
    for (const char *r : {"cs", "ss", "ds", "es", "fs", "gs"}) add(r, 32, n++);
    arch_ = "i386:x86-64";
  } else if (proc == "x86") {
    for (const char *r : {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"})
      add(r, 32, n++);
    arch_ = "i386";
  } else if (proc == "AARCH64") {
    for (int i = 0; i < 31; ++i) add("x" + std::to_string(i), 64, n++);
    add("sp", 64, n++);
    add("pc", 64, n++);
    add("cpsr", 32, n++);
    arch_ = "aarch64";
  } else if (proc == "ARM") {
    const bool m = options_.language.find("Cortex") != std::string::npos;
    for (int i = 0; i < 13; ++i) add("r" + std::to_string(i), 32, n++);
    add("sp", 32, n++);
    add("lr", 32, n++);
    add("pc", 32, n++);
    if (m) {
      add("xpsr", 32, 25);
    } else {
      for (int i = 0; i < 8; ++i) add("f" + std::to_string(i), 96, n++, "float");
      add("fps", 32, n++, "float");
      add("cpsr", 32, n++);
    }
    arch_ = "arm";
  } else {
    throw DebugError("the stub sent no target description, and revkit has no built-in register layout for " +
                     options_.language);
  }
}

void GdbRemoteTarget::finish_registers() {
  // 'g' packet offsets: registers in regnum order, back to back.
  std::vector<std::size_t> order(regs_.size());
  for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
  std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return info_[a].regnum < info_[b].regnum; });
  std::size_t offset = 0;
  int expect = order.empty() ? 0 : info_[order.front()].regnum;
  for (std::size_t i : order) {
    if (info_[i].regnum != expect) break;  // a gap: later registers only by 'p'
    info_[i].g_offset = offset;
    offset += regs_[i].size;
    ++expect;
  }
  // Names: the program language's registers where they map.
  std::set<std::string> used;
  for (RegisterDesc &d : regs_) {
    d.sleigh = map_register_name(options_.language, d.target_name, d.size, options_.sleigh_registers);
    d.name = !d.sleigh.empty() && !used.count(lower(d.sleigh)) ? d.sleigh : d.target_name;
    used.insert(lower(d.name));
  }
  // Flag bits the emulator shows as registers.
  const std::string proc = proc_of(options_.language);
  auto derive = [&](const std::string &parent, std::initializer_list<std::pair<const char *, int>> bits) {
    auto p = std::find_if(regs_.begin(), regs_.end(), [&](const RegisterDesc &d) { return lower(d.target_name) == parent; });
    if (p == regs_.end()) return;
    const std::string parent_name = p->name;
    for (auto [name, bit] : bits) {
      if (used.count(lower(name))) continue;
      RegisterDesc d;
      d.name = name;
      d.target_name = name;
      d.size = 1;
      d.group = "flags";
      d.parent = parent_name;
      d.bit = bit;
      for (const SleighRegister &s : options_.sleigh_registers)
        if (s.name == name) d.sleigh = name;
      regs_.push_back(d);
      info_.push_back(RegInfo{});
      used.insert(lower(name));
    }
  };
  if (proc == "x86") derive("eflags", {{"CF", 0}, {"PF", 2}, {"AF", 4}, {"ZF", 6}, {"SF", 7}, {"IF", 9}, {"DF", 10}, {"OF", 11}});
  else if (proc == "AARCH64") derive("cpsr", {{"NG", 31}, {"ZR", 30}, {"CY", 29}, {"OV", 28}});
  else if (proc == "ARM") {
    derive("cpsr", {{"NG", 31}, {"ZR", 30}, {"CY", 29}, {"OV", 28}, {"TB", 5}});
    derive("xpsr", {{"NG", 31}, {"ZR", 30}, {"CY", 29}, {"OV", 28}, {"TB", 24}});
  }
  // The display set: the language's curated registers where present, else
  // the core registers.
  const std::vector<std::string> curated = emu::display_register_names(options_.language, options_.pointer_size);
  by_name_.clear();
  for (std::size_t i = 0; i < regs_.size(); ++i) {
    by_name_.emplace(lower(regs_[i].name), i);
    by_name_.emplace(lower(regs_[i].target_name), i);
  }
  bool any = false;
  for (const std::string &c : curated)
    if (auto it = by_name_.find(lower(c)); it != by_name_.end()) {
      regs_[it->second].display = true;
      any = true;
    }
  if (!any)
    for (RegisterDesc &d : regs_)
      if (d.group == "general" || d.group == "flags") d.display = true;
  // pc and sp.
  auto pick = [&](std::string &out, std::initializer_list<const char *> names) {
    if (!out.empty()) {
      if (auto it = by_name_.find(lower(out)); it != by_name_.end()) out = regs_[it->second].name;
      return;
    }
    for (const char *n : names)
      if (auto it = by_name_.find(n); it != by_name_.end()) {
        out = regs_[it->second].name;
        return;
      }
  };
  pick(pc_name_, {"rip", "eip", "pc"});
  pick(sp_name_, {"rsp", "esp", "sp", "r13"});
  if (pc_name_.empty()) throw DebugError("the stub's registers have no program counter");
}

const RegisterDesc &GdbRemoteTarget::desc(std::string_view name) const {
  auto it = by_name_.find(lower(name));
  if (it == by_name_.end()) throw DebugError("no register " + std::string(name));
  return regs_[it->second];
}

// --- Registers ---

void GdbRemoteTarget::invalidate() {
  cache_.clear();
  g_loaded_ = false;
}

std::string GdbRemoteTarget::thread_arg(const std::string &id) const { return id.empty() ? "0" : id; }

void GdbRemoteTarget::ensure_thread() {
  if (thread_.empty() || hg_thread_ == thread_) return;
  const std::string r = rsp_->request("Hg" + thread_arg(thread_));
  if (r != "OK" && !r.empty()) throw DebugError("the stub can't select thread " + thread_ + " (" + r + ")");
  hg_thread_ = thread_;
}

void GdbRemoteTarget::load_g() {
  if (g_loaded_) return;
  ensure_thread();
  const std::string r = rsp_->request("g");
  if (r.empty() || r[0] == 'E') throw DebugError("the stub can't read registers (" + r + ")");
  for (std::size_t i = 0; i < regs_.size(); ++i) {
    if (!info_[i].g_offset || info_[i].regnum < 0) continue;
    const std::size_t at = *info_[i].g_offset * 2, len = regs_[i].size * 2;
    if (at + len > r.size()) continue;
    if (auto v = RspClient::from_hex(std::string_view(r).substr(at, len))) cache_.try_emplace(info_[i].regnum, std::move(*v));
  }
  g_loaded_ = true;
}

std::vector<std::uint8_t> GdbRemoteTarget::fetch(std::size_t index) {
  if (state_ != TargetState::stopped) throw DebugError("the target is " + std::string(to_string(state_)));
  const RegInfo &info = info_[index];
  const RegisterDesc &d = regs_[index];
  auto le = [&](std::vector<std::uint8_t> v) {
    v.resize(d.size, 0);
    if (options_.big_endian) std::reverse(v.begin(), v.end());
    return v;
  };
  if (auto it = cache_.find(info.regnum); it != cache_.end()) return le(it->second);
  if (info.g_offset && !g_loaded_) {
    load_g();
    if (auto it = cache_.find(info.regnum); it != cache_.end()) return le(it->second);
  }
  if (p_packet_.value_or(true)) {
    ensure_thread();
    const std::string r = rsp_->request("p" + hexnum(static_cast<std::uint64_t>(info.regnum)));
    if (r.empty()) {
      p_packet_ = false;
    } else if (r[0] == 'E' && r.size() == 3) {
      throw DebugError("the stub can't read register " + d.name + " (" + r + ")");
    } else {
      p_packet_ = true;
      auto v = RspClient::from_hex(r);
      if (!v) throw DebugError("bad register value from the stub: " + r.substr(0, 40));
      cache_[info.regnum] = *v;
      return le(*v);
    }
  }
  if (!g_loaded_) {
    load_g();
    if (auto it = cache_.find(info.regnum); it != cache_.end()) return le(it->second);
  }
  throw DebugError("the stub doesn't report register " + d.name);
}

std::vector<std::uint8_t> GdbRemoteTarget::read_register(std::string_view name) {
  const RegisterDesc &d = desc(name);
  const std::size_t index = static_cast<std::size_t>(&d - regs_.data());
  if (!d.parent.empty()) {
    const auto parent = read_register(d.parent);
    const std::uint64_t v = to_u64(parent);
    return {static_cast<std::uint8_t>((v >> d.bit) & 1)};
  }
  return fetch(index);
}

void GdbRemoteTarget::write_register(std::string_view name, std::span<const std::uint8_t> value) {
  if (state_ != TargetState::stopped) throw DebugError("the target is " + std::string(to_string(state_)));
  const RegisterDesc &d = desc(name);
  if (!d.parent.empty()) {
    auto parent = read_register(d.parent);
    std::uint64_t v = to_u64(parent);
    const bool on = !value.empty() && value[0] != 0;
    v = on ? v | (std::uint64_t{1} << d.bit) : v & ~(std::uint64_t{1} << d.bit);
    write_register(d.parent, from_u64(v, parent.size()));
    return;
  }
  const std::size_t index = static_cast<std::size_t>(&d - regs_.data());
  const RegInfo &info = info_[index];
  std::vector<std::uint8_t> v(value.begin(), value.end());
  v.resize(d.size, 0);
  if (options_.big_endian) std::reverse(v.begin(), v.end());
  ensure_thread();
  if (P_packet_.value_or(true)) {
    const std::string r = rsp_->request("P" + hexnum(static_cast<std::uint64_t>(info.regnum)) + "=" + RspClient::to_hex(v));
    if (r == "OK") {
      P_packet_ = true;
      cache_[info.regnum] = v;
      return;
    }
    if (!r.empty()) throw DebugError("the stub can't write register " + d.name + " (" + r + ")");
    P_packet_ = false;
  }
  if (!info.g_offset) throw DebugError("the stub can't write register " + d.name);
  g_loaded_ = false;
  cache_.clear();
  const std::string g = rsp_->request("g");
  if (g.empty() || g[0] == 'E') throw DebugError("the stub can't read registers (" + g + ")");
  std::string patched = g;
  const std::string hex = RspClient::to_hex(v);
  if (*info.g_offset * 2 + hex.size() > patched.size()) throw DebugError("register " + d.name + " is outside the 'g' packet");
  patched.replace(*info.g_offset * 2, hex.size(), hex);
  const std::string r = rsp_->request("G" + patched);
  if (r != "OK") throw DebugError("the stub can't write registers (" + r + ")");
  invalidate();
}

bool GdbRemoteTarget::thumb() {
  if (proc_of(options_.language) != "ARM") return false;
  if (by_name_.count("tb")) {
    try {
      return read_register("TB").at(0) != 0;
    } catch (const DebugError &) {
    }
  }
  return false;
}

// --- Memory ---

std::size_t GdbRemoteTarget::read_chunk(std::uint64_t address, std::uint8_t *out, std::size_t len) {
  const std::string r = rsp_->request("m" + hexnum(address) + "," + hexnum(len));
  if (r.empty() || (r[0] == 'E' && r.size() == 3)) return 0;
  auto v = RspClient::from_hex(r);
  if (!v) return 0;
  const std::size_t n = std::min(v->size(), len);
  std::memcpy(out, v->data(), n);
  return n;
}

std::size_t GdbRemoteTarget::read_memory(std::uint64_t address, std::span<std::uint8_t> out, std::vector<ByteRange> *unreadable) {
  if (state_ != TargetState::stopped) throw DebugError("the target is " + std::string(to_string(state_)));
  std::fill(out.begin(), out.end(), 0);
  const std::size_t chunk = std::max<std::size_t>(64, std::min<std::size_t>((packet_size_ - 32) / 2, 0x4000));
  std::size_t done = 0, read = 0;
  while (done < out.size()) {
    const std::uint64_t at = address + done;
    const std::size_t want = std::min(chunk, out.size() - done);
    const std::size_t n = read_chunk(at, out.data() + done, want);
    if (n > 0) {
      done += n;
      read += n;
      continue;
    }
    // Unreadable: skip to the next page (holes are page sized on an MMU).
    std::size_t skip = static_cast<std::size_t>(0x1000 - (at & 0xfff));
    skip = std::min(skip, out.size() - done);
    if (unreadable != nullptr) {
      if (!unreadable->empty() && unreadable->back().offset + unreadable->back().length == done)
        unreadable->back().length += static_cast<std::uint32_t>(skip);
      else unreadable->push_back({static_cast<std::uint32_t>(done), static_cast<std::uint32_t>(skip)});
    }
    done += skip;
  }
  return read;
}

bool GdbRemoteTarget::write_memory(std::uint64_t address, std::span<const std::uint8_t> bytes) {
  if (state_ != TargetState::stopped) throw DebugError("the target is " + std::string(to_string(state_)));
  const std::size_t chunk = std::max<std::size_t>(64, std::min<std::size_t>((packet_size_ - 64) / 2, 0x4000));
  for (std::size_t done = 0; done < bytes.size();) {
    const std::size_t n = std::min(chunk, bytes.size() - done);
    const auto part = bytes.subspan(done, n);
    const std::string head = hexnum(address + done) + "," + hexnum(n) + ":";
    std::string r;
    if (x_packet_.value_or(true)) {
      r = rsp_->request("X" + head + RspClient::escape(part));
      if (r.empty()) x_packet_ = false;
      else x_packet_ = true;
    }
    if (!x_packet_.value_or(true)) r = rsp_->request("M" + head + RspClient::to_hex(part));
    if (r != "OK") return false;
    done += n;
  }
  // Writing over code may change what the stub's cached registers mean: no.
  return true;
}

// --- Execution ---

std::string GdbRemoteTarget::resume_packet(bool step, int signal) {
  const std::string t = thread_arg(thread_);
  if (vcont_ && vcont_actions_.count(step ? 's' : 'c')) {
    const std::string action = signal != 0 ? std::string(step ? "S" : "C") + sig2(signal) : std::string(step ? "s" : "c");
    // Steps hold the other threads (scheduler locking); continuing runs all.
    if (step && !thread_.empty()) return "vCont;" + action + ":" + t;
    if (signal != 0 && !thread_.empty()) return "vCont;" + action + ":" + t + ";c";
    return "vCont;" + action;
  }
  if (!thread_.empty()) {
    const std::string r = rsp_->request("Hc" + t);
    (void)r;
  }
  if (signal != 0) return std::string(step ? "S" : "C") + sig2(signal);
  return step ? "s" : "c";
}

Stop GdbRemoteTarget::resume(const ResumeOptions &options) {
  if (state_ != TargetState::stopped) throw DebugError("the target is " + std::string(to_string(state_)));
  const bool step = options.mode != RunMode::run;
  int signal = 0;
  if (options_.pass_signals && last_stop_.kind == StopKind::signal && last_stop_.signal != kSigTrap &&
      last_stop_.signal != kSigInt)
    signal = last_stop_.signal;
  // Resuming from a breakpoint: step off it with it removed first, as gdb
  // does (stubs report the breakpoint again otherwise).
  {
    const std::uint64_t pc_now = pc();
    std::vector<std::pair<std::uint64_t, int>> here;
    for (const auto &b : breakpoints_)
      if (b.first == pc_now && b.second <= 1) here.push_back(b);
    if (!here.empty()) {
      for (const auto &b : here)
        rsp_->request("z" + std::to_string(b.second) + "," + hexnum(b.first) + "," + std::to_string(breakpoint_size(b.first)));
      invalidate();
      interrupt_sent_ = false;
      rsp_->send(resume_packet(true, signal), Clock::now() + rsp_->timeout());
      state_ = TargetState::running;
      stepping_ = true;
      Stop s = wait_stop(step ? options.deadline : Clock::now() + std::max(rsp_->timeout(), std::chrono::milliseconds(5000)), true);
      if (state_ == TargetState::stopped)
        for (const auto &b : here)
          rsp_->request("Z" + std::to_string(b.second) + "," + hexnum(b.first) + "," + std::to_string(breakpoint_size(b.first)));
      if (step || state_ != TargetState::stopped || s.kind != StopKind::stepped) return s;  // a signal, a watchpoint
      signal = 0;
    }
  }
  invalidate();
  interrupt_sent_ = false;
  rsp_->send(resume_packet(step, signal), Clock::now() + rsp_->timeout());
  state_ = TargetState::running;
  stepping_ = step;
  if (options.cancelled) {
    // Poll for cancellation while waiting.
    for (;;) {
      const auto slice = std::min(options.deadline, Clock::now() + std::chrono::milliseconds(100));
      Stop s = wait(slice);
      if (s.kind != StopKind::running || Clock::now() >= options.deadline) return s;
      if (options.cancelled()) {
        interrupt();
        s = wait(Clock::now() + std::chrono::seconds(5));
        if (s.kind == StopKind::interrupted) s.kind = StopKind::cancelled;
        return s;
      }
    }
  }
  return wait(options.deadline);
}

Stop GdbRemoteTarget::wait(Clock::time_point deadline) {
  if (state_ != TargetState::running) return last_stop_;
  return wait_stop(deadline, stepping_);
}

Stop GdbRemoteTarget::wait_stop(Clock::time_point deadline, bool stepping) {
  for (;;) {
    std::optional<std::string> pkt;
    try {
      pkt = rsp_->receive(deadline);
    } catch (const DebugError &e) {
      state_ = TargetState::disconnected;
      last_stop_ = Stop{};
      last_stop_.kind = StopKind::disconnected;
      last_stop_.detail = e.what();
      return last_stop_;
    }
    if (!pkt) {
      Stop s;
      s.kind = StopKind::running;
      s.detail = "still running";
      return s;
    }
    const std::string &p = *pkt;
    if (p.size() > 1 && p[0] == 'O' && p != "OK") {
      if (auto v = RspClient::from_hex(std::string_view(p).substr(1))) output_.append(v->begin(), v->end());
      continue;
    }
    if (p.empty() || p == "OK" || (p[0] == 'E' && p.size() == 3)) continue;
    if (p[0] != 'T' && p[0] != 'S' && p[0] != 'W' && p[0] != 'X' && p[0] != 'N' && p[0] != 'w') continue;
    if (p[0] == 'w') continue;  // a thread exited (only with QThreadEvents)
    Stop s = parse_stop(p, stepping);
    ++stops_;
    last_stop_ = s;
    return s;
  }
}

Stop GdbRemoteTarget::parse_stop(const std::string &p, bool stepping) {
  Stop s;
  invalidate();
  modules_.reset();
  if (p.empty()) throw DebugError("an empty stop reply");
  const char c = p[0];
  if (c == 'W' || c == 'X') {
    const auto semi = p.find(';');
    const auto code = parse_hex(p.substr(1, semi == std::string::npos ? std::string::npos : semi - 1)).value_or(0);
    state_ = TargetState::exited;
    if (c == 'W') {
      s.kind = StopKind::exited;
      s.exit_code = static_cast<std::int64_t>(code);
      s.detail = "exited with status " + std::to_string(code);
    } else {
      s.kind = StopKind::killed;
      s.signal = static_cast<int>(code);
      s.detail = "terminated by " + signal_text(s.signal);
    }
    return s;
  }
  if (c == 'N') {
    state_ = TargetState::exited;
    s.kind = StopKind::exited;
    s.detail = "no threads left to run";
    return s;
  }
  if (p.size() < 3) throw DebugError("a malformed stop reply: " + p);
  const int sig = static_cast<int>(parse_hex(p.substr(1, 2)).value_or(0));
  state_ = TargetState::stopped;
  bool watch = false, bp = false;
  std::optional<std::uint64_t> watch_addr;
  std::string thread;
  if (c == 'T') {
    std::size_t at = 3;
    while (at < p.size()) {
      const auto semi = p.find(';', at);
      const std::string pair = p.substr(at, semi == std::string::npos ? std::string::npos : semi - at);
      at = semi == std::string::npos ? p.size() : semi + 1;
      const auto colon = pair.find(':');
      if (colon == std::string::npos) continue;
      const std::string key = pair.substr(0, colon), value = pair.substr(colon + 1);
      if (key == "thread") thread = value;
      else if (key == "watch" || key == "rwatch" || key == "awatch") {
        watch = true;
        watch_addr = parse_hex(value);
      } else if (key == "swbreak" || key == "hwbreak") bp = true;
      else if (key == "library") modules_.reset();
      else if (auto rn = parse_hex(key); rn && std::all_of(key.begin(), key.end(), ::isxdigit)) {
        if (auto v = RspClient::from_hex(value)) cache_[static_cast<int>(*rn)] = std::move(*v);
      }
    }
  }
  if (!thread.empty()) {
    if (thread != thread_) hg_thread_.clear();
    thread_ = thread;
    if (thread.size() > 1 && thread[0] == 'p')
      if (auto pid = parse_hex(thread.substr(1, thread.find('.') - 1))) pid_ = static_cast<std::int64_t>(*pid);
  } else {
    hg_thread_.clear();
  }
  // The expedited registers belong to the stopping thread, which the stub
  // reads now; keep them only if that is the thread we'll read.
  s.thread = thread_;
  try {
    s.pc = pc();
  } catch (const DebugError &) {
    s.pc = 0;
  }
  s.signal = sig;
  if (watch) {
    s.kind = StopKind::watchpoint;
    s.address = watch_addr;
    s.detail = "watchpoint at " + hex(watch_addr.value_or(0));
  } else if (sig == kSigTrap && stepping) {
    s.kind = StopKind::stepped;
  } else if (bp || (sig == kSigTrap && std::any_of(breakpoints_.begin(), breakpoints_.end(), [&](const auto &b) {
                      return b.second <= 1 && b.first == s.pc;
                    }))) {
    s.kind = StopKind::breakpoint;
  } else if ((sig == kSigInt && interrupt_sent_) || (sig == 0 && interrupt_sent_)) {
    s.kind = StopKind::interrupted;
    s.detail = "interrupted";
  } else if (sig == 0) {
    s.kind = StopKind::interrupted;
  } else {
    s.kind = StopKind::signal;
    s.detail = signal_text(sig);
  }
  interrupt_sent_ = false;
  return s;
}

void GdbRemoteTarget::interrupt() {
  interrupt_sent_ = true;
  try {
    rsp_->interrupt();
  } catch (const DebugError &) {
  }
}

// --- Breakpoints ---

std::uint32_t GdbRemoteTarget::breakpoint_size(std::uint64_t address) {
  const std::string proc = proc_of(options_.language);
  if (proc == "x86") return 1;
  if (proc == "ARM") return (address & 1) != 0 ? 2 : 4;
  return 4;
}

void GdbRemoteTarget::insert_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) {
  if (state_ != TargetState::stopped) throw DebugError("the target is " + std::string(to_string(state_)));
  int type = 0;
  switch (kind) {
    case BreakKind::software: type = 0; break;
    case BreakKind::hardware: type = 1; break;
    case BreakKind::watch_write: type = 2; break;
    case BreakKind::watch_read: type = 3; break;
    case BreakKind::watch_access: type = 4; break;
  }
  std::uint64_t at = address;
  std::uint32_t k = size;
  if (type <= 1) {
    k = size != 0 ? size : breakpoint_size(address);
    if (proc_of(options_.language) == "ARM") at &= ~std::uint64_t{1};
  } else if (k == 0) {
    k = 1;
  }
  auto try_type = [&](int t) {
    const std::string r = rsp_->request("Z" + std::to_string(t) + "," + hexnum(at) + "," + std::to_string(k));
    return r;
  };
  std::string r = try_type(type);
  if (r == "OK") {
    breakpoints_.insert({at, type});
    return;
  }
  if (type == 0) {
    // Flash, or a stub without software breakpoints: a hardware one.
    const std::string r1 = try_type(1);
    if (r1 == "OK") {
      breakpoints_.insert({at, 1});
      return;
    }
  }
  if (r.empty()) throw DebugError("the stub doesn't support " + std::string(to_string(kind)) + " breakpoints");
  throw DebugError("the stub refused a " + std::string(to_string(kind)) + " breakpoint at " + hex(address) + " (" + r + ")");
}

void GdbRemoteTarget::remove_breakpoint(BreakKind kind, std::uint64_t address, std::uint32_t size) {
  if (state_ != TargetState::stopped) return;
  int type = 0;
  switch (kind) {
    case BreakKind::software: type = 0; break;
    case BreakKind::hardware: type = 1; break;
    case BreakKind::watch_write: type = 2; break;
    case BreakKind::watch_read: type = 3; break;
    case BreakKind::watch_access: type = 4; break;
  }
  std::uint64_t at = address;
  std::uint32_t k = size;
  if (type <= 1) {
    k = size != 0 ? size : breakpoint_size(address);
    if (proc_of(options_.language) == "ARM") at &= ~std::uint64_t{1};
    // Inserted as hardware when software was refused.
    if (type == 0 && !breakpoints_.count({at, 0}) && breakpoints_.count({at, 1})) type = 1;
  } else if (k == 0) {
    k = 1;
  }
  rsp_->request("z" + std::to_string(type) + "," + hexnum(at) + "," + std::to_string(k));
  breakpoints_.erase({at, type});
}

// --- Threads ---

std::vector<ThreadInfo> GdbRemoteTarget::threads() {
  std::vector<ThreadInfo> out;
  if (state_ != TargetState::stopped) return out;
  if (auto doc = xfer("threads")) {
    if (auto root = xml::parse(*doc)) {
      for (const xml::Node *t : root->all("thread")) {
        ThreadInfo ti;
        ti.id = t->attr_or("id");
        ti.name = t->attr_or("name");
        if (auto core = xml::number(t->attr_or("core", ""))) ti.core = static_cast<int>(*core);
        if (ti.name.empty()) ti.name = t->text;
        out.push_back(ti);
      }
    }
  }
  if (out.empty()) {
    std::string r = rsp_->request("qfThreadInfo");
    for (int guard = 0; guard < 10000 && !r.empty() && r[0] == 'm'; ++guard) {
      std::size_t at = 1;
      while (at < r.size()) {
        const auto comma = r.find(',', at);
        ThreadInfo ti;
        ti.id = r.substr(at, comma == std::string::npos ? std::string::npos : comma - at);
        if (!ti.id.empty()) out.push_back(ti);
        if (comma == std::string::npos) break;
        at = comma + 1;
      }
      r = rsp_->request("qsThreadInfo");
    }
  }
  for (ThreadInfo &t : out) {
    t.current = t.id == thread_;
    if (t.current) {
      try {
        t.pc = pc();
      } catch (const DebugError &) {
      }
    }
  }
  return out;
}

void GdbRemoteTarget::select_thread(const std::string &id) {
  if (state_ != TargetState::stopped) throw DebugError("the target is " + std::string(to_string(state_)));
  const std::string r = rsp_->request("T" + thread_arg(id));
  if (r != "OK") throw DebugError("no thread " + id);
  thread_ = id;
  hg_thread_.clear();
  invalidate();
}

// --- Modules, maps, auxv ---

std::map<std::uint64_t, std::uint64_t> GdbRemoteTarget::auxv() {
  if (auxv_) return *auxv_;
  std::map<std::uint64_t, std::uint64_t> out;
  if (state_ == TargetState::stopped) {
    if (auto data = xfer("auxv")) {
      const std::size_t w = options_.pointer_size;
      for (std::size_t at = 0; at + 2 * w <= data->size(); at += 2 * w) {
        auto word = [&](std::size_t off) {
          std::uint64_t v = 0;
          for (std::size_t i = 0; i < w; ++i) {
            const std::uint8_t b = static_cast<std::uint8_t>((*data)[off + i]);
            if (options_.big_endian) v = v << 8 | b;
            else v |= std::uint64_t{b} << (8 * i);
          }
          return v;
        };
        const std::uint64_t key = word(at), value = word(at + w);
        if (key == 0) break;
        out[key] = value;
      }
      auxv_ = out;  // fixed for the process's life
    }
  }
  return out;
}

std::string GdbRemoteTarget::exec_file() {
  const std::string annex = pid_ && multiprocess_ ? hexnum(static_cast<std::uint64_t>(*pid_)) : "";
  if (auto f = xfer("exec-file", annex)) {
    // The kernel's name for an executable replaced on disk since it started.
    constexpr std::string_view deleted = " (deleted)";
    if (f->size() > deleted.size() && f->compare(f->size() - deleted.size(), deleted.size(), deleted) == 0)
      f->resize(f->size() - deleted.size());
    return *f;
  }
  return "";
}

std::optional<std::string> GdbRemoteTarget::vfile_read(const std::string &path) {
  if (features_.count("vFile:unsupported")) return std::nullopt;
  const std::string open = rsp_->request("vFile:open:" + RspClient::to_hex(path) + ",0,0");
  if (open.empty()) {
    features_["vFile:unsupported"] = "+";
    return std::nullopt;
  }
  if (open[0] != 'F' || open.find('-') != std::string::npos) return std::nullopt;
  const auto fd = parse_hex(open.substr(1, open.find(';') - 1));
  if (!fd) return std::nullopt;
  std::string out;
  const std::size_t chunk = std::max<std::size_t>(256, std::min<std::size_t>(packet_size_ - 64, 0x4000));
  for (int guard = 0; guard < 4096; ++guard) {
    const std::string r = rsp_->request("vFile:pread:" + hexnum(*fd) + "," + hexnum(chunk) + "," + hexnum(out.size()));
    if (r.empty() || r[0] != 'F' || (r.size() > 1 && r[1] == '-')) break;
    const auto semi = r.find(';');
    const auto n = parse_hex(r.substr(1, semi == std::string::npos ? std::string::npos : semi - 1)).value_or(0);
    if (n == 0 || semi == std::string::npos) break;
    out += r.substr(semi + 1, n);
  }
  rsp_->request("vFile:close:" + hexnum(*fd));
  return out;
}

std::vector<MapRegion> GdbRemoteTarget::memory_map() {
  std::vector<MapRegion> out;
  if (state_ != TargetState::stopped) return out;
  if (pid_) {
    if (auto maps = vfile_read("/proc/" + std::to_string(*pid_) + "/maps"); maps && !maps->empty()) {
      std::istringstream in(*maps);
      std::string line;
      while (std::getline(in, line)) {
        std::istringstream l(line);
        std::string range, perms, offset, dev, inode, path;
        l >> range >> perms >> offset >> dev >> inode;
        std::getline(l, path);
        path.erase(0, path.find_first_not_of(' '));
        const auto dash = range.find('-');
        auto lo = parse_hex(range.substr(0, dash)), hi = parse_hex(range.substr(dash + 1));
        if (!lo || !hi || *hi <= *lo) continue;
        MapRegion r;
        r.start = *lo;
        r.size = *hi - *lo;
        r.perms = perms.substr(0, 3);
        r.offset = parse_hex(offset).value_or(0);
        r.name = path;
        r.kind = path.empty() ? "anon" : path[0] == '[' ? "anon" : "file";
        out.push_back(r);
      }
      if (!out.empty()) return out;
    }
  }
  if (auto doc = xfer("memory-map")) {
    if (auto root = xml::parse(*doc)) {
      for (const xml::Node *m : root->all("memory")) {
        MapRegion r;
        r.start = xml::number(m->attr_or("start", "0")).value_or(0);
        r.size = xml::number(m->attr_or("length", "0")).value_or(0);
        r.kind = m->attr_or("type", "ram");
        r.perms = r.kind == "ram" ? "rwx" : "r-x";
        r.name = r.kind;
        if (r.size != 0) out.push_back(r);
      }
    }
  }
  return out;
}

std::vector<ModuleInfo> GdbRemoteTarget::modules() {
  if (modules_) return *modules_;
  std::vector<ModuleInfo> out;
  if (state_ != TargetState::stopped) return out;
  // The executable.
  const std::string exe = exec_file();
  ModuleInfo main;
  main.main = true;
  main.path = exe;
  main.name = exe.substr(exe.rfind('/') + 1);
  bool have_main = !exe.empty();
  // Libraries (Linux): the dynamic linker's list.
  if (auto doc = xfer("libraries-svr4")) {
    if (auto root = xml::parse(*doc)) {
      if (auto lm = xml::number(root->attr_or("main-lm", ""))) {
        // l_addr is the first word of the main link map.
        std::vector<std::uint8_t> w(options_.pointer_size);
        if (read_memory(*lm, w) == w.size()) {
          std::uint64_t v = 0;
          for (std::size_t i = 0; i < w.size(); ++i)
            v |= std::uint64_t{w[options_.big_endian ? w.size() - 1 - i : i]} << (8 * i);
          main.load_bias = v;
          have_main = true;
        }
      }
      for (const xml::Node *l : root->all("library")) {
        ModuleInfo m;
        m.path = l->attr_or("name");
        m.name = m.path.substr(m.path.rfind('/') + 1);
        m.load_bias = xml::number(l->attr_or("l_addr", "0")).value_or(0);
        m.base = m.load_bias;
        if (!m.path.empty()) out.push_back(m);
      }
    }
  } else if (auto doc2 = xfer("libraries")) {
    if (auto root = xml::parse(*doc2)) {
      for (const xml::Node *l : root->all("library")) {
        ModuleInfo m;
        m.path = l->attr_or("name");
        m.name = m.path.substr(m.path.rfind('/') + 1);
        if (const xml::Node *seg = l->first("segment")) m.base = xml::number(seg->attr_or("address", "0")).value_or(0);
        else if (const xml::Node *sec = l->first("section")) m.base = xml::number(sec->attr_or("address", "0")).value_or(0);
        m.load_bias = m.base;
        if (!m.path.empty()) out.push_back(m);
      }
    }
  }
  // Before the dynamic linker has run, its list is empty: the auxiliary
  // vector says where it is (AT_BASE).
  const auto av = auxv();
  if (auto base = av.find(7); base != av.end() && base->second != 0) {
    const bool listed = std::any_of(out.begin(), out.end(), [&](const ModuleInfo &m) { return m.load_bias == base->second; });
    if (!listed) {
      ModuleInfo ld;
      ld.name = "ld.so";
      ld.path = "";
      ld.base = ld.load_bias = base->second;
      out.push_back(ld);
    }
  }
  // Sizes and bases from the memory map, when there is one.
  auto maps = memory_map();
  if (!maps.empty()) {
    auto extent = [&](ModuleInfo &m) {
      std::uint64_t lo = ~std::uint64_t{0}, hi = 0;
      for (const MapRegion &r : maps)
        if (!m.path.empty() && r.name == m.path) {
          lo = std::min(lo, r.start);
          hi = std::max(hi, r.start + r.size);
        }
      if (hi <= lo && m.base != 0) {
        // The loader's path may differ from the map's (/lib vs /usr/lib):
        // the file mapped at the module's base.
        std::string name;
        for (const MapRegion &r : maps)
          if (r.start == m.base) name = r.name;
        for (const MapRegion &r : maps)
          if (!name.empty() && r.name == name) {
            lo = std::min(lo, r.start);
            hi = std::max(hi, r.start + r.size);
          }
      }
      if (hi > lo) {
        m.base = lo;
        m.size = hi - lo;
      }
    };
    if (have_main) extent(main);
    for (ModuleInfo &m : out) {
      if (m.name == "ld.so" && m.path.empty()) {
        for (const MapRegion &r : maps)
          if (r.start == m.base && !r.name.empty()) {
            m.path = r.name;
            m.name = r.name.substr(r.name.rfind('/') + 1);
          }
      }
      extent(m);
    }
  }
  if (have_main) out.insert(out.begin(), main);
  modules_ = out;
  return out;
}

// --- Lifetime ---

void GdbRemoteTarget::detach() {
  if (state_ == TargetState::running) {
    interrupt();
    wait(Clock::now() + std::chrono::seconds(2));
  }
  if (state_ != TargetState::stopped) return;
  for (const auto &b : std::set<std::pair<std::uint64_t, int>>(breakpoints_))
    rsp_->request("z" + std::to_string(b.second) + "," + hexnum(b.first) + "," +
                  std::to_string(b.second <= 1 ? breakpoint_size(b.first) : 1));
  breakpoints_.clear();
  const std::string r = rsp_->request(pid_ && multiprocess_ ? "D;" + hexnum(static_cast<std::uint64_t>(*pid_)) : "D");
  (void)r;
  state_ = TargetState::detached;
  last_stop_ = Stop{};
  last_stop_.kind = StopKind::detached;
  last_stop_.detail = "detached";
}

void GdbRemoteTarget::kill() {
  if (state_ == TargetState::running) {
    interrupt();
    wait(Clock::now() + std::chrono::seconds(2));
  }
  if (state_ == TargetState::exited || state_ == TargetState::disconnected || state_ == TargetState::detached) return;
  try {
    std::string r;
    if (pid_ && multiprocess_) r = rsp_->request("vKill;" + hexnum(static_cast<std::uint64_t>(*pid_)));
    if (r != "OK") {
      rsp_->send("k", Clock::now() + std::chrono::seconds(1));
      rsp_->receive(Clock::now() + std::chrono::milliseconds(300));
    }
  } catch (const DebugError &) {
  }
  state_ = TargetState::exited;
  last_stop_ = Stop{};
  last_stop_.kind = StopKind::killed;
  last_stop_.signal = 9;
  last_stop_.detail = "killed";
}

std::string GdbRemoteTarget::take_output() {
  std::string out = std::move(output_);
  output_.clear();
  if (options_.child) out += options_.child->drain();
  return out;
}

std::string GdbRemoteTarget::monitor(const std::string &command) {
  rsp_->send("qRcmd," + RspClient::to_hex(command), Clock::now() + rsp_->timeout());
  std::string out;
  for (;;) {
    auto r = rsp_->receive(Clock::now() + rsp_->timeout());
    if (!r) throw DebugError("the stub did not answer the monitor command");
    if (r->size() > 1 && (*r)[0] == 'O' && *r != "OK") {
      if (auto v = RspClient::from_hex(std::string_view(*r).substr(1))) out.append(v->begin(), v->end());
      continue;
    }
    if (*r == "OK") return out;
    if (r->empty()) throw DebugError("the stub has no monitor commands");
    if (auto v = RspClient::from_hex(*r)) return out + std::string(v->begin(), v->end());
    return out + *r;
  }
}

}  // namespace revkit::debug
