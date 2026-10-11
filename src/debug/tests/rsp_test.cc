// The remote serial protocol's packet layer, and GdbRemoteTarget against a
// scripted stub (no gdbserver needed): framing, acknowledgements and
// retransmission, run-length and binary encodings, target descriptions with
// includes, register mapping onto SLEIGH names, stop replies.
#include "util.hh"

#include "../xml.hh"

#include <atomic>
#include <functional>
#include <map>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace revkit::debug {
namespace {

TEST(Rsp, Framing) {
  EXPECT_EQ(RspClient::frame("g"), "$g#67");
  EXPECT_EQ(RspClient::frame("OK"), "$OK#9a");
  EXPECT_EQ(RspClient::checksum(""), 0);
  const std::vector<std::uint8_t> bin{'#', '$', '}', '*', 'a', 0};
  const std::string esc = RspClient::escape(bin);
  EXPECT_EQ(esc, std::string("}\x03}\x04}]}\x0a" "a", 9) + std::string(1, '\0'));
  EXPECT_EQ(RspClient::decode(esc), std::string("#$}*a") + std::string(1, '\0'));
  // Run-length: "0* " is '0' and three more ('*' then ' ' = 32 - 29).
  EXPECT_EQ(RspClient::decode("0* "), "0000");
  EXPECT_EQ(RspClient::decode("ab*!c"), "abbbbbc");
  auto v = RspClient::from_hex("00ffxx10");
  ASSERT_TRUE(v);
  EXPECT_EQ(*v, (std::vector<std::uint8_t>{0, 0xff, 0, 0x10}));
  EXPECT_FALSE(RspClient::from_hex("0g"));
  EXPECT_FALSE(RspClient::from_hex("123"));
  EXPECT_EQ(RspClient::to_hex(std::string_view("hi")), "6869");
}

TEST(Rsp, Xml) {
  auto doc = xml::parse(R"(<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0"><!-- c -->
  <architecture>i386:x86-64</architecture>
  <xi:include href="64bit-core.xml"/>
  <feature name="x"><reg name="a&amp;b" bitsize="0x20"/></feature>
</target>)");
  ASSERT_TRUE(doc);
  EXPECT_EQ(doc->name, "target");
  EXPECT_EQ(doc->first("architecture")->text, "i386:x86-64");
  EXPECT_EQ(doc->first("xi:include")->attr_or("href"), "64bit-core.xml");
  EXPECT_EQ(doc->first("feature")->first("reg")->attr_or("name"), "a&b");
  EXPECT_EQ(xml::number("0x20"), 32u);
  EXPECT_FALSE(xml::parse("<a><b></a>"));
  EXPECT_FALSE(xml::parse("<a"));
}

TEST(Rsp, Urls) {
  EXPECT_THROW(connect_url("nonsense"), DebugError);
  EXPECT_THROW(connect_url("127.0.0.1:0"), DebugError);
  EXPECT_THROW(connect_url("127.0.0.1:99999"), DebugError);
  // Nothing listens on this socket.
  EXPECT_THROW(connect_url("unix:/nonexistent/rk.sock", std::chrono::milliseconds(200)), DebugError);
}

// A stub on the other end of a socketpair that answers from a handler.
void put(int fd, const void *p, std::size_t n) {
  if (::write(fd, p, n) != static_cast<ssize_t>(n)) {
  }
}

class FakeStub {
 public:
  using Handler = std::function<std::vector<std::string>(const std::string &)>;
  explicit FakeStub(Handler h, bool corrupt_first = false) : handler_(std::move(h)), corrupt_first_(corrupt_first) {
    int sv[2];
    EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv), 0);
    client_fd_ = sv[0];
    fd_ = sv[1];
    thread_ = std::thread([this] { loop(); });
  }
  ~FakeStub() {
    stop_ = true;
    ::shutdown(fd_, SHUT_RDWR);
    thread_.join();
    ::close(fd_);
  }
  std::unique_ptr<Transport> transport() { return std::make_unique<FdTransport>(client_fd_, client_fd_, "fake"); }
  std::vector<std::string> received;
  std::atomic<int> naks_sent{0};
  bool no_ack = false;

 private:
  void send(const std::string &payload) {
    std::string f = RspClient::frame(payload);
    if (corrupt_first_) {
      corrupt_first_ = false;
      std::string bad = f;
      bad[bad.size() - 1] = bad[bad.size() - 1] == '0' ? '1' : '0';
      put(fd_, bad.data(), bad.size());
      // The client asks again ('-'); resend below when it does.
      pending_resend_ = f;
      return;
    }
    put(fd_, f.data(), f.size());
  }
  void loop() {
    std::string buf;
    char c;
    while (!stop_ && ::read(fd_, &c, 1) == 1) {
      if (c == '-' && !pending_resend_.empty()) {
        put(fd_, pending_resend_.data(), pending_resend_.size());
        pending_resend_.clear();
        continue;
      }
      if (c == 0x03) {
        for (const std::string &r : handler_("\x03")) send(r);
        continue;
      }
      if (c != '$') continue;
      std::string body;
      while (::read(fd_, &c, 1) == 1 && c != '#') body += c;
      char cs[2];
      if (::read(fd_, cs, 2) != 2) return;
      if (!no_ack) put(fd_, "+", 1);
      body = RspClient::decode(body);
      received.push_back(body);
      if (body == "QStartNoAckMode") {
        send("OK");
        no_ack = true;
        continue;
      }
      for (const std::string &r : handler_(body)) send(r);
    }
  }

  Handler handler_;
  bool corrupt_first_;
  std::string pending_resend_;
  int fd_ = -1, client_fd_ = -1;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

TEST(Rsp, RetransmitsOnBadChecksum) {
  FakeStub stub([](const std::string &p) -> std::vector<std::string> {
    if (p == "qC") return {"QC1"};
    return {""};
  }, /*corrupt_first=*/true);
  RspClient c(stub.transport());
  EXPECT_EQ(c.request("qC"), "QC1");
  EXPECT_EQ(c.stats().bad_checksums, 1u);
}

// An x86-64 stub with a description split over an include, registers in
// 'g', memory, breakpoints and a continue that hits one.
std::vector<std::string> x86_stub(const std::string &p, std::map<std::uint64_t, std::uint8_t> &mem, bool &bp, int &resumes) {
  static const std::string target =
      R"(<?xml version="1.0"?><target><architecture>i386:x86-64</architecture><xi:include href="core.xml"/></target>)";
  static const std::string core =
      R"(<feature name="org.gnu.gdb.i386.core"><reg name="rax" bitsize="64" type="int64"/><reg name="rbx" bitsize="64"/>)"
      R"(<reg name="rsp" bitsize="64" type="data_ptr" regnum="7"/><reg name="rip" bitsize="64" type="code_ptr" regnum="16"/>)"
      R"(<reg name="eflags" bitsize="32" type="i386_eflags"/><reg name="fs_base" bitsize="64" regnum="58"/></feature>)";
  auto xfer = [](const std::string &doc, const std::string &req) {
    const auto colon = req.rfind(':');
    const auto comma = req.find(',', colon);
    const std::size_t off = std::stoul(req.substr(colon + 1, comma - colon - 1), nullptr, 16);
    const std::size_t len = std::stoul(req.substr(comma + 1), nullptr, 16);
    if (off >= doc.size()) return std::string("l");
    const std::string part = doc.substr(off, std::min<std::size_t>(len, 40));  // small chunks
    return std::string(off + part.size() >= doc.size() ? "l" : "m") + part;
  };
  if (p.rfind("qSupported", 0) == 0) return {"PacketSize=400;qXfer:features:read+;QStartNoAckMode+;swbreak+"};
  if (p == "?") return {"T05thread:01;"};
  if (p == "vCont?") return {"vCont;c;C;s;S"};
  if (p.rfind("qXfer:features:read:target.xml:", 0) == 0) return {xfer(target, p)};
  if (p.rfind("qXfer:features:read:core.xml:", 0) == 0) return {xfer(core, p)};
  if (p == "qC") return {"QC01"};
  if (p.rfind("Hg", 0) == 0) return {"OK"};
  if (p == "g") {
    // rax=0x1122, rbx=7 (regnums 0, 1); rsp is regnum 7: not in the 'g' run.
    return {"2211000000000000" "0700000000000000"};
  }
  if (p == "p7") return {"00e0ffffff7f0000"};
  if (p == "p10") return {bp ? "1010400000000000" : "0010400000000000"};
  if (p == "p11") return {"46020000"};  // ZF, PF, IF set
  if (p == "p3a") return {"0000000000000000"};
  if (p[0] == 'm') {
    const auto comma = p.find(',');
    const std::uint64_t at = std::stoull(p.substr(1, comma - 1), nullptr, 16);
    const std::size_t len = std::stoul(p.substr(comma + 1), nullptr, 16);
    std::string out;
    for (std::size_t i = 0; i < len; ++i) {
      auto it = mem.find(at + i);
      if (it == mem.end()) return {out.empty() ? "E14" : out};
      char b[3];
      std::snprintf(b, sizeof b, "%02x", it->second);
      out += b;
    }
    return {out};
  }
  if (p[0] == 'X') {
    const auto comma = p.find(','), colon = p.find(':');
    const std::uint64_t at = std::stoull(p.substr(1, comma - 1), nullptr, 16);
    const std::string data = p.substr(colon + 1);
    for (std::size_t i = 0; i < data.size(); ++i) mem[at + i] = static_cast<std::uint8_t>(data[i]);
    return {"OK"};
  }
  if (p.rfind("Z0,", 0) == 0 || p.rfind("z0,", 0) == 0) return {"OK"};
  if (p.rfind("vCont;c", 0) == 0) {
    ++resumes;
    bp = true;
    return {"O68690a", "T05thread:01;swbreak:;10:1010400000000000;"};
  }
  if (p.rfind("vCont;s", 0) == 0) return {"T05thread:01;"};
  if (p == "\x03") return {"T02thread:01;"};
  if (p.rfind("vKill", 0) == 0 || p == "k") return {"OK"};
  if (p == "D") return {"OK"};
  return {""};
}

TEST(GdbRemote, ScriptedX86Stub) {
  if (!testing::ghidra_ready()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
  std::map<std::uint64_t, std::uint8_t> mem;
  for (std::uint64_t a = 0x401000; a < 0x401100; ++a) mem[a] = static_cast<std::uint8_t>(a & 0xff);
  bool bp = false;
  int resumes = 0;
  FakeStub stub([&](const std::string &p) { return x86_stub(p, mem, bp, resumes); });
  GdbRemoteOptions o;
  o.language = "x86:LE:64:default:gcc";
  {
    lift::Lifter l(std::make_shared<const loader::Image>(), "x86:LE:64:default");
    for (const lift::RegisterDef &r : l.registers()) o.sleigh_registers.push_back({r.name, r.size});
  }
  GdbRemoteTarget t(stub.transport(), o);
  EXPECT_TRUE(t.rsp().no_ack());
  EXPECT_EQ(t.architecture(), "i386:x86-64");
  // Names: SLEIGH's where they map.
  ASSERT_NE(t.find_register("RAX"), nullptr);
  EXPECT_EQ(t.find_register("rax")->name, "RAX");
  EXPECT_EQ(t.find_register("eflags")->name, "rflags");
  EXPECT_EQ(t.find_register("fs_base")->name, "FS_OFFSET");
  EXPECT_EQ(t.pc_register(), "RIP");
  EXPECT_EQ(t.sp_register(), "RSP");
  EXPECT_TRUE(t.find_register("RAX")->display);
  EXPECT_EQ(t.read_register_u64("RAX"), 0x1122u);
  EXPECT_EQ(t.read_register_u64("rbx"), 7u);
  EXPECT_EQ(t.sp(), 0x7fffffffe000u);  // by 'p': outside the 'g' run
  EXPECT_EQ(t.pc(), 0x401000u);
  // Flags derived from eflags, as the emulator shows them.
  EXPECT_EQ(t.read_register_u64("ZF"), 1u);
  EXPECT_EQ(t.read_register_u64("CF"), 0u);
  EXPECT_EQ(t.read_register_u64("IF"), 1u);
  // Memory: a hole is reported, not an error.
  std::vector<std::uint8_t> buf(0x200);
  std::vector<ByteRange> holes;
  EXPECT_EQ(t.read_memory(0x401000, buf, &holes), 0x100u);
  EXPECT_EQ(buf[0x10], 0x10);
  ASSERT_EQ(holes.size(), 1u);
  EXPECT_EQ(holes[0].offset, 0x100u);
  const std::vector<std::uint8_t> w{'#', '$', 1};
  EXPECT_TRUE(t.write_memory(0x401004, w));
  EXPECT_EQ(mem[0x401004], '#');
  EXPECT_EQ(mem[0x401005], '$');
  // A breakpoint, a continue that prints and stops on it.
  t.insert_breakpoint(BreakKind::software, 0x401010, 0);
  ResumeOptions ro;
  ro.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  Stop s = t.resume(ro);
  EXPECT_EQ(s.kind, StopKind::breakpoint);
  EXPECT_EQ(s.pc, 0x401010u);
  EXPECT_EQ(t.take_output(), "hi\n");
  ro.mode = RunMode::step_into;
  s = t.resume(ro);
  EXPECT_EQ(s.kind, StopKind::stepped);
  EXPECT_EQ(resumes, 1);
}

TEST(GdbRemote, RegisterNames) {
  std::vector<SleighRegister> x86{{"RAX", 8}, {"rflags", 8}, {"FS_OFFSET", 8}, {"RIP", 8}};
  EXPECT_EQ(map_register_name("x86:LE:64:default", "rax", 8, x86), "RAX");
  EXPECT_EQ(map_register_name("x86:LE:64:default", "eflags", 4, x86), "rflags");
  EXPECT_EQ(map_register_name("x86:LE:64:default", "orig_rax", 8, x86), "");
  EXPECT_EQ(map_register_name("x86:LE:64:default", "fs_base", 8, x86), "FS_OFFSET");
  std::vector<SleighRegister> a64{{"x0", 8}, {"q5", 16}, {"sp", 8}};
  EXPECT_EQ(map_register_name("AARCH64:LE:64:v8A", "v5", 16, a64), "q5");
  EXPECT_EQ(map_register_name("AARCH64:LE:64:v8A", "cpsr", 4, a64), "");
  EXPECT_EQ(map_register_name("AARCH64:LE:64:v8A", "x0", 8, a64), "x0");
  // A wider stub register doesn't map onto a narrower SLEIGH one.
  EXPECT_EQ(map_register_name("AARCH64:LE:64:v8A", "sp", 16, a64), "");
}

}  // namespace
}  // namespace revkit::debug
