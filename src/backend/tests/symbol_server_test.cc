// Symbol paths, stores, servers and .pd_ cabinets (docs/pdb.md "Symbol
// servers"), with the clang-cl fixture's PDB (tests/data/msvc). The server
// is a local HTTP server on a test port, never a real one.
#include "../../msvc/tests/msvc_fixture.h"

#include "symbol_server.h"

#include "revkit/debuginfo/pdb.h"

#include <gtest/gtest.h>
#include <httplib.h>
#include <zlib.h>

#include <fstream>
#include <thread>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;

std::string Read(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}
void Write(const fs::path &p, std::string_view s) {
  fs::create_directories(p.parent_path());
  std::ofstream(p, std::ios::binary) << s;
}

void Put16(std::string &s, std::uint16_t v) {
  s.push_back(static_cast<char>(v));
  s.push_back(static_cast<char>(v >> 8));
}
void Put32(std::string &s, std::uint32_t v) {
  Put16(s, static_cast<std::uint16_t>(v));
  Put16(s, static_cast<std::uint16_t>(v >> 16));
}

// A one-file cabinet as makecab writes a .pd_: one folder of MSZIP blocks
// (each block's deflate stream may use the 32 KiB before it), or stored.
std::string Cabinet(const std::string &name, const std::string &data, bool mszip) {
  std::vector<std::string> blocks;
  std::string window;
  for (std::size_t at = 0; at < data.size() || blocks.empty(); at += 32768) {
    const std::string chunk = data.substr(at, 32768);
    if (!mszip) {
      blocks.push_back(chunk);
      continue;
    }
    z_stream z{};
    deflateInit2(&z, 9, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    if (!window.empty()) deflateSetDictionary(&z, reinterpret_cast<const Bytef *>(window.data()), static_cast<uInt>(window.size()));
    std::string out(chunk.size() + 1024, '\0');
    z.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(chunk.data()));
    z.avail_in = static_cast<uInt>(chunk.size());
    z.next_out = reinterpret_cast<Bytef *>(out.data());
    z.avail_out = static_cast<uInt>(out.size());
    deflate(&z, Z_FINISH);
    out.resize(out.size() - z.avail_out);
    deflateEnd(&z);
    blocks.push_back("CK" + out);
    window = data.substr(0, at + chunk.size());
    if (window.size() > 32768) window = window.substr(window.size() - 32768);
  }
  const std::uint32_t header = 36, folder = 8, file = 16 + static_cast<std::uint32_t>(name.size()) + 1;
  std::string cab = "MSCF";
  Put32(cab, 0);
  const std::size_t size_at = cab.size();
  Put32(cab, 0);  // cbCabinet, set below
  Put32(cab, 0);
  Put32(cab, header + folder);  // coffFiles
  Put32(cab, 0);
  cab.push_back(3);
  cab.push_back(1);
  Put16(cab, 1);  // folders
  Put16(cab, 1);  // files
  Put16(cab, 0);  // flags
  Put16(cab, 0);
  Put16(cab, 0);
  Put32(cab, header + folder + file);  // the folder's first data block
  Put16(cab, static_cast<std::uint16_t>(blocks.size()));
  Put16(cab, mszip ? 1 : 0);
  Put32(cab, static_cast<std::uint32_t>(data.size()));
  Put32(cab, 0);
  Put16(cab, 0);
  Put16(cab, 0);
  Put16(cab, 0);
  Put16(cab, 0x20);
  cab += name;
  cab.push_back('\0');
  std::size_t at = 0;
  for (const std::string &b : blocks) {
    const std::size_t n = std::min<std::size_t>(32768, data.size() - std::min(at, data.size()));
    Put32(cab, 0);
    Put16(cab, static_cast<std::uint16_t>(b.size()));
    Put16(cab, static_cast<std::uint16_t>(n));
    cab += b;
    at += n;
  }
  const std::uint32_t total = static_cast<std::uint32_t>(cab.size());
  for (int i = 0; i < 4; ++i) cab[size_at + static_cast<std::size_t>(i)] = static_cast<char>(total >> (8 * i));
  return cab;
}

TEST(SymbolPath, ParsesNtSymbolPath) {
  std::string error;
  auto p = ParseSymbolPath("srv*C:\\sym*https://msdl.microsoft.com/download/symbols/; D:\\pdbs ;cache*/var/c;;"
                           "srv*/srv/store;symsrv*symsrv.dll*/x*http://h:8/s",
                           &error);
  EXPECT_EQ(error, "");
  ASSERT_EQ(p.size(), 7u);
  EXPECT_EQ(p[0].kind, SymbolPathEntry::Kind::store);  // the server's downstream store, looked in first
  EXPECT_EQ(p[0].location, "C:\\sym");
  EXPECT_EQ(p[1].kind, SymbolPathEntry::Kind::server);
  EXPECT_EQ(p[1].location, "https://msdl.microsoft.com/download/symbols");
  EXPECT_EQ(p[1].cache, "C:\\sym");
  EXPECT_EQ(p[2].kind, SymbolPathEntry::Kind::directory);
  EXPECT_EQ(p[2].location, "D:\\pdbs");
  EXPECT_EQ(p[3].kind, SymbolPathEntry::Kind::store);
  EXPECT_EQ(p[3].location, "/var/c");
  EXPECT_EQ(p[4].location, "/srv/store");
  EXPECT_EQ(p[5].location, "/x");
  EXPECT_EQ(p[6].kind, SymbolPathEntry::Kind::server);
  EXPECT_EQ(p[6].location, "http://h:8/s");
  ParseSymbolPath("srv*", &error);
  EXPECT_NE(error, "");
}

TEST(SymbolPath, KeyIsGuidAndAgeInHex) {
  debuginfo::PdbGuid g{0x24, 0x03, 0x4f, 0xf0, 0x2a, 0x58, 0xb2, 0xfe, 0x4c, 0x4c, 0x44, 0x20, 0x50, 0x44, 0x42, 0x2e};
  EXPECT_EQ(SymbolKey(g, 1), "F04F0324582AFEB24C4C44205044422E1");
  EXPECT_EQ(SymbolKey(g, 0x1a), "F04F0324582AFEB24C4C44205044422E1A");
}

TEST(SymbolPath, ExpandsCabinets) {
  std::string data;
  for (int i = 0; i < 100000; ++i) data += static_cast<char>((i * 7) % 251);  // several blocks
  for (bool mszip : {true, false}) {
    std::string out;
    EXPECT_EQ(ExpandCabinet(Cabinet("x.pdb", data, mszip), out), "") << mszip;
    EXPECT_EQ(out, data) << mszip;
  }
  std::string out;
  EXPECT_NE(ExpandCabinet("MSCF garbage", out), "");
  std::string lzx = Cabinet("x.pdb", data, false);
  lzx[36 + 6] = 3;  // the folder's compression: LZX
  EXPECT_NE(ExpandCabinet(lzx, out).find("LZX"), std::string::npos);
  // Offsets near 2^32 wrapped the 32-bit bounds checks and read ~4 GiB past
  // the cabinet: coffFiles, then the folder's first data block.
  for (std::size_t field : {std::size_t{16}, std::size_t{36}}) {
    std::string bad = Cabinet("x.pdb", data, true);
    bad[field] = '\xf8';
    bad[field + 1] = bad[field + 2] = bad[field + 3] = '\xff';
    EXPECT_NE(ExpandCabinet(bad, out), "") << field;
  }
}

class SymbolStoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    static std::optional<msvc::testing::Fixture> fx =
        msvc::testing::build_fixture(REVKIT_TEST_CLANG, REVKIT_TEST_LLD_LINK, REVKIT_MSVC_FIXTURE, "x86_64");
    if (!fx) GTEST_SKIP() << "clang or lld-link missing, or the fixture didn't build";
    pdb_ = Read(fx->pdb);
    const auto id = debuginfo::read_pdb_identity(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(pdb_.data()), pdb_.size()));
    guid_ = id.guid;
    age_ = id.age;
    key_ = SymbolKey(guid_, age_);
    dir_ = fs::temp_directory_path() / ("revkit-symbols-" + std::to_string(::getpid()) + "-" +
                                        ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(dir_);
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(dir_, ec);
  }
  std::string pdb_, key_;
  debuginfo::PdbGuid guid_{};
  std::uint32_t age_ = 0;
  fs::path dir_;
};

TEST_F(SymbolStoreTest, FindsInStoresAndDirectories) {
  // Another build's PDB first in the path: skipped.
  Write(dir_ / "flat" / "classes-x86_64.pdb", pdb_);
  Write(dir_ / "store" / "classes-x86_64.pdb" / key_ / "classes-x86_64.pd_", Cabinet("classes-x86_64.pdb", pdb_, true));
  SymbolSettings s;
  s.path = "srv*" + (dir_ / "store").string() + ";" + (dir_ / "flat").string();
  std::vector<std::string> log;
  auto f = FindPdb(s, "C:\\build\\classes-x86_64.pdb", guid_, age_, log);
  ASSERT_TRUE(f) << ::testing::PrintToString(log);
  EXPECT_EQ(f->file, dir_ / "store" / "classes-x86_64.pdb" / key_ / "classes-x86_64.pdb");  // the .pd_, expanded
  EXPECT_EQ(Read(f->file), pdb_);
  EXPECT_FALSE(f->downloaded);
  // A different age: in no store.
  log.clear();
  EXPECT_FALSE(FindPdb(s, "classes-x86_64.pdb", guid_, age_ + 1, log));
  // The flat directory.
  s.path = (dir_ / "flat").string();
  log.clear();
  f = FindPdb(s, "classes-x86_64.pdb", guid_, age_, log);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->source, "directory " + (dir_ / "flat").string());
  // No path names: refused.
  log.clear();
  EXPECT_FALSE(FindPdb(s, "../../etc/passwd", guid_, age_, log));
}

TEST_F(SymbolStoreTest, DownloadsFromAServerOnlyWhenAllowed) {
  httplib::Server server;
  std::vector<std::string> asked;
  std::mutex mu;
  const std::string pd_ = Cabinet("classes-x86_64.pdb", pdb_, true);
  server.Get(R"(/symbols/(.*))", [&](const httplib::Request &req, httplib::Response &res) {
    {
      std::lock_guard lock(mu);
      asked.push_back(req.path);
    }
    if (req.path == "/symbols/classes-x86_64.pdb/" + key_ + "/classes-x86_64.pd_") {
      res.set_content(pd_, "application/octet-stream");
    } else {
      res.status = 404;
    }
  });
  // A port of its own: httplib binds with SO_REUSEPORT, so a fixed port
  // shared with another run of this test split the requests between them.
  const int port = server.bind_to_any_port("127.0.0.1");
  ASSERT_GT(port, 0);
  std::thread t([&] { server.listen_after_bind(); });
  const fs::path cache = dir_ / "cache";
  SymbolSettings s;
  s.path = "srv*" + cache.string() + "*http://127.0.0.1:" + std::to_string(port) + "/symbols";
  std::vector<std::string> log;
  // Downloads off: the server isn't contacted.
  EXPECT_FALSE(FindPdb(s, "classes-x86_64.pdb", guid_, age_, log));
  {
    std::lock_guard lock(mu);
    EXPECT_TRUE(asked.empty());
  }
  // On: the .pdb is missing, the .pd_ is fetched, expanded into the cache.
  s.downloads = true;
  log.clear();
  auto f = FindPdb(s, "classes-x86_64.pdb", guid_, age_, log);
  ASSERT_TRUE(f) << ::testing::PrintToString(log);
  EXPECT_TRUE(f->downloaded);
  EXPECT_EQ(f->file, cache / "classes-x86_64.pdb" / key_ / "classes-x86_64.pdb");
  EXPECT_EQ(Read(f->file), pdb_);
  {
    std::lock_guard lock(mu);
    ASSERT_EQ(asked.size(), 2u);
    EXPECT_EQ(asked[0], "/symbols/classes-x86_64.pdb/" + key_ + "/classes-x86_64.pdb");
  }
  // Again: from the cache, without asking.
  log.clear();
  f = FindPdb(s, "classes-x86_64.pdb", guid_, age_, log);
  ASSERT_TRUE(f);
  EXPECT_FALSE(f->downloaded);
  {
    std::lock_guard lock(mu);
    EXPECT_EQ(asked.size(), 2u);
  }
  server.stop();
  t.join();
}

}  // namespace
}  // namespace revkit::backend
