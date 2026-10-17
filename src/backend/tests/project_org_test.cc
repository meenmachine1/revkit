// api_minor 37 on the image backend: folders in a project, and project
// archives (.rkproj): the container's checks on hostile input, and the
// round trip a user relies on, an export imported into a fresh project
// answering every question as the original did.
#include "project_archive.h"
#include "sync_util.h"

#include "revkit/backend/image_backend.h"

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <zlib.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace revkit::backend {
namespace {

namespace pb = ::revkit::v1;
namespace fs = std::filesystem;
using api::CallContext;
using api::StatusCode;

pb::Provenance User(const std::string &who = "alice") {
  pb::Provenance p;
  p.set_kind(pb::PROVENANCE_KIND_USER);
  p.set_id(who);
  return p;
}

fs::path Corpus(const std::string &rel) { return fs::path(REVKIT_CORPUS) / rel; }

// Under one directory per process, removed when the process exits.
fs::path Scratch(const std::string &name) {
  struct Root {
    fs::path path = fs::temp_directory_path() / ("revkit-project-org-" + std::to_string(::getpid()));
    ~Root() {
      std::error_code ec;
      if (!std::getenv("RK_KEEP_TEST_DIRS")) fs::remove_all(path, ec);
    }
  };
  static Root root;
  fs::path d = root.path / name;
  fs::remove_all(d);
  fs::create_directories(d);
  return d;
}

// --- The container, without a daemon -----------------------------------------

std::string Hex64(char c) { return std::string(64, c); }

std::string Sha256Of(const std::string &data) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr);
  std::string out;
  char buf[3];
  for (unsigned i = 0; i < len; ++i) {
    std::snprintf(buf, sizeof buf, "%02x", md[i]);
    out += buf;
  }
  return out;
}

struct Collect final : archive::MemberSink {
  std::map<std::string, std::string> got;
  std::string current;
  void begin(const archive::Member &m) override {
    current = m.kind == archive::Member::kLog ? "log" : m.kind == archive::Member::kProgram ? "p" + std::to_string(m.program)
                                                                                             : "r";
    got[current].clear();
  }
  void data(std::string_view b) override { got[current].append(b); }
  void end(bool) override {}
};

// A small valid archive: one program, its bytes, an empty log (the log is
// validated separately).
struct Built {
  pb::ProjectArchiveManifest manifest;
  std::string bytes;
};

Built Build(const std::function<void(pb::ProjectArchiveManifest &)> &tweak = {},
            const std::function<void(archive::Writer &, const pb::ProjectArchiveManifest &)> &members = {}) {
  Built b;
  const std::string program = "\x7f" "ELF fake program bytes";
  const std::string log = archive::LogHeader();
  auto &m = b.manifest;
  m.set_format(std::string(archive::kFormat));
  m.set_format_version(archive::kFormatVersion);
  m.set_op_format(archive::kOpFormat);
  m.set_project_name("demo");
  m.add_folders("/a");
  m.add_folders("/a/b");
  auto *p = m.add_programs();
  p->set_key("p0");
  p->set_name("prog");
  p->set_program_id("demo/prog");
  p->set_sha256(Sha256Of(program));
  p->set_size(program.size());
  p->set_folder("/a/b");
  p->set_has_binary(true);
  p->set_ordinal(7);
  m.mutable_log()->set_path("log.bin");
  m.mutable_log()->set_size(log.size());
  m.mutable_log()->set_sha256(Sha256Of(log));
  if (tweak) tweak(m);
  archive::Writer w([&](std::string_view s) {
    b.bytes.append(s);
    return true;
  });
  EXPECT_TRUE(w.add_file(archive::kManifestPath, archive::ManifestJson(m)));
  if (members) {
    members(w, m);
  } else {
    EXPECT_TRUE(w.add_file("log.bin", log));
    EXPECT_TRUE(w.add_file("programs/p0/program.bin", program));
  }
  EXPECT_TRUE(w.finish());
  return b;
}

std::optional<archive::Error> Read(const std::string &bytes, Collect &sink, pb::ProjectArchiveManifest &m,
                                   archive::Limits limits = {}) {
  std::size_t at = 0;
  archive::Source src = [&](char *buf, std::size_t n) {
    const std::size_t take = std::min(n, bytes.size() - at);
    std::memcpy(buf, bytes.data() + at, take);
    at += take;
    return take;
  };
  return archive::ReadArchive(src, limits, m, sink);
}

TEST(ProjectArchiveContainer, ReadsWhatItWrites) {
  Built b = Build();
  Collect sink;
  pb::ProjectArchiveManifest m;
  auto e = Read(b.bytes, sink, m);
  ASSERT_FALSE(e) << e->message;
  EXPECT_EQ(m.project_name(), "demo");
  EXPECT_EQ(sink.got["p0"], "\x7f" "ELF fake program bytes");
  EXPECT_EQ(sink.got["log"], archive::LogHeader());
}

TEST(ProjectArchiveContainer, RefusesNewerVersionsClearly) {
  Built b = Build([](pb::ProjectArchiveManifest &m) { m.set_format_version(archive::kFormatVersion + 1); });
  Collect sink;
  pb::ProjectArchiveManifest m;
  auto e = Read(b.bytes, sink, m);
  ASSERT_TRUE(e);
  EXPECT_TRUE(e->unsupported);
  EXPECT_NE(e->message.find("newer than this revkit reads"), std::string::npos) << e->message;
  // A future version may add manifest fields: still the version message.
  Built c = Build([](pb::ProjectArchiveManifest &m) { m.set_format_version(9); });
  std::string json = archive::ManifestJson(c.manifest);
  json.insert(json.find('{') + 1, "\"some_new_field\": 1,");
  std::string bytes;
  archive::Writer w([&](std::string_view s) {
    bytes.append(s);
    return true;
  });
  ASSERT_TRUE(w.add_file("manifest.json", json) && w.finish());
  e = Read(bytes, sink, m);
  ASSERT_TRUE(e);
  EXPECT_TRUE(e->unsupported) << e->message;
  Built d = Build([](pb::ProjectArchiveManifest &m) { m.set_format("something-else"); });
  e = Read(d.bytes, sink, m);
  ASSERT_TRUE(e);
  EXPECT_TRUE(e->unsupported);
}

TEST(ProjectArchiveContainer, RefusesWhatTheManifestDoesntDeclare) {
  struct Case {
    const char *what;
    std::function<void(archive::Writer &, const pb::ProjectArchiveManifest &)> members;
    const char *expect;
  };
  const std::string program = "\x7f" "ELF fake program bytes";
  const std::string log = archive::LogHeader();
  std::vector<Case> cases = {
      {"a path that climbs out",
       [&](archive::Writer &w, const auto &) {
         w.add_file("log.bin", log);
         w.add_file("../../etc/passwd", "x");
       },
       "doesn't declare"},
      {"an absolute path",
       [&](archive::Writer &w, const auto &) {
         w.add_file("log.bin", log);
         w.add_file("/tmp/x", "x");
       },
       "doesn't declare"},
      {"a missing member", [&](archive::Writer &w, const auto &) { w.add_file("log.bin", log); }, "missing"},
      {"a member twice",
       [&](archive::Writer &w, const auto &) {
         w.add_file("log.bin", log);
         w.add_file("log.bin", log);
       },
       "twice"},
      {"a wrong size",
       [&](archive::Writer &w, const auto &) {
         w.add_file("log.bin", log);
         w.add_file("programs/p0/program.bin", program + "x");
       },
       "size"},
      {"a wrong hash",
       [&](archive::Writer &w, const auto &) {
         w.add_file("log.bin", log);
         std::string other = program;
         other[3] ^= 1;
         w.add_file("programs/p0/program.bin", other);
       },
       "sha256"},
      {"a member after the declared ones",
       [&](archive::Writer &w, const auto &) {
         w.add_file("log.bin", log);
         w.add_file("programs/p0/program.bin", program);
         w.add_file("extra", "x");
       },
       "doesn't declare"},
  };
  for (const Case &c : cases) {
    Built b = Build({}, c.members);
    Collect sink;
    pb::ProjectArchiveManifest m;
    auto e = Read(b.bytes, sink, m);
    ASSERT_TRUE(e) << c.what;
    EXPECT_FALSE(e->unsupported) << c.what;
    EXPECT_NE(e->message.find(c.expect), std::string::npos) << c.what << ": " << e->message;
  }
}

TEST(ProjectArchiveContainer, RefusesBadManifests) {
  std::vector<std::pair<const char *, std::function<void(pb::ProjectArchiveManifest &)>>> cases = {
      {"a folder path with ..", [](auto &m) { m.set_folders(0, "/.."); }},
      {"a folder before its parent", [](auto &m) { m.mutable_folders()->SwapElements(0, 1); }},
      {"a program name with a slash", [](auto &m) { m.mutable_programs(0)->set_name("a/b"); }},
      {"a program in an unknown folder", [](auto &m) { m.mutable_programs(0)->set_folder("/nowhere"); }},
      {"a bad hash", [](auto &m) { m.mutable_programs(0)->set_sha256("zz"); }},
      {"a huge program", [](auto &m) { m.mutable_programs(0)->set_size(std::uint64_t{1} << 40); }},
      {"a bad key", [](auto &m) { m.mutable_programs(0)->set_key("../p0"); }},
      {"an ordinal out of range", [](auto &m) { m.mutable_programs(0)->set_ordinal(99999); }},
      {"bytes in an annotations-only archive", [](auto &m) { m.set_annotations_only(true); }},
      {"a region at a bad path",
       [](auto &m) {
         auto *r = m.mutable_programs(0)->add_regions();
         r->set_sha256(Hex64('a'));
         r->set_path("programs/p0/regions/../../x.bin");
         r->set_size(4);
         r->set_offset(std::uint64_t{1} << 62);
       }},
      {"the log elsewhere", [](auto &m) { m.mutable_log()->set_path("../log.bin"); }},
  };
  for (const auto &[what, tweak] : cases) {
    Built b = Build(tweak);
    Collect sink;
    pb::ProjectArchiveManifest m;
    auto e = Read(b.bytes, sink, m);
    ASSERT_TRUE(e) << what;
    EXPECT_FALSE(e->unsupported) << what << ": " << e->message;
  }
}

// A decompression bomb: a manifest that declares little, then gigabytes of
// zeros in a member it doesn't declare, or as an over-long manifest. The
// reader stops at what was declared, never decompressing the rest.
TEST(ProjectArchiveContainer, StopsAtWhatTheManifestDeclares) {
  std::uint64_t pulled = 0;
  std::string bomb;
  {
    archive::Writer w(
        [&](std::string_view s) {
          bomb.append(s);
          return true;
        },
        1);
    ASSERT_TRUE(w.begin_file("manifest.json", std::uint64_t{1} << 30));
    const std::string zeros(1 << 20, ' ');
    for (int i = 0; i < 1024; ++i) ASSERT_TRUE(w.write(zeros));  // 1 GiB
    ASSERT_TRUE(w.end_file() && w.finish());
  }
  EXPECT_LT(bomb.size(), 8u << 20);
  Collect sink;
  pb::ProjectArchiveManifest m;
  std::size_t at = 0;
  archive::Source src = [&](char *buf, std::size_t n) {
    const std::size_t take = std::min(n, bomb.size() - at);
    std::memcpy(buf, bomb.data() + at, take);
    at += take;
    pulled += take;
    return take;
  };
  auto e = archive::ReadArchive(src, {}, m, sink);
  ASSERT_TRUE(e);
  EXPECT_NE(e->message.find("manifest.json is over the size limit"), std::string::npos) << e->message;
  EXPECT_LT(pulled, 1u << 20);  // it never inflated the gigabyte

  // Declared members, then a huge undeclared one: refused at its header.
  Built b = Build({}, [&](archive::Writer &w, const auto &) {
    w.add_file("log.bin", archive::LogHeader());
    w.add_file("programs/p0/program.bin", "\x7f" "ELF fake program bytes");
    w.add_file("more", std::string(1 << 20, '\0'));
  });
  e = Read(b.bytes, sink, m);
  ASSERT_TRUE(e);
  EXPECT_NE(e->message.find("doesn't declare"), std::string::npos) << e->message;
}

TEST(ProjectArchiveContainer, RefusesLinksAndGarbage) {
  Built b = Build();
  // Make the second member a symbolic link (typeflag '2'), fixing the
  // checksum: decompress, edit, recompress.
  std::string tar;
  {
    z_stream z{};
    inflateInit2(&z, 15 + 16);
    z.next_in = reinterpret_cast<Bytef *>(b.bytes.data());
    z.avail_in = static_cast<uInt>(b.bytes.size());
    char out[65536];
    int rc;
    do {
      z.next_out = reinterpret_cast<Bytef *>(out);
      z.avail_out = sizeof out;
      rc = inflate(&z, Z_NO_FLUSH);
      tar.append(out, sizeof out - z.avail_out);
    } while (rc == Z_OK);
    inflateEnd(&z);
  }
  const std::size_t manifest_size = archive::ManifestJson(b.manifest).size();
  const std::size_t second = 512 + (manifest_size + 511) / 512 * 512;
  tar[second + 156] = '2';
  std::memset(tar.data() + second + 148, ' ', 8);
  unsigned sum = 0;
  for (std::size_t i = 0; i < 512; ++i) sum += static_cast<unsigned char>(tar[second + i]);
  std::snprintf(tar.data() + second + 148, 8, "%06o", sum);
  std::string gz;
  // Recompress as a plain gzip stream.
  {
    z_stream z{};
    deflateInit2(&z, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    z.next_in = reinterpret_cast<Bytef *>(tar.data());
    z.avail_in = static_cast<uInt>(tar.size());
    char out[65536];
    gz.clear();
    int rc;
    do {
      z.next_out = reinterpret_cast<Bytef *>(out);
      z.avail_out = sizeof out;
      rc = deflate(&z, Z_FINISH);
      gz.append(out, sizeof out - z.avail_out);
    } while (rc == Z_OK);
    deflateEnd(&z);
  }
  Collect sink;
  pb::ProjectArchiveManifest m;
  auto e = Read(gz, sink, m);
  ASSERT_TRUE(e);
  EXPECT_NE(e->message.find("not a regular file"), std::string::npos) << e->message;

  e = Read("this is not a gzip stream at all", sink, m);
  ASSERT_TRUE(e);
  EXPECT_NE(e->message.find("gzip"), std::string::npos) << e->message;
  e = Read(b.bytes.substr(0, b.bytes.size() / 2), sink, m);
  ASSERT_TRUE(e);
}

TEST(ProjectArchiveContainer, ValidatesTheOps) {
  pb::ProjectArchiveManifest m = Build().manifest;
  const facts::SpaceId space = archive::RamSpace(7);
  auto op = [&](std::uint64_t counter, facts::FactKey key, facts::FactValue v) {
    facts::Op o;
    o.kind = facts::OpKind::Assert;
    o.key = std::move(key);
    o.value = std::move(v);
    o.id = {42, counter};
    o.stamp = counter;
    return o;
  };
  ProgramSource src;
  src.id = "demo/prog";
  src.name = "prog";
  src.sha256 = m.programs(0).sha256();
  src.file_size = m.programs(0).size();
  src.ordinal = 7;
  src.ram_space = archive::RamSpace(7);
  src.file_space = archive::FileSpace(7);
  src.path = "/home/someone/prog";
  std::vector<facts::Op> ops = {
      op(1, facts::FactKey{facts::FactKind::Note, {archive::kProjectSpace, 7}, "program"}, facts::encode_to_string(src)),
      op(2, facts::FactKey::name({space, 0x1000}), std::string("main")),
  };
  m.mutable_log()->set_count(ops.size());
  std::vector<int> owner;
  auto e = archive::ValidateLog(m, ops, {}, owner);
  ASSERT_FALSE(e) << e->message;
  EXPECT_EQ(owner, (std::vector<int>{0, 0}));

  // Rewritten for a target: new ids, spaces, a fresh replica, no host path.
  std::vector<archive::ProgramPlan> plans(1);
  plans[0] = {true, "copy/prog", "prog", 3};
  auto rw = archive::RewriteLog(m, ops, owner, plans, [] { return facts::ReplicaId{77}; });
  ASSERT_EQ(rw.ops.size(), 2u);
  EXPECT_EQ(rw.ops[1].key.addr.space, archive::RamSpace(3));
  EXPECT_EQ(rw.ops[0].key.addr.offset, 3u);
  EXPECT_EQ(rw.ops[1].id, (facts::OpId{77, 2}));
  ASSERT_TRUE(rw.sources[0]);
  EXPECT_EQ(rw.sources[0]->id, "copy/prog");
  EXPECT_TRUE(rw.sources[0]->path.empty());

  auto refused = [&](std::vector<facts::Op> bad, const char *expect) {
    m.mutable_log()->set_count(bad.size());
    auto e = archive::ValidateLog(m, bad, {}, owner);
    ASSERT_TRUE(e) << expect;
    EXPECT_NE(e->message.find(expect), std::string::npos) << e->message;
  };
  auto other = ops;
  other.push_back(op(3, facts::FactKey::name({space + 2, 0x1000}), std::string("x")));
  refused(other, "no program's space");
  other = ops;
  other.push_back(op(3, facts::FactKey::name({space, 0x1000}), std::int64_t{5}));
  refused(other, "isn't text");
  other = ops;
  facts::Op r = op(3, facts::FactKey::name({space, 0x1000}), {});
  r.kind = facts::OpKind::Retract;
  r.target_id = {42, 9};
  other.push_back(r);
  refused(other, "retracts no earlier op");
  other = ops;
  other.push_back(op(2, facts::FactKey::name({space, 0x2000}), std::string("y")));
  refused(other, "repeats");
  // A stamp past the clock's next day (UINT64_MAX wrapped the importer's
  // clock to 0): refused when the importer bounds stamps, as it does.
  {
    other = ops;
    other.push_back(op(3, facts::FactKey::name({space, 0x2000}), std::string("y")));
    other.back().stamp = UINT64_MAX;
    archive::Limits bounded;
    bounded.max_stamp = archive::FutureStampLimit();
    m.mutable_log()->set_count(other.size());
    auto future = archive::ValidateLog(m, other, bounded, owner);
    ASSERT_TRUE(future);
    EXPECT_NE(future->message.find("past this daemon's clock"), std::string::npos) << future->message;
    other.back().stamp = bounded.max_stamp - (std::uint64_t{48} * 3600 * 1000 << facts::kStampLogicalBits);
    EXPECT_FALSE(archive::ValidateLog(m, other, bounded, owner));
  }
  other = {ops[1]};
  refused(other, "has no record");
  other = ops;
  src.sha256 = Hex64('b');
  other[0].value = facts::encode_to_string(src);
  refused(other, "doesn't match its manifest");
  other = ops;
  other.push_back(op(3, facts::FactKey{facts::FactKind::Note, {archive::kProjectSpace, archive::kFolderAddress},
                                       "revkit:folder:0123456789abcdef"},
                     std::string("/x")));
  refused(other, "unknown kind");

  std::vector<facts::Op> decoded;
  EXPECT_TRUE(archive::DecodeLog("garbage", {}, decoded));
  std::string log = archive::LogHeader();
  archive::AppendLogOp(log, ops[1]);
  EXPECT_FALSE(archive::DecodeLog(log, {}, decoded));
  log += "\x05garb";
  EXPECT_TRUE(archive::DecodeLog(log, {}, decoded));
}

// --- Folders and archives on the image backend --------------------------------

class ProjectOrgTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (std::string(REVKIT_GHIDRA_ROOT).empty()) GTEST_SKIP() << "GHIDRA_ROOT not configured";
    if (!fs::exists(Corpus("elf-x86_64/gcc-O2/debug/cjson"))) GTEST_SKIP() << "no corpus";
    backend_ = Make({});
  }

  std::unique_ptr<api::Backend> Make(const fs::path &project_dir) {
    ImageBackendOptions o;
    o.ghidra_root = REVKIT_GHIDRA_ROOT;
    o.project_dir = project_dir.string();
    o.param_id = inputs::ParamIdMode::off;
    o.server_version = "rk-test";
    return MakeImageBackend(o);
  }

  std::string Import(api::Backend &b, const fs::path &file, const std::string &name, const std::string &project = "default") {
    pb::ImportProgramRequest req;
    req.set_project_id(project);
    req.set_path(file.string());
    req.set_name(name);
    pb::ImportProgramResponse resp;
    auto st = b.ImportProgram(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp.program().program_id();
  }

  pb::ListProgramsResponse List(api::Backend &b, const std::string &project = "default", bool deleted = false) {
    pb::ListProgramsRequest req;
    req.set_project_id(project);
    req.set_include_deleted(deleted);
    pb::ListProgramsResponse resp;
    auto st = b.ListPrograms(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  std::string Mkdir(api::Backend &b, const std::string &parent, const std::string &name, api::Status *status = nullptr,
                    const std::string &project = "default") {
    pb::CreateFolderRequest req;
    req.set_project_id(project);
    req.set_parent_id(parent);
    req.set_name(name);
    *req.mutable_provenance() = User();
    pb::CreateFolderResponse resp;
    auto st = b.CreateFolder(ctx_, req, resp);
    if (status) *status = st;
    else EXPECT_TRUE(st.ok()) << st.message;
    return resp.folder().folder_id();
  }

  api::Status Move(api::Backend &b, const std::string &dest, std::vector<std::string> programs,
                   std::vector<std::string> folders, pb::MoveToFolderResponse *out = nullptr) {
    pb::MoveToFolderRequest req;
    req.set_project_id("default");
    req.set_folder_id(dest);
    for (auto &p : programs) req.add_program_ids(p);
    for (auto &f : folders) req.add_folder_ids(f);
    *req.mutable_provenance() = User();
    pb::MoveToFolderResponse resp;
    auto st = b.MoveToFolder(ctx_, req, resp);
    if (out) *out = resp;
    return st;
  }

  static std::map<std::string, std::string> FolderOf(const pb::ListProgramsResponse &l) {
    std::map<std::string, std::string> out;
    for (const auto &p : l.programs()) out[p.name()] = p.folder_path();
    return out;
  }
  static std::vector<std::string> Paths(const pb::ListProgramsResponse &l) {
    std::vector<std::string> out;
    for (const auto &f : l.folders()) out.push_back(f.path());
    return out;
  }

  std::string Export(api::Backend &b, pb::ExportProjectRequest req, pb::ExportSummary *summary = nullptr) {
    if (req.project_id().empty()) req.set_project_id("default");
    std::string out;
    bool first = true;
    auto st = b.ExportProject(ctx_, req, [&](const pb::ExportProjectResponse &r) {
      if (first) {
        EXPECT_TRUE(r.has_summary());
        if (summary) *summary = r.summary();
        first = false;
      } else {
        EXPECT_FALSE(r.has_summary());
        EXPECT_LE(r.data().size(), 1u << 20);
        out += r.data();
      }
      return true;
    });
    EXPECT_TRUE(st.ok()) << st.message;
    return out;
  }

  api::Status ImportArchive(api::Backend &b, pb::ImportProjectArchiveRequest req, pb::ImportProjectArchiveResponse &resp) {
    *req.mutable_provenance() = User("bob");
    resp.Clear();
    return b.ImportProjectArchive(ctx_, req, resp);
  }

  CallContext ctx_;
  std::unique_ptr<api::Backend> backend_;
};

TEST_F(ProjectOrgTest, FoldersOrganizeAProject) {
  api::Backend &b = *backend_;
  pb::GetServerInfoResponse info;
  ASSERT_TRUE(b.GetServerInfo(ctx_, {}, info).ok());
  EXPECT_GE(info.api_minor(), 37u);
  for (const char *f : {"project-folders", "project-archive"})
    EXPECT_NE(std::find(info.features().begin(), info.features().end(), f), info.features().end()) << f;

  const std::string cjson = Import(b, Corpus("elf-x86_64/gcc-O2/stripped/cjson"), "cjson");
  const std::string zlib = Import(b, Corpus("elf-x86_64/gcc-O2/stripped/zlib"), "zlib");
  // Before any folder: everything at the root.
  const auto first = List(b);
  for (const auto &p : first.programs()) {
    EXPECT_EQ(p.folder_path(), "/");
    EXPECT_EQ(p.folder_id(), "");
  }
  pb::SubscribeRequest sub;
  sub.set_project_id("default");
  sub.add_program_ids(zlib);  // a subscriber to one program still hears of folders
  struct Events final : api::EventSink {
    std::vector<pb::RevisionEvent> got;
    std::mutex mu;
    void Send(pb::SubscribeResponse e) override {
      std::lock_guard lock(mu);
      if (e.has_revision()) got.push_back(e.revision());
    }
    void End(api::Status) override {}
  };
  auto events = std::make_shared<Events>();
  std::unique_ptr<api::Subscription> subscription;
  ASSERT_TRUE(b.Subscribe(ctx_, sub, events, subscription).ok());

  const std::string libs = Mkdir(b, "", "libs");
  ASSERT_EQ(libs.size(), 16u);
  const std::string json = Mkdir(b, libs, "json");
  api::Status st;
  Mkdir(b, libs, "json", &st);
  EXPECT_EQ(st.code, StatusCode::kAlreadyExists);
  Mkdir(b, "", "a/b", &st);
  EXPECT_EQ(st.code, StatusCode::kInvalidArgument);
  Mkdir(b, "0123456789abcdef", "x", &st);
  EXPECT_EQ(st.code, StatusCode::kNotFound);

  pb::MoveToFolderResponse moved;
  ASSERT_TRUE(Move(b, json, {cjson}, {}, &moved).ok());
  ASSERT_EQ(moved.assertions_size(), 1);
  auto l = List(b);
  EXPECT_EQ(FolderOf(l)["cjson"], "/libs/json");
  EXPECT_EQ(FolderOf(l)["zlib"], "/");
  EXPECT_EQ(Paths(l), (std::vector<std::string>{"/libs", "/libs/json"}));
  for (const auto &p : l.programs())
    if (p.name() == "cjson") {
      EXPECT_EQ(p.folder_id(), json);
      EXPECT_EQ(p.folder_origin().asserted().provenance().id(), "alice");
    }

  // A folder can't move into itself or below itself; a name can't repeat.
  EXPECT_EQ(Move(b, json, {}, {libs}).code, StatusCode::kFailedPrecondition);
  EXPECT_EQ(Move(b, libs, {}, {libs}).code, StatusCode::kFailedPrecondition);
  const std::string other = Mkdir(b, "", "json");
  EXPECT_EQ(Move(b, libs, {}, {other}).code, StatusCode::kAlreadyExists);

  // Rename, and a move of a folder with what is inside it.
  pb::RenameFolderRequest ren;
  ren.set_project_id("default");
  ren.set_folder_id(libs);
  ren.set_name("third-party");
  *ren.mutable_provenance() = User();
  pb::RenameFolderResponse renr;
  ASSERT_TRUE(b.RenameFolder(ctx_, ren, renr).ok());
  EXPECT_EQ(renr.folder().path(), "/third-party");
  ASSERT_TRUE(Move(b, other, {}, {libs}).ok());
  EXPECT_EQ(FolderOf(List(b))["cjson"], "/json/third-party/json");

  // Deleting: only empty folders.
  pb::DeleteFolderRequest del;
  del.set_project_id("default");
  del.set_folder_id(json);
  *del.mutable_provenance() = User();
  pb::DeleteFolderResponse delr;
  EXPECT_EQ(b.DeleteFolder(ctx_, del, delr).code, StatusCode::kFailedPrecondition);
  ASSERT_TRUE(Move(b, "", {cjson}, {}).ok());
  ASSERT_TRUE(b.DeleteFolder(ctx_, del, delr).ok());
  l = List(b);
  EXPECT_EQ(Paths(l), (std::vector<std::string>{"/json", "/json/third-party"}));
  EXPECT_EQ(FolderOf(l)["cjson"], "/");

  // Undo is a retraction by project: the folder comes back.
  pb::RetractAssertionsRequest undo;
  undo.set_project_id("default");
  undo.add_seqs(delr.assertion().seq());
  *undo.mutable_provenance() = User();
  pb::RetractAssertionsResponse undor;
  ASSERT_TRUE(b.RetractAssertions(ctx_, undo, undor).ok());
  ASSERT_EQ(undor.retractions_size(), 1);
  EXPECT_EQ(Paths(List(b)), (std::vector<std::string>{"/json", "/json/third-party", "/json/third-party/json"}));
  // Retracting a program's op by program id still refuses another's.
  undo.set_project_id("");
  undo.set_program_id(zlib);
  undo.set_seqs(0, moved.assertions(0).seq());
  EXPECT_EQ(b.RetractAssertions(ctx_, undo, undor).code, StatusCode::kInvalidArgument);

  // Subscribers heard of every change of the tree, filtered or not.
  int tree = 0;
  {
    std::lock_guard lock(events->mu);
    for (const auto &e : events->got)
      for (const auto &q : e.invalidated()) tree += q.kind() == pb::QUERY_KIND_PROJECT_TREE;
  }
  EXPECT_GE(tree, 6);
  subscription.reset();

  // A deleted program can't be moved.
  pb::DeleteProgramRequest dp;
  dp.set_program_id(zlib);
  *dp.mutable_provenance() = User();
  pb::DeleteProgramResponse dpr;
  ASSERT_TRUE(b.DeleteProgram(ctx_, dp, dpr).ok());
  EXPECT_EQ(Move(b, other, {zlib}, {}).code, StatusCode::kFailedPrecondition);
}

// Two daemons each moved one folder under the other at the same time: the
// merged tree has a cycle, which every daemon breaks the same way (the
// lowest id hangs from the root), and a deeper chain than allowed is cut.
TEST_F(ProjectOrgTest, CyclesFromPeersResolveTheSameEverywhere) {
  api::Backend &b = *backend_;
  const std::string a = Mkdir(b, "", "a");
  const std::string c = Mkdir(b, "", "c");
  auto folder_op = [](std::uint64_t counter, const std::string &id, const std::string &value) {
    facts::Op op;
    op.kind = facts::OpKind::Assert;
    op.prov = facts::Provenance::user("peer-user");
    op.key = facts::FactKey{facts::FactKind::Note, {archive::kProjectSpace, archive::kFolderAddress},
                            std::string(archive::kFolderSubPrefix) + id};
    op.value = value;
    op.id = {0xfeedULL, counter};
    op.stamp = (std::uint64_t{1} << 62) + counter;
    return op;
  };
  pb::PushRequest push;
  push.set_project_id("default");
  push.set_format(kSyncFormat);
  AddOp(folder_op(1, a, c + "/a"), push.mutable_ops());
  AddOp(folder_op(2, c, a + "/c"), push.mutable_ops());
  pb::PushResponse pushed;
  ASSERT_TRUE(b.Push(ctx_, push, pushed).ok());
  ASSERT_EQ(pushed.staged(), 2u);
  const std::string low = std::min(a, c), high = std::max(a, c);
  const std::string low_name = low == a ? "a" : "c", high_name = high == a ? "a" : "c";
  EXPECT_EQ(Paths(List(b)), (std::vector<std::string>{"/" + low_name, "/" + low_name + "/" + high_name}));
  // A local move that would close a cycle again is refused.
  EXPECT_EQ(Move(b, high, {}, {low}).code, StatusCode::kFailedPrecondition);
}

TEST_F(ProjectOrgTest, FoldersPersist) {
  const fs::path dir = Scratch("persist");
  {
    auto b = Make(dir);
    const std::string cjson = Import(*b, Corpus("elf-x86_64/gcc-O2/stripped/cjson"), "cjson");
    const std::string a = Mkdir(*b, "", "a");
    const std::string c = Mkdir(*b, a, "c");
    ASSERT_TRUE(Move(*b, c, {cjson}, {}).ok());
  }
  auto b = Make(dir);
  auto l = List(*b);
  EXPECT_EQ(FolderOf(l)["cjson"], "/a/c");
  EXPECT_EQ(Paths(l), (std::vector<std::string>{"/a", "/a/c"}));
}

// The gate: a corpus program with a user's work (renames, a retype, a
// struct, comments, a patch, a listing edit, a memory region with another
// file's bytes, undone and redone edits, an agent's rename), exported and
// imported into a fresh project, full and annotations-only, answers as the
// original does.
class ProjectArchiveTest : public ProjectOrgTest {
 protected:
  std::uint64_t Entry(api::Backend &b, const std::string &program, const std::string &name) {
    pb::ListFunctionsRequest req;
    req.set_program_id(program);
    req.set_name_contains(name);
    pb::ListFunctionsResponse resp;
    EXPECT_TRUE(b.ListFunctions(ctx_, req, resp).ok());
    for (const auto &f : resp.functions())
      if (f.name() == name) return f.entry().offset();
    ADD_FAILURE() << "no function " << name;
    return 0;
  }

  pb::AppendAssertionsResponse Append(api::Backend &b, const std::string &program, std::vector<pb::AssertionBody> bodies,
                                      pb::Provenance prov = User()) {
    pb::AppendAssertionsRequest req;
    req.set_program_id(program);
    *req.mutable_provenance() = prov;
    for (auto &body : bodies) *req.add_assertions()->mutable_body() = body;
    pb::AppendAssertionsResponse resp;
    auto st = b.AppendAssertions(ctx_, req, resp);
    EXPECT_TRUE(st.ok()) << st.message;
    return resp;
  }

  void Retract(api::Backend &b, const std::string &program, std::uint64_t seq) {
    pb::RetractAssertionsRequest req;
    req.set_program_id(program);
    req.add_seqs(seq);
    *req.mutable_provenance() = User();
    pb::RetractAssertionsResponse resp;
    auto st = b.RetractAssertions(ctx_, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
  }

  static pb::AssertionBody Rename(std::uint64_t at, const std::string &name) {
    pb::AssertionBody body;
    body.mutable_rename()->mutable_target()->mutable_address()->set_offset(at);
    body.mutable_rename()->set_name(name);
    return body;
  }

  // The user's work on cjson (and a little on zlib).
  void Work(api::Backend &b, const std::string &cjson, const std::string &zlib) {
    const std::uint64_t get_string = Entry(b, cjson, "cJSON_GetStringValue");
    const std::uint64_t array_size = Entry(b, cjson, "cJSON_GetArraySize");
    const std::uint64_t version = Entry(b, cjson, "cJSON_Version");
    const std::uint64_t is_null = Entry(b, cjson, "cJSON_IsNull");
    Append(b, cjson, {Rename(get_string, "get_string")});
    // A struct, from C, and a retype that uses it.
    pb::ParseCRequest parse;
    parse.set_program_id(cjson);
    auto *src = parse.add_sources();
    src->set_name("mine.h");
    src->set_text("struct point { int x; int y; long weight; };\n");
    pb::ParseCResponse parsed;
    ASSERT_TRUE(b.ParseC(ctx_, parse, parsed).ok());
    {
      pb::AppendAssertionsRequest req;
      req.set_program_id(cjson);
      *req.mutable_provenance() = User();
      for (const auto &n : parsed.nodes()) *req.add_assertions()->mutable_body()->mutable_define_type()->mutable_type() = n;
      for (const auto &n : parsed.named())
        req.add_assertions()->mutable_body()->mutable_bind_type_name()->mutable_type()->set_assertion_index(n.index());
      pb::AppendAssertionsResponse resp;
      auto st = b.AppendAssertions(ctx_, req, resp);
      ASSERT_TRUE(st.ok()) << st.message;
    }
    // Filed under a category (type archives' folders).
    pb::AssertionBody category;
    category.mutable_type_category()->set_named_key("struct cJSON");
    category.mutable_type_category()->set_path("/json/core");
    Append(b, cjson, {category});
    pb::AssertionBody retype;
    retype.mutable_retype()->mutable_target()->mutable_address()->set_offset(array_size);
    retype.mutable_retype()->mutable_type()->set_c_declaration("int cJSON_GetArraySize(const struct point *array)");
    Append(b, cjson, {retype});
    // Comments.
    pb::AssertionBody plate, eol;
    plate.mutable_comment()->mutable_address()->set_offset(version);
    plate.mutable_comment()->set_kind(pb::COMMENT_KIND_PLATE);
    plate.mutable_comment()->set_text("The library's version string.");
    eol.mutable_comment()->mutable_address()->set_offset(get_string);
    eol.mutable_comment()->set_kind(pb::COMMENT_KIND_EOL);
    eol.mutable_comment()->set_text("checked by callers");
    Append(b, cjson, {plate, eol});
    // A patch.
    pb::PatchBytesRequest patch;
    patch.set_program_id(cjson);
    patch.mutable_address()->set_offset(is_null);
    patch.set_data(std::string("\x31\xc0\xc3", 3));  // xor eax, eax; ret
    *patch.mutable_provenance() = User();
    pb::PatchBytesResponse patched;
    auto st = b.PatchBytes(ctx_, patch, patched);
    ASSERT_TRUE(st.ok()) << st.message;
    // A listing edit: an int where .data starts.
    pb::GetMemoryMapRequest mm;
    mm.set_program_id(cjson);
    pb::GetMemoryMapResponse map;
    ASSERT_TRUE(b.GetMemoryMap(ctx_, mm, map).ok());
    std::uint64_t data = 0;
    for (const auto &blk : map.blocks())
      if (blk.name() == ".data") data = blk.range().first().offset();
    ASSERT_NE(data, 0u);
    pb::AssertionBody unit;
    unit.mutable_listing_edit()->mutable_address()->set_offset(data + 8);
    unit.mutable_listing_edit()->mutable_data()->mutable_type()->set_c_declaration("int");
    Append(b, cjson, {unit});
    // A memory region with bytes from another file.
    pb::AddMemoryRegionRequest add;
    add.set_program_id(cjson);
    add.mutable_region()->set_name("blob");
    add.mutable_region()->set_start(0x7000000);
    add.mutable_region()->set_read(true);
    add.set_content(std::string(200, '\x5a') + "tail of another file");
    add.set_file_name("blob.bin");
    *add.mutable_provenance() = User();
    pb::AddMemoryRegionResponse added;
    st = b.AddMemoryRegion(ctx_, add, added);
    ASSERT_TRUE(st.ok()) << st.message;
    // Undo and redo: a rename undone, another undone and redone.
    auto undone = Append(b, cjson, {Rename(version, "version_undone")});
    Retract(b, cjson, undone.assertions(0).seq());
    auto redone = Append(b, cjson, {Rename(is_null, "is_null")});
    Retract(b, cjson, redone.assertions(0).seq());
    pb::RetractAssertionsRequest redo;
    redo.set_program_id(cjson);
    *redo.mutable_provenance() = User();
    {
      pb::ListAssertionsRequest la;
      la.set_program_id(cjson);
      la.mutable_filter()->set_include_inactive(true);
      la.mutable_page()->set_page_size(5000);
      pb::ListAssertionsResponse all;
      ASSERT_TRUE(b.ListAssertions(ctx_, la, all).ok());
      redo.add_seqs(all.assertions(all.assertions_size() - 1).seq());  // the retraction
    }
    pb::RetractAssertionsResponse redor;
    ASSERT_TRUE(b.RetractAssertions(ctx_, redo, redor).ok());
    // An agent's rename, and one on zlib.
    pb::Provenance agent;
    agent.set_kind(pb::PROVENANCE_KIND_AGENT);
    agent.set_id("model");
    agent.set_session("s-1");
    Append(b, cjson, {Rename(array_size, "array_size")}, agent);
    pb::ListFunctionsRequest lf;
    lf.set_program_id(zlib);
    lf.mutable_page()->set_page_size(3);
    pb::ListFunctionsResponse zf;
    ASSERT_TRUE(b.ListFunctions(ctx_, lf, zf).ok());
    ASSERT_GT(zf.functions_size(), 1);
    Append(b, zlib, {Rename(zf.functions(1).entry().offset(), "zlib_first")});
    // A diff session between them (not run).
    pb::CreateDiffSessionRequest ds;
    ds.set_project_id("default");
    ds.set_program_a(zlib);
    ds.set_program_b(cjson);
    ds.set_name("zlib vs cjson");
    *ds.mutable_provenance() = User();
    pb::CreateDiffSessionResponse dsr;
    ASSERT_TRUE(b.CreateDiffSession(ctx_, ds, dsr).ok());
    // Folders.
    const std::string libs = Mkdir(b, "", "libs");
    const std::string json = Mkdir(b, libs, "json");
    Mkdir(b, "", "empty");
    ASSERT_TRUE(Move(b, json, {cjson}, {}).ok());
    ASSERT_TRUE(Move(b, libs, {zlib}, {}).ok());
  }

  // Everything the gate compares, of one program.
  struct Answers {
    std::vector<std::string> functions;            // entry, name, prototype
    std::map<std::uint64_t, std::string> decompiled;  // a sample
    std::vector<std::string> history;              // every op, in order
    std::vector<std::string> effective;            // what is in force
    std::string memory;                            // the map and bytes read through it
    std::size_t undo_depth = 0;                    // assertions and retractions
    std::string types;
  };

  static std::string Normal(const std::string &s, const std::map<std::string, std::string> &ids) {
    std::string out = s;
    for (const auto &[from, to] : ids)
      for (std::size_t at; (at = out.find(from)) != std::string::npos;) out.replace(at, from.size(), to);
    return out;
  }

  Answers Ask(api::Backend &b, const std::string &program, const std::map<std::string, std::string> &ids) {
    Answers a;
    pb::ListFunctionsRequest lf;
    lf.set_program_id(program);
    lf.mutable_page()->set_page_size(5000);
    pb::ListFunctionsResponse fs;
    EXPECT_TRUE(b.ListFunctions(ctx_, lf, fs).ok());
    std::vector<std::uint64_t> sample;
    for (const auto &f : fs.functions()) {
      a.functions.push_back(std::to_string(f.entry().offset()) + " " + f.name() + " " + f.prototype());
      if (sample.size() < 12 || f.name() == "get_string" || f.name() == "array_size" || f.name() == "is_null" ||
          f.name() == "cJSON_Version")
        sample.push_back(f.entry().offset());
    }
    for (std::uint64_t e : sample) {
      pb::DecompileRequest d;
      d.set_program_id(program);
      d.mutable_function()->set_offset(e);
      d.mutable_options()->set_include_text(true);
      pb::DecompileResponse dr;
      EXPECT_TRUE(b.Decompile(ctx_, d, dr).ok());
      a.decompiled[e] = dr.function().text();
    }
    for (bool inactive : {true, false}) {
      pb::ListAssertionsRequest la;
      la.set_program_id(program);
      la.mutable_filter()->set_include_inactive(inactive);
      la.mutable_page()->set_page_size(5000);
      pb::ListAssertionsResponse all;
      EXPECT_TRUE(b.ListAssertions(ctx_, la, all).ok());
      std::map<std::uint64_t, std::size_t> index;  // seq -> position
      for (const auto &x : all.assertions()) {
        index[x.seq()] = index.size();
        pb::Assertion n = x;
        // What differs by construction: local seqs and revisions, ids and
        // stamps of the replica, the program id.
        const std::string retracts = x.retracts_seq() ? std::to_string(index[x.retracts_seq()]) : "";
        std::string by;
        for (auto r : x.retracted_by()) by += std::to_string(r > 0) + ",";
        n.clear_seq();
        n.clear_revision();
        n.clear_id();
        n.clear_retracts_id();
        n.clear_retracts_seq();
        n.clear_retracted_by();
        n.clear_retracted_by_ids();
        n.clear_depends_on_id();
        n.clear_depends_on_seq();
        n.clear_supersedes();
        n.clear_stamp();
        n.mutable_key()->clear_program_id();
        n.mutable_provenance()->clear_on_behalf_of();
        const std::string line = Normal(n.ShortDebugString(), ids) + " retracts=" + retracts + " by=" + by;
        (inactive ? a.history : a.effective).push_back(line);
      }
      if (inactive) a.undo_depth = static_cast<std::size_t>(all.assertions_size());
    }
    pb::GetMemoryMapRequest mm;
    mm.set_program_id(program);
    pb::GetMemoryMapResponse map;
    EXPECT_TRUE(b.GetMemoryMap(ctx_, mm, map).ok());
    for (const auto &blk : map.blocks()) {
      pb::MemoryBlock n = blk;
      n.clear_origin();
      a.memory += n.ShortDebugString() + "\n";
      pb::ReadMemoryRequest rm;
      rm.set_program_id(program);
      *rm.mutable_address() = blk.range().first();
      rm.set_length(static_cast<std::uint32_t>(std::min<std::uint64_t>(256, blk.range().last().offset() - blk.range().first().offset() + 1)));
      pb::ReadMemoryResponse rr;
      if (b.ReadMemory(ctx_, rm, rr).ok()) a.memory += rr.data() + "\n";
    }
    pb::FindTypesRequest ft;
    ft.set_program_id(program);
    ft.set_category("/json");  // the user's filing of the debug info's struct
    ft.mutable_page()->set_page_size(5000);
    pb::FindTypesResponse found;
    EXPECT_TRUE(b.FindTypes(ctx_, ft, found).ok());
    for (const auto &t : found.types()) a.types += t.name() + "=" + t.hash() + "@" + t.category() + ";";
    if (program.find("cjson") != std::string::npos)
      EXPECT_NE(a.types.find("cJSON=") , std::string::npos) << a.types;
    return a;
  }

  void ExpectSame(const Answers &x, const Answers &y, const std::string &what) {
    EXPECT_EQ(x.functions, y.functions) << what;
    EXPECT_EQ(x.decompiled.size(), y.decompiled.size()) << what;
    for (const auto &[e, text] : x.decompiled) EXPECT_EQ(text, y.decompiled.at(e)) << what << " at " << e;
    EXPECT_EQ(x.history, y.history) << what;
    EXPECT_EQ(x.effective, y.effective) << what;
    EXPECT_EQ(x.undo_depth, y.undo_depth) << what;
    if (x.memory != y.memory) {
      // The first line that differs, readably.
      std::istringstream xs(x.memory), ys(y.memory);
      std::string xl, yl;
      while (std::getline(xs, xl) && std::getline(ys, yl))
        if (xl != yl) break;
      ADD_FAILURE() << what << ": the memory differs:\n  " << xl.substr(0, 400) << "\n  " << yl.substr(0, 400);
    }
    EXPECT_EQ(x.types, y.types) << what;
  }

  std::map<std::string, std::string> ProgramsByName(api::Backend &b, const std::string &project) {
    std::map<std::string, std::string> out;
    const auto listed = List(b, project);
    for (const auto &p : listed.programs()) out[p.name()] = p.program_id();
    return out;
  }
};

TEST_F(ProjectArchiveTest, RoundTripGivesTheSameAnswers) {
  api::Backend &b = *backend_;
  const std::string cjson = Import(b, Corpus("elf-x86_64/gcc-O2/debug/cjson"), "cjson");
  const std::string zlib = Import(b, Corpus("elf-x86_64/gcc-O2/stripped/zlib"), "zlib");
  Work(b, cjson, zlib);
  const Answers cjson_before = Ask(b, cjson, {{cjson, "P"}});
  const Answers zlib_before = Ask(b, zlib, {{zlib, "P"}});
  EXPECT_GT(cjson_before.undo_depth, 100u);  // DWARF's and the user's

  for (bool annotations : {false, true}) {
    SCOPED_TRACE(annotations ? "annotations only" : "full");
    pb::ExportProjectRequest ex;
    ex.set_annotations_only(annotations);
    pb::ExportSummary summary;
    const std::string bytes = Export(b, ex, &summary);
    EXPECT_EQ(summary.file_name(), annotations ? "default-annotations.rkproj" : "default.rkproj");
    EXPECT_EQ(summary.manifest().programs_size(), 2);
    EXPECT_EQ(summary.manifest().annotations_only(), annotations);
    if (annotations) EXPECT_LT(bytes.size(), 200u * 1024);

    pb::ImportProjectArchiveRequest req;
    req.mutable_archive()->set_content(bytes);
    req.set_new_project_name(annotations ? "copy-annotations" : "copy");
    pb::ImportProjectArchiveResponse resp;
    if (annotations) {
      // Inspected: the binaries aren't anywhere yet.
      req.set_inspect_only(true);
      ASSERT_TRUE(ImportArchive(b, req, resp).ok());
      for (const auto &p : resp.programs()) EXPECT_EQ(p.binary_source(), "") << p.name();
      req.set_inspect_only(false);
      auto st = ImportArchive(b, req, resp);
      EXPECT_EQ(st.code, StatusCode::kFailedPrecondition);
      EXPECT_NE(st.message.find("not found"), std::string::npos) << st.message;
      // One by its bytes, the other found in a directory.
      std::ifstream f(Corpus("elf-x86_64/gcc-O2/debug/cjson"), std::ios::binary);
      req.add_binaries()->set_content(std::string(std::istreambuf_iterator<char>(f), {}));
      req.set_search_dir(Corpus("elf-x86_64/gcc-O2/stripped").string());
    }
    auto st = ImportArchive(b, req, resp);
    ASSERT_TRUE(st.ok()) << st.message;
    const std::string project = resp.project().project_id();
    EXPECT_EQ(project, annotations ? "copy-annotations" : "copy");
    ASSERT_EQ(resp.programs_size(), 2);
    for (const auto &p : resp.programs()) {
      EXPECT_FALSE(p.skipped());
      EXPECT_FALSE(p.program().program_id().empty()) << p.name();
      if (annotations) EXPECT_NE(p.binary_source(), "archive");
    }
    auto names = ProgramsByName(b, project);
    ASSERT_TRUE(names.contains("cjson") && names.contains("zlib"));
    const auto listed = List(b, project);
    EXPECT_EQ(FolderOf(listed)["cjson"], "/libs/json");
    EXPECT_EQ(FolderOf(listed)["zlib"], "/libs");
    EXPECT_EQ(Paths(listed), (std::vector<std::string>{"/empty", "/libs", "/libs/json"}));
    ExpectSame(cjson_before, Ask(b, names["cjson"], {{names["cjson"], "P"}}), "cjson");
    ExpectSame(zlib_before, Ask(b, names["zlib"], {{names["zlib"], "P"}}), "zlib");
    // The diff session came along, between the copies.
    pb::ListDiffSessionsRequest lds;
    lds.set_project_id(project);
    pb::ListDiffSessionsResponse sessions;
    ASSERT_TRUE(b.ListDiffSessions(ctx_, lds, sessions).ok());
    ASSERT_EQ(sessions.sessions_size(), 1);
    EXPECT_EQ(sessions.sessions(0).program_a(), names["zlib"]);
    EXPECT_EQ(sessions.sessions(0).program_b(), names["cjson"]);
    // Undo still works on the copy: reverting alice's work there brings
    // the debug info's names back.
    pb::RevertByProvenanceRequest rv;
    rv.set_program_id(names["cjson"]);
    rv.mutable_filter()->set_kind(pb::PROVENANCE_KIND_USER);
    rv.mutable_filter()->set_id("alice");
    *rv.mutable_provenance() = User();
    pb::RevertByProvenanceResponse rvr;
    ASSERT_TRUE(b.RevertByProvenance(ctx_, rv, rvr).ok());
    EXPECT_EQ(Entry(b, names["cjson"], "cJSON_GetStringValue"), Entry(b, cjson, "get_string"));
  }
}

TEST_F(ProjectArchiveTest, SelectionsMergeIntoAnExistingProject) {
  api::Backend &b = *backend_;
  const std::string cjson = Import(b, Corpus("elf-x86_64/gcc-O2/stripped/cjson"), "cjson");
  const std::string zlib = Import(b, Corpus("elf-x86_64/gcc-O2/stripped/zlib"), "zlib");
  const std::string libs = Mkdir(b, "", "libs");
  const std::string deep = Mkdir(b, libs, "deep");
  ASSERT_TRUE(Move(b, deep, {zlib}, {}).ok());
  pb::ListFunctionsRequest lf;
  lf.set_program_id(zlib);
  lf.mutable_page()->set_page_size(2);
  pb::ListFunctionsResponse zf;
  ASSERT_TRUE(b.ListFunctions(ctx_, lf, zf).ok());
  Append(b, zlib, {Rename(zf.functions(0).entry().offset(), "renamed_in_zlib")});

  // A folder: it becomes a top-level folder of the archive.
  pb::ExportProjectRequest ex;
  ex.add_folder_ids(libs);
  pb::ExportSummary summary;
  const std::string bytes = Export(b, ex, &summary);
  ASSERT_EQ(summary.manifest().programs_size(), 1);
  EXPECT_EQ(summary.manifest().programs(0).folder(), "/libs/deep");

  // Merged back into the same project, under a new folder: a new program
  // beside the original, with the work, under "incoming/libs/deep".
  const std::string incoming = Mkdir(b, "", "incoming");
  pb::ImportProjectArchiveRequest req;
  req.mutable_archive()->set_content(bytes);
  req.set_project_id("default");
  req.set_folder_id(incoming);
  pb::ImportProjectArchiveResponse resp;
  auto st = ImportArchive(b, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  ASSERT_EQ(resp.programs_size(), 1);
  const std::string copy = resp.programs(0).program().program_id();
  EXPECT_NE(copy, zlib);
  EXPECT_EQ(resp.programs(0).program().folder_path(), "/incoming/libs/deep");
  EXPECT_EQ(Entry(b, copy, "renamed_in_zlib"), zf.functions(0).entry().offset());
  // Again, into the same place: the name clashes, so the copy is renamed.
  st = ImportArchive(b, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(resp.programs(0).program().name(), "zlib (2)");
  EXPECT_EQ(resp.programs(0).program().folder_path(), "/incoming/libs/deep");
  // The folders were reused, not repeated.
  std::vector<std::string> paths = Paths(List(b));
  EXPECT_EQ(std::count(paths.begin(), paths.end(), "/incoming/libs/deep"), 1);

  // One program, annotations only, its binary found in the project itself.
  pb::ExportProjectRequest one;
  one.add_program_ids(cjson);
  one.set_annotations_only(true);
  const std::string ann = Export(b, one, &summary);
  EXPECT_EQ(summary.file_name(), "default-cjson-annotations.rkproj");
  pb::ImportProjectArchiveRequest again;
  again.mutable_archive()->set_content(ann);
  again.set_project_id("default");
  st = ImportArchive(b, again, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(resp.programs(0).binary_source(), "project:" + cjson);
  EXPECT_EQ(resp.programs(0).program().name(), "cjson (2)");

  // skip_missing leaves out what isn't found.
  pb::ImportProjectArchiveRequest skip;
  skip.mutable_archive()->set_content(ann);
  skip.set_skip_missing(true);
  st = ImportArchive(b, skip, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(resp.programs(0).skipped());
  EXPECT_EQ(List(b, resp.project().project_id()).programs_size(), 0);

  // A deleted program isn't exported with the project, and can't be named.
  pb::DeleteProgramRequest dp;
  dp.set_program_id(cjson);
  *dp.mutable_provenance() = User();
  pb::DeleteProgramResponse dpr;
  ASSERT_TRUE(b.DeleteProgram(ctx_, dp, dpr).ok());
  pb::ExportProjectRequest named;
  named.set_project_id("default");
  named.add_program_ids(cjson);
  EXPECT_EQ(b.ExportProject(ctx_, named, [](const auto &) { return true; }).code, StatusCode::kFailedPrecondition);
}

TEST_F(ProjectArchiveTest, UploadsAndHostFiles) {
  api::Backend &b = *backend_;
  Import(b, Corpus("elf-x86_64/gcc-O2/stripped/cjson"), "cjson");
  const fs::path dir = Scratch("host");
  pb::ExportProjectRequest ex;
  ex.set_project_id("default");
  ex.set_host_path((dir / "out.rkproj").string());
  std::vector<pb::ExportProjectResponse> msgs;
  ASSERT_TRUE(b.ExportProject(ctx_, ex, [&](const auto &m) {
                 msgs.push_back(m);
                 return true;
               }).ok());
  ASSERT_EQ(msgs.size(), 1u);
  EXPECT_EQ(msgs[0].summary().size(), fs::file_size(dir / "out.rkproj"));
  std::ifstream f(dir / "out.rkproj", std::ios::binary);
  const std::string bytes(std::istreambuf_iterator<char>(f), {});

  // Uploaded in pieces, by its owner only, in order.
  CallContext alice = ctx_, eve = ctx_;
  alice.caller = "user:alice";
  eve.caller = "user:eve";
  pb::UploadChunkRequest up;
  up.set_total_size(bytes.size());
  up.set_data(bytes.substr(0, 1000));
  pb::UploadChunkResponse upr;
  ASSERT_TRUE(b.UploadChunk(alice, up, upr).ok());
  EXPECT_FALSE(upr.complete());
  const std::string id = upr.upload_id();
  up.set_upload_id(id);
  up.set_offset(500);
  EXPECT_EQ(b.UploadChunk(alice, up, upr).code, StatusCode::kFailedPrecondition);
  up.set_offset(1000);
  up.set_data(bytes.substr(1000));
  EXPECT_EQ(b.UploadChunk(eve, up, upr).code, StatusCode::kNotFound);
  ASSERT_TRUE(b.UploadChunk(alice, up, upr).ok());
  EXPECT_TRUE(upr.complete());
  pb::ImportProjectArchiveRequest req;
  req.mutable_archive()->set_upload_id(id);
  pb::ImportProjectArchiveResponse resp;
  EXPECT_EQ(b.ImportProjectArchive(eve, req, resp).code, StatusCode::kNotFound);
  auto st = b.ImportProjectArchive(alice, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(resp.project().project_id(), "default-2");
  // From a host path.
  req.mutable_archive()->set_path((dir / "out.rkproj").string());
  // A name can't reach outside the projects' directory.
  req.set_new_project_name("../escape");
  EXPECT_EQ(ImportArchive(b, req, resp).code, StatusCode::kInvalidArgument);
  req.set_new_project_name("..");
  st = ImportArchive(b, req, resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(resp.project().project_id(), "imported");
  EXPECT_EQ(resp.project().name(), "..");
}

}  // namespace
}  // namespace revkit::backend
