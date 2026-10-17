// Extraction to the host (ExtractFileSystem) and how it opens what it
// checked: the destination is canonicalized, then opened from the browse
// root down without following a link (OpenBeneath), so a component swapped
// for a link in between is refused (docs/bug-scrub.md, "Extraction
// TOCTOU"). The swap itself can't be timed in a test; OpenBeneath's refusal
// of every link on the way is what closes it.
#include "filesystems.h"
#include "open_beneath.h"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <fstream>

namespace revkit::backend {
namespace {

namespace fs = std::filesystem;

class ExtractTest : public ::testing::Test {
 protected:
  void SetUp() override {
    dir_ = fs::temp_directory_path() / ("revkit-extract-" + std::to_string(::getpid()) + "-" +
                                        ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(dir_);
    root_ = dir_ / "root";
    fs::create_directories(root_ / "src" / "sub");
    fs::create_directories(dir_ / "elsewhere");
    std::ofstream(root_ / "src" / "a.txt") << "alpha";
    std::ofstream(root_ / "src" / "sub" / "b.txt") << "beta";
    root_ = fs::canonical(root_);
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(dir_, ec);
  }
  api::Status Extract(const std::string &host_dir, pb::ExtractFromFileSystemResponse &resp) {
    FsSession s;
    s.session = container::Session::open_directory((root_ / "src").string(), container::Limits{});
    pb::ExtractFromFileSystemRequest req;
    req.set_host_dir(host_dir);
    req.add_paths("/");
    resp.Clear();
    return ExtractFileSystem(s, api::CallContext{}, req, {root_.string()}, resp);
  }
  fs::path dir_, root_;
};

TEST_F(ExtractTest, IntoADirectoryTheRootAndATrailingSlash) {
  pb::ExtractFromFileSystemResponse resp;
  auto st = Extract((root_ / "out").string(), resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_EQ(resp.files(), 2u);
  EXPECT_TRUE(fs::exists(root_ / "out" / "sub" / "b.txt"));
  st = Extract((root_ / "out2").string() + "/", resp);
  EXPECT_FALSE(st.ok());  // a trailing slash names an existing directory
  fs::create_directories(root_ / "out2");
  st = Extract((root_ / "out2").string() + "/", resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(fs::exists(root_ / "out2" / "a.txt"));
  // The root itself.
  fs::remove_all(root_ / "src" / "sub");
  st = Extract(root_.string(), resp);
  ASSERT_TRUE(st.ok()) << st.message;
  EXPECT_TRUE(fs::exists(root_ / "a.txt"));
}

TEST_F(ExtractTest, NeverOutsideTheRoot) {
  fs::create_directory_symlink(dir_ / "elsewhere", root_ / "link");
  pb::ExtractFromFileSystemResponse resp;
  auto st = Extract((root_ / "link" / "out").string(), resp);
  EXPECT_EQ(st.code, api::StatusCode::kPermissionDenied) << st.message;
  st = Extract((root_ / ".." / "elsewhere").string(), resp);
  EXPECT_EQ(st.code, api::StatusCode::kPermissionDenied) << st.message;
  // The destination itself a link: refused, not followed.
  st = Extract((root_ / "link").string(), resp);
  EXPECT_FALSE(st.ok());
  EXPECT_TRUE(fs::is_empty(dir_ / "elsewhere"));
}

TEST_F(ExtractTest, OpenBeneathRefusesEveryLinkOnTheWay) {
  fs::create_directories(root_ / "real" / "deeper");
  std::ofstream(root_ / "real" / "deeper" / "f") << "x";
  std::ofstream(dir_ / "elsewhere" / "f") << "secret";
  fs::create_directory_symlink(dir_ / "elsewhere", root_ / "real" / "swapped");
  fs::create_symlink(root_ / "real" / "deeper" / "f", root_ / "real" / "flink");
  int fd = OpenBeneath(root_, "real/deeper/f", O_RDONLY);
  EXPECT_GE(fd, 0);
  if (fd >= 0) ::close(fd);
  fd = OpenBeneath(root_, "", O_RDONLY | O_DIRECTORY);
  EXPECT_GE(fd, 0);
  if (fd >= 0) ::close(fd);
  for (const char *rel : {"real/swapped/f", "real/flink", "real/swapped", "../root/real/deeper/f", "/etc/passwd"}) {
    errno = 0;
    fd = OpenBeneath(root_, rel, O_RDONLY);
    EXPECT_LT(fd, 0) << rel;
    if (fd >= 0) ::close(fd);
  }
  // A file where a directory is expected.
  EXPECT_LT(OpenBeneath(root_, "real/deeper/f/g", O_RDONLY), 0);
}

}  // namespace
}  // namespace revkit::backend
