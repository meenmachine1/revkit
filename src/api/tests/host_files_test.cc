#include "revkit/api/host_files.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace revkit::api {
namespace {

namespace fs = std::filesystem;

class HostFilesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    base_ = fs::temp_directory_path() / ("rk-host-files-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
                                          "-" + ::testing::UnitTest::GetInstance()->current_test_info()->name());
    fs::remove_all(base_);
    root_ = base_ / "root";
    fs::create_directories(root_ / "bin");
    fs::create_directories(root_ / "a-dir");
    fs::create_directories(base_ / "outside");
    std::ofstream(root_ / "fw.bin") << "0123456789";
    std::ofstream(root_ / ".hidden") << "x";
    std::ofstream(base_ / "outside" / "secret") << "x";
    fs::create_directory_symlink(base_ / "outside", root_ / "escape");
    root_ = fs::canonical(root_);
  }
  void TearDown() override { fs::remove_all(base_); }

  std::vector<std::string> names(const pb::ListHostFilesResponse &r) {
    std::vector<std::string> out;
    for (const auto &e : r.entries()) out.push_back(e.name());
    return out;
  }

  fs::path base_, root_;
};

TEST_F(HostFilesTest, ListsRootWithDirectoriesFirst) {
  pb::ListHostFilesResponse resp;
  ASSERT_TRUE(ListHostFiles({.roots = {root_.string()}}, {}, resp).ok());
  EXPECT_EQ(resp.path(), root_.string());
  EXPECT_TRUE(resp.parent().empty());
  // "escape" is listed (a link to a directory), but entering it is refused below.
  EXPECT_EQ(names(resp), (std::vector<std::string>{"a-dir", "bin", "escape", "fw.bin"}));
  const auto &fw = resp.entries(3);
  EXPECT_FALSE(fw.directory());
  EXPECT_EQ(fw.size(), 10u);
  EXPECT_EQ(fw.path(), (root_ / "fw.bin").string());
  EXPECT_GT(fw.modified().seconds(), 0);
}

TEST_F(HostFilesTest, HiddenOnRequest) {
  pb::ListHostFilesRequest req;
  req.set_include_hidden(true);
  pb::ListHostFilesResponse resp;
  ASSERT_TRUE(ListHostFiles({.roots = {root_.string()}}, req, resp).ok());
  EXPECT_EQ(names(resp).back(), "fw.bin");
  EXPECT_EQ(resp.entries_size(), 5);
}

TEST_F(HostFilesTest, SubdirectoryHasParent) {
  pb::ListHostFilesRequest req;
  req.set_path((root_ / "bin").string());
  pb::ListHostFilesResponse resp;
  ASSERT_TRUE(ListHostFiles({.roots = {root_.string()}}, req, resp).ok());
  EXPECT_EQ(resp.parent(), root_.string());
}

TEST_F(HostFilesTest, CannotLeaveTheRoots) {
  HostFilesOptions opt{.roots = {root_.string()}};
  for (const fs::path &p : {base_ / "outside", root_ / "..", root_ / "bin" / ".." / "..", root_ / "escape",
                            fs::path("/")}) {
    pb::ListHostFilesRequest req;
    req.set_path(p.string());
    pb::ListHostFilesResponse resp;
    EXPECT_EQ(ListHostFiles(opt, req, resp).code, StatusCode::kPermissionDenied) << p;
  }
  // A sibling whose name starts like the root is not inside it.
  fs::create_directories(base_ / "root2");
  pb::ListHostFilesRequest req;
  req.set_path((base_ / "root2").string());
  pb::ListHostFilesResponse resp;
  EXPECT_EQ(ListHostFiles(opt, req, resp).code, StatusCode::kPermissionDenied);
}

TEST_F(HostFilesTest, OffWithoutRootsAndErrorsOnBadPaths) {
  pb::ListHostFilesResponse resp;
  EXPECT_EQ(ListHostFiles({}, {}, resp).code, StatusCode::kFailedPrecondition);

  HostFilesOptions opt{.roots = {root_.string()}};
  pb::ListHostFilesRequest req;
  req.set_path((root_ / "missing").string());
  EXPECT_EQ(ListHostFiles(opt, req, resp).code, StatusCode::kNotFound);
  req.set_path((root_ / "fw.bin").string());
  EXPECT_EQ(ListHostFiles(opt, req, resp).code, StatusCode::kInvalidArgument);
}

TEST_F(HostFilesTest, Truncates) {
  pb::ListHostFilesResponse resp;
  ASSERT_TRUE(ListHostFiles({.roots = {root_.string()}, .max_entries = 2}, {}, resp).ok());
  EXPECT_EQ(resp.entries_size(), 2);
  EXPECT_TRUE(resp.truncated());
}

}  // namespace
}  // namespace revkit::api
