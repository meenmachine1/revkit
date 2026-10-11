// Fixtures made at test time with the standard tools (zip, tar, mksquashfs,
// mke2fs, xorriso, mkfs.fat, ...) or Python, in a temporary directory. A
// test whose tool is missing skips itself with a message.
#pragma once

#include "revkit/container/container.hh"
#include "revkit/container/session.hh"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace revkit::container::testing {

namespace fs = std::filesystem;

inline bool have_tool(const std::string &tool) {
  return std::system(("command -v " + tool + " >/dev/null 2>&1 || test -x /usr/sbin/" + tool + " || test -x /sbin/" +
                      tool)
                         .c_str()) == 0;
}

inline std::string tool_path(const std::string &tool) {
  for (const char *dir : {"/usr/sbin/", "/sbin/"})
    if (fs::exists(std::string(dir) + tool)) return std::string(dir) + tool;
  return tool;
}

// Runs a shell command; false when it fails.
inline bool sh(const std::string &cmd) {
  return std::system(("set -e; { " + cmd + "; } >/dev/null 2>&1").c_str()) == 0;
}

inline std::vector<std::byte> read_file(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  std::string s((std::istreambuf_iterator<char>(in)), {});
  std::vector<std::byte> out(s.size());
  std::memcpy(out.data(), s.data(), s.size());
  return out;
}

inline std::string text(const std::vector<std::byte> &b) { return std::string(reinterpret_cast<const char *>(b.data()), b.size()); }

inline std::string read_all(const Source &s) { return text(s.read_exact(0, s.size(), "test")); }

// A fresh directory under the build's temporary directory, removed after.
class TempDir {
 public:
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "rk-container-test-XXXXXX").string();
    if (!mkdtemp(tmpl.data())) throw std::runtime_error("mkdtemp");
    path_ = tmpl;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  const fs::path &path() const { return path_; }
  fs::path operator/(const std::string &s) const { return path_ / s; }

 private:
  fs::path path_;
};

// The tree every format's fixture holds:
//   bin/true           (a copy of the host's ELF /bin/true)
//   etc/config.txt     "hello config\n", mode 0640
//   etc/empty/         an empty directory
//   lib/link -> ../bin/true
//   deep/a/b/c/d.txt   "deep\n"
inline void make_tree(const fs::path &root) {
  fs::create_directories(root / "bin");
  fs::create_directories(root / "etc/empty");
  fs::create_directories(root / "lib");
  fs::create_directories(root / "deep/a/b/c");
  fs::copy_file("/bin/true", root / "bin/true");
  fs::permissions(root / "bin/true", fs::perms(0755));
  std::ofstream(root / "etc/config.txt") << "hello config\n";
  fs::permissions(root / "etc/config.txt", fs::perms(0640));
  std::ofstream(root / "deep/a/b/c/d.txt") << "deep\n";
  fs::create_symlink("../bin/true", root / "lib/link");
}

inline std::string py() { return "python3 -I"; }

// Checks the tree make_tree() writes, through a session.
inline void expect_tree(Session &s, const std::string &prefix = "", bool symlinks = true, bool modes = true) {
  auto cfg = s.open_file(prefix + "/etc/config.txt");
  EXPECT_EQ(read_all(*cfg), "hello config\n");
  auto node = s.locate(prefix + "/etc/config.txt", false);
  if (modes) {
    EXPECT_TRUE(node.fs->entry(node.entry).has_mode);
    EXPECT_EQ(node.fs->entry(node.entry).mode & 0777, 0640u);
  }
  EXPECT_EQ(read_all(*s.open_file(prefix + "/deep/a/b/c/d.txt")), "deep\n");
  auto t = s.locate(prefix + "/bin/true", false);
  EXPECT_EQ(t.fs->entry(t.entry).size, fs::file_size("/bin/true"));
  auto g = s.describe(t);
  EXPECT_EQ(g.kind, "elf") << g.description;
  auto empty = s.locate(prefix + "/etc/empty", false);
  EXPECT_EQ(empty.fs->entry(empty.entry).kind, Kind::directory);
  if (symlinks) {
    auto link = s.locate(prefix + "/lib/link", false);
    EXPECT_EQ(link.fs->entry(link.entry).kind, Kind::symlink);
    EXPECT_EQ(link.fs->entry(link.entry).link_target, "../bin/true");
    auto followed = s.locate(prefix + "/lib/link", true);
    EXPECT_EQ(followed.path, prefix + "/bin/true");
    EXPECT_EQ(s.open_file(prefix + "/lib/link")->size(), fs::file_size("/bin/true"));
  }
}

}  // namespace revkit::container::testing
