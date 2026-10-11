// A browsing session: the outermost container (a host file, bytes, or a
// host directory) and the containers mounted inside it on demand.
//
// Paths name a file through every layer: layers are separated by '!' and
// each layer is a path of percent-encoded components (container.hh), so
// "/rootfs.sqfs!/bin/busybox" is /bin/busybox inside the squashfs that is
// /rootfs.sqfs of the outermost container, and "/rootfs.sqfs!" is that
// squashfs's root. Symbolic links are followed inside their own layer
// only. Nested containers are recognised by magic, never by name.
#pragma once

#include "revkit/container/container.hh"

#include <chrono>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace revkit::container {

class Session {
 public:
  // `name`: the outermost file's name (display, and the start of each
  // container path). Error when it isn't a container.
  static std::shared_ptr<Session> open(std::shared_ptr<const Source> root, std::string name, const Limits &limits,
                                       const std::function<bool()> &cancelled = {});
  // A host directory as the outermost layer (open_host_directory).
  static std::shared_ptr<Session> open_directory(const std::string &path, const Limits &limits);

  const std::string &root_name() const { return root_name_; }
  const std::string &root_format() const { return root_->format(); }
  const std::shared_ptr<FileSystem> &root() const { return root_; }
  const Limits &limits() const { return limits_; }
  std::uint64_t budget_used() const { return budget_->used(); }

  struct Node {
    std::shared_ptr<FileSystem> fs;  // the layer the entry is in
    std::uint32_t entry = 0;
    std::string path;    // canonical session path of the entry ("/a.tar!/b")
    std::string prefix;  // the layers above ("/a.tar!"), "" in the outermost
    std::uint32_t depth = 1;  // 1: the outermost container
  };

  // The entry a path names. Symbolic links are followed on the way, and at
  // the end when follow_last. A path ending in '!' names the root of the
  // container that file holds. Error: no such entry, a link loop, a file
  // that isn't a container where a layer was expected, too deep.
  Node locate(std::string_view path, bool follow_last, const std::function<bool()> &cancelled = {});

  // A regular file's contents (links followed, inside the layer).
  std::shared_ptr<const Source> open_file(std::string_view path, const std::function<bool()> &cancelled = {});
  std::vector<std::byte> head(const Node &node, std::uint64_t n, const std::function<bool()> &cancelled = {});

  // The container a file holds, mounted once and kept while there is room
  // (Limits::max_total_bytes; least recently used first out). nullptr when
  // the file isn't a container.
  std::shared_ptr<FileSystem> mount(const Node &file, const std::function<bool()> &cancelled = {});
  // Its format by magic ("" when it isn't one), reading only its head.
  std::string container_format(const Node &file, const std::function<bool()> &cancelled = {});
  // identify() and guess() over a file's first bytes.
  Guess describe(const Node &file, const std::function<bool()> &cancelled = {});

  // "zip://fw.zip!/rootfs.sqfs!/bin/busybox": the outermost format and
  // name, then the session path. A host directory: "file:///srv/fw/x.zip!/a".
  std::string container_path(std::string_view session_path) const;

  std::chrono::steady_clock::time_point last_used() const { return last_used_; }

  Context context(const std::function<bool()> &cancelled) const;

 private:
  Session() = default;
  std::shared_ptr<const Source> open_entry(const Node &node, const Context &ctx);
  void touch();
  bool evict_one();

  std::recursive_mutex mu_;
  Limits limits_;
  std::shared_ptr<Budget> budget_;
  std::string root_name_;
  std::string root_dir_;  // a host directory session's path
  std::shared_ptr<const Source> root_src_;
  std::shared_ptr<FileSystem> root_;
  struct Cached {
    std::shared_ptr<const Source> src;
    std::shared_ptr<FileSystem> fs;  // a mounted container, or null (a file's bytes)
    std::uint64_t tick = 0;
  };
  std::map<std::string, Cached> cache_;
  std::uint64_t tick_ = 0;
  std::chrono::steady_clock::time_point last_used_ = std::chrono::steady_clock::now();
};

}  // namespace revkit::container
