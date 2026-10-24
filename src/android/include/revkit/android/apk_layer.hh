// An APK inside a container session (revkit::container) as ApkFiles: the
// zip layer a session path names, its members read through the session
// (decompressed within its limits). Separate from revkit::android so the
// parsers stay free of the container library.
#pragma once

#include "revkit/android/android.hh"
#include "revkit/container/session.hh"

#include <functional>
#include <memory>
#include <string>

namespace revkit::android {

class ApkLayer final : public ApkFiles {
 public:
  // The package a session path names: an APK file (its zip is mounted),
  // or any path inside an APK's layer ("" or "/": the outermost). Error
  // (container::Error) when there is no AndroidManifest.xml at that
  // layer's root.
  static std::unique_ptr<ApkLayer> open(std::shared_ptr<container::Session> session, const std::string &path,
                                        std::function<bool()> cancelled = {});

  // The layer's session path prefix ("/app.apk!", or "" for the outermost).
  const std::string &prefix() const { return prefix_; }
  // A member's session path ("/app.apk!/lib/x86_64/libfoo.so").
  std::string session_path(const std::string &member) const;

  std::vector<std::string> list() override;
  std::optional<std::uint64_t> size(const std::string &path) override;
  std::vector<std::byte> read(const std::string &path, std::uint64_t max) override;

 private:
  ApkLayer() = default;
  std::shared_ptr<container::Session> session_;
  std::shared_ptr<container::FileSystem> fs_;
  std::string prefix_;
  std::function<bool()> cancelled_;
};

}  // namespace revkit::android
