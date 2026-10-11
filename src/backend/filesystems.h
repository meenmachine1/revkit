// FileSystemService (api_minor 48, feature "filesystems";
// docs/filesystems.md): sessions over revkit::container, their owners,
// listings, reads, file info, extraction to the host, and the plan of an
// import (which files are programs). The import itself is the image
// backend's (ImportProgram's code path, with the bytes from here).
#pragma once

#include "revkit/api/backend.h"
#include "revkit/container/session.hh"
#include "revkit/v1/filesystem.pb.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

struct FsSession {
  std::string id;
  std::string owner;
  std::string project_id;
  std::string name;
  std::int64_t opened_at = 0;
  std::shared_ptr<container::Session> session;
};

class FileSystemRegistry {
 public:
  // RESOURCE_EXHAUSTED past kMaxPerCaller open sessions of one caller
  // (the oldest unused is closed first when it has been idle a while).
  api::Status Add(const api::CallContext &ctx, std::string project, std::string name,
                  std::shared_ptr<container::Session> session, std::shared_ptr<FsSession> &out);
  // NOT_FOUND unless the caller opened it (or is an admin).
  api::Status Get(const api::CallContext &ctx, const std::string &id, std::shared_ptr<FsSession> &out);
  api::Status Close(const api::CallContext &ctx, const pb::CloseFileSystemRequest &req);
  void List(const api::CallContext &ctx, pb::ListFileSystemsResponse &resp);

  static constexpr std::size_t kMaxPerCaller = 8;
  static constexpr std::size_t kMaxTotal = 64;
  static constexpr std::chrono::minutes kIdle{30};

 private:
  void PruneLocked();
  std::mutex mu_;
  std::map<std::string, std::shared_ptr<FsSession>> sessions_;
};

// The daemon's limits, lowered where the request asks.
container::Limits LimitsFrom(const pb::FileSystemLimits &req);
void FillLimits(const container::Limits &l, pb::FileSystemLimits *out);
void FillLayer(container::Session &s, const container::FileSystem &fs, const std::string &prefix, std::uint32_t depth,
               pb::FileSystemLayer *out);

// Exceptions from the container code as statuses: a limit is
// RESOURCE_EXHAUSTED, a missing file NOT_FOUND, anything else malformed
// INVALID_ARGUMENT.
template <class Fn>
api::Status FsGuard(Fn &&fn) {
  try {
    return fn();
  } catch (const container::LimitError &e) {
    return api::Error(api::StatusCode::kResourceExhausted, e.what());
  } catch (const container::Error &e) {
    const std::string m = e.what();
    if (m == "cancelled") return api::Error(api::StatusCode::kCancelled, m);
    return api::Error(m.starts_with("no such file") ? api::StatusCode::kNotFound : api::StatusCode::kInvalidArgument, m);
  }
}

api::Status ListFileSystemEntries(FsSession &s, const api::CallContext &ctx, const pb::ListFileSystemRequest &req,
                                  pb::ListFileSystemResponse &resp);
api::Status ReadFileSystemFile(FsSession &s, const api::CallContext &ctx, const pb::ReadFileSystemFileRequest &req,
                               pb::ReadFileSystemFileResponse &resp);
api::Status FileSystemFileInfo(FsSession &s, const api::CallContext &ctx, const pb::GetFileSystemFileInfoRequest &req,
                               pb::GetFileSystemFileInfoResponse &resp);
api::Status ExtractFileSystem(FsSession &s, const api::CallContext &ctx, const pb::ExtractFromFileSystemRequest &req,
                              const std::vector<std::string> &browse_roots, pb::ExtractFromFileSystemResponse &resp);

// One file an import would make a program of, or leaves out.
struct ImportPlanItem {
  std::string path;            // session path
  std::string container_path;  // "zip://fw.zip!/bin/x"
  std::string name;            // the program's name (display)
  std::vector<std::string> folders;  // keep_folders: folder names under the target folder
  std::string detected;
  std::string kind;            // Guess::kind
  std::string action;          // "import", "skipped"
  std::string reason;
  std::string language;        // a raw image's language from its header
  std::optional<std::uint64_t> load_address;
  bool detect_raw = false;     // run raw detection at import
};
api::Status PlanFileSystemImport(FsSession &s, const api::CallContext &ctx, const pb::ImportFromFileSystemRequest &req,
                                 std::vector<ImportPlanItem> &out, bool &capped);

}  // namespace revkit::backend
