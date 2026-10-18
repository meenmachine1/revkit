// ProviderService (api_minor 92, feature "external-decompilers";
// docs/providers.md): external decompilers run in the sandbox on a
// program's file or a file of a file system session. The image backend
// resolves the input (and the caller's right to it); this is the rest:
// settings (and their file), the tools, runs, the cache and reads.
#pragma once

#include "revkit/api/backend.h"
#include "revkit/providers/providers.h"
#include "revkit/v1/provider.pb.h"

#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// How the daemon starts (rk-daemon's flags): what it was given wins over
// the settings file.
struct ProviderOptions {
  bool enabled = true;
  std::vector<std::string> paths;     // "jadx=/opt/jadx/lib/jadx-1.5.6-all.jar"
  std::vector<std::string> disabled;  // names
  double timeout_seconds = 0;         // 0: the default
  std::uint64_t memory_bytes = 0;     // 0: the default
  bool allow_weak_sandbox = false;
  // Anything above set on the command line: the settings file isn't read.
  bool from_command_line = false;
};

class ProviderApi {
 public:
  // An input's bytes as the image backend found them (kept alive by `keep`).
  struct Input {
    std::span<const std::byte> bytes;
    std::string name;
    std::string memo_key;  // identifies the bytes: "program:<id>", "fs:<session>:<path>"
    std::shared_ptr<const void> keep;
  };
  using Resolve = std::function<api::Status(const api::CallContext &, const pb::ProviderInput &, Input &)>;

  ProviderApi(ProviderOptions options, std::string project_dir);
  ~ProviderApi();

  api::Status ListProviders(const api::CallContext &ctx, const pb::ListProvidersRequest &req,
                            pb::ListProvidersResponse &resp, const Resolve &resolve);
  api::Status DecompileExternal(const api::CallContext &ctx, const pb::DecompileExternalRequest &req,
                                pb::DecompileExternalResponse &resp, const Resolve &resolve);
  api::Status ReadProviderOutput(const api::CallContext &ctx, const pb::ReadProviderOutputRequest &req,
                                 pb::ReadProviderOutputResponse &resp, const Resolve &resolve);
  api::Status GetProviderSettings(const api::CallContext &ctx, const pb::GetProviderSettingsRequest &req,
                                  pb::GetProviderSettingsResponse &resp);
  api::Status SetProviderSettings(const api::CallContext &ctx, const pb::SetProviderSettingsRequest &req,
                                  pb::SetProviderSettingsResponse &resp);

  providers::Service &service() { return *service_; }

 private:
  struct Known {
    std::string sha256;
    providers::InputKind kind;
  };
  api::Status Identify(const api::CallContext &ctx, const pb::ProviderInput &in, const Resolve &resolve, Input &out,
                       Known &known);
  void FillInfo(const providers::Definition &d, const providers::ToolStatus &t, bool admin, pb::ProviderInfo *out);
  void Save();
  void Load();

  std::string project_dir_;
  std::filesystem::path settings_file_;
  std::unique_ptr<providers::Service> service_;
  std::filesystem::path temp_cache_;  // without a project directory
  std::mutex mu_;
  std::map<std::string, Known> known_;  // memo_key -> what the bytes are
};

// The settings as the API shows them, and back (validated: an error says
// what is wrong).
void ToProto(const providers::Settings &s, pb::ProviderSettings &out);
std::string FromProto(const pb::ProviderSettings &in, providers::Settings &out);

}  // namespace revkit::backend
