// ProviderService: see providers_api.h and docs/providers.md.
#include "providers_api.h"

#include <google/protobuf/util/json_util.h>

#include <fstream>
#include <sstream>

namespace revkit::backend {
namespace fs = std::filesystem;
using api::Error;
using api::Status;
using api::StatusCode;

namespace {

constexpr std::uint64_t kMiB = 1ull << 20;

Status FromError(const providers::Error &e) {
  switch (e.code) {
    case providers::Error::Code::invalid_argument: return Error(StatusCode::kInvalidArgument, e.what());
    case providers::Error::Code::not_found: return Error(StatusCode::kNotFound, e.what());
    case providers::Error::Code::failed_precondition: return Error(StatusCode::kFailedPrecondition, e.what());
    case providers::Error::Code::resource_exhausted: return Error(StatusCode::kResourceExhausted, e.what());
    case providers::Error::Code::cancelled: return Error(StatusCode::kCancelled, e.what());
  }
  return Error(StatusCode::kInternal, e.what());
}

template <class Fn>
Status Guard(Fn &&fn) {
  try {
    return fn();
  } catch (const providers::Error &e) {
    return FromError(e);
  } catch (const std::exception &e) {
    return Error(StatusCode::kInternal, e.what());
  }
}

pb::ProviderRunStatus StatusOf(providers::RunStatus s) {
  switch (s) {
    case providers::RunStatus::ok: return pb::PROVIDER_RUN_STATUS_OK;
    case providers::RunStatus::failed: return pb::PROVIDER_RUN_STATUS_FAILED;
    case providers::RunStatus::crashed: return pb::PROVIDER_RUN_STATUS_CRASHED;
    case providers::RunStatus::timeout: return pb::PROVIDER_RUN_STATUS_TIMEOUT;
    case providers::RunStatus::out_of_memory: return pb::PROVIDER_RUN_STATUS_OUT_OF_MEMORY;
    case providers::RunStatus::output_limit: return pb::PROVIDER_RUN_STATUS_OUTPUT_LIMIT;
    case providers::RunStatus::cancelled: return pb::PROVIDER_RUN_STATUS_UNSPECIFIED;
    case providers::RunStatus::sandbox_error: return pb::PROVIDER_RUN_STATUS_SANDBOX_ERROR;
  }
  return pb::PROVIDER_RUN_STATUS_UNSPECIFIED;
}

// Valid UTF-8, with what isn't replaced by U+FFFD (a proto string must be).
std::string Utf8(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size();) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    std::size_t n = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    bool ok = n != 0 && i + n <= s.size();
    for (std::size_t j = 1; ok && j < n; ++j) ok = (static_cast<unsigned char>(s[i + j]) >> 6) == 2;
    if (ok && n == 2 && c < 0xc2) ok = false;  // overlong
    if (ok) {
      out.append(s.substr(i, n));
      i += n;
    } else {
      out += "\xef\xbf\xbd";
      ++i;
    }
  }
  return out;
}

void FillKind(const providers::InputKind &k, pb::ProviderInputKind *out) {
  out->set_kind(k.kind);
  out->set_version(k.version);
  out->set_description(k.description);
}

void FillLimits(const providers::Settings &s, pb::ProviderLimits *out) {
  out->set_timeout_seconds(static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(s.limits.timeout).count()));
  out->set_memory_bytes(s.limits.memory_bytes);
  out->set_output_bytes(s.limits.output_bytes);
  out->set_output_files(s.limits.output_files);
  out->set_max_input_bytes(s.max_input_bytes);
}

}  // namespace

void ToProto(const providers::Settings &s, pb::ProviderSettings &out) {
  out.Clear();
  out.set_enabled(s.enabled);
  for (const providers::ProviderConfig &c : s.providers) {
    auto *p = out.add_providers();
    p->set_name(c.name);
    p->set_path(c.path);
    p->set_disabled(c.disabled);
  }
  out.set_java_path(s.java);
  out.set_node_path(s.node);
  out.set_dotnet_root(s.dotnet_root);
  out.set_timeout_seconds(static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(s.limits.timeout).count()));
  out.set_memory_bytes(s.limits.memory_bytes);
  out.set_output_bytes(s.limits.output_bytes);
  out.set_output_files(s.limits.output_files);
  out.set_max_input_bytes(s.max_input_bytes);
  out.set_cache_max_bytes(s.cache_max_bytes);
  out.set_allow_weak_sandbox(s.allow_weak_sandbox);
}

std::string FromProto(const pb::ProviderSettings &in, providers::Settings &out) {
  providers::Settings s;
  s.enabled = in.enabled();
  if (in.providers_size() > 64) return "at most 64 providers";
  for (const pb::ProviderConfig &c : in.providers()) {
    if (!providers::find_definition(c.name())) return "no provider named \"" + c.name().substr(0, 100) + "\"";
    if (!c.path().empty() && (c.path().size() > 4096 || !fs::path(c.path()).is_absolute()))
      return c.name() + ": the path must be absolute";
    s.providers.push_back({c.name(), c.path(), c.disabled()});
  }
  for (const std::string *p : {&in.java_path(), &in.node_path(), &in.dotnet_root()})
    if (!p->empty() && (p->size() > 4096 || !fs::path(*p).is_absolute())) return "\"" + p->substr(0, 200) + "\" isn't absolute";
  s.java = in.java_path();
  s.node = in.node_path();
  s.dotnet_root = in.dotnet_root();
  const providers::SandboxLimits d;
  if (in.timeout_seconds() > 3600) return "timeout_seconds: at most 3600";
  if (in.memory_bytes() && (in.memory_bytes() < 256 * kMiB || in.memory_bytes() > (64ull << 30)))
    return "memory_bytes: between 256 MiB and 64 GiB";
  if (in.output_bytes() && (in.output_bytes() < kMiB || in.output_bytes() > (16ull << 30)))
    return "output_bytes: between 1 MiB and 16 GiB";
  if (in.output_files() > 10'000'000) return "output_files: at most 10,000,000";
  if (in.max_input_bytes() > (16ull << 30)) return "max_input_bytes: at most 16 GiB";
  s.limits.timeout = in.timeout_seconds() ? std::chrono::milliseconds(1000ull * in.timeout_seconds()) : d.timeout;
  s.limits.memory_bytes = in.memory_bytes() ? in.memory_bytes() : d.memory_bytes;
  s.limits.output_bytes = in.output_bytes() ? in.output_bytes() : d.output_bytes;
  s.limits.output_files = in.output_files() ? in.output_files() : d.output_files;
  if (in.max_input_bytes()) s.max_input_bytes = in.max_input_bytes();
  if (in.cache_max_bytes()) s.cache_max_bytes = in.cache_max_bytes();
  s.allow_weak_sandbox = in.allow_weak_sandbox();
  out = std::move(s);
  return {};
}

ProviderApi::ProviderApi(ProviderOptions o, std::string project_dir) : project_dir_(std::move(project_dir)) {
  fs::path cache;
  if (!project_dir_.empty()) {
    settings_file_ = fs::path(project_dir_) / ".revkit" / "providers.json";
    cache = fs::path(project_dir_) / ".revkit" / "providers";
  } else {
    // In memory: results live as long as the daemon.
    std::string tmpl = (fs::temp_directory_path() / "rk-providers-XXXXXX").string();
    if (::mkdtemp(tmpl.data()) != nullptr) temp_cache_ = tmpl;
    cache = temp_cache_;
  }
  providers::Settings s;
  s.enabled = o.enabled;
  for (const std::string &p : o.paths) {
    const auto eq = p.find('=');
    if (eq == std::string::npos) continue;
    s.providers.push_back({p.substr(0, eq), p.substr(eq + 1), false});
  }
  for (const std::string &n : o.disabled) {
    bool found = false;
    for (auto &c : s.providers)
      if (c.name == n) found = c.disabled = true;
    if (!found) s.providers.push_back({n, "", true});
  }
  if (o.timeout_seconds > 0) s.limits.timeout = std::chrono::milliseconds(static_cast<std::int64_t>(o.timeout_seconds * 1000));
  if (o.memory_bytes) s.limits.memory_bytes = o.memory_bytes;
  s.allow_weak_sandbox = o.allow_weak_sandbox;
  service_ = std::make_unique<providers::Service>(s, cache);
  if (!o.from_command_line) Load();
}

ProviderApi::~ProviderApi() {
  if (!temp_cache_.empty()) {
    std::error_code ec;
    fs::remove_all(temp_cache_, ec);
  }
}

void ProviderApi::Save() {
  if (settings_file_.empty()) return;
  pb::ProviderSettings s;
  ToProto(service_->settings(), s);
  std::string json;
  if (!google::protobuf::util::MessageToJsonString(s, &json).ok()) return;
  std::error_code ec;
  fs::create_directories(settings_file_.parent_path(), ec);
  const fs::path tmp = settings_file_.string() + ".tmp";
  {
    std::ofstream(tmp, std::ios::trunc) << json << "\n";
  }
  fs::rename(tmp, settings_file_, ec);
}

void ProviderApi::Load() {
  std::error_code ec;
  if (settings_file_.empty() || !fs::is_regular_file(settings_file_, ec)) return;
  std::ifstream in(settings_file_);
  std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  pb::ProviderSettings p;
  if (!google::protobuf::util::JsonStringToMessage(json, &p).ok()) return;
  providers::Settings s;
  // (Settings that no longer pass the checks are dropped, not trusted.)
  if (FromProto(p, s).empty()) service_->set_settings(s);
}

void ProviderApi::FillInfo(const providers::Definition &d, const providers::ToolStatus &t, bool admin,
                           pb::ProviderInfo *out) {
  out->set_name(d.name);
  out->set_title(d.title);
  out->set_tool(d.tool);
  out->set_license(d.license);
  out->set_homepage(d.homepage);
  for (const std::string &k : d.kinds) out->add_kinds(k);
  out->set_output(d.shape == providers::Shape::file ? "file" : "tree");
  out->set_language(d.language);
  out->set_available(t.available);
  out->set_disabled(t.disabled);
  out->set_version(Utf8(t.version));
  // A reason names host paths: admins see it whole, others what it is.
  out->set_reason(admin ? Utf8(t.reason) : t.available ? "" : t.disabled ? "turned off by an admin" : d.tool + " isn't available");
  if (admin) {
    out->set_path(Utf8(t.path));
    out->set_found_by(t.found_by);
    for (const fs::path &p : t.read_paths) out->add_read_paths(Utf8(p.string()));
  }
}

Status ProviderApi::Identify(const api::CallContext &ctx, const pb::ProviderInput &in, const Resolve &resolve,
                             Input &out, Known &known) {
  if (in.source_case() == pb::ProviderInput::SOURCE_NOT_SET)
    return Error(StatusCode::kInvalidArgument, "input.program_id or input.file is required");
  if (auto st = resolve(ctx, in, out); !st.ok()) return st;
  // The memo's key names the bytes too (their size, their ends): a program
  // deleted and imported again under its name is other bytes.
  {
    const std::size_t n = out.bytes.size(), edge = std::min<std::size_t>(n, 64 * 1024);
    std::string sample(reinterpret_cast<const char *>(out.bytes.data()), edge);
    sample.append(reinterpret_cast<const char *>(out.bytes.data()) + (n - edge), edge);
    out.memo_key += ":" + std::to_string(n) + ":" + providers::sha256_hex(std::as_bytes(std::span(sample)));
  }
  {
    std::lock_guard lock(mu_);
    if (auto it = known_.find(out.memo_key); it != known_.end()) {
      known = it->second;
      return Status::Ok();
    }
  }
  known.sha256 = providers::sha256_hex(out.bytes);
  known.kind = providers::detect_kind(out.bytes, out.name);
  std::lock_guard lock(mu_);
  if (known_.size() >= 1024) known_.clear();
  known_[out.memo_key] = known;
  return Status::Ok();
}

Status ProviderApi::ListProviders(const api::CallContext &ctx, const pb::ListProvidersRequest &req,
                                  pb::ListProvidersResponse &resp, const Resolve &resolve) {
  return Guard([&]() -> Status {
    Known known;
    Input input;
    if (req.has_input())
      if (auto st = Identify(ctx, req.input(), resolve, input, known); !st.ok()) return st;
    const std::vector<providers::ToolStatus> tools = service_->tools(req.refresh());
    for (const providers::Definition &d : service_->all_definitions())
      for (const providers::ToolStatus &t : tools)
        if (t.name == d.name) FillInfo(d, t, ctx.caller_admin, resp.add_providers());
    if (req.has_input()) {
      FillKind(known.kind, resp.mutable_input_kind());
      if (known.kind) {
        for (const std::string &n : service_->for_kind(known.kind.kind)) {
          resp.add_applicable(n);
          if (service_->cached(known.sha256, known.kind, n)) resp.add_cached(n);
        }
        resp.set_default_provider(service_->default_provider(known.kind.kind));
      }
    }
    resp.set_sandbox(service_->support().describe());
    FillLimits(service_->settings(), resp.mutable_limits());
    return Status::Ok();
  });
}

Status ProviderApi::DecompileExternal(const api::CallContext &ctx, const pb::DecompileExternalRequest &req,
                                      pb::DecompileExternalResponse &resp, const Resolve &resolve) {
  return Guard([&]() -> Status {
    Known known;
    Input input;
    if (auto st = Identify(ctx, req.input(), resolve, input, known); !st.ok()) return st;
    if (!known.kind)
      return Error(StatusCode::kFailedPrecondition,
                   "this isn't a format any external decompiler takes (.NET, DEX, APK, jar, class, .pyc, Lua, wasm, "
                   "JavaScript)");
    const providers::Result r =
        service_->decompile(input.bytes, input.name, known.kind, req.provider(), req.refresh(), ctx.cancelled);
    resp.set_provider(r.provider);
    resp.set_provider_version(Utf8(r.version));
    FillKind(r.input, resp.mutable_input_kind());
    resp.set_input_sha256(r.sha256);
    resp.set_status(StatusOf(r.status));
    resp.set_detail(Utf8(r.detail));
    resp.set_stderr_tail(Utf8(r.stderr_tail));
    resp.set_seconds(r.seconds);
    resp.set_cached(r.cached);
    resp.set_output(r.shape == providers::Shape::file ? "file" : "tree");
    resp.set_language(r.language);
    for (const providers::OutputFile &f : r.files) {
      auto *o = resp.add_files();
      o->set_path(f.path);
      o->set_size(f.size);
      o->set_language(f.language);
    }
    resp.set_total_bytes(r.total_bytes);
    resp.set_sandbox(Utf8(r.sandbox));
    if (!r.main_file.empty() && !r.dir.empty()) {
      const std::uint64_t max = req.max_inline_bytes() ? std::min<std::uint64_t>(req.max_inline_bytes(), 16 * kMiB) : kMiB;
      std::uint64_t size = 0;
      const std::string text = service_->read_file(r, r.main_file, 0, max, size);
      resp.set_main_file(r.main_file);
      resp.set_main_text(Utf8(text));
      resp.set_main_truncated(size > text.size());
    }
    return Status::Ok();
  });
}

Status ProviderApi::ReadProviderOutput(const api::CallContext &ctx, const pb::ReadProviderOutputRequest &req,
                                       pb::ReadProviderOutputResponse &resp, const Resolve &resolve) {
  return Guard([&]() -> Status {
    Known known;
    Input input;
    if (auto st = Identify(ctx, req.input(), resolve, input, known); !st.ok()) return st;
    if (!known.kind) return Error(StatusCode::kFailedPrecondition, "this isn't a format any external decompiler takes");
    auto r = service_->cached(known.sha256, known.kind, req.provider());
    if (!r) return Error(StatusCode::kNotFound, "no result for this input yet: call DecompileExternal first");
    const std::uint64_t max = req.max_bytes() ? std::min<std::uint64_t>(req.max_bytes(), 16 * kMiB) : kMiB;
    std::uint64_t size = 0;
    std::string data = service_->read_file(*r, req.path(), req.offset(), max, size);
    resp.set_path(req.path());
    resp.set_size(size);
    resp.set_language(providers::language_of(req.path()));
    resp.set_truncated(req.offset() + data.size() < size);
    *resp.mutable_data() = std::move(data);
    return Status::Ok();
  });
}

Status ProviderApi::GetProviderSettings(const api::CallContext &, const pb::GetProviderSettingsRequest &,
                                        pb::GetProviderSettingsResponse &resp) {
  ToProto(service_->settings(), *resp.mutable_settings());
  resp.set_cache_dir(service_->cache_root().string());
  return Status::Ok();
}

Status ProviderApi::SetProviderSettings(const api::CallContext &ctx, const pb::SetProviderSettingsRequest &req,
                                        pb::SetProviderSettingsResponse &resp) {
  return Guard([&]() -> Status {
    providers::Settings s;
    if (std::string why = FromProto(req.settings(), s); !why.empty()) return Error(StatusCode::kInvalidArgument, why);
    service_->set_settings(s);
    Save();
    ToProto(service_->settings(), *resp.mutable_settings());
    const std::vector<providers::ToolStatus> tools = service_->tools(true);
    for (const providers::Definition &d : service_->all_definitions())
      for (const providers::ToolStatus &t : tools)
        if (t.name == d.name) FillInfo(d, t, ctx.caller_admin, resp.add_providers());
    return Status::Ok();
  });
}

}  // namespace revkit::backend
