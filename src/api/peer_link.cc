#include "revkit/api/peer_link.h"

#include "revkit/v1/sync.grpc.pb.h"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <thread>

namespace revkit::api {

namespace {

// The op encoding this build speaks (backend's kSyncFormat). A peer with
// another one refuses our calls with FAILED_PRECONDITION.
constexpr std::uint32_t kFormat = 1;
constexpr std::uint32_t kChunk = 1u << 20;

std::string StripScheme(std::string target) {
  for (const char *p : {"grpc://", "http://"})
    if (target.starts_with(p)) target.erase(0, std::char_traits<char>::length(p));
  if (!target.empty() && target.back() == '/') target.pop_back();
  return target;
}

// The local backend's pull stream: the backend only enqueues.
class LocalQueue final : public PullSink {
 public:
  void Send(pb::PullResponse event) override {
    std::lock_guard lock(mu_);
    if (end_) return;
    events_.push_back(std::move(event));
    cv_.notify_one();
  }
  void End(Status status) override {
    std::lock_guard lock(mu_);
    if (!end_) end_ = std::move(status);
    cv_.notify_one();
  }
  // An event, the end, or neither (timeout).
  std::pair<std::optional<pb::PullResponse>, std::optional<Status>> Pop(std::chrono::steady_clock::time_point until) {
    std::unique_lock lock(mu_);
    cv_.wait_until(lock, until, [&] { return !events_.empty() || end_; });
    if (!events_.empty()) {
      auto e = std::move(events_.front());
      events_.pop_front();
      return {std::move(e), std::nullopt};
    }
    return {std::nullopt, end_};
  }

 private:
  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<pb::PullResponse> events_;
  std::optional<Status> end_;
};

}  // namespace

struct PeerLink::Impl {
  std::shared_ptr<Backend> local;
  PeerLinkOptions opt;
  std::unique_ptr<pb::SyncService::Stub> stub;

  std::mutex mu;
  std::condition_variable cv;
  bool stop = false;
  std::set<grpc::ClientContext *> calls;  // open remote calls, cancelled on stop
  std::map<std::string, std::vector<std::thread>> projects;
  std::thread manager;

  bool stopping() {
    std::lock_guard lock(mu);
    return stop;
  }
  // Sleeps unless stopped first; returns whether to go on.
  bool sleep(std::chrono::milliseconds d) {
    std::unique_lock lock(mu);
    return !cv.wait_for(lock, d, [&] { return stop; });
  }
  void log(const std::string &msg) {
    if (opt.verbose) std::cerr << "rk-daemon: peer " << opt.target << ": " << msg << "\n";
  }

  // A remote call registered for cancellation for its lifetime.
  struct Call {
    Impl &impl;
    grpc::ClientContext ctx;
    explicit Call(Impl &i, std::optional<std::chrono::seconds> deadline = std::chrono::seconds(60)) : impl(i) {
      if (deadline) ctx.set_deadline(std::chrono::system_clock::now() + *deadline);
      if (!impl.opt.bearer_token.empty()) ctx.AddMetadata("authorization", "Bearer " + impl.opt.bearer_token);
      std::lock_guard lock(impl.mu);
      impl.calls.insert(&ctx);
      if (impl.stop) ctx.TryCancel();
    }
    ~Call() {
      std::lock_guard lock(impl.mu);
      impl.calls.erase(&ctx);
    }
  };

  void Run() {
    while (!stopping()) {
      std::set<std::string> ids;
      {
        CallContext ctx;
        pb::GetSyncStateResponse resp;
        if (local->GetSyncState(ctx, {}, resp).ok())
          for (const auto &p : resp.projects()) ids.insert(p.project_id());
      }
      {
        Call call(*this, std::chrono::seconds(10));
        pb::GetSyncStateResponse resp;
        grpc::Status st = stub->GetSyncState(&call.ctx, {}, &resp);
        if (st.ok()) {
          if (resp.format() != kFormat) log("speaks sync format " + std::to_string(resp.format()) + ", not ours");
          for (const auto &p : resp.projects()) ids.insert(p.project_id());
        } else if (st.error_code() == grpc::StatusCode::UNAUTHENTICATED ||
                   st.error_code() == grpc::StatusCode::PERMISSION_DENIED) {
          log("refused: " + st.error_message());
        }
      }
      {
        std::lock_guard lock(mu);
        if (stop) break;
        for (const std::string &id : ids) {
          if (projects.contains(id)) continue;
          auto &threads = projects[id];
          threads.emplace_back([this, id] { Inbound(id); });
          threads.emplace_back([this, id] { Outbound(id); });
        }
      }
      sleep(opt.rescan);
    }
  }

  // Our programs whose file the peer is missing: send each in chunks.
  void SendFiles(const std::string &project, const google::protobuf::RepeatedPtrField<pb::MissingProgram> &missing,
                 std::uint64_t from_replica) {
    for (const pb::MissingProgram &m : missing) {
      for (std::uint64_t offset = 0; !stopping();) {
        CallContext ctx;
        pb::FetchProgramRequest req;
        req.set_project_id(project);
        req.set_sha256(m.sha256());
        req.set_offset(offset);
        req.set_max_bytes(kChunk);
        pb::FetchProgramResponse chunk;
        if (!local->FetchProgram(ctx, req, chunk).ok()) break;  // we don't have it (yet)
        Call call(*this);
        pb::PushRequest push;
        push.set_project_id(project);
        push.set_from_replica(from_replica);
        push.set_format(kFormat);
        *push.mutable_program() = chunk.chunk();
        pb::PushResponse resp;
        if (grpc::Status st = stub->Push(&call.ctx, push, &resp); !st.ok()) {
          log("sending " + m.program_id() + ": " + st.error_message());
          break;
        }
        offset += chunk.chunk().data().size();
        if (offset >= chunk.chunk().total_size() || chunk.chunk().data().empty()) break;
      }
    }
  }

  // Programs we hold the record of but not the file: fetch from the peer.
  void FetchFiles(const std::string &project, const google::protobuf::RepeatedPtrField<pb::MissingProgram> &missing) {
    for (const pb::MissingProgram &m : missing) {
      for (std::uint64_t offset = 0; !stopping();) {
        Call call(*this);
        pb::FetchProgramRequest req;
        req.set_project_id(project);
        req.set_sha256(m.sha256());
        req.set_offset(offset);
        req.set_max_bytes(kChunk);
        pb::FetchProgramResponse chunk;
        if (!stub->FetchProgram(&call.ctx, req, &chunk).ok()) break;  // the peer doesn't have it (yet)
        CallContext ctx;
        pb::PushRequest push;
        push.set_project_id(project);
        push.set_format(kFormat);
        *push.mutable_program() = chunk.chunk();
        pb::PushResponse resp;
        if (Status st = local->Push(ctx, push, resp); !st.ok()) {
          log("loading " + m.program_id() + ": " + st.message);
          break;
        }
        offset += chunk.chunk().data().size();
        if (offset >= chunk.chunk().total_size() || chunk.chunk().data().empty()) break;
      }
    }
  }

  // Peer -> local.
  void Inbound(const std::string &project) {
    auto backoff = opt.min_backoff;
    while (!stopping()) {
      // Our state (creating the project here if only the peer has it).
      CallContext ctx;
      pb::PushRequest hello;
      hello.set_project_id(project);
      hello.set_format(kFormat);
      hello.set_create_project(true);
      pb::PushResponse mine;
      if (Status st = local->Push(ctx, hello, mine); !st.ok()) {
        log("project " + project + ": " + st.message);
        if (!sleep(opt.max_backoff)) return;
        continue;
      }
      FetchFiles(project, mine.missing_programs());

      Call call(*this, std::nullopt);
      pb::PullRequest req;
      req.set_project_id(project);
      req.set_replica(mine.replica());
      *req.mutable_have() = mine.version_vector();
      req.set_format(kFormat);
      req.set_live(true);
      req.set_include_presence(opt.presence);
      req.set_max_batch(500);
      req.set_peer(opt.name);
      auto reader = stub->Pull(&call.ctx, req);
      pb::PullResponse ev;
      std::uint64_t remote = 0;
      google::protobuf::RepeatedPtrField<pb::MissingProgram> missing;
      while (reader->Read(&ev)) {
        backoff = opt.min_backoff;
        pb::PushRequest push;
        push.set_project_id(project);
        push.set_from_replica(remote);
        push.set_format(kFormat);
        switch (ev.event_case()) {
          case pb::PullResponse::kHello:
            remote = ev.hello().replica();
            log("project " + project + ": pulling");
            continue;
          case pb::PullResponse::kOps: *push.mutable_ops() = std::move(*ev.mutable_ops()->mutable_ops()); break;
          case pb::PullResponse::kPresence: *push.add_presence() = std::move(*ev.mutable_presence()); break;
          case pb::PullResponse::kHeartbeat:
            // Retry files the peer didn't have yet.
            if (!missing.empty()) {
              FetchFiles(project, missing);
              CallContext c;
              pb::GetSyncStateRequest sreq;
              sreq.set_project_id(project);
              pb::GetSyncStateResponse sresp;
              if (local->GetSyncState(c, sreq, sresp).ok() && sresp.projects_size())
                missing = sresp.projects(0).missing_programs();
            }
            continue;
          default: continue;
        }
        CallContext c;
        pb::PushResponse resp;
        if (Status st = local->Push(c, push, resp); !st.ok()) {
          log("project " + project + ": applying: " + st.message);
          call.ctx.TryCancel();
          break;
        }
        if (resp.rejected()) log("project " + project + ": " + std::to_string(resp.rejected()) + " ops rejected");
        if (!resp.missing_programs().empty()) {
          FetchFiles(project, resp.missing_programs());
          missing = resp.missing_programs();
        }
      }
      grpc::Status st = reader->Finish();
      if (stopping()) return;
      log("project " + project + ": pull ended: " + st.error_message());
      if (!sleep(backoff)) return;
      backoff = std::min(backoff * 2, opt.max_backoff);
    }
  }

  // Local -> peer.
  void Outbound(const std::string &project) {
    auto backoff = opt.min_backoff;
    while (!stopping()) {
      // What the peer holds (nothing if it lacks the project: the first
      // push creates it).
      std::uint64_t remote = 0;
      pb::VersionVector have;
      google::protobuf::RepeatedPtrField<pb::MissingProgram> remote_missing;
      {
        Call call(*this, std::chrono::seconds(10));
        pb::GetSyncStateRequest req;
        req.set_project_id(project);
        pb::GetSyncStateResponse resp;
        grpc::Status st = stub->GetSyncState(&call.ctx, req, &resp);
        if (st.ok() && resp.projects_size()) {
          remote = resp.projects(0).replica();
          have = resp.projects(0).version_vector();
          remote_missing = resp.projects(0).missing_programs();
        } else if (st.error_code() != grpc::StatusCode::NOT_FOUND) {
          log("project " + project + ": " + st.error_message());
          if (!sleep(backoff)) return;
          backoff = std::min(backoff * 2, opt.max_backoff);
          continue;
        }
      }
      auto queue = std::make_shared<LocalQueue>();
      std::unique_ptr<Subscription> sub;
      {
        CallContext ctx;
        pb::PullRequest req;
        req.set_project_id(project);
        req.set_replica(remote);
        *req.mutable_have() = have;
        req.set_format(kFormat);
        req.set_live(true);
        req.set_include_presence(opt.presence);
        req.set_max_batch(500);
        req.set_peer("peer link to " + opt.target);
        if (Status st = local->Pull(ctx, req, queue, sub); !st.ok()) {
          log("project " + project + ": local pull: " + st.message);
          if (!sleep(opt.max_backoff)) return;
          continue;
        }
      }
      std::uint64_t mine = 0;
      bool restart = false;
      auto push = [&](pb::PushRequest &req) {
        Call call(*this);
        req.set_project_id(project);
        req.set_from_replica(mine);
        req.set_format(kFormat);
        req.set_create_project(true);
        pb::PushResponse resp;
        grpc::Status st = stub->Push(&call.ctx, req, &resp);
        if (!st.ok()) {
          log("project " + project + ": push: " + st.error_message());
          return false;
        }
        backoff = opt.min_backoff;
        remote_missing = resp.missing_programs();
        if (!remote_missing.empty()) SendFiles(project, remote_missing, mine);
        // The peer just created the project: stream again under its
        // replica id, so its own ops aren't echoed to it.
        if (!remote && resp.replica()) restart = true;
        return true;
      };
      bool ok = true;
      auto next_retry = std::chrono::steady_clock::now();
      while (ok && !restart && !stopping()) {
        auto [event, end] = queue->Pop(std::chrono::steady_clock::now() + std::chrono::milliseconds(200));
        if (end) break;
        if (!event) {
          if (!remote_missing.empty() && std::chrono::steady_clock::now() >= next_retry) {
            SendFiles(project, remote_missing, mine);
            next_retry = std::chrono::steady_clock::now() + std::chrono::seconds(1);
          }
          continue;
        }
        pb::PushRequest req;
        switch (event->event_case()) {
          case pb::PullResponse::kHello:
            mine = event->hello().replica();
            if (remote) {
              if (!remote_missing.empty()) SendFiles(project, remote_missing, mine);
              continue;
            }
            break;  // an empty push creates the project on the peer
          case pb::PullResponse::kOps: *req.mutable_ops() = std::move(*event->mutable_ops()->mutable_ops()); break;
          case pb::PullResponse::kPresence: *req.add_presence() = std::move(*event->mutable_presence()); break;
          default: continue;
        }
        ok = push(req);
      }
      sub.reset();
      if (stopping()) return;
      if (restart) continue;
      if (!sleep(backoff)) return;
      backoff = std::min(backoff * 2, opt.max_backoff);
    }
  }
};

PeerLink::PeerLink(std::shared_ptr<Backend> local, PeerLinkOptions options) : impl_(std::make_unique<Impl>()) {
  impl_->local = std::move(local);
  impl_->opt = std::move(options);
  impl_->opt.target = StripScheme(impl_->opt.target);
  grpc::ChannelArguments args;
  args.SetMaxReceiveMessageSize(64 << 20);
  args.SetMaxSendMessageSize(64 << 20);
  std::shared_ptr<grpc::ChannelCredentials> creds = grpc::InsecureChannelCredentials();
  if (impl_->opt.tls) {
    grpc::SslCredentialsOptions ssl;
    ssl.pem_root_certs = impl_->opt.tls_root_pem;
    creds = grpc::SslCredentials(ssl);
    if (!impl_->opt.tls_server_name.empty()) args.SetSslTargetNameOverride(impl_->opt.tls_server_name);
  }
  auto channel = grpc::CreateCustomChannel(impl_->opt.target, creds, args);
  impl_->stub = pb::SyncService::NewStub(channel);
  impl_->manager = std::thread([impl = impl_.get()] { impl->Run(); });
}

PeerLink::~PeerLink() {
  {
    std::lock_guard lock(impl_->mu);
    impl_->stop = true;
    for (grpc::ClientContext *c : impl_->calls) c->TryCancel();
  }
  impl_->cv.notify_all();
  impl_->manager.join();
  // No new threads start once stop is set.
  for (auto &[id, threads] : impl_->projects)
    for (std::thread &t : threads) t.join();
}

const std::string &PeerLink::target() const { return impl_->opt.target; }

}  // namespace revkit::api
