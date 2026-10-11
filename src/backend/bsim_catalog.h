// What BSimService (image_backend.cc, docs/bsim.md) builds on: the daemon's
// open BSim databases, a project's attached list (a NOTE), and conversions
// between revkit::bsim and the API's messages.
#pragma once

#include "revkit/bsim/store.h"
#include "revkit/v1/bsim.pb.h"

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// The project's attached databases: a NOTE with this tag at the project's
// address 0, one "attach <path>" line each.
inline constexpr const char *kBsimDatabasesTag = "revkit:bsim.databases";
std::vector<std::string> DecodeBsimAttached(const std::string &text);
std::string EncodeBsimAttached(const std::vector<std::string> &paths);

// One open database. Callers hold `mu` while they use `db`; Use() reloads
// what other processes wrote first.
struct BsimEntry {
  std::mutex mu;
  bsim::Database db;
  explicit BsimEntry(bsim::Database d) : db(std::move(d)) {}
};

class BsimCatalog {
 public:
  // The open database at `path` (opened now if it isn't). Throws
  // bsim::BsimError.
  std::shared_ptr<BsimEntry> Open(const std::string &path);
  std::shared_ptr<BsimEntry> Create(const std::string &path, bsim::DatabaseInfo info);

 private:
  std::mutex mu_;
  std::map<std::string, std::shared_ptr<BsimEntry>> open_;
};

pb::BSimTemplate ToProto(bsim::Template t);
bsim::Template FromProto(pb::BSimTemplate t, bsim::Template fallback);
// Fills everything but `error`; the caller holds e.mu.
void FillBsimDatabase(const std::string &id, const bsim::Database &db, pb::BSimDatabase &out);
void FillBsimExecutable(const bsim::Executable &e, pb::BSimExecutable &out);
void FillBsimFunction(const bsim::Executable &e, const bsim::FunctionRecord &f, pb::BSimFunction &out);

}  // namespace revkit::backend
