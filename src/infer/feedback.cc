#include "revkit/infer/feedback.h"

#include "sigdb.h"

#include "revkit/facts/thread_pool.h"

#include <mutex>

namespace revkit::infer {

namespace {

class FinalEnv : public SymbolEnv {
 public:
  FinalEnv(const CallGraph &cg, const FixpointResult &fix, const loader::Image &image, bool feedback)
      : cg_(cg), fix_(fix), org_(data_org(image)), db_(SigDb::for_image(image)), feedback_(feedback) {}

  std::optional<FunctionSymbol> function(std::uint64_t entry) override {
    const CallNode *n = cg_.find(entry);
    if (n == nullptr) return std::nullopt;
    FunctionSymbol f;
    f.name = n->name;
    f.no_return = n->no_return;
    if (!n->import.empty()) f.proto = db_.find(n->import, org_);
    else if (feedback_)
      if (const Prototype *p = fix_.find(entry)) f.proto = *p;
    return f;
  }
  std::optional<FunctionSymbol> import_slot(std::uint64_t slot) override {
    const std::string *name = cg_.slot(slot);
    if (name == nullptr) return std::nullopt;
    FunctionSymbol f;
    f.name = *name;
    f.no_return = analysis::is_known_no_return(*name);
    f.proto = db_.find(*name, org_);
    return f;
  }

 private:
  const CallGraph &cg_;
  const FixpointResult &fix_;
  DataOrg org_;
  const SigDb &db_;
  bool feedback_;
};

}  // namespace

std::map<std::uint64_t, std::string> decompile_all(const facts::Snapshot &snapshot, const ProgramKey &program,
                                                   const std::vector<std::uint64_t> &entries, bool feedback,
                                                   facts::ThreadPool *pool) {
  auto img = snapshot.get<EffectiveImage>(program);
  auto cg = snapshot.get<CallGraphQuery>(program);
  auto fix = snapshot.get<Fixpoint>(program);
  std::vector<std::string> out(entries.size());
  auto one = [&](std::size_t i) {
    FinalEnv env(*cg, *fix, *img->image, feedback);
    DecompilerPool::Lease d = img->pool->acquire();
    RunOptions o;
    o.want_c = true;
    Observation r = d->run(entries[i], env, o);
    out[i] = r.ok ? r.c : "/* error: " + r.error + " */";
  };
  if (pool != nullptr) pool->parallel_for(entries.size(), one);
  else
    for (std::size_t i = 0; i < entries.size(); ++i) one(i);
  std::map<std::uint64_t, std::string> m;
  for (std::size_t i = 0; i < entries.size(); ++i) m[entries[i]] = std::move(out[i]);
  return m;
}

}  // namespace revkit::infer
