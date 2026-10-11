#include "revkit/lift/budget.hh"

#include "action.hh"
#include "architecture.hh"
#include "funcdata.hh"

#include <algorithm>
#include <cstdio>
#include <vector>

namespace revkit::lift {
namespace {

// An action group's members (protected in ghidra::ActionGroup), through a
// pointer to member formed in a derived class.
struct GroupMembers : ghidra::ActionGroup {
  static std::vector<ghidra::Action *> &of(ghidra::ActionGroup &g) { return g.*(&GroupMembers::list); }
};

constexpr const char *kGroup = "revkit_budget";

class CheckRule final : public ghidra::Rule {
 public:
  explicit CheckRule(DecompileBudget *budget) : ghidra::Rule(kGroup, 0, "revkit_budget"), budget_(budget) {}
  ghidra::Rule *clone(const ghidra::ActionGroupList &) const override { return new CheckRule(budget_); }
  ghidra::int4 applyOp(ghidra::PcodeOp *, ghidra::Funcdata &data) override {
    budget_->check(data);
    return 0;
  }

 private:
  DecompileBudget *budget_;
};

class CheckAction final : public ghidra::Action {
 public:
  explicit CheckAction(DecompileBudget *budget) : ghidra::Action(0, "revkit_budget", kGroup), budget_(budget) {}
  ghidra::Action *clone(const ghidra::ActionGroupList &) const override { return new CheckAction(budget_); }
  ghidra::int4 apply(ghidra::Funcdata &data) override {
    budget_->check(data);
    return 0;
  }

 private:
  DecompileBudget *budget_;
};

void add_checks(ghidra::Action *act, DecompileBudget *budget) {
  if (act == nullptr) return;
  if (auto *pool = dynamic_cast<ghidra::ActionPool *>(act)) {
    pool->addRule(new CheckRule(budget));
  } else if (auto *group = dynamic_cast<ghidra::ActionGroup *>(act)) {
    std::vector<ghidra::Action *> &members = GroupMembers::of(*group);
    for (ghidra::Action *a : std::vector<ghidra::Action *>(members)) add_checks(a, budget);
    group->addAction(new CheckAction(budget));
  }
}

}  // namespace

void DecompileBudget::install(ghidra::Architecture &arch) {
  // The current root, and the one jump-table recovery runs on a partial
  // copy of the function (which reports its errors as warnings: a stop
  // there is thrown again by the next check outside).
  const std::string current = arch.allacts.getCurrentName();
  add_checks(arch.allacts.getCurrent(), this);
  add_checks(arch.allacts.setCurrent("jumptable"), this);
  arch.allacts.setCurrent(current);
}

void DecompileBudget::start(const DecompileLimits &limits) {
  limits_ = limits;
  started_ = Clock::now();
  deadline_ = limits.timeout_seconds > 0
                  ? started_ + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(limits.timeout_seconds))
                  : Clock::time_point::max();
  next_poll_ = started_;
  tick_ = 0;
  peak_ = 0;
  stopped_ = DecompileStop::none;
}

void DecompileBudget::check(const ghidra::Funcdata &fd) {
  if (stopped_ != DecompileStop::none) stop(stopped_);  // the decompiler may have caught the first throw
  if ((tick_++ & 63) != 0) return;
  const auto varnodes = static_cast<std::size_t>(fd.numVarnodes());
  peak_ = std::max(peak_, varnodes);
  if (limits_.max_varnodes != 0 && varnodes > limits_.max_varnodes) stop(DecompileStop::too_large);
  if (deadline_ == Clock::time_point::max() && !limits_.cancelled) return;
  const Clock::time_point now = Clock::now();
  if (now >= deadline_) stop(DecompileStop::timeout);
  if (limits_.cancelled && now >= next_poll_) {
    next_poll_ = now + std::chrono::milliseconds(5);
    if (limits_.cancelled()) stop(DecompileStop::cancelled);
  }
}

void DecompileBudget::stop(DecompileStop why) {
  stopped_ = why;
  throw DecompileStopped(why, message());
}

std::string DecompileBudget::message() const {
  char buf[96];
  switch (stopped_) {
    case DecompileStop::timeout:
      std::snprintf(buf, sizeof buf, "decompilation timed out after %g s", limits_.timeout_seconds);
      return buf;
    case DecompileStop::too_large:
      std::snprintf(buf, sizeof buf, "decompilation too large: over %zu varnodes", limits_.max_varnodes);
      return buf;
    case DecompileStop::cancelled: return "decompilation cancelled";
    case DecompileStop::none: break;
  }
  return {};
}

std::string describe(DecompileStop why) {
  switch (why) {
    case DecompileStop::timeout: return "decompilation timed out";
    case DecompileStop::too_large: return "decompilation too large";
    case DecompileStop::cancelled: return "decompilation cancelled";
    case DecompileStop::none: break;
  }
  return {};
}

}  // namespace revkit::lift
