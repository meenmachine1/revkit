// The lift modes' worker side: a lift::FactLookup answering from a bundle,
// and a session decompiling with lift::InputDecompiler. Mode c_text prints
// C (rk-lift's output); the image backend derives its tokens session from
// LiftSession.
#pragma once

#include "revkit/decompd/runner.h"
#include "revkit/lift/decompile.hh"

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace ghidra {
class Architecture;
class PrintLanguage;
}  // namespace ghidra

namespace revkit::decompd {

// FactLookup over a bundle's LiftFacts. A query the bundle doesn't answer
// is recorded as a miss and answered as nothing.
class BundleLookup final : public lift::FactLookup {
 public:
  void set(const Bundle *b);
  std::vector<Miss> take_misses();
  std::vector<SpaceAddr> take_asked();

  const lift::FunctionFacts *function_at(std::uint64_t entry) override;
  std::optional<Body> body_containing(std::uint64_t a) override;
  const lift::DataFacts *data_containing(const std::string &space, std::uint64_t a) override;
  const lift::ExternalRefFacts *external_at(const std::string &space, std::uint64_t a) override;
  const lift::LabelFacts *label_at(const std::string &space, std::uint64_t a) override;
  std::optional<std::string> code_label_at(const std::string &space, std::uint64_t a) override;
  std::optional<lift::Mutability> block_at(const std::string &space, std::uint64_t a) override;
  const lift::DecompElement *type(std::uint64_t id) override;
  std::vector<const lift::CommentFacts *> comments(std::uint64_t entry) override;
  std::vector<std::pair<std::uint64_t, std::string>> flow_overrides(std::uint64_t entry) override;
  std::vector<lift::TrackedFacts> tracked(std::uint64_t entry) override;

 private:
  const AddressAnswer *address(const std::string &space, std::uint64_t a);
  bool own_entry(std::uint64_t entry);

  const Bundle *b_ = nullptr;
  std::set<Miss> misses_;
  std::set<SpaceAddr> asked_;
  AddressAnswer missing_;  // what an unanswered address reads as
  std::map<std::uint64_t, lift::DecompElement> decoded_;  // this run's types, decoded when asked
};

// The DecompileConfig a lift-mode session builds its decompiler with.
lift::DecompileConfig lift_config(const Bundle &b, std::shared_ptr<BundleLookup> lookup,
                                  std::shared_ptr<BundleMemory> memory);

// The RunHooks a bundle asks for (jump tables, flow overrides, comments).
void bundle_hooks(const Bundle &b, lift::RunHooks &hooks);

class LiftSession : public Session {
 public:
  using MakePrinter = std::function<ghidra::PrintLanguage *(ghidra::Architecture *)>;
  // With `make_printer`, the decompiler prints through it (see
  // lift::InputDecompiler); otherwise C, as rk-lift prints it.
  explicit LiftSession(const Bundle &b, MakePrinter make_printer = {});
  ~LiftSession() override;

  void run(const Bundle &b, const Limits &limits, RunResult &out) override;
  bool spoiled() const override { return decompiler_->spoiled(); }
  lift::ImageArchitecture &architecture() override { return decompiler_->architecture(); }

 protected:
  // Before the run: what the session adds to the hooks (a printer of its own).
  virtual void prepare(const Bundle &, lift::RunHooks &) {}
  // After it: the payload. By default the encoded DecompileResult.
  virtual std::string payload(const Bundle &b, lift::DecompileResult &r);
  lift::InputDecompiler &decompiler() { return *decompiler_; }
  BundleLookup &lookup() { return *lookup_; }

 private:
  std::shared_ptr<BundleLookup> lookup_;
  std::shared_ptr<BundleMemory> memory_;
  std::unique_ptr<lift::InputDecompiler> decompiler_;
};

std::unique_ptr<Session> make_lift_session(const Bundle &b);

// Mode c_text's payload.
std::string encode_result(const lift::DecompileResult &r);
lift::DecompileResult decode_result(std::string_view bytes);

}  // namespace revkit::decompd
