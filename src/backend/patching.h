// What PatchService (image_backend.cc) builds on (docs/patching.md):
// assemblers per language, the context an address decodes with, the
// program's live patches, and conversions between the API's export
// settings and revkit::patch.
#pragma once

#include "revkit/analysis/analysis.h"
#include "revkit/asm/assembler.hh"
#include "revkit/facts/fact_db.h"
#include "revkit/patch/checksum.h"
#include "revkit/patch/export.h"
#include "revkit/v1/patch.pb.h"

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// Assemblers by language, one per caller at a time (an Assembler isn't
// thread-safe; its grammar is shared). Building one costs a SLEIGH engine
// (tens of milliseconds); idle ones are kept.
class Assemblers {
 public:
  class Lease {
   public:
    Lease(Assemblers *owner, std::string language, std::unique_ptr<assembler::Assembler> a)
        : owner_(owner), language_(std::move(language)), a_(std::move(a)) {}
    Lease(Lease &&) = default;
    Lease &operator=(Lease &&) = default;
    ~Lease();
    assembler::Assembler &operator*() const { return *a_; }
    assembler::Assembler *operator->() const { return a_.get(); }

   private:
    Assemblers *owner_;
    std::string language_;
    std::unique_ptr<assembler::Assembler> a_;
  };
  // Throws std::runtime_error (lift::LiftError) for a language without a spec.
  Lease Take(const std::string &language);

 private:
  std::mutex mu_;
  std::map<std::string, std::vector<std::unique_ptr<assembler::Assembler>>> idle_;
};

// The context words at `address`: the language's defaults, discovery's
// context settings (ProgramInfo::context, e.g. a Cortex-M's TMode), Thumb
// where the listing decodes Thumb, then the caller's overrides by name.
// `described`: the context in words ("TMode=1"), the non-default variables.
std::vector<std::uint32_t> ContextAt(assembler::Assembler &as, const analysis::ProgramInfo &info,
                                     std::uint64_t address, bool thumb,
                                     const google::protobuf::Map<std::string, std::uint32_t> &overrides,
                                     std::string *described);

// One live patch key with its effective value, in address order.
struct LivePatch {
  facts::FactKey key;
  std::uint64_t address = 0;
  std::string bytes;
};
// Every live patch of a program's space overlapping [first, last].
std::vector<LivePatch> LivePatches(const facts::Snapshot &snap, facts::SpaceId space, std::uint64_t first = 0,
                                   std::uint64_t last = ~std::uint64_t{0});
// The same, in the order they compose (lower precedence first), as
// patch::Patch for export.
std::vector<patch::Patch> PatchesInOrder(const facts::Snapshot &snap, facts::SpaceId space);

// The export settings stored on a program: NOTE at the program's first
// address with this tag, the settings' JSON.
inline constexpr const char *kExportSettingsTag = "patch.export";
std::string EncodeSettings(const pb::ExportSettings &s);
bool DecodeSettings(const std::string &text, pb::ExportSettings &out);

patch::Spec SpecFromPb(const pb::ChecksumSpec &s);
pb::ChecksumSpec SpecToPb(const patch::Spec &s);

std::string HexBytes(std::string_view bytes);

}  // namespace revkit::backend
