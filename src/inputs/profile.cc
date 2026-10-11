#include "revkit/inputs/profile.h"

#include <algorithm>
#include <cstdio>

namespace revkit::inputs {

std::string SignatureProfile::id() const {
  return "signature/" + std::to_string(kVersion) + "/" + (import_prototypes ? "import-prototypes" : "-");
}

bool is_import(const lift::FunctionFacts &f) {
  // assemble.cc gives import stubs and EXTERNAL functions their import's
  // label ("<EXTERNAL>_name"), and a PE import's function has no entry.
  return f.entry == 0 || !f.label.empty();
}

lift::FunctionFacts strip_function(const lift::FunctionFacts &f, const SignatureProfile &profile,
                                   const std::vector<std::uint64_t> *no_return) {
  const bool import = is_import(f);
  if (import && profile.import_prototypes) {
    lift::FunctionFacts out = f;
    out.locals.clear();
    out.id = 0;
    out.ns.clear();
    out.source_type.clear();
    out.source_name.clear();
    return out;
  }
  // What assembly gives a function nothing names (assemble.cc's
  // default_function), with what the image and discovery decide kept.
  lift::FunctionFacts out;
  out.entry = f.entry;
  if (import) {
    out.name = f.name;
    out.label = f.label;
  } else {
    char buf[32];
    std::snprintf(buf, sizeof buf, "FUN_%llx", static_cast<unsigned long long>(f.entry));
    out.name = buf;
  }
  out.body = f.body;
  out.convention = f.convention == "processEntry" ? f.convention : std::optional<std::string>("unknown");
  out.ret.type = {"void", {}, {}};
  out.ret.storage = std::vector<lift::StorageVarnode>{};
  out.ret.void_storage = true;
  out.call_fixup = f.call_fixup;
  out.call_fixup_noreturn = f.call_fixup_noreturn;
  out.is_inline = f.is_inline;
  out.noreturn = !import && no_return != nullptr ? std::binary_search(no_return->begin(), no_return->end(), f.entry)
                                                : f.noreturn;
  out.context = f.context;
  out.context_reach = f.context_reach;
  return out;
}

const lift::FunctionFacts *SignatureLookup::strip(const lift::FunctionFacts *f) {
  if (f == nullptr) return nullptr;
  if (auto it = done_.find(f); it != done_.end()) return it->second;
  return done_[f] = &owned_.emplace_back(strip_function(*f, profile_, no_return_.get()));
}

const lift::FunctionFacts *SignatureLookup::function_at(std::uint64_t entry) {
  return strip(base_.function_at(entry));
}

std::optional<lift::FactLookup::Body> SignatureLookup::body_containing(std::uint64_t a) {
  std::optional<Body> b = base_.body_containing(a);
  if (b) b->function = strip(b->function);
  return b;
}

const lift::ExternalRefFacts *SignatureLookup::external_at(const std::string &space, std::uint64_t a) {
  const lift::ExternalRefFacts *x = base_.external_at(space, a);
  if (x == nullptr) return nullptr;
  if (auto it = done_refs_.find(x); it != done_refs_.end()) return it->second;
  lift::ExternalRefFacts &copy = owned_refs_.emplace_back(*x);
  if (copy.function) copy.function = strip_function(*copy.function, profile_);
  return done_refs_[x] = &copy;
}

void SignatureLookup::reset() {
  // Over a stable base, what was returned stays valid (callers may keep it).
  if (!base_.stable()) {
    done_.clear();
    owned_.clear();
    done_refs_.clear();
    owned_refs_.clear();
  }
  base_.reset();
}

}  // namespace revkit::inputs
