#include "revkit/decompd/lift_mode.h"

#include "revkit/inputs/codec.h"

#include <algorithm>
#include <bit>

namespace revkit::decompd {

// ---- BundleLookup -------------------------------------------------------------

void BundleLookup::set(const Bundle *b) {
  b_ = b;
  misses_.clear();
  asked_.clear();
  decoded_.clear();
}

std::vector<Miss> BundleLookup::take_misses() {
  std::vector<Miss> out(misses_.begin(), misses_.end());
  misses_.clear();
  return out;
}

std::vector<SpaceAddr> BundleLookup::take_asked() {
  std::vector<SpaceAddr> out(asked_.begin(), asked_.end());
  asked_.clear();
  return out;
}

const AddressAnswer *BundleLookup::address(const std::string &space, std::uint64_t a) {
  asked_.insert({space, a});
  auto it = b_->lift.addresses.find({space, a});
  if (it != b_->lift.addresses.end()) return &it->second;
  if (std::find(b_->lift.spaces.begin(), b_->lift.spaces.end(), space) != b_->lift.spaces.end())
    misses_.insert({Miss::address, space, a});
  missing_ = AddressAnswer{};
  missing_.block = b_->lift.default_block(space, a);
  return &missing_;
}

bool BundleLookup::own_entry(std::uint64_t entry) {
  if (entry == b_->entry) return true;
  misses_.insert({Miss::entry, {}, entry});
  return false;
}

const lift::FunctionFacts *BundleLookup::function_at(std::uint64_t entry) {
  const AddressAnswer *r = address({}, entry);
  return r->starts >= 0 ? &b_->lift.functions[static_cast<std::size_t>(r->starts)] : nullptr;
}

std::optional<lift::FactLookup::Body> BundleLookup::body_containing(std::uint64_t a) {
  const AddressAnswer *r = address({}, a);
  if (r->contains < 0) return std::nullopt;
  return Body{r->body_first, r->body_last, &b_->lift.functions[static_cast<std::size_t>(r->contains)]};
}

const lift::DataFacts *BundleLookup::data_containing(const std::string &space, std::uint64_t a) {
  const AddressAnswer *r = address(space, a);
  return r->data >= 0 ? &b_->lift.data[static_cast<std::size_t>(r->data)] : nullptr;
}

const lift::ExternalRefFacts *BundleLookup::external_at(const std::string &space, std::uint64_t a) {
  const AddressAnswer *r = address(space, a);
  return r->external >= 0 ? &b_->lift.externals[static_cast<std::size_t>(r->external)] : nullptr;
}

const lift::LabelFacts *BundleLookup::label_at(const std::string &space, std::uint64_t a) {
  const AddressAnswer *r = address(space, a);
  return r->label >= 0 ? &b_->lift.labels[static_cast<std::size_t>(r->label)] : nullptr;
}

std::optional<std::string> BundleLookup::code_label_at(const std::string &space, std::uint64_t a) {
  asked_.insert({space, a});
  auto it = b_->lift.code_labels.find({space, a});
  if (it != b_->lift.code_labels.end()) return it->second;
  if (std::find(b_->lift.spaces.begin(), b_->lift.spaces.end(), space) != b_->lift.spaces.end())
    misses_.insert({Miss::code_label, space, a});
  return std::nullopt;
}

std::optional<lift::Mutability> BundleLookup::block_at(const std::string &space, std::uint64_t a) {
  // The block map answers every address; a record of its own wins.
  auto it = b_->lift.addresses.find({space, a});
  if (it != b_->lift.addresses.end()) return it->second.block;
  return b_->lift.default_block(space, a);
}

const lift::DecompElement *BundleLookup::type(std::uint64_t id) {
  if (auto done = decoded_.find(id); done != decoded_.end()) return &done->second;
  auto it = b_->lift.types.find(id);
  if (it == b_->lift.types.end()) {
    misses_.insert({Miss::type, {}, id});
    return nullptr;
  }
  if (it->second.empty()) return nullptr;
  return &decoded_.emplace(id, facts::decode_from_string<lift::DecompElement>(it->second)).first->second;
}

std::vector<const lift::CommentFacts *> BundleLookup::comments(std::uint64_t entry) {
  std::vector<const lift::CommentFacts *> out;
  if (!own_entry(entry)) return out;
  for (const lift::CommentFacts &c : b_->lift.comments) out.push_back(&c);
  return out;
}

std::vector<std::pair<std::uint64_t, std::string>> BundleLookup::flow_overrides(std::uint64_t entry) {
  if (!own_entry(entry)) return {};
  return b_->lift.flow_overrides;
}

std::vector<lift::TrackedFacts> BundleLookup::tracked(std::uint64_t entry) {
  if (!own_entry(entry)) return {};
  return b_->lift.tracked;
}

// ---- the session ----------------------------------------------------------------

lift::DecompileConfig lift_config(const Bundle &b, std::shared_ptr<BundleLookup> lookup,
                                  std::shared_ptr<BundleMemory> memory) {
  lift::DecompileConfig c;
  c.image = bundle_image(b);
  c.language_id = b.language_id;
  auto inputs = std::make_shared<lift::DecompilerInputs>();
  inputs->address_prefix = b.lift.address_prefix;
  c.inputs = std::move(inputs);
  c.lookup = std::move(lookup);
  c.memory = std::move(memory);
  c.context = b.context;
  c.default_names = b.lift.default_names;
  c.default_labels = b.lift.default_labels;
  c.default_extrapop = b.lift.default_extrapop;
  c.format_strings = b.lift.format_strings;
  c.eliminate_unreachable = b.mode != Mode::param_id;
  if (b.mode == Mode::signature) c.action = "normalize";
  return c;
}

void bundle_hooks(const Bundle &b, lift::RunHooks &hooks) {
  hooks.jump_tables = b.lift.jump_tables;
  hooks.flow_overrides = b.lift.hook_flow_overrides;
  hooks.comments = b.lift.hook_comments;
  hooks.equates = b.lift.hook_equates;
  hooks.call_targets = b.lift.hook_call_targets;
  hooks.forced_tables.insert(b.lift.hook_forced_tables.begin(), b.lift.hook_forced_tables.end());
  hooks.call_protos = b.lift.hook_call_protos;
}

LiftSession::LiftSession(const Bundle &b, MakePrinter make_printer)
    : lookup_(std::make_shared<BundleLookup>()), memory_(std::make_shared<BundleMemory>()) {
  const lift::DecompileConfig config = lift_config(b, lookup_, memory_);
  decompiler_ = make_printer ? std::make_unique<lift::InputDecompiler>(config, make_printer)
                             : std::make_unique<lift::InputDecompiler>(config);
}

LiftSession::~LiftSession() = default;

void LiftSession::run(const Bundle &b, const Limits &limits, RunResult &out) {
  lookup_->set(&b);
  memory_->set(&b);
  lift::DecompileLimits dl;
  dl.timeout_seconds = limits.timeout_seconds;
  dl.max_varnodes = limits.max_varnodes;
  lift::RunHooks hooks;
  bundle_hooks(b, hooks);
  hooks.limits = &dl;
  prepare(b, hooks);
  lift::DecompileResult r = decompiler_->decompile(b.entry, &hooks);
  out.stopped = r.stopped;
  out.varnodes = r.varnodes;
  out.payload = payload(b, r);
  out.misses = lookup_->take_misses();
  for (std::uint64_t chunk : memory_->missed()) out.misses.push_back({Miss::chunk, {}, chunk});
  out.asked = lookup_->take_asked();
  lookup_->set(nullptr);
  memory_->set(nullptr);
}

std::string LiftSession::payload(const Bundle &, lift::DecompileResult &r) { return encode_result(r); }

std::unique_ptr<Session> make_lift_session(const Bundle &b) { return std::make_unique<LiftSession>(b); }

// ---- c_text payload -------------------------------------------------------------

std::string encode_result(const lift::DecompileResult &r) {
  facts::Encoder e;
  e.varint(r.entry);
  facts::encode(e, r.ok);
  e.bytes(r.c);
  e.bytes(r.error);
  facts::encode(e, r.input_errors);
  e.u64be(std::bit_cast<std::uint64_t>(r.milliseconds));
  e.u8(static_cast<std::uint8_t>(r.stopped));
  e.varint(r.varnodes);
  return std::move(e).str();
}

lift::DecompileResult decode_result(std::string_view bytes) {
  facts::Decoder d(bytes);
  lift::DecompileResult r;
  r.entry = d.varint();
  r.ok = facts::decode<bool>(d);
  r.c = std::string(d.bytes());
  r.error = std::string(d.bytes());
  r.input_errors = facts::decode<std::vector<std::string>>(d);
  r.milliseconds = std::bit_cast<double>(d.u64be());
  const std::uint8_t s = d.u8();
  if (s > static_cast<std::uint8_t>(lift::DecompileStop::cancelled)) throw facts::DecodeError("bad stop reason");
  r.stopped = static_cast<lift::DecompileStop>(s);
  r.varnodes = d.varint();
  d.expect_done();
  return r;
}

}  // namespace revkit::decompd
