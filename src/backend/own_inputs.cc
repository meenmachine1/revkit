#include "own_inputs.h"

#include "revkit/inputs/demangled.h"

#include "define_type.h"
#include "nds_import.h"
#include "project_archive.h"
#include "param_id.h"

#include "program.h"
#include "queries.h"
#include "type_record.h"

#include "revkit/infer/infer.h"
#include "revkit/infer/types_bridge.h"
#include "revkit/inputs/codec.h"
#include "revkit/analysis/register_values.h"
#include "revkit/inputs/ghidra_types.h"
#include "revkit/lift/abi.hh"

#include "error.hh"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <set>
#include <stdexcept>

namespace revkit::backend {

namespace an = analysis;
using facts::QueryContext;

// ---- values ------------------------------------------------------------------

void ProgramInputs::encode(facts::Encoder &e) const {
  facts::encode(e, *inputs);
  facts::encode(e, slots != nullptr);
  if (!slots) return;
  std::vector<std::pair<std::uint64_t, std::string>> names(slots->names.begin(), slots->names.end());
  std::sort(names.begin(), names.end());
  facts::encode(e, names);
  facts::encode(e, slots->bodies);
  e.bytes(slots->prefix);
  e.varint(slots->word);
  facts::encode(e, slots->pointers);
}

ProgramInputs ProgramInputs::decode(facts::Decoder &d) {
  ProgramInputs v;
  auto in = std::make_shared<lift::DecompilerInputs>(facts::decode<lift::DecompilerInputs>(d));
  v.index = std::shared_ptr<lift::FactLookup>(lift::lookup_inputs(in));
  v.inputs = std::move(in);
  if (facts::decode<bool>(d)) {
    auto slots = std::make_shared<inputs::SlotNames>();
    for (auto &[a, name] : facts::decode<std::vector<std::pair<std::uint64_t, std::string>>>(d))
      slots->names.emplace(a, std::move(name));
    slots->bodies = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
    slots->prefix = std::string(d.bytes());
    slots->word = static_cast<unsigned>(d.varint());
    slots->pointers = facts::decode<std::vector<std::pair<std::uint64_t, std::uint64_t>>>(d);
    v.slots = std::move(slots);
  }
  return v;
}

void ImageInputs::encode(facts::Encoder &e) const {
  e.bytes(address_prefix);
  facts::encode(e, patches);
  facts::encode(e, synthesized_memory);
  facts::encode(e, memory);
}

ImageInputs ImageInputs::decode(facts::Decoder &d) {
  ImageInputs v;
  v.address_prefix = std::string(d.bytes());
  v.patches = facts::decode<std::vector<inputs::Patch>>(d);
  v.synthesized_memory = facts::decode<std::vector<inputs::Patch>>(d);
  v.memory = facts::decode<std::vector<lift::BlockFacts>>(d);
  return v;
}

bool AddressFacts::empty() const {
  return !starts && !contains && !data && !external && !label &&
         (!block || *block == lift::Mutability::normal);
}

void AddressFacts::encode(facts::Encoder &e) const {
  facts::encode(e, starts);
  facts::encode(e, contains);
  e.varint(body_first);
  e.varint(body_last);
  facts::encode(e, data);
  facts::encode(e, external);
  facts::encode(e, label);
  facts::encode(e, block);
  facts::encode(e, tracked);
  facts::encode(e, comments);
}

AddressFacts AddressFacts::decode(facts::Decoder &d) {
  AddressFacts v;
  v.starts = facts::decode<std::optional<lift::FunctionFacts>>(d);
  v.contains = facts::decode<std::optional<lift::FunctionFacts>>(d);
  v.body_first = d.varint();
  v.body_last = d.varint();
  v.data = facts::decode<std::optional<lift::DataFacts>>(d);
  v.external = facts::decode<std::optional<lift::ExternalRefFacts>>(d);
  v.label = facts::decode<std::optional<lift::LabelFacts>>(d);
  v.block = facts::decode<std::optional<lift::Mutability>>(d);
  v.tracked = facts::decode<std::vector<lift::TrackedFacts>>(d);
  v.comments = facts::decode<std::vector<lift::CommentFacts>>(d);
  return v;
}

// ---- queries -------------------------------------------------------------------

namespace {

// The program with the memory map at the query's revision.
const Program &Loaded(QueryContext &ctx, const std::string &program, std::shared_ptr<const Program> &keep) {
  keep = EffectiveProgram(ctx, program);
  return *keep;
}

// As Loaded, for a query that reads its debug info: the separate debug
// file read at load is an input of it.
const Program &LoadedWithDebug(QueryContext &ctx, const std::string &program, std::shared_ptr<const Program> &keep) {
  (void)ctx.get<q::DebugFile>(program);
  return Loaded(ctx, program, keep);
}

// Discovery's results through the query context, for revkit::inputs.
class ContextAnalysis final : public inputs::Analysis {
 public:
  ContextAnalysis(QueryContext &ctx, const std::string &program) : ctx_(ctx), key_{program} {}
  const an::ProgramInfo &info() override {
    if (!info_) info_ = ctx_.get<an::Program>(key_);
    return **info_;
  }
  const an::FunctionList &functions() override {
    if (!functions_) functions_ = ctx_.get<an::Functions>(key_);
    return **functions_;
  }
  const an::FlowGraph &flow(std::uint64_t entry) override {
    auto it = flows_.find(entry);
    if (it == flows_.end()) it = flows_.emplace(entry, ctx_.get<an::Flow>(an::Location{key_, entry})).first;
    return *it->second;
  }
  const an::DataList *data() override {
    if (!data_) data_ = ctx_.get<an::Data>(key_);
    return data_->get();
  }
  const std::vector<std::uint64_t> *no_return_evidence() override {
    if (!evidence_) evidence_ = ctx_.get<an::NoReturnEvidence>(key_);
    return evidence_->get();
  }

 private:
  QueryContext &ctx_;
  an::ProgramKey key_;
  std::optional<facts::Ref<an::ProgramInfo>> info_;
  std::optional<facts::Ref<an::FunctionList>> functions_;
  std::optional<facts::Ref<an::DataList>> data_;
  std::optional<facts::Ref<std::vector<std::uint64_t>>> evidence_;
  std::map<std::uint64_t, facts::Ref<an::FlowGraph>> flows_;
};

}  // namespace

namespace q {

namespace {

// With REVKIT_TIMING set, how long the program-wide inputs take (stderr).
struct InputsTimer {
  const char *what;
  std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  ~InputsTimer() {
    static const bool on = std::getenv("REVKIT_TIMING") != nullptr;
    if (on)
      std::fprintf(stderr, "revkit: %s %.1f ms\n", what,
                   std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
  }
};

}  // namespace

InputsStatic::Value InputsStatic::compute(QueryContext &ctx, const Key &program) {
  std::shared_ptr<const Program> keep;
  const Program &p = LoadedWithDebug(ctx, program, keep);
  ContextAnalysis analysis(ctx, program);  // reads analysis.program, never the functions
  inputs::Program ip{p.image_ptr(), p.language().id(), &analysis, p.debug()};
  InputsTimer timer{"inputs.static"};
  return inputs::assemble_static(ip);
}

std::size_t InputsStatic::weight(const Value &v) {
  return sizeof(Value) + v.patches.size() * 48 + v.slots.size() * sizeof(inputs::StaticInputs::Slot) +
         v.symbols.size() * 64 + v.external.functions.size() * 512 + v.imports.external_refs.size() * 512 +
         (v.external.data.size() + v.imports.data.size() + v.thread.data.size()) * 192;
}

InputsProgram::Value InputsProgram::compute(QueryContext &ctx, const Key &program) {
  std::shared_ptr<const Program> keep;
  const Program &p = LoadedWithDebug(ctx, program, keep);
  auto st = ctx.get<InputsStatic>(program);
  ContextAnalysis analysis(ctx, program);
  analysis.functions();
  InputsTimer timer{"inputs.program"};
  inputs::Program ip{p.image_ptr(), p.language().id(), &analysis, p.debug(), {}};
  // A raw image's strings are read from its bytes: as patched
  // (docs/patching.md). Other formats read none.
  if (p.image().format == loader::Format::raw) {
    const facts::SpaceId space = ctx.get<q::Source>(program)->ram_space;
    ip.read = [&ctx, &p, space](std::uint64_t addr, std::span<std::byte> out) {
      p.image().memory.read(addr, out);
      if (out.empty()) return;
      std::string s(reinterpret_cast<const char *>(out.data()), out.size());
      facts::apply_patches(facts::patches_overlapping(ctx, space, addr, addr + (out.size() - 1)), addr, s);
      std::memcpy(out.data(), s.data(), s.size());
    };
  }
  auto slots = std::make_shared<inputs::SlotNames>();
  // The PDB's own parameter names, which users want to see (Ghidra drops them).
  inputs::Options options;
  options.pdb_signatures = inputs::Options::PdbSignatures::full;
  // The library archives the project applies (library.prototypes): none
  // read from disk here, so every program of a target shares one parse.
  auto library = ctx.get<LibraryPrototypes>(program);
  options.library = library->lib;
  options.ghidra_library = library->ghidra;
  auto in = std::make_shared<lift::DecompilerInputs>(inputs::assemble_program(ip, options, &*st, slots.get()));
  ProgramInputs v;
  v.index = std::shared_ptr<lift::FactLookup>(lift::lookup_inputs(in));
  v.inputs = std::move(in);
  v.slots = std::move(slots);
  return v;
}

std::size_t InputsProgram::weight(const Value &v) {
  // A rough size: what dominates is functions, data and types.
  const lift::DecompilerInputs &in = *v.inputs;
  return sizeof(Value) + in.functions.size() * 512 + in.data.size() * 192 + in.types.size() * 256 +
         in.labels.size() * 64 + in.external_refs.size() * 512;
}

InputsImage::Value InputsImage::compute(QueryContext &ctx, const Key &program) {
  // As assemble_program lays them out, from the static part alone: the
  // decompiler's instances outlive changes to the function list.
  auto st = ctx.get<InputsStatic>(program);
  auto info = ctx.get<an::Program>(an::ProgramKey{program});
  const std::string prefix = info->qualify_names ? info->code_space + "_" : std::string();
  return ImageInputs{prefix, st->patches, st->thread.synthesized_memory, st->memory};
}

InputsSets::Value InputsSets::compute(QueryContext &ctx, const Key &program) {
  return inputs::function_sets(*ctx.get<an::Functions>(an::ProgramKey{program}),
                               &*ctx.get<an::NoReturnEvidence>(an::ProgramKey{program}));
}

InputsFunction::Value InputsFunction::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, entry] = key;
  const an::Location at{an::ProgramKey{program}, entry};
  auto f = ctx.get<an::Function>(at);
  if (f->name.empty()) return {};
  auto flow = ctx.get<an::Flow>(an::Location{at.program, f->flow_key()});
  auto sets = ctx.get<InputsSets>(program);
  auto facts = ctx.get<InputsAddress>(key);
  std::shared_ptr<const Program> keep;
  const Program &p = LoadedWithDebug(ctx, program, keep);
  ContextAnalysis analysis(ctx, program);
  inputs::Program ip{p.image_ptr(), p.language().id(), &analysis, p.debug()};
  static const std::vector<lift::LocalFacts> kNone;
  auto lifter = p.walk_lifter();
  return inputs::assemble_function(ip, {}, *sets, *f, *flow, facts->starts ? facts->starts->locals : kNone, *lifter);
}

InputsAddress::Value InputsAddress::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, a] = key;
  auto pin = ctx.get<InputsProgram>(program);
  lift::FactLookup &ix = *pin->index;
  AddressFacts out;
  // Bodies are how the index finds a containing function; the decompiler
  // doesn't read them, and leaving them out keeps a caller's lookup of a
  // callee from depending on the callee's extent. Except a function with a
  // decoding context (Thumb): the decompiler paints that context over its
  // body, so without the body it decodes the function in the default mode.
  if (const lift::FunctionFacts *f = ix.function_at(a)) {
    out.starts = *f;
    if (out.starts->context.empty()) out.starts->body.clear();
    out.tracked = ix.tracked(a);
    for (const lift::CommentFacts *c : ix.comments(a)) out.comments.push_back(*c);
  }
  if (std::optional<lift::FactLookup::Body> b = ix.body_containing(a)) {
    out.contains = *b->function;
    out.contains->body.clear();
    out.body_first = b->first;
    out.body_last = b->last;
    // Near the entry the decompiler is given the function's symbol, not a
    // hole the size of the range, so the extent doesn't matter there.
    if (a >= b->function->entry && a - b->function->entry < 8) out.body_first = out.body_last = a;
  }
  // Data containing `a`: what the program's inputs lay out, or the
  // relocated pointer slot holding `a` when it starts closer (as when
  // assemble_program lays out every slot; data starting at a slot's
  // address is laid out instead of it).
  const lift::DataFacts *d = ix.data_containing({}, a);
  if (pin->slots) {
    auto st = ctx.get<InputsStatic>(program);
    auto it = std::upper_bound(st->slots.begin(), st->slots.end(), a,
                               [](std::uint64_t x, const inputs::StaticInputs::Slot &s) { return x < s.address; });
    if (it != st->slots.begin()) {
      const inputs::StaticInputs::Slot &slot = *std::prev(it);
      const bool holds = a - slot.address < pin->slots->word;
      const lift::DataFacts *at_slot = holds ? ix.data_containing({}, slot.address) : nullptr;
      const bool laid_out = at_slot != nullptr && at_slot->addr == slot.address;
      // (Nor inside a debug-info variable: inputs::drop_overlapped.)
      const bool in_variable = d != nullptr && !d->source_name.empty() && d->addr < slot.address &&
                               slot.address <= d->addr + (d->length - 1);
      if (holds && !laid_out && !in_variable && (d == nullptr || d->addr < slot.address))
        out.data = inputs::pointer_slot(slot, *pin->slots);
    }
  }
  if (d != nullptr && !out.data) out.data = *d;
  if (const lift::ExternalRefFacts *x = ix.external_at({}, a)) out.external = *x;
  if (const lift::LabelFacts *l = ix.label_at({}, a)) out.label = *l;
  out.block = ix.block_at({}, a);
  // Constant, volatile or writable by the listing's edits, over the block's
  // say and data analysis's (docs/listing-edit.md).
  if (auto m = ctx.get<MutabilityAt>(key); *m) out.block = **m;
  if (out.data && out.data->space.empty()) {
    auto m = out.data->addr == a ? ctx.get<MutabilityAt>(key) : ctx.get<MutabilityAt>({program, out.data->addr});
    if (*m) out.data->mutability = **m;
  }
  return out;
}

MutabilityAt::Value MutabilityAt::compute(QueryContext &ctx, const Key &key) {
  auto map = ctx.get<an::MutabilityMap>(an::ProgramKey{key.first});
  const an::MutabilityPiece *p = an::mutability_at(*map, key.second);
  if (p == nullptr) return std::nullopt;
  switch (p->kind) {
    case an::MutabilityKind::constant: return lift::Mutability::constant;
    case an::MutabilityKind::is_volatile: return lift::Mutability::is_volatile;
    case an::MutabilityKind::normal: return lift::Mutability::normal;
    case an::MutabilityKind::as_map: break;
  }
  return std::nullopt;
}

InputsType::Value InputsType::compute(QueryContext &ctx, const Key &key) {
  auto pin = ctx.get<InputsProgram>(key.first);
  const lift::DecompElement *t = pin->index->type(key.second);
  if (t == nullptr) return std::nullopt;
  return *t;
}

}  // namespace q

void RegisterInputQueries(facts::Engine &engine) {
  engine.add_query<q::InputsStatic>();
  engine.add_query<q::InputsProgram>();
  engine.add_query<q::InputsImage>();
  engine.add_query<q::InputsSets>();
  engine.add_query<q::InputsFunction>();
  engine.add_query<q::InputsAddress>();
  engine.add_query<q::InputsType>();
  engine.add_query<q::MutabilityAt>();
}

// ---- the decompiler's lookups --------------------------------------------------

namespace {

const AddressFacts kNothing;
const inputs::FunctionInputs kNoFunction;

}  // namespace

template <class F>
auto QueryLookup::query(F &&get) -> decltype(get()) {
  if (failure) throw ghidra::LowlevelError("lookup failed");
  try {
    return get();
  } catch (...) {
    // Not a decompiler failure: stop the run and hand it back.
    failure = std::current_exception();
    throw ghidra::LowlevelError("lookup failed");
  }
}

bool QueryLookup::blocked(std::uint64_t a) {
  if (!frozen_ || eager_.contains(a)) return false;
  late_.push_back(a);
  return true;
}

const AddressFacts *QueryLookup::address(std::uint64_t a) {
  if (auto it = addresses_.find(a); it != addresses_.end()) return &*it->second;
  if (blocked(a)) return &kNothing;
  touched_.insert(a);
  auto ref = query([&] { return ctx_->get<q::InputsAddress>({program_, a}); });
  return &*addresses_.emplace(a, std::move(ref)).first->second;
}

const inputs::FunctionInputs *QueryLookup::function_slice(std::uint64_t entry) {
  if (auto it = functions_.find(entry); it != functions_.end()) return &*it->second;
  if (blocked(entry)) return &kNoFunction;
  auto ref = query([&] { return ctx_->get<q::InputsFunction>({program_, entry}); });
  return &*functions_.emplace(entry, std::move(ref)).first->second;
}

const SymbolInfo *QueryLookup::symbol(std::uint64_t a) {
  if (auto it = symbols_.find(a); it != symbols_.end()) return &*it->second;
  if (blocked(a)) return nullptr;
  touched_.insert(a);
  auto ref = query([&] { return ctx_->get<q::Symbol>({program_, a}); });
  return &*symbols_.emplace(a, std::move(ref)).first->second;
}

std::string QueryLookup::chunk(std::uint64_t index, std::string bytes) {
  // The program's patches over this chunk only: the run depends on the
  // patch spans of the chunks it read.
  const facts::SpaceId space = ctx_->get<q::Source>(program_)->ram_space;
  const std::uint64_t first = index * decompd::kChunk;
  facts::apply_patches(facts::patches_overlapping(*ctx_, space, first, first + (decompd::kChunk - 1)), first, bytes);
  return bytes;
}

bool QueryLookup::says_anything(std::uint64_t a) {
  const bool was = frozen_;
  frozen_ = false;
  const SymbolInfo *s = symbol(a);
  const bool any = !address(a)->empty() || (s != nullptr && s->asserted);
  frozen_ = was;
  return any;
}

std::unique_ptr<QueryLookup::Asserted> QueryLookup::asserted_type(const std::string &hash) {
  auto closure = query([&] { return ctx_->get<q::ResolvedTypes>({program_, hash}); });
  if (closure->empty()) return nullptr;
  std::map<std::string, std::string> records(closure->begin(), closure->end());
  auto out = std::make_unique<Asserted>();
  std::map<std::string, types::TypeId> ids = InternRecords(records, out->store);
  auto it = ids.find(hash);
  if (it == ids.end()) return nullptr;
  out->id = it->second;
  return out;
}

bool QueryLookup::rebound(const std::string &hash) {
  auto raw = query([&] { return ctx_->get<q::Types>({program_, hash}); });
  auto resolved = query([&] { return ctx_->get<q::ResolvedTypes>({program_, hash}); });
  return *raw != *resolved;
}

QueryLookup::QueryLookup(facts::QueryContext &ctx, std::string program, std::uint64_t entry,
                         const std::vector<std::uint64_t> *param_id_deps)
    : ctx_(&ctx), program_(std::move(program)), entry_(entry), param_id_deps_(param_id_deps) {
  static const std::set<std::string> kNone;
  models_ = &kNone;
  auto src = ctx.get<q::Source>(program_);
  if (src->program) models_ = &lift::prototype_models(src->program->language().language, src->program->language().compiler);
}

namespace {

// The compiler spec's prototype model for a function type's calling
// convention: Ghidra's names (CompilerSpec.CALLING_CONVENTION_*, the
// spellings DefineType takes), with MSABI for ms_abi on a SysV target as
// x86-64-gcc.cspec names it. Empty for the default convention.
std::vector<std::string> ConventionModels(types::CallConv cc) {
  if (cc == types::CallConv::Default) return {};
  std::vector<std::string> out{CallingConventionName(cc)};
  if (cc == types::CallConv::Ms64) out.emplace_back("MSABI");
  return out;
}

}  // namespace

// What the background inference published (never infer.prototype itself:
// a decompilation would wait for the whole program's fixpoint).
std::optional<infer::Prototype> QueryLookup::inferred(std::uint64_t entry) {
  return *query([&] { return ctx_->get<q::InferPublished>({program_, entry}); });
}

// The inferred structures an inferred prototype points to (astruct_<n>:
// program types since inference published them, ImageBackend's
// StageInferredStructures), in `store`: each name's binding, resolved as any
// program type is (types.resolved: with the user's edits of it). A name
// the program no longer binds (the user retracted it) stays an incomplete
// struct of that name.
infer::StructureIds QueryLookup::inferred_structures(const infer::Prototype &p, types::TypeStore &store) {
  std::set<std::string> names;
  std::function<void(const infer::VType &)> walk = [&](const infer::VType &t) {
    if (t.meta == infer::Meta::struct_ && t.name.starts_with("astruct_")) names.insert(t.name);
    for (const infer::VType &x : t.pointee) walk(x);
  };
  walk(p.ret);
  for (const infer::VType &t : p.params) walk(t);
  infer::StructureIds out;
  if (names.empty()) return out;
  auto named = query([&] { return ctx_->get<q::TypeNames>(program_); });
  for (const std::string &n : names) {
    const std::string *hash = named->bound("struct " + n);
    if (hash == nullptr) continue;
    auto closure = query([&] { return ctx_->get<q::ResolvedTypes>({program_, *hash}); });
    if (closure->empty()) continue;
    const std::map<std::string, std::string> records(closure->begin(), closure->end());
    const std::map<std::string, types::TypeId> ids = InternRecords(records, store);
    if (auto it = ids.find(*hash); it != ids.end()) out.emplace(n, it->second);
  }
  return out;
}

std::optional<lift::CommittedSignature> QueryLookup::param_id(std::uint64_t entry) {
  if (!param_id_deps_) return *query([&] { return ctx_->get<q::ParamIdPublished>({program_, entry}); });
  // A thunk shows what it thunks; a function sees only its dependencies
  // committed (they were decompiled before it).
  std::optional<std::uint64_t> target = query([&] { return ThunkedFunction(*ctx_, program_, entry); });
  if (!target || *target == entry_ || !std::binary_search(param_id_deps_->begin(), param_id_deps_->end(), *target))
    return std::nullopt;
  return *query([&] { return ctx_->get<q::ParamId>({program_, *target}); });
}

infer::DataOrg QueryLookup::InferOrg() {
  auto src = query([&] { return ctx_->get<q::Source>(program_); });
  return infer::data_org(src->program->image());
}

const inputs::DataOrg &QueryLookup::data_org() {
  if (!org_) {
    auto src = query([&] { return ctx_->get<q::Source>(program_); });
    const Program &p = *src->program;
    org_ = inputs::data_org(p.image(), p.language().id());
  }
  return *org_;
}

// A function type as the decompiler's prototype: `out`'s convention,
// return, parameters and varargs (dynamic storage), its types' definitions
// joining the run's overlay types. `warn`: a calling convention the compiler
// spec lacks goes into the run's warnings. False if `t` isn't a function.
bool QueryLookup::prototype_from(const Asserted &t, lift::FunctionFacts &out, bool warn) {
  const auto *fn = t.store.get(t.id).as<types::FunctionType>();
  if (fn == nullptr) return false;
  inputs::GhidraTypes enc(t.store, data_org(), nullptr);
  // The prototype's calling convention, where the compiler spec has a
  // model for it (__stdcall, __fastcall, __thiscall on 32-bit Windows):
  // its storage and stack cleanup, model-locked as Ghidra's Java side
  // commits a function's calling convention. One the spec doesn't know
  // is the default, with a warning on the function's own output.
  out.convention = "default";
  if (fn->cc != types::CallConv::Default) {
    const std::vector<std::string> names = ConventionModels(fn->cc);
    auto known = std::find_if(names.begin(), names.end(), [&](const std::string &n) { return models_->contains(n); });
    if (known != names.end()) {
      out.convention = *known;
    } else if (warn) {
      const std::string spelled = CallingConventionName(fn->cc);
      warnings_.insert("the compiler spec has no " + (spelled.empty() || spelled == "other" ? std::string("such") : spelled) +
                       " calling convention: the prototype uses the default one");
    }
  }
  out.dynamic_storage = true;
  out.ret.type = enc.ref(fn->ret);
  // A return of Ghidra's DEFAULT type ("undefined", which C reads as the
  // 1-byte undefined type) leaves it to the decompiler, unlocked, as
  // Ghidra's Edit Function does; any other return is locked.
  const auto *undef = t.store.get(fn->ret).as<types::UndefinedType>();
  out.ret.is_default = undef != nullptr && undef->size == 1;
  out.varargs = fn->varargs;
  out.params.clear();
  for (std::size_t i = 0; i < fn->params.size(); ++i) {
    lift::ParamFacts param;
    param.name = fn->params[i].name.empty() ? "param_" + std::to_string(i + 1) : fn->params[i].name;
    param.type = enc.ref(fn->params[i].type);
    out.params.push_back(std::move(param));
  }
  for (lift::DecompElement &d : enc.take_definitions())
    if (const auto *id = d.attr("id"))
      if (const auto *u = std::get_if<std::uint64_t>(id)) overlay_types_.emplace(*u, std::move(d));
  return true;
}

// A call's signature override (docs/api.md, "Call-site signature
// overrides"): the function type as a prototype for that call.
std::optional<lift::FunctionFacts> QueryLookup::call_prototype(const std::string &hash) {
  std::unique_ptr<Asserted> t = asserted_type(hash);
  if (!t) return std::nullopt;
  lift::FunctionFacts out;
  out.name = "call_override";
  if (!prototype_from(*t, out, true)) return std::nullopt;
  out.signature_source = lift::SignatureSource::user_defined;
  return out;
}

// The program's facts for a function, with this function's stack variables
// and what the project asserts about it (a rename; a prototype other than
// the debug info's).
const lift::FunctionFacts *QueryLookup::with_overlay(const lift::FunctionFacts &f) {
  if (auto it = overlaid_.find(&f); it != overlaid_.end()) return it->second;
  lift::FunctionFacts &out = owned_functions_.emplace_back(f);
  // Stack variables of the function being decompiled only: the decompiler
  // doesn't use a callee's, and they would make callers depend on its flow.
  if (f.entry == entry_) {
    for (const lift::LocalFacts &l : function_slice(f.entry)->locals) out.locals.push_back(l);
    // A debug-info local whose type reaches a rebound name (BindTypeName)
    // has the bound definition, as asserted and debug-info prototypes do
    // (types.resolved).
    for (lift::LocalFacts &l : out.locals) {
      if (l.source_type.empty() || !rebound(l.source_type)) continue;
      std::unique_ptr<Asserted> t = asserted_type(l.source_type);
      if (!t) continue;
      inputs::GhidraTypes enc(t->store, data_org(), nullptr);
      // A stack slot keeps its size: an edit that resizes the type leaves
      // the local as the debug info has it (it would overlap others).
      if (enc.size(t->id) != static_cast<std::uint64_t>(l.type_size)) continue;
      l.type = enc.ref(t->id);
      for (lift::DecompElement &d : enc.take_definitions())
        if (const auto *id = d.attr("id"))
          if (const auto *u = std::get_if<std::uint64_t>(id)) overlay_types_.emplace(*u, std::move(d));
    }
  }
  // A function type as the decompiler's prototype for `out`.
  auto apply = [&](const Asserted &t, lift::SignatureSource source) {
    if (!prototype_from(t, out, f.entry == entry_)) return false;
    out.signature_source = source;
    return true;
  };
  bool asserted = false;
  std::unique_ptr<Asserted> analysis_proto;
  if (const SymbolInfo *s = symbol(f.entry); s != nullptr) {
    if (s->asserted && !s->name.empty() && s->name != f.name && s->name != f.source_name) {
      out.name = s->name;
      out.label.clear();
      // The name replaces the demangled one, namespaces and all.
      out.ns.clear();
    }
    // A demangled prototype ranks as an import: an agent's, a script's or
    // a plugin's doesn't replace it (docs/demangle.md).
    const bool outranked = f.demangled && s->type_rank < facts::rank(facts::ProvenanceKind::Import);
    // An analysis-rank prototype (RTTI's virtual methods) types `this`
    // only, after everything else had its say (apply_this).
    const bool analysis_rank = s->type_rank == facts::rank(facts::ProvenanceKind::Analysis);
    if (s->type.starts_with("h:") && !outranked && analysis_rank && s->type.substr(2) != f.source_type &&
        f.signature_source != lift::SignatureSource::imported) {
      analysis_proto = asserted_type(s->type.substr(2));
    } else if (s->type.starts_with("h:") && !outranked && !analysis_rank) {
      asserted = true;
      const std::string hash = s->type.substr(2);
      if (hash != f.source_type) {
        if (std::unique_ptr<Asserted> t = asserted_type(hash)) apply(*t, lift::SignatureSource::user_defined);
      } else if (rebound(hash)) {
        // The debug info's own prototype, but a type it uses was edited
        // (BindTypeName): the edited types, from the same source.
        if (std::unique_ptr<Asserted> t = asserted_type(hash)) apply(*t, f.signature_source);
      }
    }
  }
  // Nothing asserted and no signature from debug info or the library
  // archive: revkit::infer's, where the program was imported with
  // ImageBackendOptions::infer_prototypes (inference refines what Ghidra's
  // analysis would commit), else Ghidra's Decompiler Parameter ID's
  // (docs/param-id.md). The analyzer's own decompilations see neither
  // inference nor anything published, only their dependencies' commits.
  // A demangled prototype's guessed `this` goes where inference counts
  // the mangled parameters alone (a static member function).
  if (!asserted && out.this_guessed && f.entry != 0 && !param_id_deps_)
    if (std::optional<infer::Prototype> p = inferred(f.entry)) {
      std::vector<bool> is_float;
      for (const infer::VType &t : p->params) is_float.push_back(t.meta == infer::Meta::float_);
      inputs::refine_demangled_this(out, is_float);
    }
  if (!asserted && f.entry != 0 && f.signature_source == lift::SignatureSource::default_) {
    bool done = false;
    if (!param_id_deps_)
      if (std::optional<infer::Prototype> p = inferred(f.entry)) {
        Asserted t;
        const infer::StructureIds structures = inferred_structures(*p, t.store);
        // A structure the program no longer has (its assertions retracted:
        // the user undid it) is undefined bytes behind the pointer.
        std::function<void(infer::VType &)> gone = [&](infer::VType &v) {
          if (v.meta == infer::Meta::struct_ && v.name.starts_with("astruct_") && !structures.contains(v.name))
            v = infer::VType::unknown(1);
          for (infer::VType &x : v.pointee) gone(x);
        };
        gone(p->ret);
        for (infer::VType &v : p->params) gone(v);
        t.id = infer::to_type(*p, t.store, InferOrg(), &structures);
        done = apply(t, lift::SignatureSource::analysis);
      }
    if (!done)
      if (std::optional<lift::CommittedSignature> s = param_id(f.entry)) inputs::apply_param_id(out, *s);
  }
  if (analysis_proto && !asserted && f.entry != 0) apply_this(out, *analysis_proto);
  if (f.entry != 0) commit_variable_types(out);
  // The user's word on whether it returns (FactKind::NoReturn), over the
  // known names and analysis's evidence: the function itself, and every
  // call to it, which ends its caller's flow there or goes on.
  if (f.entry != 0) {
    const facts::SpaceId space = query([&] { return ctx_->get<q::Source>(program_); })->ram_space;
    auto said = query([&] { return ctx_->get<facts::AssertedFact>(FactKeyAt(facts::FactKind::NoReturn, space, f.entry)); });
    if (const auto *i = std::get_if<std::int64_t>(&*said)) out.noreturn = *i != 0;
  }
  overlaid_.emplace(&f, &out);
  return &out;
}

bool QueryLookup::in_this_register(const lift::ParamFacts &p) {
  if (p.storage.size() != 1 || p.storage[0].space != "register") return false;
  auto src = query([&] { return ctx_->get<q::Source>(program_); });
  const Program &prog = *src->program;
  const std::string &lang = prog.language().id();
  const char *name = lang.starts_with("x86:LE:64") ? "RCX" : lang.starts_with("x86:LE:32") ? "ECX"
                     : lang.starts_with("AARCH64") ? "x0" : nullptr;
  if (name == nullptr) return false;
  if (!this_register_) {
    this_register_.emplace();
    for (const lift::RegisterDef &r : prog.lifter()->registers())
      if (r.name == name && r.space == "register") this_register_ = std::make_pair(r.offset, static_cast<int>(r.size));
  }
  return this_register_->second != 0 && p.storage[0].offset == this_register_->first &&
         p.storage[0].size == this_register_->second;
}

// A virtual method's prototype at analysis rank: `this` (its first
// parameter) typed, in the prototype's convention (__thiscall on 32-bit
// x86), and nothing else locked. Where another source locked the
// prototype (inference, Decompiler Parameter ID), its first parameter
// becomes `this`; where nothing did, the function's own decompilation runs
// twice as a parameter retype does (commit_variable_types): the parameters
// the first run found are committed with `this` typed.
void QueryLookup::apply_this(lift::FunctionFacts &out, const Asserted &t) {
  const auto *fn = t.store.get(t.id).as<types::FunctionType>();
  if (fn == nullptr || fn->params.empty() || out.custom_storage) return;
  inputs::GhidraTypes enc(t.store, data_org(), nullptr);
  const lift::DecompElement this_type = enc.ref(fn->params[0].type);
  auto keep_definitions = [&] {
    for (lift::DecompElement &d : enc.take_definitions())
      if (const auto *id = d.attr("id"))
        if (const auto *u = std::get_if<std::uint64_t>(id)) overlay_types_.emplace(*u, std::move(d));
  };
  std::optional<std::string> model;
  if (fn->cc != types::CallConv::Default)
    for (const std::string &n : ConventionModels(fn->cc))
      if (models_->contains(n)) {
        model = n;
        break;
      }
  auto is_float = [](const lift::DecompElement &e) {
    const auto *m = e.attr("metatype");
    return m != nullptr && std::holds_alternative<std::string>(*m) && std::get<std::string>(*m) == "float";
  };
  auto name_this = [](lift::ParamFacts &p) {
    if (p.name.empty() || p.name.starts_with("param_") || p.name.starts_with("in_")) p.name = "this";
  };
  if (out.signature_source != lift::SignatureSource::default_) {
    if (model && out.convention != *model) {
      // Locked in another convention (an inferred __stdcall): `this` goes
      // in front, in the model's register.
      lift::ParamFacts p;
      p.name = "this";
      p.type = this_type;
      out.params.insert(out.params.begin(), std::move(p));
      out.convention = *model;
      out.dynamic_storage = true;
    } else if (!out.params.empty() && !is_float(out.params[0].type) &&
               (out.dynamic_storage || in_this_register(out.params[0]))) {
      out.params[0].type = this_type;
      name_this(out.params[0]);
    } else {
      return;
    }
    keep_definitions();
    return;
  }
  if (model) out.convention = *model;
  if (out.entry != entry_ || param_id_deps_) return;  // a caller sees it unlocked
  if (!found_) {
    needs_found_ = true;
    return;
  }
  if (!found_->params || found_->params->empty() || !in_this_register((*found_->params)[0])) return;
  out.params = *found_->params;
  out.params[0].type = this_type;
  name_this(out.params[0]);
  if (!out.convention || *out.convention == "unknown") out.convention = "default";
  out.signature_source = lift::SignatureSource::user_defined;
  out.ret.is_default = true;  // the return stays the decompiler's
  out.dynamic_storage = false;
  keep_definitions();
}

// Parameters and locals the user typed (a retype of the variable, by its
// storage key): committed as Ghidra's HighFunctionDBUtil.updateDBVariable
// commits a variable's type, type-locked, so the decompiler propagates the
// type through the body (field accesses, typed loads and stores) rather
// than only printing it in the declaration. A parameter's type goes into
// the prototype callers see too; a local is told only to its own function.
void QueryLookup::commit_variable_types(lift::FunctionFacts &out) {
  // The analyzer's own decompilations (Decompiler Parameter ID) see none:
  // in Ghidra they ran before the user's edits.
  if (param_id_deps_) return;
  auto vars = query([&] { return ctx_->get<q::VariableTypes>({program_, out.entry}); });
  if (vars->empty()) return;
  // A parameter typed where no prototype is locked: the parameters the
  // decompiler found are committed first, as undefinedN of their storage
  // (the return stays unlocked), when this function is decompiled again
  // (Decompile); a caller sees the prototype unlocked.
  if (out.signature_source == lift::SignatureSource::default_ &&
      std::any_of(vars->begin(), vars->end(), [](const VariableType &v) { return v.param >= 0; }) && out.entry == entry_) {
    if (!found_) {
      needs_found_ = true;
    } else if (found_->params) {
      out.params = *found_->params;
      out.signature_source = lift::SignatureSource::user_defined;
      out.dynamic_storage = false;
      // Only the inputs are locked: the return stays the decompiler's (an
      // undefined, unlocked output, as Ghidra commits the parameters of a
      // function with no prototype), else it would be a locked void and the
      // code computing the return value would go.
      out.ret.is_default = true;
      if (!out.convention || out.convention->empty() || *out.convention == "unknown") out.convention = "default";
    }
  }
  const unsigned ptr = data_org().pointer;
  const bool big_endian =
      query([&] { return ctx_->get<q::Source>(program_); })->program->language().language.find(":BE:") != std::string::npos;
  auto sext = [&](std::uint64_t v) {
    if (ptr >= 8) return static_cast<std::int64_t>(v);
    const unsigned shift = 64 - 8 * ptr;
    return static_cast<std::int64_t>(v << shift) >> shift;
  };
  auto keep_definitions = [&](inputs::GhidraTypes &enc) {
    for (lift::DecompElement &d : enc.take_definitions())
      if (const auto *id = d.attr("id"))
        if (const auto *u = std::get_if<std::uint64_t>(id)) overlay_types_.emplace(*u, std::move(d));
  };
  for (const VariableType &v : *vars) {
    const bool param = v.param >= 0;
    if (!param && out.entry != entry_) continue;
    // A temporary: by the hash the decompiler mapped it by.
    const std::pair<std::uint64_t, std::uint64_t> *hashed = nullptr;
    if (!param && v.space.empty()) {
      if (!v.key.starts_with("unique:")) continue;
      if (!found_) {
        needs_found_ = true;
        continue;
      }
      auto h = found_->hashes.find(v.key);
      if (h == found_->hashes.end()) continue;
      hashed = &h->second;
    }
    // An unlocked prototype has no parameter list to type one of (the
    // decompiler finds the parameters itself): display only.
    if (param && (out.signature_source == lift::SignatureSource::default_ ||
                  static_cast<std::size_t>(v.param) >= out.params.size() || !out.params[v.param].valid))
      continue;
    std::unique_ptr<Asserted> t = asserted_type(v.hash);
    if (!t) continue;
    inputs::GhidraTypes enc(t->store, data_org(), nullptr);
    const std::uint64_t size = enc.size(t->id);
    if (size == 0 || size > 0xffff) continue;
    if (param) {
      lift::ParamFacts &p = out.params[static_cast<std::size_t>(v.param)];
      if (!out.dynamic_storage) {
        int stored = 0;
        for (const lift::StorageVarnode &s : p.storage) stored += s.size;
        if (stored != static_cast<int>(size)) {
          // Another size: the convention assigns every parameter's
          // storage again, unless the storage is the user's.
          if (out.custom_storage) continue;
          out.dynamic_storage = true;
        }
      }
      p.type = enc.ref(t->id);
      keep_definitions(enc);
      continue;
    }
    if (hashed != nullptr) {
      lift::LocalFacts &l = out.locals.emplace_back();
      l.name = v.name;
      l.hash = hashed->first;
      l.first_use = static_cast<int>(static_cast<std::int64_t>(hashed->second - out.entry));
      l.type = enc.ref(t->id);
      l.type_size = l.size = static_cast<int>(size);
      keep_definitions(enc);
      continue;
    }
    lift::StorageVarnode sv{v.space, v.offset, static_cast<int>(size)};
    int first_use = 0;
    if (v.space == "stack") {
      if (ptr < 8) sv.offset &= (std::uint64_t{1} << (8 * ptr)) - 1;
    } else {
      // A register the key names, or a part of it or the register around
      // it as wide as the type.
      const std::uint64_t reg = v.size != 0 ? v.size : size;
      if (big_endian) {
        if (reg < size && v.offset < size - reg) continue;
        sv.offset = v.offset + reg - size;
      }
      if (!v.pc) continue;
      first_use = static_cast<int>(static_cast<std::int64_t>(*v.pc - out.entry));
    }
    const std::int64_t lo = sext(sv.offset), hi = lo + static_cast<std::int64_t>(size);
    auto same = [&](const lift::LocalFacts &l) {
      if (l.hash || l.storage.size() != 1 || l.storage[0].space != sv.space) return false;
      if (sv.space == "stack") return sext(l.storage[0].offset) == lo;
      return l.storage[0].offset == sv.offset && l.first_use == first_use;
    };
    auto overlaps = [&](const lift::LocalFacts &l) {
      if (sv.space != "stack" || same(l)) return false;
      for (const lift::StorageVarnode &s : l.storage)
        if (s.space == "stack" && sext(s.offset) < hi && lo < sext(s.offset) + s.size) return true;
      return false;
    };
    // A typed local it would overlap wins (Ghidra refuses the conflict);
    // undefined ones in the way go, as updateDBVariable clears them.
    if (std::any_of(out.locals.begin(), out.locals.end(), [&](const lift::LocalFacts &l) { return !l.undefined && overlaps(l); }))
      continue;
    std::erase_if(out.locals, overlaps);
    auto it = std::find_if(out.locals.begin(), out.locals.end(), same);
    lift::LocalFacts &l = it != out.locals.end() ? *it : out.locals.emplace_back();
    // No name asserted: the decompiler names it (an empty name isn't
    // locked), as it did before.
    if (it == out.locals.end() || !v.name.empty()) l.name = v.name;
    l.undefined = false;
    l.first_use = first_use;
    l.storage = {sv};
    l.type = enc.ref(t->id);
    l.is_float = false;
    l.type_size = static_cast<int>(size);
    l.source_type.clear();
    keep_definitions(enc);
  }
}

const lift::FunctionFacts *QueryLookup::function_at(std::uint64_t entry) {
  const AddressFacts *af = address(entry);
  if (af->starts) return with_overlay(*af->starts);
  if (const Linked *l = linked(entry); l && l->function) return &*l->function;
  return nullptr;
}

const std::vector<std::string> &QueryLookup::links() {
  if (links_) return *links_;
  links_.emplace();
  auto src = query([&] { return ctx_->get<q::Source>(program_); });
  const facts::FactKey key = FactKeyAt(facts::FactKind::Note, archive::kProjectSpace, src->ordinal, std::string(kDsdSub));
  auto v = query([&] { return ctx_->get<facts::AssertedFact>(key); });
  const std::string *text = std::get_if<std::string>(&*v);
  if (text == nullptr || text->empty()) return *links_;
  auto programs = query([&] { return ctx_->get<q::Programs>(0); });
  for (const auto &[module, id] : DsdRecord::decode(*text).links)
    if (id != program_ && std::find(programs->begin(), programs->end(), id) != programs->end()) links_->push_back(id);
  return *links_;
}

void QueryLookup::import_types(QueryLookup &from, const lift::DecompElement &e, int depth) {
  if (depth > 32) return;
  if (const auto *id = e.attr("id"))
    if (const auto *u = std::get_if<std::uint64_t>(id); u && !overlay_types_.contains(*u))
      if (const lift::DecompElement *def = from.type(*u)) {
        overlay_types_.emplace(*u, *def);
        import_types(from, *def, depth + 1);
      }
  for (const lift::DecompElement &c : e.children) import_types(from, c, depth + 1);
}

const QueryLookup::Linked *QueryLookup::linked(std::uint64_t a) {
  if (auto it = linked_.find(a); it != linked_.end()) return &it->second;
  if (frozen_) return nullptr;
  const AddressFacts *af = address(a);
  if (af->block || af->starts || af->contains || af->data || af->label || af->external) return nullptr;
  Linked &out = linked_[a];
  QueryLookup *hit = nullptr;
  for (const std::string &id : links()) {
    std::unique_ptr<QueryLookup> &sub = linked_lookups_[id];
    if (!sub) sub = std::make_unique<QueryLookup>(*ctx_, id, 0);
    if (!sub->address(a)->block) continue;
    if (hit) return &out;  // two modules map it (overlays sharing addresses): neither
    hit = sub.get();
  }
  if (!hit) return &out;
  if (const lift::FunctionFacts *f = hit->function_at(a)) {
    lift::FunctionFacts g = *f;
    // A callee in another program: its symbol and prototype, nothing to decode.
    g.body.clear();
    g.context.clear();
    g.context_reach.clear();
    g.locals.clear();
    import_types(*hit, g.ret.type, 0);
    for (const lift::ParamFacts &prm : g.params) import_types(*hit, prm.type, 0);
    out.function = std::move(g);
  }
  if (const lift::DataFacts *d = hit->data_containing({}, a)) {
    lift::DataFacts g = *d;
    // Its bytes are the other program's: nothing here to read as constant.
    g.mutability = lift::Mutability::normal;
    g.string.reset();
    import_types(*hit, g.type, 0);
    out.data = std::move(g);
  }
  if (const lift::LabelFacts *l = hit->label_at({}, a)) out.label = *l;
  return &out;
}

std::optional<lift::FactLookup::Body> QueryLookup::body_containing(std::uint64_t a) {
  const AddressFacts *af = address(a);
  if (!af->contains) {
    // A linked module's function: its entry alone, as the decompiler names it.
    if (const Linked *l = linked(a); l && l->function) return Body{a, a, &*l->function};
    return std::nullopt;
  }
  return Body{af->body_first, af->body_last, with_overlay(*af->contains)};
}

const lift::DataFacts *QueryLookup::data_containing(const std::string &space, std::uint64_t a) {
  if (!space.empty()) return nullptr;
  const AddressFacts *af = address(a);
  const SymbolInfo *s = af->data ? symbol(af->data->addr) : symbol(a);
  const bool renamed = s != nullptr && s->asserted && !s->name.empty();
  if (af->data) {
    const lift::DataFacts &d = *af->data;
    const bool rename = renamed && s->name != d.name && s->name != d.source_name;
    const bool retype = s != nullptr && s->type.starts_with("h:") && s->type.substr(2) != d.source_type;
    // A debug-info global whose type reaches a rebound name: the bound
    // definition (types.resolved), as for prototypes.
    const bool rebind = !retype && !d.source_type.empty() && rebound(d.source_type);
    if (!rename && !retype && !rebind) return &d;
    lift::DataFacts &out = owned_data_.emplace_back(d);
    if (rename) out.name = s->name;
    if (retype || rebind) {
      if (std::unique_ptr<Asserted> t = asserted_type(retype ? s->type.substr(2) : d.source_type)) {
        inputs::GhidraTypes enc(t->store, data_org(), nullptr);
        if (const std::uint64_t size = enc.size(t->id); size != 0) {
          out.type = enc.ref(t->id);
          out.length = size;
          for (lift::DecompElement &def : enc.take_definitions())
            if (const auto *id = def.attr("id"))
              if (const auto *u = std::get_if<std::uint64_t>(id)) overlay_types_.emplace(*u, std::move(def));
        }
      }
    }
    return &out;
  }
  // A name asserted where the program has no symbol: undefined bytes that
  // carry it, as Java sends them.
  if (!renamed)
    if (const Linked *l = linked(a); l && l->data) return &*l->data;
  if (renamed && s->kind == SymbolInfo::Kind::Data && !af->label && !af->contains) {
    lift::DataFacts &out = owned_data_.emplace_back();
    out.addr = a;
    out.name = s->name;
    out.length = 1;
    out.type = {"typeref", {{"id", std::uint64_t{0xc000000000000000ULL}}, {"name", std::string("undefined")}}, {}};
    out.mutability = af->block.value_or(lift::Mutability::normal);
    return &out;
  }
  return nullptr;
}

const lift::ExternalRefFacts *QueryLookup::external_at(const std::string &space, std::uint64_t a) {
  if (!space.empty()) return nullptr;
  const AddressFacts *af = address(a);
  return af->external ? &*af->external : nullptr;
}

const lift::LabelFacts *QueryLookup::label_at(const std::string &space, std::uint64_t a) {
  if (!space.empty()) return nullptr;
  const AddressFacts *af = address(a);
  if (!af->label) {
    if (const Linked *l = linked(a); l && l->label) return &*l->label;
    return nullptr;
  }
  const SymbolInfo *s = symbol(a);
  if (s == nullptr || !s->asserted || s->name.empty() || s->name == af->label->name) return &*af->label;
  lift::LabelFacts &out = owned_labels_.emplace_back(*af->label);
  out.name = s->name;
  return &out;
}

std::optional<std::string> QueryLookup::code_label_at(const std::string &space, std::uint64_t a) {
  if (!space.empty()) return std::nullopt;
  if (const SymbolInfo *s = symbol(a); s != nullptr && s->asserted && !s->name.empty() &&
                                       s->kind == SymbolInfo::Kind::CodeLabel)
    return s->name;
  const AddressFacts *af = address(a);
  if (af->contains)
    for (const lift::LabelFacts &l : function_slice(af->contains->entry)->code_labels)
      if (l.addr == a) return l.name;
  // A target of the function being decompiled outside every function's
  // body (code only it jumps to) has the label its jump gives it, as in
  // the program-wide inputs (rk-lift).
  if (!af->contains || af->contains->entry != entry_)
    for (const lift::LabelFacts &l : function_slice(entry_)->code_labels)
      if (l.addr == a) return l.name;
  return std::nullopt;
}

std::optional<lift::Mutability> QueryLookup::block_at(const std::string &space, std::uint64_t a) {
  if (!space.empty()) return std::nullopt;
  return address(a)->block;
}

const lift::DecompElement *QueryLookup::type(std::uint64_t id) {
  if (auto it = overlay_types_.find(id); it != overlay_types_.end()) return &it->second;
  if (auto it = types_.find(id); it != types_.end()) return *it->second ? &**it->second : nullptr;
  if (frozen_) return nullptr;  // types are asked for while analysing, not printing
  auto ref = query([&] { return ctx_->get<q::InputsType>({program_, id}); });
  auto &slot = types_.emplace(id, std::move(ref)).first->second;
  if (*slot)
    if (const lift::DecompElement *defined = defined_class(id, **slot)) return defined;
  return *slot ? &**slot : nullptr;
}

// A class the demangler names (an incomplete struct of the class's name:
// a member function's `this`, a pointer parameter) that the program
// defines (a C++ header imported with ParseC, DefineType, another
// module's debug info): the program's definition, under the id the
// demangler's prototypes refer to, so every function naming the class
// sees its fields (`this->w`, not `this + 0x14`). Only a name exactly one
// complete program type has (as `class N` or `struct N`, or in a
// namespace, `class ns::N`). Null where none does.
const lift::DecompElement *QueryLookup::defined_class(std::uint64_t id, const lift::DecompElement &decl) {
  auto text = [&](const char *attr) -> const std::string * {
    const auto *v = decl.attr(attr);
    return v != nullptr ? std::get_if<std::string>(v) : nullptr;
  };
  const std::string *meta = text("metatype"), *name = text("name");
  const auto *size = decl.attr("size");
  if (decl.tag != "type" || !decl.children.empty() || meta == nullptr || *meta != "struct" || name == nullptr ||
      name->empty() || size == nullptr || !std::holds_alternative<std::int64_t>(*size) || std::get<std::int64_t>(*size) != 1)
    return nullptr;
  auto named = query([&] { return ctx_->get<q::TypeNames>(program_); });
  std::set<std::string> hashes;
  for (const NamedTypes::Entry &e : named->types) {
    if (e.library) continue;
    for (std::string_view kind : {"class ", "struct "}) {
      if (!e.key.starts_with(kind)) continue;
      const std::string_view n = std::string_view(e.key).substr(kind.size());
      if (n == *name || (n.size() > name->size() + 2 && n.ends_with(*name) &&
                         n.substr(n.size() - name->size() - 2, 2) == "::")) {
        const std::string *bound = named->bound(e.key);
        hashes.insert(bound != nullptr ? *bound : e.hash);
      }
    }
  }
  if (hashes.size() != 1) return nullptr;
  std::unique_ptr<Asserted> t = asserted_type(*hashes.begin());
  if (!t) return nullptr;
  const auto *agg = t->store.get(t->id).as<types::AggregateType>();
  if (agg == nullptr || !agg->complete || agg->size == 0 || agg->kind == types::AggregateKind::Union) return nullptr;
  inputs::GhidraTypes enc(t->store, data_org(), nullptr);
  const lift::DecompElement ref = enc.ref(t->id);
  const auto *own_attr = ref.attr("id");
  if (own_attr == nullptr || !std::holds_alternative<std::uint64_t>(*own_attr)) return nullptr;
  const std::uint64_t own = std::get<std::uint64_t>(*own_attr);
  std::optional<lift::DecompElement> def;
  for (lift::DecompElement &d : enc.take_definitions())
    if (const auto *a = d.attr("id"))
      if (const auto *u = std::get_if<std::uint64_t>(a)) {
        if (*u == own) def = d;
        overlay_types_.emplace(*u, std::move(d));
      }
  if (!def) return nullptr;
  for (auto &[k, v] : def->attrs)
    if (k == "id") v = id;
  return &overlay_types_.insert_or_assign(id, std::move(*def)).first->second;
}

std::vector<const lift::CommentFacts *> QueryLookup::comments(std::uint64_t entry) {
  std::vector<const lift::CommentFacts *> out;
  for (const lift::CommentFacts &c : address(entry)->comments) out.push_back(&c);
  return out;
}

std::vector<std::pair<std::uint64_t, std::string>> QueryLookup::flow_overrides(std::uint64_t entry) {
  return function_slice(entry)->flow_overrides;
}

std::vector<lift::TrackedFacts> QueryLookup::tracked(std::uint64_t entry) {
  std::vector<lift::TrackedFacts> out = address(entry)->tracked;
  // Register values over ranges (docs/api.md, "Register values"): what the
  // map says at the entry, over the inputs' defaults for those registers
  // (a user's value replaces one, a user's clear removes it).
  auto at = query([&] { return ctx_->get<an::RegisterValuesAt>(an::Location{an::ProgramKey{program_}, entry}); });
  for (const auto &[name, value] : *at) {
    std::erase_if(out, [&](const lift::TrackedFacts &t) { return t.register_name == name; });
    if (!value) continue;
    lift::TrackedFacts t;
    t.register_name = name;
    t.value = *value;
    out.push_back(std::move(t));
  }
  return out;
}

void QueryLookup::reset() {
  linked_.clear();
  for (auto &[id, sub] : linked_lookups_) sub->reset();
  addresses_.clear();
  functions_.clear();
  symbols_.clear();
  types_.clear();
  overlaid_.clear();
  owned_functions_.clear();
  owned_data_.clear();
  owned_labels_.clear();
  overlay_types_.clear();
}

}  // namespace revkit::backend
