#include "param_id.h"

#include "own_inputs.h"
#include "program.h"
#include "queries.h"

#include "revkit/inputs/codec.h"

#include <algorithm>
#include <stdexcept>

namespace revkit::backend {

namespace an = analysis;
using facts::QueryContext;

void ParamIdPlanValue::encode(facts::Encoder &e) const {
  facts::encode(e, enabled);
  plan.encode(e);
}

ParamIdPlanValue ParamIdPlanValue::decode(facts::Decoder &d) {
  ParamIdPlanValue v;
  v.enabled = facts::decode<bool>(d);
  v.plan = inputs::ParamIdPlan::decode(d);
  return v;
}

void ParamIdSlice::encode(facts::Encoder &e) const {
  facts::encode(e, node);
  facts::encode(e, deps);
}

ParamIdSlice ParamIdSlice::decode(facts::Decoder &d) {
  ParamIdSlice v;
  v.node = facts::decode<bool>(d);
  v.deps = facts::decode<std::vector<std::uint64_t>>(d);
  return v;
}

std::optional<std::uint64_t> ThunkedFunction(QueryContext &ctx, const std::string &program, std::uint64_t entry) {
  for (int hops = 0; hops < 16; ++hops) {
    auto f = ctx.get<an::Function>(an::Location{an::ProgramKey{program}, entry});
    if (f->name.empty() || !(f->flags & an::kFunctionThunk)) return entry;
    if (!f->import.empty()) return std::nullopt;
    entry = f->thunk_target;
  }
  return std::nullopt;
}

namespace q {

ParamIdPlan::Value ParamIdPlan::compute(QueryContext &ctx, const Key &program) {
  ParamIdPlanValue out;
  const auto mode = static_cast<inputs::ParamIdMode>(*ctx.get<ParamIdModeInput>(program));
  auto src = ctx.get<Source>(program);
  if (!src->program) throw std::logic_error("program " + program + " is not loaded");
  auto st = ctx.get<InputsStatic>(program);
  if (!inputs::param_id_enabled(mode, src->program->image(), st->memory)) return out;
  out.enabled = true;
  const an::ProgramKey key{program};
  auto functions = ctx.get<an::Functions>(key);
  auto info = ctx.get<an::Program>(key);
  std::optional<facts::Ref<an::FlowGraph>> flow;
  std::vector<inputs::CallGraphNode> nodes =
      inputs::call_graph_nodes(*functions, *info, [&](std::uint64_t k) -> const an::FlowGraph & {
        flow = ctx.get<an::Flow>(an::Location{key, k});
        return **flow;
      });
  out.plan = inputs::param_id_plan(nodes, info->code_space.empty() ? std::string("ram") : info->code_space);
  return out;
}

std::size_t ParamIdPlan::weight(const Value &v) {
  std::size_t deps = 0;
  for (const auto &[n, d] : v.plan.dependencies) deps += d.size();
  return sizeof(Value) + v.plan.nodes.size() * 64 + deps * 8 + v.plan.thunks.size() * 48;
}

ParamIdDeps::Value ParamIdDeps::compute(QueryContext &ctx, const Key &key) {
  auto plan = ctx.get<ParamIdPlan>(key.first);
  ParamIdSlice out;
  if (!plan->enabled || !std::binary_search(plan->plan.nodes.begin(), plan->plan.nodes.end(), key.second)) return out;
  out.node = true;
  out.deps = plan->plan.dependencies_of(key.second);
  return out;
}

ParamId::Value ParamId::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, entry] = key;
  lift::CommittedSignature out;
  auto slice = ctx.get<ParamIdDeps>(key);
  if (!slice->node) {
    out.detail = "not analyzed";
    return out;
  }
  auto inputs = ctx.get<Inputs>(key);
  if (!inputs->exists) {
    out.detail = "no function";
    return out;
  }
  auto src = ctx.get<Source>(program);
  if (!src->program) throw std::logic_error("program " + program + " is not loaded");
  auto image = ctx.get<InputsImage>(program);
  auto st = ctx.get<InputsStatic>(program);
  // What it sees: its dependencies' commits (decompiled before it), the
  // user's and the debug info's prototypes, nothing published.
  QueryLookup lookup(ctx, program, entry, &slice->deps);
  const lift::FunctionFacts *self = lookup.function_at(entry);
  if (lookup.failure) std::rethrow_exception(lookup.failure);
  if (self == nullptr) {
    out.detail = "no function";
    return out;
  }
  if (std::optional<std::string> skip = inputs::param_id_skip(*self, false, st->memory)) {
    out.detail = *skip;
    return out;
  }
  return EffectiveProgram(ctx, program)->decompiler().ParamId(*inputs, *image, lookup);
}

}  // namespace q

void RegisterParamIdQueries(facts::Engine &engine) {
  engine.add_input<q::ParamIdModeInput>();
  engine.add_input<q::ParamIdPublished>();
  engine.add_query<q::ParamIdPlan>();
  engine.add_query<q::ParamIdDeps>();
  engine.add_query<q::ParamId>();
}

}  // namespace revkit::backend
