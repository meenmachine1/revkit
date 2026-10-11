#include "slice.h"

#include <algorithm>
#include <deque>
#include <set>
#include <string>
#include <vector>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;

namespace {

bool OpBased(pb::SliceKind k) { return k == pb::SLICE_KIND_FORWARD_OPS || k == pb::SLICE_KIND_BACKWARD_OPS; }
bool Forward(pb::SliceKind k) { return k == pb::SLICE_KIND_FORWARD || k == pb::SLICE_KIND_FORWARD_OPS; }
bool Backward(pb::SliceKind k) { return k == pb::SLICE_KIND_BACKWARD || k == pb::SLICE_KIND_BACKWARD_OPS; }

}  // namespace

Status SliceFunction(const pb::DecompiledFunction &fn, const pb::SliceDecompiledRequest &req,
                     pb::SliceDecompiledResponse &resp) {
  const pb::DataFlow &df = fn.dataflow();
  if (df.nodes().empty()) return Error(StatusCode::kFailedPrecondition, "this decompilation has no data-flow graph");
  const pb::SliceKind kind = req.kind();
  if (kind == pb::SLICE_KIND_UNSPECIFIED || !pb::SliceKind_IsValid(kind))
    return Error(StatusCode::kInvalidArgument, "kind: DEF_USE, FORWARD, BACKWARD, FORWARD_OPS or BACKWARD_OPS");
  const auto nodes = static_cast<std::uint32_t>(df.nodes_size());
  const auto ops = static_cast<std::uint32_t>(df.ops_size());

  // Where it starts: nodes, and ops (an operator token's op).
  std::vector<std::uint32_t> start_nodes, start_ops;
  std::string caption;
  switch (req.from_case()) {
    case pb::SliceDecompiledRequest::kToken: {
      const pb::TokenPosition &at = req.token();
      if (at.line() >= static_cast<std::uint32_t>(fn.lines_size()) ||
          at.token() >= static_cast<std::uint32_t>(fn.lines(static_cast<int>(at.line())).tokens_size()))
        return Error(StatusCode::kInvalidArgument, "no token at line " + std::to_string(at.line()) + ", token " +
                                                       std::to_string(at.token()));
      const pb::CodeToken &t = fn.lines(static_cast<int>(at.line())).tokens(static_cast<int>(at.token()));
      caption = t.text();
      for (std::uint32_t n : t.varnode_indices())
        if (n < nodes) start_nodes.push_back(n);
      if (start_nodes.empty() && t.has_op_index() && t.op_index() < ops) {
        // An operator, a call's name, `return`: the value the op makes
        // (forward), or the values it reads (backward).
        const pb::DataFlowOp &op = df.ops(static_cast<int>(t.op_index()));
        if (Backward(kind)) {
          start_ops.push_back(t.op_index());
          for (std::uint32_t n : op.inputs())
            if (n < nodes) start_nodes.push_back(n);
        } else if (op.has_output() && op.output() < nodes) {
          start_nodes.push_back(op.output());
        } else if (Forward(kind)) {
          start_ops.push_back(t.op_index());
        }
      }
      break;
    }
    case pb::SliceDecompiledRequest::kVarnodeIndex:
      if (req.varnode_index() >= nodes)
        return Error(StatusCode::kInvalidArgument, "no varnode " + std::to_string(req.varnode_index()));
      start_nodes.push_back(req.varnode_index());
      for (const auto &line : fn.lines())
        for (const auto &t : line.tokens())
          if (caption.empty() && std::count(t.varnode_indices().begin(), t.varnode_indices().end(), req.varnode_index()))
            caption = t.text();
      break;
    case pb::SliceDecompiledRequest::kVariableIndex:
      if (req.variable_index() >= static_cast<std::uint32_t>(fn.variables_size()))
        return Error(StatusCode::kInvalidArgument, "no variable " + std::to_string(req.variable_index()));
      caption = fn.variables(static_cast<int>(req.variable_index())).name();
      for (int i = 0; i < fn.varnodes_size() && static_cast<std::uint32_t>(i) < nodes; ++i)
        if (fn.varnodes(i).has_variable_index() && fn.varnodes(i).variable_index() == req.variable_index())
          start_nodes.push_back(static_cast<std::uint32_t>(i));
      break;
    default:
      return Error(StatusCode::kInvalidArgument, "say where the slice starts: token, varnode_index or variable_index");
  }
  if (start_nodes.empty() && start_ops.empty())
    return Error(StatusCode::kInvalidArgument, "\"" + caption + "\" is no value to slice from (a keyword, a type, punctuation)");
  resp.set_start(caption);

  // Which ops read each node.
  std::vector<std::vector<std::uint32_t>> uses(nodes);
  for (std::uint32_t o = 0; o < ops; ++o)
    for (std::uint32_t n : df.ops(static_cast<int>(o)).inputs())
      if (n < nodes) uses[n].push_back(o);

  std::vector<char> in_node(nodes, 0), in_op(ops, 0);
  std::deque<std::uint32_t> todo;
  auto add_node = [&](std::uint32_t n) {
    if (n < nodes && !in_node[n]) {
      in_node[n] = 1;
      todo.push_back(n);
    }
  };
  for (std::uint32_t n : start_nodes) add_node(n);
  if (kind == pb::SLICE_KIND_DEF_USE) {
    // The varnode's definition and its uses: one step each way.
    for (std::uint32_t n : start_nodes) {
      if (df.nodes(static_cast<int>(n)).has_def() && df.nodes(static_cast<int>(n)).def() < ops) in_op[df.nodes(static_cast<int>(n)).def()] = 1;
      for (std::uint32_t o : uses[n]) in_op[o] = 1;
    }
  } else {
    for (std::uint32_t o : start_ops) {
      if (in_op[o]) continue;
      in_op[o] = 1;
      const pb::DataFlowOp &op = df.ops(static_cast<int>(o));
      if (Forward(kind) && op.has_output()) add_node(op.output());
    }
    while (!todo.empty()) {
      const std::uint32_t n = todo.front();
      todo.pop_front();
      if (Forward(kind)) {
        // Every op that reads it, and what each writes.
        for (std::uint32_t o : uses[n]) {
          if (in_op[o]) continue;
          in_op[o] = 1;
          const pb::DataFlowOp &op = df.ops(static_cast<int>(o));
          if (op.has_output()) add_node(op.output());
        }
      } else {
        // The op that writes it, and what that op reads.
        const pb::DataFlowNode &node = df.nodes(static_cast<int>(n));
        if (!node.has_def() || node.def() >= ops || in_op[node.def()]) continue;
        in_op[node.def()] = 1;
        for (std::uint32_t in : df.ops(static_cast<int>(node.def())).inputs()) add_node(in);
      }
    }
  }

  // The tokens: those printing a node of the slice, or (instruction slices)
  // printed from one of its ops.
  for (int l = 0; l < fn.lines_size(); ++l) {
    const auto &tokens = fn.lines(l).tokens();
    for (int i = 0; i < tokens.size(); ++i) {
      const pb::CodeToken &t = tokens[i];
      bool hit = false;
      if (OpBased(kind)) hit = t.has_op_index() && t.op_index() < ops && in_op[t.op_index()];
      else
        for (std::uint32_t n : t.varnode_indices()) hit = hit || (n < nodes && in_node[n]);
      if (!hit) continue;
      pb::TokenPosition *p = resp.add_tokens();
      p->set_line(static_cast<std::uint32_t>(l));
      p->set_token(static_cast<std::uint32_t>(i));
    }
  }
  std::set<std::uint64_t> addresses;
  for (std::uint32_t o = 0; o < ops; ++o)
    if (in_op[o] && df.ops(static_cast<int>(o)).has_address()) addresses.insert(df.ops(static_cast<int>(o)).address().offset());
  for (std::uint64_t a : addresses) resp.add_addresses()->set_offset(a);
  for (int i = 0; i < fn.varnodes_size() && static_cast<std::uint32_t>(i) < nodes; ++i)
    if (in_node[static_cast<std::size_t>(i)]) resp.add_varnode_indices(static_cast<std::uint32_t>(i));
  return Status::Ok();
}

}  // namespace revkit::backend
