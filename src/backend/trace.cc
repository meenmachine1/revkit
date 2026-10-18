#include "trace.h"

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace revkit::backend {

using api::Error;
using api::Status;
using api::StatusCode;

namespace {

constexpr std::uint32_t kDefaultDepth = 3, kMaxDepth = 8;
constexpr std::uint32_t kDefaultFunctions = 12, kMaxFunctions = 64;
constexpr std::uint32_t kDefaultNodes = 2000, kMaxNodes = 20000;
constexpr std::uint32_t kDefaultEdges = 4000, kMaxEdges = 40000;

std::uint32_t Budget(std::uint32_t asked, std::uint32_t def, std::uint32_t max) {
  return asked == 0 ? def : std::min(asked, max);
}

bool SameVarnode(const pb::Varnode &a, const pb::Varnode &b) {
  return a.space() == b.space() && a.offset() == b.offset() && a.size() == b.size();
}

// One function's decompilation, with what the walk asks of it.
struct Fn {
  std::uint64_t entry = 0;
  const pb::DecompiledFunction *f = nullptr;
  std::vector<std::vector<std::uint32_t>> uses;  // node -> ops reading it
  std::uint32_t index = 0;                        // in resp.functions

  const pb::DataFlow &df() const { return f->dataflow(); }
  std::uint32_t nodes() const { return static_cast<std::uint32_t>(df().nodes_size()); }
  std::uint32_t ops() const { return static_cast<std::uint32_t>(df().ops_size()); }
  const pb::DataFlowNode &node(std::uint32_t n) const { return df().nodes(static_cast<int>(n)); }
  const pb::DataFlowOp &op(std::uint32_t o) const { return df().ops(static_cast<int>(o)); }

  const pb::Varnode *storage(std::uint32_t n) const {
    if (n < static_cast<std::uint32_t>(f->varnodes_size())) return &f->varnodes(static_cast<int>(n)).varnode();
    return node(n).has_varnode() ? &node(n).varnode() : nullptr;
  }
  // The variable a node belongs to, when a token prints it.
  const pb::Variable *variable(std::uint32_t n) const {
    if (n >= static_cast<std::uint32_t>(f->varnodes_size())) return nullptr;
    const pb::MappedVarnode &m = f->varnodes(static_cast<int>(n));
    if (!m.has_variable_index() || m.variable_index() >= static_cast<std::uint32_t>(f->variables_size())) return nullptr;
    return &f->variables(static_cast<int>(m.variable_index()));
  }
  // The parameter (0-based) an input node is, if any.
  std::optional<std::uint32_t> parameter_of(std::uint32_t n) const {
    if (node(n).has_def() || node(n).constant()) return std::nullopt;
    if (const pb::Variable *v = variable(n); v && v->has_parameter_index()) return v->parameter_index();
    const pb::Varnode *s = storage(n);
    if (!s) return std::nullopt;
    for (const pb::Variable &v : f->variables())
      if (v.has_parameter_index())
        for (const pb::Varnode &st : v.storage())
          if (SameVarnode(st, *s)) return v.parameter_index();
    return std::nullopt;
  }
  // The input nodes of parameter i.
  std::vector<std::uint32_t> parameter_nodes(std::uint32_t i) const {
    std::vector<std::uint32_t> out;
    for (std::uint32_t n = 0; n < nodes(); ++n)
      if (auto p = parameter_of(n); p && *p == i) out.push_back(n);
    return out;
  }
  // The direct call ops at a call instruction.
  std::vector<std::uint32_t> calls_at(std::uint64_t address) const {
    std::vector<std::uint32_t> out;
    for (std::uint32_t o = 0; o < ops(); ++o)
      if (op(o).opcode() == "CALL" && op(o).address().offset() == address) out.push_back(o);
    return out;
  }
  std::vector<std::uint32_t> returns() const {
    std::vector<std::uint32_t> out;
    for (std::uint32_t o = 0; o < ops(); ++o)
      if (op(o).opcode() == "RETURN" && op(o).inputs_size() >= 2) out.push_back(o);
    return out;
  }
  // What a token prints for a node: the first token, else its variable.
  std::string text(std::uint32_t n) const {
    for (const auto &line : f->lines())
      for (const auto &t : line.tokens())
        for (std::uint32_t v : t.varnode_indices())
          if (v == n) return t.text();
    if (node(n).constant()) {
      const pb::Varnode *s = storage(n);
      char buf[32];
      std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(s ? s->offset() : 0));
      return buf;
    }
    if (const pb::Variable *v = variable(n)) return v->name();
    return "";
  }
};

enum class Dir { backward, forward };

struct State {
  std::uint64_t entry;
  std::uint32_t node;
  Dir dir;
  std::vector<std::uint64_t> stack;  // call instructions entered through, innermost last
  int depth;                         // calls crossed, net (+ into callees)
  int crossed;                       // calls crossed in all
};

class Tracer {
 public:
  Tracer(const TraceHooks &hooks, const pb::TraceValueRequest &req, pb::TraceValueResponse &resp)
      : hooks_(hooks), resp_(resp) {
    max_depth_ = Budget(req.max_depth(), kDefaultDepth, kMaxDepth);
    max_functions_ = Budget(req.max_functions(), kDefaultFunctions, kMaxFunctions);
    max_nodes_ = Budget(req.max_nodes(), kDefaultNodes, kMaxNodes);
    max_edges_ = Budget(req.max_edges(), kDefaultEdges, kMaxEdges);
  }

  // The function, decompiled once; null (said once) when it can't be.
  Fn *function(std::uint64_t entry, std::optional<std::uint32_t> from_node, std::uint64_t at) {
    if (auto it = fns_.find(entry); it != fns_.end()) return it->second.f ? &it->second : nullptr;
    if (fns_.size() >= max_functions_) {
      unknown(pb::TRACE_UNKNOWN_KIND_BUDGET, from_node, at,
              "stopped at " + hooks_.name(entry) + ": " + std::to_string(max_functions_) + " functions decompiled");
      return nullptr;
    }
    std::string error;
    Fn &fn = fns_[entry];
    fn.entry = entry;
    fn.f = hooks_.decompile(entry, &error);
    if (!fn.f || fn.f->dataflow().nodes().empty()) {
      fn.f = nullptr;
      unknown(pb::TRACE_UNKNOWN_KIND_DECOMPILE_FAILED, from_node, at,
              hooks_.name(entry) + ": " + (error.empty() ? "no data-flow graph" : error));
      return nullptr;
    }
    fn.uses.assign(fn.nodes(), {});
    for (std::uint32_t o = 0; o < fn.ops(); ++o)
      for (std::uint32_t n : fn.op(o).inputs())
        if (n < fn.nodes()) fn.uses[n].push_back(o);
    fn.index = static_cast<std::uint32_t>(order_.size());
    order_.push_back(entry);
    return &fn;
  }

  // The trace node of (function, node), added on first sight.
  std::optional<std::uint32_t> id(const Fn &fn, std::uint32_t n, int depth) {
    auto key = std::pair{fn.entry, n};
    if (auto it = ids_.find(key); it != ids_.end()) return it->second;
    if (static_cast<std::uint32_t>(resp_.nodes_size()) >= max_nodes_) {
      if (!nodes_hit_) unknown(pb::TRACE_UNKNOWN_KIND_BUDGET, std::nullopt, 0, std::to_string(max_nodes_) + " values traced");
      nodes_hit_ = true;
      return std::nullopt;
    }
    const auto i = static_cast<std::uint32_t>(resp_.nodes_size());
    pb::TraceNode *t = resp_.add_nodes();
    t->set_function(fn.index);
    t->set_node(n);
    if (n < static_cast<std::uint32_t>(fn.f->varnodes_size())) t->set_varnode_index(n);
    if (const pb::Varnode *s = fn.storage(n)) *t->mutable_varnode() = *s;
    t->set_constant(fn.node(n).constant());
    t->set_text(fn.text(n));
    if (fn.node(n).has_def() && fn.node(n).def() < fn.ops()) *t->mutable_address() = fn.op(fn.node(n).def()).address();
    t->set_depth(depth);
    ids_.emplace(key, i);
    return i;
  }

  void edge(std::optional<std::uint32_t> from, std::optional<std::uint32_t> to, pb::TraceEdgeKind kind,
            const pb::Address &at, const std::string &opcode) {
    if (!from || !to || *from == *to) return;
    if (!edge_seen_.insert({*from, *to, static_cast<int>(kind)}).second) return;
    if (static_cast<std::uint32_t>(resp_.edges_size()) >= max_edges_) {
      if (!edges_hit_) unknown(pb::TRACE_UNKNOWN_KIND_BUDGET, std::nullopt, 0, std::to_string(max_edges_) + " edges");
      edges_hit_ = true;
      return;
    }
    pb::TraceEdge *e = resp_.add_edges();
    e->set_from(*from);
    e->set_to(*to);
    e->set_kind(kind);
    *e->mutable_address() = at;
    e->set_opcode(opcode);
  }

  void unknown(pb::TraceUnknownKind kind, std::optional<std::uint32_t> node, std::uint64_t at, std::string detail) {
    if (!unknown_seen_.insert({static_cast<int>(kind), node.value_or(~0u), at, detail}).second) return;
    pb::TraceUnknown *u = resp_.add_unknowns();
    u->set_kind(kind);
    if (node) u->set_node(*node);
    if (at) u->mutable_address()->set_offset(at);
    u->set_detail(std::move(detail));
    if (kind == pb::TRACE_UNKNOWN_KIND_BUDGET) resp_.set_truncated(true);
  }

  void push(State s) {
    std::string key = std::to_string(s.entry) + ":" + std::to_string(s.node) + (s.dir == Dir::forward ? "f" : "b");
    for (std::uint64_t c : s.stack) key += "," + std::to_string(c);
    if (!seen_.insert(key).second) return;
    todo_.push_back(std::move(s));
  }

  // Can the walk cross one more call?
  bool can_cross(const State &s, std::optional<std::uint32_t> node, std::uint64_t at) {
    if (static_cast<std::uint32_t>(s.crossed) < max_depth_) return true;
    unknown(pb::TRACE_UNKNOWN_KIND_BUDGET, node, at, "the call depth limit (" + std::to_string(max_depth_) + ")");
    return false;
  }

  void run() {
    while (!todo_.empty()) {
      State s = std::move(todo_.front());
      todo_.pop_front();
      Fn *fn = function(s.entry, std::nullopt, 0);
      if (!fn || s.node >= fn->nodes()) continue;
      const auto me = id(*fn, s.node, s.depth);
      if (!me) continue;
      if (s.dir == Dir::backward) backward(s, *fn, *me);
      else forward(s, *fn, *me);
    }
  }

  void backward(const State &s, Fn &fn, std::uint32_t me) {
    const pb::DataFlowNode &node = fn.node(s.node);
    if (node.constant()) return;
    if (node.has_def() && node.def() < fn.ops()) {
      const pb::DataFlowOp &op = fn.op(node.def());
      const std::uint64_t at = op.address().offset();
      if (op.opcode() == "CALL") {
        // A call's output: the callee's returned values.
        std::string what;
        auto callee = hooks_.callee(at, &what);
        if (!callee) {
          unknown(pb::TRACE_UNKNOWN_KIND_EXTERNAL_CALL, me, at, "returned by " + (what.empty() ? "a call outside the program" : what));
          return;
        }
        if (!can_cross(s, me, at)) return;
        Fn *c = function(*callee, me, at);
        if (!c) return;
        const auto rets = c->returns();
        if (rets.empty()) unknown(pb::TRACE_UNKNOWN_KIND_UNMATCHED, me, at, hooks_.name(*callee) + " returns no value the decompiler sees");
        for (std::uint32_t r : rets) {
          const std::uint32_t v = c->op(r).inputs(1);
          if (v >= c->nodes()) continue;
          State next{*callee, v, Dir::backward, s.stack, s.depth + 1, s.crossed + 1};
          next.stack.push_back(at);
          edge(id(*c, v, next.depth), me, pb::TRACE_EDGE_KIND_RETURN, op.address(), "RETURN");
          push(std::move(next));
        }
        return;
      }
      if (op.opcode() == "CALLIND") {
        unknown(pb::TRACE_UNKNOWN_KIND_INDIRECT_CALL, me, at, "returned by an indirect call");
        return;
      }
      if (op.opcode() == "LOAD")
        unknown(pb::TRACE_UNKNOWN_KIND_MEMORY, me, at, "read from memory: the stores to it aren't followed");
      for (std::uint32_t in : op.inputs()) {
        if (in >= fn.nodes()) continue;
        edge(id(fn, in, s.depth), me, pb::TRACE_EDGE_KIND_DATAFLOW, op.address(), op.opcode());
        push({s.entry, in, Dir::backward, s.stack, s.depth, s.crossed});
      }
      return;
    }
    // An input of the function: a parameter comes from the callers.
    const auto param = fn.parameter_of(s.node);
    if (!param) {
      const pb::Varnode *st = fn.storage(s.node);
      if (st && st->space() == "ram") unknown(pb::TRACE_UNKNOWN_KIND_MEMORY, me, 0, "a global: what writes it isn't followed");
      else unknown(pb::TRACE_UNKNOWN_KIND_UNMATCHED, me, 0, "an input of " + hooks_.name(s.entry) + " that is no parameter");
      return;
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> sites;
    if (!s.stack.empty()) {
      // Back out through the call this walk came in by (its caller is the
      // function the call is in).
      for (const auto &site : hooks_.callers(s.entry))
        if (site.first == s.stack.back()) sites.push_back(site);
    } else {
      sites = hooks_.callers(s.entry);
      if (sites.empty()) {
        unknown(pb::TRACE_UNKNOWN_KIND_NO_CALLERS, me, 0,
                "parameter " + std::to_string(*param + 1) + " of " + hooks_.name(s.entry) + ": no direct calls (an entry point, or called indirectly)");
        return;
      }
    }
    for (const auto &[call, caller] : sites) {
      // Back out through a matched call costs nothing; out to every caller
      // is one more call crossed.
      State next{caller, 0, Dir::backward, s.stack, s.depth - 1, s.crossed};
      if (!next.stack.empty()) next.stack.pop_back();
      else if (!can_cross(s, me, call)) return;
      else ++next.crossed;
      Fn *g = function(caller, me, call);
      if (!g) continue;
      const auto calls = g->calls_at(call);
      if (calls.empty()) unknown(pb::TRACE_UNKNOWN_KIND_UNMATCHED, me, call, "the decompiler has no call at this instruction");
      for (std::uint32_t o : calls) {
        const pb::DataFlowOp &op = g->op(o);
        if (*param >= static_cast<std::uint32_t>(op.inputs_size())) {
          unknown(pb::TRACE_UNKNOWN_KIND_UNMATCHED, me, call, "the call passes no argument " + std::to_string(*param + 1));
          continue;
        }
        const std::uint32_t arg = op.inputs(static_cast<int>(*param));
        if (arg >= g->nodes()) continue;
        next.node = arg;
        edge(id(*g, arg, next.depth), me, pb::TRACE_EDGE_KIND_ARGUMENT, op.address(), "CALL");
        push(next);
      }
    }
  }

  void forward(const State &s, Fn &fn, std::uint32_t me) {
    for (std::uint32_t o : fn.uses[s.node]) {
      const pb::DataFlowOp &op = fn.op(o);
      const std::uint64_t at = op.address().offset();
      const std::string &code = op.opcode();
      if (code == "CALL") {
        // An argument: the callee's parameter.
        for (int i = 0; i < op.inputs_size(); ++i) {
          if (op.inputs(i) != s.node) continue;
          std::string what;
          auto callee = hooks_.callee(at, &what);
          if (!callee) {
            unknown(pb::TRACE_UNKNOWN_KIND_EXTERNAL_CALL, me, at,
                    "argument " + std::to_string(i + 1) + " of " + (what.empty() ? "a call outside the program" : what));
            continue;
          }
          if (!can_cross(s, me, at)) continue;
          Fn *c = function(*callee, me, at);
          if (!c) continue;
          const auto params = c->parameter_nodes(static_cast<std::uint32_t>(i));
          if (params.empty())
            unknown(pb::TRACE_UNKNOWN_KIND_UNMATCHED, me, at,
                    hooks_.name(*callee) + " doesn't use parameter " + std::to_string(i + 1));
          for (std::uint32_t p : params) {
            State next{*callee, p, Dir::forward, s.stack, s.depth + 1, s.crossed + 1};
            next.stack.push_back(at);
            edge(me, id(*c, p, next.depth), pb::TRACE_EDGE_KIND_ARGUMENT, op.address(), "CALL");
            push(std::move(next));
          }
        }
        continue;
      }
      if (code == "CALLIND") {
        unknown(pb::TRACE_UNKNOWN_KIND_INDIRECT_CALL, me, at,
                op.inputs_size() && op.inputs(0) == s.node ? "called through (an indirect call's target)" : "passed to an indirect call");
        continue;
      }
      if (code == "RETURN") {
        if (op.inputs_size() < 2 || op.inputs(1) != s.node) continue;
        returned(s, fn, me, op);
        continue;
      }
      if (code == "STORE") {
        if (op.inputs_size() >= 3 && op.inputs(2) == s.node)
          unknown(pb::TRACE_UNKNOWN_KIND_MEMORY, me, at, "stored to memory: the loads of it aren't followed");
        continue;
      }
      if (!op.has_output() || op.output() >= fn.nodes()) continue;
      edge(me, id(fn, op.output(), s.depth), pb::TRACE_EDGE_KIND_DATAFLOW, op.address(), code);
      push({s.entry, op.output(), Dir::forward, s.stack, s.depth, s.crossed});
    }
  }

  // A returned value: the output of the call this walk came in by, or of
  // every call of the function.
  void returned(const State &s, Fn &fn, std::uint32_t me, const pb::DataFlowOp &ret) {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> sites;
    if (!s.stack.empty()) {
      for (const auto &site : hooks_.callers(s.entry))
        if (site.first == s.stack.back()) sites.push_back(site);
    } else {
      sites = hooks_.callers(s.entry);
      if (sites.empty()) {
        unknown(pb::TRACE_UNKNOWN_KIND_NO_CALLERS, me, ret.address().offset(),
                "returned by " + hooks_.name(s.entry) + ": no direct calls (an entry point, or called indirectly)");
        return;
      }
    }
    (void)fn;
    for (const auto &[call, caller] : sites) {
      State next{caller, 0, Dir::forward, s.stack, s.depth - 1, s.crossed};
      if (!next.stack.empty()) next.stack.pop_back();
      else if (!can_cross(s, me, call)) return;
      else ++next.crossed;
      Fn *g = function(caller, me, call);
      if (!g) continue;
      for (std::uint32_t o : g->calls_at(call)) {
        const pb::DataFlowOp &op = g->op(o);
        if (!op.has_output() || op.output() >= g->nodes()) {
          unknown(pb::TRACE_UNKNOWN_KIND_UNMATCHED, me, call, "the caller ignores the returned value");
          continue;
        }
        next.node = op.output();
        edge(me, id(*g, op.output(), next.depth), pb::TRACE_EDGE_KIND_RETURN, op.address(), "CALL");
        push(next);
      }
    }
  }

  // The functions reached, each with the lines and instructions involved.
  void finish() {
    std::map<std::uint32_t, std::set<std::uint32_t>> nodes_of;  // function index -> nodes
    std::map<std::uint32_t, int> depth_of;
    for (const pb::TraceNode &t : resp_.nodes()) {
      nodes_of[t.function()].insert(t.node());
      if (!depth_of.count(t.function())) depth_of[t.function()] = t.depth();
    }
    for (std::uint64_t entry : order_) {
      const Fn &fn = fns_.at(entry);
      pb::TraceFunction *out = resp_.add_functions();
      out->mutable_entry()->set_offset(entry);
      out->set_name(hooks_.name(entry));
      out->set_depth(depth_of.count(fn.index) ? depth_of[fn.index] : 0);
      const auto &in = nodes_of[fn.index];
      std::set<std::uint64_t> addresses;
      for (const pb::TraceNode &t : resp_.nodes())
        if (t.function() == fn.index && t.has_address()) addresses.insert(t.address().offset());
      for (int l = 0; l < fn.f->lines_size(); ++l) {
        const pb::CodeLine &line = fn.f->lines(l);
        pb::TraceLine *tl = nullptr;
        for (int i = 0; i < line.tokens_size(); ++i) {
          // A token printing a traced value, or the operator computing one
          // (a value no token names: `v * 3 + 1`'s sum).
          const pb::CodeToken &tok = line.tokens(i);
          bool hit = false;
          for (std::uint32_t n : tok.varnode_indices()) hit = hit || in.count(n);
          hit = hit || (start_token_ && fn.index == 0 && start_token_->line() == static_cast<std::uint32_t>(l) &&
                        start_token_->token() == static_cast<std::uint32_t>(i));
          if (!hit && tok.varnode_indices().empty() && tok.has_op_index() && tok.op_index() < fn.ops()) {
            const pb::DataFlowOp &op = fn.op(tok.op_index());
            hit = op.has_output() && in.count(op.output());
          }
          if (!hit) continue;
          if (!tl) {
            tl = out->add_lines();
            tl->set_line(static_cast<std::uint32_t>(l));
            std::string text;
            for (const auto &t : line.tokens()) text += t.text();
            tl->set_text(std::string(2 * line.indent(), ' ') + text);
          }
          tl->add_tokens(static_cast<std::uint32_t>(i));
        }
      }
      for (std::uint64_t a : addresses) out->add_addresses()->set_offset(a);
    }
  }

  std::deque<State> todo_;
  std::optional<pb::TokenPosition> start_token_;  // shown among the start function's lines

 private:
  const TraceHooks &hooks_;
  pb::TraceValueResponse &resp_;
  std::uint32_t max_depth_, max_functions_, max_nodes_, max_edges_;
  std::map<std::uint64_t, Fn> fns_;
  std::vector<std::uint64_t> order_;
  std::map<std::pair<std::uint64_t, std::uint32_t>, std::uint32_t> ids_;
  std::set<std::tuple<std::uint32_t, std::uint32_t, int>> edge_seen_;
  std::set<std::tuple<int, std::uint32_t, std::uint64_t, std::string>> unknown_seen_;
  std::set<std::string> seen_;
  bool nodes_hit_ = false, edges_hit_ = false;
};

}  // namespace

Status TraceValue(const TraceHooks &hooks, std::uint64_t entry, const pb::TraceValueRequest &req,
                  pb::TraceValueResponse &resp) {
  const bool backward = req.direction() == pb::TRACE_DIRECTION_BACKWARD;
  if (!backward && req.direction() != pb::TRACE_DIRECTION_FORWARD)
    return Error(StatusCode::kInvalidArgument, "direction: BACKWARD or FORWARD");
  Tracer t(hooks, req, resp);
  std::string error;
  Fn *fn = t.function(entry, std::nullopt, 0);
  if (!fn) {
    const std::string why = resp.unknowns_size() ? resp.unknowns(0).detail() : "no decompilation";
    return Error(StatusCode::kFailedPrecondition, "the decompiler failed on this function: " + why);
  }
  // Where it starts, as SliceDecompiled takes it.
  std::vector<std::uint32_t> start;
  std::string caption;
  const pb::DecompiledFunction &f = *fn->f;
  switch (req.from_case()) {
    case pb::TraceValueRequest::kToken: {
      const pb::TokenPosition &at = req.token();
      if (at.line() >= static_cast<std::uint32_t>(f.lines_size()) ||
          at.token() >= static_cast<std::uint32_t>(f.lines(static_cast<int>(at.line())).tokens_size()))
        return Error(StatusCode::kInvalidArgument, "no token at line " + std::to_string(at.line()) + ", token " + std::to_string(at.token()));
      const pb::CodeToken &tok = f.lines(static_cast<int>(at.line())).tokens(static_cast<int>(at.token()));
      caption = tok.text();
      for (std::uint32_t n : tok.varnode_indices())
        if (n < fn->nodes()) start.push_back(n);
      if (start.empty() && tok.has_op_index() && tok.op_index() < fn->ops()) {
        // An operator or a call's name: the value it makes (forward), the
        // values it reads (backward).
        const pb::DataFlowOp &op = fn->op(tok.op_index());
        if (backward) {
          for (std::uint32_t n : op.inputs())
            if (n < fn->nodes()) start.push_back(n);
        } else if (op.has_output() && op.output() < fn->nodes()) {
          start.push_back(op.output());
        } else if (op.opcode() == "RETURN" && op.inputs_size() >= 2 && op.inputs(1) < fn->nodes()) {
          start.push_back(op.inputs(1));  // `return`: the value returned, on to the callers
        }
      }
      break;
    }
    case pb::TraceValueRequest::kVarnodeIndex:
      if (req.varnode_index() >= fn->nodes()) return Error(StatusCode::kInvalidArgument, "no varnode " + std::to_string(req.varnode_index()));
      start.push_back(req.varnode_index());
      caption = fn->text(req.varnode_index());
      break;
    case pb::TraceValueRequest::kVariableIndex:
      if (req.variable_index() >= static_cast<std::uint32_t>(f.variables_size()))
        return Error(StatusCode::kInvalidArgument, "no variable " + std::to_string(req.variable_index()));
      caption = f.variables(static_cast<int>(req.variable_index())).name();
      for (int i = 0; i < f.varnodes_size() && static_cast<std::uint32_t>(i) < fn->nodes(); ++i)
        if (f.varnodes(i).has_variable_index() && f.varnodes(i).variable_index() == req.variable_index())
          start.push_back(static_cast<std::uint32_t>(i));
      break;
    default:
      return Error(StatusCode::kInvalidArgument, "say where the trace starts: token, varnode_index or variable_index");
  }
  if (start.empty())
    return Error(StatusCode::kInvalidArgument, "\"" + caption + "\" is no value to trace (a keyword, a type, punctuation)");
  resp.set_start(caption);
  if (req.from_case() == pb::TraceValueRequest::kToken) t.start_token_ = req.token();
  for (std::uint32_t n : start) {
    if (auto i = t.id(*fn, n, 0)) resp.add_start_nodes(*i);
    t.push({entry, n, backward ? Dir::backward : Dir::forward, {}, 0, 0});
  }
  t.run();
  t.finish();
  return Status::Ok();
}

}  // namespace revkit::backend
