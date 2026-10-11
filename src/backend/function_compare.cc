#include "function_compare.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <string>

namespace revkit::backend {

namespace {

bool IsHexOrDigits(std::string_view s) {
  if (s.starts_with("0x")) s.remove_prefix(2);
  return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); });
}

bool IsVariable(const pb::Variable &v) {
  return v.kind() == pb::VARIABLE_KIND_PARAMETER || v.kind() == pb::VARIABLE_KIND_LOCAL;
}

bool IsVariableToken(const pb::CodeToken &t, const pb::DecompiledFunction &f) {
  if (!t.has_variable_index() || t.variable_index() >= static_cast<std::uint32_t>(f.variables_size())) return false;
  if (t.kind() != pb::CODE_TOKEN_KIND_LOCAL_VARIABLE && t.kind() != pb::CODE_TOKEN_KIND_PARAMETER) return false;
  return IsVariable(f.variables(static_cast<int>(t.variable_index())));
}

// A default symbol name (FUN_00401000, DAT_..., LAB_..., s_hello_0040...)
// with its address abstracted: moved code renames them.
std::string AbstractSymbol(const std::string &text) {
  for (std::string_view p : {"FUN_", "DAT_", "LAB_", "PTR_", "thunk_FUN_", "switchD_", "caseD_", "s_", "u_"})
    if (text.starts_with(p)) return std::string(p) + "*";
  return text;
}

struct Line {
  std::string key;
  std::vector<int> vars;
  bool addressed = false;
};

std::vector<Line> Lines(const pb::DecompiledFunction &f) {
  std::vector<Line> out;
  out.reserve(static_cast<std::size_t>(f.lines_size()));
  for (const pb::CodeLine &l : f.lines()) {
    Line x;
    for (const pb::CodeToken &t : l.tokens()) {
      if (t.kind() == pb::CODE_TOKEN_KIND_WHITESPACE) continue;
      if (t.has_address()) x.addressed = true;
      if (IsVariableToken(t, f)) {
        x.key += '\x01';
        x.vars.push_back(static_cast<int>(t.variable_index()));
      } else if (t.kind() == pb::CODE_TOKEN_KIND_FUNCTION_NAME || t.kind() == pb::CODE_TOKEN_KIND_GLOBAL_VARIABLE ||
                 t.kind() == pb::CODE_TOKEN_KIND_LABEL) {
        x.key += AbstractSymbol(t.text());
      } else if (t.kind() == pb::CODE_TOKEN_KIND_COMMENT) {
        continue;
      } else {
        x.key += t.text();
      }
      x.key += '\x02';
    }
    out.push_back(std::move(x));
  }
  return out;
}

// Line pairs with equal keys, by LCS (nothing for very long functions).
std::vector<std::pair<int, int>> AlignLines(const std::vector<Line> &a, const std::vector<Line> &b) {
  std::vector<std::pair<int, int>> out;
  const std::size_t n = a.size(), m = b.size();
  if (n == 0 || m == 0 || n * m > 4'000'000) return out;
  std::vector<std::uint32_t> t((n + 1) * (m + 1), 0);
  auto at = [&](std::size_t x, std::size_t y) -> std::uint32_t & { return t[x * (m + 1) + y]; };
  for (std::size_t x = n; x-- > 0;)
    for (std::size_t y = m; y-- > 0;)
      at(x, y) = a[x].key == b[y].key ? at(x + 1, y + 1) + 1 : std::max(at(x + 1, y), at(x, y + 1));
  for (std::size_t x = 0, y = 0; x < n && y < m;) {
    if (a[x].key == b[y].key) {
      out.emplace_back(static_cast<int>(x), static_cast<int>(y));
      ++x;
      ++y;
    } else if (at(x + 1, y) >= at(x, y + 1)) {
      ++x;
    } else {
      ++y;
    }
  }
  return out;
}

}  // namespace

bool IsDefaultVariableName(std::string_view name) {
  if (name.empty()) return true;
  auto digits = [](std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); });
  };
  if (name.starts_with("param_")) return digits(name.substr(6));
  if (name.starts_with("local_")) {
    std::string_view rest = name.substr(6);
    if (rest.starts_with("res")) rest.remove_prefix(3);
    return IsHexOrDigits(rest);
  }
  if (name.starts_with("stack0x")) return IsHexOrDigits(name.substr(7));
  // in_RAX, in_stack_00000010, unaff_RBX, extraout_EAX: registers and stack slots.
  for (std::string_view p : {"in_", "unaff_", "extraout_"})
    if (name.starts_with(p)) {
      std::string_view rest = name.substr(p.size());
      return rest.starts_with("stack_") || (!rest.empty() && std::isupper(static_cast<unsigned char>(rest[0])));
    }
  // uVar1, pcVar12, auVar3, VVar1 (a Value), pNVar4 (a Node *); uStack_14,
  // auStack_38, iStack20: a prefix the decompiler makes from the type.
  std::size_t i = 0;
  while (i < name.size() && std::isalpha(static_cast<unsigned char>(name[i])) && name.substr(i).find("Var") != 0 &&
         name.substr(i).find("Stack") != 0)
    ++i;
  if (i == 0 || i > 6) return false;
  std::string_view rest = name.substr(i);
  if (rest.starts_with("Var")) {
    rest.remove_prefix(3);
    return !rest.empty() && std::all_of(rest.begin(), rest.end(), [](unsigned char c) { return std::isdigit(c); });
  }
  if (rest.starts_with("Stack")) {
    rest.remove_prefix(5);
    if (rest.starts_with("_")) rest.remove_prefix(1);
    return IsHexOrDigits(rest);
  }
  return false;
}

std::vector<VariablePairing> PairVariables(const pb::DecompiledFunction &a, const pb::DecompiledFunction &b,
                                           const std::unordered_map<std::uint64_t, std::uint64_t> &partner) {
  const int na = a.variables_size(), nb = b.variables_size();
  std::vector<int> b_of(static_cast<std::size_t>(na), -1), a_of(static_cast<std::size_t>(nb), -1);
  std::vector<bool> param(static_cast<std::size_t>(na), false);
  // Parameters by position.
  std::map<std::uint32_t, int> params_b;
  for (int j = 0; j < nb; ++j)
    if (b.variables(j).kind() == pb::VARIABLE_KIND_PARAMETER && b.variables(j).has_parameter_index())
      params_b.emplace(b.variables(j).parameter_index(), j);
  for (int i = 0; i < na; ++i) {
    const pb::Variable &v = a.variables(i);
    if (v.kind() != pb::VARIABLE_KIND_PARAMETER || !v.has_parameter_index()) continue;
    auto it = params_b.find(v.parameter_index());
    if (it == params_b.end() || a_of[static_cast<std::size_t>(it->second)] >= 0) continue;
    b_of[static_cast<std::size_t>(i)] = it->second;
    a_of[static_cast<std::size_t>(it->second)] = i;
    param[static_cast<std::size_t>(i)] = true;
  }

  // Votes: (instructions, lines) per (a, b).
  std::map<std::pair<int, int>, std::pair<std::uint32_t, std::uint32_t>> votes;
  auto vote = [&](const std::vector<int> &va, const std::vector<int> &vb, bool line) {
    if (va.empty() || va.size() != vb.size()) return;
    for (std::size_t k = 0; k < va.size(); ++k) {
      const pb::Variable &x = a.variables(va[k]), &y = b.variables(vb[k]);
      // Locals with locals, parameters with parameters (already paired).
      if ((x.kind() == pb::VARIABLE_KIND_PARAMETER) != (y.kind() == pb::VARIABLE_KIND_PARAMETER)) continue;
      auto &v = votes[{va[k], vb[k]}];
      (line ? v.second : v.first) += 1;
    }
  };
  // By instruction: the variables each instruction's tokens print.
  auto printed = [](const pb::DecompiledFunction &f) {
    std::map<std::uint64_t, std::vector<int>> out;
    for (const pb::CodeLine &l : f.lines())
      for (const pb::CodeToken &t : l.tokens())
        if (t.has_address() && IsVariableToken(t, f)) out[t.address().offset()].push_back(static_cast<int>(t.variable_index()));
    return out;
  };
  const auto pa = printed(a), pb_ = printed(b);
  for (const auto &[x, vars] : pa) {
    auto p = partner.find(x);
    if (p == partner.end()) continue;
    auto y = pb_.find(p->second);
    if (y != pb_.end()) vote(vars, y->second, false);
  }
  // By C line.
  const auto la = Lines(a), lb = Lines(b);
  for (const auto &[x, y] : AlignLines(la, lb))
    if (la[static_cast<std::size_t>(x)].addressed && lb[static_cast<std::size_t>(y)].addressed)
      vote(la[static_cast<std::size_t>(x)].vars, lb[static_cast<std::size_t>(y)].vars, true);

  // Mutual strict best, repeatedly over what is left.
  auto score = [](const std::pair<std::uint32_t, std::uint32_t> &v) { return v.first + v.second; };
  for (bool changed = true; changed;) {
    changed = false;
    std::map<int, std::pair<std::uint32_t, int>> best_a, best_b;  // score, partner (-1: a tie)
    for (const auto &[k, v] : votes) {
      const auto [i, j] = k;
      if (b_of[static_cast<std::size_t>(i)] >= 0 || a_of[static_cast<std::size_t>(j)] >= 0) continue;
      const std::uint32_t s = score(v);
      for (auto [best, me, other] : {std::tuple{&best_a, i, j}, std::tuple{&best_b, j, i}}) {
        auto it = best->find(me);
        if (it == best->end() || s > it->second.first) (*best)[me] = {s, other};
        else if (s == it->second.first) it->second.second = -1;
      }
    }
    for (const auto &[i, bj] : best_a) {
      const int j = bj.second;
      if (j < 0) continue;
      auto it = best_b.find(j);
      if (it == best_b.end() || it->second.second != i) continue;
      if (b_of[static_cast<std::size_t>(i)] >= 0 || a_of[static_cast<std::size_t>(j)] >= 0) continue;
      b_of[static_cast<std::size_t>(i)] = j;
      a_of[static_cast<std::size_t>(j)] = i;
      changed = true;
    }
  }

  std::vector<VariablePairing> out;
  for (int i = 0; i < na; ++i) {
    if (!IsVariable(a.variables(i))) continue;
    VariablePairing p;
    p.a = i;
    p.b = b_of[static_cast<std::size_t>(i)];
    p.parameter = param[static_cast<std::size_t>(i)];
    if (p.b >= 0)
      if (auto it = votes.find({i, p.b}); it != votes.end()) std::tie(p.instructions, p.lines) = it->second;
    out.push_back(p);
  }
  for (int j = 0; j < nb; ++j)
    if (IsVariable(b.variables(j)) && a_of[static_cast<std::size_t>(j)] < 0) out.push_back({-1, j, 0, 0, false});
  return out;
}

}  // namespace revkit::backend
