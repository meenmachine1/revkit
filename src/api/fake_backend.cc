#include "revkit/api/fake_backend.h"

#include "fake_program.h"

#include <google/protobuf/util/time_util.h>
#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <sstream>

namespace revkit::api {
namespace {

using namespace fake_internal;
using google::protobuf::util::TimeUtil;

constexpr std::uint32_t kApiMinor = 12;
// The demo program's import time is fixed so its responses are deterministic.
constexpr std::int64_t kDemoImportTime = 1767225600;  // 2026-01-01T00:00:00Z

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

std::string Hex(std::uint64_t v, int width = 0) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%0*llx", width, static_cast<unsigned long long>(v));
  return buf;
}

pb::Address A(std::uint64_t offset) {
  pb::Address a;
  a.set_offset(offset);
  return a;
}

pb::AddressRange Range(std::uint64_t first, std::uint64_t last) {
  pb::AddressRange r;
  *r.mutable_first() = A(first);
  *r.mutable_last() = A(last);
  return r;
}

void SetVarnode(const VN &vn, pb::Varnode *out) {
  out->set_space(vn.space);
  out->set_offset(vn.offset);
  out->set_size(vn.size);
  out->set_register_name(vn.reg);
}

bool IsDefaultSpace(const pb::Address &a) { return a.space().empty() || a.space() == "ram"; }

int Rank(pb::ProvenanceKind kind) {
  switch (kind) {
    case pb::PROVENANCE_KIND_USER: return 4;
    case pb::PROVENANCE_KIND_IMPORT:
    case pb::PROVENANCE_KIND_MIGRATION: return 3;
    case pb::PROVENANCE_KIND_AGENT:
    case pb::PROVENANCE_KIND_PLUGIN:
    case pb::PROVENANCE_KIND_SCRIPT: return 2;
    case pb::PROVENANCE_KIND_ANALYSIS: return 1;
    default: return 0;
  }
}

const char *CommentSub(pb::CommentKind kind) {
  switch (kind) {
    case pb::COMMENT_KIND_EOL: return "eol";
    case pb::COMMENT_KIND_PRE: return "pre";
    case pb::COMMENT_KIND_POST: return "post";
    case pb::COMMENT_KIND_PLATE: return "plate";
    case pb::COMMENT_KIND_REPEATABLE: return "repeatable";
    case pb::COMMENT_KIND_DECOMPILER: return "decompiler";
    default: return "";
  }
}

std::string KeyString(const pb::FactKey &k) {
  return k.program_id() + "|" + std::to_string(k.kind()) + "|" + k.address().space() + "|" +
         Hex(k.address().offset()) + "|" + k.sub();
}

std::string Sha256Hex(const std::string &bytes) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(bytes.data(), bytes.size(), md, &len, EVP_sha256(), nullptr);
  std::string out;
  for (unsigned i = 0; i < len; ++i) out += Hex(md[i], 2);
  return out;
}

std::string Lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

pb::FactOrigin Derived(const std::string &rule, std::uint64_t revision, float confidence = 1.0f) {
  pb::FactOrigin o;
  o.mutable_derived()->set_rule(rule);
  o.mutable_derived()->set_confidence(confidence);
  o.mutable_derived()->set_computed_at_revision(revision);
  return o;
}

pb::FactOrigin Asserted(const pb::Assertion &a) {
  pb::FactOrigin o;
  o.mutable_asserted()->set_seq(a.seq());
  *o.mutable_asserted()->mutable_provenance() = a.provenance();
  return o;
}

// Opaque page tokens: "<revision>:<offset>". They pin the revision so that
// later pages come from the same snapshot.
std::string PageToken(std::uint64_t revision, std::size_t offset) {
  return std::to_string(revision) + ":" + std::to_string(offset);
}

bool ParsePageToken(const std::string &token, std::uint64_t &revision, std::size_t &offset) {
  auto colon = token.find(':');
  if (colon == std::string::npos) return false;
  try {
    revision = std::stoull(token.substr(0, colon));
    offset = std::stoull(token.substr(colon + 1));
  } catch (...) {
    return false;
  }
  return true;
}

// Applies a page request to `count` items; sets [begin, end) and the page info.
template <class Fn>
void Paginate(std::size_t count, std::size_t offset, std::uint32_t page_size, std::uint32_t def,
              std::uint32_t max, std::uint64_t revision, pb::PageInfo *info, Fn &&emit) {
  std::size_t size = page_size == 0 ? def : std::min(page_size, max);
  std::size_t end = std::min(count, offset + size);
  for (std::size_t i = offset; i < end; ++i) emit(i);
  info->set_total_count(static_cast<std::int64_t>(count));
  if (end < count) info->set_next_page_token(PageToken(revision, end));
}

// ---------------------------------------------------------------------------
// Project state: one immutable value per revision
// ---------------------------------------------------------------------------

struct ProgramMeta {
  std::string id;
  std::string name;
  std::string sha256;
  std::uint64_t file_size = 0;
  std::int64_t imported_at = 0;  // unix seconds
};

struct ProjectState {
  std::uint64_t revision = 0;
  std::string id, name, path;
  std::vector<ProgramMeta> programs;
  // The whole log with statuses as of `revision`. Copying it per commit is
  // fine for synthetic data; the real store shares structure.
  std::vector<pb::Assertion> log;
  std::map<std::string, std::size_t> winners;  // key string -> log index

  const ProgramMeta *program(const std::string &id) const {
    for (const auto &p : programs)
      if (p.id == id) return &p;
    return nullptr;
  }
};

// Recomputes liveness, statuses and winners after the log changed. Mirrors
// the fact store's rules (see revkit/facts/assertion_log.h):
//   retracted(x)   = some live retraction targets x
//   live(retract)  = !retracted
//   live(assert a) = !retracted(a) && (no dependency || live(dependency))
void Recompute(ProjectState &s) {
  const std::size_t n = s.log.size();
  std::vector<std::vector<std::size_t>> retractions_of(n);
  for (std::size_t i = 0; i < n; ++i)
    if (s.log[i].op() == pb::ASSERTION_OP_RETRACT) retractions_of[s.log[i].retracts_seq() - 1].push_back(i);

  std::vector<char> retracted(n, 0), live(n, 0);
  // Retractions only target earlier entries, so a descending pass sees every
  // retraction's liveness before the entries it targets.
  for (std::size_t i = n; i-- > 0;) {
    for (std::size_t r : retractions_of[i]) retracted[i] |= live[r];
    if (s.log[i].op() == pb::ASSERTION_OP_RETRACT) live[i] = !retracted[i];
  }
  // Dependencies point backwards, so an ascending pass resolves them.
  for (std::size_t i = 0; i < n; ++i) {
    const auto &a = s.log[i];
    if (a.op() != pb::ASSERTION_OP_ASSERT) continue;
    std::uint64_t dep = a.depends_on_seq();
    live[i] = !retracted[i] && (dep == 0 || live[dep - 1]);
  }

  s.winners.clear();
  for (std::size_t i = 0; i < n; ++i) {
    const auto &a = s.log[i];
    if (a.op() != pb::ASSERTION_OP_ASSERT || !live[i]) continue;
    auto [it, inserted] = s.winners.try_emplace(KeyString(a.key()), i);
    if (!inserted) {
      const auto &cur = s.log[it->second];
      // Higher provenance rank wins; among equals, the later assertion.
      if (Rank(a.provenance().kind()) >= Rank(cur.provenance().kind())) it->second = i;
    }
  }

  for (std::size_t i = 0; i < n; ++i) {
    auto &a = s.log[i];
    a.clear_retracted_by();
    for (std::size_t r : retractions_of[i])
      if (live[r]) a.add_retracted_by(s.log[r].seq());
    if (a.op() == pb::ASSERTION_OP_RETRACT) {
      a.set_status(live[i] ? pb::ASSERTION_STATUS_EFFECTIVE : pb::ASSERTION_STATUS_RETRACTED);
    } else if (retracted[i]) {
      a.set_status(pb::ASSERTION_STATUS_RETRACTED);
    } else if (!live[i]) {
      a.set_status(pb::ASSERTION_STATUS_DEPENDENCY_DEAD);
    } else {
      auto it = s.winners.find(KeyString(a.key()));
      a.set_status(it != s.winners.end() && it->second == i ? pb::ASSERTION_STATUS_EFFECTIVE
                                                             : pb::ASSERTION_STATUS_SHADOWED);
    }
  }
}

// ---------------------------------------------------------------------------
// View: effective facts of one program at one revision
// ---------------------------------------------------------------------------

struct Func {
  std::uint64_t entry;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> body;  // inclusive ranges
  const pb::Assertion *bounds = nullptr;                       // winning assertion, if any

  bool contains(std::uint64_t a) const {
    return std::any_of(body.begin(), body.end(), [&](auto &r) { return a >= r.first && a <= r.second; });
  }
};

class View {
 public:
  View(const ProjectState &s, const ProgramMeta &p) : s_(s), p_(p), prog_(SyntheticProgram::Get()) {
    for (const auto &f : prog_.functions) funcs_[f.entry] = Func{f.entry, {{f.entry, f.last}}};
    for (const auto &[key, idx] : s_.winners) {
      const auto &a = s_.log[idx];
      if (a.key().program_id() != p_.id || a.key().kind() != pb::FACT_KIND_FUNCTION_BOUNDS) continue;
      const auto &b = a.body().function_bounds();
      std::uint64_t entry = b.entry().offset();
      if (b.remove()) {
        funcs_.erase(entry);
        continue;
      }
      Func f{entry, {}, &a};
      for (const auto &r : b.body()) f.body.emplace_back(r.first().offset(), r.last().offset());
      if (f.body.empty()) f.body.emplace_back(entry, prog_.run_end(entry));
      funcs_[entry] = std::move(f);
    }
  }

  const SyntheticProgram &prog() const { return prog_; }
  const ProjectState &state() const { return s_; }
  const ProgramMeta &program() const { return p_; }
  std::uint64_t revision() const { return s_.revision; }

  const pb::Assertion *Winner(pb::FactKind kind, std::uint64_t addr, const std::string &sub = {}) const {
    pb::FactKey k;
    k.set_program_id(p_.id);
    k.set_kind(kind);
    k.mutable_address()->set_offset(addr);
    k.set_sub(sub);
    auto it = s_.winners.find(KeyString(k));
    return it == s_.winners.end() ? nullptr : &s_.log[it->second];
  }

  const std::map<std::uint64_t, Func> &functions() const { return funcs_; }
  const Func *FunctionAt(std::uint64_t entry) const {
    auto it = funcs_.find(entry);
    return it == funcs_.end() ? nullptr : &it->second;
  }
  const Func *FunctionContaining(std::uint64_t a) const {
    for (const auto &[e, f] : funcs_)
      if (f.contains(a)) return &f;
    return nullptr;
  }

  std::string DefaultName(std::uint64_t addr) const {
    if (auto *f = prog_.default_function_at(addr)) return f->default_name;
    if (funcs_.count(addr)) return "FUN_" + Hex(addr, 8);
    if (auto *d = prog_.data_at(addr)) return d->default_name;
    if (auto it = prog_.jump_labels.find(addr); it != prog_.jump_labels.end()) return it->second;
    return {};
  }

  // Effective symbol name at addr, or empty when there is none.
  std::string Symbol(std::uint64_t addr) const {
    if (auto *w = Winner(pb::FACT_KIND_NAME, addr); w && !w->body().rename().name().empty())
      return w->body().rename().name();
    return DefaultName(addr);
  }

  pb::FactOrigin NameOrigin(std::uint64_t addr) const {
    if (auto *w = Winner(pb::FACT_KIND_NAME, addr); w && !w->body().rename().name().empty()) return Asserted(*w);
    return Derived(prog_.data_at(addr) ? "data.default_name" : "functions.default_name", revision());
  }

  std::string DisplayOrAddress(std::uint64_t addr) const {
    std::string s = Symbol(addr);
    return s.empty() ? "0x" + Hex(addr) : s;
  }

  // Type display for a TYPE assertion's body.
  std::string TypeDisplay(const pb::Assertion &a) const {
    const auto &t = a.body().retype().type();
    if (t.has_c_declaration()) return t.c_declaration();
    if (auto *def = prog_.type_by_hash(t.type_hash())) return def->display();
    return "undefined";
  }

  std::string VarName(std::uint64_t entry, const VarDef &v) const {
    if (v.kind == pb::VARIABLE_KIND_GLOBAL) return Symbol(v.address);
    if (auto *w = Winner(pb::FACT_KIND_NAME, entry, "local:" + v.storage_key);
        w && !w->body().rename().name().empty())
      return w->body().rename().name();
    return v.default_name;
  }
  pb::FactOrigin VarNameOrigin(std::uint64_t entry, const VarDef &v) const {
    if (v.kind == pb::VARIABLE_KIND_GLOBAL) return NameOrigin(v.address);
    if (auto *w = Winner(pb::FACT_KIND_NAME, entry, "local:" + v.storage_key);
        w && !w->body().rename().name().empty())
      return Asserted(*w);
    return Derived("decompiler.ghidra.naming", revision(), 0.5f);
  }
  const pb::Assertion *VarTypeWinner(std::uint64_t entry, const VarDef &v) const {
    return v.kind == pb::VARIABLE_KIND_GLOBAL ? Winner(pb::FACT_KIND_TYPE, v.address)
                                              : Winner(pb::FACT_KIND_TYPE, entry, "local:" + v.storage_key);
  }
  std::string VarType(std::uint64_t entry, const VarDef &v) const {
    if (auto *w = VarTypeWinner(entry, v)) return TypeDisplay(*w);
    return v.default_type;
  }

  std::string DataType(const DataDef &d) const {
    if (auto *w = Winner(pb::FACT_KIND_TYPE, d.addr)) return TypeDisplay(*w);
    return d.type;
  }

  std::vector<pb::CommentView> Comments(std::uint64_t addr) const {
    std::vector<pb::CommentView> out;
    for (int k = pb::COMMENT_KIND_EOL; k <= pb::COMMENT_KIND_DECOMPILER; ++k) {
      auto kind = static_cast<pb::CommentKind>(k);
      if (auto *w = Winner(pb::FACT_KIND_COMMENT, addr, CommentSub(kind)); w && !w->body().comment().text().empty()) {
        pb::CommentView c;
        c.set_kind(kind);
        c.set_text(w->body().comment().text());
        *c.mutable_origin() = Asserted(*w);
        out.push_back(std::move(c));
      }
    }
    return out;
  }

  // Prototype C text: an asserted TYPE at the entry wins, else generated.
  std::string Prototype(const Func &f) const {
    if (auto *w = Winner(pb::FACT_KIND_TYPE, f.entry)) return TypeDisplay(*w);
    auto it = prog_.decomps.find(f.entry);
    if (it == prog_.decomps.end()) return "void " + Symbol(f.entry) + "(void)";
    const DecompDef &d = it->second;
    std::string s = d.return_type + " " + Symbol(f.entry) + "(";
    bool any = false;
    for (const auto &v : d.vars) {
      if (v.kind != pb::VARIABLE_KIND_PARAMETER) continue;
      if (any) s += ",";
      std::string t = VarType(f.entry, v);
      s += t + (t.ends_with("*") ? "" : " ") + VarName(f.entry, v);
      any = true;
    }
    return s + (any ? ")" : "void)");
  }

  void FillFunction(const Func &f, pb::Function *out) const {
    *out->mutable_entry() = A(f.entry);
    out->set_name(Symbol(f.entry));
    *out->mutable_name_origin() = NameOrigin(f.entry);
    for (auto [first, last] : f.body) *out->add_body() = Range(first, last);
    *out->mutable_bounds_origin() = f.bounds ? Asserted(*f.bounds) : Derived("functions.flow", revision());
    out->set_prototype(Prototype(f));
    if (auto *w = Winner(pb::FACT_KIND_TYPE, f.entry))
      *out->mutable_prototype_origin() = Asserted(*w);
    else
      *out->mutable_prototype_origin() = Derived("decompiler.ghidra.prototype", revision(), 0.7f);
    out->set_calling_convention("__stdcall");
    out->set_no_return(f.entry == 0x401000);
    std::uint32_t count = 0;
    for (const auto &i : prog_.insns) count += f.contains(i.addr);
    out->set_instruction_count(count);
    std::uint32_t callers = 0;
    for (const auto &x : prog_.xrefs) callers += x.to == f.entry && x.kind == pb::XREF_KIND_CALL;
    out->set_caller_count(callers);
  }

  void Tokens(const InsnDef &i, google::protobuf::RepeatedPtrField<pb::ListingToken> *out) const;
  void FillRow(const RowDef &r, std::size_t index, bool omit_bytes, pb::ListingRow *out) const;
  void FillDecompiled(const Func &f, bool include_text, pb::DecompiledFunction *out) const;

 private:
  const ProjectState &s_;
  const ProgramMeta &p_;
  const SyntheticProgram &prog_;
  std::map<std::uint64_t, Func> funcs_;
};

void AddToken(google::protobuf::RepeatedPtrField<pb::ListingToken> *out, pb::ListingTokenKind kind,
              std::string text, std::optional<std::uint32_t> operand = std::nullopt) {
  auto *t = out->Add();
  t->set_kind(kind);
  t->set_text(std::move(text));
  if (operand) t->set_operand_index(*operand);
}

// Splits operand text into display tokens: registers, scalars, separators,
// and "{}" for the symbol at the operand's target.
void TokenizeOperand(const View &v, const OperandDef &op, std::uint32_t index,
                     google::protobuf::RepeatedPtrField<pb::ListingToken> *out) {
  const std::string &s = op.text;
  for (std::size_t i = 0; i < s.size();) {
    char c = s[i];
    if (s.compare(i, 2, "{}") == 0) {
      AddToken(out, op.target && !v.Symbol(*op.target).empty() ? pb::LISTING_TOKEN_KIND_SYMBOL
                                                                : pb::LISTING_TOKEN_KIND_ADDRESS,
               v.DisplayOrAddress(*op.target), index);
      *out->rbegin()->mutable_target() = A(*op.target);
      i += 2;
    } else if (c == ' ') {
      AddToken(out, pb::LISTING_TOKEN_KIND_WHITESPACE, " ", index);
      ++i;
    } else if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
      std::size_t j = i;
      while (j < s.size() && (std::isalnum(static_cast<unsigned char>(s[j])) || s[j] == '_')) ++j;
      std::string word = s.substr(i, j - i);
      if (auto reg = RegisterVarnode(word)) {
        AddToken(out, pb::LISTING_TOKEN_KIND_REGISTER, word, index);
        SetVarnode(*reg, out->rbegin()->mutable_register_varnode());
      } else if (std::isdigit(static_cast<unsigned char>(word[0]))) {
        AddToken(out, pb::LISTING_TOKEN_KIND_SCALAR, word, index);
        out->rbegin()->set_value(static_cast<std::int64_t>(std::stoull(word, nullptr, 0)));
      } else {
        AddToken(out, pb::LISTING_TOKEN_KIND_SEPARATOR, word, index);  // "dword", "ptr"
      }
      i = j;
    } else {
      AddToken(out, pb::LISTING_TOKEN_KIND_SEPARATOR, std::string(1, c), index);
      ++i;
    }
  }
}

void View::Tokens(const InsnDef &i, google::protobuf::RepeatedPtrField<pb::ListingToken> *out) const {
  AddToken(out, pb::LISTING_TOKEN_KIND_MNEMONIC, i.mnemonic);
  for (std::size_t k = 0; k < i.operands.size(); ++k) {
    AddToken(out, k == 0 ? pb::LISTING_TOKEN_KIND_WHITESPACE : pb::LISTING_TOKEN_KIND_SEPARATOR, k == 0 ? " " : ",");
    TokenizeOperand(*this, i.operands[k], static_cast<std::uint32_t>(k), out);
  }
}

void View::FillRow(const RowDef &r, std::size_t index, bool omit_bytes, pb::ListingRow *out) const {
  out->set_row(static_cast<std::int64_t>(index));
  *out->mutable_address() = A(r.addr);
  out->set_length(r.length);
  out->set_kind(r.kind);
  out->set_block(r.block);
  if (!omit_bytes) {
    std::string bytes;
    for (std::uint64_t a = r.addr; a < r.addr + r.length; ++a)
      if (auto b = prog_.byte_at(a)) bytes.push_back(static_cast<char>(*b));
    out->set_bytes(std::move(bytes));
  }
  if (std::string name = Symbol(r.addr); !name.empty()) {
    auto *l = out->add_labels();
    l->set_name(name);
    l->set_primary(true);
    *l->mutable_origin() = NameOrigin(r.addr);
  }
  if (const Func *f = FunctionContaining(r.addr)) {
    *out->mutable_function() = A(f->entry);
    out->set_function_entry(f->entry == r.addr);
  }
  if (r.insn >= 0) {
    Tokens(prog_.insns[r.insn], out->mutable_tokens());
  } else if (r.data >= 0) {
    const DataDef &d = prog_.data[r.data];
    std::string type = DataType(d);
    AddToken(out->mutable_tokens(), pb::LISTING_TOKEN_KIND_TYPE, type);
    AddToken(out->mutable_tokens(), pb::LISTING_TOKEN_KIND_WHITESPACE, " ");
    AddToken(out->mutable_tokens(), pb::LISTING_TOKEN_KIND_DATA_VALUE, d.value_text);
    out->set_data_type(type);
    out->set_data_type_hash(prog_.hash_for_display(type));
  } else {
    AddToken(out->mutable_tokens(), pb::LISTING_TOKEN_KIND_TYPE, r.length == 1 ? "undefined" : "undefined[" + std::to_string(r.length) + "]");
  }
  for (auto &c : Comments(r.addr)) *out->add_comments() = std::move(c);
  out->set_xref_to_count(prog_.xrefs_to_count(r.addr));
}

void View::FillDecompiled(const Func &f, bool include_text, pb::DecompiledFunction *out) const {
  *out->mutable_entry() = A(f.entry);
  out->set_name(Symbol(f.entry));
  auto *origin = out->mutable_origin();
  origin->set_rule("decompiler.ghidra");
  origin->set_confidence(0.9f);
  origin->set_computed_at_revision(revision());

  auto it = prog_.decomps.find(f.entry);
  static const DecompDef kEmpty{0, "void", {}, {}, {}};
  const DecompDef &d = it == prog_.decomps.end() ? kEmpty : it->second;
  if (it == prog_.decomps.end()) out->add_warnings("fake backend: no decompiler template for this function");

  // Inputs of the derivation: every assertion the output depends on.
  auto note_input = [&](const pb::Assertion *w) {
    if (w) *origin->add_inputs() = w->key();
  };
  note_input(Winner(pb::FACT_KIND_NAME, f.entry));
  note_input(Winner(pb::FACT_KIND_TYPE, f.entry));
  note_input(f.bounds);

  for (std::size_t i = 0; i < d.vars.size(); ++i) {
    const VarDef &v = d.vars[i];
    auto *var = out->add_variables();
    var->set_index(static_cast<std::uint32_t>(i));
    var->set_kind(v.kind);
    var->set_name(VarName(f.entry, v));
    *var->mutable_name_origin() = VarNameOrigin(f.entry, v);
    std::string type = VarType(f.entry, v);
    var->mutable_type()->set_display(type);
    var->mutable_type()->set_hash(prog_.hash_for_display(type));
    if (auto *w = VarTypeWinner(f.entry, v)) {
      *var->mutable_type_origin() = Asserted(*w);
      note_input(w);
    } else {
      *var->mutable_type_origin() = Derived("decompiler.ghidra.types", revision(), 0.6f);
    }
    if (v.kind != pb::VARIABLE_KIND_GLOBAL)
      note_input(Winner(pb::FACT_KIND_NAME, f.entry, "local:" + v.storage_key));
    var->set_storage_key(v.storage_key);
    for (const auto &s : v.storage) SetVarnode(s, var->add_storage());
    if (v.kind == pb::VARIABLE_KIND_GLOBAL) *var->mutable_address() = A(v.address);
  }
  for (const auto &m : d.varnodes) {
    auto *vn = out->add_varnodes();
    SetVarnode(m.vn, vn->mutable_varnode());
    if (m.var >= 0) vn->set_variable_index(static_cast<std::uint32_t>(m.var));
    if (m.defined_at) *vn->mutable_defined_at() = A(m.defined_at);
  }

  // Prototype.
  auto *proto = out->mutable_prototype();
  proto->set_c_declaration(Prototype(f));
  proto->mutable_return_type()->set_display(d.return_type);
  proto->mutable_return_type()->set_hash(prog_.hash_for_display(d.return_type));
  for (std::size_t i = 0; i < d.vars.size(); ++i)
    if (d.vars[i].kind == pb::VARIABLE_KIND_PARAMETER) proto->add_parameter_indices(static_cast<std::uint32_t>(i));
  proto->set_calling_convention("__stdcall");
  proto->set_no_return(f.entry == 0x401000);
  if (auto *w = Winner(pb::FACT_KIND_TYPE, f.entry))
    *proto->mutable_origin() = Asserted(*w);
  else
    *proto->mutable_origin() = Derived("decompiler.ghidra.prototype", revision(), 0.7f);

  // Lines. Comments (plate at the entry; pre/decompiler at a statement's
  // address) are emitted as comment lines above the code they annotate.
  std::set<std::uint64_t> commented;
  auto comment_lines = [&](std::uint64_t addr, std::uint32_t indent, bool plate) {
    if (!commented.insert(addr * 2 + plate).second) return;
    for (const auto &c : Comments(addr)) {
      bool is_plate = c.kind() == pb::COMMENT_KIND_PLATE;
      if (is_plate != plate) continue;
      if (!plate && c.kind() != pb::COMMENT_KIND_PRE && c.kind() != pb::COMMENT_KIND_DECOMPILER) continue;
      auto *line = out->add_lines();
      line->set_indent(indent);
      *line->mutable_address() = A(addr);
      auto *t = line->add_tokens();
      t->set_kind(pb::CODE_TOKEN_KIND_COMMENT);
      t->set_text("/* " + c.text() + " */");
      *t->mutable_address() = A(addr);
    }
  };
  auto add_tok = [&](pb::CodeLine *line, pb::CodeTokenKind kind, std::string text) {
    auto *t = line->add_tokens();
    t->set_kind(kind);
    t->set_text(std::move(text));
    return t;
  };

  comment_lines(f.entry, 0, true);
  {
    auto *line = out->add_lines();
    add_tok(line, pb::CODE_TOKEN_KIND_TYPE, d.return_type)->set_type_hash(prog_.hash_for_display(d.return_type));
    add_tok(line, pb::CODE_TOKEN_KIND_WHITESPACE, " ");
    auto *name = add_tok(line, pb::CODE_TOKEN_KIND_FUNCTION_NAME, Symbol(f.entry));
    *name->mutable_target() = A(f.entry);
    *name->mutable_address() = A(f.entry);
    add_tok(line, pb::CODE_TOKEN_KIND_PUNCTUATION, "(");
    bool any = false;
    for (std::size_t i = 0; i < d.vars.size(); ++i) {
      const VarDef &v = d.vars[i];
      if (v.kind != pb::VARIABLE_KIND_PARAMETER) continue;
      if (any) add_tok(line, pb::CODE_TOKEN_KIND_PUNCTUATION, ",");
      std::string type = VarType(f.entry, v);
      add_tok(line, pb::CODE_TOKEN_KIND_TYPE, type)->set_type_hash(prog_.hash_for_display(type));
      if (!type.ends_with("*")) add_tok(line, pb::CODE_TOKEN_KIND_WHITESPACE, " ");
      auto *p = add_tok(line, pb::CODE_TOKEN_KIND_PARAMETER, VarName(f.entry, v));
      p->set_variable_index(static_cast<std::uint32_t>(i));
      for (std::size_t k = 0; k < d.varnodes.size(); ++k)
        if (d.varnodes[k].var == static_cast<int>(i) && d.varnodes[k].defined_at == 0)
          p->add_varnode_indices(static_cast<std::uint32_t>(k));
      any = true;
    }
    if (!any) add_tok(line, pb::CODE_TOKEN_KIND_KEYWORD, "void");
    add_tok(line, pb::CODE_TOKEN_KIND_PUNCTUATION, ")");
    *line->mutable_address() = A(f.entry);
  }
  add_tok(out->add_lines(), pb::CODE_TOKEN_KIND_PUNCTUATION, "{");
  bool any_local = false;
  for (std::size_t i = 0; i < d.vars.size(); ++i) {
    const VarDef &v = d.vars[i];
    if (v.kind != pb::VARIABLE_KIND_LOCAL) continue;
    auto *line = out->add_lines();
    line->set_indent(1);
    std::string type = VarType(f.entry, v);
    add_tok(line, pb::CODE_TOKEN_KIND_TYPE, type)->set_type_hash(prog_.hash_for_display(type));
    if (!type.ends_with("*")) add_tok(line, pb::CODE_TOKEN_KIND_WHITESPACE, " ");
    add_tok(line, pb::CODE_TOKEN_KIND_LOCAL_VARIABLE, VarName(f.entry, v))
        ->set_variable_index(static_cast<std::uint32_t>(i));
    add_tok(line, pb::CODE_TOKEN_KIND_PUNCTUATION, ";");
    any_local = true;
  }
  if (any_local) out->add_lines();  // blank line after declarations
  if (it == prog_.decomps.end()) {
    auto *line = out->add_lines();
    line->set_indent(1);
    add_tok(line, pb::CODE_TOKEN_KIND_COMMENT, "/* no decompilation available */");
  }
  for (const LineDef &ld : d.body) {
    std::set<std::uint64_t> addrs;
    for (const auto &t : ld.toks)
      if (t.addr) addrs.insert(t.addr);
    std::uint64_t line_addr = addrs.empty() ? 0 : *addrs.begin();
    // A comment on any instruction this statement came from goes above it.
    for (auto a : addrs) comment_lines(a, ld.indent, false);
    auto *line = out->add_lines();
    line->set_indent(ld.indent);
    if (line_addr) *line->mutable_address() = A(line_addr);
    for (const TokDef &td : ld.toks) {
      auto *t = line->add_tokens();
      t->set_kind(td.kind);
      t->set_text(td.text);
      if (td.var >= 0) {
        const VarDef &v = d.vars[td.var];
        t->set_text(VarName(f.entry, v));
        t->set_variable_index(static_cast<std::uint32_t>(td.var));
        t->set_kind(v.kind == pb::VARIABLE_KIND_PARAMETER ? pb::CODE_TOKEN_KIND_PARAMETER
                    : v.kind == pb::VARIABLE_KIND_GLOBAL  ? pb::CODE_TOKEN_KIND_GLOBAL_VARIABLE
                                                          : pb::CODE_TOKEN_KIND_LOCAL_VARIABLE);
        if (v.kind == pb::VARIABLE_KIND_GLOBAL) *t->mutable_target() = A(v.address);
      }
      if (td.target) {
        t->set_text(DisplayOrAddress(td.target));
        *t->mutable_target() = A(td.target);
      }
      if (td.addr) *t->mutable_address() = A(td.addr);
      for (auto vn : td.vns) t->add_varnode_indices(vn);
      if (td.value) t->set_value(*td.value);
    }
  }
  add_tok(out->add_lines(), pb::CODE_TOKEN_KIND_PUNCTUATION, "}");

  if (include_text) {
    std::string text;
    for (const auto &line : out->lines()) {
      if (!line.tokens().empty()) text.append(2 * line.indent(), ' ');
      for (const auto &t : line.tokens()) text += t.text();
      text += '\n';
    }
    out->set_text(std::move(text));
  }
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

struct Subscriber {
  std::uint64_t id;
  std::shared_ptr<EventSink> sink;
  std::set<std::string> programs;  // empty = all
  bool include_assertions;
};

struct Project {
  std::string id;
  bool open = true;
  std::shared_ptr<const ProjectState> head;
  std::map<std::uint64_t, std::shared_ptr<const ProjectState>> history;
  std::map<std::uint64_t, pb::RevisionEvent> events;
  std::vector<Subscriber> subscribers;
  std::vector<pb::AnalysisJob> jobs;
};

pb::RevisionEvent FilterEvent(const pb::RevisionEvent &e, const Subscriber &s) {
  pb::RevisionEvent out = e;
  if (!s.include_assertions) out.clear_assertions();
  if (s.programs.empty()) return out;
  auto keep = [&](const std::string &program) { return s.programs.count(program) > 0; };
  out.clear_changed_keys();
  for (const auto &k : e.changed_keys())
    if (keep(k.program_id())) *out.add_changed_keys() = k;
  out.clear_invalidated();
  for (const auto &q : e.invalidated())
    if (keep(q.program_id())) *out.add_invalidated() = q;
  out.clear_invalidate_all_programs();
  for (const auto &p : e.invalidate_all_programs())
    if (keep(p)) out.add_invalidate_all_programs(p);
  out.clear_assertions();
  if (s.include_assertions)
    for (const auto &a : e.assertions())
      if (keep(a.key().program_id())) *out.add_assertions() = a;
  return out;
}

class Core : public std::enable_shared_from_this<Core> {
 public:
  explicit Core(FakeBackendOptions options) : options_(std::move(options)) {}

  FakeBackendOptions options_;
  std::mutex mu_;
  std::condition_variable head_changed_;
  std::map<std::string, Project> projects_;
  std::map<std::string, std::string> program_project_;  // program id -> project id
  std::uint64_t next_subscriber_ = 1;
  std::uint64_t next_job_ = 1;

  void Unsubscribe(const std::string &project, std::uint64_t id) {
    std::lock_guard lock(mu_);
    auto it = projects_.find(project);
    if (it == projects_.end()) return;
    std::erase_if(it->second.subscribers, [&](const Subscriber &s) { return s.id == id; });
  }

  std::uint64_t Head(const std::string &project) {
    std::lock_guard lock(mu_);
    auto it = projects_.find(project);
    return it == projects_.end() ? 0 : it->second.head->revision;
  }
};

class FakeSubscription final : public Subscription {
 public:
  FakeSubscription(std::shared_ptr<Core> core, std::string project, std::uint64_t id)
      : core_(std::move(core)), project_(std::move(project)), id_(id) {}
  ~FakeSubscription() override { core_->Unsubscribe(project_, id_); }
  std::uint64_t head_revision() const override { return core_->Head(project_); }

 private:
  std::shared_ptr<Core> core_;
  std::string project_;
  std::uint64_t id_;
};

// Computes the canonical key of an assertion body and validates it against
// the program. Returns an error message, or empty on success.
std::string KeyFor(const View &v, const pb::AssertionBody &body, pb::FactKey &key) {
  const auto &prog = v.prog();
  key.set_program_id(v.program().id);
  auto check_addr = [&](const pb::Address &a) -> std::string {
    if (!IsDefaultSpace(a)) return "only the default space is supported, got \"" + a.space() + "\"";
    if (!prog.block_containing(a.offset())) return "address 0x" + Hex(a.offset()) + " is not in memory";
    return {};
  };
  auto set_target = [&](const pb::Target &t, pb::FactKind kind) -> std::string {
    key.set_kind(kind);
    if (t.has_address()) {
      if (auto e = check_addr(t.address()); !e.empty()) return e;
      key.mutable_address()->set_offset(t.address().offset());
      return {};
    }
    if (t.has_local()) {
      std::uint64_t entry = t.local().function().offset();
      if (!v.FunctionAt(entry)) return "no function at 0x" + Hex(entry);
      if (t.local().storage_key().empty()) return "local.storage_key is required";
      if (auto it = prog.decomps.find(entry); it != prog.decomps.end()) {
        const auto &vars = it->second.vars;
        if (std::none_of(vars.begin(), vars.end(), [&](const VarDef &d) {
              return d.kind != pb::VARIABLE_KIND_GLOBAL && d.storage_key == t.local().storage_key();
            }))
          return "function 0x" + Hex(entry) + " has no variable with storage_key \"" + t.local().storage_key() + "\"";
      }
      key.mutable_address()->set_offset(entry);
      key.set_sub("local:" + t.local().storage_key());
      return {};
    }
    return "target is required";
  };

  switch (body.kind_case()) {
    case pb::AssertionBody::kRename: {
      const auto &name = body.rename().name();
      if (name.size() > 256) return "name is longer than 256 bytes";
      if (std::any_of(name.begin(), name.end(), [](unsigned char c) { return std::isspace(c) || c < 0x20; }))
        return "name contains whitespace or control characters";
      return set_target(body.rename().target(), pb::FACT_KIND_NAME);
    }
    case pb::AssertionBody::kRetype: {
      const auto &t = body.retype().type();
      if (t.kind_case() == pb::TypeSpec::KIND_NOT_SET) return "type is required";
      if (t.has_type_hash() && !prog.type_by_hash(t.type_hash())) return "unknown type hash " + t.type_hash();
      if (t.has_c_declaration() && t.c_declaration().empty()) return "c_declaration is empty";
      return set_target(body.retype().target(), pb::FACT_KIND_TYPE);
    }
    case pb::AssertionBody::kComment: {
      const auto &c = body.comment();
      if (c.kind() == pb::COMMENT_KIND_UNSPECIFIED || !*CommentSub(c.kind())) return "comment.kind is required";
      if (auto e = check_addr(c.address()); !e.empty()) return e;
      key.set_kind(pb::FACT_KIND_COMMENT);
      key.mutable_address()->set_offset(c.address().offset());
      key.set_sub(CommentSub(c.kind()));
      return {};
    }
    case pb::AssertionBody::kFunctionBounds: {
      const auto &b = body.function_bounds();
      if (auto e = check_addr(b.entry()); !e.empty()) return e;
      if (!prog.insn_at(b.entry().offset())) return "no instruction at entry 0x" + Hex(b.entry().offset());
      for (const auto &r : b.body()) {
        if (r.first().offset() > r.last().offset()) return "body range first > last";
        if (auto e = check_addr(r.first()); !e.empty()) return e;
        if (auto e = check_addr(r.last()); !e.empty()) return e;
      }
      key.set_kind(pb::FACT_KIND_FUNCTION_BOUNDS);
      key.mutable_address()->set_offset(b.entry().offset());
      return {};
    }
    case pb::AssertionBody::kFlowOverride: {
      const auto &f = body.flow_override();
      if (auto e = check_addr(f.address()); !e.empty()) return e;
      if (!prog.insn_at(f.address().offset())) return "no instruction at 0x" + Hex(f.address().offset());
      if (f.kind() == pb::FLOW_OVERRIDE_KIND_UNSPECIFIED) return "flow_override.kind is required";
      key.set_kind(pb::FACT_KIND_FLOW_OVERRIDE);
      key.mutable_address()->set_offset(f.address().offset());
      return {};
    }
    case pb::AssertionBody::kNote: {
      const auto &n = body.note();
      if (auto e = check_addr(n.address()); !e.empty()) return e;
      key.set_kind(pb::FACT_KIND_NOTE);
      key.mutable_address()->set_offset(n.address().offset());
      key.set_sub(n.tag());
      return {};
    }
    case pb::AssertionBody::kDefineType: return "define_type is not supported by the fake backend";
    case pb::AssertionBody::kBindTypeName: return "bind_type_name is not supported by the fake backend";
    case pb::AssertionBody::kDiffMatch: return "diff_match assertions are written by DiffService";
    case pb::AssertionBody::KIND_NOT_SET: break;
  }
  return "assertion body is empty";
}

// Display form of a key's effective value.
std::string ValueText(const View &v, const pb::FactKey &key) {
  std::uint64_t a = key.address().offset();
  const std::string &sub = key.sub();
  switch (key.kind()) {
    case pb::FACT_KIND_NAME:
      if (sub.starts_with("local:")) {
        if (auto it = v.prog().decomps.find(a); it != v.prog().decomps.end())
          for (const auto &var : it->second.vars)
            if ("local:" + var.storage_key == sub) return v.VarName(a, var);
        if (auto *w = v.Winner(key.kind(), a, sub)) return w->body().rename().name();
        return {};
      }
      return v.Symbol(a);
    case pb::FACT_KIND_TYPE:
      if (auto *w = v.Winner(key.kind(), a, sub)) return v.TypeDisplay(*w);
      if (sub.empty()) {
        if (auto *f = v.FunctionAt(a)) return v.Prototype(*f);
        if (auto *d = v.prog().data_at(a)) return d->type;
      } else if (auto it = v.prog().decomps.find(a); it != v.prog().decomps.end()) {
        for (const auto &var : it->second.vars)
          if ("local:" + var.storage_key == sub) return var.default_type;
      }
      return {};
    case pb::FACT_KIND_COMMENT:
      if (auto *w = v.Winner(key.kind(), a, sub)) return w->body().comment().text();
      return {};
    case pb::FACT_KIND_FUNCTION_BOUNDS:
      if (auto *f = v.FunctionAt(a)) {
        std::string s;
        for (auto [first, last] : f->body) s += (s.empty() ? "" : ",") + ("0x" + Hex(first) + "-0x" + Hex(last));
        return s;
      }
      return {};
    case pb::FACT_KIND_FLOW_OVERRIDE:
      if (auto *w = v.Winner(key.kind(), a, sub)) return pb::FlowOverrideKind_Name(w->body().flow_override().kind());
      return {};
    case pb::FACT_KIND_NOTE:
      if (auto *w = v.Winner(key.kind(), a, sub)) return w->body().note().text();
      return {};
    default: return {};
  }
}

// Derived queries a changed key may affect (conservative).
void Invalidate(const View &v, const pb::FactKey &key, std::vector<pb::InvalidatedQuery> &out) {
  const std::string &program = key.program_id();
  std::uint64_t a = key.address().offset();
  const auto &prog = v.prog();
  auto add = [&](pb::QueryKind kind, std::optional<std::uint64_t> point = {},
                 std::optional<std::pair<std::uint64_t, std::uint64_t>> range = {}) {
    pb::InvalidatedQuery q;
    q.set_program_id(program);
    q.set_kind(kind);
    if (point) *q.mutable_address() = A(*point);
    if (range) *q.mutable_range() = Range(range->first, range->second);
    out.push_back(std::move(q));
  };
  auto decompile_containing = [&](std::uint64_t addr) {
    if (auto *f = v.FunctionContaining(addr)) add(pb::QUERY_KIND_DECOMPILE, f->entry);
  };
  auto decompiles_mentioning_global = [&](std::uint64_t addr) {
    for (const auto &[entry, d] : prog.decomps)
      for (const auto &var : d.vars)
        if (var.kind == pb::VARIABLE_KIND_GLOBAL && var.address == addr) add(pb::QUERY_KIND_DECOMPILE, entry);
  };
  bool local = key.sub().starts_with("local:");

  add(pb::QUERY_KIND_ASSERTIONS, a);
  switch (key.kind()) {
    case pb::FACT_KIND_NAME:
      if (local) {
        add(pb::QUERY_KIND_DECOMPILE, a);
        break;
      }
      add(pb::QUERY_KIND_FUNCTION_LIST);
      if (v.FunctionAt(a)) {
        add(pb::QUERY_KIND_FUNCTION, a);
        add(pb::QUERY_KIND_DECOMPILE, a);
      }
      add(pb::QUERY_KIND_LISTING, {}, std::pair{a, a});
      for (const auto &x : prog.xrefs)
        if (x.to == a) {
          add(pb::QUERY_KIND_LISTING, {}, std::pair{x.from, x.from});
          add(pb::QUERY_KIND_INSTRUCTION, {}, std::pair{x.from, x.from});
          decompile_containing(x.from);
        }
      decompiles_mentioning_global(a);
      add(pb::QUERY_KIND_XREFS);  // xrefs carry from_function_name / to_name
      break;
    case pb::FACT_KIND_TYPE:
      if (local) {
        add(pb::QUERY_KIND_DECOMPILE, a);
        break;
      }
      if (v.FunctionAt(a)) {
        add(pb::QUERY_KIND_FUNCTION_LIST);
        add(pb::QUERY_KIND_FUNCTION, a);
        add(pb::QUERY_KIND_DECOMPILE, a);
        for (const auto &x : prog.xrefs)
          if (x.to == a) decompile_containing(x.from);
      } else {
        add(pb::QUERY_KIND_LISTING, {}, std::pair{a, a});
        decompiles_mentioning_global(a);
      }
      break;
    case pb::FACT_KIND_COMMENT:
      add(pb::QUERY_KIND_LISTING, {}, std::pair{a, a});
      decompile_containing(a);
      break;
    case pb::FACT_KIND_FUNCTION_BOUNDS:
      add(pb::QUERY_KIND_PROGRAM);
      add(pb::QUERY_KIND_FUNCTION_LIST);
      add(pb::QUERY_KIND_FUNCTION, a);
      add(pb::QUERY_KIND_DECOMPILE, a);
      add(pb::QUERY_KIND_LISTING);
      add(pb::QUERY_KIND_XREFS);
      break;
    case pb::FACT_KIND_FLOW_OVERRIDE:
      add(pb::QUERY_KIND_INSTRUCTION, {}, std::pair{a, a});
      add(pb::QUERY_KIND_LISTING, {}, std::pair{a, a});
      decompile_containing(a);
      break;
    default: break;
  }
}

bool MatchesProvenance(const pb::ProvenanceFilter &f, const pb::Provenance &p) {
  if (f.kind() != pb::PROVENANCE_KIND_UNSPECIFIED && f.kind() != p.kind()) return false;
  if (!f.id().empty() && f.id() != p.id()) return false;
  if (!f.version().empty() && f.version() != p.version()) return false;
  if (!f.session().empty() && f.session() != p.session()) return false;
  if (!f.on_behalf_of().empty() && f.on_behalf_of() != p.on_behalf_of()) return false;
  return true;
}

bool InRange(const pb::AddressRange &r, const pb::Address &a) {
  return a.space() == r.first().space() && a.offset() >= r.first().offset() && a.offset() <= r.last().offset();
}

class FakeBackend final : public Backend {
 public:
  explicit FakeBackend(FakeBackendOptions options) : core_(std::make_shared<Core>(std::move(options))) {
    std::lock_guard lock(core_->mu_);
    Project &p = CreateProjectLocked("demo", "demo", "");
    pb::ImportProgramRequest req;
    req.set_project_id("demo");
    req.set_name("hello");
    pb::ImportProgramResponse resp;
    ImportLocked(p, req, SyntheticImage(), kDemoImportTime, resp);
  }

  // --- Meta -----------------------------------------------------------------

  Status GetServerInfo(const CallContext &, const pb::GetServerInfoRequest &,
                       pb::GetServerInfoResponse &resp) override {
    resp.set_api_major("v1");
    resp.set_api_minor(kApiMinor);
    resp.set_server_version(core_->options_.server_version);
    for (const char *f : {"fake-backend", "snapshot-reads", "subscriptions", "decompile", "import-bytes",
                          "bulk-revert", "symbols"})
      resp.add_features(f);
    resp.set_retained_revisions(core_->options_.retained_revisions);
    resp.set_max_request_bytes(64ull << 20);
    return Status::Ok();
  }

  // --- Projects ---------------------------------------------------------------

  Status ListProjects(const CallContext &, const pb::ListProjectsRequest &,
                      pb::ListProjectsResponse &resp) override {
    std::lock_guard lock(core_->mu_);
    for (auto &[id, p] : core_->projects_) FillProjectInfo(p, resp.add_projects());
    return Status::Ok();
  }

  Status OpenProject(const CallContext &, const pb::OpenProjectRequest &req,
                     pb::OpenProjectResponse &resp) override {
    std::lock_guard lock(core_->mu_);
    Project *p = nullptr;
    if (req.has_project_id()) {
      auto it = core_->projects_.find(req.project_id());
      if (it == core_->projects_.end()) return Error(StatusCode::kNotFound, "no project " + req.project_id());
      p = &it->second;
    } else if (req.has_path()) {
      if (req.path().empty()) return Error(StatusCode::kInvalidArgument, "path is empty");
      for (auto &[id, proj] : core_->projects_)
        if (proj.head->path == req.path()) p = &proj;
      if (!p) {
        if (!req.create_if_missing()) return Error(StatusCode::kNotFound, "no project at " + req.path());
        std::string name = req.name();
        if (name.empty()) name = req.path().substr(req.path().find_last_of('/') + 1);
        std::string id = name;
        for (int n = 2; core_->projects_.count(id); ++n) id = name + "-" + std::to_string(n);
        p = &CreateProjectLocked(id, name, req.path());
      }
    } else {
      return Error(StatusCode::kInvalidArgument, "project_id or path is required");
    }
    p->open = true;
    FillProjectInfo(*p, resp.mutable_project());
    for (const auto &prog : p->head->programs) FillProgramInfo(*p->head, prog, resp.add_programs());
    return Status::Ok();
  }

  Status CloseProject(const CallContext &, const pb::CloseProjectRequest &req,
                      pb::CloseProjectResponse &) override {
    std::lock_guard lock(core_->mu_);
    auto it = core_->projects_.find(req.project_id());
    if (it == core_->projects_.end()) return Error(StatusCode::kNotFound, "no project " + req.project_id());
    it->second.open = false;
    for (auto &s : it->second.subscribers) s.sink->End(Error(StatusCode::kCancelled, "project closed"));
    it->second.subscribers.clear();
    return Status::Ok();
  }

  Status ListPrograms(const CallContext &ctx, const pb::ListProgramsRequest &req,
                      pb::ListProgramsResponse &resp) override {
    std::shared_ptr<const ProjectState> s;
    std::uint64_t head = 0;
    if (auto st = ResolveProject(ctx, req.project_id(), req.read(), 0, s, head); !st.ok()) return st;
    SetSnapshot(*s, head, resp.mutable_snapshot());
    for (const auto &p : s->programs) FillProgramInfo(*s, p, resp.add_programs());
    return Status::Ok();
  }

  Status ImportProgram(const CallContext &, const pb::ImportProgramRequest &req,
                       pb::ImportProgramResponse &resp) override {
    std::string bytes;
    if (req.has_content()) {
      bytes = req.content();
    } else if (req.has_path()) {
      std::ifstream in(req.path(), std::ios::binary);
      if (!in) return Error(StatusCode::kNotFound, "cannot read " + req.path());
      bytes.assign(std::istreambuf_iterator<char>(in), {});
    } else {
      return Error(StatusCode::kInvalidArgument, "path or content is required");
    }
    std::lock_guard lock(core_->mu_);
    auto it = core_->projects_.find(req.project_id());
    if (it == core_->projects_.end()) return Error(StatusCode::kNotFound, "no project " + req.project_id());
    if (!it->second.open) return Error(StatusCode::kFailedPrecondition, "project is closed");
    ImportLocked(it->second, req, bytes, TimeUtil::GetCurrentTime().seconds(), resp);
    resp.add_warnings("fake backend: imported bytes are ignored; the program is the synthetic demo image");
    return Status::Ok();
  }

  Status GetProgramSummary(const CallContext &ctx, const pb::GetProgramSummaryRequest &req,
                           pb::GetProgramSummaryResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), {}, r); !st.ok()) return st;
    View v(*r.state, *r.program);
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    auto *s = resp.mutable_summary();
    FillProgramInfo(*r.state, *r.program, s->mutable_info());
    auto *lang = s->mutable_language();
    lang->set_language_id("x86:LE:64:default");
    lang->set_compiler_spec_id("gcc");
    lang->set_processor("x86");
    lang->set_endianness(pb::ENDIANNESS_LITTLE);
    lang->set_pointer_size(8);
    lang->set_default_space("ram");
    *s->mutable_image_base() = A(v.prog().image_base);
    auto *e = s->add_entry_points();
    *e->mutable_address() = A(fake::kEntry);
    e->set_kind("entry");
    e->set_name(v.Symbol(fake::kEntry));
    FillMemory(v, s->mutable_memory());
    s->set_function_count(static_cast<std::uint32_t>(v.functions().size()));
    s->set_instruction_count(static_cast<std::uint32_t>(v.prog().insns.size()));
    s->set_file_size(r.program->file_size);
    struct SpaceRow { const char *name; pb::AddressSpaceKind kind; std::uint32_t size; };
    for (auto sp : {SpaceRow{"ram", pb::ADDRESS_SPACE_KIND_RAM, 8}, SpaceRow{"register", pb::ADDRESS_SPACE_KIND_REGISTER, 4},
                    SpaceRow{"stack", pb::ADDRESS_SPACE_KIND_STACK, 8}, SpaceRow{"unique", pb::ADDRESS_SPACE_KIND_UNIQUE, 4},
                    SpaceRow{"const", pb::ADDRESS_SPACE_KIND_CONSTANT, 8}}) {
      auto *info = s->add_spaces();
      info->set_name(sp.name);
      info->set_kind(sp.kind);
      info->set_size(sp.size);
      info->set_word_size(1);
    }
    return Status::Ok();
  }

  // --- Assertions -------------------------------------------------------------

  Status AppendAssertions(const CallContext &, const pb::AppendAssertionsRequest &req,
                          pb::AppendAssertionsResponse &resp) override {
    if (req.provenance().kind() == pb::PROVENANCE_KIND_UNSPECIFIED)
      return Error(StatusCode::kInvalidArgument, "provenance.kind is required");
    if (req.assertions().empty()) return Error(StatusCode::kInvalidArgument, "no assertions");
    std::lock_guard lock(core_->mu_);
    Project *p = nullptr;
    const ProgramMeta *prog = nullptr;
    if (auto st = WritableProgramLocked(req.program_id(), p, prog); !st.ok()) return st;
    if (req.expected_head_revision() && req.expected_head_revision() != p->head->revision)
      return Error(StatusCode::kAborted, "head is " + std::to_string(p->head->revision) + ", expected " +
                                             std::to_string(req.expected_head_revision()));
    View v(*p->head, *prog);
    std::vector<pb::Assertion> entries;
    for (int i = 0; i < req.assertions_size(); ++i) {
      const auto &in = req.assertions(i);
      pb::Assertion a;
      a.set_op(pb::ASSERTION_OP_ASSERT);
      *a.mutable_body() = in.body();
      if (auto err = KeyFor(v, in.body(), *a.mutable_key()); !err.empty())
        return Error(StatusCode::kInvalidArgument, "assertions[" + std::to_string(i) + "]: " + err);
      if (std::uint64_t dep = in.depends_on_seq()) {
        if (dep > p->head->log.size() || p->head->log[dep - 1].op() != pb::ASSERTION_OP_ASSERT)
          return Error(StatusCode::kInvalidArgument,
                       "assertions[" + std::to_string(i) + "]: depends_on_seq is not an assertion");
        a.set_depends_on_seq(dep);
      }
      entries.push_back(std::move(a));
    }
    if (req.validate_only()) {
      SetSnapshot(*p->head, p->head->revision, resp.mutable_snapshot());
      for (auto &a : entries) {
        *a.mutable_provenance() = req.provenance();
        *resp.add_assertions() = std::move(a);
      }
      return Status::Ok();
    }
    pb::RevisionEvent ev = CommitLocked(*p, req.provenance(), pb::CHANGE_CAUSE_ASSERTION, std::move(entries));
    SetSnapshot(*p->head, p->head->revision, resp.mutable_snapshot());
    *resp.mutable_assertions() = ev.assertions();
    *resp.mutable_changed_keys() = ev.changed_keys();
    return Status::Ok();
  }

  Status RetractAssertions(const CallContext &, const pb::RetractAssertionsRequest &req,
                           pb::RetractAssertionsResponse &resp) override {
    if (req.provenance().kind() == pb::PROVENANCE_KIND_UNSPECIFIED)
      return Error(StatusCode::kInvalidArgument, "provenance.kind is required");
    if (req.seqs().empty()) return Error(StatusCode::kInvalidArgument, "no seqs");
    std::lock_guard lock(core_->mu_);
    Project *p = nullptr;
    const ProgramMeta *prog = nullptr;
    if (auto st = WritableProgramLocked(req.program_id(), p, prog); !st.ok()) return st;
    if (req.expected_head_revision() && req.expected_head_revision() != p->head->revision)
      return Error(StatusCode::kAborted, "head moved");
    std::vector<pb::Assertion> entries;
    std::set<std::uint64_t> seen;
    for (std::uint64_t seq : req.seqs()) {
      if (seq == 0 || seq > p->head->log.size())
        return Error(StatusCode::kNotFound, "no assertion with seq " + std::to_string(seq));
      const auto &target = p->head->log[seq - 1];
      if (target.key().program_id() != prog->id)
        return Error(StatusCode::kInvalidArgument, "seq " + std::to_string(seq) + " belongs to another program");
      if (target.status() == pb::ASSERTION_STATUS_RETRACTED || !seen.insert(seq).second)
        return Error(StatusCode::kFailedPrecondition, "seq " + std::to_string(seq) + " is already retracted");
      entries.push_back(RetractionOf(target));
    }
    pb::RevisionEvent ev = CommitLocked(*p, req.provenance(), pb::CHANGE_CAUSE_RETRACTION, std::move(entries));
    SetSnapshot(*p->head, p->head->revision, resp.mutable_snapshot());
    *resp.mutable_retractions() = ev.assertions();
    *resp.mutable_changed_keys() = ev.changed_keys();
    return Status::Ok();
  }

  Status GetHistory(const CallContext &ctx, const pb::GetHistoryRequest &req,
                    pb::GetHistoryResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.key().program_id(), req.read(), req.page().page_token(), r); !st.ok())
      return st;
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    std::string key = KeyString(req.key());
    std::vector<const pb::Assertion *> matches;
    for (const auto &a : r.state->log)
      if (KeyString(a.key()) == key) matches.push_back(&a);
    Paginate(matches.size(), r.page_offset, req.page().page_size(), 500, 5000, r.state->revision,
             resp.mutable_page(), [&](std::size_t i) { *resp.add_entries() = *matches[i]; });
    return Status::Ok();
  }

  Status Blame(const CallContext &ctx, const pb::BlameRequest &req, pb::BlameResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.key().program_id(), req.read(), {}, r); !st.ok()) return st;
    View v(*r.state, *r.program);
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    *resp.mutable_key() = req.key();
    std::string key = KeyString(req.key());
    std::vector<const pb::Assertion *> candidates;
    for (const auto &a : r.state->log)
      if (a.op() == pb::ASSERTION_OP_ASSERT && KeyString(a.key()) == key) candidates.push_back(&a);
    auto order = [](pb::AssertionStatus s) {
      switch (s) {
        case pb::ASSERTION_STATUS_EFFECTIVE: return 0;
        case pb::ASSERTION_STATUS_SHADOWED: return 1;
        case pb::ASSERTION_STATUS_DEPENDENCY_DEAD: return 2;
        default: return 3;
      }
    };
    std::stable_sort(candidates.begin(), candidates.end(), [&](auto *x, auto *y) {
      if (order(x->status()) != order(y->status())) return order(x->status()) < order(y->status());
      int rx = Rank(x->provenance().kind()), ry = Rank(y->provenance().kind());
      return rx != ry ? rx > ry : x->seq() > y->seq();
    });
    for (auto *a : candidates) *resp.add_candidates() = *a;
    resp.set_value_text(ValueText(v, req.key()));
    if (!candidates.empty() && candidates[0]->status() == pb::ASSERTION_STATUS_EFFECTIVE) {
      *resp.mutable_origin() = Asserted(*candidates[0]);
    } else if (!resp.value_text().empty()) {
      static const std::map<int, const char *> rules = {
          {pb::FACT_KIND_NAME, "symbols.default_name"},     {pb::FACT_KIND_TYPE, "decompiler.ghidra.types"},
          {pb::FACT_KIND_FUNCTION_BOUNDS, "functions.flow"}, {pb::FACT_KIND_COMMENT, "comments"},
          {pb::FACT_KIND_FLOW_OVERRIDE, "flow"},             {pb::FACT_KIND_NOTE, "notes"}};
      auto it = rules.find(req.key().kind());
      *resp.mutable_origin() = Derived(it == rules.end() ? "default" : it->second, r.state->revision);
    }
    return Status::Ok();
  }

  Status ListAssertions(const CallContext &ctx, const pb::ListAssertionsRequest &req,
                        pb::ListAssertionsResponse &resp) override {
    const auto &f = req.filter();
    if (f.provenance().kind() == pb::PROVENANCE_KIND_UNSPECIFIED && !f.provenance().id().empty())
      return Error(StatusCode::kInvalidArgument, "provenance filter with an id needs a kind");
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), req.page().page_token(), r); !st.ok())
      return st;
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    std::set<int> kinds(f.kinds().begin(), f.kinds().end());
    std::vector<const pb::Assertion *> matches;
    for (const auto &a : r.state->log) {
      if (a.key().program_id() != req.program_id()) continue;
      if (!f.include_inactive() && (a.op() != pb::ASSERTION_OP_ASSERT || (a.status() != pb::ASSERTION_STATUS_EFFECTIVE &&
                                                                         a.status() != pb::ASSERTION_STATUS_SHADOWED)))
        continue;
      if (!MatchesProvenance(f.provenance(), a.provenance())) continue;
      if (!kinds.empty() && !kinds.count(a.key().kind())) continue;
      if (f.has_range() && !InRange(f.range(), a.key().address())) continue;
      if (f.min_revision() && a.revision() < f.min_revision()) continue;
      if (f.max_revision() && a.revision() > f.max_revision()) continue;
      matches.push_back(&a);
    }
    Paginate(matches.size(), r.page_offset, req.page().page_size(), 500, 5000, r.state->revision,
             resp.mutable_page(), [&](std::size_t i) { *resp.add_assertions() = *matches[i]; });
    return Status::Ok();
  }

  Status RevertByProvenance(const CallContext &, const pb::RevertByProvenanceRequest &req,
                            pb::RevertByProvenanceResponse &resp) override {
    const auto &f = req.filter();
    if (f.kind() == pb::PROVENANCE_KIND_UNSPECIFIED && f.session().empty())
      return Error(StatusCode::kInvalidArgument, "filter needs a kind or a session");
    if (f.kind() == pb::PROVENANCE_KIND_UNSPECIFIED && !f.id().empty())
      return Error(StatusCode::kInvalidArgument, "provenance filter with an id needs a kind");
    if (!req.dry_run() && req.provenance().kind() == pb::PROVENANCE_KIND_UNSPECIFIED)
      return Error(StatusCode::kInvalidArgument, "provenance.kind is required");
    std::lock_guard lock(core_->mu_);
    Project *p = nullptr;
    const ProgramMeta *prog = nullptr;
    if (auto st = WritableProgramLocked(req.program_id(), p, prog); !st.ok()) return st;
    // Everything the author did, as the fact store's revert: their
    // assertions and their retractions (retracting those reinstates what
    // they removed), live or not, newest first. Already-retracted ops are
    // included so that undoing one of their retractions later cannot
    // revive their work: a full revert reads as if they never acted.
    std::vector<pb::Assertion> entries;
    for (const auto &a : p->head->log) {
      if (a.key().program_id() != prog->id || a.revision() < req.since_revision()) continue;
      if (!MatchesProvenance(f, a.provenance())) continue;
      resp.add_retracted_seqs(a.seq());
      entries.push_back(RetractionOf(a));
    }
    std::reverse(entries.begin(), entries.end());
    if (req.dry_run() || entries.empty()) {
      SetSnapshot(*p->head, p->head->revision, resp.mutable_snapshot());
      return Status::Ok();
    }
    pb::RevisionEvent ev = CommitLocked(*p, req.provenance(), pb::CHANGE_CAUSE_RETRACTION, std::move(entries));
    SetSnapshot(*p->head, p->head->revision, resp.mutable_snapshot());
    *resp.mutable_retractions() = ev.assertions();
    *resp.mutable_changed_keys() = ev.changed_keys();
    return Status::Ok();
  }

  // --- Queries ----------------------------------------------------------------

  Status GetMemoryMap(const CallContext &ctx, const pb::GetMemoryMapRequest &req,
                      pb::GetMemoryMapResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), {}, r); !st.ok()) return st;
    View v(*r.state, *r.program);
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    FillMemory(v, resp.mutable_blocks());
    return Status::Ok();
  }

  Status ReadMemory(const CallContext &ctx, const pb::ReadMemoryRequest &req,
                    pb::ReadMemoryResponse &resp) override {
    if (req.length() > (1u << 20)) return Error(StatusCode::kInvalidArgument, "length exceeds 1 MiB");
    if (!IsDefaultSpace(req.address())) return Error(StatusCode::kInvalidArgument, "only the default space is readable");
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), {}, r); !st.ok()) return st;
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    *resp.mutable_address() = req.address();
    std::string data;
    const auto &prog = SyntheticProgram::Get();
    for (std::uint64_t a = req.address().offset(); a < req.address().offset() + req.length(); ++a) {
      auto b = prog.byte_at(a);
      if (!b) break;
      data.push_back(static_cast<char>(*b));
    }
    resp.set_data(std::move(data));
    return Status::Ok();
  }

  Status ListFunctions(const CallContext &ctx, const pb::ListFunctionsRequest &req,
                       pb::ListFunctionsResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), req.page().page_token(), r); !st.ok()) return st;
    View v(*r.state, *r.program);
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    std::string needle = Lower(req.name_contains());
    std::vector<std::pair<std::string, const Func *>> matches;
    for (const auto &[entry, f] : v.functions()) {
      std::string name = v.Symbol(entry);
      if (!needle.empty() && Lower(name).find(needle) == std::string::npos) continue;
      if (req.has_range() && !InRange(req.range(), A(entry))) continue;
      matches.emplace_back(name, &f);
    }
    if (req.sort() == pb::FUNCTION_SORT_NAME)
      std::stable_sort(matches.begin(), matches.end(), [](auto &x, auto &y) { return x.first < y.first; });
    Paginate(matches.size(), r.page_offset, req.page().page_size(), 500, 5000, r.state->revision,
             resp.mutable_page(), [&](std::size_t i) { v.FillFunction(*matches[i].second, resp.add_functions()); });
    return Status::Ok();
  }

  Status ListSymbols(const CallContext &ctx, const pb::ListSymbolsRequest &req,
                     pb::ListSymbolsResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), req.page().page_token(), r); !st.ok()) return st;
    View v(*r.state, *r.program);
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    // Functions, data symbols, jump labels and any address with an
    // asserted (non-local) name.
    std::map<std::uint64_t, pb::SymbolKind> addrs;
    for (const auto &[entry, f] : v.functions()) addrs.emplace(entry, pb::SYMBOL_KIND_FUNCTION);
    for (const auto &d : v.prog().data) addrs.emplace(d.addr, pb::SYMBOL_KIND_LABEL);
    for (const auto &[addr, name] : v.prog().jump_labels) addrs.emplace(addr, pb::SYMBOL_KIND_LABEL);
    for (const auto &[key, idx] : r.state->winners) {
      const pb::FactKey &k = r.state->log[idx].key();
      if (k.program_id() == r.program->id && k.kind() == pb::FACT_KIND_NAME && k.sub().empty())
        addrs.emplace(k.address().offset(), pb::SYMBOL_KIND_LABEL);
    }
    std::set<int> kinds(req.kinds().begin(), req.kinds().end());
    const std::string needle = Lower(req.name_contains());
    std::vector<std::pair<std::uint64_t, std::string>> matches;
    for (const auto &[addr, kind] : addrs) {
      if (!kinds.empty() && !kinds.count(kind)) continue;
      if (req.has_range() && !InRange(req.range(), A(addr))) continue;
      std::string name = v.Symbol(addr);
      if (name.empty()) continue;
      if (!req.name_equals().empty() ? name != req.name_equals()
                                     : !needle.empty() && Lower(name).find(needle) == std::string::npos)
        continue;
      matches.emplace_back(addr, std::move(name));
    }
    Paginate(matches.size(), r.page_offset, req.page().page_size(), 500, 5000, r.state->revision,
             resp.mutable_page(), [&](std::size_t i) {
               auto *out = resp.add_symbols();
               *out->mutable_address() = A(matches[i].first);
               out->set_name(matches[i].second);
               out->set_kind(addrs.at(matches[i].first));
               *out->mutable_origin() = v.NameOrigin(matches[i].first);
             });
    return Status::Ok();
  }

  Status GetFunction(const CallContext &ctx, const pb::GetFunctionRequest &req,
                     pb::GetFunctionResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), {}, r); !st.ok()) return st;
    View v(*r.state, *r.program);
    std::uint64_t a = req.address().offset();
    const Func *f = req.containing() ? v.FunctionContaining(a) : v.FunctionAt(a);
    if (!f || !IsDefaultSpace(req.address()))
      return Error(StatusCode::kNotFound, std::string("no function ") + (req.containing() ? "containing" : "at") + " 0x" + Hex(a));
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    v.FillFunction(*f, resp.mutable_function());
    return Status::Ok();
  }

  Status GetListing(const CallContext &ctx, const pb::GetListingRequest &req,
                    pb::GetListingResponse &resp) override {
    constexpr std::size_t kMaxRows = 2000;
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), {}, r); !st.ok()) return st;
    View v(*r.state, *r.program);
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    const auto &rows = v.prog().rows;
    std::size_t first = 0, count = 0;
    std::optional<std::uint64_t> end_addr;
    if (req.has_rows()) {
      if (req.rows().first_row() < 0) return Error(StatusCode::kInvalidArgument, "first_row is negative");
      first = std::min<std::size_t>(static_cast<std::size_t>(req.rows().first_row()), rows.size());
      count = req.rows().row_count() == 0 ? 100 : req.rows().row_count();
      resp.set_truncated(count > kMaxRows);
      count = std::min(count, kMaxRows);
    } else if (req.has_addresses()) {
      const auto &w = req.addresses();
      if (!IsDefaultSpace(w.start())) return Error(StatusCode::kInvalidArgument, "only the default space has a listing");
      first = v.prog().row_index_at(w.start().offset());
      first -= std::min<std::size_t>(first, w.rows_before());
      count = w.max_rows() == 0 ? 200 : std::min<std::size_t>(w.max_rows(), kMaxRows);
      if (w.has_end()) end_addr = w.end().offset();
    } else {
      return Error(StatusCode::kInvalidArgument, "window (rows or addresses) is required");
    }
    resp.set_first_row(static_cast<std::int64_t>(first));
    resp.set_total_rows(static_cast<std::int64_t>(rows.size()));
    std::size_t i = first;
    for (; i < rows.size() && i - first < count; ++i) {
      if (end_addr && rows[i].addr > *end_addr) break;
      v.FillRow(rows[i], i, req.omit_bytes(), resp.add_rows());
    }
    if (end_addr && i < rows.size() && rows[i].addr <= *end_addr) resp.set_truncated(true);
    return Status::Ok();
  }

  Status GetInstruction(const CallContext &ctx, const pb::GetInstructionRequest &req,
                        pb::GetInstructionResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), {}, r); !st.ok()) return st;
    View v(*r.state, *r.program);
    const InsnDef *i = IsDefaultSpace(req.address()) ? v.prog().insn_at(req.address().offset()) : nullptr;
    if (!i) return Error(StatusCode::kNotFound, "no instruction at 0x" + Hex(req.address().offset()));
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    auto *out = resp.mutable_instruction();
    *out->mutable_address() = A(i->addr);
    out->set_length(static_cast<std::uint32_t>(i->bytes.size()));
    out->set_bytes(std::string(i->bytes.begin(), i->bytes.end()));
    out->set_mnemonic(i->mnemonic);
    v.Tokens(*i, out->mutable_tokens());
    for (std::size_t k = 0; k < i->operands.size(); ++k) {
      auto *op = out->add_operands();
      op->set_index(static_cast<std::uint32_t>(k));
      TokenizeOperand(v, i->operands[k], static_cast<std::uint32_t>(k), op->mutable_tokens());
      for (const auto &ref : i->refs)
        if (ref.operand == static_cast<int>(k)) *op->add_references() = A(ref.to);
    }
    out->set_flow(i->flow);
    for (auto t : i->flow_targets) *out->add_flow_targets() = A(t);
    if (i->flow != pb::FLOW_KIND_RETURN && i->flow != pb::FLOW_KIND_TERMINATOR)
      *out->mutable_fall_through() = A(i->addr + i->bytes.size());
    if (auto *w = v.Winner(pb::FACT_KIND_FLOW_OVERRIDE, i->addr)) {
      out->set_flow_override(w->body().flow_override().kind());
      *out->mutable_flow_override_origin() = Asserted(*w);
    }
    for (std::size_t k = 0; k < i->pcode.size(); ++k) {
      const PcodeDef &pd = i->pcode[k];
      auto *op = out->add_pcode();
      op->set_opcode(pd.op);
      std::string name = pb::PcodeOpcode_Name(pd.op);
      op->set_mnemonic(name.substr(std::string("PCODE_OPCODE_").size()));
      if (pd.out) SetVarnode(*pd.out, op->mutable_output());
      for (const auto &in : pd.in) SetVarnode(in, op->add_inputs());
      op->set_index(static_cast<std::uint32_t>(k));
    }
    if (const Func *f = v.FunctionContaining(i->addr)) *out->mutable_function() = A(f->entry);
    auto *origin = out->mutable_origin();
    origin->set_rule("disasm.sleigh");
    origin->set_confidence(1);
    origin->set_computed_at_revision(r.state->revision);
    return Status::Ok();
  }

  Status GetXrefs(const CallContext &ctx, const pb::GetXrefsRequest &req, pb::GetXrefsResponse &resp) override {
    std::uint64_t lo, hi;
    if (req.has_address()) {
      lo = hi = req.address().offset();
    } else if (req.has_range()) {
      lo = req.range().first().offset();
      hi = req.range().last().offset();
      if (lo > hi) return Error(StatusCode::kInvalidArgument, "range.first > range.last");
    } else {
      return Error(StatusCode::kInvalidArgument, "address or range is required");
    }
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), req.page().page_token(), r); !st.ok()) return st;
    View v(*r.state, *r.program);
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    auto dir = req.direction() == pb::XREF_DIRECTION_UNSPECIFIED ? pb::XREF_DIRECTION_TO : req.direction();
    std::set<int> kinds(req.kinds().begin(), req.kinds().end());
    std::vector<pb::Xref> out;
    auto emit = [&](const XrefDef &x, pb::XrefDirection d) {
      if (!kinds.empty() && !kinds.count(x.kind)) return;
      pb::Xref xr;
      *xr.mutable_from_address() = A(x.from);
      *xr.mutable_to_address() = A(x.to);
      xr.set_kind(x.kind);
      if (x.operand >= 0) xr.set_operand_index(static_cast<std::uint32_t>(x.operand));
      if (const Func *f = v.FunctionContaining(x.from)) {
        *xr.mutable_from_function() = A(f->entry);
        xr.set_from_function_name(v.Symbol(f->entry));
      }
      xr.set_to_name(v.Symbol(x.to));
      xr.set_direction(d);
      *xr.mutable_origin() = Derived("xrefs.operand", r.state->revision);
      out.push_back(std::move(xr));
    };
    for (const auto &x : v.prog().xrefs) {
      if ((dir == pb::XREF_DIRECTION_TO || dir == pb::XREF_DIRECTION_BOTH) && x.to >= lo && x.to <= hi)
        emit(x, pb::XREF_DIRECTION_TO);
      if ((dir == pb::XREF_DIRECTION_FROM || dir == pb::XREF_DIRECTION_BOTH) && x.from >= lo && x.from <= hi)
        emit(x, pb::XREF_DIRECTION_FROM);
    }
    std::stable_sort(out.begin(), out.end(), [](const pb::Xref &a, const pb::Xref &b) {
      return std::tuple(a.direction(), a.from_address().offset(), a.to_address().offset()) <
             std::tuple(b.direction(), b.from_address().offset(), b.to_address().offset());
    });
    Paginate(out.size(), r.page_offset, req.page().page_size(), 500, 5000, r.state->revision, resp.mutable_page(),
             [&](std::size_t i) { *resp.add_xrefs() = std::move(out[i]); });
    return Status::Ok();
  }

  Status Decompile(const CallContext &ctx, const pb::DecompileRequest &req, pb::DecompileResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), {}, r); !st.ok()) return st;
    View v(*r.state, *r.program);
    const Func *f = IsDefaultSpace(req.function()) ? v.FunctionAt(req.function().offset()) : nullptr;
    if (!f) return Error(StatusCode::kNotFound, "no function at 0x" + Hex(req.function().offset()));
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    v.FillDecompiled(*f, req.options().include_text(), resp.mutable_function());
    return Status::Ok();
  }

  Status GetTypes(const CallContext &ctx, const pb::GetTypesRequest &req, pb::GetTypesResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), {}, {}, r); !st.ok()) return st;
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    const auto &prog = SyntheticProgram::Get();
    std::vector<std::string> todo(req.hashes().begin(), req.hashes().end());
    std::set<std::string> done;
    while (!todo.empty()) {
      std::string h = todo.back();
      todo.pop_back();
      if (!done.insert(h).second) continue;
      const pb::TypeDefinition *t = prog.type_by_hash(h);
      if (!t) {
        resp.add_missing(h);
        continue;
      }
      *resp.add_types() = *t;
      if (!req.include_dependencies()) continue;
      if (t->has_pointer()) todo.push_back(t->pointer().target_hash());
      if (t->has_array()) todo.push_back(t->array().element_hash());
      if (t->has_typedef_type()) todo.push_back(t->typedef_type().target_hash());
      if (t->has_composite())
        for (const auto &f : t->composite().fields()) todo.push_back(f.type_hash());
    }
    return Status::Ok();
  }

  Status FindTypes(const CallContext &ctx, const pb::FindTypesRequest &req, pb::FindTypesResponse &resp) override {
    Resolved r;
    if (auto st = ResolveProgram(ctx, req.program_id(), req.read(), req.page().page_token(), r); !st.ok()) return st;
    SetSnapshot(*r.state, r.head, resp.mutable_snapshot());
    std::string needle = Lower(req.name_contains());
    std::set<int> kinds(req.kinds().begin(), req.kinds().end());
    std::vector<const pb::TypeDefinition *> matches;
    for (const auto &t : SyntheticProgram::Get().types) {
      if (t.name().empty() || Lower(t.name()).find(needle) == std::string::npos) continue;
      if (!kinds.empty() && !kinds.count(t.kind())) continue;
      matches.push_back(&t);
    }
    Paginate(matches.size(), r.page_offset, req.page().page_size(), 500, 5000, r.state->revision,
             resp.mutable_page(), [&](std::size_t i) { *resp.add_types() = *matches[i]; });
    return Status::Ok();
  }

  // --- Analysis ---------------------------------------------------------------

  Status ListAnalyzers(const CallContext &, const pb::ListAnalyzersRequest &,
                       pb::ListAnalyzersResponse &resp) override {
    for (auto [id, desc] : {std::pair{"disasm", "Recursive-descent disassembly from entry points"},
                            std::pair{"functions", "Function discovery and body recovery"},
                            std::pair{"xrefs", "Operand and data references"},
                            std::pair{"decompile-params", "Parameter recovery via the decompiler"}}) {
      auto *a = resp.add_analyzers();
      a->set_id(id);
      a->set_description(desc);
      a->set_enabled_by_default(true);
    }
    return Status::Ok();
  }

  Status StartAnalysis(const CallContext &, const pb::StartAnalysisRequest &req,
                       pb::StartAnalysisResponse &resp) override {
    std::lock_guard lock(core_->mu_);
    Project *p = nullptr;
    const ProgramMeta *prog = nullptr;
    if (auto st = WritableProgramLocked(req.program_id(), p, prog); !st.ok()) return st;
    std::vector<std::string> analyzers(req.analyzers().begin(), req.analyzers().end());
    if (analyzers.empty()) analyzers = {"disasm", "functions", "xrefs", "decompile-params"};
    *resp.mutable_job() = RunJobLocked(*p, prog->id, analyzers);
    return Status::Ok();
  }

  Status CancelAnalysis(const CallContext &, const pb::CancelAnalysisRequest &req,
                        pb::CancelAnalysisResponse &resp) override {
    std::lock_guard lock(core_->mu_);
    for (auto &[id, p] : core_->projects_)
      for (auto &job : p.jobs)
        if (job.job_id() == req.job_id()) {
          *resp.mutable_job() = job;  // fake jobs finish synchronously; nothing to cancel
          return Status::Ok();
        }
    return Error(StatusCode::kNotFound, "no job " + req.job_id());
  }

  Status GetAnalysisStatus(const CallContext &, const pb::GetAnalysisStatusRequest &req,
                           pb::GetAnalysisStatusResponse &resp) override {
    std::lock_guard lock(core_->mu_);
    auto pit = core_->program_project_.find(req.program_id());
    if (pit == core_->program_project_.end()) return Error(StatusCode::kNotFound, "no program " + req.program_id());
    Project &p = core_->projects_.at(pit->second);
    for (auto it = p.jobs.rbegin(); it != p.jobs.rend(); ++it)
      if (it->program_id() == req.program_id()) *resp.add_jobs() = *it;
    resp.set_idle(true);
    resp.set_head_revision(p.head->revision);
    return Status::Ok();
  }

  // --- Subscriptions ------------------------------------------------------------

  Status Subscribe(const CallContext &, const pb::SubscribeRequest &req, std::shared_ptr<EventSink> sink,
                   std::unique_ptr<Subscription> &out) override {
    std::lock_guard lock(core_->mu_);
    auto it = core_->projects_.find(req.project_id());
    if (it == core_->projects_.end()) return Error(StatusCode::kNotFound, "no project " + req.project_id());
    Project &p = it->second;
    if (!p.open) return Error(StatusCode::kFailedPrecondition, "project is closed");
    for (const auto &id : req.program_ids())
      if (!p.head->program(id)) return Error(StatusCode::kNotFound, "no program " + id + " in project");
    Subscriber s{core_->next_subscriber_++, std::move(sink), {req.program_ids().begin(), req.program_ids().end()},
                 req.include_assertions()};

    // Hello and replay happen under the lock, so no commit can slip between
    // them and registration: the client sees every revision exactly once.
    std::uint64_t head = p.head->revision;
    std::uint64_t from = req.from_revision();
    std::uint64_t oldest_event = p.events.empty() ? head + 1 : p.events.begin()->first;
    bool resync = from != 0 && (from > head || from + 1 < oldest_event);
    pb::SubscribeResponse hello;
    hello.mutable_hello()->set_head_revision(head);
    hello.mutable_hello()->set_resync_required(resync);
    s.sink->Send(std::move(hello));
    if (from != 0 && !resync)
      for (auto e = p.events.upper_bound(from); e != p.events.end(); ++e) {
        pb::SubscribeResponse ev;
        *ev.mutable_revision() = FilterEvent(e->second, s);
        s.sink->Send(std::move(ev));
      }
    out = std::make_unique<FakeSubscription>(core_, p.id, s.id);
    p.subscribers.push_back(std::move(s));
    return Status::Ok();
  }

 private:
  struct Resolved {
    std::shared_ptr<const ProjectState> state;
    std::uint64_t head = 0;
    const ProgramMeta *program = nullptr;
    std::size_t page_offset = 0;
  };

  static std::string SyntheticImage() {
    std::string bytes;
    for (const auto &b : SyntheticProgram::Get().blocks) bytes.append(b.bytes.begin(), b.bytes.end());
    return bytes;
  }

  Project &CreateProjectLocked(const std::string &id, const std::string &name, const std::string &path) {
    auto state = std::make_shared<ProjectState>();
    state->id = id;
    state->name = name;
    state->path = path;
    Project &p = core_->projects_[id];
    p.id = id;
    p.head = state;
    p.history[0] = state;
    return p;
  }

  void FillProjectInfo(const Project &p, pb::ProjectInfo *out) const {
    out->set_project_id(p.id);
    out->set_name(p.head->name);
    out->set_path(p.head->path);
    out->set_open(p.open);
    out->set_head_revision(p.head->revision);
    out->set_oldest_retained_revision(p.history.begin()->first);
    out->set_program_count(static_cast<std::uint32_t>(p.head->programs.size()));
  }

  static void FillProgramInfo(const ProjectState &s, const ProgramMeta &p, pb::ProgramInfo *out) {
    out->set_program_id(p.id);
    out->set_project_id(s.id);
    out->set_name(p.name);
    out->set_format("elf");
    out->set_language_id("x86:LE:64:default");
    out->set_sha256(p.sha256);
    *out->mutable_imported_at() = TimeUtil::SecondsToTimestamp(p.imported_at);
  }

  static void FillMemory(const View &v, google::protobuf::RepeatedPtrField<pb::MemoryBlock> *out) {
    for (const auto &b : v.prog().blocks) {
      auto *m = out->Add();
      m->set_name(b.name);
      *m->mutable_range() = Range(b.start, b.start + b.size - 1);
      m->set_read(b.read);
      m->set_write(b.write);
      m->set_execute(b.execute);
      m->set_initialized(b.initialized);
      m->set_has_file_offset(b.initialized);
      m->set_file_offset(b.file_offset);
      *m->mutable_origin() = Derived("loader.elf.sections", v.revision());
    }
  }

  static void SetSnapshot(const ProjectState &s, std::uint64_t head, pb::Snapshot *out) {
    out->set_revision(s.revision);
    out->set_head_revision(head);
  }

  static pb::Assertion RetractionOf(const pb::Assertion &target) {
    pb::Assertion r;
    r.set_op(pb::ASSERTION_OP_RETRACT);
    *r.mutable_key() = target.key();
    r.set_retracts_seq(target.seq());
    return r;
  }

  Status WritableProgramLocked(const std::string &program_id, Project *&p, const ProgramMeta *&prog) {
    auto pit = core_->program_project_.find(program_id);
    if (pit == core_->program_project_.end()) return Error(StatusCode::kNotFound, "no program " + program_id);
    p = &core_->projects_.at(pit->second);
    if (!p->open) return Error(StatusCode::kFailedPrecondition, "project " + p->id + " is closed");
    prog = p->head->program(program_id);
    return Status::Ok();
  }

  // Picks the snapshot a read runs against. A page token's revision is
  // used when the request does not pin one, so later pages stay consistent.
  Status ResolveProject(const CallContext &ctx, const std::string &project_id, const pb::ReadOptions &read,
                        std::uint64_t token_revision, std::shared_ptr<const ProjectState> &out,
                        std::uint64_t &head) {
    std::unique_lock lock(core_->mu_);
    auto it = core_->projects_.find(project_id);
    if (it == core_->projects_.end()) return Error(StatusCode::kNotFound, "no project " + project_id);
    Project &p = it->second;
    if (!p.open) return Error(StatusCode::kFailedPrecondition, "project " + project_id + " is closed");
    std::uint64_t want = read.revision();
    if (token_revision) {
      if (want && want != token_revision)
        return Error(StatusCode::kInvalidArgument, "page_token was issued for another revision");
      want = token_revision;
    }
    if (!want && read.min_revision() > p.head->revision) {
      // Wait for read-your-writes, bounded by the deadline (or 30 s).
      auto limit = std::min(ctx.deadline, CallContext::Clock::now() + std::chrono::seconds(30));
      while (p.head->revision < read.min_revision()) {
        if (ctx.cancelled()) return Error(StatusCode::kCancelled, "cancelled");
        if (CallContext::Clock::now() >= limit)
          return Error(StatusCode::kDeadlineExceeded, "head did not reach min_revision");
        core_->head_changed_.wait_for(lock, std::chrono::milliseconds(50));
      }
    }
    head = p.head->revision;
    if (!want) {
      out = p.head;
      return Status::Ok();
    }
    if (want > head)
      return Error(StatusCode::kOutOfRange, "revision " + std::to_string(want) + " is newer than head " +
                                                std::to_string(head));
    auto h = p.history.find(want);
    if (h == p.history.end())
      return Error(StatusCode::kFailedPrecondition,
                   "REVISION_EXPIRED: revision " + std::to_string(want) + " is older than the oldest retained (" +
                       std::to_string(p.history.begin()->first) + ")");
    out = h->second;
    return Status::Ok();
  }

  Status ResolveProgram(const CallContext &ctx, const std::string &program_id, const pb::ReadOptions &read,
                        const std::string &page_token, Resolved &r) {
    if (program_id.empty()) return Error(StatusCode::kInvalidArgument, "program_id is required");
    std::string project;
    {
      std::lock_guard lock(core_->mu_);
      auto it = core_->program_project_.find(program_id);
      if (it == core_->program_project_.end()) return Error(StatusCode::kNotFound, "no program " + program_id);
      project = it->second;
    }
    std::uint64_t token_revision = 0;
    if (!page_token.empty() && !ParsePageToken(page_token, token_revision, r.page_offset))
      return Error(StatusCode::kInvalidArgument, "malformed page_token");
    if (auto st = ResolveProject(ctx, project, read, token_revision, r.state, r.head); !st.ok()) return st;
    r.program = r.state->program(program_id);
    if (!r.program)
      return Error(StatusCode::kNotFound, "program " + program_id + " does not exist at revision " +
                                              std::to_string(r.state->revision));
    return Status::Ok();
  }

  void ImportLocked(Project &p, const pb::ImportProgramRequest &req, const std::string &bytes,
                    std::int64_t imported_at, pb::ImportProgramResponse &resp) {
    std::string name = req.name();
    if (name.empty()) name = req.has_path() ? req.path().substr(req.path().find_last_of('/') + 1) : "upload";
    std::string id = p.id + "/" + name;
    for (int n = 2; core_->program_project_.count(id); ++n) id = p.id + "/" + name + "-" + std::to_string(n);
    ProgramMeta meta{id, name, Sha256Hex(bytes), bytes.size(), imported_at};
    core_->program_project_[id] = p.id;

    // The loader's own facts: symbol-table names, with IMPORT provenance.
    pb::Provenance prov;
    prov.set_kind(pb::PROVENANCE_KIND_IMPORT);
    prov.set_id("elf");
    prov.set_session(req.provenance().session());
    prov.set_tool(req.provenance().tool());
    std::vector<pb::Assertion> entries;
    for (auto [addr, sym] : {std::pair{fake::kEntry, "entry"}, std::pair{fake::kMain, "main"}}) {
      pb::Assertion a;
      a.set_op(pb::ASSERTION_OP_ASSERT);
      a.mutable_key()->set_program_id(id);
      a.mutable_key()->set_kind(pb::FACT_KIND_NAME);
      a.mutable_key()->mutable_address()->set_offset(addr);
      *a.mutable_body()->mutable_rename()->mutable_target()->mutable_address() = A(addr);
      a.mutable_body()->mutable_rename()->set_name(sym);
      entries.push_back(std::move(a));
    }
    CommitLocked(p, prov, pb::CHANGE_CAUSE_IMPORT, std::move(entries),
                 [&](ProjectState &s) { s.programs.push_back(meta); });
    SetSnapshot(*p.head, p.head->revision, resp.mutable_snapshot());
    FillProgramInfo(*p.head, *p.head->program(id), resp.mutable_program());
    if (req.options().analyze())
      resp.set_analysis_job_id(RunJobLocked(p, id, {"disasm", "functions", "xrefs"}).job_id());
  }

  // Fake analysis jobs complete immediately; subscribers still see the
  // RUNNING and SUCCEEDED progress events a real job would send.
  pb::AnalysisJob RunJobLocked(Project &p, const std::string &program, const std::vector<std::string> &analyzers) {
    pb::AnalysisJob job;
    job.set_job_id("job-" + std::to_string(core_->next_job_++));
    job.set_program_id(program);
    for (const auto &a : analyzers) job.add_analyzers(a);
    *job.mutable_started_at() = TimeUtil::GetCurrentTime();
    job.set_state(pb::ANALYSIS_STATE_RUNNING);
    job.set_phase("analyzing");
    job.set_progress(0);
    Broadcast(p, job);
    job.set_state(pb::ANALYSIS_STATE_SUCCEEDED);
    job.set_phase("done");
    job.set_progress(1);
    job.set_first_revision(p.head->revision);
    job.set_last_revision(p.head->revision);
    *job.mutable_finished_at() = TimeUtil::GetCurrentTime();
    Broadcast(p, job);
    p.jobs.push_back(job);
    return job;
  }

  void Broadcast(Project &p, const pb::AnalysisJob &job) {
    for (auto &s : p.subscribers) {
      if (!s.programs.empty() && !s.programs.count(job.program_id())) continue;
      pb::SubscribeResponse ev;
      *ev.mutable_analysis()->mutable_job() = job;
      s.sink->Send(std::move(ev));
    }
  }

  // Appends entries as one revision, recomputes effective state, records
  // and broadcasts the revision event. Returns the event (with assertions).
  pb::RevisionEvent CommitLocked(Project &p, const pb::Provenance &prov, pb::ChangeCause cause,
                                 std::vector<pb::Assertion> entries,
                                 const std::function<void(ProjectState &)> &mutate = {}) {
    const ProjectState &prev = *p.head;
    auto next = std::make_shared<ProjectState>(prev);
    next->revision = prev.revision + 1;
    if (mutate) mutate(*next);
    auto now = TimeUtil::GetCurrentTime();
    std::size_t first_new = next->log.size();
    for (auto &a : entries) {
      a.set_seq(next->log.size() + 1);
      a.set_revision(next->revision);
      *a.mutable_time() = now;
      *a.mutable_provenance() = prov;
      next->log.push_back(std::move(a));
    }
    Recompute(*next);

    pb::RevisionEvent ev;
    ev.set_revision(next->revision);
    ev.set_previous_revision(prev.revision);
    ev.set_cause(cause);
    *ev.mutable_provenance() = prov;
    for (std::size_t i = first_new; i < next->log.size(); ++i) {
      ev.add_assertion_seqs(next->log[i].seq());
      *ev.add_assertions() = next->log[i];
    }
    // Changed keys: any key whose winner differs between the two revisions.
    std::map<std::string, pb::FactKey> changed;
    for (const auto &[k, idx] : next->winners) {
      auto it = prev.winners.find(k);
      if (it == prev.winners.end() || it->second != idx) changed.emplace(k, next->log[idx].key());
    }
    for (const auto &[k, idx] : prev.winners)
      if (!next->winners.count(k)) changed.emplace(k, prev.log[idx].key());
    std::set<std::string> seen;
    std::map<std::string, std::unique_ptr<View>> views;
    for (const auto &[k, key] : changed) {
      *ev.add_changed_keys() = key;
      const ProgramMeta *prog = next->program(key.program_id());
      if (!prog) continue;
      auto &view = views[prog->id];
      if (!view) view = std::make_unique<View>(*next, *prog);
      std::vector<pb::InvalidatedQuery> qs;
      Invalidate(*view, key, qs);
      for (auto &q : qs)
        if (seen.insert(q.SerializeAsString()).second) *ev.add_invalidated() = std::move(q);
    }
    if (next->programs.size() != prev.programs.size())
      for (const auto &prog : next->programs)
        if (!prev.program(prog.id)) ev.add_invalidate_all_programs(prog.id);

    p.head = next;
    p.history[next->revision] = next;
    p.events[next->revision] = ev;
    while (p.history.size() > core_->options_.retained_revisions) p.history.erase(p.history.begin());
    while (p.events.size() > core_->options_.retained_revisions) p.events.erase(p.events.begin());
    for (auto &s : p.subscribers) {
      pb::SubscribeResponse out;
      *out.mutable_revision() = FilterEvent(ev, s);
      s.sink->Send(std::move(out));
    }
    core_->head_changed_.notify_all();
    return ev;
  }

  std::shared_ptr<Core> core_;
};

}  // namespace

std::unique_ptr<Backend> MakeFakeBackend(FakeBackendOptions options) {
  return std::make_unique<FakeBackend>(std::move(options));
}

}  // namespace revkit::api
