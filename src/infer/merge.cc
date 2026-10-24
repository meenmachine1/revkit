#include "merge.h"

#include <algorithm>
#include <functional>
#include <map>
#include <set>

namespace revkit::infer {

namespace {

struct Param {
  VType type;
  std::uint8_t size = 0;
};

// A narrower view of an integer or unknown value: a callee that returns a
// 4-byte value zero-extended into RAX returns a 4-byte value.
VType narrow(const VType &t, std::uint8_t size) {
  if (t.meta == Meta::int_) return VType::integer(size, t.sign);
  if (t.meta == Meta::unknown) return VType::unknown(size);
  return t;
}

// A value in a floating-point register whose type is unknown: a vector
// register's low 4 or 8 bytes hold a float or a double.
VType float_of(std::uint8_t size) { return VType::floating(size == 4 ? 4 : 8); }

bool is_scalar(const VType &t) {
  return t.meta == Meta::int_ || t.meta == Meta::unknown || t.meta == Meta::bool_ || t.meta == Meta::char_;
}

// A parameter's type, narrowed to what the function uses of it: an int
// passed in a 64-bit register is truncated by every use, or by some 32-bit
// operation (RISC-V passes it sign-extended).
VType param_type(const Slot &s, const Abi &) {
  VType t = s.type;
  if (!is_scalar(t)) return t;
  if (s.used > 0 && s.used < s.size) return narrow(t, s.used);
  if (s.narrowest == 4 && s.size == 8) return narrow(t, 4);
  return t;
}

// Whether a caller's type for a value should refine the callee's.
bool refines(const VType &have, const VType &caller, std::uint8_t size) {
  if (caller.meta == Meta::unknown) return false;
  // A 32-bit pointer the caller passes in a narrower parameter (a 2-byte
  // block number) isn't what the callee takes.
  if (caller.meta == Meta::pointer && caller.size == 4 && size != 0 && caller.size > size) return false;
  if (caller.meta == Meta::pointer)
    return have.meta != Meta::pointer || have.target().meta == Meta::unknown || have.target().meta == Meta::void_ ||
           (have.target().meta == Meta::code && have.target().pointee.empty() && caller.target().meta == Meta::code);
  if (caller.size != size) return false;
  if (caller.meta == Meta::char_ || caller.meta == Meta::float_ || caller.meta == Meta::bool_)
    return have.meta == Meta::unknown || have.meta == Meta::int_;
  return have.meta == Meta::unknown;
}

}  // namespace

Prototype merge(const Abi *abi, const Evidence &ev, const DataOrg &org) {
  Prototype p;
  p.source = "merged";
  const Observation *self0 = ev.self0 != nullptr ? ev.self0 : ev.self;
  const Observation *self = ev.self != nullptr ? ev.self : ev.self0;
  if (abi == nullptr || !ev.interprocedural) {
    p.source = "self";
    if (self != nullptr) {
      for (const Slot &s : self->params) p.params.push_back(s.type);
      if (self->ret) p.ret = self->ret->type;
    }
    return p;
  }

  // ---- parameters, by argument position ----
  // Round 0 sees a register a call passes through to an unknown callee as
  // a parameter (too many); a later round, whose callees are locked, sees
  // one a callee with a parameter too many reads (also too many), and one
  // that tail-calls a function unknown at round 0 sees none there (too
  // few). So: the positions both agree on, or the one that sees any.
  std::set<ArgPos> later;
  if (self != nullptr && self != self0)
    for (const Slot &s : self->params)
      if (auto pos = arg_position(*abi, s)) later.insert(*pos);
  std::map<ArgPos, Param> params;
  std::vector<VType> unplaced;  // parameters outside the table, in order
  const Observation *storage = self0;
  if (self0 != nullptr && self0->params.empty() && self != nullptr && !self->params.empty()) storage = self;
  if (storage != nullptr) {
    for (const Slot &s : storage->params) {
      auto pos = arg_position(*abi, s);
      if (!pos) {
        unplaced.push_back(s.type);
        continue;
      }
      if (storage == self0 && self != nullptr && self != self0 && !self->params.empty() && !later.contains(*pos))
        continue;
      params[*pos] = {param_type(s, *abi), s.size};
    }
  }
  // Types from this round's view of the function.
  if (self != nullptr && self != self0) {
    for (const Slot &s : self->params) {
      auto pos = arg_position(*abi, s);
      if (!pos) continue;
      auto it = params.find(*pos);
      if (it == params.end() || s.size > it->second.size) continue;
      VType t = param_type(s, *abi);
      Param &q = it->second;
      if (t.size == q.type.size || t.meta == Meta::pointer) q.type = join(t, q.type);
    }
  }

  // Parameters it only passes on. Round 0, whose callees weren't locked,
  // doesn't see a register the function never writes go to a call (the
  // decompiler takes only written registers as an unknown callee's
  // arguments): luaL_checklstring's `len`, passed straight to
  // lua_tolstring, isn't there. A later round, with the callee locked,
  // sees it, and it is the function's parameter when the callee reads it
  // itself, not when it is a parameter too many the callee asks for.
  if (self != nullptr && self0 != nullptr && self != self0 && ev.callee_reads) {
    std::vector<std::pair<ArgPos, std::size_t>> passed;
    for (std::size_t i = 0; i < self->params.size(); ++i) {
      const Slot &s = self->params[i];
      auto pos = arg_position(*abi, s);
      // Integer registers only: a float register a callee reads at round 0
      // is as often its own vector code's.
      if (s.reg.empty() || !pos || pos->cls != 0 || params.contains(*pos)) continue;
      bool read = false;
      for (const CallSite &c : self->calls) {
        if (c.target == 0 || !c.locked) continue;
        for (std::size_t j = 0; j < c.args.size() && !read; ++j)
          read = c.args[j].from_param == static_cast<std::int32_t>(i) && ev.callee_reads(c.target, j, c.args[j]);
        if (read) break;
      }
      if (read) passed.emplace_back(*pos, i);
    }
    std::sort(passed.begin(), passed.end());
    // Every integer argument register read is a register save area's
    // pattern (a tail call into a variadic function, whose own code the
    // flow then takes in), not parameters passed on: none of them then.
    const int last = static_cast<int>(abi->int_regs.size()) - 1;
    auto reaches_last = [&](const Observation *o) {
      for (const Slot &s : o->params)
        if (auto pos = arg_position(*abi, s); pos && pos->cls == 0 && pos->index >= last) return true;
      return false;
    };
    if (reaches_last(self0) || reaches_last(self)) passed.clear();
    for (const auto &[pos, i] : passed) {
      // No holes: the convention assigns parameters in order.
      const bool follows = pos.index == 0 || params.contains(ArgPos{pos.cls, pos.index - 1}) ||
                           (abi->positional && (params.contains(ArgPos{0, pos.index - 1}) ||
                                                params.contains(ArgPos{1, pos.index - 1})));
      if (follows) params[pos] = {param_type(self->params[i], *abi), self->params[i].size};
    }
  }

  // Registers the decompiler drops the use of (ARM's `msr cpsr_c, r0`: the
  // state it restores shows in no C value; its callers, unlocked, then
  // pass nothing either), on 32-bit targets: an integer argument register
  // the entry's straight-line code reads before writing it, other than to
  // store it (a push), is a parameter, in order.
  if (org.pointer_size == 4 && self0 != nullptr && !self0->entry_reads.empty()) {
    for (std::size_t i = 0; i < abi->int_regs.size(); ++i) {
      const ArgPos pos{0, static_cast<int>(i)};
      if (params.contains(pos)) continue;
      const std::string &reg = abi->int_regs[i];
      if (std::find(self0->entry_reads.begin(), self0->entry_reads.end(), reg) == self0->entry_reads.end()) break;
      if (i > 0 && !params.contains(ArgPos{0, static_cast<int>(i) - 1})) break;
      params[pos] = {VType::unknown(org.pointer_size), org.pointer_size};
    }
  }

  // Parameters no caller passes, on 32-bit targets: the decompiler takes
  // a stack word an ARM function pushes for alignment (`push {r3, lr}`)
  // and passes to an unknown callee for a parameter, and a register its
  // code only passes on for one too, and every caller of a function
  // locked with them shows an `in_r3` or an `extraout_r2`. The last
  // parameters (stack words, then registers, from the end) that no more
  // than half of two or more callers set before the call go (one that
  // sets it may have left a value there for itself); a caller passing its
  // own parameter on there counts as setting it (the decompiler doesn't
  // count a register a call passes through unchanged as an unknown
  // callee's argument, but does at a call locked to the previous
  // prototype).
  if (org.pointer_size == 4 && ev.unlocked.size() >= 2 && !params.empty()) {
    auto passes = [&](const ArgPos &pos) {
      std::size_t n = 0;
      for (const CallSite *c : ev.unlocked)
        for (const Slot &a : c->args)
          if (auto ap = arg_position(*abi, a); ap && *ap == pos) {
            ++n;
            break;
          }
      // Passed on: a caller's own parameter, unchanged, at a call locked
      // to the previous prototype.
      for (const CallSite *c : ev.current)
        for (const Slot &a : c->args)
          if (auto ap = arg_position(*abi, a); ap && *ap == pos && a.from_param >= 0) {
            ++n;
            break;
          }
      return n * 2 > ev.unlocked.size();
    };
    std::vector<ArgPos> order;
    for (const auto &[pos, q] : params) order.push_back(pos);
    std::sort(order.begin(), order.end(),
              [&](const ArgPos &a, const ArgPos &b) { return order_key(*abi, a) > order_key(*abi, b); });
    // A register the entry's code reads as a value (not a push) stays.
    auto read_at_entry = [&](const ArgPos &pos) {
      return pos.cls == 0 && static_cast<std::size_t>(pos.index) < abi->int_regs.size() &&
             std::find(self0->entry_reads.begin(), self0->entry_reads.end(), abi->int_regs[pos.index]) !=
                 self0->entry_reads.end();
    };
    for (const ArgPos &pos : order) {
      if (pos.cls == 1 || passes(pos) || (self0 != nullptr && read_at_entry(pos)))
        break;
      params.erase(pos);
    }
  }

  // ---- varargs ----
  // A variadic function saves the argument registers its named
  // parameters don't use (the register save area, or Windows' home
  // slots) before anything else touches them: a run of saved argument
  // registers that ends at the last one, starting after the named ones.
  // On System V x86-64 it also reads AL. The decompiler takes the saved
  // registers for parameters, untyped.
  bool varargs = false;
  int named = -1;
  if (self0 != nullptr) {
    std::vector<int> saved;  // integer argument register indices, in store order
    for (const std::string &r : self0->spills)
      for (std::size_t i = 0; i < abi->int_regs.size(); ++i)
        if (r == abi->int_regs[i] && std::find(saved.begin(), saved.end(), static_cast<int>(i)) == saved.end())
          saved.push_back(static_cast<int>(i));
    std::vector<int> sorted = saved;
    std::sort(sorted.begin(), sorted.end());
    const int last = static_cast<int>(abi->int_regs.size()) - 1;
    const bool run = sorted.size() >= 2 && sorted.back() == last &&
                     sorted.back() - sorted.front() + 1 == static_cast<int>(sorted.size());
    const int first = run ? sorted.front() : -1;
    if (abi->al_varargs && self0->reads_al) varargs = true;
    if (run) {
      if (abi->positional) {
        // Windows: a run after the first slot, or saved last-to-first.
        if (first >= 1 || (!saved.empty() && saved.front() == last)) varargs = true;
      } else if (first >= 1 || !abi->al_varargs) {
        varargs = true;
      }
    }
    if (varargs && first >= 1) named = first;
  }
  if (varargs) {
    if (named < 0) {
      // Every argument register saved (unoptimized code saves the named
      // ones too): the named ones are those the function uses as
      // something, up to the last.
      named = 0;
      for (const auto &[pos, q] : params)
        if (pos.cls == 0 && q.type.meta != Meta::unknown) named = std::max(named, pos.index + 1);
    }
    for (auto it = params.begin(); it != params.end();) {
      // Float registers are saved too and read as va_arg's doubles: named
      // float parameters before `...` are rare enough to drop them all.
      const bool drop = (it->first.cls == 0 && it->first.index >= named) || it->first.cls == 1 || it->first.cls == 2;
      it = drop ? params.erase(it) : std::next(it);
    }
    for (int i = 0; i < named; ++i)
      params.try_emplace(ArgPos{0, i}, Param{VType::unknown(org.pointer_size), org.pointer_size});
    p.varargs = true;
  }

  // Types the callers' values have where they pass them.
  const std::vector<const CallSite *> &typed = ev.current.empty() ? ev.unlocked : ev.current;
  // Where ints and pointers are one size (32-bit), a pointer some caller
  // passes is a pointer only if more callers pass one than an integer
  // there: one caller's mistyped value (a size computed from pointers, a
  // field typed by another guess) would otherwise make memcpy's length a
  // `char *`, and every caller's constant a cast.
  std::map<ArgPos, std::pair<int, int>> votes;  // position -> (pointers, integers)
  if (org.pointer_size == 4)
    for (const CallSite *c : typed)
      for (const Slot &s : c->args)
        if (auto pos = arg_position(*abi, s)) {
          if (s.type.meta == Meta::pointer) ++votes[*pos].first;
          else if (s.type.meta == Meta::int_ || s.type.meta == Meta::char_ || s.type.meta == Meta::bool_ ||
                   (!s.constants.empty() && !s.data_address && !s.code_address))
            ++votes[*pos].second;
        }
  for (const CallSite *c : typed) {
    for (const Slot &s : c->args) {
      auto pos = arg_position(*abi, s);
      if (!pos) continue;
      auto it = params.find(*pos);
      if (it == params.end()) continue;
      Param &q = it->second;
      if (org.pointer_size == 4 && s.type.meta == Meta::pointer && q.type.meta != Meta::pointer) {
        const auto [ptrs, ints] = votes[*pos];
        if (ptrs <= ints) continue;
      }
      if (refines(q.type, s.type, q.size)) q.type = join(s.type, q.type);
    }
  }
  // A caller passing the address of static data or of a function: a
  // pointer (the decompiler types such constants by how the callee uses
  // them, which it doesn't know).
  for (const auto *sites : {&ev.unlocked, &ev.current})
    for (const CallSite *c : *sites)
      for (const Slot &s : c->args) {
        if (!s.data_address && !s.code_address) continue;
        auto pos = arg_position(*abi, s);
        if (!pos) continue;
        auto it = params.find(*pos);
        if (it == params.end() || it->second.size != org.pointer_size) continue;
        VType &t = it->second.type;
        bool function_address = s.code_address && !s.data_address;
        if (function_address && org.pointer_size == 4 && ev.is_function &&
            std::none_of(s.constants.begin(), s.constants.end(), ev.is_function)) {
          // On a 32-bit target a raw image is one read/write/execute block,
          // where strings and tables are too: only a function's entry is a
          // function's address, and an address past the first 64 KiB is
          // data's (below it, sizes and offsets land in code too often).
          if (std::none_of(s.constants.begin(), s.constants.end(), [](std::uint64_t c) { return c >= 0x10000; }))
            continue;
          function_address = false;
        }
        if (function_address) {
          // A function's address: a pointer to a function of its prototype.
          VType code = VType::code_type();
          if (ev.proto_of)
            for (std::uint64_t a : s.constants)
              if (auto fp = ev.proto_of(a)) {
                code = VType::code_of(*fp);
                break;
              }
          const VType fn = VType::pointer_to(code, org.pointer_size);
          if (t.meta == Meta::unknown || t.meta == Meta::int_ || (t.is_pointer() && t.target().meta != Meta::code) ||
              (t.is_pointer() && t.target().meta == Meta::code && t.target().pointee.empty()))
            t = fn;
        } else if (t.meta == Meta::unknown || t.meta == Meta::int_) {
          t = VType::pointer_to(VType::unknown(1), org.pointer_size);
        }
      }
  std::vector<std::pair<int, VType>> ordered;
  for (auto &[pos, q] : params)
    if (pos.cls == 1 && q.type.meta == Meta::unknown) q.type = float_of(q.type.size);
  for (const auto &[pos, q] : params) ordered.emplace_back(order_key(*abi, pos), q.type);
  std::sort(ordered.begin(), ordered.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
  for (auto &[k, t] : ordered) p.params.push_back(std::move(t));
  for (VType &t : unplaced) p.params.push_back(std::move(t));

  // ---- return value ----
  int used = 0;
  std::uint8_t used_size = 0;
  VType used_type;
  for (const CallSite *c : ev.unlocked) {
    if (!c->ret_used) continue;
    ++used;
    used_size = std::max(used_size, c->ret_type.size);
    used_type = join(used_type, c->ret_type);
  }
  if (self0 != nullptr && self0->ret) {
    p.ret = self0->ret->type;
    if (float_return(*abi, self0->ret->reg) && p.ret.meta == Meta::unknown)
      p.ret = float_of(self0->ret_natural > 0 ? self0->ret_natural : self0->ret->size);
    if (self != nullptr && self->ret && self->ret->size == self0->ret->size) p.ret = join(self->ret->type, p.ret);
    // A value zero- or sign-extended into a wider return register is as
    // wide as it was (an int in RAX), unless callers read all of it.
    const std::uint8_t natural = self0->ret_natural;
    if (natural > 0 && natural < self0->ret->size && is_scalar(p.ret) && !(used > 0 && used_size > natural))
      p.ret = narrow(p.ret, natural);
    else if (used > 0 && used_size > 0 && used_size < self0->ret->size && is_scalar(p.ret))
      p.ret = narrow(p.ret, used_size);
  } else if (used > 0 && used * 2 > static_cast<int>(ev.unlocked.size())) {
    // The function leaves a value most callers read (a tail call's result).
    p.ret = used_type.meta == Meta::unknown && used_size == 0 ? VType::unknown(org.pointer_size) : used_type;
  } else if (ev.tail_ret) {
    // It returns what it tail-calls returns.
    p.ret = *ev.tail_ret;
  }
  // A function's address.
  if (self0 != nullptr && !self0->ret_code.empty() && !p.ret.is_void() && self0->ret->size == org.pointer_size) {
    VType code = VType::code_type();
    if (ev.proto_of)
      for (std::uint64_t a : self0->ret_code)
        if (auto fp = ev.proto_of(a)) {
          code = VType::code_of(*fp);
          break;
        }
    p.ret = VType::pointer_to(code, org.pointer_size);
  }
  // An element of a function-pointer table.
  if (self0 != nullptr && !self0->ret_loaded.empty() && !p.ret.is_void() && self0->ret->size == org.pointer_size &&
      ev.table_proto)
    for (std::uint64_t a : self0->ret_loaded)
      if (auto fp = ev.table_proto(a)) {
        p.ret = VType::pointer_to(VType::code_of(*fp), org.pointer_size);
        break;
      }
  // A static buffer's or string's address.
  if (self0 != nullptr && self0->ret_address && !p.ret.is_void() && p.ret.meta != Meta::pointer &&
      self0->ret->size == org.pointer_size)
    p.ret = VType::pointer_to(VType::unknown(1), org.pointer_size);
  // Return types the callers' values have where they read them: told the
  // previous prototype (current) or not (unlocked, pointers only: an
  // unlocked call's integer result is only as wide as the register).
  for (const CallSite *c : ev.current)
    if (c->ret_used && !p.ret.is_void() && refines(p.ret, c->ret_type, p.ret.size)) p.ret = join(c->ret_type, p.ret);
  for (const CallSite *c : ev.unlocked)
    if (c->ret_used && !p.ret.is_void() && c->ret_type.meta == Meta::pointer && refines(p.ret, c->ret_type, p.ret.size))
      p.ret = join(c->ret_type, p.ret);
  return p;
}

std::optional<Prototype> family_vote(const Prototype &own, const std::vector<Prototype> &members) {
  if (members.size() < 2) return std::nullopt;
  std::map<std::size_t, int> arity;
  int returns = 0, varargs = 0;
  for (const Prototype &m : members) {
    ++arity[m.params.size()];
    returns += !m.ret.is_void();
    varargs += m.varargs;
  }
  std::size_t n = 0;
  int best = -1;
  for (const auto &[a, count] : arity)
    if (count >= best) {
      best = count;
      n = a;
    }
  if (best * 2 < static_cast<int>(members.size())) return std::nullopt;
  auto vote = [&](auto get, const VType &fallback) {
    std::vector<std::pair<VType, int>> counts;
    for (const Prototype &m : members) {
      const VType *t = get(m);
      if (t == nullptr || t->meta == Meta::unknown) continue;
      auto it = std::find_if(counts.begin(), counts.end(), [&](const auto &c) { return c.first == *t; });
      if (it == counts.end()) counts.emplace_back(*t, 1);
      else ++it->second;
    }
    const VType *pick = &fallback;
    int top = 0;
    for (const auto &[t, c] : counts)
      if (c > top) {
        top = c;
        pick = &t;
      }
    // Signedness as Ghidra's type lattice orders it: signed is the default
    // for arithmetic, unsigned needs evidence, so one member's unsigned
    // view of an integer of the chosen size wins.
    if (pick->meta == Meta::int_ && pick->sign != Sign::is_unsigned)
      for (const auto &[t, c] : counts)
        if (t.meta == Meta::int_ && t.size == pick->size && t.sign == Sign::is_unsigned) return t;
    return *pick;
  };
  Prototype p;
  p.source = "family";
  p.varargs = varargs * 2 > static_cast<int>(members.size());
  if (returns * 2 > static_cast<int>(members.size()))
    p.ret = vote([](const Prototype &m) { return m.ret.is_void() ? nullptr : &m.ret; },
                 own.ret.is_void() ? VType::unknown(8) : own.ret);
  for (std::size_t i = 0; i < n; ++i) {
    const VType fallback = i < own.params.size() ? own.params[i] : VType::unknown(8);
    p.params.push_back(vote([&](const Prototype &m) { return i < m.params.size() ? &m.params[i] : nullptr; }, fallback));
  }
  return p;
}

Prototype join(const Prototype &prev, const Prototype &next) {
  if (prev.params.size() != next.params.size() || prev.varargs != next.varargs) return next;
  Prototype out = next;
  for (std::size_t i = 0; i < out.params.size(); ++i) out.params[i] = infer::join(prev.params[i], next.params[i]);
  if (!prev.ret.is_void() && !next.ret.is_void()) out.ret = infer::join(prev.ret, next.ret);
  return out;
}

Prototype finalize(const Prototype &p, const DataOrg &org, bool keep_return_width, bool typed_loads) {
  const Priors &pr = SigDb::priors(org);
  std::function<VType(const VType &, bool)> spell = [&](const VType &t, bool ret) -> VType {
    switch (t.meta) {
      case Meta::unknown:
        if (ret && keep_return_width) {
          auto it = pr.returns.find(t.size);
          return it != pr.returns.end() ? it->second : t;
        }
        return ret ? pr.unknown_return(t.size) : pr.unknown_param(t.size);
      case Meta::int_:
        if (!ret || t.sign == Sign::unknown) return ret ? pr.integer_return(t.size) : pr.integer_param(t.size);
        return t;
      case Meta::bool_:
        // The decompiler's bool is a 0/1 value; C returns those as int.
        return ret ? pr.unknown_return(4) : t;
      case Meta::pointer: {
        const VType &to = t.target();
        if (to.meta == Meta::code && !to.pointee.empty()) {
          VType code = to;
          for (std::size_t i = 0; i < code.pointee.size(); ++i) code.pointee[i] = spell(code.pointee[i], i == 0);
          return VType::pointer_to(code, t.size);
        }
        // A returned void *: mostly an allocator's result handed on, which
        // C code returns as the type it fills (char * in the headers far
        // more often than void *).
        if (ret && to.meta == Meta::void_ && pr.pointee.meta != Meta::unknown) return VType::pointer_to(pr.pointee, t.size);
        if (to.meta == Meta::unknown) {
          if (to.size > 1) return VType::pointer_to(pr.unknown_param(to.size), t.size);
          // Only reached at offsets (a structure's fields): `char` would
          // type each byte load against its instruction.
          if (typed_loads) return VType::pointer_to(VType::void_type(), t.size);
          if (pr.pointee.meta != Meta::unknown) return VType::pointer_to(pr.pointee, t.size);
        }
        // Bytes: the decompiler's signedness comes from the loads compilers
        // pick; C strings are char. Unless the loads are typed by their
        // instructions, as the source's C has them.
        if (!typed_loads && to.meta == Meta::int_ && to.size == 1 && pr.pointee.meta == Meta::char_)
          return VType::pointer_to(pr.pointee, t.size);
        return t;
      }
      default:
        return t;
    }
  };
  Prototype out = p;
  out.ret = spell(p.ret, true);
  for (VType &t : out.params) t = spell(t, false);
  return out;
}

}  // namespace revkit::infer
