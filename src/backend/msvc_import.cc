#include "msvc_import.h"

#include "listing_edit.h"
#include "program.h"
#include "queries.h"
#include "type_record.h"

#include "revkit/analysis/units.h"
#include "revkit/demangle/demangle.h"
#include "revkit/types/describe.h"

#include <algorithm>
#include <set>

namespace revkit::backend {

namespace {

using facts::FactKind;
namespace an = analysis;

// The name the file or the debug info gives each address: loader symbols
// (demangled as the demangler analysis names them), exports and the debug
// info's functions and globals.
std::map<std::uint64_t, std::string> KnownNames(const Program &program, const std::vector<DebugFacts> &debug) {
  std::map<std::uint64_t, std::string> out;
  auto add = [&](std::uint64_t a, const std::string &name) {
    if (name.empty()) return;
    std::string shown = name;
    if (demangle::detect(name) != demangle::Scheme::None)
      if (auto d = demangle::parse(name)) shown = d->name;
    out.emplace(a, shown);
  };
  for (const DebugFacts &d : debug)
    for (const auto &[a, n] : d.names) out.emplace(a, n);
  const loader::Image &image = program.image();
  for (const loader::Symbol &s : image.symbols)
    if (s.defined && s.value != 0 && s.type != loader::SymbolType::section && s.type != loader::SymbolType::file)
      add(s.value, s.name);
  for (const loader::Export &e : image.exports)
    if (e.forwarder.empty() && e.address != 0) add(e.address, e.name);
  return out;
}

// What the PDB says a class is: the type a named class or struct key
// ("class geo::Rect", "struct geo::Rect") has among its records.
class DebugClasses {
 public:
  explicit DebugClasses(const std::vector<DebugFacts> &debug) {
    for (const DebugFacts &d : debug) {
      if (d.source != "pdb") continue;
      for (const auto &[hash, record] : d.records) {
        try {
          TypeRecord r = DecodeTypeRecord(record);
          const auto *a = r.type.as<types::AggregateType>();
          if (a == nullptr || a->name.empty() || !a->complete || a->kind == types::AggregateKind::Union) continue;
          by_name_.emplace(a->name, hash);
          records_ = &d.records;
        } catch (const std::exception &) {
        }
      }
    }
  }
  // The class's type interned into `store`, or invalid.
  types::TypeId get(const std::string &name, types::TypeStore &store) const {
    auto it = by_name_.find(name);
    if (it == by_name_.end() || records_ == nullptr) return {};
    // The records the class reaches.
    std::map<std::string, std::string> closure;
    std::vector<std::string> work{it->second};
    while (!work.empty()) {
      std::string h = std::move(work.back());
      work.pop_back();
      if (closure.contains(h)) continue;
      auto r = records_->find(h);
      if (r == records_->end()) continue;
      closure.emplace(h, r->second);
      for (const std::string &ref : DecodeTypeRecord(r->second).refs) work.push_back(ref);
    }
    std::map<std::string, types::TypeId> ids = InternRecords(closure, store);
    auto id = ids.find(it->second);
    return id == ids.end() ? types::TypeId() : id->second;
  }

 private:
  std::map<std::string, std::string> by_name_;
  const std::map<std::string, std::string> *records_ = nullptr;
};

// How far past `this` a method reads or writes, from its p-code: a walk
// of its first instructions (both ways at each branch) that tracks which
// registers hold `this` plus a constant (copies, adds; a call keeps only
// the callee-saved ones) and the loads and stores through them. 0 when
// nothing is found or the language isn't x86 or AArch64.
class ThisExtent {
 public:
  explicit ThisExtent(const Program &program) : program_(program) {
    const std::string &lang = program.language().id();
    const char *self = nullptr;
    std::vector<std::string> saved;
    if (lang.starts_with("x86:LE:64")) {
      self = "RCX";
      saved = {"RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15", "RSP"};
    } else if (lang.starts_with("x86:LE:32")) {
      self = "ECX";
      saved = {"EBX", "EBP", "ESI", "EDI", "ESP"};
    } else if (lang.starts_with("AARCH64")) {
      self = "x0";
      for (int i = 19; i <= 29; ++i) saved.push_back("x" + std::to_string(i));
      saved.push_back("sp");
    } else {
      return;
    }
    auto lifter = program.lifter();
    for (const lift::RegisterDef &r : lifter->registers()) {
      if (r.space != "register") continue;
      if (r.name == self) this_ = {r.offset, r.size};
      for (const std::string &n : saved)
        if (r.name == n) saved_.push_back({r.offset, r.size});
    }
  }

  std::uint64_t operator()(std::uint64_t entry) const {
    if (this_.second == 0) return 0;
    auto lifter = program_.lifter();
    using Key = std::pair<std::string, std::uint64_t>;  // space, offset
    struct Value {
      std::uint32_t size;
      std::int64_t delta;
    };
    using State = std::map<Key, Value>;
    std::uint64_t reach = 0;
    std::vector<std::pair<std::uint64_t, State>> work{{entry, State{{{"register", this_.first}, {this_.second, 0}}}}};
    std::set<std::uint64_t> visited;
    std::size_t budget = 400;
    while (!work.empty() && budget > 0) {
      auto [at, state] = std::move(work.back());
      work.pop_back();
      while (budget-- > 0 && visited.insert(at).second && program_.executable(at)) {
        std::optional<lift::Instruction> insn = lifter->lift_pcode(at);
        if (!insn || insn->length == 0) break;
        bool ends = false;
        auto value = [&](const lift::Varnode &v) -> std::optional<std::int64_t> {
          auto it = state.find({v.space, v.offset});
          if (it == state.end() || it->second.size != v.size) return std::nullopt;
          return it->second.delta;
        };
        auto kill = [&](const lift::Varnode &v) {
          for (auto it = state.begin(); it != state.end();) {
            const bool overlap = it->first.first == v.space && it->first.second < v.offset + v.size &&
                                 v.offset < it->first.second + it->second.size;
            it = overlap ? state.erase(it) : std::next(it);
          }
        };
        auto access = [&](const lift::Varnode &addr, std::uint32_t size) {
          if (auto d = value(addr); d && *d >= 0 && *d < (1 << 20))
            reach = std::max<std::uint64_t>(reach, static_cast<std::uint64_t>(*d) + size);
        };
        for (const lift::PcodeOp &op : insn->pcode) {
          if (op.opcode == "LOAD" && op.inputs.size() == 2 && op.output) access(op.inputs[1], op.output->size);
          if (op.opcode == "STORE" && op.inputs.size() == 3) access(op.inputs[1], op.inputs[2].size);
          std::optional<std::int64_t> result;
          if (op.output) {
            if (op.opcode == "COPY" && op.inputs.size() == 1) {
              result = value(op.inputs[0]);
            } else if ((op.opcode == "INT_ADD" || op.opcode == "INT_SUB") && op.inputs.size() == 2) {
              auto a = value(op.inputs[0]);
              const lift::Varnode &k = op.inputs[1];
              if (a && k.space == "const") {
                const std::int64_t c = static_cast<std::int64_t>(k.offset << (64 - 8 * k.size)) >> (64 - 8 * k.size);
                result = op.opcode == "INT_ADD" ? *a + c : *a - c;
              }
            }
            kill(*op.output);
            if (result) state[{op.output->space, op.output->offset}] = {op.output->size, *result};
          }
          if (op.opcode == "CALL" || op.opcode == "CALLIND") {
            // Only callee-saved registers survive a call.
            for (auto it = state.begin(); it != state.end();) {
              const bool keep = it->first.first == "register" &&
                                std::any_of(saved_.begin(), saved_.end(), [&](const auto &r) {
                                  return r.first == it->first.second && r.second == it->second.size;
                                });
              it = keep ? std::next(it) : state.erase(it);
            }
          }
          if (op.opcode == "RETURN" || op.opcode == "BRANCHIND") ends = true;
          if ((op.opcode == "BRANCH" || op.opcode == "CBRANCH") && !op.inputs.empty() &&
              op.inputs[0].space != "const") {
            work.push_back({op.inputs[0].offset, state});
            if (op.opcode == "BRANCH") ends = true;
          }
        }
        // Temporaries don't outlive their instruction.
        for (auto it = state.begin(); it != state.end();) it = it->first.first == "unique" ? state.erase(it) : std::next(it);
        if (ends) break;
        at += insn->length;
      }
    }
    return reach;
  }

 private:
  const Program &program_;
  std::pair<std::uint64_t, std::uint32_t> this_{0, 0};
  std::vector<std::pair<std::uint64_t, std::uint32_t>> saved_;
};

pb::AssertionBody RenameBody(std::uint64_t a, const std::string &name) {
  pb::AssertionBody body;
  body.mutable_rename()->mutable_target()->mutable_address()->set_offset(a);
  body.mutable_rename()->set_name(name);
  return body;
}

}  // namespace

namespace {

// One pass's defs as assertions.
AnalysisFacts Collect(const Program &program, msvc::Markup &m, const std::string &pass,
                      const std::map<std::uint64_t, std::string> &known) {
  AnalysisFacts out;
  out.source = pass;
  const loader::Image &image = program.image();
  types::TypeStore &st = m.store;
  const std::uint8_t ptr = static_cast<std::uint8_t>(image.bits / 8);

  // The records every used type reaches.
  std::set<types::TypeId> roots;
  std::map<std::string, std::string> records;

  for (const msvc::DataDef &d : m.data) {
    if (d.pass != pass) continue;
    an::UnitMark mark;
    mark.kind = an::UnitKind::data;
    an::DataSpec &spec = mark.data;
    spec.pointer_size = ptr;
    types::TypeId elem = d.type;
    types::TypeId item = d.type;
    std::uint64_t size = st.size_of(d.type);
    if (d.string) {
      // A char[n] string: its characters as a terminated string.
      const auto *arr = st.get(d.type).as<types::ArrayType>();
      if (arr == nullptr) continue;
      elem = arr->element;
      spec.string = an::StringKind::utf8;
      spec.layout = an::StringLayout::terminated;
      spec.count = arr->count;
      spec.format = an::ValueFormat::character;
      spec.collapsed = true;
    } else {
      spec.count = d.count;
      if (d.count > 0) {
        item = st.array_of(d.type, d.count);
        size *= d.count;
      }
      spec.collapsed = d.collapsed || d.count > 0;
      LayOutElement(st, elem, spec);
    }
    if (size == 0) continue;
    spec.type = st.hash(elem).hex();
    spec.type_name = ElementName(st, elem);
    spec.element = st.size_of(elem);
    spec.item_type = st.hash(item).hex();
    spec.item_name = ElementName(st, item);
    mark.length = size;
    roots.insert(item);
    roots.insert(elem);
    AnalysisAssertion a;
    a.kind = FactKind::CodeUnit;
    a.address = d.address;
    a.sub = an::unit_sub(mark);
    a.value = facts::encode_to_string(mark);
    pb::ListingEdit *e = a.body.mutable_listing_edit();
    e->mutable_address()->set_offset(d.address);
    pb::DefineData *dd = e->mutable_data();
    dd->mutable_type()->set_type_hash(spec.type);
    if (d.string) {
      dd->set_string(pb::STRING_ENCODING_UTF8);
      dd->set_layout(pb::STRING_LAYOUT_TERMINATED);
    } else if (d.count > 0) {
      dd->set_count(d.count);
    }
    dd->set_size(size);
    dd->set_type_hash(spec.type);
    dd->set_type_name(spec.type_name);
    dd->set_collapsed(spec.collapsed);
    out.assertions.push_back(std::move(a));
    if (!d.name.empty() && !known.contains(d.address))
      out.assertions.push_back({FactKind::Name, d.address, {}, d.name, RenameBody(d.address, d.name)});
  }
  for (const msvc::LabelDef &l : m.labels)
    if (l.pass == pass && !known.contains(l.address))
      out.assertions.push_back({FactKind::Name, l.address, {}, l.name, RenameBody(l.address, l.name)});
  for (const msvc::FunctionDef &f : m.functions) {
    if (f.pass != pass || !program.executable(f.entry)) continue;
    if (f.create) {
      AnalysisAssertion a;
      a.kind = FactKind::FunctionBounds;
      a.address = f.entry;
      a.value = facts::AddressSet{};
      a.body.mutable_function_bounds()->mutable_entry()->set_offset(f.entry);
      out.assertions.push_back(std::move(a));
    }
    if (!f.name.empty() && !known.contains(f.entry))
      out.assertions.push_back({FactKind::Name, f.entry, {}, f.name, RenameBody(f.entry, f.name)});
    if (f.prototype.valid()) {
      const std::string hash = st.hash(f.prototype).hex();
      AnalysisAssertion a;
      a.kind = FactKind::Type;
      a.address = f.entry;
      a.value = "h:" + hash;
      a.body.mutable_retype()->mutable_target()->mutable_address()->set_offset(f.entry);
      a.body.mutable_retype()->mutable_type()->set_type_hash(hash);
      out.assertions.push_back(std::move(a));
      roots.insert(f.prototype);
    }
  }
  if (pass == "msvc")
    for (const msvc::ClassStruct &c : m.classes) {
      roots.insert(c.type);
      if (c.vftable.valid()) roots.insert(c.vftable);
    }
  std::vector<types::TypeId> work(roots.begin(), roots.end());
  std::set<types::TypeId> seen(roots.begin(), roots.end());
  while (!work.empty()) {
    types::TypeId id = work.back();
    work.pop_back();
    records.emplace(st.hash(id).hex(), EncodeTypeRecord(st, id));
    types::Type t = st.get(id);
    types::for_each_ref(t, [&](types::TypeId &ref, types::EdgeKind) {
      if (seen.insert(ref).second) work.push_back(ref);
    });
  }
  // Types first, so every assertion's hashes are defined when it lands.
  std::vector<AnalysisAssertion> typed;
  for (auto &[hash, record] : records) {
    AnalysisAssertion a;
    a.kind = FactKind::TypeDef;
    a.sub = hash;
    a.value = record;
    typed.push_back(std::move(a));
  }
  typed.insert(typed.end(), std::make_move_iterator(out.assertions.begin()),
               std::make_move_iterator(out.assertions.end()));
  out.assertions = std::move(typed);
  return out;
}

}  // namespace

std::vector<AnalysisFacts> CollectPeAnalysis(const Program &program, const std::vector<DebugFacts> &debug) {
  const loader::Image &image = program.image();
  if (image.format != loader::Format::pe) return {};
  const std::map<std::uint64_t, std::string> known = KnownNames(program, debug);
  const DebugClasses classes(debug);
  msvc::MarkupOptions o;
  o.named = [&](std::uint64_t a) {
    auto it = known.find(a);
    return it == known.end() ? std::string() : it->second;
  };
  o.class_type = [&](const std::string &name, types::TypeStore &store) { return classes.get(name, store); };
  const ThisExtent extent(program);
  o.this_extent = [&](std::uint64_t entry) { return extent(entry); };
  msvc::Markup m = msvc::analyze(image, o);
  std::vector<AnalysisFacts> out;
  for (const char *pass : {"pe", "msvc"}) {
    AnalysisFacts a = Collect(program, m, pass, known);
    for (const auto &[what, n] : m.counts)
      if (msvc::count_pass(what) == pass) a.counts[what] = n;
    if (std::string(pass) == "msvc") a.warnings = m.warnings;
    out.push_back(std::move(a));
  }
  return out;
}

}  // namespace revkit::backend
