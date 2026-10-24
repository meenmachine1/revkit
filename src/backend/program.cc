#include "program.h"

#include "revkit/inputs/demangled.h"

#include "listing_edit.h"

#include "relocate.h"

#include "revkit/inputs/debug_info.h"
#include "revkit/inputs/inputs.h"
#include "revkit/lift/context.hh"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <map>
#include <unordered_map>
#include <optional>
#include <set>
#include <span>
#include <thread>
#include <tuple>

namespace revkit::backend {

std::string FormatAddressName(const char *prefix, std::uint64_t addr) {
  char buf[48];
  std::snprintf(buf, sizeof buf, "%s%08llx", prefix, static_cast<unsigned long long>(addr));
  return buf;
}

namespace {

int SymbolRank(const loader::Symbol &s) {
  switch (s.bind) {
    case loader::SymbolBind::global: return 3;
    case loader::SymbolBind::weak: return 2;
    case loader::SymbolBind::local: return 1;
    default: return 0;
  }
}

}  // namespace

std::unique_ptr<lift::Lifter> Program::MakeLifter() const {
  auto lifter = std::make_unique<lift::Lifter>(image_, language_.language);
  for (const lift::ContextRegion &c : lift::image_context(*image_)) lifter->set_context(c.name, c.value, c.start, c.end);
  return lifter;
}

std::shared_ptr<Program> Program::Load(std::shared_ptr<const loader::Bytes> bytes, const Options &options) {
  std::shared_ptr<Program> p(new Program());
  p->options_ = options;
  p->file_ = bytes;

  loader::LoadOptions lo;
  lo.image_base = options.image_base;
  lo.ghidra_image_base = true;  // addresses line up with a default Ghidra import
  lo.macho_slice = options.macho_slice;
  std::shared_ptr<const loader::Image> image_ptr = options.image;
  if (!image_ptr && options.raw) {
    if (options.language_id.empty()) throw loader::LoadError("a raw image needs ImportOptions.language_id");
    loader::RawOptions raw = *options.raw;
    raw.language = options.language_id;
    image_ptr = std::make_shared<const loader::Image>(loader::parse_raw(bytes, raw));
  }
  if (!image_ptr) image_ptr = std::make_shared<const loader::Image>(loader::parse(bytes, lo));
  // A rebased PIE needs its RELATIVE relocations applied, as Ghidra does,
  // or pointer tables in its data keep link-time addresses.
  std::vector<std::string> reloc_warnings;
  if (!options.image && image_ptr->format == loader::Format::elf) {
    loader::Image linked = loader::parse(bytes, {});
    p->rebase_delta_ = image_ptr->image_base - linked.image_base;
    if (auto patched = RelocateRelative(linked, p->rebase_delta_, reloc_warnings))
      image_ptr = std::make_shared<const loader::Image>(loader::parse(patched, lo));
  }
  p->image_ = std::move(image_ptr);
  const loader::Image &image = *p->image_;
  p->format_ = !options.format.empty()                  ? options.format
                : image.format == loader::Format::elf   ? "elf"
                : image.format == loader::Format::raw   ? "raw"
                : image.format == loader::Format::macho ? "macho"
                                                        : "pe";
  p->warnings_ = image.warnings;
  p->warnings_.insert(p->warnings_.end(), reloc_warnings.begin(), reloc_warnings.end());

  if (!options.language_id.empty()) {
    p->language_.language = options.language_id;
    p->language_.compiler = options.compiler_spec_id.empty() ? "default" : options.compiler_spec_id;
  } else if (!options.language.language.empty()) {
    p->language_ = options.language;
    if (!options.compiler_spec_id.empty()) p->language_.compiler = options.compiler_spec_id;
  } else if (auto guess = loader::guess_language(image)) {
    p->language_ = *guess;
    if (!options.compiler_spec_id.empty()) p->language_.compiler = options.compiler_spec_id;
  } else {
    throw loader::LoadError("no Ghidra language for machine " + std::to_string(image.machine) +
                            "; pass ImportOptions.language_id");
  }
  if (!lift::language_exists(p->language_.id()))
    throw lift::LiftError("the Ghidra install has no language " + p->language_.id());
  // What Describe() reads about the language, beside the debug info and the
  // engine built below: each builds a SLEIGH engine (tens of milliseconds).
  // A failure is Describe()'s to report.
  std::jthread language([id = p->language_.id()] {
    try {
      analysis::prepare_language(id);
    } catch (const std::exception &) {
    }
  });
  if (options.discovery_pool) {
    // Discovery decodes in parallel above 1 MB of code; its engines can be
    // built meanwhile (the import parses the debug info, describes and
    // stores the program first).
    std::uint64_t code = 0;
    for (const loader::Block &b : image.blocks)
      if (b.perms.exec && b.initialized) code += b.size;
    if (code > (1u << 20))
      p->preparing_ = std::make_shared<std::jthread>([id = p->language_.id(), pool = options.discovery_pool] {
        try {
          analysis::prepare_decoders(id, *pool);
        } catch (const std::exception &) {
          // Discovery builds its own.
        }
      });
  }

  if (options.loaded) options.loaded(*p->image_);
  if (options.debug_info) {
    std::shared_ptr<const loader::Bytes> separate;
    const loader::Image &im = *p->image_;
    if (options.find_debug_file && im.format == loader::Format::elf && !loader::find_section(im, ".debug_info") &&
        !loader::find_section(im, ".zdebug_info"))
      if (auto f = options.find_debug_file(im)) {
        separate = std::move(f->bytes);
        p->debug_file_ = std::move(f->file);
      }
    p->debug_ = inputs::read_debug_info(im, options.binary, separate);
    if (!p->debug_ || !p->debug_->dwarf) p->debug_file_.clear();
  }
  DecompilerPool::Config dc;
  dc.image = p->image_;
  dc.language_id = p->language_.id();
  dc.max_instances = options.decompilers;
  dc.workers = options.decompile_workers;
  dc.limits = options.decompile_limits;
  p->MakeEngines(std::make_unique<DecompilerPool>(std::move(dc)));
  {
    auto lifter = p->lifters_->Acquire();
    p->code_space_ = lifter->code_space_name();
    p->spaces_ = lifter->spaces();
  }
  return p;
}

void Program::MakeEngines(std::unique_ptr<DecompilerPool> decompiler) {
  const Program *self = this;
  lifters_ = std::make_unique<Pool<lift::Lifter>>([self] { return self->MakeLifter(); }, options_.lifters);
  walk_lifters_ = std::make_unique<Pool<lift::Lifter>>([self] { return self->MakeLifter(); }, options_.lifters);
  // ARM: Thumb code discovery found decodes with TMode set.
  if (language_.language.starts_with("ARM:"))
    thumb_lifters_ = std::make_unique<Pool<lift::Lifter>>(
        [self] {
          auto l = self->MakeLifter();
          l->set_context("TMode", 1, 0);
          return l;
        },
        std::max(1u, options_.lifters / 2));
  decompiler_ = std::move(decompiler);
}

std::size_t Program::ParkIdleEngines(std::chrono::steady_clock::duration idle_for) const {
  std::size_t n = 0;
  for (auto *pool : {lifters_.get(), walk_lifters_.get(), thumb_lifters_.get()})
    if (pool) n += pool->ParkIdle(idle_for);
  if (decompiler_) n += decompiler_->ParkIdleEngines(idle_for);
  std::vector<std::shared_ptr<const Program>> variants;
  {
    std::lock_guard lock(variants_mu_);
    for (const auto &[key, v] : variants_) variants.push_back(v);
  }
  for (const auto &v : variants)
    if (v.get() != this) n += v->ParkIdleEngines(idle_for);
  return n;
}

std::shared_ptr<const Program> Program::WithMemory(const analysis::MemoryMapInfo &map,
                                                   const RegionBytesReader &bytes) const {
  if (!map.edited) return shared_from_this();
  std::string key = facts::encode_to_string(map);
  {
    std::lock_guard lock(variants_mu_);
    auto &vs = variants_;
    for (auto it = vs.begin(); it != vs.end(); ++it)
      if (it->first == key) {
        auto found = it->second;
        std::rotate(vs.begin(), it, it + 1);
        return found;
      }
  }
  std::shared_ptr<loader::Image> image = analysis::image_with_memory(*image_, map, bytes);
  std::shared_ptr<Program> v(new Program());
  v->image_ = image;
  v->language_ = language_;
  v->format_ = format_;
  v->code_space_ = code_space_;
  v->spaces_ = spaces_;
  v->file_ = file_;
  v->warnings_ = warnings_;
  v->rebase_delta_ = rebase_delta_;
  v->options_ = options_;
  v->debug_ = debug_;
  v->shared_ = shared_;
  v->MakeEngines(std::make_unique<DecompilerPool>(decompiler_->SharedConfig(image)));
  std::lock_guard lock(variants_mu_);
  auto &vs = variants_;
  for (const auto &[k, p] : vs)
    if (k == key) return p;  // another thread built it first
  vs.insert(vs.begin(), {std::move(key), v});
  constexpr std::size_t kKept = 4;
  if (vs.size() > kKept) vs.resize(kKept);
  return v;
}

std::shared_ptr<const loader::Image> Program::Reload(std::shared_ptr<const loader::Bytes> bytes) const {
  if (options_.image) return nullptr;  // a loader plugin's
  loader::LoadOptions lo;
  lo.image_base = options_.image_base;
  lo.ghidra_image_base = true;
  lo.macho_slice = options_.macho_slice;
  if (options_.raw) {
    loader::RawOptions raw = *options_.raw;
    raw.language = options_.language_id;
    return std::make_shared<const loader::Image>(loader::parse_raw(bytes, raw));
  }
  auto image = std::make_shared<const loader::Image>(loader::parse(bytes, lo));
  if (image->format == loader::Format::elf) {
    loader::Image linked = loader::parse(bytes, {});
    std::vector<std::string> warnings;
    if (auto patched = RelocateRelative(linked, image->image_base - linked.image_base, warnings))
      image = std::make_shared<const loader::Image>(loader::parse(patched, lo));
  }
  return image;
}

analysis::ProgramInfo Program::Describe(facts::SpaceId space, const analysis::ByteSource &bytes) const {
  analysis::ProgramInfo info = analysis::describe(*image_, language_.id(), space, bytes);
  info.references = true;  // xrefs come from discovery's decode
  return info;
}

LabelMap Program::LoaderLabels(const analysis::ProgramInfo &info) const {
  const loader::Image &image = *image_;
  std::set<std::uint64_t> entries;
  for (const analysis::Seed &s : info.seeds) entries.insert(s.address);
  std::map<std::uint64_t, std::uint64_t> sizes;
  for (const loader::Symbol &s : image.symbols)
    if (s.defined && s.size) sizes[s.value] = std::max(sizes[s.value], s.size);

  // Defined non-function symbols in mapped memory; where several share an
  // address: global over weak over local, then lexically smallest.
  std::map<std::uint64_t, const loader::Symbol *> best;
  for (const loader::Symbol &s : image.symbols) {
    using T = loader::SymbolType;
    if (!s.defined || s.name.empty() || s.name[0] == '$') continue;
    if (s.type != T::object && s.type != T::notype && s.type != T::common && s.type != T::tls) continue;
    if (!image.memory.is_mapped(s.value) || entries.contains(s.value)) continue;
    auto [it, inserted] = best.emplace(s.value, &s);
    if (!inserted) {
      const loader::Symbol &cur = *it->second;
      if (SymbolRank(s) > SymbolRank(cur) || (SymbolRank(s) == SymbolRank(cur) && s.name < cur.name)) it->second = &s;
    }
  }
  std::map<std::uint64_t, std::string> names;
  for (const auto &[addr, s] : best) names.emplace(addr, s->name);
  // PE import address table slots carry the imported names. (A Mach-O's
  // bound slots don't: Ghidra's loader makes them pointers, PTR__name_*.)
  if (image.format == loader::Format::pe)
    for (const loader::Import &imp : image.imports)
      if (imp.iat_address && !imp.name.empty() && image.memory.is_mapped(imp.iat_address))
        names.emplace(imp.iat_address, imp.name);

  LabelMap out;
  for (auto &[addr, name] : names) {
    auto it = sizes.find(addr);
    Label l{addr, std::move(name), it == sizes.end() ? 0 : it->second, {}};
    // The demangler analysis's name (docs/demangle.md).
    if (std::optional<std::string> d = inputs::demangled_name(l.name)) {
      l.mangled = std::move(l.name);
      l.name = std::move(*d);
    }
    out.labels.push_back(std::move(l));
  }
  return out;
}

namespace {

int OperandOf(const lift::Instruction &insn, std::uint64_t v) {
  for (const lift::Token &t : insn.tokens)
    if ((t.kind == lift::Token::Kind::address || t.kind == lift::Token::Kind::scalar) && t.value == v) return t.operand;
  return -1;
}

}  // namespace

int Program::XrefOperand(const StaticXref &x) const {
  if (x.operand != StaticXref::kOperandFromText) return x.operand;
  auto lifter = lifters_->Acquire();
  auto insn = lifter->lift(x.from, x.delay_slot);
  return insn ? OperandOf(*insn, x.to) : -1;
}

CodeMap Program::Code(const std::vector<analysis::CodeUnit> &code) const {
  CodeMap out;
  std::optional<ListingSpan> span;
  auto close = [&] {
    if (span && !span->rows.empty()) out.spans.push_back(std::move(*span));
    span.reset();
  };
  for (const analysis::CodeUnit &c : code) {
    if (span && c.address < span->end) continue;  // inside the previous instruction
    const loader::Block *b = block_containing(c.address);
    if (b == nullptr || c.length == 0 || c.length - 1 > b->start + (b->size - 1) - c.address) continue;
    const auto block = static_cast<std::uint32_t>(b - image_->blocks.data());
    // A span is a run of adjacent instructions in one block.
    if (!span || c.address != span->end || block != span->block || c.thumb != span->thumb ||
        c.address + c.length - span->start > ListingSpan::kOffsetMask) {
      close();
      span = ListingSpan{c.address, c.address, 0, block, true, c.thumb, {}};
    }
    span->rows.push_back(static_cast<std::uint32_t>(c.address - span->start));
    ++out.instructions;
    if (c.delay != 0 && c.delay < c.length) {
      span->rows.push_back(static_cast<std::uint32_t>(c.address + (c.length - c.delay) - span->start) |
                           ListingSpan::kDelaySlot);
      ++out.instructions;
    }
    span->end = c.address + c.length;
  }
  close();
  return out;
}

std::vector<StaticXref> Program::FunctionXrefs(const analysis::FunctionInfo &f, const analysis::FlowGraph &flow) const {
  // References are what discovery's decode of the flow recorded (from the
  // p-code, as AddXrefs finds them); the display text only says which
  // operand each is in, which is decoded when a reference is served.
  static constexpr pb::XrefKind kKinds[] = {pb::XREF_KIND_CALL,         pb::XREF_KIND_JUMP,
                                            pb::XREF_KIND_CONDITIONAL_JUMP, pb::XREF_KIND_DATA_POINTER,
                                            pb::XREF_KIND_DATA_READ,    pb::XREF_KIND_DATA_WRITE,
                                            pb::XREF_KIND_FALLTHROUGH};
  std::vector<StaticXref> out;
  std::size_t r = 0;
  for (std::size_t k = 0; k < flow.insns.size(); ++k) {
    const analysis::FlowInsn &i = flow.insns[k];
    while (r < flow.refs.size() && flow.refs[r].insn < k) ++r;
    if (!f.body.contains(facts::Address{f.entry.space, i.address})) continue;
    for (; r < flow.refs.size() && flow.refs[r].insn == k; ++r) {
      const analysis::FlowRef &x = flow.refs[r];
      // (A fallthrough override's is the mnemonic's, as Ghidra's.)
      out.push_back({x.from(flow), x.to, kKinds[static_cast<unsigned>(x.kind)],
                     x.kind == analysis::RefKind::fallthrough ? -1 : StaticXref::kOperandFromText, x.delay_slot});
    }
    // A recovered jump table: the jump refers to every case.
    if (i.kind == analysis::FlowKind::jump_indirect)
      for (std::uint64_t t : i.targets) out.push_back({i.address, t, pb::XREF_KIND_INDIRECT_JUMP, -1, false});
  }
  std::sort(out.begin(), out.end(), [](const StaticXref &a, const StaticXref &b) {
    return std::tie(a.from, a.to, a.kind) < std::tie(b.from, b.to, b.kind);
  });
  out.erase(std::unique(out.begin(), out.end(),
                        [](const StaticXref &a, const StaticXref &b) {
                          return a.from == b.from && a.to == b.to && a.kind == b.kind;
                        }),
            out.end());
  return out;
}

LabelMap Program::DefaultLabels(const LabelMap &loader_labels, const FunctionTable &functions,
                                const XrefTable &xrefs, const analysis::DataList &data) const {
  // Analysis data names its address (where nothing else does), as
  // revkit::inputs names it for the decompiler: strings after their text,
  // pointers after their target's label, accessed and referenced bytes DAT_.
  // (Pointers are named after their targets' names as the file spells
  // them, as revkit::inputs names them for the decompiler.)
  std::unordered_map<std::uint64_t, std::string> names;
  for (const Func &f : functions.funcs) names.emplace(f.entry, f.mangled.empty() ? f.name : f.mangled);
  for (const Label &l : loader_labels.labels) names.emplace(l.address, l.mangled.empty() ? l.name : l.mangled);
  std::map<std::uint64_t, std::string> data_names;
  for (const analysis::DataItem &d : data.items) {
    if (names.contains(d.address)) continue;
    std::string name;
    switch (d.kind) {
      case analysis::DataKind::string:
        name = FormatAddressName((analysis::string_label("s_", d.text) + "_").c_str(), d.address);
        break;
      case analysis::DataKind::unicode:
      case analysis::DataKind::unicode32:
        name = FormatAddressName((analysis::string_label("u_", d.text) + "_").c_str(), d.address);
        break;
      case analysis::DataKind::pointer: continue;  // below
      default: name = FormatAddressName("DAT_", d.address); break;
    }
    data_names.emplace(d.address, name);
    names.emplace(d.address, std::move(name));
  }
  inputs::SlotNames slot_names;
  slot_names.word = image_->bits / 8;
  for (const Func &f : functions.funcs)
    for (const Range &r : f.body) slot_names.bodies.emplace_back(r.first, r.second);
  std::sort(slot_names.bodies.begin(), slot_names.bodies.end());
  for (const analysis::DataItem &d : data.items)
    if (d.kind == analysis::DataKind::pointer) slot_names.pointers.emplace_back(d.address, d.value);
  slot_names.names = std::move(names);
  for (const analysis::DataItem &d : data.items)
    if (d.kind == analysis::DataKind::pointer && !slot_names.names.contains(d.address))
      data_names.emplace(d.address, inputs::pointer_name(d.address, d.value, block_containing(d.value) != nullptr, slot_names));

  // Each reference target that is neither a function nor a loader label
  // gets a default name, from its first reference (by from, to, kind):
  // by_to keeps that order within a target.
  std::vector<Label> found;
  for (std::size_t k = 0; k < xrefs.by_to.size();) {
    const StaticXref &x = xrefs.xrefs[xrefs.by_to[k]];
    for (++k; k < xrefs.by_to.size() && xrefs.xrefs[xrefs.by_to[k]].to == x.to; ++k) {
    }
    if (functions.at(x.to) || loader_labels.find(x.to) || data_names.contains(x.to)) continue;
    const char *prefix;
    switch (x.kind) {
      case pb::XREF_KIND_CALL: prefix = "FUN_"; break;
      case pb::XREF_KIND_JUMP:
      case pb::XREF_KIND_CONDITIONAL_JUMP:
      case pb::XREF_KIND_INDIRECT_JUMP: prefix = "LAB_"; break;
      default: prefix = executable(x.to) ? "LAB_" : "DAT_"; break;
    }
    found.push_back(Label{x.to, FormatAddressName(prefix, x.to), 0, {}});
  }
  for (auto &[a, name] : data_names) {
    if (functions.at(a)) continue;
    const analysis::DataItem *d = data.at(a);
    found.push_back(Label{a, std::move(name), d ? d->length : 0, {}});
  }
  std::sort(found.begin(), found.end(), [](const Label &a, const Label &b) { return a.address < b.address; });
  LabelMap out;
  out.labels.reserve(loader_labels.labels.size() + found.size());
  std::merge(std::make_move_iterator(found.begin()), std::make_move_iterator(found.end()), loader_labels.labels.begin(),
             loader_labels.labels.end(), std::back_inserter(out.labels),
             [](const Label &a, const Label &b) { return a.address < b.address; });
  return out;
}

RowIndex Program::Rows(const CodeMap &code, const LabelMap &labels, const analysis::DataList &data) const {
  const loader::Image &image = *image_;
  RowIndex out;
  // Defined data (not the bare labels of referenced bytes) is a row each.
  for (const analysis::DataItem &d : data.items)
    if (d.kind != analysis::DataKind::label) out.data.push_back(d);
  std::map<std::uint32_t, std::vector<const ListingSpan *>> code_spans;  // block -> spans
  for (const ListingSpan &s : code.spans) code_spans[s.block].push_back(&s);

  // Every block in address order. Gaps between code spans (and whole
  // non-code blocks) become data spans, split at labels so each labelled
  // address starts a row.
  auto add_undefined = [&](std::uint32_t bi, std::uint64_t from, std::uint64_t to) {
    std::uint64_t a = from;
    auto it = std::upper_bound(labels.labels.begin(), labels.labels.end(), from,
                               [](std::uint64_t v, const Label &l) { return v < l.address; });
    for (; a < to; ++it) {
      std::uint64_t stop = (it == labels.labels.end() || it->address >= to) ? to : it->address;
      if (stop > a) out.spans.push_back(ListingSpan{a, stop, 0, bi, false, false, false, {}});
      a = stop;
      if (it == labels.labels.end()) break;
    }
  };
  // Undefined bytes around the data items in [from, to).
  auto add_data = [&](std::uint32_t bi, std::uint64_t from, std::uint64_t to) {
    auto it = std::lower_bound(out.data.begin(), out.data.end(), from,
                               [](const analysis::DataItem &d, std::uint64_t v) { return d.address < v; });
    std::uint64_t a = from;
    for (; it != out.data.end() && it->address < to; ++it) {
      const std::uint64_t end = std::min<std::uint64_t>(to, it->address + it->length);
      if (it->address < a || end <= it->address) continue;
      if (it->address > a) add_undefined(bi, a, it->address);
      ListingSpan span{it->address, end, 0, bi, false, false, true, {}};
      // A user's expanded struct or array: a row per field or element.
      if (it->origin == analysis::kDataUser && !it->spec.collapsed)
        if (const std::uint32_t n = DataComponents(*it)) {
          const analysis::DataSpec &spec = it->spec;
          span.rows.reserve(n + 1);
          span.rows.push_back(0);
          for (std::uint32_t i = 0; i < n; ++i) {
            const std::uint64_t off = spec.count > 0 ? i * spec.element : spec.fields[i].offset;
            span.rows.push_back(static_cast<std::uint32_t>(std::min<std::uint64_t>(off, ListingSpan::kOffsetMask)));
          }
        }
      out.spans.push_back(std::move(span));
      a = end;
    }
    if (a < to) add_undefined(bi, a, to);
  };
  for (std::uint32_t bi = 0; bi < image.blocks.size(); ++bi) {
    const loader::Block &b = image.blocks[bi];
    if (b.size == 0) continue;
    const std::uint64_t end = b.start + b.size;
    std::uint64_t a = b.start;
    if (auto it = code_spans.find(bi); it != code_spans.end()) {
      for (const ListingSpan *s : it->second) {
        if (s->start > a) add_data(bi, a, s->start);
        a = s->end;
        out.spans.push_back(*s);
      }
    }
    if (a < end) add_data(bi, a, end);
  }
  std::int64_t row = 0;
  for (ListingSpan &s : out.spans) {
    s.first_row = row;
    row += s.row_count();
  }
  out.total_rows = row;
  return out;
}

pb::FlowKind FlowOf(const lift::Instruction &insn, const std::string &code_space, std::vector<std::uint64_t> &targets) {
  pb::FlowKind kind = pb::FLOW_KIND_FALL_THROUGH;
  for (const lift::PcodeOp &op : insn.pcode) {
    const bool ram_target = !op.inputs.empty() && op.inputs[0].space == code_space;
    if (op.opcode == "CALL") {
      kind = pb::FLOW_KIND_CALL;
      if (ram_target) targets.push_back(op.inputs[0].offset);
    } else if (op.opcode == "CALLIND") {
      kind = pb::FLOW_KIND_INDIRECT_CALL;
    } else if (op.opcode == "BRANCHIND") {
      kind = pb::FLOW_KIND_INDIRECT_BRANCH;
    } else if (op.opcode == "RETURN") {
      kind = pb::FLOW_KIND_RETURN;
    } else if (op.opcode == "BRANCH" && ram_target) {
      kind = pb::FLOW_KIND_UNCONDITIONAL_BRANCH;
      targets.push_back(op.inputs[0].offset);
    } else if (op.opcode == "CBRANCH" && ram_target) {
      if (kind == pb::FLOW_KIND_FALL_THROUGH) kind = pb::FLOW_KIND_CONDITIONAL_BRANCH;
      targets.push_back(op.inputs[0].offset);
    }
  }
  return kind;
}

std::vector<StaticRow> Program::Page(const RowIndex &index, std::int64_t page, PatchedBytes *patches,
                                     const DataSettingsMap *settings) const {
  std::vector<StaticRow> rows;
  const std::int64_t first = page * RowIndex::kPageRows,
                     last = std::min(index.total_rows, first + RowIndex::kPageRows);
  if (first >= last) return rows;
  auto lifter = lifters_->Acquire();
  std::optional<decltype(lifter)> thumb;  // leased on the first Thumb row
  rows.reserve(static_cast<std::size_t>(last - first));
  for (std::int64_t r = first; r < last; ++r) {
    const ListingSpan &s = index.span_of_row(r);
    const std::int64_t k = r - s.first_row;
    StaticRow row;
    row.block = s.block;
    row.address = index.row_address(r);
    const std::uint64_t next = r + 1 < s.first_row + s.row_count() ? index.row_address(r + 1) : s.end;
    row.length = static_cast<std::uint32_t>(next - row.address);
    row.kind = pb::LISTING_ROW_KIND_UNDEFINED;
    if (s.data) DataRow(index, s, k, row, patches, settings);
    // Patched bytes in the row: decoded from them (bytes outside any patch
    // decode from the image, with its context commits, as before).
    facts::PatchList over;
    if (patches && row.length > 0) over = patches->overlapping(row.address, row.address + (row.length - 1));
    if (s.code && !(s.rows[static_cast<std::size_t>(k)] & ListingSpan::kUndefined)) {
      lift::Lifter *l = &*lifter;
      if (s.thumb && thumb_lifters_) {
        if (!thumb) thumb.emplace(thumb_lifters_->Acquire());
        l = &**thumb;
      }
      const bool slot = s.rows[static_cast<std::size_t>(k)] & ListingSpan::kDelaySlot;
      std::optional<lift::Instruction> insn;
      if (over.empty()) {
        insn = l->lift(row.address, slot);
      } else {
        std::string window = read(row.address, 32);
        facts::apply_patches(patches->overlapping(row.address, row.address + 31), row.address, window);
        insn = l->lift(row.address, std::as_bytes(std::span(window.data(), window.size())), slot);
      }
      if (insn) {
        row.kind = pb::LISTING_ROW_KIND_INSTRUCTION;
        row.flow = FlowOf(*insn, code_space_, row.targets);
        row.tokens = std::move(insn->tokens);
        if (row.tokens.empty()) row.tokens.push_back({lift::Token::Kind::mnemonic, insn->text, -1, 0, 0, {}});
      }
    }
    // (A large data item's row shows its first bytes.)
    row.bytes = read(row.address, s.data ? std::min<std::uint32_t>(row.length, kMaxDataRowBytes) : row.length);
    if (!over.empty()) {
      row.original = row.bytes;
      facts::apply_patches(over, row.address, row.bytes);
      row.patched = row.bytes != row.original;
      if (!row.patched) row.original.clear();
    }
    rows.push_back(std::move(row));
  }
  return rows;
}

// A data item's row as Ghidra's listing shows it: string data as ds
// "text", pointers as addr <target>, accessed bytes as undefinedN <hex>.
std::uint32_t Program::DataComponents(const analysis::DataItem &d) {
  if (d.origin != analysis::kDataUser || d.spec.string != analysis::StringKind::none) return 0;
  if (d.spec.count > 0) return static_cast<std::uint32_t>(std::min<std::uint64_t>(d.spec.count, kMaxElementRows));
  return static_cast<std::uint32_t>(d.spec.fields.size());
}

namespace {

// (Bytes that aren't UTF-8 show escaped: a protobuf string must be UTF-8.)
std::string Quoted(std::string_view text, const char *prefix) {
  std::string q = prefix;
  q += '"';
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (static_cast<unsigned char>(c) >= 0x80) {
      const std::size_t n = Utf8Sequence(text, i);
      if (n == 0) {
        char buf[8];
        std::snprintf(buf, sizeof buf, "\\x%02x", static_cast<unsigned char>(c));
        q += buf;
      } else {
        q.append(text.substr(i, n));
        i += n - 1;
      }
      continue;
    }
    switch (c) {
      case '\n': q += "\\n"; break;
      case '\t': q += "\\t"; break;
      case '\r': q += "\\r"; break;
      case '"': q += "\\\""; break;
      case '\\': q += "\\\\"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\x%02x", static_cast<unsigned char>(c));
          q += buf;
        } else {
          q += c;
        }
    }
  }
  return q + '"';
}

}  // namespace

// A value of a user's data definition at `at`, `size` bytes of `format`
// (`type`: its C spelling, for arrays of characters): the text the listing
// shows, or the address a pointer holds.
void Program::UserValue(analysis::ValueFormat format, std::uint64_t at, std::uint64_t size, StaticRow &row,
                        PatchedBytes *patches, const DataSettings &settings) const {
  if (!settings.empty() && format != analysis::ValueFormat::aggregate)
    return SetValue(format, at, size, row, patches, settings);
  const bool big = image_->endian == loader::Endian::big;
  if (format == analysis::ValueFormat::pointer && size <= 8) {
    const std::string b = read(at, static_cast<std::uint32_t>(size), patches);
    if (b.size() == size) {
      std::uint64_t v = 0;
      for (std::size_t i = 0; i < b.size(); ++i) v |= std::uint64_t{static_cast<unsigned char>(b[big ? b.size() - 1 - i : i])} << (8 * i);
      row.data_target = v;
      return;
    }
  }
  if (format == analysis::ValueFormat::string) {
    std::string b = read(at, static_cast<std::uint32_t>(std::min<std::uint64_t>(size, 1024)), patches);
    if (auto z = b.find('\0'); z != std::string::npos) b.resize(z);
    row.data_value = Quoted(b, "");
    return;
  }
  if (format == analysis::ValueFormat::aggregate) {
    row.data_value = "{...}";
    return;
  }
  const std::string b = read(at, static_cast<std::uint32_t>(std::min<std::uint64_t>(size, 8)), patches);
  row.data_value = size > 8 ? "??" : FormatValue(format, b, big);
}

// A value as data settings say (data_settings.h): integers in their
// format, signedness, byte order and padding; floats and pointers in their
// byte order (a pointer also by its kind, mask and shift); char arrays in
// their charset and termination.
void Program::SetValue(analysis::ValueFormat format, std::uint64_t at, std::uint64_t size, StaticRow &row,
                       PatchedBytes *patches, const DataSettings &s) const {
  using F = analysis::ValueFormat;
  const bool big = s.endian == DataSettings::Endian::big      ? true
                   : s.endian == DataSettings::Endian::little ? false
                                                              : image_->endian == loader::Endian::big;
  if (format == F::string) {
    const std::string b = read(at, static_cast<std::uint32_t>(std::min<std::uint64_t>(size, kMaxDataRowBytes)), patches);
    const std::string charset = s.charset.empty() ? "UTF-8" : s.charset;
    row.data_value = QuoteChars(b, charset, big, s.termination == DataSettings::Termination::all, CharsetPrefix(charset));
    return;
  }
  if (size == 0 || size > 8) {
    row.data_value = "??";
    return;
  }
  const std::string b = read(at, static_cast<std::uint32_t>(size), patches);
  if (b.size() != size) {
    row.data_value = "??";
    return;
  }
  if (format == F::pointer) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < b.size(); ++i) v |= std::uint64_t{static_cast<unsigned char>(b[big ? b.size() - 1 - i : i])} << (8 * i);
    if (s.mask) v &= *s.mask;
    if (s.shift) v = *s.shift >= 0 ? v << *s.shift : v >> -*s.shift;
    if (s.pointer == DataSettings::Pointer::image_base) v += image_->image_base;
    else if (s.pointer == DataSettings::Pointer::relative) v += at;
    if (size < 8 && s.pointer != DataSettings::Pointer::image_base && s.pointer != DataSettings::Pointer::relative &&
        !s.shift)
      v &= (std::uint64_t{1} << (8 * size)) - 1;
    row.data_target = v;
    return;
  }
  if (format == F::floating) {
    std::string ordered = b;
    if (big != (image_->endian == loader::Endian::big)) std::reverse(ordered.begin(), ordered.end());
    row.data_value = FormatValue(format, ordered, image_->endian == loader::Endian::big);
    return;
  }
  // Integers, characters, booleans, enums and undefined bytes: a boolean or
  // a character keeps its look unless a format is set.
  if (s.format == DataSettings::Format::unset && (format == F::boolean || format == F::character) &&
      s.sign == DataSettings::Sign::unset && s.padding == DataSettings::Padding::unset) {
    std::string ordered = b;
    if (big != (image_->endian == loader::Endian::big)) std::reverse(ordered.begin(), ordered.end());
    row.data_value = FormatValue(format, ordered, image_->endian == loader::Endian::big);
    return;
  }
  const bool is_signed = s.sign == DataSettings::Sign::is_signed     ? true
                         : s.sign == DataSettings::Sign::is_unsigned ? false
                                                                     : format == F::signed_int;
  const DataSettings::Format f = s.format != DataSettings::Format::unset ? s.format
                                 : format == F::character             ? DataSettings::Format::character
                                                                      : DataSettings::Format::hex;
  row.data_value = FormatInteger(b, big, is_signed, f, s.padding);
}

void Program::DataRow(const RowIndex &index, const ListingSpan &span, std::int64_t k, StaticRow &row,
                      PatchedBytes *patches, const DataSettingsMap *settings) const {
  auto it = std::lower_bound(index.data.begin(), index.data.end(), span.start,
                             [](const analysis::DataItem &d, std::uint64_t v) { return d.address < v; });
  if (it == index.data.end() || it->address != span.start) return;
  const analysis::DataItem &d = *it;
  row.kind = pb::LISTING_ROW_KIND_DATA;
  // The settings this row shows by: its item's (a struct field's own) over its type's.
  auto settings_of = [&](std::string_view field, const std::string &type) {
    row.data_settings_type = type;
    return settings ? settings->at(d.address, field, type) : DataSettings{};
  };
  const bool big_program = image_->endian == loader::Endian::big;
  auto program_order = [&](const DataSettings &s) {
    return s.endian == DataSettings::Endian::big ? true : s.endian == DataSettings::Endian::little ? false : big_program;
  };
  // A string's text from its bytes, as its settings say (after a Pascal length).
  auto string_value = [&](const DataSettings &s, std::string_view charset, std::uint64_t skip, const char *prefix) {
    const std::uint64_t n = std::min<std::uint64_t>(d.length, kMaxDataRowBytes);
    std::string b = read(d.address, static_cast<std::uint32_t>(n), patches);
    b.erase(0, std::min<std::size_t>(b.size(), skip));
    const std::string cs = s.charset.empty() ? std::string(charset) : s.charset;
    row.data_value = QuoteChars(b, cs, program_order(s), s.termination == DataSettings::Termination::all,
                                s.charset.empty() ? std::string_view(prefix) : CharsetPrefix(cs));
  };
  if (d.origin == analysis::kDataUser) {
    const analysis::DataSpec &spec = d.spec;
    if (k == 0) {
      row.length = d.length;
      row.data_type = spec.item_name;
      row.data_mnemonic = DataMnemonic(spec);
      row.data_components = DataComponents(d);
      row.data_collapsed = spec.collapsed;
      if (spec.string != analysis::StringKind::none) {
        const char *prefix = spec.string == analysis::StringKind::utf8 ? "" : spec.string == analysis::StringKind::utf16 ? "u" : "U";
        const DataSettings s = settings_of("", spec.string == analysis::StringKind::utf8    ? "string"
                                               : spec.string == analysis::StringKind::utf16 ? "unicode"
                                                                                            : "unicode32");
        if (s.charset.empty() && s.termination == DataSettings::Termination::unset && s.endian == DataSettings::Endian::unset) {
          row.data_value = Quoted(d.text, prefix);
        } else {
          const std::uint64_t skip = spec.layout == analysis::StringLayout::pascal     ? 1
                                     : spec.layout == analysis::StringLayout::pascal16 ? 2
                                                                                       : 0;
          string_value(s, spec.string == analysis::StringKind::utf8 ? "UTF-8" : spec.string == analysis::StringKind::utf16 ? "UTF-16" : "UTF-32",
                       skip, prefix);
        }
      } else if (spec.count > 0) {
        const DataSettings s = settings_of("", spec.type_name);
        if (spec.format == analysis::ValueFormat::character) {
          UserValue(analysis::ValueFormat::string, d.address, d.length, row, patches, s);
        } else {
          std::string v = "{";
          for (std::uint64_t i = 0; i < spec.count && i < 8; ++i) {
            StaticRow e;
            UserValue(spec.format, d.address + i * spec.element, spec.element, e, patches, s);
            if (i) v += ", ";
            if (e.data_target && !s.empty()) {
              char buf[32];
              std::snprintf(buf, sizeof buf, "%0*llxh", static_cast<int>(2 * spec.pointer_size), static_cast<unsigned long long>(*e.data_target));
              v += buf;
            } else {
              v += e.data_target ? FormatValue(analysis::ValueFormat::hex, read(d.address + i * spec.element, spec.pointer_size, patches),
                                               image_->endian == loader::Endian::big)
                                 : e.data_value;
            }
          }
          row.data_value = v + (spec.count > 8 ? ", ...}" : "}");
        }
      } else {
        UserValue(spec.format, d.address, d.length, row, patches, settings_of("", spec.type_name));
      }
      return;
    }
    const std::size_t i = static_cast<std::size_t>(k - 1);
    row.data_parent = d.address;
    if (spec.count > 0) {
      row.address = d.address + i * spec.element;
      row.length = static_cast<std::uint32_t>(spec.element);
      row.data_field = "[" + std::to_string(i) + "]";
      row.data_depth = 1;
      row.data_type = spec.type_name;
      row.data_mnemonic = spec.format == analysis::ValueFormat::pointer ? "addr" : spec.type_name;
      // An element shows by its array's settings.
      UserValue(spec.format, row.address, spec.element, row, patches, settings_of("", spec.type_name));
      return;
    }
    if (i >= spec.fields.size()) return;
    const analysis::DataField &f = spec.fields[i];
    // The field's path from the item: its parents' names, then its own.
    std::vector<std::string> path;
    for (std::size_t j = 0; j <= i; ++j) {
      const analysis::DataField &g = spec.fields[j];
      path.resize(std::min<std::size_t>(path.size(), g.depth - 1));
      path.push_back(g.name);
    }
    std::string name;
    for (const std::string &p : path) name += (name.empty() || p.starts_with("[") ? "" : ".") + p;
    row.address = d.address + f.offset;
    row.length = static_cast<std::uint32_t>(f.size);
    row.data_field = name;
    row.data_depth = f.depth;
    row.data_type = f.type;
    row.data_mnemonic = f.format == analysis::ValueFormat::pointer ? "addr" : f.type;
    UserValue(f.format, row.address, f.size, row, patches, settings_of(name, f.type));
    return;
  }
  auto quoted = [&](const char *prefix) {
    std::string q = prefix;
    q += '"';
    for (std::size_t i = 0; i < d.text.size(); ++i) {
      const char c = d.text[i];
      switch (c) {
        case '\n': q += "\\n"; break;
        case '\t': q += "\\t"; break;
        case '\r': q += "\\r"; break;
        case '"': q += "\\\""; break;
        case '\\': q += "\\\\"; break;
        default:
          if (static_cast<unsigned char>(c) < 0x80) {
            q += c;
          } else if (const std::size_t n = Utf8Sequence(d.text, i)) {
            q.append(d.text, i, n);
            i += n - 1;
          } else {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\x%02x", static_cast<unsigned char>(c));
            q += buf;
          }
      }
    }
    return q + '"';
  };
  switch (d.kind) {
    case analysis::DataKind::string: {
      row.data_type = "string";
      row.data_mnemonic = "ds";
      const DataSettings s = settings_of("", row.data_type);
      if (s.charset.empty() && s.termination == DataSettings::Termination::unset) row.data_value = quoted("");
      else string_value(s, "UTF-8", 0, "");
      break;
    }
    case analysis::DataKind::unicode:
    case analysis::DataKind::unicode32: {
      row.data_type = d.kind == analysis::DataKind::unicode ? "unicode" : "unicode32";
      row.data_mnemonic = row.data_type;
      const char *prefix = d.kind == analysis::DataKind::unicode ? "u" : "U";
      const DataSettings s = settings_of("", row.data_type);
      if (s.charset.empty() && s.termination == DataSettings::Termination::unset && s.endian == DataSettings::Endian::unset)
        row.data_value = quoted(prefix);
      else string_value(s, d.kind == analysis::DataKind::unicode ? "UTF-16" : "UTF-32", 0, prefix);
      break;
    }
    case analysis::DataKind::pointer: {
      row.data_type = "pointer";
      row.data_mnemonic = "addr";
      const DataSettings s = settings_of("", row.data_type);
      if (s.empty()) row.data_target = d.value;
      else SetValue(analysis::ValueFormat::pointer, d.address, d.length, row, patches, s);
      break;
    }
    default: {
      row.data_type = d.length == 1 ? "undefined" : "undefined" + std::to_string(d.length);
      row.data_mnemonic = row.data_type;
      const DataSettings s = settings_of("", row.data_type);
      if (!s.empty()) {
        SetValue(analysis::ValueFormat::hex, d.address, d.length, row, patches, s);
        break;
      }
      // The value as the bytes read, little or big end first.
      const std::string b = read(d.address, d.length, patches);
      if (b.size() == d.length && d.length <= 8) {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < b.size(); ++i) {
          const std::size_t k = image_->endian == loader::Endian::little ? i : b.size() - 1 - i;
          v |= std::uint64_t{static_cast<unsigned char>(b[i])} << (8 * k);
        }
        char buf[32];
        std::snprintf(buf, sizeof buf, "%0*llxh", static_cast<int>(2 * d.length), static_cast<unsigned long long>(v));
        row.data_value = buf;
      } else {
        row.data_value = "??";
      }
      break;
    }
  }
}

std::optional<Program::Decoded> Program::instruction(std::uint64_t addr, bool thumb, PatchedBytes *patches) const {
  if (!executable(addr)) return std::nullopt;
  auto lifter = thumb && thumb_lifters_ ? thumb_lifters_->Acquire() : lifters_->Acquire();
  // From the bytes, so the decode depends on `thumb` and the painted
  // context only: a pooled engine's earlier context commits (an ARM blx's
  // switch to Thumb at its target, which SLEIGH paints to the end of the
  // space) must not turn later ARM code after that target into Thumb.
  facts::PatchList over;
  if (patches) over = patches->overlapping(addr, addr + 31);
  std::string window = read(addr, 32);
  if (!over.empty()) facts::apply_patches(over, addr, window);
  std::optional<lift::Instruction> insn = lifter->lift(addr, std::as_bytes(std::span(window.data(), window.size())));
  if (!insn) return std::nullopt;
  Decoded d{std::move(*insn), {}};
  auto note = [&](const lift::Varnode &v) {
    if (v.space == "register") d.registers.try_emplace({v.offset, v.size}, lifter->register_name(v.offset, v.size));
  };
  for (const lift::PcodeOp &op : d.insn.pcode) {
    if (op.output) note(*op.output);
    for (const lift::Varnode &v : op.inputs) note(v);
  }
  return d;
}

const loader::Block *Program::block_containing(std::uint64_t addr) const {
  const auto &blocks = image_->blocks;
  auto it = std::upper_bound(blocks.begin(), blocks.end(), addr,
                             [](std::uint64_t a, const loader::Block &b) { return a < b.start; });
  if (it == blocks.begin()) return nullptr;
  const loader::Block &b = *std::prev(it);
  return addr - b.start < b.size ? &b : nullptr;
}

bool Program::executable(std::uint64_t addr) const {
  const loader::Block *b = block_containing(addr);
  return b != nullptr && b->perms.exec && b->initialized;
}

std::string Program::read(std::uint64_t addr, std::uint32_t len, PatchedBytes *patches) const {
  if (patches) {
    std::string out = read(addr, len);
    if (!out.empty()) facts::apply_patches(patches->overlapping(addr, addr + (out.size() - 1)), addr, out);
    return out;
  }
  std::string out;
  std::uint64_t a = addr;
  while (out.size() < len) {
    const loader::Block *b = block_containing(a);
    if (b == nullptr || !b->initialized) break;
    std::uint64_t n = std::min<std::uint64_t>(len - out.size(), b->start + b->size - a);
    std::size_t old = out.size();
    out.resize(old + n);
    image_->memory.read(a, std::span(reinterpret_cast<std::byte *>(out.data() + old), n));
    a += n;
    if (a == 0) break;  // wrapped
  }
  return out;
}

void Program::NoteDecompile(std::uint64_t entry, const std::vector<std::uint64_t> &touched) const {
  std::lock_guard lock(shared_->touch_mu);
  shared_->served.insert(entry);
  for (std::uint64_t target : touched) {
    auto &v = shared_->touched_by[target];
    if (std::find(v.begin(), v.end(), entry) == v.end()) v.push_back(entry);
  }
}

void Program::NoteDecompileFailure(std::uint64_t entry, bool failed) const {
  std::lock_guard lock(shared_->touch_mu);
  if (failed) shared_->failed.insert(entry);
  else shared_->failed.erase(entry);
}

bool Program::DecompileFailed(std::uint64_t entry) const {
  std::lock_guard lock(shared_->touch_mu);
  return shared_->failed.contains(entry);
}

std::shared_ptr<const DecompileOutput> Program::Escalated(const std::string &bundle_hash) const {
  std::lock_guard lock(shared_->touch_mu);
  auto it = shared_->escalated.find(bundle_hash);
  return it == shared_->escalated.end() ? nullptr : it->second;
}

void Program::SetEscalated(const std::string &bundle_hash, std::shared_ptr<const DecompileOutput> out) const {
  std::lock_guard lock(shared_->touch_mu);
  shared_->escalated[bundle_hash] = std::move(out);
}

std::vector<std::uint64_t> Program::DecompilesServed() const {
  std::lock_guard lock(shared_->touch_mu);
  return {shared_->served.begin(), shared_->served.end()};
}

std::vector<std::uint64_t> Program::DecompilesTouching(std::uint64_t target) const {
  std::lock_guard lock(shared_->touch_mu);
  auto it = shared_->touched_by.find(target);
  return it == shared_->touched_by.end() ? std::vector<std::uint64_t>{} : it->second;
}

}  // namespace revkit::backend
