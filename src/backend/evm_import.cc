#include "evm_import.h"

#include "program.h"

#include "revkit/analysis/units.h"
#include "revkit/analysis/user_refs.h"
#include "revkit/facts/codec.h"
#include "revkit/evm/evm.h"

#include <cstdio>

namespace revkit::backend {

namespace {

using facts::FactKind;

// A piece of code: the runtime at 0, the creation code at kCreationBase.
struct Segment {
  std::string block;
  std::uint64_t base = 0;
  evm::Bytes code;
};

std::vector<Segment> Segments(const loader::Image &image) {
  std::vector<Segment> out;
  for (const loader::Block &b : image.blocks) {
    if (b.name != "runtime" && b.name != "init") continue;
    Segment s{b.name, b.start, evm::Bytes(b.size)};
    image.memory.read(b.start, s.code);
    // Creation code is the constructor, then the runtime it copies (data
    // there, the runtime block's code), then any constructor arguments.
    if (b.name == "init")
      if (const evm::Layout l = evm::layout(s.code); l.creation) s.code.resize(l.runtime_offset);
    out.push_back(std::move(s));
  }
  std::sort(out.begin(), out.end(), [](const Segment &a, const Segment &b) { return a.base < b.base; });
  return out;
}

std::string Hex4(std::uint64_t v) {
  char buf[24];
  std::snprintf(buf, sizeof buf, "%04llx", static_cast<unsigned long long>(v));
  return buf;
}

AnalysisAssertion Name(std::uint64_t a, const std::string &name) {
  AnalysisAssertion n;
  n.kind = FactKind::Name;
  n.address = a;
  n.value = name;
  n.body.mutable_rename()->mutable_target()->mutable_address()->set_offset(a);
  n.body.mutable_rename()->set_name(name);
  return n;
}

AnalysisAssertion Function(std::uint64_t a) {
  AnalysisAssertion f;
  f.kind = FactKind::FunctionBounds;
  f.address = a;
  f.value = facts::AddressSet{};
  f.body.mutable_function_bounds()->mutable_entry()->set_offset(a);
  return f;
}

AnalysisAssertion Plate(std::uint64_t a, const std::string &text) {
  AnalysisAssertion c;
  c.kind = FactKind::Comment;
  c.address = a;
  c.sub = "plate";
  c.value = text;
  pb::Comment *pc = c.body.mutable_comment();
  pc->mutable_address()->set_offset(a);
  pc->set_kind(pb::COMMENT_KIND_PLATE);
  pc->set_text(text);
  return c;
}

// Disassemble here (a ListingEdit's code mark): code starts at a JUMPDEST,
// so discovery decodes from it even where no flow it follows reaches it,
// and data analysis can't take a PUSH32's ASCII immediate for a string.
AnalysisAssertion CodeMark(std::uint64_t a) {
  analysis::UnitMark mark;
  mark.kind = analysis::UnitKind::code;
  AnalysisAssertion c;
  c.kind = FactKind::CodeUnit;
  c.address = a;
  c.sub = analysis::unit_sub(mark);
  c.value = facts::encode_to_string(mark);
  c.body.mutable_listing_edit()->mutable_address()->set_offset(a);
  c.body.mutable_listing_edit()->mutable_disassemble();
  return c;
}

AnalysisAssertion JumpReference(std::uint64_t from, std::uint64_t to) {
  analysis::UserRef u;
  u.type = analysis::UserRefType::computed_jump;
  u.to = to;
  AnalysisAssertion r;
  r.kind = FactKind::Reference;
  r.address = from;
  r.sub = analysis::user_ref_sub(-1, to);
  r.value = analysis::encode_user_ref(u);
  pb::UserReference *b = r.body.mutable_reference();
  b->mutable_from()->set_offset(from);
  b->mutable_to()->set_offset(to);
  b->set_type(pb::REFERENCE_TYPE_COMPUTED_JUMP);
  return r;
}

}  // namespace

std::optional<loader::RawOptions> EvmRawOptions(std::span<const std::byte> file) {
  std::optional<evm::Bytes> code = evm::bytecode_of(file);
  if (!code) return std::nullopt;
  loader::RawOptions o;
  o.language = evm::kLanguage;
  o.perms = {true, false, true};
  o.entry = 0;
  const evm::Layout l = evm::layout(*code);
  if (!l.creation) {
    o.block_name = "runtime";
    return o;
  }
  // The creation code in its own segment, its runtime at 0.
  o.block_name = "init";
  o.base = evm::kCreationBase;
  o.entry = evm::kCreationBase;  // deployment runs the constructor
  loader::RawRegion r;
  r.name = "runtime";
  r.start = 0;
  r.size = l.runtime_size;
  r.perms = {true, false, true};
  r.initialized = true;
  r.file_offset = l.runtime_offset;
  r.file_size = l.runtime_size;
  o.regions.push_back(r);
  return o;
}

bool IsEvm(const Program &program) { return program.language().language.starts_with("EVM:"); }

std::optional<AnalysisFacts> CollectEvmAnalysis(const Program &program) {
  if (!IsEvm(program)) return std::nullopt;
  AnalysisFacts out;
  out.source = "evm";
  std::size_t functions = 0, known = 0, refs = 0, labels = 0;
  std::uint32_t jumps = 0, resolved = 0, unresolved = 0;
  for (const Segment &s : Segments(program.image())) {
    const evm::Analysis a = evm::analyze(s.code);
    jumps += a.jumps;
    resolved += a.resolved();
    unresolved += static_cast<std::uint32_t>(a.unresolved.size());
    const bool runtime = s.block == "runtime";
    const std::vector<evm::Selector> sel = runtime ? evm::dispatcher(a.insns) : std::vector<evm::Selector>{};
    // The entry: the dispatcher (runtime code) or the constructor.
    out.assertions.push_back(Function(s.base));
    out.assertions.push_back(Name(s.base, runtime ? (sel.empty() ? "runtime" : "dispatcher") : "constructor"));
    ++functions;
    std::set<std::uint64_t> named{s.base};
    for (const evm::Selector &x : sel) {
      const std::uint64_t entry = s.base + x.entry;
      if (!a.jumpdests.contains(x.entry) || !named.insert(entry).second) continue;
      const evm::KnownSignature *k = evm::known_signature(x.selector);
      char sel_hex[16];
      std::snprintf(sel_hex, sizeof sel_hex, "0x%08x", x.selector);
      out.assertions.push_back(Function(entry));
      out.assertions.push_back(Name(entry, k ? evm::signature_name(k->signature) : evm::selector_name(x.selector)));
      std::string plate = std::string("selector ") + sel_hex;
      if (k) {
        plate = std::string(k->signature) + " (" + k->standard + ")\n" + plate + " (the signature is the usual one for "
                "this selector: a guess from revkit's table)";
        ++known;
      }
      out.assertions.push_back(Plate(entry, plate));
      ++functions;
    }
    // JUMPDESTs as solc's assembly calls them, tag_<offset>, and code.
    for (std::uint32_t d : a.jumpdests) {
      const std::uint64_t at = s.base + d;
      out.assertions.push_back(CodeMark(at));
      if (named.contains(at)) continue;
      out.assertions.push_back(Name(at, "tag_" + Hex4(d)));
      ++labels;
    }
    // The computed jumps' targets.
    for (const auto &[pc, targets] : a.computed)
      for (std::uint32_t t : targets) {
        out.assertions.push_back(JumpReference(s.base + pc, s.base + t));
        ++refs;
      }
    if (a.meta) {
      out.assertions.push_back(Plate(s.base + a.meta->offset, "solc metadata (CBOR, " + std::to_string(a.meta->size) +
                                                                   " bytes): not code"));
    }
    if (a.budget) out.warnings.push_back(s.block + ": the stack analysis stopped at its budget; some paths weren't followed");
  }
  out.counts["functions"] = functions;
  out.counts["known_signatures"] = known;
  out.counts["jumpdest_labels"] = labels;
  out.counts["jump_references"] = refs;
  out.warnings.push_back("EVM: " + std::to_string(resolved) + " of " + std::to_string(jumps) +
                         " jumps with known targets, " + std::to_string(unresolved) + " unresolved");
  return out;
}

void FillEvmSummary(const Program &program, pb::EvmSummary *out) {
  const std::vector<Segment> segments = Segments(program.image());
  if (program.file()) {
    if (std::optional<evm::Bytes> file = evm::bytecode_of(*program.file())) {
      const evm::Layout l = evm::layout(*file);
      out->set_creation(l.creation);
      out->set_runtime_offset(l.runtime_offset);
      out->set_runtime_size(l.runtime_size);
    }
  }
  for (const Segment &s : segments) {
    const evm::Analysis a = evm::analyze(s.code);
    out->set_jumps(out->jumps() + a.jumps);
    out->set_direct_jumps(out->direct_jumps() + static_cast<std::uint32_t>(a.direct.size()));
    out->set_resolved_jumps(out->resolved_jumps() + a.resolved());
    out->set_unresolved_jumps(out->unresolved_jumps() + static_cast<std::uint32_t>(a.unresolved.size()));
    out->set_unreached_jumps(out->unreached_jumps() + static_cast<std::uint32_t>(a.unreached.size()));
    out->set_jumpdests(out->jumpdests() + static_cast<std::uint32_t>(a.jumpdests.size()));
    out->set_budget(out->budget() || a.budget);
    if (s.block != "runtime") continue;
    if (a.meta) {
      out->set_metadata_offset(a.meta->offset);
      out->set_metadata_size(a.meta->size);
    }
    for (const evm::Selector &x : evm::dispatcher(a.insns)) {
      pb::EvmFunction *f = out->add_functions();
      f->set_selector(x.selector);
      f->mutable_entry()->set_offset(s.base + x.entry);
      const evm::KnownSignature *k = evm::known_signature(x.selector);
      f->set_name(k ? evm::signature_name(k->signature) : evm::selector_name(x.selector));
      if (k) {
        f->set_signature(k->signature);
        f->set_standard(k->standard);
      }
    }
  }
}

}  // namespace revkit::backend
