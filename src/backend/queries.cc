#include "queries.h"

#include "auto_struct.h"

#include "diff_session.h"

#include "param_id.h"
#include "signatures.h"

#include "own_inputs.h"

#include "listing_edit.h"
#include "revkit/analysis/user_refs.h"
#include "program.h"
#include "type_record.h"
#include "project_archive.h"

#include "revkit/infer/infer.h"
#include "revkit/inputs/demangled.h"
#include "revkit/inputs/ghidra_types.h"
#include "revkit/demangle/demangle.h"
#include "parse_c.h"
#include "revkit/lift/lifter.hh"
#include "revkit/plugins/queries.h"
#include "revkit/msvc/msvc.h"
#include "revkit/v1/query.pb.h"

#include <algorithm>
#include <deque>
#include <filesystem>
#include <optional>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>

namespace revkit::backend {

namespace an = ::revkit::analysis;
using facts::AssertedFact;
using facts::FactKind;
using facts::FactValue;
using facts::QueryContext;

facts::FactKey FactKeyAt(FactKind kind, facts::SpaceId space, std::uint64_t address, std::string sub) {
  return facts::FactKey{kind, facts::Address{space, address}, std::move(sub)};
}

facts::FactKey TypeDefKey(facts::SpaceId space, const std::string &hash) {
  return FactKeyAt(FactKind::TypeDef, space, 0, hash);
}

// The decompiler build is part of it, so every decompilation (and every
// failure) is recomputed when the decompiler changes.
std::string DefaultDecompilerOptions() {
  return "ghidra 12.1; printer c-language tokens; analysis default; build " + decompd::decompiler_build();
}

namespace {

template <class Reader>
std::shared_ptr<const loader::Bytes> ReadRegionBytes(Reader &reader, const an::RegionBytes &b) {
  return an::region_bytes(reader, b);
}

template <class Reader>
std::shared_ptr<const Program> Effective(Reader &reader, const std::string &id) {
  auto src = reader.template get<q::Source>(id);
  if (!src->program) throw std::logic_error("program " + id + " is not loaded");
  auto map = reader.template get<an::MemoryMap>(AnalysisKey(id));
  return src->program->WithMemory(*map, [&](const an::RegionBytes &b) { return ReadRegionBytes(reader, b); });
}

struct Loaded {
  facts::Ref<ProgramSource> source;
  std::shared_ptr<const Program> keep;
  const Program &program;
};

// The program a query is about, with the memory map at the query's
// revision (EffectiveProgram). Its source never changes after import, so
// that dependency only matters across sessions (it pins the file's hash).
Loaded Load(QueryContext &ctx, const std::string &id) {
  auto src = ctx.get<q::Source>(id);
  auto p = Effective(ctx, id);
  const Program &ref = *p;
  return {std::move(src), std::move(p), ref};
}

std::vector<Range> Ranges(const facts::AddressSet &s) {
  std::vector<Range> out;
  for (const facts::AddressRange &r : s.ranges()) out.emplace_back(r.first.offset, r.last.offset);
  return out;
}

const std::string *String(const FactValue &v) { return std::get_if<std::string>(&v); }

pb::CommentKind CommentKindOf(const std::string &sub) {
  if (sub == "plate") return pb::COMMENT_KIND_PLATE;
  if (sub == "pre") return pb::COMMENT_KIND_PRE;
  if (sub == "decompiler") return pb::COMMENT_KIND_DECOMPILER;
  return pb::COMMENT_KIND_UNSPECIFIED;  // eol, post, repeatable: the decompiler doesn't show them
}

}  // namespace

void RememberRegionBytes(const std::string &sha256, std::shared_ptr<const loader::Bytes> bytes) {
  an::remember_region_bytes(sha256, std::move(bytes));
}

std::shared_ptr<const Program> EffectiveProgram(QueryContext &ctx, const std::string &program) {
  return Effective(ctx, program);
}

std::shared_ptr<const Program> EffectiveProgram(const facts::Snapshot &snap, const std::string &program) {
  return Effective(snap, program);
}

namespace q {

LoaderNames::Value LoaderNames::compute(QueryContext &ctx, const Key &program) {
  auto info = ctx.get<an::Program>(AnalysisKey(program));
  return Load(ctx, program).program.LoaderLabels(*info);
}

Functions::Value Functions::compute(QueryContext &ctx, const Key &program) {
  auto found = ctx.get<an::Functions>(AnalysisKey(program));
  FunctionTable t;
  t.funcs.reserve(found->functions.size());
  for (const an::FunctionInfo &f : found->functions) {
    Func out;
    out.entry = f.entry.offset;
    out.body = Ranges(f.body);
    out.asserted = (f.flags & (an::kFunctionAssertedEntry | an::kFunctionAssertedBody)) != 0;
    out.name = f.name;
    if (std::optional<std::string> d = inputs::demangled_name(f.name)) {
      out.mangled = std::move(out.name);
      out.name = std::move(*d);
    }
    out.flags = f.flags;
    if ((f.flags & an::kFunctionThunk) && f.import.empty()) out.thunk_target = f.thunk_target;
    t.funcs.push_back(std::move(out));
  }
  t.index();
  return t;
}

Code::Value Code::compute(QueryContext &ctx, const Key &program) {
  auto found = ctx.get<an::Functions>(AnalysisKey(program));
  return Load(ctx, program).program.Code(found->code);
}

std::size_t Code::weight(const Value &v) {
  std::size_t n = sizeof(Value);
  for (const auto &s : v.spans) n += sizeof(s) + s.rows.capacity() * sizeof(std::uint32_t);
  return n;
}

FunctionXrefs::Value FunctionXrefs::compute(QueryContext &ctx, const Key &key) {
  const an::Location at{AnalysisKey(key.first), key.second};
  auto f = ctx.get<an::Function>(at);
  if (f->name.empty()) return {};  // no function here
  auto flow = ctx.get<an::Flow>(an::Location{at.program, f->flow_key()});
  return Load(ctx, key.first).program.FunctionXrefs(*f, *flow);
}

namespace {

// analysis.data with listing.user_data's items in place of the ones they
// lay out again: `data` itself when there are none, else a copy in `storage`.
const an::DataList &WithUserData(const an::DataList &data, const std::vector<an::DataItem> &relaid, an::DataList &storage) {
  if (relaid.empty()) return data;
  storage = data;
  for (const an::DataItem &r : relaid) {
    auto it = std::lower_bound(storage.items.begin(), storage.items.end(), r.address,
                               [](const an::DataItem &d, std::uint64_t v) { return d.address < v; });
    if (it != storage.items.end() && it->address == r.address) *it = r;
  }
  return storage;
}

const an::DataList &EffectiveData(QueryContext &ctx, const std::string &program, facts::Ref<an::DataList> &data,
                                  an::DataList &storage) {
  data = ctx.get<an::Data>(AnalysisKey(program));
  auto relaid = ctx.get<q::UserData>(program);
  return WithUserData(*data, *relaid, storage);
}

}  // namespace

UserData::Value UserData::compute(QueryContext &ctx, const Key &program) {
  auto data = ctx.get<an::Data>(AnalysisKey(program));
  Value out;
  std::optional<Loaded> l;
  for (const an::DataItem &d : data->items) {
    if (d.origin != an::kDataUser || d.spec.string != an::StringKind::none || d.spec.type.empty() || d.spec.element == 0)
      continue;
    auto raw = ctx.get<Types>({program, d.spec.type});
    auto resolved = ctx.get<ResolvedTypes>({program, d.spec.type});
    if (raw->empty() || *raw == *resolved) continue;
    std::map<std::string, std::string> records(resolved->begin(), resolved->end());
    types::TypeStore store;
    std::map<std::string, types::TypeId> ids;
    try {
      ids = InternRecords(records, store);
    } catch (const facts::DecodeError &) {
      continue;
    }
    auto id = ids.find(d.spec.type);
    if (id == ids.end()) continue;
    an::DataItem item = d;
    an::DataSpec &spec = item.spec;
    LayOutElement(store, id->second, spec);
    spec.type_name = ElementName(store, id->second);
    // The mark's extent and stride stay: what doesn't fit an element (and
    // what is inside it) is left out.
    std::vector<an::DataField> kept;
    std::uint32_t skip = 0;
    for (an::DataField &f : spec.fields) {
      if (skip != 0 && f.depth > skip) continue;
      skip = 0;
      if (f.offset + f.size > spec.element) {
        skip = f.depth;
        continue;
      }
      kept.push_back(std::move(f));
    }
    spec.fields = std::move(kept);
    std::erase_if(spec.pointers, [&](std::uint64_t off) { return off + spec.pointer_size > spec.element; });
    // Its pointers' references, as analysis.data reads them (user_item).
    item.refs.clear();
    item.value = 0;
    item.kind = spec.count == 0 && spec.format == an::ValueFormat::pointer ? an::DataKind::pointer : an::DataKind::defined;
    if (spec.pointer_size != 0 && spec.pointer_size <= 8 && !spec.pointers.empty()) {
      if (!l) l.emplace(Load(ctx, program));
      QueryPatches patches(ctx, l->source->ram_space);
      const bool big = l->program.image().endian == loader::Endian::big;
      const std::uint64_t elements = std::max<std::uint64_t>(spec.count, 1);
      for (std::uint64_t e = 0; e < elements && item.refs.size() < (1u << 16); ++e)
        for (std::uint64_t off : spec.pointers) {
          const std::uint64_t slot = item.address + e * spec.element + off;
          if (slot + spec.pointer_size > item.address + item.length) break;
          const std::string b = l->program.read(slot, spec.pointer_size, &patches);
          if (b.size() != spec.pointer_size) continue;
          std::uint64_t v = 0;
          for (std::size_t i = 0; i < b.size(); ++i)
            v |= std::uint64_t{static_cast<unsigned char>(b[big ? b.size() - 1 - i : i])} << (8 * i);
          if (item.kind == an::DataKind::pointer) item.value = v;
          if (v != 0 && l->program.block_containing(v) != nullptr) item.refs.emplace_back(slot, v);
        }
    }
    out.push_back(std::move(item));
  }
  return out;
}

Xrefs::Value Xrefs::compute(QueryContext &ctx, const Key &program) {
  auto funcs = ctx.get<Functions>(program);
  XrefTable t;
  for (const Func &f : funcs->funcs) {
    auto mine = ctx.get<FunctionXrefs>({program, f.entry});
    t.xrefs.insert(t.xrefs.end(), mine->begin(), mine->end());
  }
  std::sort(t.xrefs.begin(), t.xrefs.end(), [](const StaticXref &a, const StaticXref &b) {
    return std::tie(a.from, a.to, a.kind) < std::tie(b.from, b.to, b.kind);
  });
  // References from data: the user's data definitions' pointers
  // (docs/listing-edit.md), and the pointers analysis and the loader laid
  // down, where they hold a mapped address (Ghidra's pointer data).
  facts::Ref<an::DataList> raw;
  an::DataList storage;
  const an::DataList &data = EffectiveData(ctx, program, raw, storage);
  std::optional<Loaded> l;
  auto add = [&](std::uint64_t from, std::uint64_t to) {
    StaticXref x;
    x.from = from;
    x.to = to;
    x.kind = pb::XREF_KIND_DATA_POINTER;
    t.xrefs.push_back(x);
  };
  for (const an::DataItem &d : data.items) {
    if (d.origin == an::kDataUser) {
      for (const auto &[slot, to] : d.refs) add(slot, to);
    } else if (d.kind == an::DataKind::pointer && d.value != 0) {
      if (!l) l.emplace(Load(ctx, program));
      if (l->program.block_containing(d.value) != nullptr) add(d.address, d.value);
    }
  }
  std::sort(t.xrefs.begin(), t.xrefs.end(), [](const StaticXref &a, const StaticXref &b) {
    return std::tie(a.from, a.to, a.kind) < std::tie(b.from, b.to, b.kind);
  });
  t.xrefs.erase(std::unique(t.xrefs.begin(), t.xrefs.end(),
                            [](const StaticXref &a, const StaticXref &b) {
                              return a.from == b.from && a.to == b.to && a.kind == b.kind;
                            }),
                t.xrefs.end());
  // User references (docs/api.md, "Equates and user references"): the
  // ones added, in place of analysis's from the same instruction to the
  // same address of the same kind; a removal takes away analysis's (of any
  // kind) from the instruction to the address.
  {
    auto src = ctx.get<Source>(program);
    const facts::SpaceId space = src->ram_space;
    std::vector<StaticXref> added;
    std::set<std::pair<std::uint64_t, std::uint64_t>> removed;
    for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::Reference, {space, 0}, {space, ~std::uint64_t{0}})) {
      auto v = ctx.get<AssertedFact>(k);
      const std::string *text = String(*v);
      if (!text) continue;
      auto r = an::parse_user_ref(k.sub, *text);
      if (!r) continue;
      if (r->remove) {
        removed.emplace(k.addr.offset, r->to);
        continue;
      }
      StaticXref x;
      x.from = k.addr.offset;
      x.to = r->to;
      x.operand = r->operand;
      x.user = true;
      x.primary = r->primary;
      switch (r->type) {
        case an::UserRefType::data: x.kind = pb::XREF_KIND_DATA_POINTER; break;
        case an::UserRefType::read: x.kind = pb::XREF_KIND_DATA_READ; break;
        case an::UserRefType::write: x.kind = pb::XREF_KIND_DATA_WRITE; break;
        case an::UserRefType::call: x.kind = pb::XREF_KIND_CALL; break;
        case an::UserRefType::jump: x.kind = pb::XREF_KIND_JUMP; break;
        case an::UserRefType::computed_call: x.kind = pb::XREF_KIND_INDIRECT_CALL; break;
        case an::UserRefType::computed_jump: x.kind = pb::XREF_KIND_INDIRECT_JUMP; break;
      }
      added.push_back(x);
    }
    if (!added.empty() || !removed.empty()) {
      std::erase_if(t.xrefs, [&](const StaticXref &x) {
        if (removed.contains({x.from, x.to})) return true;
        return std::any_of(added.begin(), added.end(),
                           [&](const StaticXref &u) { return u.from == x.from && u.to == x.to && u.kind == x.kind; });
      });
      // A user reference at a removed pair is the user's own key's: a
      // removal at another operand's key doesn't take it away.
      t.xrefs.insert(t.xrefs.end(), added.begin(), added.end());
      std::sort(t.xrefs.begin(), t.xrefs.end(), [](const StaticXref &a, const StaticXref &b) {
        return std::tie(a.from, a.to, a.kind, a.operand) < std::tie(b.from, b.to, b.kind, b.operand);
      });
    }
  }
  t.index();
  return t;
}

std::size_t Xrefs::weight(const Value &v) {
  return sizeof(Value) + v.xrefs.capacity() * sizeof(StaticXref) + v.by_to.capacity() * sizeof(std::uint32_t);
}

DefaultNames::Value DefaultNames::compute(QueryContext &ctx, const Key &program) {
  auto loader = ctx.get<LoaderNames>(program);
  auto funcs = ctx.get<Functions>(program);
  auto xrefs = ctx.get<Xrefs>(program);
  facts::Ref<an::DataList> raw;
  an::DataList storage;
  const an::DataList &data = EffectiveData(ctx, program, raw, storage);
  return Load(ctx, program).program.DefaultLabels(*loader, *funcs, *xrefs, data);
}

Rows::Value Rows::compute(QueryContext &ctx, const Key &program) {
  auto code = ctx.get<Code>(program);
  auto labels = ctx.get<DefaultNames>(program);
  facts::Ref<an::DataList> raw;
  an::DataList storage;
  const an::DataList &data = EffectiveData(ctx, program, raw, storage);
  return Load(ctx, program).program.Rows(*code, *labels, data);
}

std::size_t Rows::weight(const Value &v) {
  std::size_t n = sizeof(Value);
  for (const auto &s : v.spans) n += sizeof(s) + s.rows.capacity() * sizeof(std::uint32_t);
  return n;
}

// The data settings a listing page shows by (data_settings.h): the items'
// and fields' over the page's addresses (from the item the first row is
// in), and every type's defaults.
DataSettingsMap PageDataSettings(QueryContext &ctx, facts::SpaceId space, const RowIndex &rows, std::int64_t page) {
  DataSettingsMap out;
  const std::int64_t first = page * RowIndex::kPageRows, last = std::min(rows.total_rows, first + RowIndex::kPageRows);
  if (first >= last) return out;
  auto read = [&](const facts::FactKey &k) -> std::optional<DataSettings> {
    auto v = ctx.get<AssertedFact>(k);
    const std::string *text = String(*v);
    if (!text || text->empty()) return std::nullopt;
    return DataSettings::parse(*text);
  };
  for (const facts::FactKey &k : facts::asserted_at(ctx, FactKind::Note, facts::Address{space, 0})) {
    if (!k.sub.starts_with(kDataTypeSettingsPrefix)) continue;
    if (auto s = read(k)) out.types.emplace(k.sub.substr(kDataTypeSettingsPrefix.size()), std::move(*s));
  }
  const std::uint64_t lo = rows.span_of_row(first).start, hi = rows.row_address(last - 1);
  for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::Note, {space, lo}, {space, hi})) {
    if (k.sub != kDataSettingsTag && !k.sub.starts_with(kDataFieldSettingsPrefix)) continue;
    if (auto s = read(k))
      out.items.emplace(std::pair{k.addr.offset, k.sub == kDataSettingsTag ? std::string() : k.sub.substr(kDataFieldSettingsPrefix.size())},
                        std::move(*s));
  }
  return out;
}

Page::Value Page::compute(QueryContext &ctx, const Key &key) {
  auto rows = ctx.get<Rows>(key.first);
  Loaded l = Load(ctx, key.first);
  QueryPatches patches(ctx, l.source->ram_space);
  const DataSettingsMap settings = PageDataSettings(ctx, l.source->ram_space, *rows, key.second);
  return l.program.Page(*rows, key.second, &patches, settings.empty() ? nullptr : &settings);
}

std::size_t Page::weight(const Value &v) {
  std::size_t n = sizeof(Value);
  for (const auto &r : v) {
    n += sizeof(r) + r.bytes.capacity() + r.tokens.capacity() * sizeof(lift::Token);
    for (const auto &t : r.tokens) n += t.text.capacity();
  }
  return n;
}

SearchPage::Value SearchPage::compute(QueryContext &ctx, const Key &key) {
  auto rows = ctx.get<Rows>(key.first);
  Loaded l = Load(ctx, key.first);
  QueryPatches patches(ctx, l.source->ram_space);
  Value out;
  const DataSettingsMap settings = PageDataSettings(ctx, l.source->ram_space, *rows, key.second);
  for (const StaticRow &r : l.program.Page(*rows, key.second, &patches, settings.empty() ? nullptr : &settings))
    out.push_back(SearchRow::From(r));
  return out;
}

std::size_t SearchPage::weight(const Value &v) {
  std::size_t n = sizeof(Value);
  for (const auto &r : v)
    n += sizeof(r) + r.text.capacity() + r.numbers.capacity() * sizeof(SearchRow::Number) + r.data_type.capacity() +
         r.data_mnemonic.capacity() + r.bytes.capacity();
  return n;
}

HeaderBucket::Value HeaderBucket::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, index] = key;
  // The program's space only: not its memory map.
  auto source = ctx.get<q::Source>(program);
  const facts::SpaceId space = source->ram_space;
  auto rows = ctx.get<Rows>(program);
  auto funcs = ctx.get<Functions>(program);
  auto labels = ctx.get<DefaultNames>(program);
  const std::uint64_t lo = index << facts::kBucketShift, hi = lo + ((std::uint64_t{1} << facts::kBucketShift) - 1);
  // (address, lines), then summed per address. The predicates match what
  // GetListing renders (image_backend.cc, HeaderLines).
  std::vector<std::pair<std::uint64_t, std::uint32_t>> lines;
  for (auto f = std::lower_bound(funcs->funcs.begin(), funcs->funcs.end(), lo,
                                 [](const Func &x, std::uint64_t v) { return x.entry < v; });
       f != funcs->funcs.end() && f->entry <= hi; ++f)
    lines.emplace_back(f->entry, 2);  // signature, label
  for (auto lb = std::lower_bound(labels->labels.begin(), labels->labels.end(), lo,
                                  [](const Label &x, std::uint64_t v) { return x.address < v; });
       lb != labels->labels.end() && lb->address <= hi; ++lb)
    if (!funcs->at(lb->address)) lines.emplace_back(lb->address, 1);
  for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::Name, {space, lo}, {space, hi})) {
    if (!k.sub.empty() || funcs->at(k.addr.offset) || labels->find(k.addr.offset)) continue;
    auto v = ctx.get<AssertedFact>(k);
    if (const std::string *name = String(*v); name && !name->empty()) lines.emplace_back(k.addr.offset, 1);
  }
  for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::Comment, {space, lo}, {space, hi})) {
    if (k.sub != "plate" && k.sub != "pre") continue;
    auto v = ctx.get<AssertedFact>(k);
    if (const std::string *text = String(*v); text && !text->empty())
      lines.emplace_back(k.addr.offset, static_cast<std::uint32_t>(CommentLines(*text).size()));
  }
  std::sort(lines.begin(), lines.end());
  backend::HeaderBucket out;
  for (std::size_t i = 0; i < lines.size();) {
    const std::uint64_t a = lines[i].first;
    std::uint32_t n = 0;
    for (; i < lines.size() && lines[i].first == a; ++i) n += lines[i].second;
    // Only code units' own addresses have header lines (as only they show
    // their labels and comments).
    const std::int64_t r = rows->row_at(a);
    if (n == 0 || r >= rows->total_rows || rows->row_address(r) != a) continue;
    out.entries.push_back({a, r, n, 0});
  }
  out.index();
  return out;
}

HeaderSlots::Value HeaderSlots::compute(QueryContext &ctx, const Key &program) {
  // The program's space only: not its memory map.
  auto source = ctx.get<q::Source>(program);
  const facts::SpaceId space = source->ram_space;
  auto funcs = ctx.get<Functions>(program);
  auto labels = ctx.get<DefaultNames>(program);
  std::vector<std::uint64_t> out;
  auto add = [&](std::uint64_t index) {
    if (out.empty() || out.back() != index) out.push_back(index);
  };
  for (const Func &f : funcs->funcs) add(f.entry >> facts::kBucketShift);
  for (const Label &lb : labels->labels) add(lb.address >> facts::kBucketShift);
  for (FactKind kind : {FactKind::Name, FactKind::Comment})
    for (std::uint64_t index : *ctx.get<facts::AssertedBuckets>({kind, space})) out.push_back(index);
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

Headers::Value Headers::compute(QueryContext &ctx, const Key &program) {
  auto slots = ctx.get<HeaderSlots>(program);
  HeaderIndex out;
  for (std::uint64_t index : *slots) {
    auto bucket = ctx.get<q::HeaderBucket>({program, index});
    if (bucket->entries.empty()) continue;
    out.buckets.push_back({index, bucket->entries.front().row, bucket->entries.back().row, bucket->lines, 0});
  }
  out.index();
  return out;
}

namespace {

std::optional<std::uint64_t> ParseHex(std::string_view s) {
  if (!s.starts_with("0x") || s.size() == 2) return std::nullopt;
  std::uint64_t v = 0;
  for (char c : s.substr(2)) {
    int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    if (d < 0 || v >> 60) return std::nullopt;
    v = v * 16 + static_cast<std::uint64_t>(d);
  }
  return v;
}

}  // namespace

// The parameters a decompilation found, as Ghidra's commitParamsToDatabase
// commits them without their types: each in its storage, undefinedN. None
// where one isn't in one piece of storage, or the list has a gap.
static std::optional<std::vector<lift::ParamFacts>> FoundParameters(const pb::DecompiledFunction &f, const Program &program) {
  std::map<std::uint32_t, const pb::Variable *> by_index;
  for (const pb::Variable &v : f.variables())
    if (v.kind() == pb::VARIABLE_KIND_PARAMETER) by_index.emplace(v.parameter_index(), &v);
  if (by_index.empty()) return std::nullopt;
  const inputs::DataOrg org = inputs::data_org(program.image(), program.language().id());
  std::vector<lift::ParamFacts> out;
  for (const auto &[index, v] : by_index) {
    if (index != out.size() || v->storage_size() != 1) return std::nullopt;
    const pb::Varnode &s = v->storage(0);
    if (s.space() == "join" || s.size() == 0 || s.size() > 8) return std::nullopt;
    lift::ParamFacts p;
    p.name = v->name();
    p.storage.push_back({s.space(), s.offset(), static_cast<int>(s.size())});
    p.stack = s.space() == "stack";
    p.type = inputs::builtin_type("undefined" + std::to_string(s.size()), org);
    out.push_back(std::move(p));
  }
  return out;
}

VariableTypes::Value VariableTypes::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, entry] = key;
  auto src = ctx.get<Source>(program);
  const facts::SpaceId space = src->ram_space;
  Value out;
  std::optional<std::vector<lift::RegisterDef>> registers;
  for (const facts::FactKey &k : facts::asserted_at(ctx, FactKind::Type, {space, entry})) {
    if (!k.sub.starts_with("local:")) continue;
    auto type = ctx.get<AssertedFact>(k);
    const std::string *t = String(*type);
    // A C-text type the parser couldn't read stays display only.
    if (t == nullptr || !t->starts_with("h:") || t->size() == 2) continue;
    VariableType v;
    v.key = k.sub.substr(6);
    v.hash = t->substr(2);
    auto name = ctx.get<AssertedFact>(FactKeyAt(FactKind::Name, space, entry, k.sub));
    if (const std::string *n = String(*name)) v.name = *n;
    // The storage the key names (decompiler.cc's StorageText). A key made
    // unique with "#n", a temporary's (unique space, which Ghidra maps by
    // a hash of the p-code) or a name's names none.
    const std::string_view sk = v.key;
    const auto colon = sk.find(':');
    if (sk.starts_with("param:")) {
      const std::string_view n = sk.substr(6);
      if (!n.empty() && n.size() < 4 && std::all_of(n.begin(), n.end(), [](char c) { return c >= '0' && c <= '9'; }))
        v.param = std::stoi(std::string(n));
    } else if (colon != std::string_view::npos && sk.find('#') == std::string_view::npos) {
      const std::string sp(sk.substr(0, colon));
      std::string_view rest = sk.substr(colon + 1);
      std::optional<std::uint64_t> pc;
      if (const auto at = rest.find('@'); at != std::string_view::npos) {
        pc = ParseHex(rest.substr(at + 1));
        rest = rest.substr(0, at);
      }
      if (sp == "stack") {
        const bool neg = rest.starts_with('-');
        if (std::optional<std::uint64_t> off = ParseHex(neg ? rest.substr(1) : rest)) {
          v.space = sp;
          v.offset = neg ? 0 - *off : *off;
        }
      } else if (sp != "unique" && sp != "name" && pc) {
        if (std::optional<std::uint64_t> off = ParseHex(rest)) {
          v.space = sp;
          v.offset = *off;
        } else {
          if (!registers) registers = Load(ctx, program).program.lifter()->registers();
          for (const lift::RegisterDef &r : *registers)
            if (r.space == sp && r.name == rest) {
              v.space = sp;
              v.offset = r.offset;
              v.size = r.size;
              break;
            }
        }
        if (!v.space.empty()) v.pc = pc;
      }
    }
    out.push_back(std::move(v));
  }
  return out;
}

Symbol::Value Symbol::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, addr] = key;
  Loaded l = Load(ctx, program);
  const facts::SpaceId space = l.source->ram_space;
  // Only this address's function: a discovery change elsewhere validates.
  auto func = ctx.get<an::Function>(an::Location{AnalysisKey(program), addr});
  auto name = ctx.get<AssertedFact>(FactKeyAt(FactKind::Name, space, addr));
  auto type = ctx.get<AssertedFact>(FactKeyAt(FactKind::Type, space, addr));
  const std::string *asserted = String(*name);
  if (asserted && asserted->empty()) asserted = nullptr;  // an empty rename restores the default

  SymbolInfo s;
  // Only hashed types reach the decompiler; a C-text retype is display only
  // and must not re-decompile anything.
  if (const std::string *t = String(*type); t && t->starts_with("h:")) s.type = *t;
  // A user's data definition here types it, under any TYPE assertion
  // (docs/listing-edit.md).
  if (s.type.empty() && !String(*type)) {
    auto data = ctx.get<an::Data>(AnalysisKey(program));
    if (const an::DataItem *d = data->at(addr); d && d->origin == an::kDataUser && !d->spec.item_type.empty())
      s.type = "h:" + d->spec.item_type;
  }
  s.asserted = asserted != nullptr;
  if (!s.type.empty() && String(*type)) {
    // Who gave the type: a demangled prototype outranks an agent's
    // (docs/demangle.md). TYPE keys keep their winner's order.
    auto order = ctx.get<facts::AssertedOrder>(FactKeyAt(FactKind::Type, space, addr));
    if (order->size() >= 8) {
      std::uint64_t r = 0;
      for (int i = 0; i < 8; ++i) r = (r << 8) | static_cast<unsigned char>((*order)[i]);
      s.type_rank = static_cast<int>(r);
    }
  }
  if (!func->name.empty()) {
    s.kind = SymbolInfo::Kind::Function;
    s.name = asserted ? *asserted : inputs::demangled_name(func->name).value_or(func->name);
    s.no_return = (func->flags & an::kFunctionNoReturn) != 0;
    return s;
  }
  auto defaults = ctx.get<DefaultNames>(program);
  const Label *label = defaults->find(addr);
  if (!asserted && !label) {
    s.type.clear();  // a type with no symbol tells the decompiler nothing yet
    return s;
  }
  s.kind = l.program.executable(addr) ? SymbolInfo::Kind::CodeLabel : SymbolInfo::Kind::Data;
  s.name = asserted ? *asserted : label->name;
  s.size = label ? label->size : 0;
  return s;
}

DemangleScopes::Value DemangleScopes::compute(QueryContext &ctx, const Key &program) {
  Loaded l = Load(ctx, program);
  const loader::Image &image = l.program.image();
  inputs::ClassScopes scopes;
  auto add = [&](const std::string &name) {
    if (demangle::detect(name) == demangle::Scheme::None) return;
    if (auto d = demangle::parse(name)) scopes.add(*d);
  };
  for (const loader::Symbol &s : image.symbols) add(s.name);
  for (const loader::Export &e : image.exports) add(e.name);
  for (const loader::Import &i : image.imports) add(i.name);
  return scopes.list();
}

RttiClasses::Value RttiClasses::compute(QueryContext &ctx, const Key &program) {
  Loaded l = Load(ctx, program);
  const msvc::Rtti rtti = msvc::scan_rtti(l.program.image());
  pb::GetClassHierarchyResponse out;
  auto addr = [](std::uint64_t a) {
    pb::Address x;
    x.set_offset(a);
    return x;
  };
  std::map<std::string, std::set<std::string>> derived;
  for (const msvc::ClassInfo &c : rtti.classes) {
    pb::RttiClass *k = out.add_classes();
    k->set_name(c.name);
    k->set_mangled(c.mangled);
    k->set_is_struct(c.is_struct);
    *k->mutable_type_descriptor() = addr(c.type_descriptor);
    if (c.hierarchy != 0) *k->mutable_hierarchy() = addr(c.hierarchy);
    k->set_hierarchy_attributes(c.hierarchy_attributes);
    k->set_type_name((c.is_struct ? "struct " : "class ") + c.name);
    const std::vector<std::size_t> direct = c.direct_bases();
    for (std::size_t i = 1; i < c.bases.size(); ++i) {
      const msvc::BaseClass &b = c.bases[i];
      pb::RttiBase *x = k->add_bases();
      x->set_name(b.name);
      *x->mutable_type_descriptor() = addr(b.type_descriptor);
      *x->mutable_base_descriptor() = addr(b.descriptor);
      x->set_direct(std::find(direct.begin(), direct.end(), i) != direct.end());
      x->set_is_virtual(b.is_virtual());
      x->set_offset(b.mdisp);
      x->set_vbtable_offset(b.pdisp);
      x->set_vbtable_index(b.vdisp);
      x->set_attributes(b.attributes);
      x->set_depth(b.depth);
      if (x->direct() && !b.name.empty()) derived[b.name].insert(c.name);
    }
  }
  for (const msvc::Vftable &t : rtti.vftables) {
    pb::RttiVftable *v = out.mutable_classes(static_cast<int>(t.cls))->add_vftables();
    *v->mutable_address() = addr(t.address);
    *v->mutable_locator() = addr(t.locator);
    v->set_offset(t.offset);
    if (t.subobject != t.cls) v->set_subobject(rtti.classes[t.subobject].name);
    for (std::size_t i = 0; i < t.entries.size(); ++i) {
      pb::RttiVirtualFunction *f = v->add_functions();
      f->set_slot(static_cast<std::uint32_t>(i));
      *f->mutable_entry() = addr(t.entries[i]);
    }
  }
  for (pb::RttiClass &k : *out.mutable_classes())
    for (const std::string &d : derived[k.name()]) k.add_derived(d);
  std::sort(out.mutable_classes()->begin(), out.mutable_classes()->end(),
            [](const pb::RttiClass &a, const pb::RttiClass &b) { return a.name() < b.name(); });
  return Deterministic(out);
}

Demangled::Value Demangled::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, entry] = key;
  Loaded l = Load(ctx, program);
  auto func = ctx.get<an::Function>(an::Location{AnalysisKey(program), entry});
  if (func->name.empty() || demangle::detect(func->name) == demangle::Scheme::None) return std::nullopt;
  std::optional<demangle::Demangled> d = demangle::parse(func->name);
  if (!d || !d->function) return std::nullopt;
  auto list = ctx.get<DemangleScopes>(program);
  inputs::ClassScopes scopes;
  for (const std::string &c : *list) scopes.insert(c);
  types::TypeStore store;
  const cparse::Profile profile = ProgramProfile(l.program);
  std::optional<inputs::DemangledPrototype> p = inputs::demangled_prototype(*d, scopes, profile, store);
  if (!p) return std::nullopt;
  DemangledProto out;
  out.full = d->full;
  // "<ret> \x01(<params>)": the pieces around the name.
  const std::string text = inputs::demangled_display(*p, store, "\x01");
  const std::size_t at = text.find('\x01');
  if (at == std::string::npos) return std::nullopt;
  out.ret = text.substr(0, at);
  while (!out.ret.empty() && out.ret.back() == ' ') out.ret.pop_back();
  out.params = text.substr(at + 1);
  out.this_guessed = p->this_guessed;
  const auto *fn = store.get(p->type).as<types::FunctionType>();
  for (std::size_t i = p->has_this ? 1 : 0; fn != nullptr && i < fn->params.size(); ++i) {
    const types::TypeId t = store.strip_typedefs(fn->params[i].type);
    out.param_float.push_back(store.kind(t) == types::Kind::Float);
  }
  if (p->this_guessed && fn != nullptr) {
    // The same without `this`, renumbered.
    types::FunctionType without = *fn;
    without.params.erase(without.params.begin());
    for (std::size_t i = 0; i < without.params.size(); ++i)
      if (without.params[i].name.starts_with("param_")) without.params[i].name = "param_" + std::to_string(i + 1);
    inputs::DemangledPrototype q = *p;
    q.type = store.function(std::move(without));
    q.has_this = false;
    const std::string t2 = inputs::demangled_display(q, store, "\x01");
    if (const std::size_t a2 = t2.find('\x01'); a2 != std::string::npos) out.params_static = t2.substr(a2 + 1);
  }
  return out;
}

Container::Value Container::compute(QueryContext &ctx, const Key &key) {
  auto defaults = ctx.get<DefaultNames>(key.first);
  const Label *l = defaults->containing(key.second);
  return l && l->size != 0 ? l->address : key.second;
}

namespace {

// The project's types (docs/types.md#project-types): TYPE_DEF keys in the
// project's space, which every program of the project sees after its own.
facts::FactKey ProjectTypeKey(const std::string &sub) {
  facts::FactKey k = TypeDefKey(archive::kProjectSpace, sub);
  k.addr.offset = archive::kProjectTypesAddress;
  return k;
}

}  // namespace

Types::Value Types::compute(QueryContext &ctx, const Key &key) {
  auto src = ctx.get<Source>(key.first);
  std::map<std::string, std::string> found;
  std::deque<std::string> work{key.second};
  while (!work.empty()) {
    std::string hash = std::move(work.front());
    work.pop_front();
    if (found.contains(hash)) continue;
    auto rec = ctx.get<AssertedFact>(TypeDefKey(src->ram_space, hash));
    const std::string *bytes = String(*rec);
    facts::Ref<facts::FactValue> project;
    facts::Ref<LibraryTypes> lib;
    if (!bytes) {
      // Not the program's: the project's, else the library archive's.
      project = ctx.get<AssertedFact>(ProjectTypeKey(hash));
      bytes = String(*project);
    }
    if (!bytes) {
      lib = ctx.get<Library>(key.first);
      bytes = lib->record(hash);
    }
    if (!bytes) continue;
    try {
      for (const std::string &ref : DecodeTypeRecord(*bytes).refs) work.push_back(ref);
    } catch (const facts::DecodeError &) {
      continue;
    }
    found.emplace(std::move(hash), *bytes);
  }
  return {found.begin(), found.end()};
}

void TypeArchiveSetting::encode(facts::Encoder &e) const {
  e.bytes(name);
  e.u8((enabled ? 1 : 0) | (attached ? 2 : 0));
  e.bytes(header);
  e.bytes(sidecar);
}

TypeArchiveSetting TypeArchiveSetting::decode(facts::Decoder &d) {
  TypeArchiveSetting s;
  s.name = std::string(d.bytes());
  const std::uint8_t f = d.u8();
  s.enabled = f & 1;
  s.attached = f & 2;
  s.header = std::string(d.bytes());
  s.sidecar = std::string(d.bytes());
  return s;
}

TypeArchiveSettings::Value TypeArchiveSettings::compute(QueryContext &ctx, const Key &) {
  Value out;
  for (const facts::FactKey &k :
       facts::asserted_at(ctx, FactKind::Note, facts::Address{archive::kProjectSpace, archive::kTypeArchiveAddress})) {
    if (!k.sub.starts_with(archive::kTypeArchiveSubPrefix)) continue;
    auto v = ctx.get<AssertedFact>(k);
    const std::string *bytes = String(*v);
    if (!bytes || bytes->empty()) continue;  // detached
    pb::TypeArchiveSetting body;
    if (!body.ParseFromString(*bytes)) continue;
    TypeArchiveSetting s;
    s.name = k.sub.substr(archive::kTypeArchiveSubPrefix.size());
    s.enabled = body.enabled();
    s.attached = !body.header().empty();
    s.header = body.header();
    s.sidecar = body.sidecar();
    out.push_back(std::move(s));
  }
  std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) { return a.name < b.name; });
  return out;
}

LibraryPrototypes::Value LibraryPrototypes::compute(QueryContext &ctx, const Key &program) {
  auto src = ctx.get<q::Source>(program);
  if (!src->program) throw std::logic_error("program " + program + " is not loaded");
  const Program &p = *src->program;
  auto settings = ctx.get<TypeArchiveSettings>(0);
  std::map<std::string, const TypeArchiveSetting *> by_name;
  for (const TypeArchiveSetting &s : *settings) by_name.emplace(s.name, &s);
  auto enabled = [&](const std::string &name) {
    auto it = by_name.find(name);
    return it == by_name.end() || it->second->enabled;
  };
  LibraryRef out;
  out.ghidra = enabled("ghidra");
  std::vector<inputs::LibraryArchiveText> texts;
  for (const std::string &name : inputs::default_library_archives(p.image())) {
    auto it = by_name.find(name);
    if (it != by_name.end() && it->second->attached) continue;  // an attached archive of that name replaces it
    if (enabled(name))
      if (std::optional<std::string> h = inputs::read_library_archive(name)) texts.push_back({name, std::move(*h)});
  }
  // Archives attached to the project apply to every program, after the
  // shipped ones (whose prototypes come first where both declare a name).
  for (const TypeArchiveSetting &s : *settings)
    if (s.attached && s.enabled) texts.push_back({s.name, s.header});
  if (texts.empty()) return out;
  out.lib = inputs::parse_library(texts, ProgramProfile(p));
  out.identity = out.lib->identity;
  return out;
}

Library::Value Library::compute(QueryContext &ctx, const Key &program) {
  // The image's format and data organization only: not its memory map.
  auto src = ctx.get<q::Source>(program);
  if (!src->program) throw std::logic_error("program " + program + " is not loaded");
  const Program &p = *src->program;
  auto ref = ctx.get<LibraryPrototypes>(program);
  LibraryTypes out;
  if (ref->lib) out = ConvertLibrary(*ref->lib);
  if (!ref->ghidra) return out;
  std::optional<std::filesystem::path> root = lift::ghidra_root();
  if (!root) return out;
  const loader::Image &image = p.image();
  const bool pe = image.format == loader::Format::pe;
  auto archive = inputs::GhidraArchive::for_program(*root, pe, image.bits);
  if (!archive) return out;
  const std::string name = pe ? (image.bits == 64 ? "windows_vs12_64" : "windows_vs12_32") : (image.bits == 64 ? "generic_clib_64" : "generic_clib");
  // Plain char is signed on x86, unsigned on ARM, AArch64, RISC-V, PowerPC.
  const bool char_signed = p.language().id().starts_with("x86");
  LibraryTypes ghidra = ConvertArchive(*archive, name, inputs::data_org(image, p.language().id()), char_signed);
  if (out.archive.empty()) return ghidra;
  MergeLibraryTypes(out, ghidra);
  return out;
}

std::size_t Library::weight(const Value &v) {
  std::size_t n = sizeof(Value);
  for (const auto &[h, r] : v.records) n += h.capacity() + r.capacity() + 64;
  for (const auto &[k, h] : v.named) n += k.capacity() + h.capacity() + 64;
  return n;
}

TypeNames::Value TypeNames::compute(QueryContext &ctx, const Key &program) {
  auto src = ctx.get<Source>(program);
  NamedTypes out;
  for (const facts::FactKey &k : facts::asserted_at(ctx, FactKind::TypeDef, facts::Address{src->ram_space, 0})) {
    auto v = ctx.get<AssertedFact>(k);
    const std::string *bytes = String(*v);
    if (!bytes) continue;
    if (IsTypeNameSub(k.sub)) {
      if (bytes->starts_with("h:")) out.bindings.emplace_back(k.sub.substr(5), bytes->substr(2));
      continue;
    }
    if (IsTypeCategorySub(k.sub)) continue;
    try {
      if (std::string named = NamedTypeKey(DecodeTypeRecord(*bytes).type); !named.empty())
        out.types.push_back({std::move(named), k.sub});
    } catch (const facts::DecodeError &) {
    }
  }
  // The project's (docs/types.md#project-types): its named types the
  // program doesn't define itself, and its bindings of names the program
  // doesn't bind.
  std::set<std::string> have, own_keys, own_bound;
  for (const auto &t : out.types) {
    have.insert(t.hash);
    own_keys.insert(t.key);
  }
  for (const auto &[key, hash] : out.bindings) own_bound.insert(key);
  for (const facts::FactKey &k :
       facts::asserted_at(ctx, FactKind::TypeDef, facts::Address{archive::kProjectSpace, archive::kProjectTypesAddress})) {
    auto v = ctx.get<AssertedFact>(k);
    const std::string *bytes = String(*v);
    if (!bytes) continue;
    if (IsTypeNameSub(k.sub)) {
      if (bytes->starts_with("h:") && !own_bound.contains(k.sub.substr(5)))
        out.bindings.emplace_back(k.sub.substr(5), bytes->substr(2));
      continue;
    }
    if (IsTypeCategorySub(k.sub) || have.contains(k.sub)) continue;
    try {
      if (std::string named = NamedTypeKey(DecodeTypeRecord(*bytes).type); !named.empty()) {
        NamedTypes::Entry e{std::move(named), k.sub};
        e.project = true;
        have.insert(k.sub);
        out.types.push_back(std::move(e));
      }
    } catch (const facts::DecodeError &) {
    }
  }
  // The library archive's, unless the program or the project defines that very type.
  auto lib = ctx.get<Library>(program);
  for (const auto &[key, hash] : lib->named)
    if (!have.contains(hash)) out.types.push_back({key, hash, true});
  std::sort(out.types.begin(), out.types.end(),
            [](const auto &a, const auto &b) { return std::tie(a.key, a.hash) < std::tie(b.key, b.hash); });
  std::sort(out.bindings.begin(), out.bindings.end());
  return out;
}

AggregateIds::Value AggregateIds::compute(QueryContext &ctx, const Key &program) {
  auto src = ctx.get<Source>(program);
  Value out;
  auto add = [&](const std::string &hash, std::string_view bytes) {
    const std::uint64_t id = inputs::aggregate_id(hash);
    if (id == 0) return;
    try {
      if (DecodeTypeRecord(bytes).type.as<types::AggregateType>() != nullptr) out.emplace_back(id, hash);
    } catch (const facts::DecodeError &) {
    }
  };
  for (const facts::FactKey &k : facts::asserted_at(ctx, FactKind::TypeDef, facts::Address{src->ram_space, 0})) {
    if (IsTypeNameSub(k.sub) || IsTypeCategorySub(k.sub)) continue;
    auto v = ctx.get<AssertedFact>(k);
    if (const std::string *bytes = String(*v)) add(k.sub, *bytes);
  }
  for (const facts::FactKey &k :
       facts::asserted_at(ctx, FactKind::TypeDef, facts::Address{archive::kProjectSpace, archive::kProjectTypesAddress})) {
    if (IsTypeNameSub(k.sub) || IsTypeCategorySub(k.sub)) continue;
    auto v = ctx.get<AssertedFact>(k);
    if (const std::string *bytes = String(*v)) add(k.sub, *bytes);
  }
  auto lib = ctx.get<Library>(program);
  for (const auto &[hash, bytes] : lib->records) add(hash, bytes);
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

TypeCategories::Value TypeCategories::compute(QueryContext &ctx, const Key &program) {
  auto src = ctx.get<Source>(program);
  Value out;
  std::set<std::string> filed;  // keys the program files (a "/" too)
  for (const facts::FactKey &k : facts::asserted_at(ctx, FactKind::TypeDef, facts::Address{src->ram_space, 0})) {
    if (!IsTypeCategorySub(k.sub)) continue;
    auto v = ctx.get<AssertedFact>(k);
    const std::string *path = String(*v);
    if (!path) continue;
    filed.insert(k.sub);
    if (path->empty() || *path == "/") continue;
    out.emplace_back(k.sub.substr(kTypeCategorySub.size()), *path);
  }
  // The project's filing of the names the program doesn't file.
  for (const facts::FactKey &k :
       facts::asserted_at(ctx, FactKind::TypeDef, facts::Address{archive::kProjectSpace, archive::kProjectTypesAddress})) {
    if (!IsTypeCategorySub(k.sub) || filed.contains(k.sub)) continue;
    auto v = ctx.get<AssertedFact>(k);
    const std::string *path = String(*v);
    if (!path || path->empty() || *path == "/") continue;
    out.emplace_back(k.sub.substr(kTypeCategorySub.size()), *path);
  }
  std::sort(out.begin(), out.end());
  return out;
}

ResolvedTypes::Value ResolvedTypes::compute(QueryContext &ctx, const Key &key) {
  auto src = ctx.get<Source>(key.first);
  auto record = [&](const std::string &hash) -> std::optional<std::string> {
    auto rec = ctx.get<AssertedFact>(TypeDefKey(src->ram_space, hash));
    if (const std::string *bytes = String(*rec)) return *bytes;
    auto project = ctx.get<AssertedFact>(ProjectTypeKey(hash));
    if (const std::string *bytes = String(*project)) return *bytes;
    auto lib = ctx.get<Library>(key.first);
    if (const std::string *bytes = lib->record(hash)) return *bytes;
    return std::nullopt;
  };
  std::map<std::string, std::string> found;
  std::deque<std::string> work{key.second};
  while (!work.empty()) {
    std::string hash = std::move(work.front());
    work.pop_front();
    if (found.contains(hash)) continue;
    std::optional<std::string> bytes = record(hash);
    if (!bytes) continue;
    std::string rec = std::move(*bytes);
    TypeRecord decoded;
    try {
      decoded = DecodeTypeRecord(rec);
    } catch (const facts::DecodeError &) {
      continue;
    }
    // A bound name: its definition stands in for this one.
    if (std::string named = NamedTypeKey(decoded.type); !named.empty()) {
      // The program's binding of the name, else the project's.
      auto bound = ctx.get<AssertedFact>(TypeDefKey(src->ram_space, TypeNameSub(named)));
      const std::string *b = String(*bound);
      facts::Ref<facts::FactValue> project_bound;
      if (!b || !b->starts_with("h:")) {
        project_bound = ctx.get<AssertedFact>(ProjectTypeKey(TypeNameSub(named)));
        b = String(*project_bound);
      }
      if (b && b->starts_with("h:") && b->substr(2) != hash)
        if (std::optional<std::string> other = record(b->substr(2))) {
          try {
            TypeRecord r = DecodeTypeRecord(*other);
            if (NamedTypeKey(r.type) == named) {
              rec = *other;
              decoded = std::move(r);
            }
          } catch (const facts::DecodeError &) {
          }
        }
    }
    for (const std::string &ref : decoded.refs) work.push_back(ref);
    found.emplace(std::move(hash), std::move(rec));
  }
  return {found.begin(), found.end()};
}

std::size_t Types::weight(const Value &v) {
  std::size_t n = sizeof(Value);
  for (const auto &[h, r] : v) n += h.capacity() + r.capacity() + sizeof(std::pair<std::string, std::string>);
  return n;
}

Inputs::Value Inputs::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, entry] = key;
  auto src = ctx.get<Source>(program);
  const an::Location at{AnalysisKey(program), entry};
  auto f = ctx.get<an::Function>(at);
  DecompileInputs in;
  in.entry = entry;
  if (f->name.empty()) return in;
  in.exists = true;
  in.body = Ranges(f->body);
  // Jump tables discovery recovered in the body, for the decompiler to use
  // where it can't recover them itself.
  auto flow = ctx.get<an::Flow>(an::Location{at.program, f->flow_key()});
  for (const an::FlowInsn &i : flow->insns)
    if (i.kind == an::FlowKind::jump_indirect && !i.targets.empty() && f->body.contains({f->entry.space, i.address}))
      in.jump_tables.emplace(i.address, i.targets);
  std::vector<Range> scan = in.body;
  if (!Contains(scan, entry)) scan.emplace_back(entry, entry);
  const facts::SpaceId space = src->ram_space;
  for (const Range &r : scan) {
    for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::Comment, {space, r.first}, {space, r.second})) {
      pb::CommentKind kind = CommentKindOf(k.sub);
      if (kind == pb::COMMENT_KIND_UNSPECIFIED) continue;
      auto v = ctx.get<AssertedFact>(k);
      if (const std::string *text = String(*v); text && !text->empty())
        in.comments.push_back({k.addr.offset, kind, *text});
    }
    for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::FlowOverride, {space, r.first}, {space, r.second})) {
      auto v = ctx.get<AssertedFact>(k);
      if (const auto *kind = std::get_if<std::int64_t>(&*v)) in.flow_overrides[k.addr.offset] = static_cast<int>(*kind);
    }
  }
  std::sort(in.comments.begin(), in.comments.end(), [](const auto &a, const auto &b) {
    return std::tie(a.address, a.kind) < std::tie(b.address, b.kind);
  });
  // The user's equates and references in the body (docs/api.md, "Equates
  // and user references").
  std::map<std::uint64_t, std::vector<an::UserRef>> calls;
  for (const Range &r : scan) {
    for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::Equate, {space, r.first}, {space, r.second})) {
      auto v = ctx.get<AssertedFact>(k);
      const std::string *text = String(*v);
      auto sub = an::parse_equate_sub(k.sub);
      auto d = text ? an::parse_operand_display(*text) : std::nullopt;
      if (!sub || !d) continue;
      lift::EquateFacts e;
      e.addr = k.addr.offset;
      e.value = sub->value;
      e.hash = sub->hash;
      if (d->equate()) {
        e.name = d->name;
      } else {
        switch (d->format) {
          case an::ScalarFormat::none: continue;
          case an::ScalarFormat::hex: e.format = 1; break;
          case an::ScalarFormat::signed_dec:
          case an::ScalarFormat::unsigned_dec: e.format = 2; break;
          case an::ScalarFormat::octal: e.format = 3; break;
          case an::ScalarFormat::binary: e.format = 4; break;
          case an::ScalarFormat::chr: e.format = 5; break;
          case an::ScalarFormat::flt:
            // The decompiler has no float conversion: the text, as an equate.
            e.name = an::format_scalar(sub->value, sub->value >> 32 == 0 ? 32 : 64, d->format);
            break;
        }
      }
      in.equates.push_back(std::move(e));
    }
    // Calls' signature overrides (docs/api.md, "Call-site signature
    // overrides").
    for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::CallSignature, {space, r.first}, {space, r.second})) {
      auto v = ctx.get<AssertedFact>(k);
      if (const std::string *text = String(*v); text && text->starts_with("h:") && text->size() > 2)
        in.call_signatures[k.addr.offset] = text->substr(2);
    }
    for (const facts::FactKey &k : facts::asserted_keys(ctx, FactKind::Reference, {space, r.first}, {space, r.second})) {
      auto v = ctx.get<AssertedFact>(k);
      const std::string *text = String(*v);
      auto u = text ? an::parse_user_ref(k.sub, *text) : std::nullopt;
      if (!u || u->remove) continue;
      if (u->is_call()) {
        calls[k.addr.offset].push_back(*u);
      } else if (u->type == an::UserRefType::computed_jump) {
        // The jump's table: what discovery follows (its recovered targets
        // and the user's), given to the decompiler as an override.
        const an::FlowInsn *i = flow->at(k.addr.offset);
        if (i == nullptr || i->kind != an::FlowKind::jump_indirect) continue;
        auto &table = in.jump_tables[k.addr.offset];
        if (table.empty()) table = i->targets;
        if (std::find(table.begin(), table.end(), u->to) == table.end()) table.push_back(u->to);
        in.forced_tables.insert(k.addr.offset);
      }
    }
  }
  // A computed call's user call reference, the primary one (or the only
  // one), is the call's target (Ghidra's call override).
  for (const auto &[at, refs] : calls) {
    const an::FlowInsn *i = flow->at(at);
    if (i == nullptr || (i->kind != an::FlowKind::call_indirect && !(i->kind == an::FlowKind::call && i->resolved)))
      continue;
    const an::UserRef *pick = nullptr;
    for (const an::UserRef &u : refs)
      if (u.primary) pick = &u;
    if (pick == nullptr && refs.size() == 1) pick = &refs[0];
    if (pick != nullptr) in.call_targets[at] = pick->to;
  }
  return in;
}


Decompile::Value Decompile::compute(QueryContext &ctx, const Key &key) {
  const auto &[program, entry] = key;
  Loaded l = Load(ctx, program);
  ctx.get<DecompilerOptions>(program);
  auto inputs = ctx.get<Inputs>(key);
  if (!inputs->exists) {
    DecompileOutput out;
    out.function.mutable_entry()->set_offset(entry);
    out.function.add_warnings("no function at this address");
    return out;
  }
  auto image = ctx.get<InputsImage>(program);
  QueryLookup lookup(ctx, program, entry);
  DecompileOutput out = l.program.decompiler().Decompile(*inputs, *image, lookup);
  for (const std::string &w : lookup.warnings()) out.function.add_warnings(w);
  if (!lookup.needs_found()) return out;
  // A variable's type needs what this decompilation found (the parameters
  // where nothing locked the prototype, a temporary's hash): committed,
  // it runs again.
  QueryLookup::Found found;
  found.params = FoundParameters(out.function, l.program);
  found.hashes.insert(out.dynamic.begin(), out.dynamic.end());
  if (!found.params && found.hashes.empty()) return out;
  QueryLookup again(ctx, program, entry);
  again.commit_found(std::move(found));
  DecompileOutput typed = l.program.decompiler().Decompile(*inputs, *image, again);
  for (const std::string &w : again.warnings()) typed.function.add_warnings(w);
  typed.touched.insert(typed.touched.end(), out.touched.begin(), out.touched.end());
  std::sort(typed.touched.begin(), typed.touched.end());
  typed.touched.erase(std::unique(typed.touched.begin(), typed.touched.end()), typed.touched.end());
  return typed;
}

std::size_t Decompile::weight(const Value &v) {
  return sizeof(Value) + v.function.SpaceUsedLong() + v.touched.capacity() * 8 + v.references.capacity() * 8 +
         v.prototype.capacity() * sizeof(DecompileOutput::TokenRef) + v.declaration_types.capacity() * 16 +
         [&] {
           std::size_t n = 0;
           for (const auto &[key, list] : v.accesses) n += 48 + key.size() + list.capacity() * sizeof(infer::PointerAccess);
           return n;
         }();
}

}  // namespace q

void RegisterQueries(facts::Engine &engine) {
  engine.add_input<q::Source>();
  engine.add_input<q::DebugFile>();
  engine.add_input<q::Programs>();
  engine.add_input<q::DecompilerOptions>();
  analysis::register_queries(engine);  // analysis.program and discovery
  plugins::register_queries(engine);   // plugins.program and analyzer plugins
  infer::register_queries(engine);     // infer.*: prototypes, when staged
  engine.add_input<q::InferPublished>();  // and as the background inference publishes them
  engine.add_query<q::LoaderNames>();
  engine.add_query<q::Functions>();
  engine.add_query<q::Code>();
  engine.add_query<q::FunctionXrefs>();
  engine.add_query<q::UserData>();
  engine.add_query<q::Xrefs>();
  engine.add_query<q::DefaultNames>();
  engine.add_query<q::DemangleScopes>();
  engine.add_query<q::RttiClasses>();
  engine.add_query<q::Demangled>();
  engine.add_query<q::Rows>();
  engine.add_query<q::Page>();
  engine.add_query<q::SearchPage>();
  engine.add_query<q::HeaderBucket>();
  engine.add_query<q::HeaderSlots>();
  engine.add_query<q::Headers>();
  engine.add_query<q::Symbol>();
  engine.add_query<q::VariableTypes>();
  engine.add_query<q::Container>();
  engine.add_query<q::Types>();
  engine.add_query<q::TypeArchiveSettings>();
  engine.add_query<q::LibraryPrototypes>();
  engine.add_query<q::Library>();
  engine.add_query<q::TypeNames>();
  engine.add_query<q::TypeCategories>();
  engine.add_query<q::AggregateIds>();
  engine.add_query<q::ResolvedTypes>();
  engine.add_query<q::Inputs>();
  RegisterInputQueries(engine);
  RegisterParamIdQueries(engine);
  RegisterSignatureQueries(engine);
  engine.add_query<q::Decompile>();
  RegisterAutoStructQueries(engine);  // infer.pointer_accesses (auto_struct.h)
  RegisterDiffQueries(engine);  // diff.*: fingerprints, matches, sessions (docs/diff.md)
}

}  // namespace revkit::backend
