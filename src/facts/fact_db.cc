#include "revkit/facts/fact_db.h"

#include <algorithm>
#include <limits>
#include <chrono>
#include <cstdio>
#include <random>
#include <set>
#include <tuple>

namespace revkit::facts {

namespace {

const std::string kRevisionKey = "revision";
const std::string kReplicaKey = "replica";

// Pages are persisted 16 to a record: a lone 4 KiB value would take two
// LMDB overflow pages, doubling the footprint of the byte store.
constexpr std::uint64_t kPagesPerChunk = 16;

std::string chunk_key(SpaceId space, std::uint64_t chunk) {
  Encoder e;
  e.varint(space);
  e.u64be(chunk);
  return std::move(e).str();
}

// A chunk record is a bitmap of present pages followed by their contents.
std::string encode_chunk(const std::vector<std::string> &pages) {
  Encoder e;
  std::uint32_t present = 0;
  for (std::size_t i = 0; i < pages.size(); ++i)
    if (!pages[i].empty()) present |= 1u << i;
  e.u32be(present);
  for (const auto &p : pages)
    if (!p.empty()) e.raw(p);
  return std::move(e).str();
}

std::string seq_key(Seq s) {
  Encoder e;
  e.u64be(s);
  return std::move(e).str();
}

std::string revision_value(Revision r) {
  Encoder e;
  e.u64be(r);
  return std::move(e).str();
}

}  // namespace

std::string AssertedFact::describe(const FactKey &k) {
  std::string s(to_string(k.kind));
  if (k.kind != FactKind::TypeDef)
    s += "@" + std::to_string(k.addr.space) + ":0x" + detail::to_hex(k.addr.offset);
  if (!k.sub.empty()) s += (k.kind == FactKind::TypeDef ? ":" : "/") + k.sub;
  return s;
}

AssertedSpan::Value AssertedSpan::compute(QueryContext &ctx, const BucketKey &key) {
  constexpr unsigned kShift = kBucketShift - kSpanShift;
  auto bucket = ctx.get<AssertedKeys>(BucketKey{key.kind, key.space, key.index >> kShift});
  auto in_span = [&](const std::pair<std::uint64_t, std::string> &k) { return (k.first >> kSpanShift) == key.index; };
  auto first = std::find_if(bucket->begin(), bucket->end(), in_span);
  return {first, std::find_if_not(first, bucket->end(), in_span)};
}

std::vector<FactKey> asserted_at(QueryContext &ctx, FactKind kind, Address at) {
  std::vector<FactKey> out;
  auto span = ctx.get<AssertedSpan>(BucketKey{kind, at.space, at.offset >> kSpanShift});
  for (auto it = std::lower_bound(span->begin(), span->end(), std::pair{at.offset, std::string()});
       it != span->end() && it->first == at.offset; ++it)
    out.push_back(FactKey{kind, at, it->second});
  return out;
}

std::vector<FactKey> asserted_keys(QueryContext &ctx, FactKind kind, Address first, Address last) {
  std::vector<FactKey> out;
  if (first.space != last.space || first.offset > last.offset) return out;
  // A range of a few spans reads them, so it only depends on keys near it.
  constexpr std::uint64_t kMaxSpans = 16;
  if ((last.offset >> kSpanShift) - (first.offset >> kSpanShift) < kMaxSpans) {
    for (std::uint64_t i = first.offset >> kSpanShift;; ++i) {
      auto keys = ctx.get<AssertedSpan>(BucketKey{kind, first.space, i});
      for (const auto &[offset, sub] : *keys)
        if (offset >= first.offset && offset <= last.offset) out.push_back(FactKey{kind, Address{first.space, offset}, sub});
      if (i == last.offset >> kSpanShift) break;
    }
    return out;
  }
  const std::uint64_t lo = first.offset >> kBucketShift, hi = last.offset >> kBucketShift;
  auto read = [&](std::uint64_t index) {
    auto keys = ctx.get<AssertedKeys>(BucketKey{kind, first.space, index});
    for (const auto &[offset, sub] : *keys)
      if (offset >= first.offset && offset <= last.offset) out.push_back(FactKey{kind, Address{first.space, offset}, sub});
  };
  // A narrow range reads its buckets directly; a wide one goes through the
  // directory instead of probing millions of empty buckets.
  if (hi - lo < 8) {
    for (std::uint64_t i = lo;; ++i) {
      read(i);
      if (i == hi) break;
    }
  } else {
    auto dir = ctx.get<AssertedBuckets>({kind, first.space});
    for (std::uint64_t i : *dir)
      if (i >= lo && i <= hi) read(i);
  }
  return out;
}

class FactDb::IndexUpdate {
 public:
  explicit IndexUpdate(Engine::Writer &w) : w_(w) {}

  void change(const FactKey &k, bool present) {
    Pending &p = buckets_[BucketKey{k.kind, k.addr.space, k.addr.offset >> kBucketShift}];
    std::pair<std::uint64_t, std::string> entry{k.addr.offset, k.sub};
    if (present) {
      p.del.erase(entry);
      p.add.push_back(std::move(entry));
    } else {
      p.del.insert(std::move(entry));
    }
  }

  // Merges in sorted batches: one import can add a whole bucket's worth of
  // keys (every type definition lands in bucket 0), and inserting them one
  // at a time into a sorted vector would be quadratic.
  void stage() {
    for (auto &[b, p] : buckets_) {
      auto cur_ref = w_.latest<AssertedKeys>(b);
      const AssertedKeys::Value &cur = *cur_ref;
      AssertedKeys::Value next;
      next.reserve(cur.size() + p.add.size());
      for (const auto &e : cur)
        if (!p.del.contains(e)) next.push_back(e);
      std::erase_if(p.add, [&](const auto &e) { return p.del.contains(e); });
      std::sort(p.add.begin(), p.add.end());
      const auto middle = static_cast<std::ptrdiff_t>(next.size());
      next.insert(next.end(), std::make_move_iterator(p.add.begin()), std::make_move_iterator(p.add.end()));
      std::inplace_merge(next.begin(), next.begin() + middle, next.end());
      next.erase(std::unique(next.begin(), next.end()), next.end());
      if (cur.empty() != next.empty()) {
        auto &dir = directory(b.kind, b.space);
        auto pos = std::lower_bound(dir.begin(), dir.end(), b.index);
        if (next.empty()) dir.erase(pos);
        else dir.insert(pos, b.index);
      }
      w_.set<AssertedKeys>(b, std::move(next));
    }
    for (auto &[k, dir] : dirs_) w_.set<AssertedBuckets>(k, std::move(dir));
  }

 private:
  struct Pending {
    std::vector<std::pair<std::uint64_t, std::string>> add;
    std::set<std::pair<std::uint64_t, std::string>> del;
  };

  std::vector<std::uint64_t> &directory(FactKind kind, SpaceId space) {
    auto it = dirs_.find({kind, space});
    if (it == dirs_.end()) it = dirs_.emplace(std::pair{kind, space}, *w_.latest<AssertedBuckets>({kind, space})).first;
    return it->second;
  }

  Engine::Writer &w_;
  std::map<BucketKey, Pending> buckets_;
  std::map<std::pair<FactKind, SpaceId>, std::vector<std::uint64_t>> dirs_;
};

std::string read_bytes(QueryContext &ctx, Address addr, std::size_t n) {
  std::string out;
  out.reserve(n);
  while (out.size() < n) {
    std::uint64_t off = addr.offset + out.size();
    if (off < addr.offset) break;  // wrapped
    auto page = ctx.get<MemoryPage>(PageKey{addr.space, off / kPageSize});
    std::size_t in_page = off % kPageSize;
    if (page->size() <= in_page) break;
    std::size_t take = std::min(n - out.size(), page->size() - in_page);
    out.append(*page, in_page, take);
  }
  return out;
}

// ---- Rebase ----

std::string Shift::str() const {
  char buf[48];
  std::snprintf(buf, sizeof buf, "0x%llx/%u", static_cast<unsigned long long>(delta), bits);
  return buf;
}

std::optional<Shift> Shift::parse(std::string_view text) {
  const std::size_t slash = text.find('/');
  if (slash == std::string_view::npos || !text.starts_with("0x") || slash < 3) return std::nullopt;
  Shift s;
  s.delta = 0;
  for (char c : text.substr(2, slash - 2)) {
    const int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
    if (d < 0 || (s.delta >> 60) != 0) return std::nullopt;
    s.delta = s.delta << 4 | static_cast<std::uint64_t>(d);
  }
  unsigned bits = 0;
  const std::string_view b = text.substr(slash + 1);
  if (b.empty() || b.size() > 2) return std::nullopt;
  for (char c : b) {
    if (c < '0' || c > '9') return std::nullopt;
    bits = bits * 10 + static_cast<unsigned>(c - '0');
  }
  if (bits == 0 || bits > 64) return std::nullopt;
  s.bits = bits;
  return s;
}

namespace {

bool default_moves(const FactKey &k) {
  return k.kind != FactKind::TypeDef && k.kind != FactKind::Rebase && k.kind != FactKind::Language;
}

// The Shift a Rebase key's value says (identity: none).
Shift shift_of(const FactValue &v) {
  if (const auto *t = std::get_if<std::string>(&v))
    if (auto s = Shift::parse(*t)) return *s;
  return {};
}

}  // namespace

FactKey shifted_key(const Relocator *r, const FactKey &k, const Shift &shift) {
  if (shift.identity()) return k;
  FactKey out = k;
  if (r ? r->moves(k) : default_moves(k)) out.addr.offset = shift.apply(k.addr.offset);
  if (r)
    if (auto sub = r->sub(k, shift)) out.sub = std::move(*sub);
  return out;
}

FactValue shifted_value(const Relocator *r, const FactKey &stored, const FactValue &v, const Shift &shift) {
  if (shift.identity()) return v;
  const SpaceId space = stored.addr.space;
  if (const auto *a = std::get_if<Address>(&v)) {
    if (a->space != space) return v;
    return Address{space, shift.apply(a->offset)};
  }
  if (const auto *set = std::get_if<AddressSet>(&v)) {
    AddressSet out;
    for (const AddressRange &range : set->ranges()) {
      if (range.first.space != space || !shift.moves(range.first.offset) || !shift.moves(range.last.offset)) {
        out.add(range);
        continue;
      }
      const std::uint64_t first = shift.apply(range.first.offset), last = shift.apply(range.last.offset);
      if (first <= last) {
        out.add(AddressRange{{space, first}, {space, last}});
      } else {  // wrapped at the top of the space
        const std::uint64_t top = shift.bits >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << shift.bits) - 1;
        out.add(AddressRange{{space, first}, {space, top}});
        out.add(AddressRange{{space, 0}, {space, last}});
      }
    }
    return out;
  }
  if (const auto *t = std::get_if<std::string>(&v); t && r)
    if (auto moved = r->value(stored, *t, shift)) return std::move(*moved);
  return v;
}

Shift FactDb::shift(SpaceId space) const {
  std::lock_guard lock(shift_mu_);
  auto it = shifts_.find(space);
  return it == shifts_.end() ? Shift{} : it->second;
}

FactKey FactDb::moved(const FactKey &stored) const {
  if (stored.kind == FactKind::Rebase) return stored;
  return shifted_key(opt_.relocator.get(), stored, shift(stored.addr.space));
}

FactValue FactDb::moved_value(const FactKey &stored, const FactValue &v) const {
  if (stored.kind == FactKind::Rebase) return v;
  return shifted_value(opt_.relocator.get(), stored, v, shift(stored.addr.space));
}

namespace {

std::string order_of(const AssertionLog &log, const FactKey &k) {
  std::optional<Op> w = log.winner(k);
  if (!w) return {};
  Encoder e;
  e.u64be(static_cast<std::uint64_t>(rank(w->prov.kind)));
  e.u64be(w->stamp);
  e.u64be(w->id.replica);
  e.u64be(w->id.counter);
  e.u64be(w->seq);
  return std::move(e).str();
}

}  // namespace

PatchSpan::Value PatchSpan::compute(QueryContext &ctx, const Key &key) {
  Value out;
  for (const auto &[offset, sub] : *ctx.get<AssertedSpan>(BucketKey{FactKind::Patch, key.first, key.second})) {
    if (!sub.empty()) continue;
    const FactKey k{FactKind::Patch, Address{key.first, offset}, sub};
    auto v = ctx.get<AssertedFact>(k);
    const std::string *bytes = std::get_if<std::string>(&*v);
    if (bytes == nullptr || bytes->empty()) continue;
    out.push_back({*ctx.get<AssertedOrder>(k), {offset, *bytes}});
  }
  return out;
}

PatchedPage::Value PatchedPage::compute(QueryContext &ctx, const Key &key) {
  // Keys starting in [from, last]: those that can reach into the page. The
  // bucket's keys are sorted, and the range lies in at most two buckets.
  const std::uint64_t first = key.index * kPageSize, last = first + (kPageSize - 1);
  const std::uint64_t from = first >= kMaxPatchBytes - 1 ? first - (kMaxPatchBytes - 1) : 0;
  for (std::uint64_t b = from >> kBucketShift;; ++b) {
    const auto keys = ctx.get<AssertedKeys>(BucketKey{FactKind::Patch, key.space, b});
    auto it = std::lower_bound(keys->begin(), keys->end(), std::pair{from, std::string()});
    if (it != keys->end() && it->first <= last) return true;
    if (b == last >> kBucketShift) return false;
  }
}

namespace {

// patches_overlapping() over a context or a snapshot (anything with get<Q>).
template <class Reader>
PatchList overlapping(Reader &r, SpaceId space, std::uint64_t first, std::uint64_t last) {
  if (last < first) return {};
  // A patch overlapping the range starts at most kMaxPatchBytes - 1 bytes
  // before it.
  const std::uint64_t from = first >= kMaxPatchBytes - 1 ? first - (kMaxPatchBytes - 1) : 0;
  if ((last >> kSpanShift) - (from >> kSpanShift) <= 64) {
    // Every patch over the range overlaps one of its pages: none may, none does.
    bool gated = false;
    for (std::uint64_t p = first / kPageSize; !gated; ++p) {
      gated = *r.template get<PatchedPage>(PageKey{space, p});
      if (p == last / kPageSize) break;
    }
    if (!gated) return {};
  }
  std::vector<std::pair<std::string, std::pair<std::uint64_t, std::string>>> found;
  auto take = [&](const PatchSpan::Value &span) {
    for (const auto &e : span) {
      const std::uint64_t at = e.second.first, end = at + (e.second.second.size() - 1);
      if (end >= first && at <= last) found.push_back(e);
    }
  };
  if ((last >> kSpanShift) - (from >> kSpanShift) <= 64) {
    // A page's 17 spans one by one, so a patch elsewhere in the 64 KiB
    // bucket only re-runs the span filters, which cut off.
    for (std::uint64_t i = from >> kSpanShift;; ++i) {
      take(*r.template get<PatchSpan>({space, i}));
      if (i == last >> kSpanShift) break;
    }
  } else {
    // A wide range: the spans that have patches, through the bucket directory.
    for (std::uint64_t b : *r.template get<AssertedBuckets>({FactKind::Patch, space})) {
      if (b < from >> kBucketShift || b > last >> kBucketShift) continue;
      std::set<std::uint64_t> spans;
      for (const auto &[offset, sub] : *r.template get<AssertedKeys>(BucketKey{FactKind::Patch, space, b}))
        if (offset >= from && offset <= last) spans.insert(offset >> kSpanShift);
      for (std::uint64_t i : spans) take(*r.template get<PatchSpan>({space, i}));
    }
  }
  std::sort(found.begin(), found.end());
  PatchList out;
  out.reserve(found.size());
  for (auto &[order, p] : found) out.push_back(std::move(p));
  return out;
}

}  // namespace

PatchList patches_overlapping(QueryContext &ctx, SpaceId space, std::uint64_t first, std::uint64_t last) {
  return overlapping(ctx, space, first, last);
}

PatchList patches_overlapping(const Snapshot &snap, SpaceId space, std::uint64_t first, std::uint64_t last) {
  return overlapping(snap, space, first, last);
}

void apply_patches(const PatchList &patches, std::uint64_t at, std::string &bytes) {
  for (const auto &[p, data] : patches)
    for (std::size_t i = 0; i < data.size(); ++i) {
      const std::uint64_t a = p + i;
      if (a >= at && a - at < bytes.size()) bytes[static_cast<std::size_t>(a - at)] = data[i];
    }
}

EffectivePage::Value EffectivePage::compute(QueryContext &ctx, const Key &key) {
  auto page = ctx.get<MemoryPage>(key);
  std::string out = *page;
  if (out.empty()) return out;
  const std::uint64_t first = key.index * kPageSize, last = first + (kPageSize - 1);
  apply_patches(patches_overlapping(ctx, key.space, first, last), first, out);
  return out;
}

std::string read_effective_bytes(QueryContext &ctx, Address addr, std::size_t n) {
  std::string out;
  out.reserve(n);
  while (out.size() < n) {
    std::uint64_t off = addr.offset + out.size();
    if (off < addr.offset) break;  // wrapped
    auto page = ctx.get<EffectivePage>(PageKey{addr.space, off / kPageSize});
    std::size_t in_page = off % kPageSize;
    if (page->size() <= in_page) break;
    std::size_t take = std::min(n - out.size(), page->size() - in_page);
    out.append(*page, in_page, take);
  }
  return out;
}

FactDb::FactDb(FactDbOptions opt) : opt_(std::move(opt)) {
  private_storage_ = !opt_.storage;
  storage_ = opt_.storage ? std::move(opt_.storage) : make_memory_storage();

  Revision last = 0;
  if (auto r = storage_->get(Table::Meta, kRevisionKey)) {
    if (r->size() != 8) throw StorageError("corrupt revision record");
    Decoder d(*r);
    last = d.u64be();
  }
  // This replica's id: given, recorded, or new (and recorded).
  replica_ = opt_.replica;
  if (!replica_) {
    if (auto r = storage_->get(Table::Meta, kReplicaKey)) {
      if (r->size() != 8) throw StorageError("corrupt replica record");
      Decoder d(*r);
      replica_ = d.u64be();
    }
  }
  if (!replica_) {
    std::random_device rd;
    while (!replica_) replica_ = std::uint64_t{rd()} << 32 | rd();
  }
  {
    Encoder e;
    e.u64be(replica_);
    WriteBatch b;
    b.put(Table::Meta, kReplicaKey, std::move(e).str());
    storage_->write(b);
  }
  log_.set_local_replica(replica_);

  engine_ = std::make_unique<Engine>(EngineOptions{opt_.keep_evicted ? storage_.get() : nullptr, opt_.memo_budget, last});
  engine_->add_input<AssertedFact>();
  engine_->add_input<MemoryPage>();
  engine_->add_input<LogLength>();
  engine_->add_input<AssertedKeys>();
  engine_->add_input<AssertedBuckets>();
  engine_->add_input<AssertedOrder>();
  engine_->add_query<AssertedSpan>();
  engine_->add_query<PatchSpan>();
  engine_->add_query<PatchedPage>();
  engine_->add_query<EffectivePage>();

  // Replay the log in chunks so liveness is rebuilt without holding every op.
  std::vector<Op> chunk;
  auto apply = [&] {
    log_.append(chunk);
    chunk.clear();
  };
  try {
    storage_->scan(Table::Log, "", [&](std::string_view, std::string_view v) {
      chunk.push_back(decode_from_string<Op>(v));
      if (chunk.size() >= 65536) apply();
      return true;
    });
  } catch (const DecodeError &e) {
    throw StorageError(std::string("corrupt assertion log: ") + e.what());
  }
  apply();
  clock_ = log_.max_stamp();

  // Rebased spaces first: every key is indexed where it reads now.
  const std::vector<FactKey> all_keys = log_.keys();
  for (const FactKey &k : all_keys)
    if (k.kind == FactKind::Rebase)
      if (Shift sh = shift_of(log_.effective(k)); !sh.identity()) shifts_[k.addr.space] = sh;
  auto w = engine_->begin_write();
  {
    IndexUpdate index(w);
    for (const FactKey &k : all_keys) {
      FactValue v = log_.effective(k);
      if (std::holds_alternative<std::monostate>(v)) continue;
      const FactKey mk = moved(k);
      index.change(mk, true);
      if (ordered_kind(k.kind)) w.set<AssertedOrder>(mk, order_of(log_, k));
      w.set<AssertedFact>(mk, moved_value(k, v));
    }
    index.stage();
    if (log_.size()) w.set<LogLength>(0, log_.size());
  }
  try {
    storage_->scan(Table::Bytes, "", [&](std::string_view k, std::string_view v) {
      Decoder kd(k);
      auto space = decode<SpaceId>(kd);
      std::uint64_t chunk = kd.u64be();
      kd.expect_done();
      Decoder vd(v);
      std::uint32_t present = vd.u32be();
      for (std::uint64_t i = 0; i < kPagesPerChunk; ++i)
        if (present & (1u << i))
          w.set<MemoryPage>(PageKey{space, chunk * kPagesPerChunk + i}, std::string(vd.raw(kPageSize)));
      vd.expect_done();
      return true;
    });
  } catch (const DecodeError &e) {
    throw StorageError(std::string("corrupt byte store: ") + e.what());
  }
  if (!w.empty()) {
    // Persist the opening revision too: memos computed now carry it, and the
    // next session must start past it.
    WriteBatch b;
    b.put(Table::Meta, kRevisionKey, revision_value(engine_->revision() + 1));
    storage_->write(b);
    w.commit();
  }
}

FactDb::~FactDb() = default;

std::int64_t FactDb::now() const {
  if (opt_.clock) return opt_.clock();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

Stamp FactDb::tick() {
  const Stamp physical = static_cast<Stamp>(std::max<std::int64_t>(0, now() / 1000000)) << kStampLogicalBits;
  // Saturating: a clock at the top stays there instead of wrapping to 0,
  // where every later stamp would sort before the ones already made.
  const Stamp c = clock_.load();
  const Stamp s = std::max(c == std::numeric_limits<Stamp>::max() ? c : c + 1, physical);
  clock_ = s;
  return s;
}

void FactDb::observe(Stamp s) {
  if (s > clock_.load()) clock_ = s;
}

std::size_t FactDb::waiting() const {
  std::lock_guard lock(waiting_mu_);
  return waiting_.size();
}

FactDbTransaction::FactDbTransaction(FactDb &db) : db_(&db), writer_(db.engine_->begin_write()) {}

FactDb::Transaction FactDb::begin() { return Transaction(*this); }

Revision FactDbTransaction::next_revision() const { return db_->engine_->revision() + 1; }
Seq FactDbTransaction::next_seq() const { return db_->log_.next_seq() + ops_.size(); }

Stamp FactDbTransaction::stamp() {
  if (!stamp_) stamp_ = db_->tick();
  return stamp_;
}

bool FactDbTransaction::known(const OpId &id) const {
  if (db_->log_.has(id)) return true;
  auto it = staged_vv_.find(id.replica);
  return it != staged_vv_.end() && id.counter <= it->second;
}

std::optional<Seq> FactDbTransaction::seq_of(const OpId &id) const {
  if (auto it = staged_ids_.find(id); it != staged_ids_.end()) return it->second;
  return db_->log_.find(id);
}

OpId FactDbTransaction::next_local_id() {
  const ReplicaId r = db_->replica_;
  auto it = staged_vv_.find(r);
  std::uint64_t c = it != staged_vv_.end() ? it->second : 0;
  if (!c) {
    const VersionVector vv = db_->log_.version_vector();
    if (auto v = vv.find(r); v != vv.end()) c = v->second;
  }
  return {r, c + 1};
}

// Validates op (with its seq and seq references set) against the log and
// what is staged, then stages it.
void FactDbTransaction::stage(Op op) {
  writer();
  db_->log_.validate(op, ops_);
  staged_vv_[op.id.replica] = op.id.counter;
  staged_ids_[op.id] = op.seq;
  ops_.push_back(std::move(op));
}

Engine::Writer &FactDbTransaction::writer() {
  if (!writer_) throw std::logic_error("transaction already committed");
  return *writer_;
}

Seq FactDbTransaction::assert_fact(const Provenance &who, FactKey key, FactValue value,
                                     Seq depends_on, std::string meta) {
  // The key reads moved in a rebased space: it is stored image-relative.
  if (key.kind != FactKind::Rebase)
    if (const Shift sh = db_->shift(key.addr.space); !sh.identity()) {
      const Shift back = sh.inverse();
      value = shifted_value(db_->relocator(), key, value, back);
      if (db_->relocator())
        if (auto m = db_->relocator()->meta(key, meta, back)) meta = std::move(*m);
      key = shifted_key(db_->relocator(), key, back);
    }
  Op op;
  op.seq = next_seq();
  op.time_ns = db_->now();
  op.prov = who;
  op.kind = OpKind::Assert;
  op.key = std::move(key);
  op.value = std::move(value);
  op.depends_on = depends_on;
  op.meta = std::move(meta);
  writer();
  op.id = next_local_id();
  op.stamp = stamp();
  if (depends_on) {
    const Seq committed = db_->log_.next_seq();
    if (depends_on >= committed && depends_on - committed < ops_.size()) op.depends_on_id = ops_[depends_on - committed].id;
    else if (auto d = db_->log_.op(depends_on)) op.depends_on_id = d->id;
  }
  // What this supersedes: the winner among its rank, counting what this
  // transaction staged before it.
  const int r = rank(who.kind);
  if (auto top = db_->log_.top_of_rank(op.key, r)) op.supersedes = *top;
  for (const Op &p : ops_)
    if (p.kind == OpKind::Assert && p.key == op.key && rank(p.prov.kind) == r) op.supersedes = p.id;
  stage(std::move(op));
  return ops_.back().seq;
}

Seq FactDbTransaction::retract(const Provenance &who, Seq target, std::string meta) {
  Op op;
  op.seq = next_seq();
  op.time_ns = db_->now();
  op.prov = who;
  op.kind = OpKind::Retract;
  op.target = target;
  op.meta = std::move(meta);
  writer();
  Seq committed = db_->log_.next_seq();
  if (target >= committed && target - committed < ops_.size()) {
    op.key = ops_[target - committed].key;
    op.target_id = ops_[target - committed].id;
  } else if (auto t = db_->log_.op(target)) {
    op.key = t->key;
    op.target_id = t->id;
  } else {
    throw std::invalid_argument("retraction of unknown op " + std::to_string(target));
  }
  op.id = next_local_id();
  op.stamp = stamp();
  stage(std::move(op));
  return ops_.back().seq;
}

MergeResult FactDbTransaction::merge(std::span<const Op> ops, const std::function<void(Op &)> &on_stage) {
  writer();
  MergeResult result;
  std::lock_guard lock(db_->waiting_mu_);
  auto &waiting = db_->waiting_;
  auto &waiting_on = db_->waiting_on_;
  // The first op `op` follows that isn't held or staged yet.
  auto missing = [&](const Op &op) -> std::optional<OpId> {
    if (op.id.counter > 1)
      if (OpId prev{op.id.replica, op.id.counter - 1}; !known(prev)) return prev;
    if (op.kind == OpKind::Retract && !known(op.target_id)) return op.target_id;
    if (op.kind == OpKind::Assert && op.depends_on_id && !known(op.depends_on_id)) return op.depends_on_id;
    return std::nullopt;
  };
  auto reject = [&](const Op &op, const std::string &why) {
    ++result.rejected;
    result.errors.push_back("op " + op.id.str() + ": " + why);
  };
  // Stages `first` if nothing it follows is missing, then whatever was
  // waiting on what got staged.
  auto place = [&](const OpId &first) {
    std::vector<OpId> work{first};
    while (!work.empty()) {
      const OpId id = work.back();
      work.pop_back();
      auto it = waiting.find(id);
      if (it == waiting.end()) continue;
      if (auto m = missing(it->second)) {
        waiting_on[*m].push_back(id);
        continue;
      }
      Op op = std::move(it->second);
      waiting.erase(it);
      op.seq = next_seq();
      op.target = op.depends_on = 0;
      try {
        if (op.kind == OpKind::Retract) op.target = *seq_of(op.target_id);
        else if (op.depends_on_id) op.depends_on = *seq_of(op.depends_on_id);
        if (on_stage) on_stage(op);
        db_->log_.validate(op, ops_);
      } catch (const std::invalid_argument &e) {
        // Its replica's later ops wait for it forever; between correct
        // replicas this cannot happen.
        reject(op, e.what());
        continue;
      }
      db_->observe(op.stamp);
      stage(std::move(op));
      ++result.staged;
      if (auto w = waiting_on.find(id); w != waiting_on.end()) {
        work.insert(work.end(), w->second.begin(), w->second.end());
        waiting_on.erase(w);
      }
    }
  };
  for (const Op &in : ops) {
    if (!in.id) {
      reject(in, "no id");
      continue;
    }
    if (in.kind == OpKind::Retract && !in.target_id) {
      reject(in, "retraction without a target id");
      continue;
    }
    if (known(in.id) || waiting.contains(in.id)) {
      ++result.duplicate;
      continue;
    }
    waiting.emplace(in.id, in);
    place(in.id);
  }
  result.waiting = waiting.size();
  return result;
}

std::vector<Seq> FactDbTransaction::revert(const Provenance &who, const Provenance &whose,
                                             Seq since) {
  // Newest first, so a retraction is undone before the op it targeted is
  // retracted; the end state is the same either way, the log reads better.
  auto seqs = db_->log_.ops_by(whose, since);
  std::vector<Seq> out;
  out.reserve(seqs.size());
  for (auto it = seqs.rbegin(); it != seqs.rend(); ++it) out.push_back(retract(who, *it));
  return out;
}

std::string &FactDbTransaction::page(PageKey k) {
  auto it = pages_.find(k);
  if (it == pages_.end()) {
    std::string cur = *writer().latest<MemoryPage>(k);
    if (cur.empty()) cur.assign(kPageSize, '\0');
    it = pages_.emplace(k, std::move(cur)).first;
  }
  return it->second;
}

void FactDbTransaction::write_bytes(Address at, std::string_view bytes) {
  if (!bytes.empty() && bytes.size() - 1 > ~std::uint64_t{0} - at.offset)
    throw std::out_of_range("write_bytes wraps the address space");
  std::size_t done = 0;
  while (done < bytes.size()) {
    std::uint64_t off = at.offset + done;
    std::string &p = page(PageKey{at.space, off / kPageSize});
    std::size_t in_page = off % kPageSize;
    std::size_t take = std::min(bytes.size() - done, kPageSize - in_page);
    p.replace(in_page, take, bytes.substr(done, take));
    done += take;
  }
}

Revision FactDbTransaction::commit(std::vector<FactKey> *changed) {
  Engine::Writer &w = writer();
  if (changed) changed->clear();
  if (ops_.empty() && pages_.empty() && !inputs_) {
    writer_.reset();
    return db_->engine_->revision();
  }

  // Ops that may change a space's Shift (a rebase, its undo or redo, a
  // revert, a peer's): appended first, so the client can stage what
  // follows the new base (bytes, inputs) in this commit, before anything
  // is written. (The log is ahead of the storage until the write below; a
  // storage error there is fatal to the store either way.)
  std::vector<FactKey> appended;
  bool early = false;
  std::map<SpaceId, std::pair<Shift, Shift>> rebased;
  // A program's language works the same way (FactKind::Language): what it
  // was before these ops, read before they are appended.
  std::map<FactKey, std::string> language_before;
  auto text_of = [](const FactValue &v) {
    const auto *s = std::get_if<std::string>(&v);
    return s ? *s : std::string();
  };
  for (const Op &op : ops_)
    if (op.key.kind == FactKind::Language && !language_before.contains(op.key))
      language_before[op.key] = text_of(db_->log_.effective(op.key));
  if (!language_before.empty() ||
      std::any_of(ops_.begin(), ops_.end(), [](const Op &op) { return op.key.kind == FactKind::Rebase; })) {
    const std::size_t staged = ops_.size();
    appended = db_->log_.append(ops_);
    early = true;
    for (const FactKey &k : appended) {
      if (k.kind != FactKind::Rebase) continue;
      const Shift before = db_->shift(k.addr.space), after = shift_of(db_->log_.effective(k));
      if (before != after) rebased[k.addr.space] = {before, after};
    }
    if (db_->opt_.on_rebase)
      for (const auto &[space, sh] : rebased) db_->opt_.on_rebase(*this, space, sh.first, sh.second);
    if (db_->opt_.on_language)
      for (const auto &[k, before] : language_before)
        if (const std::string after = text_of(db_->log_.effective(k)); after != before)
          db_->opt_.on_language(*this, k.addr.space, before, after);
    if (ops_.size() != staged) throw std::logic_error("on_rebase or on_language staged ops");
  }

  WriteBatch batch;
  for (const Op &op : ops_) batch.put(Table::Log, seq_key(op.seq), encode_to_string(op));
  // Rewrite each touched chunk whole, from staged pages and committed ones.
  for (auto it = pages_.begin(); !db_->private_storage_ && it != pages_.end();) {
    const PageKey first = it->first;
    const std::uint64_t chunk = first.index / kPagesPerChunk;
    std::vector<std::string> pages(kPagesPerChunk);
    for (std::uint64_t i = 0; i < kPagesPerChunk; ++i) {
      PageKey k{first.space, chunk * kPagesPerChunk + i};
      auto staged = pages_.find(k);
      pages[i] = staged != pages_.end() ? staged->second : *w.latest<MemoryPage>(k);
    }
    batch.put(Table::Bytes, chunk_key(first.space, chunk), encode_chunk(pages));
    while (it != pages_.end() && it->first.space == first.space &&
           it->first.index / kPagesPerChunk == chunk)
      ++it;
  }
  batch.put(Table::Meta, kRevisionKey, revision_value(db_->engine_->revision() + 1));
  db_->storage_->write(batch);

  if (!ops_.empty()) {
    FactDb::IndexUpdate index(w);
    const std::vector<FactKey> keys = early ? std::move(appended) : db_->log_.append(ops_);
    for (const auto &[space, sh] : rebased) db_->reindex(w, index, space, sh.first, sh.second, changed);
    for (const FactKey &k : keys) {
      // A rebased space's keys were all indexed again above.
      if (k.kind != FactKind::Rebase && rebased.contains(k.addr.space)) continue;
      const FactKey mk = db_->moved(k);
      // The winner can change without the value changing (an equal value
      // asserted later): its order still moves.
      if (ordered_kind(k.kind)) w.set<AssertedOrder>(mk, order_of(db_->log_, k));
      FactValue now = db_->moved_value(k, db_->log_.effective(k));
      auto before_ref = w.latest<AssertedFact>(mk);
      const FactValue &before = *before_ref;
      if (before == now) continue;
      if (changed) changed->push_back(mk);
      if (std::holds_alternative<std::monostate>(before) != std::holds_alternative<std::monostate>(now))
        index.change(mk, !std::holds_alternative<std::monostate>(now));
      w.set<AssertedFact>(mk, std::move(now));
    }
    index.stage();
    w.set<LogLength>(0, db_->log_.size());
    if (changed && !rebased.empty()) {
      std::sort(changed->begin(), changed->end());
      changed->erase(std::unique(changed->begin(), changed->end()), changed->end());
    }
  }
  for (auto &[k, v] : pages_) w.set<MemoryPage>(k, std::move(v));
  ops_.clear();
  pages_.clear();
  Revision r = w.commit();
  writer_.reset();
  return r;
}

// Every key of `space` moves from where `before` put it to where `after`
// does: the old places read absent, the new ones the keys' values (in two
// passes, so a key landing where another left is right).
void FactDb::reindex(Engine::Writer &w, IndexUpdate &index, SpaceId space, const Shift &before, const Shift &after,
                     std::vector<FactKey> *changed) {
  std::vector<FactKey> keys;
  for (const FactKey &k : log_.keys())
    if (k.addr.space == space && k.kind != FactKind::Rebase) keys.push_back(k);
  const Relocator *r = opt_.relocator.get();
  for (const FactKey &k : keys) {
    const FactKey old_key = shifted_key(r, k, before);
    auto cur = w.latest<AssertedFact>(old_key);
    if (std::holds_alternative<std::monostate>(*cur)) continue;
    w.set<AssertedFact>(old_key, FactValue{});
    if (ordered_kind(k.kind)) w.set<AssertedOrder>(old_key, std::string());
    index.change(old_key, false);
    if (changed) changed->push_back(old_key);
  }
  {
    std::lock_guard lock(shift_mu_);
    if (after.identity()) shifts_.erase(space);
    else shifts_[space] = after;
  }
  for (const FactKey &k : keys) {
    FactValue v = log_.effective(k);
    if (std::holds_alternative<std::monostate>(v)) continue;
    const FactKey new_key = shifted_key(r, k, after);
    if (ordered_kind(k.kind)) w.set<AssertedOrder>(new_key, order_of(log_, k));
    w.set<AssertedFact>(new_key, shifted_value(r, k, v, after));
    index.change(new_key, true);
    if (changed) changed->push_back(new_key);
  }
}

}  // namespace revkit::facts
