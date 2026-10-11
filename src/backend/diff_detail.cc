// DiffDetail from a correlation (diff_detail.h).

#include "diff_detail.h"

#include <algorithm>
#include <map>
#include <unordered_map>

namespace revkit::backend {

namespace {

pb::DiffLineStatus ToApi(diff::InsnStatus s) { return static_cast<pb::DiffLineStatus>(static_cast<int>(s)); }
pb::DiffBlockStatus ToApi(diff::BlockStatus s) { return static_cast<pb::DiffBlockStatus>(static_cast<int>(s)); }

void Blocks(const diff::FunctionCode &f, const std::vector<std::int32_t> &partner,
            const std::vector<diff::BlockStatus> &status, const std::vector<std::int32_t> &row_of,
            google::protobuf::RepeatedPtrField<pb::DiffBlock> &out) {
  for (std::size_t x = 0; x < f.blocks.size(); ++x) {
    const diff::CodeBlock &bl = f.blocks[x];
    pb::DiffBlock *o = out.Add();
    const diff::CodeInsn &first = f.insns[bl.first], &last = f.insns[bl.last];
    o->mutable_range()->mutable_first()->set_offset(first.address);
    o->mutable_range()->mutable_last()->set_offset(last.address + std::max<std::uint32_t>(last.length, 1) - 1);
    o->set_status(ToApi(status[x]));
    o->set_partner(partner[x]);
    const std::int32_t r0 = row_of[bl.first], r1 = row_of[bl.last];
    if (r0 >= 0 && r1 >= r0) {
      o->set_first_row(static_cast<std::uint32_t>(r0));
      o->set_rows(static_cast<std::uint32_t>(r1 - r0 + 1));
    }
    for (const diff::CodeEdge &e : bl.succ)
      if (o->successors().empty() || o->successors(o->successors_size() - 1) != e.to) o->add_successors(e.to);
  }
}

}  // namespace

void FillCounts(const diff::Correlation &c, pb::DiffChangeSummary &out) {
  out.set_equal(c.equal);
  out.set_changed(c.changed);
  out.set_inserted(c.inserted);
  out.set_deleted(c.deleted);
  std::uint32_t n[5] = {};
  for (diff::BlockStatus s : c.block_status_a) ++n[static_cast<int>(s)];
  for (diff::BlockStatus s : c.block_status_b)
    if (s == diff::BlockStatus::added) ++n[static_cast<int>(s)];
  out.set_blocks_unchanged(n[1]);
  out.set_blocks_modified(n[2]);
  out.set_blocks_added(n[3]);
  out.set_blocks_removed(n[4]);
  out.set_hunks(static_cast<std::uint32_t>(c.hunks().size()));
}

void FillDetail(const diff::FunctionCode &a, const diff::FunctionCode &b, const diff::Correlation &c,
                const std::vector<diff::RefChange> &refs, std::vector<pb::ListingRow> rows_a,
                std::vector<pb::ListingRow> rows_b, pb::DiffDetail &out) {
  // Instruction index <-> row index, by address.
  auto index = [](const diff::FunctionCode &f, const std::vector<pb::ListingRow> &rows, std::vector<std::int32_t> &row_of,
                  std::vector<std::int32_t> &insn_of) {
    std::unordered_map<std::uint64_t, std::int32_t> at;
    for (std::size_t r = 0; r < rows.size(); ++r) at.emplace(rows[r].address().offset(), static_cast<std::int32_t>(r));
    row_of.assign(f.insns.size(), -1);
    insn_of.assign(rows.size(), -1);
    for (std::size_t i = 0; i < f.insns.size(); ++i)
      if (auto it = at.find(f.insns[i].address); it != at.end()) {
        row_of[i] = it->second;
        insn_of[static_cast<std::size_t>(it->second)] = static_cast<std::int32_t>(i);
      }
  };
  std::vector<std::int32_t> row_a, row_b, insn_a, insn_b;
  index(a, rows_a, row_a, insn_a);
  index(b, rows_b, row_b, insn_b);
  Blocks(a, c.block_a, c.block_status_a, row_a, *out.mutable_blocks_a());
  Blocks(b, c.block_b, c.block_status_b, row_b, *out.mutable_blocks_b());

  auto rows = [](const diff::FunctionCode &f, const std::vector<pb::ListingRow> &in, const std::vector<std::int32_t> &insn_of,
                 const std::vector<std::int32_t> &partner, const std::vector<diff::InsnStatus> &status,
                 const std::vector<bool> &moved, const std::vector<std::int32_t> &other_row,
                 google::protobuf::RepeatedPtrField<pb::DiffRow> &o) {
    for (std::size_t r = 0; r < in.size(); ++r) {
      pb::DiffRow *d = o.Add();
      const pb::ListingRow &lr = in[r];
      *d->mutable_address() = lr.address();
      d->set_length(lr.length());
      d->set_text(RowText(lr));
      for (const pb::ListingToken &t : lr.tokens()) {
        pb::DiffToken *dt = d->add_tokens();
        dt->set_text(t.text());
        dt->set_kind(static_cast<std::uint32_t>(t.kind()));
        if (t.has_target()) *dt->mutable_target() = t.target();
        dt->set_operand(t.has_operand_index() ? static_cast<std::int32_t>(t.operand_index()) : -1);
      }
      for (const pb::Label &l : lr.labels())
        if (l.primary() || d->label().empty()) d->set_label(l.name());
      std::string comment;
      for (const pb::CommentView &cv : lr.comments()) comment += (comment.empty() ? "" : " ") + cv.text();
      d->set_comment(std::move(comment));
      d->set_flow(static_cast<std::uint32_t>(lr.flow()));
      d->set_partner(-1);
      const std::int32_t i = insn_of[r];
      if (i < 0) continue;
      const auto ii = static_cast<std::size_t>(i);
      d->set_status(ToApi(status[ii]));
      if (partner[ii] >= 0) d->set_partner(other_row[static_cast<std::size_t>(partner[ii])]);
      d->set_block(f.insns[ii].block);
      d->set_moved(moved[ii]);
    }
  };
  rows(a, rows_a, insn_a, c.insn_a, c.status_a, c.moved_a, row_b, *out.mutable_rows_a());
  rows(b, rows_b, insn_b, c.insn_b, c.status_b, c.moved_b, row_a, *out.mutable_rows_b());

  // Lines: the correlation's, in rows; rows it doesn't know go after the
  // line of the row before them.
  std::vector<std::pair<std::int32_t, std::int32_t>> lines;
  for (const auto &[x, y] : c.lines) {
    const std::int32_t ra = x >= 0 ? row_a[static_cast<std::size_t>(x)] : -1;
    const std::int32_t rb = y >= 0 ? row_b[static_cast<std::size_t>(y)] : -1;
    if (ra >= 0 || rb >= 0) lines.emplace_back(ra, rb);
  }
  auto place = [&](std::size_t n, const std::vector<std::int32_t> &insn_of, bool side_a) {
    std::vector<std::int32_t> line_of(n, -1);
    for (std::size_t k = 0; k < lines.size(); ++k) {
      const std::int32_t r = side_a ? lines[k].first : lines[k].second;
      if (r >= 0) line_of[static_cast<std::size_t>(r)] = static_cast<std::int32_t>(k);
    }
    std::vector<std::vector<std::pair<std::int32_t, std::int32_t>>> after(lines.size() + 1);
    std::int32_t anchor = -1;
    bool any = false;
    for (std::size_t r = 0; r < n; ++r) {
      if (insn_of[r] >= 0 && line_of[r] >= 0) {
        anchor = line_of[r];
        continue;
      }
      any = true;
      after[static_cast<std::size_t>(anchor + 1)].push_back(side_a ? std::pair{static_cast<std::int32_t>(r), -1}
                                                                     : std::pair{-1, static_cast<std::int32_t>(r)});
    }
    if (!any) return;
    std::vector<std::pair<std::int32_t, std::int32_t>> merged(after[0]);
    for (std::size_t k = 0; k < lines.size(); ++k) {
      merged.push_back(lines[k]);
      merged.insert(merged.end(), after[k + 1].begin(), after[k + 1].end());
    }
    lines = std::move(merged);
  };
  place(rows_a.size(), insn_a, true);
  place(rows_b.size(), insn_b, false);
  bool in = false;
  for (std::size_t k = 0; k < lines.size(); ++k) {
    pb::DiffLine *l = out.add_lines();
    l->set_a(lines[k].first);
    l->set_b(lines[k].second);
    bool same = true;
    if (lines[k].first < 0 || lines[k].second < 0) {
      // A row the correlation doesn't know isn't a difference.
      const pb::DiffRow &r = lines[k].first >= 0 ? out.rows_a(lines[k].first) : out.rows_b(lines[k].second);
      same = r.status() == pb::DIFF_LINE_STATUS_UNSPECIFIED;
    } else {
      const pb::DiffRow &r = out.rows_a(lines[k].first);
      same = (r.status() == pb::DIFF_LINE_STATUS_EQUAL || r.status() == pb::DIFF_LINE_STATUS_UNSPECIFIED) && !r.moved();
    }
    if (!same && !in) out.add_hunks(static_cast<std::uint32_t>(k));
    in = !same;
  }

  for (const diff::RefChange &x : refs) {
    pb::DiffReferenceChange *r = out.add_references();
    r->set_side(x.in_b ? pb::DIFF_SIDE_B : pb::DIFF_SIDE_A);
    r->set_kind(x.ref.kind == diff::CodeRef::Kind::data ? pb::DIFF_REFERENCE_KIND_DATA : pb::DIFF_REFERENCE_KIND_CALL);
    const diff::FunctionCode &f = x.in_b ? b : a;
    r->mutable_from()->set_offset(f.insns[x.insn].address);
    const std::int32_t row = (x.in_b ? row_b : row_a)[x.insn];
    r->set_row(row >= 0 ? static_cast<std::uint32_t>(row) : 0);
    r->mutable_target()->set_offset(x.ref.to);
  }
  FillCounts(c, *out.mutable_summary());
  out.mutable_summary()->set_hunks(static_cast<std::uint32_t>(out.hunks_size()));
}

std::string RowText(const pb::ListingRow &row) {
  std::string s;
  for (const pb::ListingToken &t : row.tokens()) s += t.text();
  // One space between the mnemonic and the operands, none at the ends.
  std::string out;
  for (char ch : s) {
    if (ch == '\t') ch = ' ';
    if (ch == ' ' && (out.empty() || out.back() == ' ')) continue;
    out.push_back(ch);
  }
  while (!out.empty() && out.back() == ' ') out.pop_back();
  return out;
}

std::string SummaryText(const pb::DiffChangeSummary &s, const std::vector<SummaryItem> &items,
                        const std::vector<std::string> &gained, const std::vector<std::string> &lost) {
  const std::uint32_t n = s.changed() + s.inserted() + s.deleted();
  std::string out;
  auto join = [](const std::vector<std::string> &v, std::string_view sep) {
    std::string r;
    for (const std::string &x : v) r += (r.empty() ? "" : std::string(sep)) + x;
    return r;
  };
  if (n == 0) {
    out = s.hunks() ? "the same instructions, moved" : "no instruction changed";
  } else {
    std::vector<std::string> parts;
    const bool one_kind = (s.changed() == n || s.inserted() == n || s.deleted() == n);
    const std::string noun = n == 1 ? " instruction " : " instructions ";
    if (one_kind)
      out = std::to_string(n) + noun + (s.changed() ? "changed" : s.inserted() ? "inserted" : "deleted");
    else {
      if (s.changed()) parts.push_back(std::to_string(s.changed()) + " changed");
      if (s.inserted()) parts.push_back(std::to_string(s.inserted()) + " inserted");
      if (s.deleted()) parts.push_back(std::to_string(s.deleted()) + " deleted");
      out = join(parts, ", ");
    }
    if (!items.empty()) {
      std::vector<std::string> shown;
      for (const SummaryItem &it : items) {
        const std::string b = it.b + (it.new_callee ? " (new)" : "");
        if (it.status == diff::InsnStatus::changed) shown.push_back(it.a + " → " + b);
        else if (it.status == diff::InsnStatus::inserted) shown.push_back((one_kind ? "" : "+ ") + b);
        else shown.push_back((one_kind ? "" : "− ") + it.a);
      }
      out += ": " + join(shown, "; ");
    }
  }
  if (items.empty()) {
    auto first = [](const std::vector<std::string> &v) {
      std::vector<std::string> r(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(v.size(), 3)));
      if (v.size() > 3) r.push_back("…");
      return r;
    };
    if (!gained.empty()) out += "; calls " + join(first(gained), ", ");
    if (!lost.empty()) out += "; no longer calls " + join(first(lost), ", ");
  }
  const std::uint32_t added = s.blocks_added(), removed = s.blocks_removed();
  if (added || removed) {
    auto blocks = [](std::uint32_t k) { return std::to_string(k) + (k == 1 ? " block" : " blocks"); };
    std::string t;
    if (added) t = blocks(added) + " added";
    if (removed) t += (t.empty() ? blocks(removed) : ", " + std::to_string(removed)) + " removed";
    out += "; " + t;
  }
  return out;
}

}  // namespace revkit::backend
