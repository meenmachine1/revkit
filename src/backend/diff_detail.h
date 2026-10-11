// Inside a pair (docs/diff.md "Inside a function"): turning a correlation
// (src/diff/correlate.h) and both functions' listing rows into the API's
// DiffDetail, and a pair's change summary into a line of text.
#pragma once

#include "revkit/diff/correlate.h"
#include "revkit/v1/diff.pb.h"
#include "revkit/v1/listing.pb.h"

#include <string>
#include <vector>

namespace revkit::backend {

namespace pb = ::revkit::v1;

// Fills out's blocks, rows (moved from rows_a/rows_b, matched to the
// correlation's instructions by address), lines, hunks, the references
// (unnamed: target, row and side only) and the summary's counts. Rows the
// correlation doesn't know (an instruction outside analysis's flow) get a
// line of their own and no status.
void FillDetail(const diff::FunctionCode &a, const diff::FunctionCode &b, const diff::Correlation &c,
                const std::vector<diff::RefChange> &refs, std::vector<pb::ListingRow> rows_a,
                std::vector<pb::ListingRow> rows_b, pb::DiffDetail &out);

// Counts for a summary without rows (SummarizeFunctionDiffs).
void FillCounts(const diff::Correlation &c, pb::DiffChangeSummary &out);

// An instruction's text as the listing shows it ("sub r0,r0,#0x7").
std::string RowText(const pb::ListingRow &row);

// One differing instruction for the summary line.
struct SummaryItem {
  diff::InsnStatus status = diff::InsnStatus::changed;
  std::string a, b;  // the instruction's text on each side (empty where it has none)
  bool new_callee = false;  // B's instruction calls a function only in B
};

// "1 instruction changed: sub r0,r0,#0x7 → bl FUN_00000400 (new)";
// "12 changed, 3 inserted, 1 deleted; calls FUN_x (new); 2 blocks added".
// `items` are the differing instructions when there are at most three
// (else empty); `gained`/`lost` name the calls gained and lost, "(new)"
// already appended where the callee is only in B.
std::string SummaryText(const pb::DiffChangeSummary &s, const std::vector<SummaryItem> &items,
                        const std::vector<std::string> &gained, const std::vector<std::string> &lost);

}  // namespace revkit::backend
