"""Binary diffing and version tracking (DiffService, api_minor 16, feature
"diff"; docs/diff.md).

    with Client("127.0.0.1:50051", actor="user:alice") as rk:
        s = rk.diff("default", "default/fw-1.0", "default/fw-1.1")   # create, run, wait
        print(s.counts())
        for m in s.matches(min_confidence=0.95, change_kinds=["modified"]):
            print(m.a.name, "->", hex(m.b.entry.offset), m.tier, m.confidence, m.evidence.detail)
        run = s.apply(min_confidence=0.95)           # names, comments, prototypes; one revision
        print(run.names, "names ported in run", run.run_id)
        s.revert_apply(run.run_id)                    # undo the whole run

Any two functions, in one program or two, with or without a session
(api_minor 54, feature "function-compare"):

        c = rk.compare_functions("default/fw-1.0", 0x401000, "default/fw-1.1", 0x402000)
        print(c.detail.summary.text)                  # what changed, in a line
        for v in c.markup.variables:                  # variables that correspond
            print(v.a.name, "->", v.b.name, v.evidence)
        r = rk.port_function_markup("default/fw-1.0", 0x401000, "default/fw-1.1", 0x402000)
        print(r.names, r.signatures, r.variable_names, r.comments)   # one revision; r.seqs undoes it
        s.port(0x401000, 0x402000, items=["variable_names"])          # through a session's match
        s.unmatch((0x401000, 0x402000))               # undo a decision on a pair

A session's matches are derived (recomputed as either program changes);
accepting, rejecting and setting a match, and porting markup, are
assertions with provenance (ported markup: ``migration:diff``, version =
the session id, session = the apply run).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Iterator, Optional, Sequence, Tuple, Union

from revkit.v1 import common_pb2, diff_pb2

if TYPE_CHECKING:  # pragma: no cover
    from revkit.client import Client

AddressLike = Union[int, common_pb2.Address]
Pair = Tuple[AddressLike, AddressLike]

_TIERS = {n.removeprefix("DIFF_TIER_").lower(): v for n, v in diff_pb2.DiffTier.items()}
_STATUSES = {n.removeprefix("DIFF_MATCH_STATUS_").lower(): v for n, v in diff_pb2.DiffMatchStatus.items()}
_CHANGES = {n.removeprefix("DIFF_CHANGE_KIND_").lower(): v for n, v in diff_pb2.DiffChangeKind.items()}
_SORTS = {n.removeprefix("DIFF_SORT_").lower(): v for n, v in diff_pb2.DiffSort.items()}
_ITEMS = {n.removeprefix("DIFF_MARKUP_ITEM_").lower(): v for n, v in diff_pb2.DiffMarkupItem.items()}
_POLICIES = {n.removeprefix("DIFF_APPLY_POLICY_").lower(): v for n, v in diff_pb2.DiffApplyPolicy.items()}
_KINDS = {n.removeprefix("FUNCTION_MARKUP_KIND_").lower(): v for n, v in diff_pb2.FunctionMarkupKind.items()}
_KINDS.update({k + "s": v for k, v in list(_KINDS.items()) if k != "unspecified"})  # "names", "comments", ...


def _addr(a: AddressLike) -> common_pb2.Address:
    return a if isinstance(a, common_pb2.Address) else common_pb2.Address(offset=int(a))


def _enum(table: dict, value, what: str) -> int:
    if isinstance(value, int):
        return value
    try:
        return table[str(value).lower()]
    except KeyError:
        raise ValueError(f"unknown {what} {value!r}; one of {sorted(k for k in table if k != 'unspecified')}") from None


def _pairs(pairs: Sequence[Pair]) -> list:
    return [diff_pb2.DiffPair(entry_a=_addr(a), entry_b=_addr(b)) for a, b in pairs]


def markup_items(items: Sequence) -> list:
    """FunctionMarkupItem messages from names ("name", "signature",
    "variable_names", "variable_types", "comments", and since api_minor 71
    "global_names", "global_types", "callee_names", "callee_signatures";
    a dict's "address" picks one source global or callee), (kind, variable) pairs
    ("variable_name", "stack:-0x14"), {"kind", "variable", "address",
    "comment_kind"} dicts, or messages."""
    out = []
    for it in items:
        if isinstance(it, diff_pb2.FunctionMarkupItem):
            out.append(it)
        elif isinstance(it, dict):
            m = diff_pb2.FunctionMarkupItem(kind=_enum(_KINDS, it["kind"], "markup kind"),
                                            variable=it.get("variable", ""), comment_kind=it.get("comment_kind", ""))
            if it.get("address") is not None:
                m.address.CopyFrom(_addr(it["address"]))
            out.append(m)
        elif isinstance(it, (tuple, list)):
            out.append(diff_pb2.FunctionMarkupItem(kind=_enum(_KINDS, it[0], "markup kind"), variable=str(it[1])))
        else:
            out.append(diff_pb2.FunctionMarkupItem(kind=_enum(_KINDS, it, "markup kind")))
    return out


def compare_functions(client: "Client", program_a: str, entry_a: AddressLike, program_b: str, entry_b: AddressLike, *,
                      project_id: str = "", session_id: str = "", markup: bool = True,
                      revision: int = 0) -> diff_pb2.CompareFunctionsResponse:
    """Two functions (one program or two): summaries, ``detail`` (what
    changed inside the pair: aligned listings, hunks, a summary) and, with
    ``markup``, what can be ported between them (signatures, variables
    paired by position and by instructions, comments by aligned instruction)."""
    project_id = project_id or (program_a or program_b).split("/")[0]
    return client._call(client.stubs.diff.CompareFunctions, diff_pb2.CompareFunctionsRequest(
        project_id=project_id, program_a=program_a, entry_a=_addr(entry_a), program_b=program_b, entry_b=_addr(entry_b),
        session_id=session_id, markup=markup, omit_bytes=True, read=common_pb2.ReadOptions(revision=revision)))


def port_function_markup(client: "Client", from_program: str, from_entry: AddressLike, to_program: str,
                         to_entry: AddressLike, *, items: Sequence = (), overwrite: bool = False, dry_run: bool = False,
                         project_id: str = "", session_id: str = "", actor=None,
                         reason: str = "") -> diff_pb2.PortFunctionMarkupResponse:
    """Ports markup from one function to another as one revision: ``items``
    (see markup_items; empty: everything someone set on the source side).
    Without ``overwrite`` only over default names and the decompiler's
    guesses, and comments where the target has none. ``seqs`` undoes it."""
    project_id = project_id or from_program.split("/")[0]
    return client._call(client.stubs.diff.PortFunctionMarkup, diff_pb2.PortFunctionMarkupRequest(
        project_id=project_id, from_program=from_program, from_entry=_addr(from_entry), to_program=to_program,
        to_entry=_addr(to_entry), items=markup_items(items), overwrite=overwrite, dry_run=dry_run,
        session_id=session_id, provenance=client._prov(actor, reason)))


def tier_name(t: int) -> str:
    """A DiffTier as a short name: "bytes", "pcode", "call_order", ..."""
    return diff_pb2.DiffTier.Name(t).removeprefix("DIFF_TIER_").lower()


class DiffSession:
    """One diff session: two programs of a project, their matches and the
    decisions taken on them."""

    def __init__(self, client: "Client", project_id: str, session_id: str,
                 info: Optional[diff_pb2.DiffSessionInfo] = None):
        self.client = client
        self.project_id = project_id
        self.id = session_id
        self.info = info

    def __repr__(self):
        return f"<DiffSession {self.id}>"

    def _call(self, name, request):
        return self.client._call(getattr(self.client.stubs.diff, name), request)

    # -- running ---------------------------------------------------------------------

    def run(self, *, wait: bool = True, timeout: float = 600.0, poll: float = 0.05) -> diff_pb2.GetDiffStatusResponse:
        """Starts a run (fingerprints, then matching) and, with ``wait``, returns
        once it ends. Raises RuntimeError if it failed."""
        self._call("RunDiff", diff_pb2.RunDiffRequest(project_id=self.project_id, session_id=self.id))
        return self.wait(timeout=timeout, poll=poll) if wait else self.status()

    def wait(self, *, timeout: float = 600.0, poll: float = 0.05) -> diff_pb2.GetDiffStatusResponse:
        deadline = time.monotonic() + timeout
        while True:
            st = self.status()
            state = st.session.run.state
            if state != diff_pb2.DIFF_RUN_STATE_RUNNING:
                if state == diff_pb2.DIFF_RUN_STATE_FAILED:
                    raise RuntimeError(f"diff run failed: {st.session.run.message}")
                return st
            if time.monotonic() > deadline:
                raise TimeoutError(f"diff run still {st.session.run.phase} after {timeout} s")
            time.sleep(poll)

    def status(self) -> diff_pb2.GetDiffStatusResponse:
        st = self._call("GetDiffStatus", diff_pb2.GetDiffStatusRequest(project_id=self.project_id, session_id=self.id))
        self.info = st.session
        return st

    def counts(self) -> diff_pb2.DiffCounts:
        """Counts for the whole session at head (computes the matches if needed)."""
        return self._call("ListMatches", diff_pb2.ListMatchesRequest(
            project_id=self.project_id, session_id=self.id, page=common_pb2.PageRequest(page_size=1))).counts

    def cancel(self) -> diff_pb2.DiffRun:
        return self._call("CancelDiff", diff_pb2.CancelDiffRequest(project_id=self.project_id, session_id=self.id)).run

    # -- reading -----------------------------------------------------------------------

    def matches(self, *, tiers: Sequence = (), min_confidence: float = 0.0, max_confidence: float = 0.0,
                statuses: Sequence = (), change_kinds: Sequence = (), name_contains: str = "",
                sort: Union[str, int] = "address_a", descending: bool = False, revision: int = 0,
                page_size: int = 1000) -> Iterator[diff_pb2.DiffMatch]:
        """Matched pairs, filtered and sorted, paged transparently (one revision).
        Tiers, statuses and change kinds by name ("bytes", "accepted", "modified")."""
        f = diff_pb2.DiffMatchFilter(
            tiers=[_enum(_TIERS, t, "tier") for t in tiers], min_confidence=min_confidence,
            max_confidence=max_confidence, statuses=[_enum(_STATUSES, s, "status") for s in statuses],
            change_kinds=[_enum(_CHANGES, c, "change kind") for c in change_kinds], name_contains=name_contains)
        req = diff_pb2.ListMatchesRequest(project_id=self.project_id, session_id=self.id, filter=f,
                                          sort=_enum(_SORTS, sort, "sort"), descending=descending,
                                          read=common_pb2.ReadOptions(revision=revision),
                                          page=common_pb2.PageRequest(page_size=page_size))
        while True:
            resp = self._call("ListMatches", req)
            yield from resp.matches
            if not resp.page.next_page_token:
                return
            req.page.page_token = resp.page.next_page_token

    def unmatched(self, side: str = "a", *, name_contains: str = "", max_candidates: int = 8,
                  page_size: int = 500) -> Iterator[diff_pb2.DiffUnmatched]:
        """Functions of side "a" or "b" without a match, with their candidates."""
        req = diff_pb2.ListUnmatchedRequest(
            project_id=self.project_id, session_id=self.id,
            side=diff_pb2.DIFF_SIDE_A if side.lower() == "a" else diff_pb2.DIFF_SIDE_B,
            name_contains=name_contains, max_candidates=max_candidates, page=common_pb2.PageRequest(page_size=page_size))
        while True:
            resp = self._call("ListUnmatched", req)
            yield from resp.functions
            if not resp.page.next_page_token:
                return
            req.page.page_token = resp.page.next_page_token

    def function_diff(self, entry_a: Optional[AddressLike] = None,
                      entry_b: Optional[AddressLike] = None, *, detail: bool = False) -> diff_pb2.GetFunctionDiffResponse:
        """One function (or a pair): summaries and evidence. With ``detail``
        (api_minor 17), what changed inside the pair: ``resp.detail`` has the
        block and instruction maps, both listings aligned (``lines``), the
        differences (``hunks``), the references gained or lost and a summary."""
        req = diff_pb2.GetFunctionDiffRequest(project_id=self.project_id, session_id=self.id, detail=detail)
        if entry_a is not None:
            req.entry_a.CopyFrom(_addr(entry_a))
        if entry_b is not None:
            req.entry_b.CopyFrom(_addr(entry_b))
        return self._call("GetFunctionDiff", req)

    def summaries(self, *pairs: Pair) -> list:
        """What changed inside matched pairs (entry in A, entry in B), in a line
        each: DiffChangeSummary with counts and ``text`` (api_minor 17)."""
        out = []
        pairs = list(pairs)
        for i in range(0, len(pairs), 500):
            resp = self._call("SummarizeFunctionDiffs", diff_pb2.SummarizeFunctionDiffsRequest(
                project_id=self.project_id, session_id=self.id, pairs=_pairs(pairs[i:i + 500])))
            out.extend(resp.summaries)
        return out

    # -- deciding ------------------------------------------------------------------------

    def accept(self, *pairs: Pair, min_confidence: float = 0.0, actor=None, reason: str = "") -> diff_pb2.AcceptMatchesResponse:
        """Accepts pairs (entry in A, entry in B), or every proposed match at or
        above ``min_confidence``."""
        return self._call("AcceptMatches", diff_pb2.AcceptMatchesRequest(
            project_id=self.project_id, session_id=self.id, pairs=_pairs(pairs), min_confidence=min_confidence,
            provenance=self.client._prov(actor, reason)))

    def reject(self, *pairs: Pair, actor=None, reason: str = "") -> diff_pb2.RejectMatchesResponse:
        """Rejects pairs: never proposed again in this session."""
        return self._call("RejectMatches", diff_pb2.RejectMatchesRequest(
            project_id=self.project_id, session_id=self.id, pairs=_pairs(pairs), provenance=self.client._prov(actor, reason)))

    def set_match(self, entry_a: AddressLike, entry_b: AddressLike, *, actor=None, reason: str = "") -> diff_pb2.SetMatchResponse:
        """Matches two functions by hand, replacing the matches either had."""
        return self._call("SetMatch", diff_pb2.SetMatchRequest(
            project_id=self.project_id, session_id=self.id, entry_a=_addr(entry_a), entry_b=_addr(entry_b),
            provenance=self.client._prov(actor, reason)))

    def unmatch(self, *pairs: Pair, actor=None, reason: str = "") -> diff_pb2.UnmatchResponse:
        """Undoes the decisions on pairs (accepted, applied or rejected), so the
        matcher's proposals apply again (api_minor 54). ``seqs`` undoes it."""
        return self._call("Unmatch", diff_pb2.UnmatchRequest(
            project_id=self.project_id, session_id=self.id, pairs=_pairs(pairs), provenance=self.client._prov(actor, reason)))

    def _programs(self) -> Tuple[str, str]:
        if self.info is None or not self.info.program_a:
            self.status()
        return self.info.program_a, self.info.program_b

    def compare(self, entry_a: AddressLike, entry_b: AddressLike, *, markup: bool = True) -> diff_pb2.CompareFunctionsResponse:
        """Two functions of this session's programs (matched or not), with this
        session's matches deciding which calls correspond (api_minor 54)."""
        return compare_functions(self.client, "", entry_a, "", entry_b, project_id=self.project_id, session_id=self.id,
                                 markup=markup)

    def port(self, entry_a: AddressLike, entry_b: AddressLike, *, items: Sequence = (), reverse: bool = False,
             overwrite: bool = False, dry_run: bool = False, actor=None, reason: str = "") -> diff_pb2.PortFunctionMarkupResponse:
        """Ports markup from A's function to B's (``reverse``: B's to A's): the
        name, the signature, variables' names and types, comments by aligned
        instruction; ``items`` picks (see markup_items). One revision by the
        caller, recording this session in ported_from (api_minor 54)."""
        a, b = self._programs()
        src, dst = ((b, entry_b), (a, entry_a)) if reverse else ((a, entry_a), (b, entry_b))
        return port_function_markup(self.client, src[0], src[1], dst[0], dst[1], items=items, overwrite=overwrite,
                                    dry_run=dry_run, project_id=self.project_id, session_id=self.id, actor=actor,
                                    reason=reason)

    # -- porting -------------------------------------------------------------------------

    def apply(self, *pairs: Pair, min_confidence: float = 0.95, items: Sequence = ("names", "comments", "prototypes"),
              policy: Union[str, int] = "safe", dry_run: bool = False, actor=None, reason: str = "") -> diff_pb2.ApplyMarkupResponse:
        """Ports markup from A to B over ``pairs``, or every match at or above
        ``min_confidence``, as one revision. Returns the counts and the run id."""
        return self._call("ApplyMarkup", diff_pb2.ApplyMarkupRequest(
            project_id=self.project_id, session_id=self.id, pairs=_pairs(pairs), min_confidence=min_confidence,
            items=[_enum(_ITEMS, i, "item") for i in items], policy=_enum(_POLICIES, policy, "policy"),
            dry_run=dry_run, provenance=self.client._prov(actor, reason)))

    def revert_apply(self, run_id: str, *, actor=None, reason: str = "") -> diff_pb2.RevertApplyResponse:
        """Retracts everything apply run ``run_id`` asserted, in one revision."""
        return self._call("RevertApply", diff_pb2.RevertApplyRequest(
            project_id=self.project_id, session_id=self.id, run_id=run_id, provenance=self.client._prov(actor, reason)))
