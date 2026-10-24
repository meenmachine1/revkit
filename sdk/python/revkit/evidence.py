"""What a result rests on, and what it leaves unknown (docs/api.md, "Result evidence").

Every value a read returns has a ``FactOrigin``: the assertion that won (who
said it: ``user:alice``, ``import:dwarf``, ``agent:claude``) or the analysis
rule that derived it (``derived:decompile.ghidra.naming``). Since api_minor 97
(feature "result-evidence") the origin also says how far to trust the value,
its source tier, and decompilations and functions list what analysis could not
determine (``.unknowns``)::

    fn = prog.decompile(0x401136)
    for u in fn.unknowns:                       # indirect calls, failures, ...
        print(unknown_dict(u))
    print(source(prog.function(0x401136).name_origin))
    # {'by': 'import:elf', 'tier': 'symbol'}

``source_tier`` derives the tier from the provenance or rule when an older
daemon left it unset, so it works against any daemon.
"""

from __future__ import annotations

from typing import Optional

from revkit.v1 import common_pb2

# Most trusted first. The order is for reading: precedence between
# assertions is the fact store's (user > import > agent > analysis).
TIERS = ("user", "debug_info", "symbol", "library", "agent", "inferred", "guessed", "default")

_DEBUG_IDS = ("dwarf", "pdb", "go")
_LIBRARY_IDS = ("fid", "archive", "bsim")
_SYMBOL_IDS = ("pe", "objc", "swift", "msvc")


def provenance_tier(p: common_pb2.Provenance) -> str:
    """The source tier of an assertion's provenance (the daemon's rule, docs/api.md)."""
    k = p.kind
    if k == common_pb2.PROVENANCE_KIND_USER:
        return "user"
    if k in (common_pb2.PROVENANCE_KIND_AGENT, common_pb2.PROVENANCE_KIND_PLUGIN, common_pb2.PROVENANCE_KIND_SCRIPT):
        return "agent"
    if k in (common_pb2.PROVENANCE_KIND_IMPORT, common_pb2.PROVENANCE_KIND_ANALYSIS):
        i = p.id
        if i in _DEBUG_IDS or i.startswith(("debug", "dwarf", "pdb")):
            return "debug_info"
        if i in _LIBRARY_IDS or i.startswith(("fid:", "library")):
            return "library"
        if k == common_pb2.PROVENANCE_KIND_IMPORT or i in _SYMBOL_IDS:
            return "symbol"
        return "inferred"
    if k == common_pb2.PROVENANCE_KIND_MIGRATION:
        return "inferred"
    return ""


def rule_tier(rule: str, confidence: float = 1.0) -> str:
    """The source tier of a derivation, from its rule and confidence."""
    if rule in ("names.default", "types.default") or rule.startswith("default"):
        return "default"
    if rule.startswith("library"):
        return "library"
    if rule.startswith(("names.loader", "loader.", "types.builtin")) or rule == "analysis.demangler":
        return "symbol"
    if 0 < confidence < 0.9:
        return "guessed"
    return "inferred"


def source_tier(origin: Optional[common_pb2.FactOrigin]) -> str:
    """How far to trust a value: "user", "debug_info", "symbol", "library", "agent", "inferred",
    "guessed" or "default" (a placeholder); "" when the origin says nothing."""
    if origin is None:
        return ""
    if origin.tier:
        return common_pb2.SourceTier.Name(origin.tier).removeprefix("SOURCE_TIER_").lower()
    which = origin.WhichOneof("source")
    if which == "asserted":
        return provenance_tier(origin.asserted.provenance)
    if which == "derived":
        return rule_tier(origin.derived.rule, origin.derived.confidence)
    return ""


def origin_text(origin: Optional[common_pb2.FactOrigin]) -> str:
    """Who or what produced a value: ``"user:alice"``, ``"import:dwarf"``, ``"derived:<rule>"``; "" if unset."""
    if origin is None:
        return ""
    if origin.HasField("asserted"):
        from revkit.client import format_provenance

        return format_provenance(origin.asserted.provenance)
    if origin.HasField("derived"):
        return f"derived:{origin.derived.rule}"
    return ""


def source(origin: Optional[common_pb2.FactOrigin]) -> dict:
    """``{"by": origin_text, "tier": source_tier}`` (with the assertion's ``seq`` for blame and undo)."""
    out = {"by": origin_text(origin), "tier": source_tier(origin)}
    if origin is not None and origin.HasField("asserted"):
        out["seq"] = origin.asserted.seq
    return out


def unknown_kind(kind: int) -> str:
    """An UnknownKind as "indirect_call", "decompile_failed", ..."""
    return common_pb2.UnknownKind.Name(kind).removeprefix("UNKNOWN_KIND_").lower()


def unknown_dict(u: common_pb2.Unknown) -> dict:
    """One Unknown as ``{"kind", "address", "detail"}`` (address as "0x..." when it has one)."""
    out = {"kind": unknown_kind(u.kind)}
    if u.HasField("address"):
        out["address"] = f"0x{u.address.offset:x}"
    if u.detail:
        out["detail"] = u.detail
    return out


def unknowns(message) -> list:
    """A result's unknowns as dicts (DecompiledFunction, Function); [] for a message without them."""
    try:
        return [unknown_dict(u) for u in message.unknowns]
    except AttributeError:
        return []
