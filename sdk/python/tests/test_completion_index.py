"""The script editor's completion index (ui/src/scripts/script-api.json)
must be what revkit.script.completion_index builds from the SDK now: regenerate
it with sdk/python/generate.sh after changing the script API."""

import json
from pathlib import Path

from revkit.script import __all__ as script_names
from revkit.script.completion_index import FORMAT, build, render, signature

INDEX = Path(__file__).resolve().parents[3] / "ui" / "src" / "scripts" / "script-api.json"


def test_index_is_current():
    assert INDEX.read_text(encoding="utf-8") == render(build()), "stale: run sdk/python/generate.sh"


def test_index_covers_the_api_and_ghidras_names():
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    assert index["format"] == FORMAT
    names = {e["name"]: e for e in index["globals"]}
    assert set(script_names) <= set(names)
    assert names["decompile_many"]["signature"] == "decompile_many(funcs=None, *, text=True, parallelism=0)"
    assert names["current_program"]["type"] == "Program" and names["monitor"]["type"] == "Monitor"
    assert names["getFunctionAt"]["group"] == "ghidra" and names["currentProgram"]["type"] == "GhidraProgram"
    program = {e["name"]: e for e in index["members"]["Program"]}
    assert program["functions"]["signature"].startswith("functions(") and program["functions"]["doc"]
    assert "getFunctionManager" in {e["name"] for e in index["members"]["GhidraProgram"]}


def test_signatures_leave_out_annotations_and_self():
    class K:
        def m(self, a: int, b: "str" = "x", *rest, c: bool = True, **kw) -> None:
            pass

    assert signature("m", K.m, drop_self=True) == "m(a, b='x', *rest, c=True, **kw)"
    assert signature("f", lambda x, *, y=None: 0) == "f(x, *, y=None)"
