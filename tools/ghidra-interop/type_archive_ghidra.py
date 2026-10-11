"""Runs under PyGhidra (scripts/setup-pyghidra.sh): parses type archive
headers with Ghidra's own C parser (CParserUtils, into a data type archive
with the language's and compiler spec's data organization) and writes each
named type's layout as Ghidra lays it out, as JSON. type_archive_check.py
drives it and compares the layouts with revkit's.

    python type_archive_ghidra.py jobs.json out.json

jobs.json: [{"header": path, "language": "x86:LE:64:default", "compiler": "gcc"}, ...]
out.json:  [{"header": path, "success": bool, "messages": str, "types": [
              {"name", "kind", "category", "length", "alignment", "components": [
                 {"offset", "length", "name", "bit_offset", "bit_size"}]}]}, ...]
"""

import json
import os
import sys
import tempfile

import pyghidra


def main(jobs_path: str, out_path: str) -> int:
    pyghidra.start()
    from java.io import File  # noqa: E402
    from ghidra.app.util.cparser.C import CParserUtils  # noqa: E402
    from ghidra.program.model.data import (BitFieldDataType, Enum, FileDataTypeManager, Structure, TypeDef,  # noqa: E402
                                           Union)
    from ghidra.util.task import TaskMonitor  # noqa: E402

    with open(jobs_path) as f:
        jobs = json.load(f)
    results = []
    for job in jobs:
        tmp = tempfile.mkdtemp(prefix="rk-ghidra-archive-")
        gdt = os.path.join(tmp, "parsed.gdt")
        dtm = FileDataTypeManager.createFileArchive(File(gdt), job["language"], job["compiler"])
        out = {"header": job["header"], "success": False, "messages": "", "types": []}
        try:
            tx = dtm.startTransaction("parse")
            try:
                res = CParserUtils.parseHeaderFiles(None, [job["header"]], [], [], dtm, TaskMonitor.DUMMY)
                out["success"] = bool(res.successful())
                out["messages"] = str(res.getFormattedParseMessage(None) or "")
            except Exception as e:  # a catastrophic parse error
                out["messages"] = f"{type(e).__name__}: {e}"
            finally:
                dtm.endTransaction(tx, True)
            it = dtm.getAllDataTypes()
            while it.hasNext():
                dt = it.next()
                kind = ("struct" if isinstance(dt, Structure) else "union" if isinstance(dt, Union)
                        else "enum" if isinstance(dt, Enum) else "typedef" if isinstance(dt, TypeDef) else None)
                if kind is None:
                    continue
                t = {"name": str(dt.getName()), "kind": kind, "category": str(dt.getCategoryPath().getPath()),
                     "length": int(dt.getLength()), "alignment": int(dt.getAlignment()), "components": []}
                if kind in ("struct", "union"):
                    for c in dt.getDefinedComponents():
                        cdt = c.getDataType()
                        comp = {"offset": int(c.getOffset()), "length": int(c.getLength()),
                                "name": str(c.getFieldName()) if c.getFieldName() else ""}
                        if isinstance(cdt, BitFieldDataType):
                            comp["bit_offset"] = int(cdt.getBitOffset())
                            comp["bit_size"] = int(cdt.getDeclaredBitSize())
                        t["components"].append(comp)
                out["types"].append(t)
        finally:
            dtm.close()
            for name in os.listdir(tmp):
                os.unlink(os.path.join(tmp, name))
            os.rmdir(tmp)
        results.append(out)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
