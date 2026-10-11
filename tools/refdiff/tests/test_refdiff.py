"""Unit tests for refformat and refdiff. Run with pytest or
`python3 -m unittest discover -s tools/refdiff/tests`."""

import copy
import gzip
import io
import json
import os
import random
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import cnorm  # noqa: E402
import refdiff  # noqa: E402
import refformat  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))


def insn(addr, text, pcode, length=4):
    return {"addr": addr, "len": length, "mnemonic": text.split()[0], "text": text, "pcode": pcode}


def op(name, out, *ins):
    return {"op": name, "out": out, "in": list(ins)}


def sample_doc():
    """A small but complete reference document."""
    rsp = ["register", "0x20", 8]
    return {
        "format_version": 1,
        "producer": "test",
        "binary": {"path": "t/bin", "sha256": "ab" * 32, "language": "x86:LE:64:default",
                   "compiler": "gcc", "image_base": "0x100000"},
        "memory": [
            {"name": ".text", "start": "0x101000", "end": "0x101fff", "perms": "r-x"},
            {"name": ".data", "start": "0x104000", "end": "0x104fff", "perms": "rw-"},
            {"name": "csr", "start": "0x0", "end": "0x7fff", "perms": "rw-", "space": "csreg"},
        ],
        "functions": [
            {"entry": "0x101000", "name": "main", "body": [["0x101000", "0x101007"]],
             "prototype": "int main(int argc, char * * argv)", "decompiled_c": "int main(void)\n{\n  return 0;\n}\n"},
            {"entry": "0x101010", "name": "helper", "body": [["0x101010", "0x101013"]],
             "prototype": "void helper(void)"},
        ],
        "instructions": [
            insn("0x101000", "SUB RSP,0x8", [
                op("INT_SUB", rsp, rsp, ["const", "0x8", 8]),
                op("INT_AND", ["unique", "0x58300", 8], rsp, ["const", "0xff", 8]),
                op("POPCOUNT", ["unique", "0x58400", 1], ["unique", "0x58300", 8]),
            ]),
            insn("0x101004", "RET", [
                op("LOAD", ["register", "0x288", 8], ["space", "ram", 8], rsp),
                op("RETURN", None, ["register", "0x288", 8]),
            ]),
            insn("0x101010", "NOP", [], length=4),
        ],
    }


def rates(tally):
    return {c: tally.rate(c) for c in refdiff.CATEGORIES}


class RefFormatTest(unittest.TestCase):
    def test_dumps_is_canonical(self):
        doc = sample_doc()
        shuffled = copy.deepcopy(doc)
        for key in ("memory", "functions", "instructions"):
            random.Random(1).shuffle(shuffled[key])
        shuffled = dict(reversed(list(shuffled.items())))
        self.assertEqual(refformat.dumps(doc), refformat.dumps(shuffled))
        text = refformat.dumps(doc)
        self.assertEqual(json.loads(text)["functions"][0]["entry"], "0x101000")
        self.assertTrue(text.isascii())

    def test_sorts_numerically_not_lexically(self):
        doc = sample_doc()
        doc["functions"] = [dict(doc["functions"][0], entry="0x9"), dict(doc["functions"][0], entry="0x10")]
        self.assertEqual([f["entry"] for f in json.loads(refformat.dumps(doc))["functions"]], ["0x9", "0x10"])

    def test_write_load_roundtrip_and_gzip_determinism(self):
        doc = sample_doc()
        with tempfile.TemporaryDirectory() as d:
            for name in ("a.json", "b.json.gz", "c.json.gz"):
                refformat.write(os.path.join(d, name), doc)
                self.assertEqual(refformat.load(os.path.join(d, name)), json.loads(refformat.dumps(doc)))
            with open(os.path.join(d, "b.json.gz"), "rb") as f1, open(os.path.join(d, "c.json.gz"), "rb") as f2:
                self.assertEqual(f1.read(), f2.read())
            with gzip.open(os.path.join(d, "b.json.gz"), "rt") as f:
                self.assertEqual(f.read(), refformat.dumps(doc))

    def test_load_rejects_other_versions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            with open(path, "w") as f:
                json.dump({"format_version": 2}, f)
            with self.assertRaises(ValueError):
                refformat.load(path)

    def test_unique_renumbering(self):
        a = [op("INT_ADD", ["unique", "0x100", 8], ["register", "0x0", 8], ["const", "0x1", 8]),
             op("COPY", ["register", "0x8", 8], ["unique", "0x100", 8])]
        b = [op("INT_ADD", ["unique", "0xe80", 8], ["register", "0x0", 8], ["const", "0x1", 8]),
             op("COPY", ["register", "0x8", 8], ["unique", "0xe80", 8])]
        self.assertEqual(refformat.normalize_pcode(a), refformat.normalize_pcode(b))
        # Same ops, but the COPY reads a different temp than the ADD wrote.
        c = copy.deepcopy(b)
        c[1]["in"][0] = ["unique", "0xf00", 8]
        self.assertNotEqual(refformat.normalize_pcode(a), refformat.normalize_pcode(c))
        # Other spaces are not renumbered.
        d = copy.deepcopy(a)
        d[0]["in"][0] = ["register", "0x10", 8]
        self.assertNotEqual(refformat.normalize_pcode(a), refformat.normalize_pcode(d))

    def test_unique_order_output_before_inputs(self):
        # Within one op the output is numbered before the inputs.
        a = [op("INT_ADD", ["unique", "0x10", 8], ["unique", "0x20", 8], ["unique", "0x10", 8])]
        self.assertEqual(refformat.normalize_pcode(a)[0][1], ("unique", "u0", 8))
        self.assertEqual(refformat.normalize_pcode(a)[0][2][0], ("unique", "u1", 8))

    def test_find_reference_files(self):
        with tempfile.TemporaryDirectory() as d:
            refformat.write(os.path.join(d, "x", "a.json"), sample_doc())
            refformat.write(os.path.join(d, "x", "b.exe.json.gz"), sample_doc())
            open(os.path.join(d, "_stats.json"), "w").close()
            self.assertEqual(sorted(refformat.find_reference_files(d)), ["x/a", "x/b.exe"])


class CompareTest(unittest.TestCase):
    def test_self_compare_is_perfect(self):
        t = refdiff.compare_docs(sample_doc(), sample_doc())
        for cat in refdiff.CATEGORIES:
            if cat != "binaries":
                self.assertEqual(t.rate(cat), 1.0, cat)
        self.assertEqual(t.counts["instructions"], [3, 3])
        self.assertEqual(t.counts["memory"], [3, 3])

    def test_prototype_change_only_hits_prototypes(self):
        cand = sample_doc()
        cand["functions"][1]["prototype"] = "int helper(void)"
        r = rates(refdiff.compare_docs(sample_doc(), cand))
        self.assertEqual(r["prototypes"], 0.5)
        for cat in ("functions", "names", "bodies", "decompiled_c", "instructions", "pcode", "memory"):
            self.assertEqual(r[cat], 1.0, cat)

    def test_missing_function_counts_against_attributes(self):
        cand = sample_doc()
        del cand["functions"][1]
        r = rates(refdiff.compare_docs(sample_doc(), cand))
        for cat in ("functions", "names", "bodies", "prototypes", "decompiled_c"):
            self.assertEqual(r[cat], 0.5, cat)

    def test_extra_function_counts_too(self):
        cand = sample_doc()
        cand["functions"].append({"entry": "0x101020", "name": "extra", "body": [["0x101020", "0x101020"]],
                                  "prototype": "void extra(void)"})
        t = refdiff.compare_docs(sample_doc(), cand)
        self.assertEqual(t.counts["functions"], [2, 3])

    def test_omitted_field_on_one_side_disagrees(self):
        cand = sample_doc()
        del cand["functions"][0]["decompiled_c"]
        self.assertEqual(rates(refdiff.compare_docs(sample_doc(), cand))["decompiled_c"], 0.5)
        # Omitted on both sides agrees (helper has no decompiled_c in either).
        self.assertEqual(rates(refdiff.compare_docs(sample_doc(), sample_doc()))["decompiled_c"], 1.0)

    def test_loose_c(self):
        cand = sample_doc()
        cand["functions"][0]["decompiled_c"] = "int main(void) {\n    return 0;\n}"
        self.assertEqual(rates(refdiff.compare_docs(sample_doc(), cand))["decompiled_c"], 0.5)
        self.assertEqual(rates(refdiff.compare_docs(sample_doc(), cand, loose_c=False))["decompiled_c"], 0.5)
        cand["functions"][0]["decompiled_c"] = "int main(void)  \n{\n return 0;\n}"
        self.assertEqual(rates(refdiff.compare_docs(sample_doc(), cand, loose_c=True))["decompiled_c"], 1.0)

    def test_structural_c_categories(self):
        cand = sample_doc()
        # Same tokens, different layout: only the exact comparison differs.
        cand["functions"][0]["decompiled_c"] = "\nint main(void)\n\n{\n    return 0;\n}\n\n"
        r = rates(refdiff.compare_docs(sample_doc(), cand))
        self.assertEqual((r["decompiled_c"], r["c_tokens"], r["c_ast"], r["c_alpha"]), (0.5, 1.0, 1.0, 1.0))
        # A comment only: the AST is the same.
        cand["functions"][0]["decompiled_c"] = "/* WARNING: x */\nint main(void)\n{\n  return 0;\n}\n"
        r = rates(refdiff.compare_docs(sample_doc(), cand))
        self.assertEqual((r["c_tokens"], r["c_ast"]), (0.5, 1.0))
        # A different statement differs everywhere.
        cand["functions"][0]["decompiled_c"] = "int main(void)\n{\n  return 1;\n}\n"
        r = rates(refdiff.compare_docs(sample_doc(), cand))
        self.assertEqual((r["c_tokens"], r["c_ast"], r["c_alpha"]), (0.5, 0.5, 0.5))

    def test_only_restricts_categories(self):
        t = refdiff.compare_docs(sample_doc(), sample_doc(), only={"c_ast"})
        self.assertEqual(t.counts["c_ast"], [2, 2])
        self.assertEqual(t.counts["instructions"], [0, 0])
        self.assertEqual(t.counts["functions"], [0, 0])

    def test_pcode_unique_renumbering_and_real_difference(self):
        cand = sample_doc()
        p = cand["instructions"][0]["pcode"]
        p[1]["out"] = ["unique", "0x1000", 8]
        p[2]["in"][0] = ["unique", "0x1000", 8]
        p[2]["out"] = ["unique", "0x2000", 1]
        self.assertEqual(rates(refdiff.compare_docs(sample_doc(), cand))["pcode"], 1.0)
        p[0]["in"][1] = ["const", "0x10", 8]
        r = rates(refdiff.compare_docs(sample_doc(), cand))
        self.assertAlmostEqual(r["pcode"], 2 / 3)
        self.assertEqual(r["instructions"], 1.0)

    def test_instruction_text_and_missing(self):
        cand = sample_doc()
        cand["instructions"][2]["text"] = "NOP dword ptr [RAX]"
        del cand["instructions"][1]
        t = refdiff.compare_docs(sample_doc(), cand)
        self.assertEqual(t.counts["instructions"], [1, 3])
        self.assertEqual(t.counts["pcode"], [2, 3])  # text differs but p-code still matches
        self.assertEqual(t.counts["pcode_shared"], [2, 2])  # only addresses both sides have

    def test_memory_and_spaces(self):
        cand = sample_doc()
        cand["memory"][2]["space"] = "other"  # same start, different space: two distinct blocks
        t = refdiff.compare_docs(sample_doc(), cand)
        self.assertEqual(t.counts["memory"], [2, 4])
        cand = sample_doc()
        cand["memory"][1]["perms"] = "r--"
        self.assertEqual(refdiff.compare_docs(sample_doc(), cand).counts["memory"], [2, 3])

    def test_examples_are_collected(self):
        cand = sample_doc()
        cand["functions"][0]["name"] = "entry"
        t = refdiff.compare_docs(sample_doc(), cand, max_examples=5)
        self.assertEqual(t.examples["names"], [("0x101000", "main", "entry")])


class BaselineTest(unittest.TestCase):
    def test_unchanged_rates_are_not_regressions(self):
        # 2/3 rounds up to 0.666667 in the baseline, above the exact 0.6666...
        t = refdiff.Tally()
        for ok in (True, True, False):
            t.add("names", ok)
        per = {"bin": t}
        baseline = json.loads(json.dumps(refdiff.baseline_doc(t, per)))
        self.assertEqual(refdiff.check_baseline(baseline, t, per, 0.0), [])


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ref = os.path.join(self.tmp.name, "ref")
        self.cand = os.path.join(self.tmp.name, "cand")
        for root in (self.ref, self.cand):
            refformat.write(os.path.join(root, "elf-x86_64", "a.json"), sample_doc())
            refformat.write(os.path.join(root, "pe-x86_64", "b.exe.json"), sample_doc())

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = refdiff.main(list(args) + ["-j", "1"])
        return code, out.getvalue(), err.getvalue()

    def test_dir_self_check(self):
        code, out, _ = self.run_cli(self.ref, self.ref)
        self.assertEqual(code, 0)
        self.assertIn("OK", out)
        self.assertNotIn("FAIL", out)

    def test_baseline_regression(self):
        baseline = os.path.join(self.tmp.name, "baseline.json")
        code, _, _ = self.run_cli(self.ref, self.cand, "--save-baseline", baseline)
        self.assertEqual(code, 0)
        self.assertEqual(self.run_cli(self.ref, self.cand, "--baseline", baseline)[0], 0)
        doc = sample_doc()
        doc["instructions"][0]["pcode"][0]["op"] = "INT_ADD"
        refformat.write(os.path.join(self.cand, "elf-x86_64", "a.json"), doc)
        code, out, _ = self.run_cli(self.ref, self.cand, "--baseline", baseline)
        self.assertEqual(code, 1)
        self.assertIn("regression: total pcode", out)
        self.assertIn("regression: elf-x86_64/a pcode", out)
        # Within tolerance: 1/6 of instructions = 16.7% drop overall, 33% for a.
        self.assertEqual(self.run_cli(self.ref, self.cand, "--baseline", baseline, "--tolerance", "0.34")[0], 0)

    def test_improvement_is_not_a_regression(self):
        doc = sample_doc()
        del doc["functions"][1]
        refformat.write(os.path.join(self.cand, "elf-x86_64", "a.json"), doc)
        baseline = os.path.join(self.tmp.name, "baseline.json")
        self.run_cli(self.ref, self.cand, "--save-baseline", baseline)
        refformat.write(os.path.join(self.cand, "elf-x86_64", "a.json"), sample_doc())
        self.assertEqual(self.run_cli(self.ref, self.cand, "--baseline", baseline)[0], 0)

    def test_missing_binary(self):
        os.remove(os.path.join(self.cand, "pe-x86_64", "b.exe.json"))
        code, out, err = self.run_cli(self.ref, self.cand, "--require", "binaries=1.0")
        self.assertEqual(code, 1)
        self.assertIn("missing from candidate", err)
        # Its contents count as disagreement in every category.
        self.assertRegex(out, r"functions\s+2\s+4\s+50.00%")

    def test_require_and_bad_category(self):
        self.assertEqual(self.run_cli(self.ref, self.cand, "--require", "pcode=1.0")[0], 0)
        self.assertEqual(self.run_cli(self.ref, self.cand, "--require", "bogus=1.0")[0], 2)

    def test_file_mode_and_mixed_args(self):
        a = os.path.join(self.ref, "elf-x86_64", "a.json")
        self.assertEqual(self.run_cli(a, a)[0], 0)
        self.assertEqual(self.run_cli(a, self.cand)[0], 2)

    def test_json_output(self):
        out_json = os.path.join(self.tmp.name, "result.json")
        self.run_cli(self.ref, self.cand, "--json", out_json)
        with open(out_json) as f:
            doc = json.load(f)
        self.assertEqual(doc["total"]["instructions"], {"agree": 6, "total": 6, "rate": 1.0})
        self.assertEqual(sorted(doc["binaries"]), ["elf-x86_64/a", "pe-x86_64/b.exe"])


class CNormTest(unittest.TestCase):
    REF = (
        "\n/* WARNING: Removing unreachable block (ram,0x001012f7) */\n\n"
        "int sum(int *values,int count)\n\n{\n  int iVar1;\n  long lVar2;\n  char buf [16];\n  \n"
        "  iVar1 = 0;\n  for (lVar2 = 0; lVar2 < count; lVar2 = lVar2 + 1) {\n"
        "    iVar1 = iVar1 + values[lVar2] + DAT_00104010;\n  }\n"
        "  printf(\"%d /* not a comment */\\n\",iVar1);\n  return iVar1;\n}\n"
    )

    def test_tokenize(self):
        toks = cnorm.tokenize('a->b += 0x10; s = "x /* y */"; c = \'\\n\'; /* c1 */ d <<= 1.5e3;')
        kinds = [k for k, _ in toks]
        self.assertIn(("op", "->"), toks)
        self.assertIn(("op", "+="), toks)
        self.assertIn(("number", "0x10"), toks)
        self.assertIn(("string", '"x /* y */"'), toks)
        self.assertIn(("char", "'\\n'"), toks)
        self.assertIn(("comment", "/* c1 */"), toks)
        self.assertIn(("op", "<<="), toks)
        self.assertIn(("number", "1.5e3"), toks)
        self.assertEqual(kinds.count("comment"), 1)

    def test_whitespace_and_wrapping_ignored(self):
        wrapped = self.REF.replace("iVar1 + values[lVar2]", "iVar1 +\n                values [ lVar2 ]")
        for mode in ("tokens", "ast", "alpha"):
            self.assertEqual(cnorm.normalize(self.REF, mode), cnorm.normalize(wrapped, mode), mode)
        self.assertNotEqual(cnorm.normalize(self.REF, "loose"), cnorm.normalize(wrapped, "loose"))

    def test_comments(self):
        reflowed = self.REF.replace("(ram,0x001012f7) */", "(ram,0x001012f7)\n   */")
        reworded = self.REF.replace("Removing unreachable", "Keeping")
        self.assertEqual(cnorm.normalize(self.REF, "tokens"), cnorm.normalize(reflowed, "tokens"))
        self.assertNotEqual(cnorm.normalize(self.REF, "tokens"), cnorm.normalize(reworded, "tokens"))
        self.assertEqual(cnorm.normalize(self.REF, "ast"), cnorm.normalize(reworded, "ast"))
        # Comment markers inside strings are code.
        inner = self.REF.replace("/* not a comment */", "/* other */")
        self.assertNotEqual(cnorm.normalize(self.REF, "ast"), cnorm.normalize(inner, "ast"))

    def test_alpha_renames_variables_only(self):
        renamed = (self.REF.replace("iVar1", "total").replace("lVar2", "lVar7").replace("count", "n")
                   .replace("buf", "tmp"))
        self.assertNotEqual(cnorm.normalize(self.REF, "ast"), cnorm.normalize(renamed, "ast"))
        self.assertEqual(cnorm.normalize(self.REF, "alpha"), cnorm.normalize(renamed, "alpha"))
        for other in (self.REF.replace("DAT_00104010", "DAT_00104018"),  # a global
                      self.REF.replace("printf", "puts"),                   # a callee
                      self.REF.replace("long lVar2", "ulong lVar2"),        # a type
                      self.REF.replace("lVar2 + 1", "lVar2 + 2")):          # a constant
            self.assertNotEqual(cnorm.normalize(self.REF, "alpha"), cnorm.normalize(other, "alpha"))

    def test_alpha_keeps_fields(self):
        a = "void f(S *p)\n\n{\n  p->len = 0;\n  return;\n}\n"
        b = "void f(S *q)\n\n{\n  q->size = 0;\n  return;\n}\n"
        self.assertNotEqual(cnorm.normalize(a, "alpha"), cnorm.normalize(b, "alpha"))
        self.assertEqual(cnorm.normalize(a, "alpha"), cnorm.normalize(b.replace("size", "len"), "alpha"))

    def test_missing_and_first_difference(self):
        self.assertIsNone(cnorm.normalize(None, "ast"))
        a, b = cnorm.first_difference("x = 1; y = 2;", "x = 1; y = 3;", context=2)
        self.assertEqual((a, b), ("y = 2 ;", "y = 3 ;"))


@unittest.skipUnless(os.environ.get("REFDIFF_REAL_REFS") or os.path.isdir(os.path.join(REPO, "out", "ref")),
                     "no real export (set REFDIFF_REAL_REFS or run scripts/phase0.sh)")
class RealExportSelfCheck(unittest.TestCase):
    """Diffing a real Ghidra export against itself must give 100% everywhere."""

    def test_self_check(self):
        root = os.environ.get("REFDIFF_REAL_REFS") or os.path.join(REPO, "out", "ref")
        total, per, warnings = refdiff.compare_paths(root, root)
        self.assertEqual(warnings, [])
        self.assertTrue(per)
        for cat in refdiff.CATEGORIES:
            a, t = total.counts[cat]
            self.assertEqual(a, t, cat)


if __name__ == "__main__":
    unittest.main()
