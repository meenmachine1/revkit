#!/usr/bin/env python3
"""Recounts docs/ghidra-feature-survey.md from its rows, so the counts can't drift.

Every table row with a Status cell (the second column of a table whose
header starts "| Feature |") is counted under its part (## Part 1 / ## Part 2)
and its topic (the nearest ### heading in Part 1, #### in Part 2). Statuses:
Have (any "Have ..." spelling), Partial, Missing, In progress.

It rewrites three tables in place, each between markers:

  <!-- survey-summary:total -->      the totals at the top of the file
  <!-- survey-summary:part1 -->      Part 1's per-topic counts
  <!-- survey-summary:part2 -->      Part 2's per-module counts

and, in docs/wishlist.md, the counts sentence between
<!-- survey-summary:wishlist --> markers.

    scripts/survey_summary.py           # rewrite
    scripts/survey_summary.py --check   # exit 1 if a table is out of date

Python's standard library only.
"""
import argparse
import re
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SURVEY = ROOT / "docs" / "ghidra-feature-survey.md"
WISHLIST = ROOT / "docs" / "wishlist.md"
KINDS = ("Have", "Partial", "Missing", "In progress")


def kind_of(status: str) -> str | None:
    s = status.strip().strip("*")
    if s.startswith("Have"):
        return "Have"
    for k in KINDS[1:]:
        if s == k:
            return k
    return None


def count(text: str):
    """{part: OrderedDict(topic -> {kind: n})} from the rows."""
    parts = {1: OrderedDict(), 2: OrderedDict()}
    part, topic, in_table = 0, None, False
    for line in text.splitlines():
        if line.startswith("## Part 1"):
            part = 1
        elif line.startswith("## Part 2"):
            part = 2
        elif line.startswith("## "):
            part = 0
        m = re.match(r"^(#{3,4}) (.+)$", line)
        if m and part:
            level, name = len(m.group(1)), m.group(2).strip()
            if (part == 1 and level == 3) or (part == 2 and level == 4):
                topic = re.sub(r"\s*\(.*\)$", "", name) if part == 2 else name
            in_table = False
            continue
        if not line.startswith("|"):
            in_table = False
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and cells[0] == "Feature":
            in_table = True
            continue
        if not in_table or len(cells) < 3 or set(cells[0]) <= set("-: "):
            continue
        k = kind_of(cells[1])
        if k is None or not part or topic is None:
            continue
        parts[part].setdefault(topic, {x: 0 for x in KINDS})[k] += 1
    return parts


def totals(topics) -> dict:
    t = {k: 0 for k in KINDS}
    for c in topics.values():
        for k in KINDS:
            t[k] += c[k]
    return t


def total_table(parts) -> str:
    rows = ["| Part | Features | Have | Partial | Missing | In progress |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    names = {1: "Base (CodeBrowser, analyzers, types, search, symbols, ...)",
             2: "Everything else (decompiler, graphs, VT, BSim, FID, debugger, formats, ...)"}
    grand = {k: 0 for k in KINDS}
    for p in (1, 2):
        t = totals(parts[p])
        for k in KINDS:
            grand[k] += t[k]
        rows.append(f"| {names[p]} | {sum(t.values())} | {t['Have']} | {t['Partial']} | {t['Missing']} | {t['In progress']} |")
    rows.append(f"| **Total** | **{sum(grand.values())}** | **{grand['Have']}** | **{grand['Partial']}** | "
                f"**{grand['Missing']}** | **{grand['In progress']}** |")
    return "\n".join(rows)


def topic_table(topics, head: str, total_label: str) -> str:
    rows = [f"| {head} | Have | Partial | Missing | In progress |", "|---|---|---|---|---|"]
    for name, c in topics.items():
        rows.append(f"| {name} | {c['Have']} | {c['Partial']} | {c['Missing']} | {c['In progress']} |")
    t = totals(topics)
    rows.append(f"| **{total_label.format(topics=len(topics), features=sum(t.values()))}** | **{t['Have']}** | "
                f"**{t['Partial']}** | **{t['Missing']}** | **{t['In progress']}** |")
    return "\n".join(rows)


def replace_between(text: str, name: str, body: str) -> str:
    pat = re.compile(rf"(<!-- survey-summary:{name} -->\n)(?:.*?\n)?(<!-- /survey-summary:{name} -->)", re.S)
    if not pat.search(text):
        raise SystemExit(f"marker survey-summary:{name} not found")
    return pat.sub(lambda m: m.group(1) + body + "\n" + m.group(2), text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 when a table is out of date; change nothing")
    a = ap.parse_args()
    text = SURVEY.read_text()
    parts = count(text)
    new = replace_between(text, "total", total_table(parts))
    new = replace_between(new, "part1", topic_table(parts[1], "Topic", "Total ({topics} topics, {features} features)"))
    new = replace_between(new, "part2", topic_table(parts[2], "Module / topic", "Total ({topics} modules, {features} features)"))
    t1, t2 = totals(parts[1]), totals(parts[2])
    g = {k: t1[k] + t2[k] for k in KINDS}
    sentence = (f"Of {sum(g.values())} Ghidra features: revkit has {g['Have']}, has part of {g['Partial']}, lacks "
                f"{g['Missing']}, and {g['In progress']} {'is' if g['In progress'] == 1 else 'are'} being built (counted by `scripts/survey_summary.py` from "
                f"the survey's rows).")
    wl = WISHLIST.read_text()
    new_wl = replace_between(wl, "wishlist", sentence)
    stale = new != text or new_wl != wl
    if a.check:
        if stale:
            print("docs/ghidra-feature-survey.md or docs/wishlist.md counts are out of date: run scripts/survey_summary.py",
                  file=sys.stderr)
        return 1 if stale else 0
    SURVEY.write_text(new)
    WISHLIST.write_text(new_wl)
    print(sentence)
    return 0


if __name__ == "__main__":
    sys.exit(main())
