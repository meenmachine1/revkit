#!/usr/bin/env python3
"""Scores auto-detection (docs/autodetect.md) on cases with known answers.

  detect_score.py [--cases build/detect-cases] [--out build/detect-out]
                  [--detect 'build/tools/rk-lift/rk-lift --detect'] [-j N]
                  [--only GLOB] [--split NAME] [--timeout SECONDS]
                  [--baseline FILE | --save-baseline FILE]

The cases are a directory with cases.json (scripts/detect_cases.py builds
the firmware corpus's; scripts/bench-detect.sh external ones). The detector
is run once per case on the file alone and prints a report as JSON:

  {"refusal": null | {"reason": "high-entropy" | "not-code" |
                      "unknown-processor" | "too-small", "detail": "..."},
   "suggestions": [                      best first
     {"language": "ARM:LE:32:Cortex:default",
      "tie_group": ["ARM:LE:32:Cortex:default", ...],   languages it can't tell apart
      "base": "0x8000000" | null,        null: undetermined (position-independent)
      "offset": "0x0",
      "regions": ["ram:20000000:40000", ...],   as --region takes them
      "region_details": [{"region": "ram:20000000:40000", "kind": "ram" | "mmio" | "unknown",
                          "confidence": "high" | ..., "evidence": ["...", ...]}, ...],
      "confidence": {"processor": "high" | "medium" | "low", "variant": ...,
                     "base": ..., "offset": ...},
      "evidence": [{"about": "processor", "text": "..."}, ...]}],
   "segments": [{"offset": "0x0", "size": "0x200", "kind": "code" | ...}, ...]}

What is measured, over the cases that are programs:

  family      the best suggestion names the processor family, byte order and
              word size (top-1), or one of the best three does (top-3)
  language    the best suggestion's language is the case's, or the case's is
              in its tie group (compared without the compiler)
  variant     the best suggestion's language is exactly the case's
  base        the best suggestion's base is exact
  load        base - offset is right: the image lands where it should, which
              is what analysis needs
  offset      the offset is exact
  confident-wrong  an answer given at high confidence is wrong: the headline,
              and what a gate holds at zero

and of the memory regions beyond the image (RAM, MMIO), on the cases whose
regions are known (regions in cases.json; null: not known), per kind:

  ram_found, mmio_found   every true region of the kind overlaps a suggested
              region of the same kind
  ram_start, mmio_start   a suggested region of the kind holds its start
  ram_size, mmio_size     the suggested region overlapping it most is within
              2x of its size
  ram_end     a suggested RAM region holds the true one's last word (where
              the stack starts)
  ram_window_found, mmio_window_found   where only windows are known (a
              board's memory map: regions_partial in cases.json), a
              suggested region of the kind overlaps one
  ram_false, mmio_false, unknown_false   suggested regions (of each kind,
              "unknown" for one the detector couldn't classify) that overlap
              no true region or window of their kind (or of any kind, for
              "unknown"): counts, lower is better
  region confident-wrong   a region suggested at high confidence that is
              false; counted in confident-wrong too

and over the cases that are no program: refused (a refusal and no
suggestion at high confidence); over the near misses (code of a processor
derived from one revkit knows, near_miss_of in cases.json): unconfident
(no suggestion at high processor confidence; naming the processor it came
from is allowed, with confidence it is confident-wrong). Times are
wall-clock per case.
"""
import argparse
import concurrent.futures
import fnmatch
import json
import os
import shlex
import statistics
import subprocess
import sys
import time


def num(v):
    if v is None:
        return None
    return int(v, 0) if isinstance(v, str) else int(v)


def fields(language):
    """(family, byte order, bits, variant) of a language id, without the compiler."""
    p = (language or '').split(':')
    return tuple(p[:4]) if len(p) >= 4 else None


def truth_family(case):
    """What the case says of the family: (family, byte order or None, bits or None)."""
    if case.get('language'):
        f = fields(case['language'])
        return f[0], f[1], f[2]
    if case.get('family_ids'):
        return set(case['family_ids'])
    if case.get('family'):
        return case['family'], case.get('endian'), str(case['bits']) if case.get('bits') else None
    return None


def family_matches(language, want):
    f = fields(language)
    if f is None or want is None:
        return False
    if isinstance(want, set):  # the language ids that fit (detect_external.py's family_ids)
        return ':'.join(f[:3]) in want
    families = want[0] if isinstance(want[0], list) else [want[0]]
    return f[0] in families and want[1] in (None, f[1]) and want[2] in (None, f[2])


def parse_region(text):
    """(kind, start, size) of a region in --region's spelling: name:start:size[:perms][:init|uninit|volatile].
    Volatile is MMIO; anything else is RAM."""
    p = text.split(':')
    kind = 'mmio' if 'volatile' in p[3:] else 'ram'
    return kind, int(p[1], 16), int(p[2], 16)


def suggested_regions(suggestion):
    """(kind, start, size, confidence) of each region a suggestion makes."""
    details = suggestion.get('region_details')
    if details is not None:
        out = []
        for d in details:
            _, start, size = parse_region(d['region'])
            out.append((d.get('kind') or parse_region(d['region'])[0], start, size, d.get('confidence')))
        return out
    return [(*parse_region(r), None) for r in suggestion.get('regions') or []]


def overlap(a_start, a_size, b_start, b_size):
    return max(0, min(a_start + a_size, b_start + b_size) - max(a_start, b_start))


def judge_regions(case, top, v):
    """Region verdicts into v; True if a region given at high confidence is false.

    case['regions']: the true regions, exactly (start and size scored); null
    where they aren't known. case['regions_partial']: [{"kind": "ram" |
    "mmio" | "any", "region": ...}], windows the true regions are somewhere
    in (a board's memory map): scored for found and false only."""
    exact = case.get('regions')
    partial = case.get('regions_partial')
    if exact is None and partial is None:
        return False
    truth = [parse_region(r) for r in exact or []]
    windows = [(w['kind'], *parse_region(w['region'])[1:]) for w in partial or []]
    got = suggested_regions(top) if top else []
    for kind in ('ram', 'mmio'):
        want = [t for t in truth if t[0] == kind]
        if want:
            found = start = size = end = True
            for _, t_start, t_size in want:
                same = [g for g in got if g[0] == kind and overlap(g[1], g[2], t_start, t_size) > 0]
                found = found and bool(same)
                start = start and any(g[1] <= t_start < g[1] + g[2] for g in got if g[0] == kind)
                end = end and any(g[1] <= t_start + t_size - 4 < g[1] + g[2] for g in got if g[0] == kind)
                best = max(same, key=lambda g: overlap(g[1], g[2], t_start, t_size), default=None)
                size = size and best is not None and t_size / 2 <= best[2] <= 2 * t_size
            v[f'{kind}_found'], v[f'{kind}_start'], v[f'{kind}_size'] = found, start, size
            if kind == 'ram':
                v['ram_end'] = end  # where the stack starts
        if any(w[0] == kind for w in windows):
            v[f'{kind}_window_found'] = any(g[0] == kind and overlap(g[1], g[2], w[1], w[2]) > 0
                                            for g in got for w in windows if w[0] == kind)
    wrong = False
    every = truth + windows
    for kind in ('ram', 'mmio', 'unknown'):
        false = [g for g in got if g[0] == kind and
                 not any((t[0] in (kind, 'any') or kind == 'unknown') and overlap(g[1], g[2], t[1], t[2]) > 0
                         for t in every)]
        v[f'{kind}_false'] = len(false)
        wrong = wrong or any(g[3] == 'high' for g in false)
    v['region_confident_wrong'] = wrong
    return wrong


def run_one(detect, cases_dir, case, timeout):
    path = os.path.join(cases_dir, case['path'])
    started = time.monotonic()
    try:
        p = subprocess.run(detect + [path], capture_output=True, timeout=timeout)
        seconds = time.monotonic() - started
        if p.returncode not in (0, 1):  # 1: refused or not confident
            return {'error': f'exit {p.returncode}: {p.stderr.decode(errors="replace")[-300:]}', 'seconds': seconds}
        report = json.loads(p.stdout)
    except subprocess.TimeoutExpired:
        return {'error': f'timeout after {timeout} s', 'seconds': timeout}
    except (json.JSONDecodeError, OSError) as e:
        return {'error': str(e), 'seconds': time.monotonic() - started}
    report['seconds'] = seconds
    return report


def judge(case, report):
    """One case's verdicts: name -> True/False (None: not asked of this case)."""
    v = {'error': 'error' in report}
    suggestions = report.get('suggestions') or []
    refused = report.get('refusal') is not None or not suggestions
    high = lambda s, about: (s.get('confidence') or {}).get(about) == 'high'
    want = truth_family(case)
    if case.get('near_miss_of'):  # a processor revkit has no language for, derived from one it has
        v['unconfident'] = not v['error'] and not any(high(s, 'processor') for s in suggestions)
        v['confident_wrong'] = any(high(s, 'processor') for s in suggestions)
        return v
    if want is None:  # no program
        v['refused'] = not v['error'] and refused and not any(high(s, 'processor') for s in suggestions)
        v['reason'] = (report.get('refusal') or {}).get('reason') == case.get('refusal')
        v['confident_wrong'] = any(high(s, 'processor') for s in suggestions)
        v['confident_wrong'] = judge_regions(case, suggestions[0] if suggestions else {}, v) or v['confident_wrong']
        return v
    top = suggestions[0] if suggestions else {}
    v['answered'] = bool(suggestions) and report.get('refusal') is None
    v['family'] = family_matches(top.get('language'), want)
    v['family_top3'] = any(family_matches(s.get('language'), want) for s in suggestions[:3])
    wrong_confident = high(top, 'processor') and not v['family']
    if case.get('language'):
        truth = fields(case['language'])
        group = [fields(x) for x in [top.get('language')] + list(top.get('tie_group') or [])]
        v['language'] = truth in group
        v['variant'] = fields(top.get('language')) == truth
        v['tie_group_size'] = len(set(group))
        wrong_confident = wrong_confident or (high(top, 'variant') and not v['language'])
    if case.get('base') is not None and v['family']:
        base, offset = num(top.get('base')), num(top.get('offset')) or 0
        t_base, t_offset = num(case['base']), num(case.get('offset')) or 0
        v['base'] = base == t_base
        v['load'] = base is not None and base - offset == t_base - t_offset
        v['offset'] = offset == t_offset
        wrong_confident = wrong_confident or (high(top, 'base') and not v['load']) or \
            (high(top, 'offset') and not v['offset'])
    elif case.get('base') is not None:
        v['base'] = v['load'] = v['offset'] = False
    wrong_confident = judge_regions(case, top, v) or wrong_confident
    v['confident_wrong'] = wrong_confident
    return v


RATES = ['answered', 'family', 'family_top3', 'language', 'variant', 'base', 'load', 'offset', 'refused', 'unconfident',
         'ram_found', 'ram_start', 'ram_end', 'ram_size', 'mmio_found', 'mmio_start', 'mmio_size',
         'ram_window_found', 'mmio_window_found']
# Counts where lower is better.
COUNTS = ['confident_wrong', 'errors', 'ram_false', 'mmio_false', 'unknown_false', 'region_confident_wrong']


def summarize(rows):
    """Counts over a group of (case, report, verdicts)."""
    s = {'cases': len(rows), 'errors': sum(1 for _, _, v in rows if v['error']),
         'confident_wrong': sum(1 for _, _, v in rows if v.get('confident_wrong'))}
    if any('ram_false' in v for _, _, v in rows):
        for k in ('ram_false', 'mmio_false', 'unknown_false'):
            s[k] = sum(v.get(k, 0) for _, _, v in rows)
        s['region_confident_wrong'] = sum(1 for _, _, v in rows if v.get('region_confident_wrong'))
    for k in RATES:
        asked = [v[k] for _, _, v in rows if v.get(k) is not None]
        if asked:
            s[k] = {'right': sum(asked), 'of': len(asked)}
    times = sorted(r.get('seconds', 0) for _, r, _ in rows)
    if times:
        s['seconds'] = {'p50': round(statistics.median(times), 2), 'p95': round(times[int(0.95 * (len(times) - 1))], 2),
                        'max': round(times[-1], 2)}
    return s


def show(title, s):
    cells = [f'{k} {s[k]["right"]}/{s[k]["of"]}' for k in RATES if k in s]
    t = s.get('seconds', {})
    cells += [f'{k.replace("_", "-")} {s[k]}' for k in COUNTS[2:] if k in s]
    print(f'{title:<22} {s["cases"]:>4} cases  ' + '  '.join(cells) +
          f'  confident-wrong {s["confident_wrong"]}  errors {s["errors"]}' +
          (f'  p50 {t["p50"]} s  p95 {t["p95"]} s  max {t["max"]} s' if t else ''))


def regressions(old, new, path=''):
    """Where `new` is worse than the baseline `old`."""
    out = []
    for group, o in old.items():
        n = new.get(group)
        if n is None:
            out.append(f'{group}: missing')
            continue
        for k in RATES:
            if k in o and (k not in n or n[k]['right'] * o[k]['of'] < o[k]['right'] * n[k]['of']):
                got = f'{n[k]["right"]}/{n[k]["of"]}' if k in n else 'none'
                out.append(f'{group}: {k} {got}, baseline {o[k]["right"]}/{o[k]["of"]}')
        for k in COUNTS:
            if k in o and n.get(k, 0) > o[k]:
                out.append(f'{group}: {k} {n[k]}, baseline {o[k]}')
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cases', default='build/detect-cases')
    ap.add_argument('--out', default='build/detect-out')
    ap.add_argument('--detect', default='build/tools/rk-lift/rk-lift --detect')
    ap.add_argument('-j', type=int, default=os.cpu_count() or 1)
    ap.add_argument('--only')
    ap.add_argument('--split')
    ap.add_argument('--timeout', type=float, default=300)
    ap.add_argument('--baseline')
    ap.add_argument('--save-baseline')
    ap.add_argument('--reports', help="judge a previous run's reports.json again instead of detecting")
    args = ap.parse_args()

    cases = json.load(open(os.path.join(args.cases, 'cases.json')))['cases']
    if args.only:
        cases = [c for c in cases if fnmatch.fnmatch(c['name'], args.only)]
    if args.split:
        cases = [c for c in cases if c.get('split') == args.split]
    if not cases:
        sys.exit('detect_score: no cases')
    detect = shlex.split(args.detect)
    os.makedirs(args.out, exist_ok=True)

    if args.reports:
        saved = {x['name']: x['report'] for x in json.load(open(args.reports))}
        cases = [c for c in cases if c['name'] in saved]
        reports = [saved[c['name']] for c in cases]
    else:
        with concurrent.futures.ThreadPoolExecutor(args.j) as pool:
            reports = list(pool.map(lambda c: run_one(detect, args.cases, c, args.timeout), cases))
    # The reports first, so a judging error doesn't throw away the run.
    if not args.reports:
        json.dump([{'name': c['name'], 'report': r} for c, r in zip(cases, reports)],
                  open(os.path.join(args.out, 'reports.json'), 'w'))
    rows = [(c, r, judge(c, r)) for c, r in zip(cases, reports)]

    groups = {'all': rows}
    for c, r, v in rows:
        groups.setdefault(f'kind {c.get("kind", "?")}', []).append((c, r, v))
        if c.get('arch'):
            groups.setdefault(f'arch {c["arch"]}', []).append((c, r, v))
        groups.setdefault(f'split {c.get("split", "?")}', []).append((c, r, v))
    summary = {g: summarize(rs) for g, rs in sorted(groups.items())}
    for g, s in summary.items():
        show(g, s)
    for c, r, v in rows:
        if v['error']:
            print(f'  error: {c["name"]}: {r["error"]}')
        elif v.get('confident_wrong'):
            print(f'  confident and wrong: {c["name"]}')

    # A confident answer that is wrong is a failure whatever the baseline.
    wrong = [c['name'] for c, _, v in rows if v.get('confident_wrong')]
    json.dump({'summary': summary,
               'cases': [{'name': c['name'], 'verdicts': v, 'report': r} for c, r, v in rows]},
              open(os.path.join(args.out, 'report.json'), 'w'), indent=1)
    if args.save_baseline:
        json.dump({g: {k: v for k, v in s.items() if k != 'seconds'} for g, s in summary.items()},
                  open(args.save_baseline, 'w'), indent=1, sort_keys=True)
        print(f'detect_score: baseline saved to {args.save_baseline}')
    if args.baseline:
        bad = regressions(json.load(open(args.baseline)), summary)
        for b in bad:
            print(f'REGRESSION {b}')
        if bad:
            sys.exit(1)
        print('detect_score: no regression against the baseline')
    if wrong and (args.baseline or args.save_baseline):
        sys.exit(f'detect_score: {len(wrong)} confident answers are wrong')


if __name__ == '__main__':
    main()
