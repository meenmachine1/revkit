#!/usr/bin/env python3
"""Builds auto-detection test cases from files outside the repository
(scripts/bench-detect.sh; docs/autodetect.md).

  detect_external.py MANIFEST.json --out DIR

The manifest lists files and what is known about each:

  {"cases": [
    {"name": "qemu/opensbi-rv64",
     "source": "/path/to/file",          also relative to the manifest
     "unpack": "xz" | "bz2",             optional: the file is compressed
     "elf": true,                        optional: an ELF, turned into the flat image
                                         of its loaded segments (its base is the truth)
     "language": "RISCV:LE:64:RV64GC:default",   or only what is known:
     "family": "RISCV", "endian": "LE", "bits": 64,   family may be a list of names
                                                      for one processor (z80, z180)
     "base": "0x80000000", "offset": "0x0",       optional
     "kind": "image" | "chunk" | "negative",      chunk: code cut out of programs,
                                                  with no layout to find
     "refusal": "unknown-processor",              for a negative
     "max_bytes": 1048576,                        optional: only the first bytes
     "split": "dev" | "heldout" | "hash"}]}      hash: by the name, half each

The result is a cases.json and the files, as scripts/detect_cases.py makes
them. Held-out cases are for a final run, not for tuning (docs/heldout.md).
"""
import argparse
import bz2
import hashlib
import json
import lzma
import os
import struct
import sys


def flat_image(elf):
    """The loaded segments of an ELF as one flat image, and its base."""
    if elf[:4] != b'\x7fELF':
        raise ValueError('not an ELF')
    wide, e = elf[4] == 2, '<' if elf[5] == 1 else '>'
    if wide:
        phoff, = struct.unpack_from(e + 'Q', elf, 0x20)
        phentsize, phnum = struct.unpack_from(e + 'HH', elf, 0x36)
    else:
        phoff, = struct.unpack_from(e + 'I', elf, 0x1c)
        phentsize, phnum = struct.unpack_from(e + 'HH', elf, 0x2a)
    loads = []
    for i in range(phnum):
        at = phoff + i * phentsize
        if wide:
            kind, _, offset, _, paddr, filesz = struct.unpack_from(e + 'IIQQQQ', elf, at)
        else:
            kind, offset, _, paddr, filesz = struct.unpack_from(e + 'IIIII', elf, at)
        if kind == 1 and filesz:
            loads.append((paddr, elf[offset:offset + filesz]))
    if not loads:
        raise ValueError('no loaded segments')
    base = min(a for a, _ in loads)
    image = bytearray(max(a + len(d) for a, d in loads) - base)
    for a, d in loads:
        image[a - base:a - base + len(d)] = d
    return bytes(image), base


# Processors Ghidra names apart that a family answer may name for each other:
# a variant of the same instruction set (a superset, a renamed derivative).
RELATED = [
    ['6502', '65C02'], ['z80', 'z180', 'z182', 'z8401x'], ['8051', '80251', '80390', '8051 Banked'],
    ['PIC-24E', 'PIC-24F', 'PIC-24H', 'dsPIC30F', 'dsPIC33F', 'dsPIC33E', 'dsPIC33C'],
    ['6805', 'HC05'], ['HC08', 'HCS08'], ['HC-12', 'HCS-12', 'HCS12', 'HCS-12X'], ['6809', 'H6309'],
    ['SuperH', 'SuperH4'], ['TI_MSP430', 'TI_MSP430X'], ['M16C/60', 'M16C/80'], ['PIC-24', 'PIC-24E'],
]


def ghidra_languages():
    """(processor, byte order, size) of every language id the Ghidra install defines."""
    import glob
    import xml.etree.ElementTree as ET
    root = os.environ.get('REVKIT_GHIDRA_ROOT') or os.environ.get('GHIDRA_INSTALL_DIR') or os.path.expanduser('~/ghidra/ghidra_12.1.4_PUBLIC')
    out = set()
    for path in glob.glob(os.path.join(root, 'Ghidra', 'Processors', '*', 'data', 'languages', '*.ldefs')):
        for lang in ET.parse(path).getroot().iter('language'):
            # The id's fields, as answers spell them: "avr8:LE:16:default" has
            # processor "AVR8".
            p = lang.get('id').split(':')
            out.add((p[0], p[1], p[2], p[3]))
    return out


def family_truth(truth, languages):
    """A manifest's family, byte order and bits as the language ids that fit
    them ("family_ids", processor:order:size). Collectors write a processor as
    they know it ("AVR8" for avr8, "Z80" for z80) and give the data width as
    bits (8 for a 6502, whose Ghidra language is 16 bits, its address size).
    So: the processor and its RELATED ones, and per processor its languages of
    the stated order and bits, or all of them where it has none of those bits
    (another convention). A 64-bit language with 32-bit addresses
    ("VLE-32addr", "ilp32") is 32 bits."""
    family = truth.get('family')
    if not family or not languages:
        return
    names = {p.lower(): p for p, _, _, _ in languages}
    group = []
    for f in family if isinstance(family, list) else [family]:
        name = names.get(f.lower(), names.get(f.lower().replace('-', ''), f))
        group += [g for g in next((g for g in RELATED if name in g), [name]) if g not in group]
    name = group[0]
    bits = str(truth['bits']) if truth.get('bits') else None
    order = truth.get('endian')
    ids = set()
    for proc in group:
        mine = [(e, b, v) for p, e, b, v in languages if p == proc]
        fit = lambda e, b, v: (order in (None, e) or all(x != order for x, _, _ in mine)) and \
            (bits is None or b == bits or (bits == '32' and ('32addr' in v or 'ilp32' in v)))
        chosen = [(e, b) for e, b, v in mine if fit(e, b, v)] or [(e, b) for e, b, _ in mine]
        ids.update(f'{proc}:{e}:{b}' for e, b in chosen)
    if ids:
        truth['family'] = group if len(group) > 1 else name
        truth['family_ids'] = sorted(ids)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('manifest')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    root = os.path.dirname(os.path.abspath(args.manifest))
    os.makedirs(args.out, exist_ok=True)
    cases = []
    languages = ghidra_languages()
    for c in json.load(open(args.manifest))['cases']:
        source = os.path.join(root, os.path.expanduser(c['source']))
        try:
            data = open(source, 'rb').read()
            if c.get('unpack') == 'xz':
                data = lzma.decompress(data)
            elif c.get('unpack') == 'bz2':
                data = bz2.decompress(data)
            truth = {k: v for k, v in c.items() if k not in ('source', 'unpack', 'elf', 'max_bytes')}
            # "regions" as records (name, file offset, address, size) are
            # where the file's bytes load (a HEX file's segments), not the
            # RAM and I/O regions the scorer's "regions" strings are.
            regions = truth.get('regions')
            if regions is not None and (not isinstance(regions, list) or any(not isinstance(r, str) for r in regions)):
                truth['image_regions'] = truth.pop('regions')
            family_truth(truth, languages)
            if c.get('elf'):
                data, base = flat_image(data)
                truth.setdefault('base', hex(base))
                truth.setdefault('offset', '0x0')
            if c.get('max_bytes'):
                data = data[:c['max_bytes']]
        except (OSError, ValueError, lzma.LZMAError) as e:
            print(f'detect_external: {c["name"]}: skipped: {e}', file=sys.stderr)
            continue
        if truth.get('split') == 'hash':
            truth['split'] = 'dev' if hashlib.sha256(c['name'].encode()).digest()[0] % 2 == 0 else 'heldout'
        truth.setdefault('kind', 'image')
        path = c['name'].replace('/', '__') + '.bin'
        with open(os.path.join(args.out, path), 'wb') as f:
            f.write(data)
        cases.append({'path': path, 'size': len(data), **truth})
    json.dump({'cases': cases}, open(os.path.join(args.out, 'cases.json'), 'w'), indent=1)
    print(f'detect_external: {len(cases)} cases in {args.out}', file=sys.stderr)


if __name__ == '__main__':
    main()
