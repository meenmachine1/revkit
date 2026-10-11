#!/usr/bin/env python3
"""Generates src/detect/profiles.inc: how often real code of each
instruction set uses each mnemonic, which auto-detection compares a
candidate language's decoding with (docs/autodetect.md, "Related
processors"; src/detect/fit.cc).

  detect_profiles.py [--corpus out/firmware-corpus] [--elf-corpus out/corpus]
                     [--rk-lift build/tools/rk-lift/rk-lift] [--out src/detect/profiles.inc]

The real code is revkit's own: the firmware corpus's images (the kit),
the images scripts/detect_cases.py builds with clang, and the .text of the
corpus's optimised Linux programs (gcc and clang, -O2). Each is run through
`rk-lift --detect-features`, and what the code that control flow reaches
decodes to under the true processor (reached_forms of its sweep) is
counted, per processor, address size and decoding mode. Only counts are
kept, so nothing of the programs themselves is in the output.
"""
import argparse
import collections
import glob
import json
import os
import struct
import subprocess
import sys
import tempfile

import detect_cases


def elf_text(path):
    """The .text section of an ELF, or None."""
    data = open(path, 'rb').read()
    if data[:4] != b'\x7fELF':
        return None
    wide, e = data[4] == 2, '<' if data[5] == 1 else '>'
    if wide:
        shoff, = struct.unpack_from(e + 'Q', data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(e + 'HHH', data, 0x3a)
    else:
        shoff, = struct.unpack_from(e + 'I', data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(e + 'HHH', data, 0x2e)

    def section(i):
        at = shoff + i * shentsize
        if wide:
            name, kind, _, _, offset, size = struct.unpack_from(e + 'IIQQQQ', data, at)
        else:
            name, kind, _, _, offset, size = struct.unpack_from(e + 'IIIIII', data, at)
        return name, offset, size

    _, str_off, _ = section(shstrndx)
    for i in range(shnum):
        name, offset, size = section(i)
        end = data.index(b'\0', str_off + name)
        if data[str_off + name:end] == b'.text':
            return data[offset:offset + size]
    return None


def census(rk_lift, path, language):
    """(processor, bits, mode, Counter of mnemonics) of the code control flow
    reaches, under the sweep of the true processor; None if none was taken."""
    p = subprocess.run([rk_lift, '--detect-features', path], capture_output=True)
    report = json.loads(p.stdout)
    processor, _, bits = language.split(':')[:3]
    for sweep in report.get('sweeps', []):
        forms = sweep['features'].get('reached_forms')
        if sweep['language'].split(':')[0] == processor and forms:
            mode = sweep['candidate'].split(' (')[1].rstrip(')') if ' (' in sweep['candidate'] else ''
            counts = collections.Counter()
            for form, n in forms.items():
                counts[form.rsplit('/', 1)[0]] += n
            return processor, int(bits), mode, counts
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    ap.add_argument('--corpus', default=os.path.join(root, 'out', 'firmware-corpus'))
    ap.add_argument('--elf-corpus', default=os.path.join(root, 'out', 'corpus'))
    ap.add_argument('--rk-lift', default=os.path.join(root, 'build', 'tools', 'rk-lift', 'rk-lift'))
    ap.add_argument('--out', default=os.path.join(root, 'src', 'detect', 'profiles.inc'))
    args = ap.parse_args()

    profiles = collections.defaultdict(collections.Counter)
    sources = collections.defaultdict(int)

    def add(path, language):
        got = census(args.rk_lift, path, language)
        if got is None:
            print(f'detect_profiles: {os.path.basename(path)}: no sweep of {language}', file=sys.stderr)
            return
        processor, bits, mode, counts = got
        profiles[(processor, bits, mode)] += counts
        sources[(processor, bits, mode)] += 1

    manifest = json.load(open(os.path.join(args.corpus, 'manifest.json')))
    for image in manifest['images']:
        add(os.path.join(args.corpus, image['path']), image['language'])
    with tempfile.TemporaryDirectory(dir=os.path.join(root, 'build')) as tmp:
        for image, data in detect_cases.built_images(tmp):
            path = os.path.join(tmp, image['name'].replace('/', '_') + '.bin')
            with open(path, 'wb') as f:
                f.write(data)
            add(path, image['language'])
        languages = {'elf-x86_64': 'x86:LE:64:default', 'elf-aarch64': 'AARCH64:LE:64:v8A',
                     'elf-riscv64': 'RISCV:LE:64:default'}
        for kind, language in languages.items():
            for elf in sorted(glob.glob(os.path.join(args.elf_corpus, kind, '*-O2', 'stripped', '*'))):
                text = elf_text(elf)
                if not text:
                    continue
                path = os.path.join(tmp, kind + '-' + os.path.basename(os.path.dirname(os.path.dirname(elf))) + '-' +
                                    os.path.basename(elf) + '.bin')
                with open(path, 'wb') as f:
                    f.write(text[:1 << 20])
                add(path, language)

    lines = ['// Generated by scripts/detect_profiles.py: do not edit. How often the code',
             '// that control flow reaches in real code (the firmware corpus, the images',
             '// scripts/detect_cases.py builds, the corpus\'s -O2 programs) uses each',
             '// mnemonic, per processor, address size and decoding mode.']
    names = []
    for (processor, bits, mode), counts in sorted(profiles.items()):
        name = 'k' + ''.join(c if c.isalnum() else '_' for c in f'{processor}_{bits}_{mode}')
        names.append((name, processor, bits, mode, sum(counts.values())))
        lines.append(f'// {processor}:{bits}{" " + mode if mode else ""}: {sources[(processor, bits, mode)]} programs')
        lines.append(f'constexpr Mnemonics {name}[] = {{')
        for mnemonic, n in sorted(counts.items()):
            lines.append(f'    {{{json.dumps(mnemonic)}, {n}}},')
        lines.append('};')
    lines.append('constexpr Profile kProfiles[] = {')
    for name, processor, bits, mode, total in names:
        lines.append(f'    {{"{processor}", {bits}, "{mode}", {total}, {name}}},')
    lines.append('};')
    with open(args.out, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    for (name, processor, bits, mode, total) in names:
        print(f'detect_profiles: {processor}:{bits} {mode or "-"}: {total} instructions, '
              f'{len(profiles[(processor, bits, mode)])} mnemonics', file=sys.stderr)


if __name__ == '__main__':
    main()
