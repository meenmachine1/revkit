#!/usr/bin/env python3
"""Download the corpus's external sources into a cache dir and verify their
sha256 pins from corpus.json (or --corpus-json: heldout.json, firmware/firmware.json). Already-cached files that verify are kept.

  fetch.py --cache out/cache
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--corpus-json", default=os.path.join(HERE, "corpus.json"))
    args = ap.parse_args()
    with open(args.corpus_json) as f:
        externals = json.load(f).get("externals", {})
    os.makedirs(args.cache, exist_ok=True)
    bad = 0
    for name, ext in sorted(externals.items()):
        # "file" names the cached copy when the URL's basename is ambiguous
        # (GitHub tag archives are all v<version>.tar.gz).
        dest = os.path.join(args.cache, ext.get("file") or os.path.basename(ext["url"]))
        if os.path.exists(dest) and sha256_file(dest) == ext["sha256"]:
            continue
        print("fetching %s: %s" % (name, ext["url"]), flush=True)
        tmp = dest + ".part"
        req = urllib.request.Request(ext["url"], headers={"User-Agent": "revkit-corpus-fetch"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
            out.write(resp.read())
        digest = sha256_file(tmp)
        if digest != ext["sha256"]:
            print("ERROR %s: sha256 %s, pinned %s" % (name, digest, ext["sha256"]), file=sys.stderr)
            os.remove(tmp)
            bad += 1
            continue
        os.replace(tmp, dest)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
