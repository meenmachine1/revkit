#!/usr/bin/env python3
"""Reads Ghidra's side of the firmware benchmark from a running Ghidra, through
the ghidra-mcp plugin's HTTP server (GHIDRA_MCP_URL, default
http://127.0.0.1:8089): only GET endpoints that read (list_functions,
disassemble_function, decompile_function). Nothing is written to Ghidra.

  bench_firmware_fetch.py functions OUT.json           the function list
  bench_firmware_fetch.py disasm OUT.json              every function's disassembly
  bench_firmware_fetch.py decompile OUT.json SAMPLE    C for the sample's entries (cached in OUT.json;
                                                       a function Ghidra can't decompile is null)

GHIDRA_PROGRAM names the program in Ghidra (required)."""
import json, sys, os, urllib.request, urllib.parse, concurrent.futures
URL = os.environ.get('GHIDRA_MCP_URL', 'http://127.0.0.1:8089')
PROGRAM = os.environ.get('GHIDRA_PROGRAM') or sys.exit('bench_firmware_fetch: set GHIDRA_PROGRAM to the program name in Ghidra')
def get(path, **params):
    params['program'] = PROGRAM
    with urllib.request.urlopen(URL + path + '?' + urllib.parse.urlencode(params), timeout=120) as r:
        return r.read().decode()
def main():
    what = sys.argv[1]
    out = sys.argv[2]
    if what == 'functions':
        funcs = json.loads(get('/list_functions'))['functions']
        json.dump({'functions': funcs, 'count': len(funcs)}, open(out, 'w'))
    elif what == 'disasm':
        funcs = json.loads(get('/list_functions'))['functions']
        res = {}
        def one(f):
            try: return f['address'], json.loads(get('/disassemble_function', address='0x' + f['address']))
            except Exception as e: return f['address'], {'error': str(e)}
        with concurrent.futures.ThreadPoolExecutor(4) as ex:
            for a, d in ex.map(one, funcs): res[a] = d
        json.dump(res, open(out, 'w'))
    elif what == 'decompile':
        addrs = [a for a in open(sys.argv[3]).read().split()]
        res = json.load(open(out)) if os.path.exists(out) else {}
        todo = [a for a in addrs if a not in res]
        def one(a):
            try:
                t = get('/decompile_function', address=a, timeout=60)
                if t.startswith('{"error"'): return a, None   # Ghidra couldn't decompile it
                return a, t
            except Exception as e: return a, None
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            for a, d in ex.map(one, todo): res[a] = d
        json.dump(res, open(out, 'w'))
main()
