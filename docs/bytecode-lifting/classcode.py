import struct, sys
d = open(sys.argv[1], 'rb').read()
p = 8
n = struct.unpack_from('>H', d, p)[0]; p += 2
cp = [None] * n
i = 1
while i < n:
    t = d[p]; p += 1
    if t == 1:
        l = struct.unpack_from('>H', d, p)[0]; cp[i] = d[p+2:p+2+l].decode(); p += 2 + l
    elif t in (3, 4): p += 4
    elif t in (5, 6): p += 8; i += 1
    elif t in (7, 8, 16, 19, 20): p += 2
    elif t in (9, 10, 11, 12, 17, 18): p += 4
    elif t == 15: p += 3
    i += 1
p += 6
ni = struct.unpack_from('>H', d, p)[0]; p += 2 + 2 * ni
def skip_members(p, show):
    c = struct.unpack_from('>H', d, p)[0]; p += 2
    for _ in range(c):
        acc, nm, ds, ac = struct.unpack_from('>HHHH', d, p); p += 8
        for _ in range(ac):
            an, al = struct.unpack_from('>HI', d, p)
            if show and cp[an] == 'Code':
                ms, ml, cl = struct.unpack_from('>HHI', d, p + 6)
                print(f"{cp[nm]}{cp[ds]} acc={acc:#x} max_stack={ms} max_locals={ml} code_off={p+14:#x} code_len={cl}")
            p += 6 + al
    return p
p = skip_members(p, False)
skip_members(p, True)
