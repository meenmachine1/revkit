# Lays out one CPython 3.12 code object for the PyVM SLEIGH experiment:
# code at 0, small-int constants at 0x400, a name table at 0x500 pointing
# at NUL-terminated names from 0x600.
import struct, sys
def add(a, b):
    c = a + b
    if c > 10:
        c -= 3
    return c * 2
def g(xs):
    s = 0
    for x in xs:
        s += len(x)
    return s
for fn in (add, g):
    co = fn.__code__
    img = bytearray(0x700)
    img[:len(co.co_code)] = co.co_code
    for i, k in enumerate(co.co_consts):
        struct.pack_into('<q', img, 0x400 + 8 * i, k if isinstance(k, int) else 0)
    p = 0x600
    for i, n in enumerate(co.co_names):
        struct.pack_into('<I', img, 0x500 + 4 * i, p)
        img[p:p + len(n)] = n.encode(); p += len(n) + 1
    open(f'{sys.argv[1]}/py_{fn.__name__}.img', 'wb').write(img)
