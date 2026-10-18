# Hand-assembled Lua 5.4 functions for the LuaVM SLEIGH experiment:
# code at 0, K[] (8-byte integers or string addresses) at 0x400, strings at 0x600.
import struct, sys
def abc(op, a, b=0, c=0, k=0): return op | a << 7 | k << 15 | b << 16 | c << 24
def asbx(op, a, v): return op | a << 7 | (v + 65535) << 15
def abx(op, a, v): return op | a << 7 | v << 15
def sj(op, v): return op | (v + 0xffffff) << 7
funcs = {
  # function f(a, b) local c = a + b; if c > 10 then c = c - 3 end; return c * 2 end
  'f': ([abc(34, 2, 0, 1), abc(46, 0, 1, 6), abc(64, 2, 10 + 127, 0), sj(56, 2),
         abc(21, 2, 2, -3 + 127), abc(47, 2, 3 + 127, 7), abc(24, 3, 2, 0), abc(48, 3, 0, 8),
         abc(72, 3), abc(71, 0)], [2]),
  # function g(n) local s = 0; for i = 1, n do s = s + i end; return s end
  'g': ([asbx(1, 1, 0), asbx(1, 2, 1), abc(0, 3, 0), asbx(1, 4, 1), abx(74, 2, 2),
         abc(34, 1, 1, 5), abc(46, 1, 5, 6), abx(73, 2, 3), abc(72, 1), abc(71, 0)], []),
  # function h(x) return tostring(x) end
  'h': ([abc(11, 1, 0, 0), abc(0, 2, 0), abc(68, 1, 2, 2), abc(72, 1), abc(71, 0)], ['tostring']),
}
for name, (code, ks) in funcs.items():
    img = bytearray(0x700)
    for i, w in enumerate(code): struct.pack_into('<I', img, 4 * i, w)
    p = 0x600
    for i, kv in enumerate(ks):
        if isinstance(kv, str):
            struct.pack_into('<q', img, 0x400 + 8 * i, p); img[p:p + len(kv)] = kv.encode(); p += len(kv) + 1
        else:
            struct.pack_into('<q', img, 0x400 + 8 * i, kv)
    open(f'{sys.argv[1]}/lua_{name}.img', 'wb').write(img)
