#!/usr/bin/env python3
"""Real Lua and LuaJIT bytecode for the container tests (docs/filesystems.md).

Each of Lua 5.1 to 5.5, LuaJIT 2.0 and 2.1 compiles one script and dumps it
with string.dump, as luac would, stripped and not (lupa bundles the
interpreters: pip install lupa into a scratch venv). Writes <out>/<name>.luac
and <out>/index.txt ("name size" lines) and exits 77 when lupa is missing,
which the tests take as a skip.

    python3 -I make_lua_chunks.py <out-dir>
"""
import importlib
import os
import sys

SCRIPT = r"""
local t = {1, 2.5, "three", true, nil}
local function add(a, b) return a + b end
local function sum(xs)
  local s = 0
  for i = 1, #xs do s = s + xs[i] end
  return s
end
return function(n)
  local inner = function(x) return add(x, n) .. "!" end
  return sum({n, 2, 3}) + #t, inner(4), string.format("%d", n)
end
"""

ENGINES = [("lua51", "lua-5.1"), ("lua52", "lua-5.2"), ("lua53", "lua-5.3"), ("lua54", "lua-5.4"),
           ("lua55", "lua-5.5"), ("luajit20", "luajit-2.0"), ("luajit21", "luajit-2.1")]


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    made = []
    for module, name in ENGINES:
        try:
            lua = importlib.import_module("lupa." + module).LuaRuntime(encoding=None)
        except ImportError:
            continue
        load = lua.eval("function(src) return (loadstring or load)(src) end")
        dump = lua.eval("function(f, strip) return string.dump(f, strip) end")
        f = load(SCRIPT.encode())
        for strip, suffix in ((False, ""), (True, "-stripped")):
            data = dump(f, strip)
            path = os.path.join(out, name + suffix + ".luac")
            with open(path, "wb") as fh:
                fh.write(data)
            made.append((name + suffix, len(data)))
    if not made:
        print("lupa is not installed", file=sys.stderr)
        sys.exit(77)
    with open(os.path.join(out, "index.txt"), "w") as fh:
        for name, size in made:
            fh.write(f"{name} {size}\n")


if __name__ == "__main__":
    main()
