#!/usr/bin/env python3
"""Generate revkit's library signature database from C headers.

Parses system headers with clang (-ast-dump=json), resolves typedefs to
the types they name (as the DWARF ground truth does), and writes one line
per function in Ghidra's notation, which src/infer reads:

    name<TAB>return type<TAB>param type<TAB>...[<TAB>...][<TAB>cbN=ret|param|...]...

A `cbN=` field gives the prototype of a function-pointer parameter N
(0-based): what a function passed there is called as (qsort's comparator
is `cb3=int|void *|void *`); `cbN~=` marks trailing parameters the function
may leave out (main).

Types are a base name plus stars: `int`, `ulong`, `char * *`, `_IO_FILE *`,
`code *` (any function pointer), `void *`. A trailing `...` field marks a
variadic function. Asm labels (glibc's `strtol` -> `__isoc23_strtol`)
add a line for the label name too.

    gen_sigdb.py --profile glibc -o src/infer/data/glibc-lp64.sigs
    gen_sigdb.py --profile mingw -o src/infer/data/win64.sigs

The headers are the host's: glibc's /usr/include for the LP64 ELF targets
and mingw-w64's /usr/x86_64-w64-mingw32/include for Windows. Prototypes
(names and parameter types) are interface facts; no header text is
copied. See docs/infer.md for sources and licenses.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

PROFILES = {
    "glibc": {
        "target": "x86_64-linux-gnu",
        "defines": ["-D_GNU_SOURCE", "-D_LARGEFILE64_SOURCE", "-D_FORTIFY_SOURCE=2", "-O2"],
        "headers": """
            aio.h argz.h arpa/inet.h assert.h complex.h ctype.h dirent.h dlfcn.h envz.h err.h errno.h error.h
            execinfo.h fcntl.h fenv.h fnmatch.h ftw.h getopt.h glob.h grp.h iconv.h ifaddrs.h inttypes.h
            langinfo.h libgen.h libintl.h link.h locale.h malloc.h math.h mcheck.h memory.h mntent.h
            monetary.h netdb.h net/if.h netinet/in.h nl_types.h obstack.h poll.h pthread.h pty.h pwd.h
            regex.h sched.h search.h semaphore.h setjmp.h shadow.h signal.h spawn.h stdio.h stdio_ext.h
            stdlib.h string.h strings.h syslog.h termios.h threads.h time.h uchar.h ucontext.h unistd.h utime.h
            utmp.h wchar.h wctype.h wordexp.h sys/auxv.h sys/epoll.h sys/eventfd.h sys/file.h sys/inotify.h
            sys/ioctl.h sys/ipc.h sys/mman.h sys/msg.h sys/prctl.h sys/random.h sys/resource.h sys/select.h
            sys/sem.h sys/sendfile.h sys/shm.h sys/signalfd.h sys/socket.h sys/stat.h sys/statfs.h
            sys/statvfs.h sys/sysinfo.h sys/time.h sys/timerfd.h sys/times.h sys/types.h sys/uio.h
            sys/un.h sys/utsname.h sys/wait.h sys/xattr.h
        """.split(),
        # Runtime entry points the headers don't declare.
        "extra": [
            # main as C programs define it: int main(int, char **), whose
            # parameters C lets it leave out ("cbN~=": trailing parameters
            # optional; the function's own view decides how many).
            "__libc_start_main\tint\tcode *\tint\tchar * *\tcode *\tcode *\tcode *\tvoid *\tcb0~=int|int|char * *",
            "__stack_chk_fail\tvoid",
            "__cxa_finalize\tvoid\tvoid *",
            "__cxa_atexit\tint\tcode *\tvoid *\tvoid *",
            "__gmon_start__\tvoid",
            "_ITM_deregisterTMCloneTable\tvoid\tvoid *",
            "_ITM_registerTMCloneTable\tvoid\tvoid *\tulong",
            "__assert_fail\tvoid\tchar *\tchar *\tuint\tchar *",
        ],
    },
    "mingw": {
        "target": "x86_64-w64-mingw32",
        "defines": ["-DWIN32_LEAN_AND_MEAN", "-D_CRT_SECURE_NO_WARNINGS"],
        "headers": """
            windows.h assert.h conio.h ctype.h direct.h errno.h fcntl.h float.h io.h locale.h malloc.h math.h
            process.h setjmp.h signal.h stdio.h stdlib.h string.h time.h wchar.h wctype.h sys/stat.h
            sys/timeb.h sys/utime.h
        """.split(),
        "extra": [
            "__getmainargs\tint\tint *\tchar * * *\tchar * * *\tint\tvoid *",
            "__wgetmainargs\tint\tint *\twchar_t * * *\twchar_t * * *\tint\tvoid *",
            "__set_app_type\tvoid\tint",
            "__setusermatherr\tvoid\tcode *",
            "_initterm\tvoid\tcode * *\tcode * *",
            "_amsg_exit\tvoid\tint",
            "__iob_func\t_iobuf *",
            "___mb_cur_max_func\tint",
            "___lc_codepage_func\tuint",
            "__C_specific_handler\tint\tvoid *\tvoid *\tvoid *\tvoid *",
        ],
    },
}

# C spellings -> Ghidra's names (longest first), as protonorm.py.
SPELLINGS = [
    ("long long unsigned int", "ulonglong"), ("unsigned long long int", "ulonglong"),
    ("unsigned long long", "ulonglong"), ("long long int", "longlong"), ("signed long long", "longlong"),
    ("long long", "longlong"), ("long unsigned int", "ulong"), ("unsigned long int", "ulong"),
    ("unsigned long", "ulong"), ("signed long", "long"), ("long int", "long"),
    ("short unsigned int", "ushort"), ("unsigned short int", "ushort"), ("unsigned short", "ushort"),
    ("signed short", "short"), ("short int", "short"), ("unsigned char", "uchar"),
    ("signed char", "char"), ("unsigned int", "uint"), ("signed int", "int"), ("long double", "longdouble"),
    ("unsigned __int128", "uint128"), ("__int128", "int128"), ("unsigned", "uint"), ("signed", "int"),
    ("_Bool", "bool"),
]
DROP = {"const", "volatile", "restrict", "__restrict", "_Atomic", "struct", "union", "enum", "__unaligned",
        "__ptr32", "__ptr64", "__attribute__"}
BASE_OK = {"void", "char", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "longlong",
           "ulonglong", "int128", "uint128", "float", "double", "longdouble", "bool", "code", "wchar_t"}
_TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\*|\(|\)|\[|\]|,|\.\.\.|\d+")


class Resolver:
    def __init__(self, typedefs: dict[str, str], enums: set[str], target_long: str):
        self.typedefs = typedefs
        self.enums = enums
        self.long = target_long

    def callback(self, ctype: str, depth: int = 0) -> str | None:
        """'int (*)(const void *, const void *)' (or a typedef of one) -> 'int|void *|void *'."""
        if depth > 16:
            return None
        s = strip_attributes(ctype).strip()
        for q in ("const ", "volatile "):
            s = s.replace(q, "")
        name = s.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name in self.typedefs:
            return self.callback(self.typedefs[name], depth + 1)
        m = re.match(r"^(.*?)\(\s*\*\s*\)\s*\((.*)\)\s*$", s)
        if not m:
            return None
        ret = self.ghidra(m.group(1))
        if ret is None or "(" in m.group(1):
            return None
        args = split_params(m.group(2))
        if args == ["void"]:
            args = []
        out = [ret]
        for a in args:
            if a.strip() == "...":
                out.append("...")
                continue
            g = self.ghidra(a)
            if g is None or g == "code":
                return None
            out.append(g)
        return "|".join(out)

    def ghidra(self, ctype: str, depth: int = 0) -> str | None:
        """C type spelling -> Ghidra notation, typedefs resolved; None if unsupported."""
        if depth > 32:
            return None
        s = strip_attributes(ctype).strip()
        # Function pointers and anything with a parameter list: code *.
        if "(" in s:
            if re.search(r"\(\s*\*", s) or re.search(r"\(\^", s):
                return "code *"
            return "code"
        # Arrays decay.
        stars_extra = s.count("[")
        s = re.sub(r"\[[^\]]*\]", "", s)
        toks = [t for t in _TOK.findall(s) if t not in DROP]
        stars = toks.count("*") + stars_extra
        words = [t for t in toks if t != "*"]
        base = " ".join(words)
        for c, g in SPELLINGS:
            if base == c:
                base = g
                break
        if base in ("__builtin_va_list", "va_list", "__gnuc_va_list"):
            base, stars = "void", stars + 1
        if base in BASE_OK:
            return base + " *" * stars
        if base in self.enums:
            return "int" + " *" * stars
        if base in self.typedefs:
            target = self.typedefs[base]
            # typedef struct X X: the tag itself.
            if [t for t in _TOK.findall(target) if t not in DROP] == [base]:
                return base + " *" * stars
            inner = self.ghidra(target, depth + 1)
            if inner is None:
                return None
            if inner == "code":
                inner = "code"
            return inner + " *" * stars
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", base):
            # A struct or union tag (struct _IO_FILE -> _IO_FILE).
            return base + " *" * stars
        return None


def clang_ast(profile: dict, headers: list[str]) -> list[dict]:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        for h in headers:
            f.write(f"#include <{h}>\n")
        src = f.name
    try:
        cmd = ["clang", "-target", profile["target"], "-fsyntax-only", "-w", "-Xclang", "-ast-dump=json",
               *profile["defines"], src]
        out = subprocess.run(cmd, check=False, capture_output=True)
        if not out.stdout:
            sys.stderr.write(out.stderr.decode(errors="replace")[-4000:])
            raise SystemExit("clang failed")
        return json.loads(out.stdout).get("inner", [])
    finally:
        os.unlink(src)


def usable_headers(profile: dict) -> list[str]:
    ok = []
    for h in profile["headers"]:
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(f"#include <{h}>\n")
            src = f.name
        r = subprocess.run(["clang", "-target", profile["target"], "-fsyntax-only", "-w", *profile["defines"], src],
                           capture_output=True)
        os.unlink(src)
        if r.returncode == 0:
            ok.append(h)
        else:
            sys.stderr.write(f"skipping <{h}>\n")
    return ok


def split_params(t: str) -> list[str]:
    """Top-level comma split of a parameter list."""
    out, depth, cur = [], 0, ""
    for ch in t:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def strip_attributes(t: str) -> str:
    """Removes __attribute__((...)) groups (calling conventions, ...)."""
    while True:
        i = t.find("__attribute__")
        if i < 0:
            return t
        j = t.find("(", i)
        depth = 0
        for k in range(j, len(t)):
            if t[k] == "(":
                depth += 1
            elif t[k] == ")":
                depth -= 1
                if depth == 0:
                    t = t[:i] + t[k + 1:]
                    break
        else:
            return t[:i]


def split_function_type(t: str) -> tuple[str, str] | None:
    """'int (const char *, ...)' -> ('int', 'const char *, ...')."""
    t = strip_attributes(t).strip()
    if not t.endswith(")"):
        return None
    depth = 0
    for i in range(len(t) - 1, -1, -1):
        c = t[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                return t[:i].strip(), t[i + 1:-1]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=sorted(PROFILES), required=True)
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()
    profile = PROFILES[args.profile]
    headers = usable_headers(profile)
    decls = clang_ast(profile, headers)

    typedefs: dict[str, str] = {}
    enums: set[str] = set()
    funcs: dict[str, dict] = {}
    for d in decls:
        kind = d.get("kind")
        if kind == "TypedefDecl" and "name" in d:
            ty = d.get("type", {})
            typedefs[d["name"]] = ty.get("desugaredQualType", ty.get("qualType", ""))
        elif kind == "EnumDecl" and d.get("name"):
            enums.add(d["name"])
        elif kind == "FunctionDecl" and d.get("name") and not d.get("isImplicit"):
            name = d["name"]
            funcs.setdefault(name, d)
    # typedef enum {...} name: the typedef's type names the enum.
    for n, t in list(typedefs.items()):
        m = re.fullmatch(r"enum\s+(\w+)", t.strip())
        if m:
            enums.add(m.group(1))
        if re.fullmatch(r"enum\s*\(.*\)|enum \(unnamed.*", t.strip()):
            typedefs[n] = "int"
    res = Resolver(typedefs, enums, "long")

    lines: dict[str, str] = {}
    for name, d in sorted(funcs.items()):
        params = [p for p in d.get("inner", []) if p.get("kind") == "ParmVarDecl"]
        ftype = d.get("type", {}).get("qualType", "")
        sp = split_function_type(ftype)
        if sp is None:
            continue
        ret_c = sp[0]
        ret = res.ghidra(ret_c)
        if ret is None or ret == "code":
            continue
        types = []
        callbacks = []
        bad = False
        for i, p in enumerate(params):
            ty = p.get("type", {})
            qual = ty.get("qualType", "")
            g = res.ghidra(qual)
            if g is None or g == "code":
                bad = True
                break
            types.append(g)
            if g == "code *":
                cb = res.callback(ty.get("desugaredQualType", qual)) or res.callback(qual)
                if cb:
                    callbacks.append(f"cb{i}={cb}")
        if bad:
            continue
        fields = [name, ret, *types]
        if d.get("variadic"):
            fields.append("...")
        fields += callbacks
        line = "\t".join(fields)
        lines[name] = line
        for inner in d.get("inner", []):
            if inner.get("kind") == "AsmLabelAttr":
                label = inner.get("label") or ""
                if label and label not in funcs:
                    lines[label] = "\t".join([label, *fields[1:]])
    for e in profile["extra"]:
        lines[e.split("\t")[0]] = e

    with open(args.output, "w") as out:
        out.write(f"# revkit library signatures ({args.profile}, clang -target {profile['target']}), "
                  "generated by tools/rk-sigdb/gen_sigdb.py\n")
        out.write("# name\treturn\tparams...  (Ghidra notation, typedefs resolved; '...' = variadic)\n")
        for name in sorted(lines):
            out.write(lines[name] + "\n")
    print(f"{args.output}: {len(lines)} functions from {len(headers)} headers", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
