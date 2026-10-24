#!/usr/bin/env python3
"""Writes a small Android package for revkit's tests (docs/android.md).

    make_apk.py OUT.apk [--cc CC:ABI ...] [--flutter] [--utf16] [--plain]
                        [--unpacked DIR]

The APK holds:

- AndroidManifest.xml as binary XML (AXML): the string pool (UTF-8, or
  UTF-16 with --utf16), the resource map, the android namespace, typed
  attributes (ints, booleans, strings, references into resources.arsc);
  an application class, every kind of component, exported flags given and
  implied, intent filters with data, permissions;
- resources.arsc: package 0x7f com.example.droid with string (default, fr,
  and a sparse en-rGB), bool (compact entries), color, dimen, integer, xml
  (a file), mipmap (a file), style (a bag) and attr types. --plain leaves
  out the sparse and compact encodings (for tools that don't read them);
- res/xml/network_security_config.xml and res/layout/main.xml (AXML);
- classes.dex: com.example.droid.MainActivity, NativeLib (native methods:
  overloads, an underscore, one registered at run time) and NativeLib$Inner;
- lib/<abi>/libnative.so and libhelper.so for each --cc (compiled here
  from native.c and helper.c beside this script), and with --flutter
  lib/<abi>/libapp.so and libflutter.so (flutter_app.c, flutter_engine.c).

Everything is written from the formats' descriptions (AOSP's
ResourceTypes.h, the Dalvik executable format); nothing is copied from a
real app.
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ANDROID_NS = "http://schemas.android.com/apk/res/android"
PKG = "com.example.droid"

# android.R.attr ids of the attributes used.
ATTR = {
    "theme": 0x01010000, "label": 0x01010001, "icon": 0x01010002, "name": 0x01010003,
    "permission": 0x01010006, "protectionLevel": 0x01010009, "debuggable": 0x0101000f,
    "exported": 0x01010010, "process": 0x01010011, "authorities": 0x01010018,
    "grantUriPermissions": 0x0101001b, "priority": 0x0101001c, "value": 0x01010024,
    "mimeType": 0x01010026, "scheme": 0x01010027, "host": 0x01010028, "port": 0x01010029,
    "path": 0x0101002a, "pathPrefix": 0x0101002b, "minSdkVersion": 0x0101020c,
    "versionCode": 0x0101021b, "versionName": 0x0101021c, "targetSdkVersion": 0x01010270,
    "allowBackup": 0x01010280, "usesCleartextTraffic": 0x010104ec,
    "networkSecurityConfig": 0x01010527, "compileSdkVersion": 0x01010572,
    "compileSdkVersionCodename": 0x01010573, "targetActivity": 0x01010202,
    "maxSdkVersion": 0x01010271, "extractNativeLibs": 0x010104ea,
    "layout_width": 0x010100f4, "layout_height": 0x010100f5, "text": 0x0101014f,
    "textColor": 0x01010098, "textSize": 0x01010095, "id": 0x010100d0,
}

T_NULL, T_REF, T_STRING, T_DIM, T_INT, T_HEX, T_BOOL, T_ARGB8 = 0x00, 0x01, 0x03, 0x05, 0x10, 0x11, 0x12, 0x1c


def align(b, n=4):
    return b + b"\0" * (-len(b) % n)


# --- string pools ---


def string_pool(strings, utf8=True):
    data = b""
    offsets = []
    for s in strings:
        offsets.append(len(data))
        if utf8:
            raw = s.encode("utf-8")
            n16 = len(s.encode("utf-16-le")) // 2

            def ln(n):
                return bytes([0x80 | (n >> 8), n & 0xff]) if n > 0x7f else bytes([n])

            data += ln(n16) + ln(len(raw)) + raw + b"\0"
        else:
            raw = s.encode("utf-16-le")
            n = len(raw) // 2
            data += (struct.pack("<HH", 0x8000 | (n >> 16), n & 0xffff) if n > 0x7fff else struct.pack("<H", n)) + raw + b"\0\0"
    data = align(data)
    header = 28
    start = header + 4 * len(strings)
    body = b"".join(struct.pack("<I", o) for o in offsets) + data
    size = header + len(body)
    return struct.pack("<HHIIIIII", 0x0001, header, size, len(strings), 0, 0x100 if utf8 else 0, start, 0) + body


# --- binary XML ---


class Xml:
    """Elements as (name, [(ns, name, type, data or string)], children)."""

    def __init__(self, root, utf8=True):
        self.root = root
        self.utf8 = utf8

    def build(self):
        attr_names = []  # names with resource ids, in id order
        others = []

        def collect(e):
            name, attrs, children = e
            for ns, an, t, v in attrs:
                if ns == ANDROID_NS and an in ATTR:
                    if an not in attr_names:
                        attr_names.append(an)
                elif an not in others:
                    others.append(an)
                if t == T_STRING and v not in others:
                    others.append(v)
            if name not in others:
                others.append(name)
            for c in children:
                collect(c)

        collect(self.root)
        attr_names.sort(key=lambda a: ATTR[a])
        for s in ("android", ANDROID_NS):
            if s not in others:
                others.append(s)
        others = [s for s in others if s not in attr_names]
        strings = attr_names + others
        index = {s: i for i, s in enumerate(strings)}
        chunks = [string_pool(strings, self.utf8)]
        resmap = b"".join(struct.pack("<I", ATTR[a]) for a in attr_names)
        chunks.append(struct.pack("<HHI", 0x0180, 8, 8 + len(resmap)) + resmap)
        node = lambda t, size, line: struct.pack("<HHIII", t, 16, size, line, 0xffffffff)
        chunks.append(node(0x0100, 24, 1) + struct.pack("<II", index["android"], index[ANDROID_NS]))
        line = [2]

        def emit(e):
            name, attrs, children = e
            sorted_attrs = sorted(attrs, key=lambda a: ATTR.get(a[1], 0xffffffff) if a[0] == ANDROID_NS else 0x7fffffff)
            body = b""
            for ns, an, t, v in sorted_attrs:
                nsi = index[ANDROID_NS] if ns == ANDROID_NS else 0xffffffff
                if t == T_STRING:
                    raw, data = index[v], index[v]
                else:
                    raw, data = 0xffffffff, v & 0xffffffff
                body += struct.pack("<IIIHBBI", nsi, index[an], raw, 8, 0, t, data)
            ext = struct.pack("<IIHHHHHH", 0xffffffff, index[name], 20, 20, len(attrs), 0, 0, 0)
            chunks.append(node(0x0102, 16 + len(ext) + len(body), line[0]) + ext + body)
            line[0] += 1
            for c in children:
                emit(c)
            chunks.append(node(0x0103, 24, line[0]) + struct.pack("<II", 0xffffffff, index[name]))
            line[0] += 1

        emit(self.root)
        chunks.append(node(0x0101, 24, line[0]) + struct.pack("<II", index["android"], index[ANDROID_NS]))
        body = b"".join(chunks)
        return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def a(name, t, v):
    return (ANDROID_NS, name, t, v)


def plain(name, t, v):
    return (None, name, t, v)


# --- resources.arsc ---

# (type name, entries, configs): entries are names; values per config are
# (type, data) or ("str", text) or ("bag", parent, [(attr, (type, data))]).
R = {}


def build_resources(plain_encoding):
    types = [
        ("attr", ["accent"]),
        ("string", ["app_name", "hello", "net_host", "unused_label"]),
        ("bool", ["cleartext", "is_tablet"]),
        ("color", ["primary"]),
        ("dimen", ["padding", "text_size"]),
        ("integer", ["max_items"]),
        ("xml", ["network_security_config"]),
        ("mipmap", ["ic_launcher"]),
        ("style", ["AppTheme"]),
        ("layout", ["main"]),
    ]
    ids = {}
    for ti, (tname, entries) in enumerate(types):
        for ei, e in enumerate(entries):
            ids[(tname, e)] = 0x7f000000 | ((ti + 1) << 16) | ei
    R.update(ids)
    values = {
        ("attr", "accent"): {"": ("bag", 0, [(0x01000000, (T_INT, 0x01))])},  # ^type: reference
        ("string", "app_name"): {"": ("str", "Droid Test"), "fr": ("str", "Droïde d'essai"), "en-rGB": ("str", "Droid Test (UK)")},
        ("string", "hello"): {"": ("str", "Hello, world!"), "fr": ("str", "Bonjour, le monde !")},
        ("string", "net_host"): {"": ("str", "api.example.com")},
        ("string", "unused_label"): {"": ("str", "日本語 \U0001F600")},
        ("bool", "cleartext"): {"": (T_BOOL, 0xffffffff)},
        ("bool", "is_tablet"): {"": (T_BOOL, 0), "sw600dp": (T_BOOL, 0xffffffff)},
        ("color", "primary"): {"": (T_ARGB8, 0xff336699), "night": (T_ARGB8, 0xff112233)},
        ("dimen", "padding"): {"": (T_DIM, (16 << 8) | 1)},     # 16dip
        ("dimen", "text_size"): {"": (T_DIM, (14 << 8) | 2)},   # 14sp
        ("integer", "max_items"): {"": (T_INT, 42)},
        ("xml", "network_security_config"): {"": ("str", "res/xml/network_security_config.xml")},
        ("mipmap", "ic_launcher"): {"xxhdpi-v4": ("str", "res/mipmap-xxhdpi-v4/ic_launcher.png")},
        ("style", "AppTheme"): {"": ("bag", 0x01030005, [(ATTR["textColor"], (T_REF, 0)), (ATTR["textSize"], (T_REF, 0))])},
        ("layout", "main"): {"": ("str", "res/layout/main.xml")},
    }
    # Bag items referring to the table's own ids.
    values[("style", "AppTheme")][""] = ("bag", 0x01030005, [(ATTR["textColor"], (T_REF, ids[("color", "primary")])),
                                                            (ATTR["textSize"], (T_REF, ids[("dimen", "text_size")]))])
    gstrings = []

    def gs(s):
        if s not in gstrings:
            gstrings.append(s)
        return gstrings.index(s)

    for k in sorted(values):
        for cfg in values[k]:
            v = values[k][cfg]
            if v[0] == "str":
                gs(v[1])
    type_names = [t for t, _ in types]
    keys = []
    for _, entries in types:
        for e in entries:
            if e not in keys:
                keys.append(e)

    def config(q):
        c = bytearray(64)
        struct.pack_into("<I", c, 0, 64)
        for part in q.split("-") if q else []:
            if part == "fr":
                c[8:10] = b"fr"
            elif part == "en":
                c[8:10] = b"en"
            elif part == "rGB":
                c[10:12] = b"GB"
            elif part == "night":
                c[29] = 0x20
            elif part == "sw600dp":
                struct.pack_into("<H", c, 30, 600)
            elif part == "xxhdpi":
                struct.pack_into("<H", c, 14, 480)
            elif part.startswith("v"):
                struct.pack_into("<H", c, 24, int(part[1:]))
        return bytes(c)

    pkg_chunks = []
    for ti, (tname, entries) in enumerate(types):
        tid = ti + 1
        spec = struct.pack("<HHIBBHI", 0x0202, 16, 16 + 4 * len(entries), tid, 0, 0, len(entries)) + b"\0\0\0\0" * len(entries)
        pkg_chunks.append(spec)
        cfgs = []
        for e in entries:
            for q in values.get((tname, e), {}):
                if q not in cfgs:
                    cfgs.append(q)
        for q in cfgs:
            sparse = (not plain_encoding) and q == "en-rGB"
            compact = (not plain_encoding) and tname == "bool"
            ents = []
            for ei, e in enumerate(entries):
                v = values.get((tname, e), {}).get(q)
                if v is None:
                    ents.append(None)
                    continue
                key = keys.index(e)
                if v[0] == "bag":
                    _, parent, items = v
                    body = struct.pack("<HHIII", 16, 1, key, parent, len(items))
                    for an, (t, d) in items:
                        body += struct.pack("<IHBBI", an, 8, 0, t, d)
                elif compact:
                    t, d = v
                    body = struct.pack("<HHI", key, 0x0008 | (t << 8), d)
                else:
                    t, d = (T_STRING, gs(v[1])) if v[0] == "str" else v
                    body = struct.pack("<HHI", 8, 0, key) + struct.pack("<HBBI", 8, 0, t, d)
                ents.append(body)
            data = b""
            if sparse:
                offs = b""
                n = 0
                for ei, body in enumerate(ents):
                    if body is None:
                        continue
                    offs += struct.pack("<HH", ei, len(data) // 4)
                    data += body
                    n += 1
                count, flags = n, 0x01
            else:
                offs = b""
                for body in ents:
                    if body is None:
                        offs += struct.pack("<I", 0xffffffff)
                    else:
                        offs += struct.pack("<I", len(data))
                        data += body
                count, flags = len(ents), 0
            hsize = 20 + 64
            start = hsize + len(offs)
            chunk = struct.pack("<HHIBBHII", 0x0201, hsize, start + len(data), tid, flags, 0, count, start) + config(q) + offs + data
            pkg_chunks.append(chunk)
    tpool = string_pool(type_names, False)
    kpool = string_pool(keys, True)
    name = PKG.encode("utf-16-le").ljust(256, b"\0")
    hsize = 288
    header_rest = struct.pack("<I", 0x7f) + name + struct.pack("<IIIII", hsize, len(type_names), hsize + len(tpool), len(keys), 0)
    body = tpool + kpool + b"".join(pkg_chunks)
    pkg = struct.pack("<HHI", 0x0200, hsize, hsize + len(body)) + header_rest + body
    gpool = string_pool(gstrings, True)
    table_body = gpool + pkg
    return struct.pack("<HHII", 0x0002, 12, 12 + len(table_body), 1) + table_body


# --- the XML files ---


def manifest(utf8):
    def intent(actions, categories=(), data=()):
        kids = [("action", [a("name", T_STRING, x)], []) for x in actions]
        kids += [("category", [a("name", T_STRING, x)], []) for x in categories]
        kids += [("data", [a(k, T_STRING, v) for k, v in d], []) for d in data]
        return ("intent-filter", [], kids)

    app = ("application", [
        a("name", T_STRING, ".DroidApp"),
        a("label", T_REF, R[("string", "app_name")]),
        a("icon", T_REF, R[("mipmap", "ic_launcher")]),
        a("theme", T_REF, R[("style", "AppTheme")]),
        a("debuggable", T_BOOL, 0xffffffff),
        a("allowBackup", T_BOOL, 0),
        a("usesCleartextTraffic", T_REF, R[("bool", "cleartext")]),
        a("networkSecurityConfig", T_REF, R[("xml", "network_security_config")]),
        a("extractNativeLibs", T_BOOL, 0xffffffff),
    ], [
        ("activity", [a("name", T_STRING, ".MainActivity"), a("exported", T_BOOL, 0xffffffff)],
         [intent(["android.intent.action.MAIN"], ["android.intent.category.LAUNCHER"])]),
        ("activity", [a("name", T_STRING, "com.example.droid.DeepLinkActivity")],
         [intent(["android.intent.action.VIEW"], ["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"],
                 [[("scheme", "https"), ("host", "example.com"), ("pathPrefix", "/open")]])]),
        ("activity", [a("name", T_STRING, ".SettingsActivity"), a("exported", T_BOOL, 0)], []),
        ("activity-alias", [a("name", T_STRING, ".Launcher2"), a("targetActivity", T_STRING, ".MainActivity")], []),
        ("service", [a("name", T_STRING, ".SyncService"), a("exported", T_BOOL, 0xffffffff),
                     a("permission", T_STRING, "com.example.droid.permission.SYNC"), a("process", T_STRING, ":sync")], []),
        ("receiver", [a("name", T_STRING, ".BootReceiver")],
         [("intent-filter", [a("priority", T_INT, 999)], [("action", [a("name", T_STRING, "android.intent.action.BOOT_COMPLETED")], [])])]),
        ("provider", [a("name", T_STRING, ".DataProvider"), a("authorities", T_STRING, "com.example.droid.data"),
                      a("exported", T_BOOL, 0), a("grantUriPermissions", T_BOOL, 0xffffffff)], []),
        ("meta-data", [a("name", T_STRING, "io.example.API_KEY"), a("value", T_STRING, "k-123")], []),
    ])
    root = ("manifest", [
        a("versionCode", T_INT, 7),
        a("versionName", T_STRING, "1.2.3"),
        a("compileSdkVersion", T_INT, 34),
        a("compileSdkVersionCodename", T_STRING, "14"),
        plain("package", T_STRING, PKG),
        plain("platformBuildVersionCode", T_INT, 34),
        plain("platformBuildVersionName", T_STRING, "14"),
    ], [
        ("uses-sdk", [a("minSdkVersion", T_INT, 24), a("targetSdkVersion", T_INT, 34)], []),
        ("uses-permission", [a("name", T_STRING, "android.permission.INTERNET")], []),
        ("uses-permission", [a("name", T_STRING, "android.permission.READ_EXTERNAL_STORAGE"), a("maxSdkVersion", T_INT, 28)], []),
        ("permission", [a("name", T_STRING, "com.example.droid.permission.SYNC"), a("protectionLevel", T_HEX, 2)], []),
        ("uses-feature", [a("name", T_STRING, "android.hardware.camera")], []),
        app,
    ])
    return Xml(root, utf8).build()


def network_security_config(utf8):
    root = ("network-security-config", [], [
        ("domain-config", [plain("cleartextTrafficPermitted", T_BOOL, 0xffffffff)],
         [("domain", [plain("includeSubdomains", T_BOOL, 0xffffffff)], [])]),
    ])
    # The domain's text isn't modelled by Xml; the config's shape is enough.
    return Xml(root, utf8).build()


def layout(utf8):
    root = ("LinearLayout", [a("layout_width", T_INT, -1), a("layout_height", T_INT, -1)], [
        ("TextView", [a("id", T_REF, 0x7f0b0001), a("text", T_REF, R[("string", "hello")]),
                      a("textColor", T_REF, R[("color", "primary")]), a("textSize", T_REF, R[("dimen", "text_size")]),
                      a("layout_width", T_DIM, (120 << 8) | 1), a("layout_height", T_INT, -2)], []),
    ])
    return Xml(root, utf8).build()


# --- classes.dex ---


def uleb(n):
    out = b""
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def dex():
    # (class, super, [(name, params, return, access)])
    classes = [
        ("Lcom/example/droid/MainActivity;", "Landroid/app/Activity;", []),
        ("Lcom/example/droid/NativeLib;", "Ljava/lang/Object;", [
            ("hello", ["Ljava/lang/String;"], "Ljava/lang/String;", 0x0109),
            ("add", ["I", "I"], "I", 0x0101),
            ("add", ["J", "J"], "J", 0x0101),
            ("do_it", [], "V", 0x0109),
            ("registered", [], "V", 0x0109),
        ]),
        ("Lcom/example/droid/NativeLib$Inner;", "Ljava/lang/Object;", [("ping", [], "I", 0x0109)]),
    ]
    strings = set()
    types = set()
    protos = set()

    def shorty(params, ret):
        s = lambda t: "L" if t[0] in "L[" else t
        return s(ret) + "".join(s(p) for p in params)

    for c, sup, methods in classes:
        types.update([c, sup])
        for n, params, ret, _ in methods:
            strings.add(n)
            types.update(params + [ret])
            protos.add((shorty(params, ret), ret, tuple(params)))
    for _, _, params in protos:
        pass
    strings.update(types)
    strings.update(p[0] for p in protos)
    strings = sorted(strings)
    sidx = {s: i for i, s in enumerate(strings)}
    types = sorted(types, key=lambda t: sidx[t])
    tidx = {t: i for i, t in enumerate(types)}
    protos = sorted(protos, key=lambda p: (tidx[p[1]], [tidx[x] for x in p[2]]))
    pidx = {p: i for i, p in enumerate(protos)}
    methods = []
    for c, _, ms in classes:
        for n, params, ret, acc in ms:
            methods.append((tidx[c], pidx[(shorty(params, ret), ret, tuple(params))], sidx[n], c, acc))
    methods.sort(key=lambda m: (m[0], m[2], m[1]))
    midx = {(m[0], m[2], m[1]): i for i, m in enumerate(methods)}

    header = 0x70
    off = header
    string_ids_off = off
    off += 4 * len(strings)
    type_ids_off = off
    off += 4 * len(types)
    proto_ids_off = off
    off += 12 * len(protos)
    method_ids_off = off
    off += 8 * len(methods)
    class_defs_off = off
    off += 32 * len(classes)
    data_off = off
    data = b""
    # type lists
    tl_off = {}
    for p in protos:
        if p[2] and p[2] not in tl_off:
            data = align(data)
            tl_off[p[2]] = data_off + len(data)
            data += struct.pack("<I", len(p[2])) + b"".join(struct.pack("<H", tidx[x]) for x in p[2])
    data = align(data)
    tl_count = len(tl_off)
    tl_start = min(tl_off.values()) if tl_off else 0
    # class data
    cd_off = {}
    cd_start = data_off + len(data)
    for c, _, ms in classes:
        if not ms:
            continue
        mid = lambda n, p, r: midx[(tidx[c], sidx[n], pidx[(shorty(p, r), r, tuple(p))])]
        direct = sorted((mid(n, p, r), acc) for n, p, r, acc in ms if acc & 0x8)
        virtual = sorted((mid(n, p, r), acc) for n, p, r, acc in ms if not acc & 0x8)
        cd_off[c] = data_off + len(data)
        item = uleb(0) + uleb(0) + uleb(len(direct)) + uleb(len(virtual))
        for lst in (direct, virtual):
            prev = 0
            for mi, acc in lst:
                item += uleb(mi - prev) + uleb(acc) + uleb(0)
                prev = mi
        data += item
    cd_count = len(cd_off)
    # string data
    sd_start = data_off + len(data)
    sd_off = []
    for s in strings:
        sd_off.append(data_off + len(data))
        data += uleb(len(s.encode("utf-16-le")) // 2) + s.encode("utf-8") + b"\0"
    data = align(data)
    map_off = data_off + len(data)
    items = [(0x0000, 1, 0), (0x0001, len(strings), string_ids_off), (0x0002, len(types), type_ids_off),
             (0x0003, len(protos), proto_ids_off), (0x0005, len(methods), method_ids_off),
             (0x0006, len(classes), class_defs_off)]
    if tl_count:
        items.append((0x1001, tl_count, tl_start))
    if cd_count:
        items.append((0x2000, cd_count, cd_start))
    items += [(0x2002, len(strings), sd_start), (0x1000, 1, map_off)]
    items.sort(key=lambda x: x[2])
    data += struct.pack("<I", len(items)) + b"".join(struct.pack("<HHII", t, 0, n, o) for t, n, o in items)
    body = b""
    body += b"".join(struct.pack("<I", o) for o in sd_off)
    body += b"".join(struct.pack("<I", sidx[t]) for t in types)
    for sh, ret, params in protos:
        body += struct.pack("<III", sidx[sh], tidx[ret], tl_off.get(params, 0) if params else 0)
    for ci, pi, ni, _, _ in methods:
        body += struct.pack("<HHI", ci, pi, ni)
    for c, sup, ms in classes:
        body += struct.pack("<IIIIIIII", tidx[c], 0x0001, tidx[sup], 0, 0xffffffff, 0, cd_off.get(c, 0), 0)
    file_size = header + len(body) + len(data)
    h = bytearray(header)
    h[0:8] = b"dex\n035\0"
    struct.pack_into("<" + "I" * 20, h, 0x20, file_size, header, 0x12345678, 0, 0, map_off,
                     len(strings), string_ids_off, len(types), type_ids_off, len(protos), proto_ids_off,
                     0, 0, len(methods), method_ids_off, len(classes), class_defs_off, len(data), data_off)
    out = bytearray(bytes(h) + body + data)
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    struct.pack_into("<I", out, 8, zlib.adler32(bytes(out[12:])) & 0xffffffff)
    return bytes(out)


# --- the libraries ---


def compile_libs(cc, flutter, tmp):
    out = {}
    def build(name, src, extra=()):
        path = os.path.join(tmp, os.path.basename(cc) + "-" + name)
        subprocess.run([cc, "-shared", "-fPIC", "-O1", "-Wl,--build-id", "-Wl,-soname," + name, "-o", path,
                        os.path.join(HERE, src), *extra], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        out[name] = path
        return path
    helper = build("libhelper.so", "helper.c")
    build("libnative.so", "native.c", ["-L" + os.path.dirname(helper), "-l:" + os.path.basename(helper)])
    if flutter:
        build("libapp.so", "flutter_app.c")
        build("libflutter.so", "flutter_engine.c")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--cc", action="append", default=[], help="COMPILER:ABI")
    ap.add_argument("--flutter", action="store_true")
    ap.add_argument("--utf16", action="store_true")
    ap.add_argument("--plain", action="store_true")
    ap.add_argument("--unpacked")
    args = ap.parse_args()
    utf8 = not args.utf16
    files = {}
    files["resources.arsc"] = build_resources(args.plain)
    files["AndroidManifest.xml"] = manifest(utf8)
    files["classes.dex"] = dex()
    files["res/xml/network_security_config.xml"] = network_security_config(utf8)
    files["res/layout/main.xml"] = layout(utf8)
    files["res/mipmap-xxhdpi-v4/ic_launcher.png"] = b"\x89PNG\r\n\x1a\n" + b"\0" * 24
    with tempfile.TemporaryDirectory() as tmp:
        for spec in args.cc:
            cc, abi = spec.rsplit(":", 1)
            libs = compile_libs(cc, args.flutter, tmp)
            for name, path in libs.items():
                files[f"lib/{abi}/{name}"] = open(path, "rb").read()
        order = ["AndroidManifest.xml", "classes.dex", "resources.arsc"]
        names = order + sorted(n for n in files if n not in order)
        with zipfile.ZipFile(args.out, "w") as z:
            for n in names:
                stored = n.endswith(".so") or n == "resources.arsc" or n.endswith(".png")
                z.writestr(zipfile.ZipInfo(n, date_time=(2026, 1, 1, 0, 0, 0)), files[n],
                           compress_type=zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED)
        if args.unpacked:
            for n, b in files.items():
                p = os.path.join(args.unpacked, n)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "wb").write(b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
