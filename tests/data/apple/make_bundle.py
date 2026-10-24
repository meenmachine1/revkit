#!/usr/bin/env python3
"""Lays out the Apple application fixtures around build.sh's Mach-O files.

    make_bundle.py OUTDIR [--plists-only]   (OUTDIR/bin holds build.sh's output)

Everything is written here from the formats' public descriptions, with
the standard library only; no Apple tool, SDK or binary is used, and every
hash, certificate and signature is fake (nothing in revkit verifies them):

  Demo.app/            an iOS app (shallow layout)
    Demo               the main executable, its lld signature replaced by
                       one with a CodeDirectory (and an alternate one),
                       requirements, XML and DER entitlements and a CMS
                       blob holding two made-up certificates
    Info.plist         binary (plistlib's bplist00)
    embedded.mobileprovision   CMS signed data around an XML plist
    _CodeSignature/CodeResources
    Base.lproj/Main.storyboardc/   a compiled storyboard: Info.plist and
                       two NIBArchive nibs (the view one as a nib directory)
    SettingsController.nib     a standalone NIBArchive nib
    Frameworks/Greeter.framework/{Greeter, Info.plist}
    PlugIns/Share.appex/{Share, Info.plist}
  Demo.ipa             Payload/Demo.app as a zip
  MacDemo.app/Contents/  a macOS app: Info.plist (XML), MacOS/MacDemo,
                       Resources/MainMenu.nib (an NSKeyedArchiver nib),
                       Frameworks/Greeter.framework (versioned, with links)
  plists/              single plists and nibs for the parsers' tests (all
                       that --plists-only writes: no Mach-O needed)
"""

import hashlib
import os
import plistlib
import shutil
import struct
import sys
import zipfile

# ---- DER ---------------------------------------------------------------------


def der(tag, content):
    n = len(content)
    if n < 0x80:
        head = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + head + content


def seq(*items):
    return der(0x30, b"".join(items))


def set_(*items):
    return der(0x31, b"".join(items))


def ctx(n, content):
    return der(0xA0 | n, content)


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, out)


def integer(n):
    length = max(1, (n.bit_length() + 8) // 8)
    return der(0x02, n.to_bytes(length, "big", signed=True))


def utf8(s):
    return der(0x0C, s.encode())


def null():
    return der(0x05, b"")


def name(pairs):
    return seq(*[set_(seq(oid(o), utf8(v))) for o, v in pairs])


CN, OU, O, C = "2.5.4.3", "2.5.4.11", "2.5.4.10", "2.5.4.6"
SHA256_RSA = "1.2.840.113549.1.1.11"


def certificate(subject, issuer, serial):
    """A certificate's shape with a made-up key and signature."""
    tbs = seq(
        ctx(0, integer(2)),
        integer(serial),
        seq(oid(SHA256_RSA), null()),
        name(issuer),
        seq(der(0x17, b"260101000000Z"), der(0x17, b"270101000000Z")),
        name(subject),
        seq(seq(oid("1.2.840.113549.1.1.1"), null()), der(0x03, b"\x00" + seq(integer(65537)))),
    )
    return seq(tbs, seq(oid(SHA256_RSA), null()), der(0x03, b"\x00" + bytes(16)))


LEAF = [(CN, "Apple Development: Jane Doe (ABCDE12345)"), (OU, "ABCDE12345"), (O, "Jane Doe"), (C, "US")]
WWDR = [(CN, "Apple Worldwide Developer Relations Certification Authority"), (OU, "G3"), (O, "Apple Inc."), (C, "US")]
ROOT = [(CN, "Apple Root CA"), (O, "Apple Inc."), (C, "US")]


def signed_data(content, certs):
    """CMS ContentInfo of SignedData (RFC 5652); content None: detached."""
    encap = [oid("1.2.840.113549.1.7.1")]
    if content is not None:
        encap.append(ctx(0, der(0x04, content)))
    signer = seq(
        integer(1),
        seq(name(WWDR), integer(1)),
        seq(oid("2.16.840.1.101.3.4.2.1")),
        seq(oid("1.2.840.113549.1.1.1"), null()),
        der(0x04, bytes(32)),
    )
    sd = seq(
        integer(1),
        set_(seq(oid("2.16.840.1.101.3.4.2.1"))),
        seq(*encap),
        der(0xA0, b"".join(certs)),
        set_(signer),
    )
    return seq(oid("1.2.840.113549.1.7.2"), ctx(0, sd))


def der_plist(v):
    """Apple's DER entitlements encoding of a plist value."""
    if isinstance(v, bool):
        return der(0x01, b"\xff" if v else b"\x00")
    if isinstance(v, int):
        return integer(v)
    if isinstance(v, str):
        return utf8(v)
    if isinstance(v, list):
        return seq(*[der_plist(x) for x in v])
    if isinstance(v, dict):
        return der(0xB0, b"".join(seq(utf8(k), der_plist(v[k])) for k in sorted(v)))
    raise TypeError(v)


# ---- code signatures -----------------------------------------------------------

BE32 = struct.Struct(">I")


def blob(magic, payload):
    return BE32.pack(magic) + BE32.pack(8 + len(payload)) + payload


def req_data(b):
    if isinstance(b, str):
        b = b.encode()
    return BE32.pack(len(b)) + b + bytes((-len(b)) % 4)


def op(n):
    return BE32.pack(n)


DESIGNATED = (
    "identifier \"com.example.demo\" and anchor apple generic and "
    "certificate leaf[subject.CN] = \"Apple Development: Jane Doe (ABCDE12345)\" and "
    "certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"
)


def requirements():
    ident = op(2) + req_data("com.example.demo")
    generic = op(15)
    leaf_cn = op(11) + op(0) + req_data("subject.CN") + op(1) + req_data("Apple Development: Jane Doe (ABCDE12345)")
    wwdr = op(14) + op(1) + req_data(bytes.fromhex("2a864886f763640602 01".replace(" ", ""))) + op(0)
    expr = op(6) + op(6) + op(6) + ident + generic + leaf_cn + wwdr
    designated = blob(0xFADE0C00, op(1) + expr)
    return blob(0xFADE0C01, BE32.pack(1) + BE32.pack(3) + BE32.pack(20) + designated)


ENTITLEMENTS = {
    "application-identifier": "ABCDE12345.com.example.demo",
    "com.apple.developer.team-identifier": "ABCDE12345",
    "get-task-allow": True,
    "keychain-access-groups": ["ABCDE12345.com.example.demo"],
    "aps-environment": "development",
}


def code_directory(ident, team, code, hash_type, page_log2, special, flags):
    """A CodeDirectory, version 0x20400, its code hashes those of `code`."""
    hash_size = 20 if hash_type == 1 else 32
    algo = hashlib.sha1 if hash_type == 1 else hashlib.sha256
    page = 1 << page_log2
    n_code = (len(code) + page - 1) // page
    n_special = max(special) if special else 0
    ident_b = ident.encode() + b"\0"
    team_b = team.encode() + b"\0"
    header = 88
    ident_off = header
    team_off = ident_off + len(ident_b)
    hash_off = team_off + len(team_b) + n_special * hash_size
    hashes = b""
    for s in range(n_special, 0, -1):
        h = special.get(s)
        hashes += algo(h).digest()[:hash_size] if h is not None else bytes(hash_size)
    for i in range(n_code):
        hashes += algo(code[i * page : (i + 1) * page]).digest()[:hash_size]
    length = hash_off + n_code * hash_size
    body = struct.pack(
        ">IIIIIIIIIBBBBIIIIQQQQ",
        0xFADE0C02,
        length,
        0x20400,
        flags,
        hash_off,
        ident_off,
        n_special,
        n_code,
        len(code),
        hash_size,
        hash_type,
        0,
        page_log2,
        0,
        0,
        team_off,
        0,
        0,
        0,
        0x4000,
        1,
    )
    assert len(body) == header, len(body)
    return body + ident_b + team_b + hashes


def super_blob(entries):
    entries = sorted(entries, key=lambda e: e[0])
    index = b""
    data = b""
    at = 12 + 8 * len(entries)
    for slot, b in entries:
        index += BE32.pack(slot) + BE32.pack(at + len(data))
        data += b
    return BE32.pack(0xFADE0CC0) + BE32.pack(12 + len(index) + len(data)) + BE32.pack(len(entries)) + index + data


def signature_for(code, ident, team):
    ent_xml = plistlib.dumps(ENTITLEMENTS, fmt=plistlib.FMT_XML)
    ent = blob(0xFADE7171, ent_xml)
    der_ent = blob(0xFADE7172, der(0x70, integer(1) + der_plist(ENTITLEMENTS)))
    reqs = requirements()
    special = {2: reqs, 5: ent, 7: der_ent}
    flags = 0x10000  # runtime
    cd1 = code_directory(ident, team, code, 1, 12, special, flags)
    cd2 = code_directory(ident, team, code, 2, 12, special, flags)
    cms = blob(0xFADE0B01, signed_data(None, [certificate(LEAF, WWDR, 7), certificate(WWDR, ROOT, 2)]))
    return super_blob([(0, cd1), (2, reqs), (5, ent), (7, der_ent), (0x1000, cd2), (0x10000, cms)])


def resign(path, ident, team):
    """Replaces a Mach-O's LC_CODE_SIGNATURE data (64-bit, little-endian)
    with signature_for() of its code, growing __LINKEDIT to fit."""
    data = bytearray(open(path, "rb").read())
    assert struct.unpack_from("<I", data, 0)[0] == 0xFEEDFACF
    ncmds = struct.unpack_from("<I", data, 16)[0]
    at = 32
    sig_cmd = linkedit = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        if cmd == 0x1D:
            sig_cmd = at
        if cmd == 0x19 and data[at + 8 : at + 24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit = at
        at += size
    assert sig_cmd and linkedit
    dataoff = struct.unpack_from("<I", data, sig_cmd + 8)[0]
    del data[dataoff:]
    # The size first (the hashes cover the load commands that record it).
    size = len(signature_for(bytes(data), ident, team))
    size += (-size) % 16
    struct.pack_into("<I", data, sig_cmd + 12, size)
    fileoff = struct.unpack_from("<Q", data, linkedit + 40)[0]
    filesize = dataoff + size - fileoff
    struct.pack_into("<Q", data, linkedit + 48, filesize)
    struct.pack_into("<Q", data, linkedit + 32, (filesize + 0x3FFF) & ~0x3FFF)
    sig = signature_for(bytes(data), ident, team)
    sig += bytes(size - len(sig))
    open(path, "wb").write(bytes(data) + sig)


# ---- NIBArchive ------------------------------------------------------------------


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n == 0:
            out.append(b | 0x80)
            return bytes(out)
        out.append(b)


class Ref:
    def __init__(self, i):
        self.i = i


class Nib:
    """A NIBArchive (UIKit's compiled nib): objects of classes with keyed
    values, as the public write-ups of the format describe it."""

    def __init__(self):
        self.objects = []  # (class, [(key, value)])

    def obj(self, cls, *pairs):
        self.objects.append((cls, list(pairs)))
        return Ref(len(self.objects) - 1)

    def string(self, s):
        return self.obj("NSString", ("NS.bytes", s.encode()))

    def array(self, items):
        return self.obj("NSArray", ("NSInlinedValue", True), *[("UINibEncoderEmptyKey", r) for r in items])

    def set_(self, i, *pairs):
        self.objects[i.i][1].extend(pairs)

    @staticmethod
    def value(v):
        if v is True:
            return b"\x04"
        if v is False:
            return b"\x05"
        if v is None:
            return b"\x09"
        if isinstance(v, Ref):
            return b"\x0a" + struct.pack("<I", v.i)
        if isinstance(v, int):
            if -128 <= v < 128:
                return b"\x00" + struct.pack("<b", v)
            if -(1 << 15) <= v < 1 << 15:
                return b"\x01" + struct.pack("<h", v)
            if -(1 << 31) <= v < 1 << 31:
                return b"\x02" + struct.pack("<i", v)
            return b"\x03" + struct.pack("<q", v)
        if isinstance(v, float):
            return b"\x07" + struct.pack("<d", v)
        if isinstance(v, bytes):
            return b"\x08" + varint(len(v)) + v
        raise TypeError(v)

    def encode(self):
        keys, classes = [], []
        for cls, pairs in self.objects:
            if cls not in classes:
                classes.append(cls)
            for k, _ in pairs:
                if k not in keys:
                    keys.append(k)
        objects = b""
        values = b""
        start = 0
        for cls, pairs in self.objects:
            objects += varint(classes.index(cls)) + varint(start) + varint(len(pairs))
            start += len(pairs)
            for k, v in pairs:
                values += varint(keys.index(k)) + self.value(v)
        key_table = b"".join(varint(len(k.encode())) + k.encode() for k in keys)
        class_table = b"".join(varint(len(c) + 1) + varint(0) + c.encode() + b"\0" for c in classes)
        o_off = 50
        k_off = o_off + len(objects)
        v_off = k_off + len(key_table)
        c_off = v_off + len(values)
        header = b"NIBArchive" + struct.pack(
            "<IIIIIIIIII", 1, 10, len(self.objects), o_off, len(keys), k_off, start, v_off, len(classes), c_off
        )
        return header + objects + key_table + values + class_table


# UIControlEvents
TOUCH_DOWN, TOUCH_UP_INSIDE, VALUE_CHANGED = 1 << 0, 1 << 6, 1 << 12


def nib_root(n, top, objects, connections):
    empty = n.array([])
    root = n.obj(
        "NSObject",
        ("UINibTopLevelObjectsKey", n.array(top)),
        ("UINibObjectsKey", n.array(objects)),
        ("UINibConnectionsKey", n.array(connections)),
        ("UINibVisibleWindowsKey", empty),
        ("UINibAccessibilityConfigurationsKey", empty),
        ("UINibKeyValuePairsKey", empty),
    )
    return root


def proxy(n, ident):
    return n.obj("UIProxyObject", ("UIProxiedObjectIdentifier", n.string(ident)))


def event(n, label, source, dest, mask):
    return n.obj(
        "UIRuntimeEventConnection",
        ("UILabel", n.string(label)),
        ("UISource", source),
        ("UIDestination", dest),
        ("UIEventMask", mask),
    )


def outlet(n, label, source, dest):
    return n.obj("UIRuntimeOutletConnection", ("UILabel", n.string(label)), ("UISource", source), ("UIDestination", dest))


def scene_view_nib():
    """The storyboard scene's view: a button, a slider and a custom label,
    their actions sent to File's Owner (the scene's ViewController) and
    to the first responder."""
    n = Nib()
    n.obj("NSObject")  # object 0: the root, filled in below
    owner = proxy(n, "IBFilesOwner")
    first = proxy(n, "IBFirstResponder")
    button = n.obj("UIButton", ("UIAccessibilityLabel", n.string("Tap me")), ("UITag", 1))
    slider = n.obj("UISlider", ("UIValue", 0.5))
    label = n.obj(
        "UIClassSwapper",
        ("UIClassName", n.string("GreetingLabel")),
        ("UIOriginalClassName", n.string("UILabel")),
        ("UIText", n.string("Hello")),
    )
    view = n.obj("UIView", ("UISubviews", n.array([button, slider, label])))
    for v in (button, slider, label):
        n.set_(v, ("UISuperview", view))
    conns = [
        event(n, "buttonTapped:", button, owner, TOUCH_UP_INSIDE),
        event(n, "sliderChanged:", slider, owner, VALUE_CHANGED),
        event(n, "copyAll:", button, first, TOUCH_DOWN),
        outlet(n, "view", owner, view),
        outlet(n, "greetingLabel", owner, label),
    ]
    root = nib_root(n, [owner, first, view], [owner, first, view, button, slider, label], conns)
    # The root must be object 0: swap it in.
    n.objects[0], n.objects[root.i] = n.objects[root.i], n.objects[0]
    return fix_refs(n, 0, root.i)


def fix_refs(n, a, b):
    """References to objects a and b swapped (after moving b to a)."""
    for _, pairs in n.objects:
        for k, (key, v) in enumerate(pairs):
            if isinstance(v, Ref) and v.i in (a, b):
                pairs[k] = (key, Ref(b if v.i == a else a))
    return n.encode()


def scene_controller_nib():
    """The storyboard scene's controller: a ViewController (a custom class
    of UIViewController) whose view is in the view nib."""
    n = Nib()
    n.obj("NSObject")
    owner = proxy(n, "IBFilesOwner")
    vc = n.obj(
        "UIClassSwapper",
        ("UIClassName", n.string("ViewController")),
        ("UIOriginalClassName", n.string("UIViewController")),
        ("UINibName", n.string("BYZ-38-t0r-view-8bC-Xf-vdC")),
        ("UIStoryboardIdentifier", n.string("UIViewController-BYZ-38-t0r")),
    )
    conns = [outlet(n, "sceneViewController", owner, vc)]
    root = nib_root(n, [owner, vc], [owner, vc], conns)
    n.objects[0], n.objects[root.i] = n.objects[root.i], n.objects[0]
    return fix_refs(n, 0, root.i)


def settings_nib():
    """A standalone nib loaded by SettingsController (UIKit's default nib
    name is the class's): Save and Cancel buttons."""
    n = Nib()
    n.obj("NSObject")
    owner = proxy(n, "IBFilesOwner")
    first = proxy(n, "IBFirstResponder")
    save = n.obj("UIButton", ("UIAccessibilityLabel", n.string("Save")))
    cancel = n.obj("UIButton", ("UIAccessibilityLabel", n.string("Cancel")))
    view = n.obj("UIView", ("UISubviews", n.array([save, cancel])))
    conns = [
        event(n, "save:", save, owner, TOUCH_UP_INSIDE),
        event(n, "cancel:", cancel, owner, TOUCH_UP_INSIDE),
        event(n, "undefinedAction:", cancel, first, TOUCH_UP_INSIDE),
        outlet(n, "view", owner, view),
    ]
    root = nib_root(n, [owner, first, view], [owner, first, view, save, cancel], conns)
    n.objects[0], n.objects[root.i] = n.objects[root.i], n.objects[0]
    return fix_refs(n, 0, root.i)


# ---- NSKeyedArchiver (macOS nibs) -------------------------------------------------


def keyed_main_menu():
    """MainMenu.nib as AppKit compiles it: an NSKeyedArchiver archive whose
    IB.objectdata is an NSIBObjectData with the connections."""
    objs = ["$null"]

    def add(o):
        objs.append(o)
        return plistlib.UID(len(objs) - 1)

    def cls(name, *supers):
        return add({"$classname": name, "$classes": [name, *supers, "NSObject"]})

    c_custom = cls("NSCustomObject")
    c_item = cls("NSMenuItem")
    c_menu = cls("NSMenu")
    c_control = cls("NSNibControlConnector", "NSNibConnector")
    c_outlet = cls("NSNibOutletConnector", "NSNibConnector")
    c_array = cls("NSMutableArray", "NSArray")
    c_data = cls("NSIBObjectData")
    owner = add({"$class": c_custom, "NSClassName": "NSApplication"})
    first = add({"$class": c_custom, "NSClassName": "FirstResponder"})
    delegate = add({"$class": c_custom, "NSClassName": "AppDelegate"})
    about = add({"$class": c_item, "NSTitle": "About MacDemo", "NSKeyEquiv": ""})
    copy = add({"$class": c_item, "NSTitle": "Copy All", "NSKeyEquiv": "a"})
    items = add({"$class": c_array, "NS.objects": [about, copy]})
    menu = add({"$class": c_menu, "NSTitle": "MacDemo", "NSMenuItems": items})
    for item in (about, copy):
        objs[item.data]["NSMenu"] = menu
    conns = add(
        {
            "$class": c_array,
            "NS.objects": [
                add({"$class": c_control, "NSSource": about, "NSDestination": delegate, "NSLabel": "showAbout:"}),
                add({"$class": c_control, "NSSource": copy, "NSDestination": first, "NSLabel": "copyAll:"}),
                add({"$class": c_outlet, "NSSource": owner, "NSDestination": delegate, "NSLabel": "delegate"}),
            ],
        }
    )
    all_objs = add({"$class": c_array, "NS.objects": [menu, about, copy, delegate, first]})
    parents = add({"$class": c_array, "NS.objects": [owner, menu, menu, owner, owner]})
    data = add(
        {
            "$class": c_data,
            "NSRoot": owner,
            "NSConnections": conns,
            "NSObjectsKeys": all_objs,
            "NSObjectsValues": parents,
            "NSVisibleWindows": add({"$class": c_array, "NS.objects": []}),
        }
    )
    archive = {"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"IB.objectdata": data}, "$objects": objs}
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


# ---- the bundles -------------------------------------------------------------------


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


DEMO_INFO = {
    "CFBundleIdentifier": "com.example.demo",
    "CFBundleName": "Demo",
    "CFBundleDisplayName": "Demo App",
    "CFBundleExecutable": "Demo",
    "CFBundlePackageType": "APPL",
    "CFBundleVersion": "42",
    "CFBundleShortVersionString": "1.2.3",
    "CFBundleSupportedPlatforms": ["iPhoneOS"],
    "MinimumOSVersion": "15.0",
    "LSRequiresIPhoneOS": True,
    "UIDeviceFamily": [1, 2],
    "UIMainStoryboardFile": "Main",
    "UILaunchStoryboardName": "LaunchScreen",
    "UIBackgroundModes": ["audio", "remote-notification"],
    "UIRequiredDeviceCapabilities": ["arm64"],
    "CFBundleURLTypes": [{"CFBundleURLName": "com.example.demo", "CFBundleURLSchemes": ["demo", "demo-auth"]}],
    "LSApplicationQueriesSchemes": ["maps"],
    "NSCameraUsageDescription": "Scan codes with the camera.",
    "NSLocationWhenInUseUsageDescription": "Show what is near you.",
    "CFBundleDocumentTypes": [
        {
            "CFBundleTypeName": "Demo Document",
            "CFBundleTypeRole": "Editor",
            "LSHandlerRank": "Owner",
            "LSItemContentTypes": ["com.example.demo.document"],
        }
    ],
    "UTExportedTypeDeclarations": [
        {
            "UTTypeIdentifier": "com.example.demo.document",
            "UTTypeDescription": "Demo Document",
            "UTTypeConformsTo": ["public.data", "public.content"],
            "UTTypeTagSpecification": {"public.filename-extension": ["demo"], "public.mime-type": "application/x-demo"},
        }
    ],
    "UTImportedTypeDeclarations": [
        {"UTTypeIdentifier": "org.example.markdown", "UTTypeConformsTo": ["public.plain-text"],
         "UTTypeTagSpecification": {"public.filename-extension": ["md", "markdown"]}}
    ],
    "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False, "NSExceptionDomains": {"example.org": {}}},
    "DTSDKName": "iphoneos17.0",
    "DTXcode": "1500",
    "BuildMachineOSBuild": "23A344",
}


def profile_plist():
    import datetime

    return {
        "AppIDName": "Demo",
        "ApplicationIdentifierPrefix": ["ABCDE12345"],
        "CreationDate": datetime.datetime(2026, 1, 2, 3, 4, 5),
        "ExpirationDate": datetime.datetime(2027, 1, 2, 3, 4, 5),
        "Name": "Demo Development",
        "Platform": ["iOS"],
        "ProvisionedDevices": ["00008030-0011223344556677", "00008101-8899AABBCCDDEEFF"],
        "TeamIdentifier": ["ABCDE12345"],
        "TeamName": "Jane Doe",
        "TimeToLive": 365,
        "UUID": "6F9619FF-8B86-D011-B42D-00C04FC964FF",
        "Version": 1,
        "DeveloperCertificates": [certificate(LEAF, WWDR, 7)],
        "Entitlements": dict(ENTITLEMENTS),
    }


def ios_app(out, bins):
    app = os.path.join(out, "Demo.app")
    shutil.rmtree(app, ignore_errors=True)
    os.makedirs(app)
    shutil.copy(os.path.join(bins, "Demo"), os.path.join(app, "Demo"))
    resign(os.path.join(app, "Demo"), "com.example.demo", "ABCDE12345")
    write(os.path.join(app, "Info.plist"), plistlib.dumps(DEMO_INFO, fmt=plistlib.FMT_BINARY))
    write(os.path.join(app, "PkgInfo"), b"APPL????")
    profile = plistlib.dumps(profile_plist(), fmt=plistlib.FMT_XML)
    write(os.path.join(app, "embedded.mobileprovision"),
          signed_data(profile, [certificate(WWDR, ROOT, 3), certificate(ROOT, ROOT, 1)]))
    write(os.path.join(app, "_CodeSignature", "CodeResources"),
          plistlib.dumps({"files": {"Info.plist": bytes(20)}, "files2": {}, "rules": {}}, fmt=plistlib.FMT_XML))
    sb = os.path.join(app, "Base.lproj", "Main.storyboardc")
    write(os.path.join(sb, "Info.plist"), plistlib.dumps({
        "UIStoryboardDesignatedEntryPointIdentifier": "UIViewController-BYZ-38-t0r",
        "UIStoryboardVersion": 1,
        "UIViewControllerIdentifiersToNibNames": {"UIViewController-BYZ-38-t0r": "UIViewController-BYZ-38-t0r"},
    }, fmt=plistlib.FMT_BINARY))
    write(os.path.join(sb, "UIViewController-BYZ-38-t0r.nib"), scene_controller_nib())
    view = os.path.join(sb, "BYZ-38-t0r-view-8bC-Xf-vdC.nib")
    write(os.path.join(view, "runtime.nib"), scene_view_nib())
    write(os.path.join(view, "objects-13.0+.nib"), scene_view_nib())
    write(os.path.join(app, "SettingsController.nib"), settings_nib())
    fw = os.path.join(app, "Frameworks", "Greeter.framework")
    os.makedirs(fw)
    shutil.copy(os.path.join(bins, "Greeter"), os.path.join(fw, "Greeter"))
    write(os.path.join(fw, "Info.plist"), plistlib.dumps({
        "CFBundleIdentifier": "com.example.greeter", "CFBundleExecutable": "Greeter", "CFBundlePackageType": "FMWK",
        "CFBundleShortVersionString": "2.0", "CFBundleVersion": "200", "MinimumOSVersion": "15.0",
    }, fmt=plistlib.FMT_XML))
    ext = os.path.join(app, "PlugIns", "Share.appex")
    os.makedirs(ext)
    shutil.copy(os.path.join(bins, "Share"), os.path.join(ext, "Share"))
    write(os.path.join(ext, "Info.plist"), plistlib.dumps({
        "CFBundleIdentifier": "com.example.demo.share", "CFBundleExecutable": "Share", "CFBundlePackageType": "XPC!",
        "CFBundleVersion": "42", "MinimumOSVersion": "15.0",
        "NSExtension": {"NSExtensionPointIdentifier": "com.apple.share-services",
                        "NSExtensionPrincipalClass": "ShareViewController"},
    }, fmt=plistlib.FMT_XML))
    # The .ipa: Payload/Demo.app, directories first, as Xcode's export writes it.
    with zipfile.ZipFile(os.path.join(out, "Demo.ipa"), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("Payload/"), b"")
        for root, dirs, files in sorted(os.walk(app)):
            dirs.sort()
            rel = os.path.relpath(root, out)
            z.writestr(zipfile.ZipInfo("Payload/" + rel + "/"), b"")
            for f in sorted(files):
                info = zipfile.ZipInfo("Payload/" + rel + "/" + f)
                info.external_attr = (0o755 if f in ("Demo", "Greeter", "Share") else 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, open(os.path.join(root, f), "rb").read())


def mac_app(out, bins):
    app = os.path.join(out, "MacDemo.app")
    shutil.rmtree(app, ignore_errors=True)
    contents = os.path.join(app, "Contents")
    write(os.path.join(contents, "Info.plist"), plistlib.dumps({
        "CFBundleIdentifier": "com.example.macdemo", "CFBundleExecutable": "MacDemo", "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "LSMinimumSystemVersion": "12.0",
        "NSMainNibFile": "MainMenu", "NSPrincipalClass": "NSApplication",
        "NSAppleEventsUsageDescription": "Talk to other apps.",
    }, fmt=plistlib.FMT_XML))
    os.makedirs(os.path.join(contents, "MacOS"))
    shutil.copy(os.path.join(bins, "MacDemo"), os.path.join(contents, "MacOS", "MacDemo"))
    write(os.path.join(contents, "Resources", "MainMenu.nib"), keyed_main_menu())
    fw = os.path.join(contents, "Frameworks", "Greeter.framework")
    a = os.path.join(fw, "Versions", "A")
    os.makedirs(os.path.join(a, "Resources"))
    shutil.copy(os.path.join(bins, "Greeter-mac"), os.path.join(a, "Greeter"))
    write(os.path.join(a, "Resources", "Info.plist"), plistlib.dumps({
        "CFBundleIdentifier": "com.example.greeter", "CFBundleExecutable": "Greeter", "CFBundlePackageType": "FMWK",
    }, fmt=plistlib.FMT_XML))
    os.symlink("A", os.path.join(fw, "Versions", "Current"))
    os.symlink("Versions/Current/Greeter", os.path.join(fw, "Greeter"))
    os.symlink("Versions/Current/Resources", os.path.join(fw, "Resources"))


def plists(out):
    d = os.path.join(out, "plists")
    os.makedirs(d, exist_ok=True)
    write(os.path.join(d, "info-binary.plist"), plistlib.dumps(DEMO_INFO, fmt=plistlib.FMT_BINARY))
    write(os.path.join(d, "info-xml.plist"), plistlib.dumps(DEMO_INFO, fmt=plistlib.FMT_XML))
    write(os.path.join(d, "info-utf16.plist"),
          plistlib.dumps(DEMO_INFO, fmt=plistlib.FMT_XML).decode().replace('encoding="UTF-8"', 'encoding="UTF-16"')
          .encode("utf-16"))
    import datetime

    values = {
        "int": 7, "neg": -5, "big": (1 << 64) - 1, "real": 2.5, "yes": True, "no": False,
        "date": datetime.datetime(2026, 10, 18, 12, 0, 0), "data": b"\x00\x01\xfe", "unicode": "café \U0001F600",
        "nested": {"list": [1, "two", [3.0]]}, "empty": {}, "none": [],
    }
    write(os.path.join(d, "values-binary.plist"), plistlib.dumps(values, fmt=plistlib.FMT_BINARY))
    write(os.path.join(d, "values-xml.plist"), plistlib.dumps(values, fmt=plistlib.FMT_XML))
    write(os.path.join(d, "keyed.plist"), keyed_main_menu())
    write(os.path.join(d, "settings.nib"), settings_nib())
    write(os.path.join(d, "scene-view.nib"), scene_view_nib())
    write(os.path.join(d, "scene-controller.nib"), scene_controller_nib())
    write(os.path.join(d, "signature.bin"), signature_for(b"\0" * 10000, "com.example.demo", "ABCDE12345"))


def main():
    out = sys.argv[1]
    plists(out)
    if "--plists-only" in sys.argv[2:]:
        return
    bins = os.path.join(out, "bin")
    ios_app(out, bins)
    mac_app(out, bins)


if __name__ == "__main__":
    main()
