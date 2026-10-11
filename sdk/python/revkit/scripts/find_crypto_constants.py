# @category Analysis/Crypto
# @description Finds well-known cryptographic constants and tables (AES S-boxes, SHA and MD5
# @description initial values and round constants, CRC-32 tables, Blowfish, ChaCha) and notes each one.
# @context program
# @arg annotate:bool=true Add a "crypto" note at each match
"""Find crypto constants with the daemon's byte search (FindBytes).

Word constants are matched in the program's byte order; byte tables as
they are. Each match gets a note tagged "crypto" naming what it is (and
the function using it, when one does).
"""
import struct

from revkit.script import *

# name: (word size, words) or (None, bytes)
SIGNATURES = {
    "AES S-box": (None, bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    "AES inverse S-box": (None, bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    "SHA-256 initial hash values": (4, [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A]),
    "SHA-256 round constants": (4, [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5]),
    "SHA-512 initial hash values": (8, [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B]),
    "SHA-1 / MD5 initial values": (4, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]),
    "MD5 round constants": (4, [0xD76AA478, 0xE8C7B756, 0x242070DB]),
    "CRC-32 table": (4, [0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA]),
    "CRC-32C table": (4, [0x00000000, 0xF26B8303, 0xE13B70F7]),
    "Blowfish P-array": (4, [0x243F6A88, 0x85A308D3, 0x13198A2E]),
    "ChaCha / Salsa20 constant": (None, b"expand 32-byte k"),
}

big = ":BE:" in current_program.summary().language.language_id


def pattern(spec):
    size, value = spec
    if size is None:
        return value
    fmt = (">" if big else "<") + ("I" if size == 4 else "Q") * len(value)
    return struct.pack(fmt, *value)


found = 0
monitor.set_max(len(SIGNATURES))
for name, spec in SIGNATURES.items():
    monitor.increment()
    monitor.message(name)
    for a in find_bytes(pattern(spec), max_results=-1):
        f = function_containing(a)
        where = f" in {f.name}" if f else ""
        users = {x.from_function_name for x in xrefs_to(a) if x.from_function_name}
        used = f" (used by {', '.join(sorted(users))})" if users else ""
        print(f"0x{a:x} {name}{where}{used}")
        if args["annotate"]:
            note(a, name + used, tag="crypto")
        found += 1
print(f"{found} crypto constant(s) found")
