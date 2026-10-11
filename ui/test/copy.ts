// Unit tests for Copy Special's formats (src/data/copyformats.ts).

import assert from "node:assert/strict";
import { formatAddresses, formatBytes } from "../src/data/copyformats";

const b = new Uint8Array([0x48, 0x89, 0xe5, 0xc3]);
assert.equal(formatBytes("hex", b), "4889e5c3");
assert.equal(formatBytes("hex-spaced", b), "48 89 e5 c3");
assert.equal(formatBytes("python", b), 'b"\\x48\\x89\\xe5\\xc3"');
assert.equal(formatBytes("base64", b), "SInlww==");
assert.equal(formatBytes("c", b, "code"), "unsigned char code[4] = {\n  0x48, 0x89, 0xe5, 0xc3\n};\n");
const long = formatBytes("c", new Uint8Array(13));
assert.equal(long.split("\n").length, 5, long);
assert.ok(long.includes("0x00, 0x00\n  0x00") === false && long.includes(",\n  0x00\n"), long);
assert.equal(formatBytes("hex", new Uint8Array()), "");
assert.equal(formatAddresses([0x401000n, 0x401004n]), "401000\n401004\n");
assert.equal(formatAddresses([]), "");
console.log("ok   copy special formats");
