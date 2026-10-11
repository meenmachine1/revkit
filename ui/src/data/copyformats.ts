// Copy Special (Ghidra's ClipboardPlugin): selected bytes as a hex string,
// a C array, Python bytes or Base64, an address list, or the listing's text
// as shown. Pure formatting; the app reads the bytes (GetByteView) and
// writes the clipboard.

export type CopyFormat = "hex" | "hex-spaced" | "c" | "python" | "base64" | "addresses" | "listing";

export const COPY_FORMATS: { id: CopyFormat; label: string; detail: string }[] = [
  { id: "hex", label: "Hex string", detail: "4889e5c3" },
  { id: "hex-spaced", label: "Hex bytes", detail: "48 89 e5 c3" },
  { id: "c", label: "C array", detail: "unsigned char data[] = { 0x48, 0x89, … };" },
  { id: "python", label: "Python bytes", detail: 'b"\\x48\\x89\\xe5\\xc3"' },
  { id: "base64", label: "Base64", detail: "SInlww==" },
  { id: "addresses", label: "Address list", detail: "one code unit address per line" },
  { id: "listing", label: "Listing text (as shown)", detail: "the selected rows, as the listing draws them" },
];

const hex2 = (b: number) => b.toString(16).padStart(2, "0");

/** Bytes as text in one of the byte formats (`name`: the C array's name). */
export function formatBytes(format: CopyFormat, bytes: Uint8Array, name = "data"): string {
  const list = [...bytes];
  switch (format) {
    case "hex":
      return list.map(hex2).join("");
    case "hex-spaced":
      return list.map(hex2).join(" ");
    case "c": {
      const lines: string[] = [];
      for (let i = 0; i < list.length; i += 12) lines.push("  " + list.slice(i, i + 12).map((b) => `0x${hex2(b)}`).join(", "));
      return `unsigned char ${name}[${list.length}] = {\n${lines.join(",\n")}\n};\n`;
    }
    case "python":
      return `b"${list.map((b) => `\\x${hex2(b)}`).join("")}"`;
    case "base64": {
      let s = "";
      for (const b of list) s += String.fromCharCode(b);
      return btoa(s);
    }
    default:
      return "";
  }
}

/** Addresses, one per line, in hex. */
export function formatAddresses(addrs: bigint[]): string {
  return addrs.map((a) => a.toString(16)).join("\n") + (addrs.length ? "\n" : "");
}
