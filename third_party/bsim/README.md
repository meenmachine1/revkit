# BSim feature weights

Ghidra's BSim weight tables, used by revkit's C++ port of BSim's vector
comparison (`src/diff/lsh.{h,cc}`): per-hash document counts (`idflookup`,
the 1000 most common feature hashes of BSim's training corpus), the idf
and tf weight curves, and the significance model's parameters.

- Upstream: Ghidra 12.1.4 PUBLIC, `Ghidra/Features/BSim/data/`, copied
  unchanged (SHA-256 below).
- License: Apache 2.0 (`LICENSE`, Ghidra's), like the rest of Ghidra.

| file | used for (`GenSignatures.getWeightsFile`) | signature settings |
| --- | --- | --- |
| `lshweights_64.xml` | both programs 64-bit | `0x49` |
| `lshweights_64_32.xml` | both 64-bit, language variant containing `-32` | `0x49` |
| `lshweights_32.xml` | both 32-bit | `0x49` |
| `lshweights_nosize.xml` | 32-bit vs 64-bit, or another equal size | `0x4d` (sizes collapsed) |

The settings word is what the decompiler's `GraphSigManager` is set to
when the vectors are generated (`SigManager::setSettings`): `0x49` =
`SIG_COLLAPSE_INDNOISE | SIG_DONOTUSE_CONST` (shifted left 2, plus the
check bit), `0x4d` adds `SIG_COLLAPSE_SIZE`. A table only fits vectors
generated with its own settings.

```
08c5089ea1b4fb8f8e91c88656d5c4976758ab901aab82c2a7d38e665520feac  lshweights_32.xml
121c740a89c31e4811107fd6da8fd3ead8dcd343ce5651220440b65cf3bb1160  lshweights_64_32.xml
1b0795effc4f696082faca3a2145e714c1b120aed7461a0f32d3ba29a0056912  lshweights_64.xml
3af6daef4a0f0c12de3dace9124092bc21e5c3a6c3943ccd8756d5485a4949ba  lshweights_nosize.xml
```
