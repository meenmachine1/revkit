# Decompiler quality against the original source

[decomp-parity.md](decomp-parity.md) measures how often revkit's C is
*identical* to Ghidra's. This note measures something else: given a
stripped binary, whose C is closer to the source it was compiled from,
revkit's or Ghidra's. Both tools work from their own analysis: revkit
from `rk-lift --analyze --decompile` (its discovery, data analysis,
inference and loader, nothing from Ghidra), and Ghidra from its default
auto-analysis (the reference exports, `out/ref` and `out/firmware-ref`).
The decompiler is the same (Ghidra's, vendored); what differs is what each
tells it. Identity with Ghidra is kept as a regression guard only
(`corpus/baselines`), and revkit departs from it where that brings the C
closer to the source.

```sh
scripts/decompile-corpus.sh --inputs own --out build/corpus-out/revkit-decomp-own --in-order   # revkit, tuning corpus
python3 scripts/firmware_score.py --out build/corpus-out/firmware                               # revkit, firmware corpus
python3 scripts/decomp-quality.py --markdown build/quality/report.md --json build/quality/report.json \
    [--rows rows.json] [--judge build/judge]
python3 scripts/decomp-quality.py --heldout ...      # the held-out set, once (docs/heldout.md)
```

The truth comes from each stripped binary's debug twin
(`scripts/source_truth.py`): DWARF read with pyelftools (functions, their
source file and line, parameter, return and local types, global variables,
`DW_AT_noreturn`), the PDB's prototypes for PE (`rk-debuginfo`; source
locations from an ELF build of the same program), and each function's
definition cut out of the corpus sources (unpacked from the same archives
the corpus builds use) by brace matching from its declaration line. 3,484
functions of the 27 stripped tuning binaries and 14,589 of the 23 firmware
images are decompiled by both tools and have truth.

## The metrics

Every metric is computed per function for each tool and compared: W/T/L
count the functions where revkit is better, equal or worse, and p is a
two-sided sign test on W against L (a verdict at p < 0.01). The
**composite** counts, per function, the metrics revkit wins minus those it
loses, the prototype once (by its parameter types), and sign-tests the
functions where that is positive against those where it is negative.

| metric | what it measures | what it can't show |
| --- | --- | --- |
| `proto_arity`, `proto_return` | parameter count; whether a value is returned | |
| `proto_ret_class`, `proto_param_class` | type class (void, int, char, bool, float, pointer, struct) of the return and of each parameter position | sizes and signedness; a pointer counts as right whatever it points to |
| `proto_exact` | the whole signature after notation normalization (protonorm) | names, so struct pointers (most of the program's types) never match on a stripped binary |
| `call_args` | calls to the program's own functions passing the callee's true argument count (direct calls and calls through named pointer slots) | argument values |
| `lib_call_args` | calls by name (library functions; the program's own are `FUN_` when stripped) to functions the source calls, passing an argument count the source's calls of that function pass (multisets: printf's count is its format's) | calls the compiler rewrote (`printf("x\n")` to `puts`) aren't counted |
| `noreturn` | calls marked non-returning exactly where the callee is `DW_AT_noreturn` | callees without the attribute that never return anyway |
| `noise` | `in_`, `unaff_`, `extraout_` variables (values the prototype doesn't explain) | a varargs function's register save area is noise by this count but correct C |
| `undefined` | `undefinedN` types | |
| `locals_class` | overlap of the declared locals' type classes with the source's locals (as multisets) | which variable is which (not mapped by storage); optimized builds' locals differ from the source's anyway |
| `members` | member accesses (`p->f`) against the source's count | neither tool recovers structures on a stripped binary: ties |
| `globals_named` | the source's global variables accessed by symbol rather than raw address | the global's type |
| `gotos`, `loops`, `switch` | distance to the source's counts of each; a switch where the source has one | macros: the source isn't preprocessed (Lua's `vmdispatch` hides its switch) |
| `strings`, `constants` | the source's string literals shown as literals; its numeric literals (≥ 10) shown with their value | macros and folded constants |
| `failed`, `warnings` | decompiler failures; warnings other than "does not return" | |
| `casts`, `temporaries`, `length` | casts per line; declared locals against the source's; log of the line ratio | style: a cast to a correct type counts the same as a pointless one |

These are proxies. They count what can be checked mechanically and say
nothing of whether the C *means* what the source means; the judged sample
below is for that.

## Results

(Tuning: the 27 stripped binaries of `out/corpus`; firmware: the 23 raw
images of `out/firmware-corpus`. Before: master at c7b2045; after: this
branch.)

### Per function (the composite)

| family | paired | before W/T/L | after W/T/L | after p |
| --- | ---: | --- | --- | ---: |
| ALL firmware | 14589 | 1328/12147/1114 (WIN) | 3788/10287/514 (WIN) | 0 |
| ALL tuning | 3484 | 27/3396/61 (LOSS) | 1744/892/848 (WIN) | 1.4e-70 |
| ELF clang -O0 | 558 | 2/552/4 (tie) | 304/169/85 (WIN) | 5.3e-30 |
| ELF clang -O2 | 1048 | 9/1035/4 (tie) | 496/245/307 (WIN) | 2.7e-11 |
| ELF gcc -O0 | 400 | 0/395/5 (tie) | 197/127/76 (WIN) | 1.5e-13 |
| ELF gcc -O2 | 1252 | 14/1221/17 (tie) | 644/278/330 (WIN) | 4.6e-24 |
| PE clang -O0 | 101 | 0/101/0 (tie) | 44/39/18 (WIN) | 0.0013 |
| PE clang -O2 | 125 | 2/92/31 (LOSS) | 59/34/32 (WIN) | 0.0061 |
| fw cortexm | 2682 | 215/2437/30 (WIN) | 709/1906/67 (WIN) | 3.4e-136 |
| fw m68k | 1038 | 89/926/23 (WIN) | 296/723/19 (WIN) | 4.4e-65 |
| fw mips | 2740 | 189/2291/260 (LOSS) | 303/2219/218 (WIN) | 0.00023 |
| fw ppc | 3940 | 195/3345/400 (LOSS) | 402/3483/55 (WIN) | 3.3e-66 |
| fw sh4 | 1710 | 167/1268/275 (LOSS) | 1216/422/72 (WIN) | 7.1e-269 |
| fw xtensa | 2479 | 473/1880/126 (WIN) | 862/1534/83 (WIN) | 4.2e-164 |

After merging master at 0ee1a1e (processors, patching, the memory map,
the firmware discovery work) the benchmark was re-run on the merged
tree (`build/quality/merged.md`): the tuning families are unchanged
(their C is the same), and every firmware family still wins, Cortex-M by
more (master's discovery pairs 41 more functions):

| family | paired | branch W/T/L | merged W/T/L | merged p |
| --- | ---: | --- | --- | ---: |
| ALL firmware | 14630 | 3788/10287/514 | 3892/10223/515 (WIN) | 0 |
| ALL tuning | 3484 | 1744/892/848 | 1744/892/848 (WIN) | 1.4e-70 |
| fw cortexm | 2723 | 709/1906/67 | 812/1844/67 (WIN) | 2e-163 |
| fw m68k | 1038 | 296/723/19 | 296/723/19 (WIN) | 4.4e-65 |
| fw mips | 2739 | 303/2219/218 | 303/2219/217 (WIN) | 0.00019 |
| fw ppc | 3939 | 402/3483/55 | 402/3480/57 (WIN) | 5.4e-65 |
| fw sh4 | 1712 | 1216/422/72 | 1217/423/72 (WIN) | 3.7e-269 |
| fw xtensa | 2479 | 862/1534/83 | 862/1534/83 (WIN) | 4.2e-164 |

The judged sample below was drawn again from the merged tree's C.

### Per metric, after (W/T/L; + and − mark p < 0.01)

| metric | ALL firmware | ALL tuning | ELF clang -O0 | ELF clang -O2 | ELF gcc -O0 | ELF gcc -O2 | PE clang -O0 | PE clang -O2 | cortexm | m68k | mips | ppc | sh4 | xtensa |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `call_args` | 529/9755/202+ | 430/1286/243+ | 15/237/0+ | 163/377/146 | 2/139/0 | 243/466/97+ | 1/32/0 | 6/35/0 | 11/2046/14 | 67/721/4+ | 104/1927/117 | 28/3056/4+ | 171/378/62+ | 148/1627/1+ |
| `casts` | 2527/11319/743+ | 637/1024/1822− | 132/205/221− | 180/258/609− | 75/147/178− | 202/340/710− | 26/51/24 | 22/23/80− | 282/2270/130+ | 91/922/25+ | 198/2374/168 | 123/3720/97 | 1274/389/47+ | 559/1644/276+ |
| `constants` | 78/2093/3+ | 13/513/15 | 2/145/4 | 5/89/1 | 0/110/4 | 4/116/6 | 2/33/0 | 0/20/0 | 15/404/0+ | 1/189/0 | 2/199/1 | 1/646/0 | 28/254/1+ | 31/401/1+ |
| `failed` | 0/14589/0 | 1/3483/0 | 0/558/0 | 1/1047/0 | 0/400/0 | 0/1252/0 | 0/101/0 | 0/125/0 | 0/2682/0 | 0/1038/0 | 0/2740/0 | 0/3940/0 | 0/1710/0 | 0/2479/0 |
| `globals_named` | 25/1106/1+ | 0/429/1 | 0/79/0 | 0/153/1 | 0/53/0 | 0/144/0 | - | - | 0/4/0 | 12/330/0+ | 6/367/1 | 7/405/0 | - | - |
| `gotos` | 240/12487/130+ | 24/3418/11 | 0/557/1 | 8/1036/3 | 0/399/1 | 16/1217/5 | 0/95/0 | 0/114/1 | 40/2587/37 | 26/1000/8+ | 54/996/20+ | 56/3851/18+ | 4/1684/15 | 60/2369/32+ |
| `length` | 1344/10285/1228 | 407/2581/465 | 67/461/30+ | 101/758/188− | 48/328/24+ | 128/917/193− | 13/79/3 | 50/38/27 | 200/2281/183 | 51/927/56 | 102/847/121 | 117/3712/96 | 463/839/401 | 411/1679/371 |
| `locals_class` | 972/11478/407+ | 504/2416/533 | 77/436/45+ | 144/668/235− | 75/297/28+ | 193/838/207 | 8/81/6 | 7/96/12 | 147/2442/75+ | 54/965/15+ | 60/927/83 | 53/3848/24+ | 418/1143/142+ | 240/2153/68+ |
| `loops` | 246/12546/65+ | 3/3446/4 | 0/558/0 | 2/1045/0 | 0/400/0 | 1/1233/4 | 0/95/0 | 0/115/0 | 43/2611/10+ | 34/992/8+ | 64/985/21+ | 48/3865/12+ | 0/1700/3 | 57/2393/11+ |
| `members` | 2/7820/0 | 10/1683/21 | 0/265/0 | 5/518/14 | 0/154/0 | 3/660/6 | 1/27/0 | 1/59/1 | 0/1524/0 | 1/664/0 | 1/669/0 | 0/2393/0 | 0/997/0 | 0/1573/0 |
| `noise` | 269/14265/55+ | 12/3092/379− | 0/544/14− | 4/854/189− | 1/385/14− | 5/1101/146− | 1/95/5 | 1/113/11− | 29/2649/4+ | 15/1018/5 | 21/2684/35 | 20/3911/9 | 0/1708/2 | 184/2295/0+ |
| `noreturn` | 418/1358/4+ | 0/182/4 | - | 0/91/0 | - | 0/91/4 | - | - | 67/296/4+ | 66/272/0+ | 169/175/0+ | 63/301/0+ | 53/57/0+ | 0/257/0 |
| `proto_arity` | 31/14538/20 | 90/3320/64 | 6/552/0 | 26/964/48 | 5/389/6 | 34/1210/8+ | 4/97/0 | 15/108/2+ | 5/2670/7 | 11/1023/4 | 4/2730/6 | 5/3935/0 | 0/1710/0 | 6/2470/3 |
| `proto_exact` | 11/14575/3 | 336/3099/39+ | 105/436/17+ | 39/999/0+ | 98/287/15+ | 52/1196/4+ | 29/69/3+ | 13/112/0+ | 4/2678/0 | 0/1038/0 | 2/2736/2 | 0/3940/0 | 2/1707/1 | 3/2476/0 |
| `proto_param_class` | 88/14393/108 | 1657/1763/54+ | 198/357/3+ | 558/447/33+ | 120/279/1+ | 735/502/15+ | 19/82/0+ | 27/96/2+ | 7/2668/7 | 13/1016/9 | 35/2632/73− | 13/3921/6 | 7/1698/5 | 13/2458/8 |
| `proto_ret_class` | 110/14439/40+ | 399/2973/102+ | 67/490/1+ | 106/851/81 | 62/338/0+ | 139/1093/20+ | 4/97/0 | 21/104/0+ | 13/2659/10 | 4/1034/0 | 36/2689/15+ | 43/3885/12+ | 11/1696/3 | 3/2476/0 |
| `proto_return` | 105/14459/25+ | 195/3216/63+ | 16/542/0+ | 64/929/45 | 8/392/0+ | 95/1140/17+ | 2/99/0 | 10/114/1 | 2/2675/5 | 4/1034/0 | 38/2694/8+ | 57/3872/11+ | 1/1708/1 | 3/2476/0 |
| `strings` | 1995/3046/0+ | 90/650/14+ | 8/81/0+ | 31/237/7+ | 7/35/0 | 37/280/7+ | 3/6/0 | 4/11/0 | 490/566/0+ | 213/165/0+ | 213/191/0+ | 227/1401/0+ | 356/287/0+ | 496/436/0+ |
| `switch` | 0/587/0 | 0/232/0 | 0/34/0 | 0/75/0 | 0/27/0 | 0/84/0 | 0/6/0 | 0/6/0 | 0/125/0 | 0/36/0 | 0/37/0 | 0/221/0 | 0/79/0 | 0/89/0 |
| `temporaries` | 1188/11287/382+ | 299/2383/771− | 29/477/52 | 82/643/322− | 44/313/43 | 126/778/334− | 6/82/7 | 12/90/13 | 147/2452/65+ | 58/960/16+ | 51/919/100− | 53/3840/32 | 572/1028/103+ | 307/2088/66+ |
| `undefined` | 1302/13002/285+ | 2261/1127/95+ | 353/193/12+ | 738/289/20+ | 241/153/6+ | 819/382/51+ | 43/56/2+ | 67/54/4+ | 240/2420/22+ | 65/954/19+ | 77/2551/112 | 55/3844/41 | 552/1103/55+ | 313/2130/36+ |
| `warnings` | 340/14183/66+ | 17/3450/16 | 2/555/1 | 5/1037/5 | 0/398/2 | 8/1236/8 | 0/101/0 | 2/123/0 | 79/2590/13+ | 13/1024/1+ | 14/2700/26 | 37/3895/8+ | 11/1681/18 | 186/2293/0+ |

### Where revkit wins, and why

- **Firmware strings and literal pools.** A raw image is read/write/execute
  (Ghidra's raw loader maps it so), and the decompiler prints a string only
  from read-only memory and folds only read-only words: Ghidra's firmware C
  shows no source string at all (`FUN_0801d298(DAT_0800013c, ...)`) and
  reads every constant through its literal pool. revkit takes strings in
  the image and literal-pool words no code writes for constants
  ([firmware.md](firmware.md#constants-in-a-writable-image)): source
  strings shown 1995/3046/0, casts 2527/11319/743, temporaries
  1188/11287/382, undefined types 1302/13002/285, call-site arguments on
  SuperH (calls through pools become direct calls).
- **Prototypes on 64-bit programs.** revkit's inference
  ([infer.md](infer.md)) locks a prototype for every function of a
  stripped x86-64, AArch64 or RISC-V program: parameter type classes
  1657/1763/54, exact signatures 336/3099/39, call-site argument counts
  430/1286/243, undefined types 2261/1127/95.
- **No-return callees** (firmware): DWARF confirms revkit's no-return
  analysis where Ghidra's evidence misses `fw_panic` and assertions
  (418/1358/4), with the gotos and loops that follow from it.
- **Callee-saved registers** (all processors): a global's address kept
  across a call in `r31` or `s0` now types its accesses (PowerPC c_ast
  +5.3 points before the departures above).

### Where revkit loses, and why

- **`noise` on 64-bit programs (12/3092/379).** Locked prototypes make the
  decompiler name what they don't explain: a varargs function's register
  save area (`in_x2`..`in_x7`: correct C, the source's `va_start`), callees
  inferred with a parameter too many (an `in_` value passed on), and
  callees whose float return inference misses (`luaL_checknumber`'s double
  in XMM0: its callers read an `extraout_`). The last two are inference
  errors.
- **`casts` and `temporaries` on 64-bit programs.** Typed prototypes meet
  untyped locals and globals: `(char *)0x0`, `(ulong)param_1`. Some are
  the price of a right type (`param_1[5]` for `*(long *)(param_1 + 0x28)`),
  some of a wrong one.
- **MIPS parameter classes (35/2632/73).** Mostly Ghidra being right by
  accident: missing that an assertion never returns, it merges the
  assertion's message into the first parameter and types it `char *`.
- **Structures** (`members`): neither tool recovers them from a stripped
  binary; every comparison ties.

### The user's ARM firmware

The camera firmware has no source, so it gets the structural checks only
(4,300 functions, master → this branch): no decompiler failures before or
after; string literals 1 → 3,221 and `s_` symbols 2,539 → 51; literal-pool
reads through `*DAT_x` 2,388 → 2,354 (pool words holding RAM or peripheral
addresses stay reads, below); gotos 3,465 → 3,393; `undefinedN` 22,041 →
21,949; warnings 1,273 → 1,894, of which 616 more "Removing unreachable
block" in 21 soft-float routines whose mode word is now a constant (their
branches on it are decided) and 5 more `_` overlap warnings. Inference is
off there: it is a 32-bit ARM image mixing ARM and Thumb (below).

### Held-out

Once, at the end (docs/heldout.md: summary rates only), on the 44 stripped
binaries of the held-out set (bzip2, MuJS, tcc, Mbed TLS, SQLite):

| family | paired | composite W/T/L | p | prototype classes | call-site arguments | undefined | noise | casts |
| --- | ---: | --- | ---: | --- | --- | --- | --- | --- |
| all held-out | 26026 | 15742/5501/4783 (WIN) | 0 | 14447/10635/734 | 4421/10925/476 | 19678/5659/688 | 335/22508/3182 | 5542/7032/13451 |
| ELF clang -O0 | 4645 | 3096/1034/515 (WIN) | 0 | 2896/1712/37 | 491/2408/106 | 3717/877/51 | 8/4318/319 | 613/1642/2390 |
| ELF clang -O2 | 7030 | 3642/1428/1960 (WIN) | 2e-113 | 3509/3068/243 | 1103/2078/137 | 5118/1643/268 | 35/5846/1148 | 1509/1464/4056 |
| ELF gcc -O0 | 3092 | 2172/596/324 (WIN) | 0 | 2076/1015/1 | 10/1804/62 | 2572/504/16 | 4/2851/237 | 495/1096/1501 |
| ELF gcc -O2 | 6401 | 3602/1402/1397 (WIN) | 9.4e-221 | 3688/2537/176 | 1335/2193/162 | 4842/1429/130 | 45/5591/765 | 934/1393/4074 |
| PE clang -O0 | 2453 | 1481/686/286 (WIN) | 4.4e-194 | 946/1427/80 | 355/1504/1 | 1655/717/81 | 153/2096/204 | 724/1050/679 |
| PE clang -O2 | 2405 | 1749/355/301 (WIN) | 1.2e-247 | 1332/876/197 | 1127/938/8 | 1774/489/142 | 90/1806/509 | 1267/387/751 |

Identity with Ghidra on the held-out set's own inputs went from 81.9% to
41.6% (the inferred prototypes); `heldout-rk-decomp-own.json` is lowered
to match.

### Library prototypes and format strings (2026-10-08)

revkit's own library archives ([types.md](types.md#library-prototypes))
in place of Ghidra's `.gdt` for the names they declare, and call-site
prototypes from constant printf/scanf formats
([types.md](types.md#format-strings)). Before: this branch with the
archives hidden (`REVKIT_TYPEINFO_DIR` an empty directory: Ghidra's
`.gdt` alone, as master) and `--no-format-strings`, which is master's
output; after: the branch. W/T/L per paired function (revkit against
Ghidra), the tuning corpus, `decompile-corpus.sh --inputs own -P 2`:

| family | composite before → after | `call_args` before → after | `proto_param_class` before → after | `lib_call_args` before → after | `warnings` before → after | `casts` before → after | `strings` before → after | `undefined` before → after | `noise` before → after |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ALL tuning | 1744/892/848 → 1758/881/845 | 430/1286/243 → 430/1286/243 | 1657/1763/54 → 1657/1763/54 | 1/459/0 → 7/453/0 | 17/3450/16 → 25/3442/16 | 637/1024/1822 → 647/1014/1822 | 90/650/14 → 98/642/14 | 2261/1127/95 → 2265/1126/92 | 12/3092/379 → 12/3091/380 |
| ELF clang -O0 | 304/169/85 → 305/168/85 | 15/237/0 → 15/237/0 | 198/357/3 → 198/357/3 | 0/94/0 → 1/93/0 | 2/555/1 → 2/555/1 | 132/205/221 → 135/202/221 | 8/81/0 → 10/79/0 | 353/193/12 → 354/193/11 | 0/544/14 → 0/544/14 |
| ELF clang -O2 | 496/245/307 → 500/241/307 | 163/377/146 → 163/377/146 | 558/447/33 → 558/447/33 | 0/107/0 → 2/105/0 | 5/1037/5 → 9/1033/5 | 180/258/609 → 180/256/611 | 31/237/7 → 34/234/7 | 738/289/20 → 738/289/20 | 4/854/189 → 4/854/189 |
| ELF gcc -O0 | 197/127/76 → 198/126/76 | 2/139/0 → 2/139/0 | 120/279/1 → 120/279/1 | 0/71/0 → 0/71/0 | 0/398/2 → 0/398/2 | 75/147/178 → 78/143/179 | 7/35/0 → 7/35/0 | 241/153/6 → 242/153/5 | 1/385/14 → 1/385/14 |
| ELF gcc -O2 | 644/278/330 → 652/273/327 | 243/466/97 → 243/466/97 | 735/502/15 → 735/502/15 | 0/125/0 → 3/122/0 | 8/1236/8 → 12/1232/8 | 202/340/710 → 206/339/707 | 37/280/7 → 40/277/7 | 819/382/51 → 821/381/50 | 5/1101/146 → 5/1100/147 |
| PE clang -O0 | 44/39/18 → 44/39/18 | 1/32/0 → 1/32/0 | 19/82/0 → 19/82/0 | 0/20/0 → 0/20/0 | 0/101/0 → 0/101/0 | 26/51/24 → 26/51/24 | 3/6/0 → 3/6/0 | 43/56/2 → 43/56/2 | 1/95/5 → 1/95/5 |
| PE clang -O2 | 59/34/32 → 59/34/32 | 6/35/0 → 6/35/0 | 27/96/2 → 27/96/2 | 1/42/0 → 1/42/0 | 2/123/0 → 2/123/0 | 22/23/80 → 22/23/80 | 4/11/0 → 4/11/0 | 67/54/4 → 67/54/4 | 1/113/11 → 1/113/11 |

Call-site argument counts to the program's own functions and parameter
classes hold exactly (the gate): those come from inference, which reads
its own signature database, not the decompiler's library facts. The
gains are where library calls show: `lib_call_args` (a printf whose
format says one argument passes one), string literals (a format's string
argument as `"path"`, not `&DAT_...`), casts (`(ulong)` on an `int` a
`%d` names), and warnings (Ghidra's archive leaves import thunks'
convention unknown, "WARNING: Unknown calling convention", which
revkit's archives don't). Most calls already had the right count at both
tools (453 ties): the decompiler finds a varargs call's register
arguments well on these ABIs. The PE families tie throughout: their C
changes in the mingw start-up code (no truth), and mingw's CRT calls in
the programs were already right.

Corpus gates: Ghidra's inputs (`rk-decomp.json`) and the reference's
function list (`rk-decomp-refonly.json`) are unchanged (format strings
are for revkit's inputs only), the firmware gates hold, and the demangle
gate holds. Identity with Ghidra's C under revkit's inputs
(`rk-decomp-own.json`) drops, c_tokens 43.3% → 28.5% and c_ast 55.5% →
50.0% of 9,812 functions: of 862 stripped functions whose C changed, the
commonest differences are import thunks losing Ghidra's unknown-convention
warning (513) and Ghidra's `__cdecl`/`__stdcall` on x86-64 PE names
(131, the same ABI: revkit's parser records no convention there, as
compilers don't), the headers' parameter names and types where Ghidra's
archive differs (`__libc_start_main`'s `main`, `argc`, `argv`), `vsnprintf`'s `va_list` is the `__va_list_tag *` it is,
and format calls pass the format's arguments; the baseline is lowered to
match, as the benchmark above says the C is closer to the source: the
composite improves in every ELF family and holds on PE (the only metric
moves the other way are single functions: 2 more cast losses in ELF
clang -O2, one more `noise` loss).

## The judged sample

`scripts/decomp-quality.py --judge build/judge` writes a blinded packet:
per family (the six tuning groups and the six firmware processors; not the
user's firmware, which has no source), 40 functions drawn with seed
20261005, stratified by the source function's length, among the functions
whose two decompilations differ. Each item (`build/judge/<family>/<item>.md`)
has the original source and the two decompilations as X and Y in random
order; `build/judge/items.json` lists the items and, per family, how many
paired functions there were and how many were identical (ties by
definition); `answers-template.csv` is the answer sheet; the key is kept
apart in `build/judge-key/key.json`. Judges compare X and Y against the
source for correctness first and readability second (`README.md` there).

## What was tried and left out

- **Inference on 32-bit processors** (ARM, MIPS, PowerPC, SuperH, Xtensa,
  68000 conventions as tables): the per-function metrics favoured it, but
  the C read worse. With ints and pointers the same size, inference typed
  sizes and block numbers as pointers (littlefs's `lfs_bd_read`: all eight
  parameters). A raw ARM image mixing ARM and Thumb also needs discovery's
  Thumb ranges in the inference decompiler, which it doesn't get yet.
- **Folding every literal-pool word**, as an ELF's read-only `.text` makes
  Ghidra do: with an address in RAM or in a peripheral region constant,
  the decompiler forwards a store there to later loads, so a register
  polled after a write became an infinite loop on the camera firmware
  (whose regions aren't declared volatile), and in an image at address 0
  small numbers read as pointers into it.
- **Inference's later rounds' parameters** (a function passing its
  arguments on to a callee known only later): taking them dropped
  AArch64 arity from 88% to 56% (callees with a parameter too many pass it
  up the call graph).

## Blinded judging: results (2026-10-07)

The packet above (480 items: 12 families x 40 functions whose two
decompilations differ, X and Y in random order) was judged blind by two
judges, each a separate Claude agent given only the packet and its README,
never the key: one took the six desktop families, the other the six
firmware ones. Their answers were then unblinded with `build/judge-key`.
Wins for revkit / Ghidra / same, with a two-sided sign test on the
decided items:

| Group | Correctness | p | Readability | p |
| --- | --- | ---: | --- | ---: |
| All 480 | **129** / 33 / 318 | 1e-14 | **271** / 68 / 141 | 8e-30 |
| Desktop (ELF and PE, gcc and clang, -O0 and -O2) | 39 / 24 / 177 | 0.08 | **107** / 57 / 76 | 1e-4 |
| Firmware (six processors) | **90** / 9 / 141 | 6e-18 | **164** / 11 / 65 | 4e-36 |
| elf-clang-o0 | 6 / 1 / 33 | 0.13 | **24** / 7 / 9 | 0.003 |
| elf-clang-o2 | 8 / 10 / 22 | 0.82 | 13 / 11 / 16 | 0.84 |
| elf-gcc-o0 | 5 / 6 / 29 | 1 | 15 / 14 / 11 | 1 |
| elf-gcc-o2 | **10** / 1 / 29 | 0.01 | 17 / 10 / 13 | 0.25 |
| pe-clang-o0 | 3 / 3 / 34 | 1 | **23** / 7 / 10 | 0.005 |
| pe-clang-o2 | 7 / 3 / 30 | 0.34 | 15 / 8 / 17 | 0.21 |
| fw-cortexm | **11** / 0 / 29 | 0.001 | **35** / 0 / 5 | 6e-11 |
| fw-m68k | 3 / 1 / 36 | 0.63 | **24** / 0 / 16 | 1e-7 |
| fw-mips | 8 / 6 / 26 | 0.79 | **19** / 7 / 14 | 0.03 |
| fw-ppc | 2 / 2 / 36 | 1 | 12 / 4 / 24 | 0.08 |
| fw-sh4 | **40** / 0 / 0 | 2e-12 | **40** / 0 / 0 | 2e-12 |
| fw-xtensa | **26** / 0 / 14 | 3e-8 | **34** / 0 / 6 | 1e-10 |

Reading it:

- revkit is never significantly worse. Ghidra wins one family on
  correctness by a non-significant 10 to 8 (elf-clang-o2).
- On desktop binaries revkit is ahead on readability, with correctness
  mostly tied. On firmware it is far ahead on both, and on SuperH and
  Xtensa it wins nearly every item.
- What the judges' notes credit: call arguments and return values (one side
  drops or invents arguments, or loses a return), types (pointer widths,
  int64 results, array indexing instead of raw offsets), callees and
  constants resolved, no-return calls such as assert, and inline string
  literals.

Limits: the judges are language models, not people; each family had one
judge, so there is no measure of agreement between judges; and the items
are the functions where the two tools differ (identical ones are ties by
construction, `items.json`).
