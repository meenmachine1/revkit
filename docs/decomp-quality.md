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
| `members` | member accesses (`p->f`) against the source's count | inlined callees' accesses, which the source doesn't count (revkit's inferred structures show them, 2026-10-18) |
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

- **`noise` on 64-bit programs (12/3092/379; 11/3190/282 since
  2026-10-17, below).** Locked prototypes make the
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
- **Structures** (`members`): since 2026-10-18 inference composes them
  for passed-on pointers on 64-bit programs (below); firmware still ties.

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

### Re-measured, and inference's call graph fixed (2026-10-17)

Measured again on master at 5060db44 (the round after 0.1.2) with the
same commands, paired metrics only (no judges; the held-out sets were not
used): **every number is the same as above**, tuning composite
1758/881/845 and firmware 3892/10223/515 in every family. What landed
since doesn't reach `rk-lift --analyze --decompile` on these corpora:
register values, fallthrough overrides, data settings, debug files and
BSim apply are the user's facts (or need debug links the stripped corpus
doesn't have); MIPS `gp` and the PowerPC TOC come from an ELF's symbols,
and the firmware images are raw (the tuning corpus has neither
processor); the shared SLEIGH engines and the scrub's fixes change no
output.

**Where revkit loses.** Firmware loses on no metric. On the tuning corpus
the composite's 845 losses were driven by casts (in 739 of them),
temporaries (476), locals (370), length (308), `noise` (263) and
call-site argument counts (157), and two binaries, Lua on x86-64 gcc-O2
and on AArch64 clang-O2, held about half of each. The C side by side with
the source showed the causes in inference (the decompiler's prototypes on
stripped 64-bit programs), each fixed on master:

| commit | cause | tuning composite after | metrics that moved most (W/T/L) |
| --- | --- | --- | --- |
| (5060db44) | | 1758/881/845 | |
| 0f40be2c | at a call locked to the callee's previous prototype the decompiler casts a caller's pointer to the callee's integer parameter (`(ulong)param_1`), and the observation read the cast's type, so `lua_State *` stayed `long`/`ulong` in a fifth of the functions taking it | 1830/842/812 | parameter classes 1657/1763/54 → 1838/1583/53, casts 647/1014/1822 → 740/959/1784 |
| 8d067fe3 | inference's call graph didn't know the functions only the no-return evidence finds (luaX_syntaxerror, luaD_throw on AArch64), so it decompiled their callers on into the next function's code and took its argument registers as parameters (error_expected with five, luaL_checkstack with eight), which spread up the call graph | 1879/836/769 | parameter counts 90/3320/64 → 90/3351/33, call-site arguments 430/1286/243 → 459/1319/181, returns 195/3216/63 → 195/3250/29 |
| 0d518887 | a parameter only passed on unchanged (luaL_checklstring's `len` to lua_tolstring) is invisible in round 0, where the decompiler takes only registers written before a call as an unknown callee's arguments | 1897/821/766 | call-site arguments → 476/1392/91, string literals 98/646/10 → 102/650/2 |
| 120d102b | inference's decompilations followed a jump to another function's entry into its code (the final C's inputs make it a tail call, `CALL_RETURN`): a jump into luaL_error took in its register save area as six parameters | 1926/821/737 | call-site arguments → 504/1430/25, parameter counts → 115/3348/11, noise → 11/3190/282 |
| 42f71fee | a pointer passed on unchanged had each function's own target type (`lua_State *` as `long *` here, `char *` there), so every call between them cast it | 1957/809/718 | casts → 668/1069/1746 |

`rk-infer`'s gate (`tools/rk-infer/score.py`) moved with them: arity
90.3% → 92.9% (AArch64 87.9% → 94.2%), signature 13.6% → 13.6%, every
architecture at or above its baseline. The firmware corpus doesn't
change: inference is off for 32-bit processors there. A sixth candidate,
a quorum for a function-pointer table's return type (one member's
leaked pointer return typed all of Lua's C functions `long *`), was
measured and left out: after the fixes above the table's members agree
on `int`, and the quorum only turned that into `long`.

After (master at 42f71fee), per family:

| family | paired | before W/T/L | after W/T/L | after p |
| --- | ---: | --- | --- | ---: |
| ALL firmware | 14630 | 3892/10223/515 (WIN) | 3892/10223/515 (WIN) | 0 |
| ALL tuning | 3484 | 1758/881/845 (WIN) | 1957/809/718 (WIN) | 1.7e-131 |
| ELF clang -O0 | 558 | 305/168/85 (WIN) | 321/154/83 (WIN) | 4.1e-34 |
| ELF clang -O2 | 1048 | 500/241/307 (WIN) | 597/227/224 (WIN) | 6.6e-40 |
| ELF gcc -O0 | 400 | 198/126/76 (WIN) | 208/117/75 (WIN) | 1.3e-15 |
| ELF gcc -O2 | 1252 | 652/273/327 (WIN) | 727/238/287 (WIN) | 1.2e-44 |
| PE clang -O0 | 101 | 44/39/18 (WIN) | 45/39/17 (WIN) | 0.0005 |
| PE clang -O2 | 125 | 59/34/32 (WIN) | 59/34/32 (WIN) | 0.0061 |

and per metric on the tuning corpus (+ and − mark p < 0.01; the firmware
columns are those of the table above):

| metric | ALL tuning | ELF clang -O0 | ELF clang -O2 | ELF gcc -O0 | ELF gcc -O2 | PE clang -O0 | PE clang -O2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `call_args` | 504/1430/25+ | 15/237/0+ | 210/461/15+ | 2/139/0 | 270/526/10+ | 1/32/0 | 6/35/0 |
| `casts` | 668/1069/1746− | 143/199/216− | 175/286/586− | 82/143/175− | 220/361/671− | 26/54/21 | 22/26/77− |
| `constants` | 13/513/15 | 2/145/4 | 5/89/1 | 0/110/4 | 4/116/6 | 2/33/0 | 0/20/0 |
| `failed` | 1/3483/0 | 0/558/0 | 1/1047/0 | 0/400/0 | 0/1252/0 | 0/101/0 | 0/125/0 |
| `globals_named` | 0/425/0 | 0/78/0 | 0/151/0 | 0/53/0 | 0/143/0 | - | - |
| `gotos` | 23/3418/12 | 0/557/1 | 7/1038/2 | 0/399/1 | 16/1215/7 | 0/95/0 | 0/114/1 |
| `length` | 420/2569/464 | 73/458/27+ | 103/775/169− | 51/326/23+ | 130/894/214− | 13/79/3 | 50/37/28 |
| `lib_call_args` | 7/453/0 | 1/93/0 | 2/105/0 | 0/71/0 | 3/122/0 | 0/20/0 | 1/42/0 |
| `locals_class` | 534/2429/490 | 80/435/43+ | 154/704/189 | 77/295/28+ | 208/819/211 | 8/81/6 | 7/95/13 |
| `loops` | 3/3446/4 | 0/558/0 | 2/1045/0 | 0/400/0 | 1/1233/4 | 0/95/0 | 0/115/0 |
| `members` | 5/1688/21− | 0/265/0 | 3/521/13 | 0/154/0 | 0/662/7 | 1/27/0 | 1/59/1 |
| `noise` | 11/3190/282− | 0/542/16− | 4/942/101− | 1/385/14− | 4/1112/136− | 1/95/5 | 1/114/10 |
| `noreturn` | 0/182/4 | - | 0/91/0 | - | 0/91/4 | - | - |
| `proto_arity` | 115/3348/11+ | 6/552/0 | 34/1003/1+ | 5/389/6 | 51/1199/2+ | 4/97/0 | 15/108/2+ |
| `proto_exact` | 337/3098/39+ | 107/434/17+ | 39/999/0+ | 98/287/15+ | 51/1197/4+ | 29/69/3+ | 13/112/0+ |
| `proto_param_class` | 1883/1567/24+ | 218/337/3+ | 655/377/6+ | 134/265/1+ | 829/411/12+ | 19/82/0+ | 28/95/2+ |
| `proto_ret_class` | 400/3025/49+ | 66/491/1+ | 102/912/24+ | 62/338/0+ | 145/1083/24+ | 4/97/0 | 21/104/0+ |
| `proto_return` | 199/3241/34+ | 16/542/0+ | 65/961/12+ | 8/392/0+ | 97/1134/21+ | 2/99/0 | 11/113/1+ |
| `strings` | 102/652/0+ | 10/79/0+ | 35/240/0+ | 7/35/0 | 43/281/0+ | 3/6/0 | 4/11/0 |
| `switch` | 0/232/0 | 0/34/0 | 0/75/0 | 0/27/0 | 0/84/0 | 0/6/0 | 0/6/0 |
| `temporaries` | 316/2423/714− | 32/474/52 | 95/696/256− | 46/311/43 | 126/770/342− | 6/82/7 | 11/90/14 |
| `undefined` | 2277/1112/94+ | 361/186/11+ | 735/288/24+ | 245/150/5+ | 825/379/48+ | 44/55/2+ | 67/54/4+ |
| `warnings` | 25/3440/18 | 2/555/1 | 9/1032/6 | 0/398/2 | 12/1231/9 | 0/101/0 | 2/123/0 |

Identity with Ghidra under revkit's own inputs (`rk-decomp-own.json`)
is c_ast 49.98% → 50.01%. Its baseline was re-saved in 0f40be2c: master
had already fallen below it by one or two functions in each AArch64 debug
build (the C runtime's `_init` and import stubs, since library
prototypes stopped applying to the C runtime's own code), and the fixes
here move no identity rate down. The other gates (Ghidra's inputs 100%,
the reference function list, rk-lift, rk-infer, demangle, the C parser
round trip, firmware, detection) hold.

**What's left.** The composite's 718 losses are now casts (644 of
them), temporaries (400), locals (322), length (267) and `noise` (160);
call-site arguments (19) and parameter classes (17) are nearly gone.

- **Structure pointers typed `long *`.** Of the casts revkit prints that
  Ghidra doesn't, the commonest by far are `*(T *)((long)param_1 + off)`
  (about 2,300) and the same through locals (1,400): a struct pointer is
  a pointer to its first word, so every other field takes two casts where
  Ghidra's untyped `param_1 + off` takes one. The fix is structures:
  inference composing one per class of passed-on pointers from their
  accesses (`infer::pointer_accesses`, `compose_structure`, which the
  backend's Auto Structure already uses), so fields print as
  `param_1->field_0x10` and `members` stops losing. That is a new feature,
  not a tweak, and is the next step.
- **Null pointers.** `(char *)0x0` and `(long *)0x0` account for about
  1,600 more: the price of a typed parameter (Ghidra passes `0` to an
  untyped one), which the cast metric counts like any other.
- **Floats.** Most remaining `noise` is a float register read as
  `in_XMM0_Qa`/`in_d0` or left as `extraout_d0`: callees whose double
  return or parameter round 0 can't see (`luaL_checknumber`), the known gap
  in [infer.md](infer.md).
- **Locals and temporaries** on -O2 builds follow the prototypes (more
  typed values, more declared temporaries) and the source's own locals
  don't map to registers; they move little without the structures above.

### Inferred structures for passed-on pointers (2026-10-18)

The fix "What's left" above names: inference composes one structure per
class of pointers that are one value (passed on unchanged, returned,
loaded from one field of one structure) from every access through them,
and types the class's parameters and returns with it
([infer.md](infer.md#structures)). Before: this branch with
`--no-infer-structures` (the same C as master at 16745f16: the tuning
composite reproduces 1957/809/718 exactly); after: the branch. Same
commands, paired metrics only (no judges; the held-out sets were not
used).

The casts the section counted: `*(T *)((long)param_1 + off)` 2,842 → 77,
the same through locals 1,263 → 333; member accesses (`->`) in revkit's
C 84 → 29,674. Per family:

| family | paired | before W/T/L | after W/T/L | after p |
| --- | ---: | --- | --- | ---: |
| ALL firmware | 14630 | 3892/10223/515 (WIN) | 3892/10223/515 (WIN) | 0 |
| ALL tuning | 3484 | 1957/809/718 (WIN) | 2159/667/658 (WIN) | 5.2e-185 |
| ELF clang -O0 | 558 | 321/154/83 (WIN) | 358/127/73 (WIN) | 3.2e-46 |
| ELF clang -O2 | 1048 | 597/227/224 (WIN) | 668/170/210 (WIN) | 2.7e-56 |
| ELF gcc -O0 | 400 | 208/117/75 (WIN) | 229/101/70 (WIN) | 7.1e-21 |
| ELF gcc -O2 | 1252 | 727/238/287 (WIN) | 807/193/252 (WIN) | 3.1e-68 |
| PE clang -O0 | 101 | 45/39/17 (WIN) | 46/38/17 (WIN) | 0.00034 |
| PE clang -O2 | 125 | 59/34/32 (WIN) | 51/38/36 (**tie**) | 0.13 |

Per metric, before → after where it moved (+ and − mark p < 0.01):

| metric | ALL tuning | ELF clang -O0 | ELF clang -O2 | ELF gcc -O0 | ELF gcc -O2 | PE clang -O0 | PE clang -O2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `casts` | 668/1069/1746− → 1199/864/1420− | 143/199/216− → 198/181/179 | 175/286/586− → 385/206/456 | 82/143/175− → 100/138/162− | 220/361/671− → 464/265/523 | 26/54/21 → 31/50/20 | 22/26/77− → 21/24/80− |
| `members` | 5/1688/21− → 672/681/361+ | 0/265/0 → 141/114/10+ | 3/521/13 → 183/178/176 | 0/154/0 → 57/97/0+ | 0/662/7 → 268/235/166+ | 1/27/0 → 9/19/0+ | 1/59/1 → 14/38/9 |
| `locals_class` | 534/2429/490 → 766/2182/505+ | 80/435/43+ → 107/410/41+ | 154/704/189 → 244/604/199 | 77/295/28+ → 84/287/29+ | 208/819/211 → 310/712/216+ | 8/81/6 → 9/80/6 | 7/95/13 → 12/89/14 |
| `temporaries` | 316/2423/714− → 420/2254/779− | 32/474/52 → 43/463/52 | 95/696/256− → 141/615/291− | 46/311/43 → 50/310/40 | 126/770/342− → 164/700/374− | 6/82/7 | 11/90/14 → 16/84/15 |
| `length` | 420/2569/464 → 437/2399/617− | 73/458/27+ → 76/441/41+ | 103/775/169− → 94/701/252− | 51/326/23+ → 49/326/25+ | 130/894/214− → 156/815/267− | 13/79/3 → 13/78/4 | 50/37/28 → 49/38/28 |
| `undefined` | 2277/1112/94+ → 2406/1016/61+ | 361/186/11+ → 369/177/12+ | 735/288/24+ → 781/258/8+ | 245/150/5+ → 252/143/5+ | 825/379/48+ → 893/329/30+ | 44/55/2+ | 67/54/4+ |
| `proto_param_class` | 1883/1567/24+ → 1888/1563/23+ | | | | 829/411/12+ → 834/407/11+ | | |
| `proto_ret_class` | 400/3025/49+ → 407/3018/49+ | | | | 145/1083/24+ → 152/1076/24+ | | |
| `constants` | 13/513/15 → 11/507/23 | 2/145/4 → 1/143/7 | 5/89/1 → 5/86/4 | | 4/116/6 → 3/115/8 | | |
| `warnings` | 25/3440/18 → 25/3437/21 | | | | 12/1231/9 → 12/1228/12 | | |

Every other metric is unchanged. Reading it:

- **Casts** improve in every ELF family (ELF clang -O0, clang -O2 and gcc
  -O2 no longer lose significantly); the 1,420 losses left are mostly
  null pointers (`(astruct_1 *)0x0`, `(char *)0x0`: a typed pointer field
  takes one where Ghidra's untyped word takes `0`), stores wider than a
  field (`*(undefined8 *)&p->field_0x18 = 0`, an inlined `memset` over
  an `int` and its padding), and calls between classes of one type that
  never meet (Lua's `expdesc *` is five classes, so a call from one to
  another casts).
- **Members** win (672/681/361, from 5/1688/21): the fields print as
  `p->field_0x10`. The losses are -O2 code with inlined callees (cJSON's
  `cJSON_Create*Array` with `cJSON_New_Item` inlined zero every field of
  every new node): the source counts its own few accesses, not the
  inlined ones, and Ghidra's 0 is nearer.
- **Locals** win (`astruct_4 *paVar3` where the source has `StkId`);
  **temporaries** move both ways (W−L −398 → −359), losing more in the
  -O2 families: values of distinct struct types no longer share one
  variable, and the decompiler splits struct copies into per-field ones.
- **Length** now loses (437/2399/617, p < 0.01), in the -O2 families
  only. In the 247 functions it newly loses, 825 more lines: statements
  (+491: the decompiler splits a 16-byte copy or a zeroing store into one
  per field, `p->field_0x0 = 0; p->field_0x8 = 0; …`, where a struct is
  typed, as it does with debug-info types), lines wrapped at 100 columns
  (+180: `param_1->field_0x18->field_0x40` is longer than `param_1[3]`),
  piece assignments (+104: a stack object typed with a structure the
  caller writes at other widths, `local_40._8_8_ = ...`) and
  declarations (+42).
- **PE clang -O2 falls from a win to a tie** (59/34/32 → 51/38/36, p
  0.13): of the 12 of its 125 functions that went from a win to a tie or
  a loss, 7 are cJSON's array constructors with inlined `cJSON_New_Item`
  (`members`, above) and 5 move on locals, temporaries and length; 4
  went the other way. This is the one requirement the change doesn't
  meet; no rule that fixes it without undoing the structures elsewhere
  was found.
- `constants` loses 8 functions where an array index (`param_1[0x22]`)
  showed a number the source also has; `warnings` 3 more.
- **Firmware is unchanged**: inference is off for 32-bit processors
  (below), and structures come from inference's classes.

`rk-infer`'s gate (`tools/rk-infer/score.py`): arity 92.9%, signature
13.6% (+8.9 pp), every architecture at or above its baseline (x86-64
signature 10.8% → 10.7%: main's `argv`, typed by its library callback,
had been taken for a structure; fixed, a callback's prototype is never
replaced). Identity with Ghidra under revkit's own inputs
(`rk-decomp-own.json`) c_ast 50.01% → 49.90% (c_tokens 28.50% → 28.38%: 11 of 9,812 functions); the baseline is
lowered to match, as the benchmark above says the C is closer to the
source in every ELF family. The other gates (Ghidra's inputs, the
reference function list, rk-lift, firmware) hold. Timing: `rk-infer` on
`/usr/bin/cmake` -j 6, 368 s and 1.65 GB with structures, 398 s and
1.62 GB without (4,318 structures, 8,465 parameters and 1,425 returns
typed); `/usr/bin/bash` 75 s either way; the tuning corpus decompiles in
77 s with them, 109 s without (two binaries at once, each in order).

**32-bit processors** (since 2026-10-21 inference is on for ARM, MIPS
and PowerPC: [below](#inference-on-32-bit-arm-mips-and-powerpc-2026-10-21)). Inference was off there (`infer::supports`: with
ints and pointers one size it typed sizes as pointers), so structures
don't reach the firmware corpus, where `members` ties in every family
(2/7820/0) and the casts already win. The structure pass needs only the
call graph's pass-through edges and the accesses, not inference's
integer-versus-pointer choices: running it on the decompiler's own
prototypes for 32-bit targets (a parameter with field accesses is a
pointer whatever its width) is worth a follow-up; it needs the ARM, MIPS,
PowerPC, SuperH and Xtensa argument registers (the conventions tried in
"What was tried", below) and discovery's Thumb ranges in inference's
decompiler.

**What's left.**

- **Length and temporaries on -O2 builds**: per-field copies and stores
  are the decompiler's (its "split combined structure fields"); a
  structure's copy as one assignment would need the decompiler's
  splitting off for inferred types only.
- **One type, several classes**: classes that never pass a value to each
  other stay apart (Lua's expdesc, TValue), so calls between them cast;
  joining classes by layout alone risks merging different structures of
  one shape.
- **Locals not from a parameter or a call** (a `malloc` result kept in a
  local, a stack object whose address is passed) aren't classed; a stack
  object passed to a structure parameter takes the structure, and the
  caller's writes at other widths become pieces.
- **Fields of fields**: observations record one level of loaded values
  (`p->a->b` gets `b`'s accesses only through classes that meet `p->a`'s
  value elsewhere); embedded structures (`&L->base_ci` passed on) and
  unions are composed as overlapping fields.
- **Null pointers and floats**: as before.

### Inference on 32-bit ARM, MIPS and PowerPC (2026-10-21)

Inference had been off for 32-bit processors (with ints and pointers one
size it typed sizes as pointers, and it decoded a raw image's Thumb code
as ARM). It is on now for ARM and Thumb, MIPS o32 and PowerPC SysV, with
the fixes [infer.md](infer.md#32-bit-processors) lists: Thumb decoding in
inference's decompiler, Thumb pointers, thunks' prototypes, constants,
callers' pointer votes, word priors, uses the decompiler drops (an SDK's
interrupt restore), parameters no caller passes (`push {r3, lr}`),
stack-only spills, PIC prologues, structures through word parameters,
and soft-float library prototypes. Before: this branch with
`--no-infer-prototypes`, the same C as master for these images (inference
was off there); after: the branch. Paired metrics only (no judges; the
held-out sets were not used); the tuning corpus (64-bit) gives
byte-identical C, so its numbers are those above.

| family | paired | before W/T/L | after W/T/L | after p |
| --- | ---: | --- | --- | ---: |
| ALL firmware | 14630 | 3892/10223/515 (WIN) | 8548/4611/1471 (WIN) | 0 |
| fw cortexm | 2722 | 812/1843/67 (WIN) | 1899/454/369 (WIN) | 2.9e-247 |
| fw mips | 2739 | 303/2219/217 (WIN) | 1679/680/380 (WIN) | 3.9e-194 |
| fw ppc | 3940 | 402/3481/57 (WIN) | 2595/797/548 (WIN) | 1.4e-316 |
| fw m68k | 1038 | 296/723/19 (WIN) | (unchanged) | |
| fw sh4 | 1712 | 1217/423/72 (WIN) | (unchanged) | |
| fw xtensa | 2479 | 862/1534/83 (WIN) | (unchanged) | |

Per metric, before → after where it moved (+ and − mark p < 0.01):

| metric | ALL firmware | cortexm | mips | ppc | m68k | sh4 | xtensa |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `call_args` | 529/9791/200+ → 2918/7148/454+ | 11/2081/13 → 941/1036/128+ | 104/1927/116 → 728/1320/99+ | 28/3056/4+ → 863/2065/160+ | 67/721/4+ | 171/379/62+ | 148/1627/1+ |
| `casts` | 2551/11328/751+ → 3781/5638/5211− | 305/2281/136+ → 598/690/1434− | 198/2373/168 → 518/821/1400− | 123/3718/99 → 740/1171/2029− | 91/922/25+ | 1275/390/47+ | 559/1644/276+ |
| `constants` | 78/2099/3+ → 95/2013/72 | 15/410/0+ → 26/369/30 | 2/199/1 → 4/188/10 | 1/646/0 → 5/612/30− | 1/189/0 | 28/254/1+ | 31/401/1+ |
| `failed` | 0/14630/0 | 0/2722/0 | 0/2739/0 | 0/3940/0 | 0/1038/0 | 0/1712/0 | 0/2479/0 |
| `globals_named` | 25/1106/1+ → 31/1096/1+ | 0/4/0 | 6/367/1 → 10/361/1 | 7/405/0 → 9/401/0+ | 12/330/0+ | - | - |
| `gotos` | 242/12530/127+ → 269/12488/142+ | 42/2627/34 → 47/2615/41 | 54/996/20+ → 58/990/22+ | 56/3852/18+ → 74/3828/24+ | 26/1000/8+ | 4/1686/15 | 60/2369/32+ |
| `length` | 1370/10296/1233+ → 2289/8564/2046+ | 226/2291/186 → 550/1667/486 | 102/847/121 → 186/655/229 | 117/3712/97 → 628/2796/502+ | 51/927/56 | 463/840/402 | 411/1679/371 |
| `lib_call_args` | 0/7/0 | - | - | 0/7/0 | - | - | - |
| `locals_class` | 981/11511/407+ → 2506/8992/1401+ | 155/2473/75+ → 643/1590/470+ | 60/927/83 → 255/645/170+ | 53/3849/24+ → 895/2495/536+ | 54/965/15+ | 419/1144/142+ | 240/2153/68+ |
| `loops` | 252/12587/60+ → 253/12581/65+ | 49/2649/5+ → 49/2648/6+ | 64/985/21+ → 64/983/23+ | 48/3866/12+ → 49/3863/14+ | 34/992/8+ | 0/1702/3 | 57/2393/11+ |
| `members` | 2/7843/0 → 1860/5638/347+ | 0/1545/0 → 581/862/102+ | 1/669/0 → 375/223/72+ | 0/2393/0 → 903/1317/173+ | 1/664/0 | 0/999/0 | 0/1573/0 |
| `noise` | 269/14308/53+ → 415/13501/714− | 29/2693/0+ → 76/2388/258− | 21/2683/35 → 40/2462/237− | 20/3909/11 → 100/3628/212− | 15/1018/5 | 0/1710/2 | 184/2295/0+ |
| `noreturn` | 418/1363/0+ | 67/301/0+ | 169/175/0+ | 63/301/0+ | 66/272/0+ | 53/57/0+ | 0/257/0 |
| `proto_arity` | 29/14582/19 → 587/13844/199+ | 3/2713/6 → 299/2361/62+ | 4/2729/6 → 106/2546/87 | 5/3935/0 → 165/3732/43+ | 11/1023/4 | 0/1712/0 | 6/2470/3 |
| `proto_exact` | 10/14617/3 → 489/14076/65+ | 3/2719/0 → 101/2604/17+ | 2/2735/2 → 167/2542/30+ | 0/3940/0 → 216/3707/17+ | 0/1038/0 | 2/1709/1 | 3/2476/0 |
| `proto_param_class` | 88/14434/108 → 4582/9797/251+ | 7/2708/7 → 1411/1214/97+ | 35/2631/73− → 1217/1449/73+ | 13/3921/6 → 1921/1960/59+ | 13/1016/9 | 7/1700/5 | 13/2458/8 |
| `proto_ret_class` | 118/14471/41+ → 1042/13121/467+ | 21/2692/9 → 305/2237/180+ | 36/2688/15+ → 286/2348/105+ | 43/3883/14+ → 433/3328/179+ | 4/1034/0 | 11/1698/3 | 3/2476/0 |
| `proto_return` | 105/14499/26+ → 799/13622/209+ | 2/2716/4 → 236/2414/72+ | 38/2693/8+ → 218/2446/75+ | 57/3870/13+ → 337/3542/61+ | 4/1034/0 | 1/1710/1 | 3/2476/0 |
| `strings` | 2110/2954/0+ | 605/473/0+ | 213/191/0+ | 227/1401/0+ | 213/165/0+ | 356/288/0+ | 496/436/0+ |
| `switch` | 0/588/0 | 0/126/0 | 0/37/0 | 0/221/0 | 0/36/0 | 0/79/0 | 0/89/0 |
| `temporaries` | 1191/11325/383+ → 2174/8909/1816+ | 149/2489/65+ → 521/1555/627− | 51/919/100− → 142/659/269− | 53/3840/33 → 573/2618/735− | 58/960/16+ | 573/1029/103+ | 307/2088/66+ |
| `undefined` | 1343/13010/277+ → 7721/6474/435+ | 279/2429/14+ → 2080/588/54+ | 77/2550/112 → 1869/741/129+ | 57/3842/41 → 2842/956/142+ | 65/954/19+ | 552/1105/55+ | 313/2130/36+ |
| `warnings` | 342/14220/68+ → 361/14189/80+ | 80/2625/17+ → 84/2617/21+ | 14/2699/26 → 18/2693/28 | 37/3895/8+ → 48/3878/14+ | 13/1024/1+ | 12/1684/16 | 186/2293/0+ |

Reading it:

- **Prototypes** win in every measure: parameter classes (4582 wins, 251
  losses), arity (587/199), returns, return classes and exact signatures,
  and calls to the program's functions pass the right count far more
  often (`call_args` 2918/7148/454).
- **Members** win (1860/5638/347, from 2/7843/0): structures through word
  parameters print `p->field_0x10`. **Undefined types** win much more
  (7721/6474/435).
- **Casts lose** in the three families, where they won or tied (ALL
  firmware 2551/11328/751+ → 3781/5638/5211−). Null pointers compared or
  passed (`p != (astruct_15 *)0x0`, where Ghidra's untyped word takes
  `0`) are about a third of the difference; without them casts still
  lose (4067/5838/4725). The rest are conversions between a typed value
  and a parameter of another type: a pointer loaded from a literal pool
  (an untyped word) passed to a structure parameter, a pointer passed to
  an `int` parameter that the callers' votes kept an integer, a
  structure's address passed where a callee was typed `int *`. This is
  the 64-bit tuning corpus's profile too (its casts lose since
  inference).
- **Noise loses** (269/14308/53+ → 415/13501/714−): `extraout_` values
  after calls (registers GCC keeps live across a call it knows doesn't
  clobber them, `-fipa-ra`, and the high word of a 64-bit result that a
  locked 32-bit return says is clobbered) and `in_` values where a callee
  kept a parameter only some callers pass, or a stack word it reads.
- **Temporaries** lose in the three families (the 64-bit tuning
  families' profile: typed values don't share variables); ALL firmware
  still wins (2174/8909/1816+). `constants` loses in ppc (5/612/30):
  constants passed to typed parameters print as casts or characters.
- `strings`, `noreturn`, `loops` and `gotos` are unchanged or better.

**The ARM fixture** (tests/data/arm32: two ARMv5TE images, -O2 and -Os,
ARM and Thumb code, C and C++; Ghidra's reference from `ghidra_export.py
--firmware-corpus` on the fixture's manifest, which `decomp-quality.py`
takes with `--firmware-corpus`, its sources named by the manifest's
`src_root`): composite 7/83/0 → 44/26/20 (WIN, p 0.0037); parameter
classes 0/90/0 → 26/60/4+, members 0/52/0 → 14/38/0+, undefined
4/86/0 → 47/43/0+; casts 5/83/2 → 22/38/30 and noise 0/90/0 → 6/77/7 (not
significant on 90 functions). The SDK restore takes its argument at all
its call sites, and the seven-argument calls pass seven; its arity losses
are `to_fixed`, whose one caller passes it a call's result in r0 (which
the drop rule doesn't count as setting r0), and two C++ functions.

**Gates.** The firmware gate's identity rates with Ghidra fall for the
three families (cortexm c_ast 50.3% → 4.8%, mips 48.0% → 6.3%, ppc to
6.4%; discovery, listing and DWARF recall unchanged): their baselines
(`corpus/baselines/firmware-cortexm.json`, `-mips`, `-ppc`) are re-saved,
as the benchmark above says the C is closer to the source in every
family. `rk-infer`'s gate is unchanged (+8.9 pp at signature, every
architecture at or above its baseline), and the tuning corpus's C is
byte-identical.

**What's left.** The cast and noise losses above; `extraout_` after
calls needs per-function clobber lists (what a callee really writes)
rather than the convention's; a structure of words none of which is
dereferenced reads as an `int` array; RISC-V rv32 and x86-32 have tables
but no corpus image.

### Source shape (2026-10-21)

The fork's source-shape options ([decompiler-inputs.md](decompiler-inputs.md#source-shape)),
on by default for revkit's inputs: loads typed by their instruction's
extension, comparisons with the constant on the right, a decrement's
signed flag test as one comparison; and inference's own decompiler typing
loads as the final C's does ([infer.md](infer.md#load-types)). Before: this
branch with `--no-source-shape` (rk-lift; Ghidra's forms, and inference's
loads typed from their uses: master's C on these stripped binaries but for
bitfields, which print as fields either way); after: the default,
`--source-shape extension,right,flag`. Same commands, paired metrics only
(no judges; the held-out sets were not used). Re-measured 2026-10-23 on
master with inference on 32-bit ARM, MIPS and PowerPC (the section above),
so the firmware "before" is that section's "after".

| family | paired | before W/T/L | after W/T/L | after p |
| --- | ---: | --- | --- | ---: |
| ALL firmware | 14630 | 8548/4611/1471 (WIN) | 8628/4521/1481 (WIN) | 0 |
| ALL tuning | 3484 | 2159/667/658 (WIN) | 2142/711/631 (WIN) | 6.6e-191 |
| ELF clang -O0 | 558 | 358/127/73 (WIN) | 355/136/67 (WIN) | 1.9e-48 |
| ELF clang -O2 | 1048 | 668/170/210 (WIN) | 663/177/208 (WIN) | 5e-56 |
| ELF gcc -O0 | 400 | 229/101/70 (WIN) | 224/111/65 (WIN) | 1.3e-21 |
| ELF gcc -O2 | 1252 | 807/193/252 (WIN) | 805/206/241 (WIN) | 1.7e-71 |
| PE clang -O0 | 101 | 46/38/17 (WIN) | 44/44/13 (WIN) | 4.7e-05 |
| PE clang -O2 | 125 | 51/38/36 (tie) | 51/37/37 (tie) | 0.17 |
| fw cortexm | 2722 | 1899/454/369 (WIN) | 1889/461/372 (WIN) | 1.4e-243 |
| fw m68k | 1038 | 296/723/19 (WIN) | 296/723/19 (WIN) | 4.4e-65 |
| fw mips | 2739 | 1679/680/380 (WIN) | 1677/681/381 (WIN) | 2.8e-193 |
| fw ppc | 3940 | 2595/797/548 (WIN) | 2595/800/545 (WIN) | 6e-318 |
| fw sh4 | 1712 | 1217/423/72 (WIN) | 1229/412/71 (WIN) | 2e-273 |
| fw xtensa | 2479 | 862/1534/83 (WIN) | 942/1444/93 (WIN) | 1.8e-177 |

No family loses, and none changes verdict: the firmware composite gains
80 functions and loses 10 (xtensa +80, sh4 +12; the three inference
families within a few functions either way); the tuning composite has 17
fewer wins and 27 fewer losses (none significant; more ties). 68000's C
changes only in comparisons' operand order (`1 < param_1` → `param_1 > 1`),
which no metric reads. Per metric, before → after where it moved (+ and −
mark p < 0.01):

| metric | ALL firmware | ALL tuning | where |
| --- | --- | --- | --- |
| `undefined` | 7721/6474/435+ → 7952/6256/422+ | 2406/1016/61+ → 2408/1019/56+ | an `undefined1`/`undefined2` load (and what it reaches) typed `byte`, `ushort`, `short` from its instruction: xtensa 313 → 497 wins, sh4 552 → 619 (on ARM, MIPS and PowerPC inference's prototypes had already typed most of them) |
| `constants` | 95/2013/72 → 112/1997/71+ | 11/507/23 → 12/509/20 | ppc's loss (5/612/30−) no longer significant (13/605/29) |
| `members` | 1860/5638/347+ → 1875/5619/351+ | | |
| `proto_param_class` | 4582/9797/251+ → 4608/9771/251+ | 1888/1563/23+ → 1887/1564/23+ | |
| `locals_class` | 2506/8992/1401+ → 2514/8977/1408+ | 766/2182/505+ → 758/2176/519+ | |
| `length` | 2289/8564/2046+ → 2304/8555/2040+ | 437/2399/617− → 440/2399/614− | |
| `temporaries` | 2174/8909/1816+ → 2166/8902/1831+ | 420/2254/779− → 414/2244/795− | |
| `casts` | 3781/5638/5211− → 3746/5561/5323− | 1199/864/1420− → 1178/887/1418− | a value whose type now follows its load casts where it meets another (`(short)param_1[1] >> 1` after an `ldrh`): cortexm 1434 → 1515 losses |
| `proto_exact` | 489/14076/65+ → 389/14170/71+ | 337/3098/39+ → 299/3115/60+ | byte pointees: with every load typed, inference's defaults keep a `uchar *` and spell an unknown pointee `void *` where the headers' prior gave `char *` (`naive_strstr(uchar *, uchar *)`, zlib's `zError` returning `void *`); 212 functions lose an exact signature, 47 gain one |
| `strings` | | 102/652/0+ → 94/657/3+ | a `char` buffer loaded with `movzx` typed `byte` (cJSON, features on gcc and clang -O2) |

**The byte-pointee rule, measured both ways.** With inference's defaults
spelling byte pointees `char` as before (the `typed_loads` branch of
`finalize` off, everything else the default): composite 8638/4485/1507
(firmware) and 2160/655/669 (tuning); `proto_exact` 504/14061/65+ and
338/3097/39+, `strings` (tuning) 101/650/3+, `undefined` 7987/6231/412+,
but `casts` (tuning) 1191/844/1448−. The composites are within 20 net
functions of the default's (8628/4521/1481, 2142/711/631), so neither is
better by them; the default keeps the rule, because it makes a byte load
print as its instruction encodes it (`*(byte *)(param_1 + 4)` for an
`ldrb`, which a `char *` turns into a signed read), the point of the
source shape, and the exact-signature loss is the price. Spelling a
pointee `char` only where a string reaches it (a call's `char *`
parameter, a string literal) might keep both (not tried).

Each option on its own, and the alternatives (composite W/T/L; measured
2026-10-21, before inference on 32-bit processors):

| `--source-shape` | ALL tuning | ALL firmware | notes |
| --- | --- | --- | --- |
| `none` (before) | 2156/670/658 | 3892/10223/515 | |
| `extension` | 2159/658/667 | | casts 1443 losses, strings 3 |
| `right` | 2156/670/658 | | moves no metric: they don't read operand order |
| `encoded` | 2153/663/668 | | `constants` 11/507/23 → 22/475/44 (−); gcc -O0 0/110/4 → 1/97/16 (−) |
| `flag` | 2157/670/657 | | |
| `words,right,flag` | 2162/666/656 | 4026/10095/509 | zero-extended bytes untyped |
| `extension,right,flag` (default) | 2160/658/666 | 4306/9794/530 | |
| `extension,encoded,flag` | 2158/651/675 | 4352/9723/555 | firmware `constants` 78/2099/3 → 126/2009/45 |
| `extension,right,flag,compilable` | 2061/673/750 | 2042/6292/6296 (**LOSS**) | casts 1416 → 1574 losses (tuning), 751 → 7306 (firmware); `undefined` 7273 firmware losses (`(undefined4)` casts) |

Reading it:

- **Loads** are the gain: Ghidra types an 8- or 16-bit load by its uses,
  and the instruction's extension is simplified away before types are
  inferred; with it kept, a raw image's halfword and byte values get a
  type, and a value loaded with `ldrh` and stored back after an add is
  `ushort`, not `short`. `words` (bytes left out) gives up about a third
  of the firmware gain to keep 3 tuning functions' `char` buffers.
- **Comparisons.** Constant on the right changes no metric (the metrics
  count values, not order) and reads as the source does (`x > 8`, `x >=
  0`), so it is the default. The encoded constant loses `constants` on
  tuning, significantly on gcc -O0: GCC and LLVM rewrite `x < 10` as
  `x <= 9`, so their instructions carry a constant the source doesn't, and
  Ghidra's canonical `x < 10` is the source's. On firmware (also GCC) it
  wins more functions than it loses. It is a program setting
  (`COMPARISON_FORM_ENCODED`) for code from a compiler that keeps the
  source's constants: CodeWarrior's, which the DS experiment matched.
- **Flag tests** are rare on these corpora (one composite win); the
  CodeWarrior loop they fix (`subs; bgt`) isn't what GCC or LLVM emit.
- **Compilable C** loses everywhere the casts count: C a compiler accepts
  casts every pointer/integer conversion, which raw firmware is full of.
  It stays a setting for C meant to be compiled.

**Gates** (2026-10-23). Ghidra's inputs (`rk-decomp.json`: c_ast 100%)
and the reference function list (`rk-decomp-refonly.json`) are unchanged:
the options are off there. The firmware gate's discovery, listing, DWARF
and truth-precision rates don't move, and with `--no-source-shape` it
passes clean; with the default only the identity rates with Ghidra's C
fall, as the C departs from Ghidra's forms on purpose:

| arch | c_ast | c_alpha | c_shape | c_shape_dwarf |
| --- | --- | --- | --- | --- |
| cortexm | 4.8% → 3.5% | 4.9% → 3.5% | 13.3% → 11.6% | 15.8% → 14.1% |
| m68k | 55.8% → 48.2% | 69.9% → 58.2% | 73.3% → 61.2% | 77.2% → 65.1% |
| mips | 6.3% → 5.6% | 6.8% → 6.1% | 18.4% → 17.1% | 24.8% → 23.4% |
| ppc | 6.7% → 5.8% | 7.0% → 6.1% | 22.3% → 19.5% | 24.0% → 21.2% |
| sh4 | 17.8% → 16.3% | 18.0% → 16.5% | 18.9% → 17.6% | 33.8% → 32.5% |
| xtensa | 43.1% → 32.2% | 47.6% → 35.5% | 50.3% → 39.8% | 72.3% → 61.9% |

Identity under revkit's own inputs (`rk-decomp-own.json`) falls likewise,
c_ast 49.90% → 42.07%, c_alpha 50.30% → 42.34%, c_tokens 28.38% →
23.80% (with `--no-source-shape`, one function of cjson.exe's debug build,
whose bitfields now print as fields: `s->seen_eof == 0`, not
`(s->field_0x1010 & 1) == 0`). The firmware baselines
(`corpus/baselines/firmware-*.json`) and `rk-decomp-own.json` are re-saved
for this section, as the paired metrics above say no family's C is
further from the source. `rk-infer`'s gate is unchanged (+8.9 pp at
signature, every architecture at or above its baseline): rk-infer keeps Ghidra's
load types (`Options::load_extension` off), so its observations are as
before.

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
  Thumb ranges in the inference decompiler, which it didn't get then.
  *Since done* for ARM, MIPS and PowerPC, with those fixed
  ([above](#inference-on-32-bit-arm-mips-and-powerpc-2026-10-21));
  SuperH, Xtensa and 68000 stay off.
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
