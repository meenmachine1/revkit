# Known issues

Bugs we know about and intend to fix. Newest first. Each entry says what
happens, where it was seen, what's been ruled out, and any workaround.

## 32-bit inference and matching decompilation (2026-10-23)

- **Status:** *fixed* (`api_minor` 112, feature `c-dialect`;
  [api.md](api.md#queries), [nds.md](nds.md#from-revkit-to-a-scratch)).
  Found rerunning the DS matching-decompilation pipeline on master
  `07f58073`: with prototype inference on for 32-bit ARM, the decompiled
  C of a DS game's modules scored *lower* compiled with the original
  compiler than with inference off (one module: fuzzy 61.0% → 46.3%; off,
  60.5%). The causes, as found on the 32-bit ARM fixture
  (`tests/data/arm32`) compiled back with clang at its own flags:
  - **The header wasn't C89.** `<stdbool.h>`, `_Static_assert`, `long
    long` padding bitfields (`unsigned long long : 64`), and Ghidra's
    `undefined4` defined twice (the built-in `unsigned int` and the
    archive's `unsigned char[4]` for the inferred structures' unknown
    fields), with `code` a `void` no call through it compiles. Under
    `clang -std=c89 -pedantic-errors --target=armv5te-none-eabi`, 0 of the
    fixture's 52 functions compiled with master's header. Now
    `dialect: C89` writes what an old compiler takes, and Ghidra's names
    are defined once in any dialect.
  - **Names the C used weren't in the header.** An inferred structure's
    gaps, which the decompiler names by offset (`*(int *)&p->field_0x10`),
    fields it drops (overlaps), the `_func_*` function types (whose
    functions' prototypes were then left out, so callers declared them
    implicitly), and the globals (`DAT_...`, never declared by ExportC).
    Now the header writes the structures as the decompiler sees them, the
    function types and the globals, and `per_function` gives the header
    and every function's C in one call, at one revision. Inference
    publishes in a revision of its own after the import, and renumbers
    its structures when it runs again: header and C taken on either side
    of it disagree (`Program.wait_for_analysis()` first).
  - **Where both compiled, the layout cost the code.** The header wrote
    an inferred structure with gaps as `#pragma pack(1)` with explicit
    offsets, and an ARMv5 compiler loads and stores every field of a
    packed structure a byte at a time: `h_read` 0.11 fuzzy with inference
    against 1.00 without. Now gaps are byte members and the layout is
    natural. Inference's prototype choices (widths, signedness, pointers
    against ints) changed no compiled function for the worse.
- **Measured** on the fixture (52 functions of the -O2 image, compiled
  per function with the header, scored by instruction-sequence
  similarity to the original): master, lenient C89 (`-w`): inference on
  41 compile, fuzzy 0.698; off 34, 0.715; on the 33 both compile, on
  0.701 against off 0.725 (the pipeline's "a little worse"). Now, strict
  C89: on 52 of 52, fuzzy 0.740, 21 exact; off 42, 0.649, 15 exact; on the
  42 both compile, on 0.755 against off 0.649, no function worse with
  inference (the -Os image: 0.763 against 0.659). The off failures are
  calls whose argument counts the decompiler guessed one way in the
  caller and another in the callee.
- **For a matching run:** `prog.set_decompiler_settings(comparison_form=
  "encoded", compilable_c=True)`, `prog.wait_for_analysis()`, then
  `prog.export_c(None, header=True, dialect="c89", per_function=True)`;
  compile each `function_sources[i].source` after `#include` of the
  header. No "matching mode" for inference: nothing it chose hurt the
  compiled code once the header was right.
- **Left:** a function returning its last call's result through `blx`;
  `pop {pc}` (Thumb interworking: `lerpf` tail-calling soft float) is
  inferred `void`, so its caller passes nothing on (`to_fixed()`); C++
  names (`Scene::Update`) are left out of a C89 header as comments; the
  cross-module no-return fix only applies to programs imported with
  `ImportDsdProject` (it needs the module boundaries); raw imports with
  their own assertions still see calls into other modules as not
  returning.

## Found by a matching-decompilation run on a Nintendo DS game (2026-10-18)

A private experiment used revkit 0.1.3 as the front end of a matching
decompilation of a retail DS game (ARMv5TE, CodeWarrior 1.2; main, ITCM and
15 overlays loaded as raw programs, symbols from ds-decomp asserted through
the SDK). It reached 67% objdiff fuzzy and 9% exact in under two hours. These
are the revkit problems it hit, costliest first. No game data is recorded
here. Fixed in `api_minor` 104 and gone from this list: calls into
another module taken as no-return, the DS's I/O not volatile, Thumb
entries through the SDK, an import's name taken silently, all-or-nothing and slow assertion
batches, and stores that only grow ([nds.md](nds.md#what-a-matching-run-needed)).

- ~~**Prototypes on 32-bit ARM are guessed.**~~ *Fixed 2026-10-21*:
  inference runs on 32-bit ARM and Thumb
  ([infer.md](infer.md#32-bit-processors)); stack arguments past r3 count
  (a seven-argument call passes seven) and an interrupt restore whose use
  of r0 the decompiler drops takes it (the 32-bit ARM fixture,
  `tests/data/arm32`). Before: inference was off for 32-bit; Ghidra's
  Parameter ID on raw images (`--param-id on`) helped about a third of the
  functions it touched and hurt twice as many.
- **Daemon memory with Parameter ID.** With `--param-id on` and 16 programs
  in one project the daemon reached 5.4 GB. Measured and partly reduced
  (fewer retained analysis revisions); the rest is the memo budget filling,
  which `--memo-budget` and `--retain` bound
  ([memory.md](memory.md#many-programs-and-parameter-id)).
- ~~**Token gaps.** Volatile globals come back as `punctuation` tokens with no
  target or variable entry. String-literal tokens have no target address.
  Some variable type text isn't valid C (`code() * *`).~~ *Fixed*
  (`api_minor` 106, feature `decompiler-settings`;
  [api.md](api.md#decompiler-settings)).
- **Output a C compiler rejects or miscompiles,** which had to be rewritten
  before compiling: partial field access (`x._0_2_`), a label or `case` at
  the end of a block with no statement, stack structs split into scalars,
  struct copies printed as word copies, 1-bit bitfield tests as signed
  shifts, load signedness that doesn't match the instruction (`ldrh` shown
  signed), and pointer/integer conversions without casts.
  *Mostly fixed* (2026-10-21; [decompiler-inputs.md](decompiler-inputs.md#source-shape)):
  load signedness follows the load's extension and bitfields print as
  fields by default; the program setting `compilable_c` prints partial
  accesses as lvalues, `;` after a label ending a block, and casts on
  pointer/integer conversions. Left: stack structs split into scalars and
  struct copies printed as word copies.
- **What hand-matching had to fix, most common first** (a 16-minute
  sprint on functions already 95–99% similar; 61 became exact). Each is
  something the decompiler or its inputs could get right in bulk:
  signedness of 8- and 16-bit loads and stores (the type should follow
  `ldrh`/`ldrsh`/`ldrb`/`ldrsb`); comparison constants shifted by one
  (`x < 1` for `x <= 0`, `8 < x` for `9 <= x`) and compare operand order;
  bitfields printed as masks and shifts (`& 1`, `(x & 0x1f) >> 4`,
  `& 0xfe`); byte-count loop guards as `!= 0` for a signed `0 < n`;
  dropped or invented arguments from guessed 32-bit prototypes (one SDK
  function called by 263 functions lost its only argument: since
  inference on 32-bit ARM, a register the entry reads is a parameter);
  stack arrays
  one element too large; and the order of independent stores.
  *Since 2026-10-21* ([decompiler-inputs.md](decompiler-inputs.md#source-shape)):
  load signedness, comparisons (the constant on the right by default, the
  instruction's constant with `COMPARISON_FORM_ENCODED`), bitfields
  printed where the type has them, and `subs; bgt` loop guards as `n > 0`.
  Not yet: bitfields detected from masks in inferred structures, stack
  arrays sized right (the element count isn't in stripped code), the order
  of independent stores.

## Discovery loses the code after a skipped jump on AVR

- **Status:** open (2026-10-05). Found scoring the AVR firmware images.
- **What happens:** on AVR, the code that follows a skip instruction and
  an unconditional `rjmp`, `jmp` or `ret` (`cpse r25, r1` / `rjmp done` /
  the code that runs when the skip is taken) is not part of the function,
  and functions only that code calls are not found. On grbl for the
  ATmega328P revkit's functions hold 48% of the instructions Ghidra's do
  and 79.5% of Ghidra's functions are found (the mcukit images: 76% and
  78% of the instructions). The listing and the decompiled C of the
  functions that are found are right.
- **Cause:** AVR's SLEIGH has no skip in an instruction's own p-code. The
  five skip instructions (`cpse`, `sbrc`, `sbrs`, `sbic`, `sbis`) set a
  context bit for the next address (`globalset(inst_next, useSkipCond)`),
  and an instruction decoded with that bit begins with a conditional
  branch over itself. Discovery decodes every instruction from its bytes
  and the painted context alone (`Lifter::lift_pcode` turns context
  commits off, so that one decode never depends on another): the `rjmp`
  after a skip decodes as a plain jump with no fall-through. The linear
  listing and the decompiler apply the commits.
- **Seen on:** `avr/grbl-atmega328p-Os`, `avr/mcukit-atmega328p-*`
  (`scripts/ci.sh --firmware`; 137 lost fall-throughs on grbl: 115 after
  `rjmp`, 14 after `ret`, 8 after `jmp`). Any language whose instructions
  set context for the next one is affected the same way.
- **Fix to make:** have a decode report the context its instruction
  commits for the next address, and decode the instruction a flow falls
  into with it: the commits of the instruction before are a function of
  that instruction's bytes, so flows stay deterministic. Ghidra's
  disassembler does the same through the program's context register.
- **Workaround:** none in discovery; a function can be created by hand at
  the code that is missing (`FUNCTION_BOUNDS`).

## Opening a file to import is slow in Chrome on one Ubuntu machine

- **Status:** open, local to that Ubuntu machine (2026-10-05); the UI now
  measures it and has a diagnostics dialog (below); waiting for the
  user's timings from that machine.
  The same UI is fast in Chrome on macOS, so this is the Ubuntu desktop
  setup (likely its XDG file-chooser portal), not revkit. Revisit only if
  it shows up on other Linux machines.
- **What happens:** in the Open dialog, "Import file…" takes about 2–20 s
  before the native file chooser appears. GNOME dims the window and the
  tab feels close to crashing; once it took about 20 s. The user reports
  other sites' file pickers are fast in the same browser. The in-app
  "Browse daemon host…" picker (ListHostFiles) that was added as a
  workaround is also still slower than it should be for them.
- **Seen on:** Chrome on Ubuntu (GNOME), reaching `rk-daemon` over
  Tailscale at `http://<tailscale-ip>:50052` (plain HTTP).
- **Ruled out, measured from headless Chrome on the daemon host:**
  - the click reaches the browser's file chooser 25–55 ms after the click,
    at DPR 1 and 2, with and without a program open;
  - the page is idle before the click: no requestAnimationFrame loop, no
    canvas redraws, 0% main-thread time;
  - no expensive CSS on the dialog (the backdrop is a plain translucent
    overlay, no `backdrop-filter`);
  - an incognito window with no program open is still slow (about 5 s).
- **Suspects to check next:**
  - something about this origin in the user's Chrome: plain-HTTP origin on
    a Tailscale IP vs the HTTPS sites that are fast; try serving the UI
    over HTTPS (`tailscale serve`, which needs enabling on the tailnet);
  - the long-lived streaming requests (Connect server streaming for
    subscriptions and presence) holding the renderer or network stack
    busy while a modal native dialog opens;
  - for the in-app picker: round-trip latency to the daemon over
    Tailscale per listing, and rendering of large folders.
  - Get a Chrome performance trace (DevTools → Performance, record while
    clicking) from the affected machine; nothing here reproduces it.
- **Workarounds:** drag and drop a file onto the Open dialog (fast), or
  type a path on the daemon host into the path field.
- **Investigated 2026-10-05 (phase 7), what changed in the UI:**
  - Nothing in the page decides how fast the native chooser appears: the
    page asks (a click on a file `<input>`, or `showOpenFilePicker`) and
    Chrome's browser process opens the GTK or XDG-portal dialog. Headless
    Chrome on the daemon host still answers in 34–48 ms with any of the
    variants below, so the delay is between Chrome and the desktop on
    that machine. What the UI can do is ask in the plainest way, take
    other suspects out, and measure on the affected machine.
  - **No file input waits in the page.** "Import file…" makes the
    `<input type=file>` on the click (no `accept` filter) and removes it
    after the pick (`ui/src/ui/filepick.ts`).
  - **The live stream pauses while the chooser is open** (the
    long-lived-stream suspect): the subscription stream ends when the
    chooser opens and resumes from the last revision when it closes, so
    nothing is missed (`Live.pause`; the status bar says "paused").
  - **Every pick is timed**: click to the window losing focus to the
    chooser ("shown"), and to it closing. When it took over 2 s to appear
    the dialog says so and points at drag and drop and Browse daemon host.
  - **Diagnostics: time the system file chooser…** (command palette)
    opens the chooser three ways, a plain `<input>`, an `<input>` with an
    accept filter (binary extensions and MIME types), and the File System
    Access picker, with the stream running or paused, lists the timings
    and copies them. It can also make one of them what Import file… uses
    (`?picker=input|accept|fsa` does the same for one page).
  - **A difference from the sites that are fast:** at
    `http://<tailscale-ip>:50052` the page isn't a secure context, so the
    File System Access picker doesn't exist there (Chrome offers it only
    on HTTPS and localhost); most sites the user compared are HTTPS.
  - The in-app browser now shows how long each listing took (`· 312 in
    850 ms` after the path), which separates the daemon's time and the
    network's from drawing.
- **The experiment to run on the affected machine** (it needs that
  machine; nothing here reproduces the delay):
  1. In the UI, Ctrl+Shift+P → "Diagnostics: time the system file
     chooser…". Press each button three times, cancelling the chooser
     each time, once with "pause the live stream" off and once on; then
     Copy timings and send them. If all are slow, the page isn't the
     cause; if only some are, Import file… can use the fast one.
  2. The same over HTTPS (`tailscale serve`, or `rk-daemon
     --tls-self-signed`, see security.md): the File System Access button
     then works too; compare.
  3. Chrome with a fresh profile, to rule out profile state (remembered
     folders, extensions): `google-chrome --user-data-dir=$(mktemp -d)
     http://<tailscale-ip>:50052`, then step 1.
  4. The portal without Chrome: `gdbus call --session --dest
     org.freedesktop.portal.Desktop --object-path
     /org/freedesktop/portal/desktop --method
     org.freedesktop.portal.FileChooser.OpenFile "" "revkit test" "{}"`
     opens the desktop's chooser; count how long until it appears, then
     cancel it. If that is slow too, the delay is the XDG portal: check
     `systemctl --user status xdg-desktop-portal
     xdg-desktop-portal-gnome xdg-desktop-portal-gtk` and `journalctl
     --user -b | grep -i portal` for timeouts (two backends both claiming
     the FileChooser interface, or one timing out, are known causes of
     multi-second delays), and whether the chooser's sidebar lists a
     network location that is slow or gone (Tailscale's own mounts, an
     SMB or SFTP bookmark).
  5. Another site's file picker in the same window right after step 1,
     to compare under the same conditions.
