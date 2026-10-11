# Known issues

Bugs we know about and intend to fix. Newest first. Each entry says what
happens, where it was seen, what's been ruled out, and any workaround.

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
