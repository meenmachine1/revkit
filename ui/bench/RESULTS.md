# Listing: benchmark results

Two rounds of the same frame-time benchmark: **UI v1 against the real
`rk-daemon`** on the largest corpus binary (this section), and the
**phase-0 spike** against a 10M-instruction mock daemon (below, as
measured then).

**Gate:** median frame time under 16 ms (on vsync-capped engines: the median
frame lands on every vsync; see "How to read the numbers" in the spike
section, which applies unchanged).

## Phase 5: the function graph, and the listing with the new views

**Function graph on 2,000 blocks** (`bench/graph.ts`): a generated
function of 1,999 basic blocks, 2,988 edges and 12,202 instructions (900
ifs, loops and switches, `cc -O0`), served by `rk-daemon` and shown in the
graph view at 1600×1000, host Chrome 153 headless, software rendering;
load average 13 to 17 from other agents' builds. Each scenario is 148
frames: **fit** pans the fitted graph (every block on screen, drawn as
boxes with a bar per line), **pan** scrolls at 1:1 (text), **zoom** sweeps
from fitted to 1.2× and back (both levels of detail).

| Engine | DPR | GetFunctionGraph | ELK layout (worker) | Shown | fit: frame p50 / p95, render p50 / p95 (ms) | pan | zoom |
|---|---|---|---|---|---|---|---|
| chrome | 1 | 141 ms | 1195 ms | 1.4 s | 16.7 / 17.0, 1.3 / 1.7 | 16.7 / 16.8, 0.3 / 0.6 | 16.7 / 16.8, 0.4 / 1.1 |
| chrome | 2 | 184 ms | 1149 ms | 1.4 s | 16.7 / 16.9, 1.3 / 1.7 | 16.7 / 16.8, 0.2 / 0.4 | 16.7 / 16.8, 0.3 / 1.0 |
| chrome-uncapped | 1 | 222 ms | 1322 ms | 1.6 s | 4.3 / 5.6, 1.3 / 2.2 | 0.9 / 1.5, 0.2 / 0.6 | 1.0 / 3.4, 0.2 / 0.9 |
| chrome-uncapped | 2 | 162 ms | 1106 ms | 1.3 s | 7.3 / 11.7, 1.2 / 2.3 | 3.2 / 6.0, 0.2 / 0.4 | 3.4 / 7.0, 0.2 / 1.0 |

Every frame lands on vsync on the capped engine, and the uncapped frame
cost stays under 12 ms at p95 with all 2,000 blocks on screen: the canvas
draws only what is in view, edges as one path per color, and text only
above 6 px per line. Layout is ELK's layered algorithm with one
crossing-minimization pass for graphs over 400 blocks (thoroughness 1:
1.1 to 1.3 s here, against 1.6 s at the default 7 in Node), in a web
worker, so the page stays responsive while it runs; an edit that keeps the
blocks and edges (a rename, a comment) reuses the layout. The daemon's
`GetFunctionGraph` (listing rows for 12,202 instructions) takes 95 to 230
ms in the page, binary encoding, and about 240 ms as JSON over curl.

**Graph diff on a 2,000-block pair** (`bench/diffgraph.ts`, diff M3): the
same generated function in two versions (18 constants changed, 5
statements inserted, 3 removed; 1,999 and 1,993 blocks, 12,202 and 12,183
instructions), shown in Compare's graph diff at 1600×1000, host Chrome 153
headless, software rendering, load about 2. `GetFunctionDiff` with detail:
388 ms cold, 230 ms warm (JSON). Union layout of 1,999 nodes in ELK's
worker: 0.46 to 0.49 s side by side, 0.97 to 1.01 s merged (bigger nodes);
shown 0.7 s and 1.0 s after the request.

| Engine | DPR | mode | fit: frame p50 / p95, render p50 / p95 (ms) | pan | zoom |
|---|---|---|---|---|---|
| chrome | 1 | side by side | 16.7 / 16.9, 0.6 / 1.0 | 16.7 / 16.8, 0.3 / 0.4 | 16.7 / 16.8, 0.3 / 0.9 |
| chrome | 1 | merged | 16.7 / 16.9, 0.4 / 0.5 | 16.7 / 16.9, 0.2 / 0.3 | 16.7 / 16.8, 0.2 / 0.4 |
| chrome-uncapped | 1 | side by side | 1.2 / 2.2, 0.5 / 0.9 | 0.5 / 0.6, 0.2 / 0.3 | 0.3 / 1.0, 0.1 / 0.4 |
| chrome-uncapped | 1 | merged | 0.6 / 1.1, 0.2 / 0.4 | 0.3 / 0.4, 0.1 / 0.2 | 0.2 / 0.6, 0.1 / 0.2 |
| chrome-uncapped | 2 | side by side | 1.6 / 2.5, 0.5 / 0.7 | 0.6 / 1.6, 0.1 / 0.2 | 0.7 / 2.6, 0.2 / 0.7 |
| chrome-uncapped | 2 | merged | 0.9 / 1.7, 0.2 / 0.4 | 0.5 / 1.4, 0.1 / 0.2 | 0.6 / 1.3, 0.1 / 0.2 |

Side by side draws two canvases per frame and still stays under 3 ms at
p95 uncapped: drawing is culled to the viewport with the function graph's
level of detail.

**Listing, A/B against master** (`build/bench/ab.sh`, not committed:
master's UI bundle and this branch's served in turn by the same
`rk-daemon` on Lua, `chrome-uncapped`, DPR 1 and 2, the eight scenarios,
two rounds). Round 1 ran under load 13 to 17; round 2, quieter, is the
one to read: `render()` medians are 0.2 to 0.3 ms per frame in every
scenario on both bundles, and the worst-scenario frame medians are 2.3 ms
(branch) and 1.9 ms (master) at DPR 1, 3.8 ms (branch) and 5.7 ms
(master) at DPR 2, with no dropped or blank frames on either. The views
cost the listing nothing while hidden; plugin annotations (none in this
run) are laid out with the row, once.

## UI v1.1: header rows, flow arrows, a paged functions panel

A short check that v1.1's listing (header rows from the daemon, flow
arrows in a gutter) costs no frame time, and a smoke check of the paged
functions panel and header rows on the largest binary on the host.

**Frame time, A/B on Lua** (the v1 setup: `rk-daemon` on
`corpus/elf-x86_64/gcc-O2/debug/lua`, the eight scenarios, host Chrome 153
uncapped, software and RTX 4080). v1.1 as shipped against the same build
with `headers=0&arrows=0` (v1's layout: labels in a column, no arrows),
one round each, back to back. Other agents' builds kept the 1-minute load
at 11 to 38 (the v1 rounds waited for load under 6), so frame medians
mostly measure the host: the flat-fill control, which draws nothing,
varied from 0.2 to 6.4 ms between runs. JS time in `render()` is the
steadier figure.

| Engine | DPR | v1.1: worst-scenario median / p95 frame (ms) | v1.1: `render()` median / p95, worst scenario | v1 layout: worst median / p95 | v1 layout: `render()` | Load (v1.1, v1) |
|---|---|---|---|---|---|---|
| chrome-uncapped | 1 | 6.6 / 13.4 | 0.8 / 1.4 | 12.3 / 32.6 | 1.5 / 5.1 | 18, 34 |
| chrome-uncapped | 2 | 4.7 / 9.5 | 0.6 / 1.1 | 26.0 / 38.0 | 1.5 / 5.2 | 11, 38 |
| chrome-gpu-uncapped | 1 | 8.1 / 19.9 | 1.2 / 4.6 | 2.9 / 9.8 | 0.6 / 0.8 | 24, 25 |
| chrome-gpu-uncapped | 2 | 2.1 / 17.5 | 0.5 / 1.2 | 1.8 / 6.4 | 0.5 / 0.7 | 25, 20 |

No regression shows through the noise: every run stays far under 16 ms
median, with 0 % blank frames, and `render()` stays at 0.5 to 1.5 ms per
frame in both layouts. Header rows add rows (Lua: 52,942 → 59,516), not
work per row. The arrows first cost 0.3 to 0.8 ms per frame (a 1,200-row
scan each frame, measured in an earlier noisy run); they now keep the
jumps near the view per 64-row step and cache version, so a frame only
filters them. Raw runs: `bench/raw/v11-ab-*.json` (not committed). A
quiet-host rerun with three rounds (`bench/suite.sh`) is still to do.

**Large binary: libLLVM** (`/usr/lib/x86_64-linux-gnu/libLLVM.so.20.1`,
143 MB, **127,008 functions**, 20,247,947 listing rows, 22,034,326 with
header rows), `bench/scale-smoke.ts` against `rk-daemon --open` (import
about 4 minutes on the loaded host, 5.6 GB resident):

| What | Time |
|---|---|
| `ListFunctions`, first page of 200 (with the total) | 29 ms |
| a page of 200 by `offset` anywhere in the list (10 positions) | median 4.1 ms, max 8.4 ms |
| the current function's position (`range` count) | 1.8 ms |
| filter (`name_contains`): "parse" (1,053), "x86" (58), no match | 21, 61, 18 ms |
| first `GetListing` with `header_rows` (computes `listing.header_*`) | 629 ms |
| then 256 header-numbered rows mid-program | 4.6 ms |
| UI: page loaded, panel listing 127,008 functions | 1.8 s |
| UI: panel scrolled to 50 % / to the end, rows filled | 18 ms / 10 ms |
| UI: typing "parse" to "1,053 matches" (120 ms debounce included) | 196 ms |

v1's panel loaded every function before showing any (26 pages of 5,000
here). A rename's commit with header-row windows was 4.5 s on libLLVM with
the first design (one whole-program `listing.headers` memo, and a commit
that revalidated discovery's results); with per-bucket memos and windows
computed from the previous revision for edits that don't steer discovery,
it is about 1 ms on cmake (2.2M rows; it was 120 ms) and was not re-timed
on libLLVM. The first listing read after any edit still revalidates
discovery's results (about 0.1 s on cmake), with or without header rows,
as on master.

## UI v1 against rk-daemon

### Setup

- **Program:** `corpus/elf-x86_64/gcc-O2/debug/lua` (1.27 MB, 699 functions,
  47,944 instructions, **53,412 listing rows**), the largest binary in
  `~/dev/revkit/out/corpus`, served by `rk-daemon --backend image`
  (RelWithDebInfo) on the same host. The UI is the v1 bundle (`ui/dist`) the
  daemon serves; it reads `GetListing` in 256-row pages over Connect with
  binary protobuf on HTTP/1.1.
- **Scenarios:** the spike's set and harness, unchanged except that each
  scenario starts 30 % into the listing and random jumps go to random
  function entries (`GetListing` address window, 256 rows each side). The
  page runs with `dpr=native` (the fallback off) unless noted.
- **Engines:** as in the spike: Playwright 1.63 Chromium, WebKit and Firefox
  in Docker (software rendering), host Chrome 153 in software and on the RTX
  4080, and the Tauri shell's WebKitGTK 2.52.6 under Xvfb (CPU painting, no
  compositing), both as shipped (fallback probe on) and with `dpr=native`.
- **Runs:** 3 rounds of everything (`bench/suite.sh`), each step started only
  once the 1-minute load average was below 6. The host is shared with other
  agents' builds, and load rose to 15-30 during some runs; the spread
  between rounds is in the per-scenario tables ("medians a–b") and the load
  per Playwright run in `bench/results.json`.

### Verdict

| Engine | DPR 1 | DPR 2 |
|---|---|---|
| Chromium 153 (Playwright, software) | **pass**: on vsync, 0 % dropped; uncapped worst-scenario median 1.5 ms | **pass**: 0 % dropped; uncapped 5.5 ms |
| Chrome 153 (host, software) | **pass**; uncapped 3.9 ms | **pass** (capped, 0 % dropped); uncapped 13 ms worst median, with round medians from 5 to 21 ms as load came and went |
| Chrome 153 (host, RTX 4080) | **pass**; uncapped 1.0 ms | **pass**; uncapped 1.6 ms |
| WebKit 26.6 (Playwright) | **pass**: 16.0 ms (its cadence), 0 % dropped | **pass**: 16.0 ms, p95 19 ms |
| Firefox 155 (Playwright) | **pass**: 17.1 ms (its cadence) | **pass** |
| WebKitGTK 2.52.6 (Tauri, Xvfb, CPU painting), `dpr=native` | **pass**: 16 ms | **FAIL**: 18–19 ms median (47–55 fps), as in the spike |
| WebKitGTK as shipped (fallback probe on) | **pass** (no probe at DPR 1) | **FAIL**; the probe fell back to a DPR 1 canvas in 2 of 3 runs, which gains about 1 ms (see below) |

The real daemon and API change nothing about the verdict: every engine that
passed against the mock passes against `rk-daemon`, with the same headroom,
and WebKitGTK without GPU compositing at scale 2 still misses by 2–3 ms per
frame.

### What the real data path changed

- **Rendering cost is the same.** JS time in the listing's `render()` is
  0.3–1.4 ms per frame in Chromium, 2 ms in WebKit, 4–5 ms in Firefox and
  2–5 ms in WebKitGTK, against 0.2–0.7, 0.5–0.7, 1.3 and 2–3 ms in the spike.
  Real rows carry more tokens (labels, xref counts, flow markers, comments)
  but the per-row runs are still computed once and cached.
- **Pages arrive about as fast as from the mock.** A 256-row `GetListing`
  page lands 3–9 ms (median) after it is requested during steady scrolling
  (the mock: 4–6 ms), 6–7 ms in WebKitGTK at DPR 1 and 14–17 ms at DPR 2
  (the spike: 5–19 ms). The exception is host Chrome uncapped at DPR 2,
  which ran under the most load: 26–29 ms. During the scrollbar drag, with
  six requests in flight over HTTP/1.1, a page takes about 43 ms in
  Chromium and Firefox, 6–16 ms in WebKit and WebKitGTK.
- **Jumps:** from `goTo(address)` to a fully drawn viewport takes 14–20 ms
  median and 17–25 ms p95 (one 512-row address-window request), except
  host Chrome uncapped at DPR 2 (26/37 ms) and the as-shipped WebKitGTK
  runs at scale 2 (p95 25–42 ms).
- **Never blank.** 0 % blank frames in every run. In the scrollbar drag,
  Chromium and Firefox show the content one fetch behind the thumb in
  61–69 % of frames (the spike: 9–93 %, by engine), WebKit in 2–7 %,
  WebKitGTK in 1–17 %. The program is 200 times smaller than the mock's, so
  a 4 s sweep moves about 450 rows per frame instead of 94,000; the stale
  share stays high because every frame still needs one or two new 256-row
  pages, which arrive two or three frames later.
- **Live updates during scrolling** are not in these scenarios; the e2e test
  covers their correctness (`ui/e2e/run.ts`).

### On the fact-store backend

These runs used the image backend as it was before master's fact-store
backend landed. After merging it into this branch, one round of host Chrome
(software, capped and uncapped, DPR 1 and 2; load 2–10) gave the same
picture: every scenario on vsync with 0 % dropped and 0 % blank, uncapped
worst-scenario medians of 1.2 ms (DPR 1) and 8.0 ms (DPR 2), 256-row pages
in 3–6 ms during steady scrolling (19 ms uncapped at DPR 2), about 43 ms
during the drag, and jumps filled in 14–21 ms median, 17–23 ms p95.

### The DPR 1 fallback on WebKitGTK

The UI times idle frames, then real listing redraws, a moment after start.
At DPR > 1, redraws that miss vsync switch the canvas to DPR 1 (CSS
upscale, nearest-neighbour) and the status bar says so; if DPR 1 measures
more than 10 % slower it goes back and only warns. On this host the probe
read 16–17 ms per redraw at DPR 2 against 16 ms idle when quiet (17 falls
back, 16 doesn't, so it is borderline here), and 67 ms when the machine was
busy.

Whether DPR 1 helps was measured directly with `bench/tauri-dpr-ab.sh`:
the shell at scale 2, alternating `dpr=native` and `dpr=1`, four runs each
(per-run median frame interval in ms; the fourth pair ran while load rose):

| Scenario | `dpr=native` (canvas at DPR 2) | `dpr=1` (canvas at DPR 1) |
|---|---|---|
| steady-3000 | 19, 18, 19, 18 | 18, 18, 20, 21 |
| fling | 18, 18, 18, 18 | 17, 17, 17, 26 |
| scrollbar-drag | 18, 19, 18, 32 | 17, 18, 18, 23 |
| fill-baseline (flat fill, no text) | 16, 17, 17, 18 | 17, 17, 16, 17 |

In quiet runs DPR 1 saves about 1 ms per frame (fling 18 → 17 ms, 55–57 →
57–59 fps) and the main-thread cost drops from 15–16 to 14–15 ms. It can't
do more: the flat-fill control, which draws nothing, already takes 16–17 ms
at either canvas resolution, because WebKitGTK's non-composited path paints
the whole window at device scale on the CPU every frame. The fallback keeps
the canvas from adding to that floor and tells the user why scrolling is
slow; what fixes it is GPU compositing (a real display with working
DMA-BUF, not Xvfb) or the browser-tab mode, as the spike concluded. Running
`bench/tauri.sh` on a Linux desktop with a GPU is still the open item.

### Gate table (3 runs each)

| Where | Engine | DPR | Painter | Runs | Gate | Worst-scenario median frame (ms) | Worst p95 | Worst p99 | Lowest fps | Max dropped | Main-thread cost median (worst) | Control: flat fill median frame |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| docker | chromium 153.0.8010.12 | 1 | direct | 3 | **pass** | 16.7 | 16.8 | 16.8 | 60 | 0.0% | 4.3 | 16.7 |
| docker | chromium 153.0.8010.12 | 2 | direct | 3 | **pass** | 16.7 | 16.8 | 16.8 | 60 | 0.0% | 4.7 | 16.7 |
| docker | chromium-uncapped 153.0.8010.12 | 1 | direct | 3 | **pass** | 1.5 | 4.5 | 5.3 | 494 | 0.0% | 1.3 | 0.4 |
| docker | chromium-uncapped 153.0.8010.12 | 2 | direct | 3 | **pass** | 5.5 | 7.2 | 16.9 | 178 | 0.0% | 5.1 | 2.7 |
| docker | webkit 26.6 | 1 | direct | 3 | **pass** | 16.0 | 17.0 | 17.0 | 62 | 0.0% | 5.0 | 16.0 |
| docker | webkit 26.6 | 2 | direct | 3 | **pass** | 16.0 | 19.0 | 21.0 | 61 | 0.0% | 6.0 | 16.0 |
| docker | firefox 155.0 | 1 | direct | 3 | **pass** | 17.1 | 17.2 | 17.2 | 60 | 0.0% | 5.0 | 17.1 |
| docker | firefox 155.0 | 2 | direct | 3 | **pass** | 17.1 | 17.2 | 17.2 | 60 | 0.0% | 6.0 | 17.1 |
| host | chrome 153.0.8010.36 | 1 | direct | 3 | **pass** | 16.7 | 16.8 | 16.8 | 60 | 0.0% | 2.7 | 16.7 |
| host | chrome 153.0.8010.36 | 2 | direct | 3 | **pass** | 16.7 | 16.8 | 16.8 | 60 | 0.0% | 12.0 | 16.7 |
| host | chrome-uncapped 153.0.8010.36 | 1 | direct | 3 | **pass** | 3.9 | 5.6 | 7.9 | 245 | 0.0% | 3.6 | 1.4 |
| host | chrome-uncapped 153.0.8010.36 | 2 | direct | 3 | **pass** | 13.2 | 30.5 | 34.8 | 71 | 10.9% | 13.2 | 2.6 |
| host | chrome-gpu 153.0.8010.36 | 1 | direct | 3 | **pass** | 16.7 | 16.8 | 16.8 | 59 | 2.4% | 2.9 | 16.7 |
| host | chrome-gpu 153.0.8010.36 | 2 | direct | 3 | **pass** | 16.7 | 16.8 | 16.8 | 60 | 0.0% | 1.8 | 16.7 |
| host | chrome-gpu-uncapped 153.0.8010.36 | 1 | direct | 3 | **pass** | 1.0 | 2.6 | 3.2 | 795 | 0.0% | 0.9 | 0.1 |
| host | chrome-gpu-uncapped 153.0.8010.36 | 2 | direct | 3 | **pass** | 1.6 | 4.1 | 5.3 | 531 | 0.0% | 1.4 | 0.1 |
| host Xvfb | tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1 | 1 | direct | 3 | **pass** | 16.0 | 18.0 | 19.0 | 62 | 0.0% | 6.0 | 2.0 |
| host Xvfb, canvas at DPR 1 | tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1 | 2 | direct | 2 | **FAIL** | 35.5 | 48.0 | 65.5 | 26 | 58.6% | 28.5 | 17.0 |
| host Xvfb | tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1 | 2 | direct | 1 | **FAIL** | 18.0 | 21.0 | 25.0 | 55 | 1.3% | 15.0 | 16.0 |
| host Xvfb | tauri-webkitgtk-native WebKitGTK 2.52.6 / Tauri 2.12.1 | 1 | direct | 3 | **pass** | 16.0 | 17.0 | 17.0 | 62 | 0.2% | 6.0 | 2.0 |
| host Xvfb | tauri-webkitgtk-native WebKitGTK 2.52.6 / Tauri 2.12.1 | 2 | direct | 3 | **FAIL** | 19.0 | 42.0 | 54.0 | 47 | 18.9% | 17.0 | 17.0 |

(`host Xvfb, canvas at DPR 1` are the as-shipped WebKitGTK runs at scale 2
where the probe fell back; one of them ran while the machine was loaded,
which is most of the gap to the run that stayed at DPR 2.)

### Per-scenario detail


#### chromium 153.0.8010.12, DPR 1, direct painter (docker, 3 runs, idle interval 16.667 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.6 / 3.0 / 3.3 | 0.3 / 0.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.5 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 3.5 / 4.0 / 4.2 | 0.6 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.1 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 3.3 / 4.5 / 4.8 | 0.7 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.2 ms | 0 |
| fling | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 3.4 / 4.4 / 4.6 | 0.6 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 4.0 / 5.8 / 6.2 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 66.5% (33.3 ms) | 43.0 ms | 0 |
| random-jumps (jump→filled 15.6/18.1 ms) | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 2.4 / 4.6 / 5.4 | 0.5 / 1.1 | 0.0% (0.0–0.0) | 0.0% | 0.3% (17.2 ms) | 7.2 ms | 0 |
| hover-scroll | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 4.3 / 4.7 / 4.9 | 0.7 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.0 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.3 / 1.4 / 1.6 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chromium 153.0.8010.12, DPR 2, direct painter (docker, 3 runs, idle interval 16.666 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 4.7 / 11.5 / 12.0 | 0.4 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.3 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 4.0 / 4.3 / 4.9 | 0.4 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.7 ms | 0 |
| steady-12000 | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 4.0 / 5.0 / 7.4 | 0.4 / 0.6 | 0.0% (0.0–2.6) | 0.0% | 0.0% | 5.7 ms | 0 |
| fling | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 3.8 / 4.2 / 5.6 | 0.3 / 0.5 | 0.0% (0.0–2.8) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 4.5 / 5.4 / 6.7 | 0.7 / 1.1 | 0.0% (0.0–13.6) | 0.0% | 66.9% (33.3 ms) | 42.9 ms | 0 |
| random-jumps (jump→filled 13.7/17.1 ms) | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 3.7 / 4.7 / 6.4 | 0.3 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.3% (17.1 ms) | 5.9 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 4.1 / 4.4 / 6.4 | 0.4 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.9 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.5 / 3.8 / 4.1 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chromium-uncapped 153.0.8010.12, DPR 1, direct painter (docker, 3 runs, idle interval 17.615 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 0.9 / 1.1 / 1.5 (medians 0.8–1.2) | 1122 | 0.8 / 1.0 / 1.3 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.6 ms | 0 |
| steady-3000 | 0.9 / 1.5 / 1.6 (medians 0.9–1.8) | 982 | 0.9 / 1.3 / 1.4 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.8 ms | 0 |
| steady-12000 | 1.4 / 1.7 / 2.3 (medians 1.2–1.6) | 684 | 1.3 / 1.5 / 2.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.1 ms | 0 |
| fling | 1.5 / 4.5 / 5.2 (medians 0.9–1.6) | 494 | 1.3 / 3.8 / 4.6 | 0.3 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 1.2 / 2.4 / 3.1 (medians 1.2–2.2) | 754 | 1.1 / 1.8 / 2.3 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 67.3% (13.7 ms) | 44.7 ms | 0 |
| random-jumps (jump→filled 19.6/22.0 ms) | 0.9 / 1.9 / 5.3 (medians 0.8–1.3) | 929 | 0.9 / 1.6 / 4.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.3 ms | 0 |
| hover-scroll | 1.1 / 4.0 / 5.3 (medians 0.9–1.4) | 641 | 1.0 / 3.7 / 4.8 | 0.3 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 11.0 ms | 0 |
| fill-baseline | 0.4 / 1.2 / 1.3 (medians 0.4–0.4) | 1992 | 0.3 / 1.1 / 1.2 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chromium-uncapped 153.0.8010.12, DPR 2, direct painter (docker, 3 runs, idle interval 17.032 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 3.1 / 3.6 / 4.0 (medians 2.9–3.2) | 319 | 3.0 / 3.4 / 3.7 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 11.7 ms | 0 |
| steady-3000 | 3.5 / 3.8 / 4.2 (medians 3.4–3.7) | 291 | 3.4 / 3.6 / 3.8 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 9.4 ms | 0 |
| steady-12000 | 3.9 / 4.2 / 5.1 (medians 3.5–3.9) | 256 | 3.7 / 4.0 / 4.3 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 9.3 ms | 0 |
| fling | 3.6 / 4.7 / 5.1 (medians 3.1–4.4) | 276 | 3.5 / 4.6 / 4.9 | 0.3 / 0.4 | 0.0% (0.0–0.2) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 5.5 / 7.2 / 8.2 (medians 4.9–5.5) | 178 | 5.1 / 6.5 / 7.3 | 0.6 / 1.0 | 0.0% (0.0–4.7) | 0.0% | 64.8% (35.3 ms) | 50.9 ms | 0 |
| random-jumps (jump→filled 23.1/25.2 ms) | 4.0 / 6.4 / 16.9 (medians 4.0–4.9) | 195 | 3.9 / 5.6 / 7.7 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 17.0 ms | 0 |
| hover-scroll | 4.2 / 5.0 / 7.3 (medians 3.6–5.0) | 232 | 4.1 / 4.7 / 6.8 | 0.4 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 12.3 ms | 0 |
| fill-baseline | 2.7 / 3.0 / 4.6 (medians 2.0–3.3) | 365 | 1.7 / 1.9 / 3.9 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### webkit 26.6, DPR 1, direct painter (docker, 3 runs, idle interval 21.795 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 2.0 / 4.0 / 4.0 | 1.0 / 1.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| steady-3000 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 2.0 / 4.0 / 4.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| steady-12000 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 2.0 / 4.0 / 5.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.0 ms | n/a |
| fling | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 3.0 / 4.0 / 5.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 9.0 / 10.0 | 2.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 2.4% (16.0 ms) | 6.0 ms | n/a |
| random-jumps (jump→filled 15.0/17.0 ms) | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 3.0 / 5.0 / 8.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| hover-scroll | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 2.0 / 4.0 / 4.0 | 1.0 / 1.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.0 ms | n/a |
| fill-baseline | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 0.0 / 1.0 / 1.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

#### webkit 26.6, DPR 2, direct painter (docker, 3 runs, idle interval 16 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.0 / 17.0 / 18.0 (medians 16.0–16.0) | 62 | 3.0 / 4.0 / 5.0 | 1.0 / 2.0 | 0.0% (0.0–1.6) | 0.0% | 0.0% | 6.0 ms | n/a |
| steady-3000 | 16.0 / 17.0 / 18.0 (medians 16.0–16.0) | 62 | 3.0 / 5.0 / 5.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| steady-12000 | 16.0 / 17.0 / 19.0 (medians 16.0–16.0) | 62 | 4.0 / 5.0 / 7.0 | 1.0 / 2.0 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 7.0 ms | n/a |
| fling | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 3.0 / 4.0 / 5.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.0 / 19.0 / 21.0 (medians 16.0–16.0) | 61 | 6.0 / 11.0 / 13.0 | 2.0 / 4.0 | 0.0% (0.0–15.5) | 0.0% | 6.9% (17.0 ms) | 7.0 ms | n/a |
| random-jumps (jump→filled 16.0/17.0 ms) | 16.0 / 17.0 / 17.0 (medians 16.0–27.0) | 62 | 3.0 / 6.0 / 10.0 | 1.0 / 2.0 | 0.0% (0.0–44.2) | 0.0% | 0.0% | 6.0 ms | n/a |
| hover-scroll | 16.0 / 17.0 / 17.0 (medians 16.0–26.0) | 62 | 3.0 / 5.0 / 5.0 | 1.0 / 2.0 | 0.0% (0.0–39.9) | 0.0% | 0.0% | 5.0 ms | n/a |
| fill-baseline | 16.0 / 17.0 / 17.0 (medians 16.0–25.0) | 62 | 0.0 / 1.0 / 1.0 | 0.0 / 0.0 | 0.0% (0.0–35.4) | 0.0% | 0.0% | 0.0 ms | n/a |

#### firefox 155.0, DPR 1, direct painter (docker, 3 runs, idle interval 16.591 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 17.1 / 17.1 / 17.2 (medians 17.1–17.1) | 60 | 3.0 / 4.0 / 5.0 | 2.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| steady-3000 | 17.0 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 4.0 / 6.0 / 6.0 | 3.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 9.0 ms | n/a |
| steady-12000 | 17.0 / 17.2 / 17.2 (medians 16.4–17.1) | 60 | 5.0 / 6.0 / 7.0 | 4.0 / 5.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 8.0 ms | n/a |
| fling | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 4.0 / 6.0 / 6.0 | 3.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 3.0 / 5.0 / 6.0 | 2.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 61.4% (33.0 ms) | 45.0 ms | n/a |
| random-jumps (jump→filled 17.0/19.0 ms) | 17.1 / 17.2 / 17.2 (medians 17.1–17.1) | 60 | 3.0 / 4.0 / 5.0 | 2.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.0 ms | n/a |
| hover-scroll | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 2.0 / 5.0 / 5.0 | 2.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| fill-baseline | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 0.0 / 1.0 / 1.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

#### firefox 155.0, DPR 2, direct painter (docker, 3 runs, idle interval 16.675 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 4.0 / 6.0 / 7.0 | 3.0 / 5.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| steady-3000 | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 4.0 / 5.0 / 7.0 | 3.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 8.0 ms | n/a |
| steady-12000 | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 4.0 / 6.0 / 7.0 | 3.0 / 5.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| fling | 17.1 / 17.2 / 17.2 (medians 17.1–17.1) | 60 | 3.0 / 4.0 / 6.0 | 3.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 4.0 / 7.0 / 9.0 | 3.0 / 6.0 | 0.0% (0.0–0.0) | 0.0% | 61.4% (33.0 ms) | 45.0 ms | n/a |
| random-jumps (jump→filled 17.0/25.0 ms) | 17.1 / 17.2 / 17.2 (medians 17.1–17.1) | 60 | 6.0 / 8.0 / 9.0 | 5.0 / 7.0 | 0.0% (0.0–0.0) | 0.0% | 0.3% (18.0 ms) | 9.0 ms | n/a |
| hover-scroll | 17.0 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 3.0 / 4.0 / 6.0 | 3.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| fill-baseline | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 0.0 / 0.0 / 1.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

#### chrome 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 16.666 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 2.7 / 3.7 / 4.5 | 0.5 / 0.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.5 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.9 / 3.1 / 3.2 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.2 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.8 / 3.7 / 4.0 | 0.4 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.3 ms | 0 |
| fling | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 1.4 / 2.4 / 3.2 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 2.3 / 3.0 / 3.6 | 0.8 / 1.1 | 0.0% (0.0–0.0) | 0.0% | 66.8% (33.3 ms) | 43.6 ms | 0 |
| random-jumps (jump→filled 16.3/17.4 ms) | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.4 / 2.5 / 3.2 | 0.3 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.3% (17.0 ms) | 3.7 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.7 / 6.3 / 6.6 | 0.3 / 0.7 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 3.2 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.1 / 1.4 / 2.5 | 0.0 / 0.0 | 0.0% (0.0–0.6) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chrome 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 16.666 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 4.1 / 5.0 / 7.1 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.2 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 4.6 / 5.6 / 6.2 | 0.4 / 0.6 | 0.0% (0.0–20.4) | 0.0% | 0.0% | 5.9 ms | 0 |
| steady-12000 | 16.7 / 16.8 / 16.8 (medians 16.7–33.3) | 60 | 3.9 / 5.9 / 6.8 | 0.4 / 0.6 | 0.0% (0.0–51.0) | 0.0% | 0.0% | 5.9 ms | 0 |
| fling | 16.7 / 16.7 / 16.8 (medians 16.7–33.3) | 60 | 10.5 / 11.6 / 11.9 | 0.6 / 0.8 | 0.0% (0.0–37.4) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 12.0 / 13.3 / 14.2 | 1.4 / 1.9 | 0.0% (0.0–17.8) | 0.0% | 63.2% (33.3 ms) | 46.7 ms | 0 |
| random-jumps (jump→filled 9.7/23.6 ms) | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 9.9 / 12.4 / 13.4 | 0.6 / 1.4 | 0.0% (0.0–0.0) | 0.0% | 0.3% (17.2 ms) | 15.0 ms | 0 |
| hover-scroll | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 4.8 / 12.4 / 13.0 | 0.5 / 0.9 | 0.0% (0.0–2.6) | 0.0% | 0.0% | 7.3 ms | 0 |
| fill-baseline | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 1.6 / 4.9 / 5.2 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chrome-uncapped 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 17.521 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 2.5 / 3.6 / 5.3 (medians 1.0–3.6) | 466 | 2.3 / 3.3 / 4.9 | 0.5 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 16.0 ms | 0 |
| steady-3000 | 1.1 / 2.0 / 3.0 (medians 0.9–4.7) | 778 | 1.1 / 1.8 / 2.7 | 0.2 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.7 ms | 0 |
| steady-12000 | 1.5 / 3.2 / 5.9 (medians 1.3–5.1) | 632 | 1.4 / 2.7 / 5.2 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.4 ms | 0 |
| fling | 3.6 / 5.6 / 5.8 (medians 0.9–4.0) | 245 | 3.3 / 5.1 / 5.3 | 0.7 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 2.8 / 5.4 / 7.9 (medians 1.2–9.0) | 331 | 2.4 / 4.5 / 6.0 | 0.5 / 1.2 | 0.0% (0.0–11.4) | 0.0% | 65.6% (22.8 ms) | 46.5 ms | 0 |
| random-jumps (jump→filled 19.5/25.3 ms) | 2.1 / 4.0 / 6.3 (medians 0.8–6.1) | 382 | 1.9 / 3.5 / 5.0 | 0.4 / 0.6 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 16.1 ms | 0 |
| hover-scroll | 3.9 / 5.2 / 5.6 (medians 0.9–5.3) | 245 | 3.6 / 4.8 / 5.0 | 0.7 / 0.8 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 12.4 ms | 0 |
| fill-baseline | 1.4 / 3.2 / 3.4 (medians 0.4–3.4) | 583 | 1.1 / 2.8 / 3.0 | 0.0 / 0.0 | 0.0% (0.0–2.3) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chrome-uncapped 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 17.486 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 11.3 / 17.8 / 31.8 (medians 7.9–15.1) | 88 | 11.0 / 17.1 / 23.2 | 0.7 / 0.9 | 4.4% (0.0–29.3) | 0.0% | 0.0% | 29.5 ms | 0 |
| steady-3000 | 11.6 / 22.3 / 33.2 (medians 9.7–12.4) | 81 | 12.0 / 18.1 / 20.6 | 0.8 / 2.0 | 7.2% (0.0–9.8) | 0.0% | 0.0% | 29.0 ms | 0 |
| steady-12000 | 9.7 / 13.4 / 14.3 (medians 5.0–9.9) | 107 | 9.3 / 12.8 / 13.2 | 0.6 / 0.9 | 0.0% (0.0–1.1) | 0.0% | 0.0% | 26.3 ms | 0 |
| fling | 7.6 / 14.5 / 17.5 (medians 3.9–11.0) | 111 | 7.5 / 14.0 / 16.4 | 0.6 / 0.9 | 1.3% (0.0–21.2) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 13.2 / 30.5 / 34.8 (medians 10.8–21.0) | 71 | 13.2 / 18.4 / 25.9 | 1.3 / 3.0 | 10.9% (6.1–33.0) | 0.0% | 68.8% (51.0 ms) | 65.5 ms | 0 |
| random-jumps (jump→filled 25.7/37.2 ms) | 11.6 / 15.4 / 17.6 (medians 9.3–12.1) | 84 | 11.2 / 14.0 / 16.5 | 0.6 / 1.3 | 0.3% (0.3–10.4) | 0.0% | 0.0% | 41.8 ms | 0 |
| hover-scroll | 9.0 / 12.5 / 14.8 (medians 7.6–16.2) | 119 | 8.8 / 12.1 / 14.7 | 0.6 / 0.8 | 0.0% (0.0–29.7) | 0.0% | 0.0% | 24.3 ms | 0 |
| fill-baseline | 2.6 / 6.1 / 9.2 (medians 2.3–10.5) | 283 | 1.6 / 4.3 / 7.7 | 0.0 / 0.0 | 0.0% (0.0–12.7) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chrome-gpu 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 59 | 2.5 / 3.4 / 3.6 | 0.7 / 0.8 | 2.4% (1.6–3.3) | 0.0% | 0.0% | 4.6 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 2.9 / 3.4 / 3.5 | 0.7 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 2.1 / 3.5 / 4.0 | 0.6 / 1.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.4 ms | 0 |
| fling | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 2.8 / 4.0 / 11.7 | 0.7 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 2.3 / 3.8 / 4.2 | 1.0 / 1.7 | 0.0% (0.0–3.3) | 0.0% | 66.9% (33.3 ms) | 43.4 ms | 0 |
| random-jumps (jump→filled 16.5/17.4 ms) | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.2 / 2.9 / 3.6 | 0.4 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.3% (17.0 ms) | 4.8 ms | 0 |
| hover-scroll | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 1.1 / 1.5 / 2.0 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.1 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 0.1 / 0.1 / 0.2 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chrome-gpu 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 16.666 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 0.9 / 1.5 / 1.8 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.0 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.0 / 1.5 / 1.7 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.3 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.1 / 1.9 / 2.1 | 0.3 / 0.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.3 ms | 0 |
| fling | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.1 / 1.3 / 1.7 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 1.8 / 3.5 / 4.0 | 0.8 / 1.6 | 0.0% (0.0–14.9) | 0.0% | 63.1% (33.3 ms) | 43.0 ms | 0 |
| random-jumps (jump→filled 16.7/17.2 ms) | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 0.8 / 1.6 / 1.9 | 0.3 / 0.7 | 0.0% (0.0–0.3) | 0.0% | 0.3% (17.0 ms) | 3.5 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.8 (medians 16.7–16.7) | 60 | 1.2 / 3.1 / 5.9 | 0.3 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 2.5 ms | 0 |
| fill-baseline | 16.7 / 16.8 / 16.8 (medians 16.7–16.7) | 60 | 0.2 / 0.3 / 0.3 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chrome-gpu-uncapped 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 17.329 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 0.8 / 1.6 / 2.2 (medians 0.6–0.9) | 1019 | 0.7 / 1.4 / 1.9 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.7 ms | 0 |
| steady-3000 | 0.8 / 2.6 / 3.2 (medians 0.6–1.3) | 795 | 0.7 / 2.5 / 2.7 | 0.3 / 0.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.1 ms | 0 |
| steady-12000 | 1.0 / 2.5 / 3.1 (medians 0.9–3.6) | 887 | 0.9 / 2.2 / 2.7 | 0.2 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | 0 |
| fling | 0.8 / 2.4 / 3.2 (medians 0.6–1.3) | 912 | 0.7 / 2.1 / 2.8 | 0.3 / 0.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 0.8 / 1.7 / 2.3 (medians 0.7–1.4) | 1127 | 0.7 / 1.3 / 1.8 | 0.2 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 68.5% (12.8 ms) | 43.6 ms | 0 |
| random-jumps (jump→filled 19.1/20.1 ms) | 0.6 / 0.8 / 1.4 (medians 0.5–1.2) | 1613 | 0.5 / 0.7 / 1.0 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.9 ms | 0 |
| hover-scroll | 0.6 / 1.0 / 1.3 (medians 0.6–1.4) | 1490 | 0.6 / 0.9 / 1.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.0 ms | 0 |
| fill-baseline | 0.1 / 0.1 / 0.2 (medians 0.1–0.1) | 16667 | 0.0 / 0.1 / 0.1 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### chrome-gpu-uncapped 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 17.4 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 0.6 / 0.9 / 1.2 (medians 0.6–1.5) | 1511 | 0.6 / 0.8 / 1.0 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.9 ms | 0 |
| steady-3000 | 0.7 / 1.1 / 1.3 (medians 0.6–1.8) | 1366 | 0.6 / 0.9 / 1.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.5 ms | 0 |
| steady-12000 | 0.9 / 1.2 / 1.4 (medians 0.9–2.1) | 1120 | 0.8 / 1.0 / 1.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.9 ms | 0 |
| fling | 0.6 / 1.1 / 1.2 (medians 0.6–1.4) | 1460 | 0.6 / 0.9 / 1.0 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 1.6 / 4.1 / 5.3 (medians 0.8–4.0) | 531 | 1.4 / 3.1 / 4.0 | 0.5 / 1.1 | 0.0% (0.0–0.0) | 0.0% | 66.5% (14.5 ms) | 46.1 ms | 0 |
| random-jumps (jump→filled 19.6/22.6 ms) | 0.8 / 1.5 / 3.6 (medians 0.6–1.2) | 1056 | 0.7 / 1.3 / 2.1 | 0.2 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 10.2 ms | 0 |
| hover-scroll | 0.7 / 1.3 / 2.2 (medians 0.7–0.9) | 1052 | 0.6 / 1.2 / 2.0 | 0.2 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.9 ms | 0 |
| fill-baseline | 0.1 / 0.2 / 0.3 (medians 0.1–0.2) | 7143 | 0.0 / 0.1 / 0.2 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

#### tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 1, direct painter (host Xvfb, 3 runs, idle interval 15.138 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 11.0 / 16.0 / 17.0 (medians 10.0–11.0) | 95 | 5.0 / 11.0 / 11.0 | 2.0 / 5.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.0 ms | n/a |
| steady-3000 | 16.0 / 17.0 / 19.0 (medians 16.0–16.0) | 62 | 6.0 / 12.0 / 17.0 | 2.0 / 5.0 | 0.0% (0.0–1.5) | 0.0% | 0.0% | 7.0 ms | n/a |
| steady-12000 | 16.0 / 18.0 / 18.0 (medians 16.0–16.0) | 62 | 5.0 / 15.0 / 16.0 | 2.0 / 7.0 | 0.0% (0.0–18.9) | 0.0% | 0.0% | 7.0 ms | n/a |
| fling | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 12.0 / 13.0 | 2.0 / 6.0 | 0.0% (0.0–3.4) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.0 / 17.0 / 17.0 (medians 16.0–28.0) | 62 | 6.0 / 8.0 / 9.0 | 2.0 / 3.0 | 0.0% (0.0–48.3) | 0.0% | 1.2% (16.0 ms) | 6.0 ms | n/a |
| random-jumps (jump→filled 14.0/15.0 ms) | 16.0 / 17.0 / 17.0 (medians 16.0–18.0) | 62 | 4.0 / 7.0 / 9.0 | 2.0 / 3.0 | 0.0% (0.0–36.1) | 0.0% | 0.0% | 6.0 ms | n/a |
| hover-scroll | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 6.0 / 6.0 | 2.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| fill-baseline | 2.0 / 3.0 / 4.0 (medians 2.0–4.0) | 427 | 2.0 / 2.0 / 3.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

#### tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 2, direct painter (host Xvfb, canvas at DPR 1, 2 runs, idle interval 16.115 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 29.0 / 41.0 / 44.0 (medians 17.0–41.0) | 33 | 25.0 / 34.0 / 37.0 | 4.0 / 6.5 | 35.3% (10.3–60.4) | 0.0% | 0.0% | 28.0 ms | n/a |
| steady-3000 | 30.5 / 44.0 / 65.5 (medians 18.0–43.0) | 31 | 25.0 / 34.0 / 57.5 | 4.5 / 7.0 | 40.2% (13.4–67.1) | 0.0% | 0.0% | 28.5 ms | n/a |
| steady-12000 | 35.5 / 48.0 / 49.5 (medians 25.0–46.0) | 26 | 28.5 / 40.0 / 42.5 | 5.5 / 8.5 | 58.6% (45.0–72.1) | 0.0% | 0.0% | 30.0 ms | n/a |
| fling | 31.5 / 45.5 / 48.0 (medians 20.0–43.0) | 31 | 26.5 / 38.0 / 40.0 | 4.5 / 8.0 | 47.1% (30.4–63.9) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 21.5 / 33.5 / 35.0 (medians 18.0–25.0) | 40 | 18.5 / 30.0 / 32.5 | 3.0 / 6.5 | 21.1% (0.0–42.3) | 0.0% | 13.4% (29.5 ms) | 23.0 ms | n/a |
| random-jumps (jump→filled 12.0/42.0 ms) | 16.5 / 31.0 / 35.5 (medians 16.0–17.0) | 54 | 13.5 / 26.5 / 31.5 | 2.0 / 5.0 | 8.9% (0.0–17.8) | 0.0% | 0.6% (15.5 ms) | 15.5 ms | n/a |
| hover-scroll | 18.0 / 21.5 / 23.0 (medians 18.0–18.0) | 55 | 15.5 / 16.5 / 17.0 | 2.0 / 3.0 | 0.3% (0.0–0.7) | 0.0% | 0.0% | 16.5 ms | n/a |
| fill-baseline | 17.0 / 22.5 / 24.5 (medians 17.0–17.0) | 56 | 9.5 / 14.5 / 16.5 | 0.0 / 0.0 | 9.1% (0.0–18.1) | 0.0% | 0.0% | 0.0 ms | n/a |

#### tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 2, direct painter (host Xvfb, 1 run, idle interval 8.508 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 17.0 / 18.0 / 20.0 | 60 | 14.0 / 16.0 / 17.0 | 3.0 / 4.0 | 0.0% | 0.0% | 0.0% | 16.0 ms | n/a |
| steady-3000 | 18.0 / 21.0 / 22.0 | 55 | 15.0 / 17.0 / 17.0 | 3.0 / 4.0 | 0.0% | 0.0% | 0.0% | 16.0 ms | n/a |
| steady-12000 | 18.0 / 21.0 / 25.0 | 55 | 15.0 / 17.0 / 22.0 | 3.0 / 4.0 | 1.3% | 0.0% | 0.0% | 16.0 ms | n/a |
| fling | 17.0 / 20.0 / 23.0 | 57 | 15.0 / 16.0 / 18.0 | 3.0 / 4.0 | 0.6% | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 17.0 / 19.0 / 22.0 | 58 | 15.0 / 17.0 / 18.0 | 4.0 / 4.0 | 0.0% | 0.0% | 17.2% (17.0 ms) | 15.0 ms | n/a |
| random-jumps (jump→filled 7.0/25.0 ms) | 16.0 / 19.0 / 20.0 | 60 | 13.0 / 17.0 / 18.0 | 3.0 / 4.0 | 0.0% | 0.0% | 0.0% | 14.0 ms | n/a |
| hover-scroll | 18.0 / 20.0 / 21.0 | 56 | 15.0 / 16.0 / 17.0 | 3.0 / 4.0 | 0.0% | 0.0% | 0.0% | 15.0 ms | n/a |
| fill-baseline | 16.0 / 17.0 / 18.0 | 65 | 8.0 / 9.0 / 10.0 | 0.0 / 0.0 | 0.0% | 0.0% | 0.0% | 0.0 ms | n/a |

#### tauri-webkitgtk-native WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 1, direct painter (host Xvfb, 3 runs, idle interval 15.138 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 13.0 / 17.0 / 17.0 (medians 10.0–16.0) | 80 | 6.0 / 12.0 / 12.0 | 2.0 / 6.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 14.0 ms | n/a |
| steady-3000 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 6.0 / 9.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.0 ms | n/a |
| steady-12000 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 6.0 / 7.0 | 2.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 7.0 ms | n/a |
| fling | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 6.0 / 6.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 6.0 / 8.0 / 11.0 | 2.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 2.0% (16.0 ms) | 6.0 ms | n/a |
| random-jumps (jump→filled 14.0/15.0 ms) | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 9.0 / 11.0 | 2.0 / 5.0 | 0.2% (0.0–0.3) | 0.0% | 0.0% | 6.0 ms | n/a |
| hover-scroll | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 6.0 / 9.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 9.0 ms | n/a |
| fill-baseline | 2.0 / 3.0 / 4.0 (medians 2.0–6.0) | 417 | 2.0 / 2.0 / 3.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

#### tauri-webkitgtk-native WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 2, direct painter (host Xvfb, 3 runs, idle interval 15.391 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 17.0 / 19.0 / 22.0 (medians 17.0–48.0) | 59 | 15.0 / 16.0 / 18.0 | 3.0 / 4.0 | 0.0% (0.0–68.3) | 0.0% | 0.0% | 17.0 ms | n/a |
| steady-3000 | 18.0 / 21.0 / 22.0 (medians 18.0–44.0) | 55 | 15.0 / 17.0 / 17.0 | 3.0 / 4.0 | 0.3% (0.0–62.7) | 0.0% | 0.0% | 16.0 ms | n/a |
| steady-12000 | 18.0 / 21.0 / 24.0 (medians 18.0–48.0) | 54 | 16.0 / 17.0 / 18.0 | 3.0 / 4.0 | 1.2% (0.6–66.5) | 0.0% | 0.0% | 16.0 ms | n/a |
| fling | 18.0 / 42.0 / 54.0 (medians 18.0–47.0) | 47 | 15.0 / 31.0 / 45.0 | 3.0 / 8.0 | 18.9% (0.3–66.4) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 19.0 / 21.0 / 22.0 (medians 18.0–41.0) | 54 | 17.0 / 18.0 / 19.0 | 4.0 / 4.0 | 0.0% (0.0–69.6) | 0.0% | 11.1% (19.0 ms) | 16.0 ms | n/a |
| random-jumps (jump→filled 21.0/25.0 ms) | 16.0 / 19.0 / 22.0 (medians 16.0–44.0) | 60 | 14.0 / 17.0 / 18.0 | 3.0 / 4.0 | 0.5% (0.2–64.2) | 0.0% | 0.0% | 14.0 ms | n/a |
| hover-scroll | 18.0 / 21.0 / 22.0 (medians 18.0–45.0) | 54 | 15.0 / 17.0 / 17.0 | 3.0 / 4.0 | 0.0% (0.0–61.7) | 0.0% | 0.0% | 17.0 ms | n/a |
| fill-baseline | 17.0 / 18.0 / 22.0 (medians 17.0–34.0) | 60 | 9.0 / 10.0 / 13.0 | 0.0 / 0.0 | 0.0% (0.0–52.3) | 0.0% | 0.0% | 0.0 ms | n/a |

### Reproducing

See `ui/README.md` (Benchmarks): start `rk-daemon --open <lua>
--allow-origin tauri://localhost`, build `ui/dist` and the shell, then
`bench/suite.sh` (all engines, 3 rounds, waits for a quiet machine) and
`bench/tauri-dpr-ab.sh`. Raw files go to `ui/bench/raw/` (not committed);
`bench/report-all.sh` regenerates `bench/results.json` and the tables
above.

## Phase-0 spike: mock daemon, 10M instructions

**Gate:** median frame time under 16 ms on a 10M-instruction program, in Chromium and WebKit.

### Verdict

| Engine | DPR 1 | DPR 2 |
|---|---|---|
| Chromium 153 (Playwright, software) | **pass**: every scenario on vsync, 0 % dropped; uncapped frames 0.9 to 2.8 ms median | **pass**: on vsync, 0 % dropped; uncapped 2.3 to 4.6 ms |
| Google Chrome 153 (host, software) | **pass**: same as above | **pass** |
| Google Chrome 153 (host, RTX 4080) | **pass**: uncapped 0.5 ms median (2.0 ms for the scrollbar drag) | **pass**: uncapped 0.5 to 2.1 ms |
| WebKit 26.6 (Playwright) | **pass**: 16.1 ms (its 62 Hz cadence), 0 % dropped | **pass**: 16.1 ms median; p95 up to 21 ms on flings |
| Firefox 155 (Playwright) | **pass**: 17.1 ms (its idle cadence), 0 % dropped | **pass** |
| WebKitGTK 2.52.6 in the Tauri 2.12 shell, Xvfb, CPU painting | **pass**: 16 ms median, p99 17 ms | **FAIL**: 18 to 20 ms median (50 to 54 fps); 13 % of frames dropped on random jumps |
| WebKitGTK, GPU render process, SHM transport | **pass**: 17 ms median (1 ms timer), 60 fps | **FAIL**: 29 to 34 ms, but its flat-fill control is just as slow (see below) |

The gate passes in both named engines, Chromium and WebKit, at both scales,
so the web-UI decision stands. Each one has headroom: uncapped Chromium
spends at most 4.6 ms per frame in software and 2.1 ms on the GPU.

The exception is WebKitGTK, which Tauri uses on Linux. Without GPU
compositing it misses at DPR 2. A control that only fills the canvas with a
flat color each frame (no text, no data) already takes 17 ms there, so the
listing adds only 1 to 3 ms on top of an engine floor that sits at the
budget. When other work loaded the box (load average 13), the same
configuration fell to 24 fps. WebKitGTK's real GPU path, with DMA-BUF to a
GPU compositor, can't run on this headless host. Measuring it on a real
Linux desktop is the open item before committing to Tauri on Linux.

### How to read the numbers

- **Frame interval** is the delta between successive `requestAnimationFrame`
  timestamps over each scenario: what the user sees. On a vsync-capped engine
  it can't drop below the engine's idle cadence (Chromium 16.7 ms; Playwright
  WebKit 16.1 ms, Firefox 17.1 ms and WebKitGTK about 16 ms in headless/Xvfb
  mode), so **the gate counts as passed when the median interval is within 5 %
  of max(16.7 ms, the idle cadence)**, meaning the median frame lands on
  every vsync. For the `*-uncapped` runs (Chromium with
  `--disable-gpu-vsync --disable-frame-rate-limit`) the interval *is* the
  frame time and must be under 16 ms.
- **fps** = 1000 / mean frame interval.
- **Dropped** = missed vsyncs as a share of the vsyncs in the scenario:
  Σ(round(Δ/I) − 1) / (span/I), with I the idle cadence. With WebKitGTK's
  1 ms timer (tauri:// isn't cross-origin isolated), I measures 16 ms and
  18 ms frames round to one interval, so look at fps there.
- **Main-thread cost** is the time from the start of the frame's rAF callback
  to the first task after the frame (a `MessageChannel` message posted from
  rAF): JS plus whatever style/layout/paint/canvas flush the engine does on
  the main thread. Raster and compositing on other threads or processes
  aren't in it. That's why the uncapped and GPU runs are the better guide to
  total cost.
- **JS render** is the time inside the listing's `render()` alone.
- **Blank frames** drew at least one placeholder row because its data hadn't
  arrived. **Stale frames** instead redrew the most recent fully loaded
  position (the view holds it for up to 150 ms), so the content lagged the
  scrollbar, by "lag" ms. Neither is hidden from the frame numbers. Every
  run had 0 % blank frames.
- **Long tasks** come from `PerformanceObserver('longtask')`, which only
  Chromium supports (`n/a` elsewhere). None were recorded in any Chromium
  run of the direct painter. Long animation frames (LoAF) are in the JSON.
- Each configuration ran **3 times** (the main table). The tables give the
  median of each statistic across runs, and per-scenario rows also show the
  range of the per-run medians and drop rates. The first round ran while
  other agents' fuzzers held the load average at 10 to 15; rounds 2 and 3 ran
  at 1 to 4. The spread (for example WebKitGTK DPR 2: 18 ms quiet vs 41 ms
  loaded) shows how sensitive the CPU paint paths are to a busy machine.

#### Scenarios

All scenarios drive the real input handlers in-page with synthetic events,
one step per frame, dispatched between frames as real input would be
(`src/bench/harness.ts`). The viewport is 1920×1080 CSS px with the
decompiler pane open; the listing canvas is 1400×1020 CSS px, so 2800×2040
device px at DPR 2, with about 57 visible rows. Each scenario starts from
row 2,000,000.

| id | What |
|---|---|
| steady-600 / -3000 / -12000 | Wheel deltas every frame at 600, 3000 and 12000 px/s (33, 170 and 670 rows/s), 5 s |
| fling | 4 trackpad-style flings: per-frame pixel deltas from v(t) = 25000·e^(−t/400 ms) px/s, down, down, down, up |
| scrollbar-drag | Pointer drag of the scrollbar thumb from the start position to the bottom, then to the top, over 4 s: sweeps all 11.3M rows (~94k rows per frame) |
| random-jumps | 24 `jumpTo(random address)` calls 250 ms apart (the go-to box path: `GetRowsAround`, select, center, decompiler update), with a slow scroll in between; also reports time from jump to fully drawn |
| hover-scroll | Steady scroll at 1500 px/s while the pointer wiggles over the operand column, so the hovered token and its highlight across visible rows change every frame |
| fill-baseline | Control: fill the whole listing canvas with a flat color each frame and draw nothing else, which gives the engine's floor for a full-canvas update at that size |

### Machine and engines

- Intel Core i9-14900F (24 cores / 32 threads), 31 GB RAM, NVIDIA GeForce
  RTX 4080 SUPER (driver 595.84), Ubuntu 24.04.4, kernel 7.0.0-31.
- The machine was shared with other agents (fuzzers, C++ builds). Load
  average is recorded per run in `results-spike.json`.
- **Docker:** `mcr.microsoft.com/playwright:v1.63.0-noble`, Playwright 1.63.0,
  `--network host --ipc host`, no GPU passed in. Chromium is the full browser
  in new-headless mode (`channel: "chromium"`, not the headless shell);
  `chrome://gpu` reports *Canvas: Software only, Compositing: Software only,
  Rasterization: Software only*, with WebGL on SwiftShader. Playwright's
  WebKit 26.6 and Firefox 155 render in software.
- **Host Chrome:** `/usr/bin/google-chrome` 153.0.8010.36 in headless mode,
  driven by the same runner. The default is software (same `chrome://gpu`
  status as above). `chrome-gpu` adds `--enable-gpu --ignore-gpu-blocklist`:
  *Canvas, Compositing and Rasterization: Hardware accelerated*, ANGLE on
  the RTX 4080 (OpenGL 4.5).
- **Tauri shell:** `ui/tauri/src-tauri`, Tauri 2.12.1 (wry 0.57), system
  WebKitGTK 2.52.6, release build, loading the same `dist/` over
  `tauri://localhost`. It runs under Xvfb at 1920×1080 (DPR 1) or 3840×2160
  with `GDK_SCALE=2` (DPR 2); Playwright can't drive it, so the page runs
  the identical scenario set itself (`?autobench=`) and POSTs results to the
  mock daemon. Two configurations:
  - *default*: Xvfb has no DRI3, so WebKitGTK picks hardware acceleration
    policy **never** (`webkit://gpu`) and paints on the CPU without
    compositing. This is also what Tauri apps get with
    `WEBKIT_DISABLE_COMPOSITING_MODE=1`, in many VMs and on remote X.
  - *gpu-shm*: `WEBKIT_FORCE_DMABUF_RENDERER=1 WEBKIT_DMABUF_RENDERER_FORCE_SHM=1
    WEBKIT_FORCE_COMPOSITING_MODE=1 WEBKIT_WEB_RENDER_DEVICE_FILE=/dev/dri/renderD128`.
    Policy **always**; the render process runs EGL (surfaceless) on the RTX
    4080 with 2 GPU paint threads, and every frame is copied into shared
    memory for the Xvfb-side UI process. That readback, not painting, sets
    its floor: the flat-fill control takes 29 ms at DPR 2.
- The data source is the mock daemon (Node 24, same host, localhost HTTP/1.1,
  binary protobuf). Page fetch latency (256 rows) is 4 to 6 ms median in
  Playwright engines and 5 to 19 ms in WebKitGTK.

#### How the GPU affected the results

- **Chromium:** with the same build and flags apart from the GPU, the
  uncapped frame time drops from 2.8 to 2.0 ms (DPR 1, worst scenario
  median) and from 4.6 to 2.1 ms (DPR 2). In the steady scenarios it drops
  from about 1 to 2.5 ms to 0.5 ms. The flat-fill control drops from 0.4 /
  1.4 ms to 0.1 ms. On the GPU, DPR barely matters; in software, cost
  roughly doubles with 4× the pixels. Both clear the budget by a factor of
  3 or more, so for Chromium the GPU buys headroom, not the pass.
- **WebKitGTK:** the GPU only helped where its output could be shown cheaply.
  At DPR 1 the gpu-shm main-thread cost is 5 ms against 6 ms on the CPU. At
  DPR 2 the SHM readback makes gpu-shm *slower* than the CPU path, 29 ms for
  a flat fill. This is an artifact of running under Xvfb; on a real
  compositor the frame would go over as a DMA-BUF with no readback.
- The Playwright WebKit and Firefox containers had no GPU at all, and both
  pass at DPR 2 in software. Their headless rendering paths aren't the
  WebKitGTK 2.52 library Tauri links, and they evidently do less per frame
  than WebKitGTK's non-composited path. That's why the Playwright WebKit
  row can't stand in for Tauri on Linux here.

### What made the difference

1. **Full-viewport canvas redraws are cheap; text is not the bottleneck.**
   The direct painter (`fillText` per run, batched by color, with runs
   precomputed once per row) spends 0.2 to 0.7 ms of JS per frame in
   Chromium, about 0.5 to 0.7 ms in WebKit, 1.3 ms in Firefox and 2 to 3 ms
   in WebKitGTK. The remaining frame cost is the engine moving 3 to 6M
   pixels: compare each run's flat-fill control with its scenarios.
2. **Caching glyphs or rows didn't help** (table below). A static per-color
   glyph atlas (one `drawImage` per glyph) is 2 to 4× slower than `fillText`
   in Chromium and no better anywhere else. A per-row bitmap cache cuts
   main-thread JS, but total frame time is about the same (uncapped Chromium:
   0.9 vs 1.0 ms at DPR 1, 3.3 vs 2.6 ms at DPR 2). Its first version, rows as slots
   in a few large shared canvases, ran at 90 ms per frame in Chromium at DPR
   2: drawing a canvas that changed since it was last drawn snapshots the
   whole canvas. One small canvas per row fixed that. None of the painters
   changes WebKitGTK's DPR 2 result.
3. **Binary protobuf pages.** A 256-row page is 13 KB binary vs 59 KB JSON
   and decodes in about 0.5 ms vs 1.0 to 1.6 ms (`bench/micro.ts`, all three
   engines). End to end it made no visible difference at localhost latency
   (variants table), so it's a bandwidth and battery choice, not a frame-rate
   one.
4. **Data latency is handled by the view, not by blocking.** The scrollbar
   drag sweeps 94k rows per frame, so no prefetch can keep up. Three changes
   took it from 99.6 % blank frames to 0 % blank frames:
   - Hold the most recent fully loaded position (≤ 150 ms old) instead of
     drawing placeholders, so the content trails the thumb by about one
     frame.
   - Predict one frame ahead (the per-frame row velocity) and fetch there.
     This helps Chromium most (stale frames fall to about 8 %) because the
     synthetic drag is perfectly linear. Treat that number as a best case;
     WebKit and Firefox stay at 76 to 93 % stale frames, lagging by one frame.
   - Stop aborting in-flight requests that leave the wanted set. With fetch
     latency near one frame, aborting starved the drag of all data.

   With 25 ms of injected daemon latency (variants table), steady scrolls and
   flings still never show a blank row, jumps fill in about 2 frames (32 ms)
   instead of 1, and the drag lags 1 to 2 frames.
5. **Decompiler updates off the critical frame.** Every navigation used to
   rebuild the CodeMirror state in the same frame as the listing redraw. It
   now swaps the document in a transaction scheduled after the listing's
   frame. This is a design choice and wasn't benchmarked separately; the
   jump scenario includes the decompiler update.
6. **Dispatch input between frames in the harness.** The first harness
   dispatched synthetic wheel events inside a rAF callback, which deferred
   the view's redraw to the next frame, so it rendered every other frame.
   Real input arrives before rAF. This was a measurement bug, not a UI bug,
   but it would have halved every frame count.

Nothing in the measured path skips frames or draws blank rows to save
time. The hold policy is the only place content isn't the requested
position, and it is counted as stale frames.

### What wasn't measured

- **WebKitGTK on a real GPU display** (DMA-BUF to the compositor, no SHM
  readback). This is the configuration Tauri users on working Linux desktops
  get. The only GPU-backed display on this host is the user's desktop
  session, and the spike didn't open windows on it. To measure it:
  `NO_XVFB=1 DISP=:0 SCALES=1 SUFFIX=-x11gpu ui/bench/tauri.sh` on a
  desktop with working GPU drivers, plus DPR 2 on a ≥ 3840×2160 screen.
- macOS (WKWebView) and Windows (WebView2): not available here.
- Real user input. Synthetic events go through the same handlers, but
  real wheel/trackpad input gets coalesced and pre-processed by the engine.
- A real daemon: the mock serves pages in under 1 ms on localhost. The
  25 ms latency variant gives a feel for the UI side; the daemon's own row
  path has to hold up separately.

### Gate table (direct painter, 3 runs each)

Worst scenario per configuration; the `fill-baseline` control is excluded from the gate and shown in the last column.

| Where | Engine | DPR | Painter | Runs | Gate | Worst-scenario median frame (ms) | Worst p95 | Worst p99 | Lowest fps | Max dropped | Main-thread cost median (worst) | Control: flat fill median frame |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| docker | chromium 153.0.8010.12 | 1 | direct | 3 | **pass** | 16.7 | 16.7 | 16.7 | 60 | 0.0% | 2.0 | 16.7 |
| docker | chromium 153.0.8010.12 | 2 | direct | 3 | **pass** | 16.7 | 16.7 | 16.7 | 60 | 0.0% | 3.6 | 16.7 |
| docker | chromium-uncapped 153.0.8010.12 | 1 | direct | 3 | **pass** | 2.8 | 3.9 | 7.0 | 348 | 0.0% | 2.5 | 0.4 |
| docker | chromium-uncapped 153.0.8010.12 | 2 | direct | 3 | **pass** | 4.6 | 5.9 | 16.8 | 212 | 0.0% | 4.3 | 1.4 |
| docker | webkit 26.6 | 1 | direct | 3 | **pass** | 16.1 | 16.2 | 16.2 | 62 | 0.0% | 4.0 | 16.1 |
| docker | webkit 26.6 | 2 | direct | 3 | **pass** | 16.1 | 21.4 | 22.5 | 59 | 0.3% | 6.4 | 16.1 |
| docker | firefox 155.0 | 1 | direct | 3 | **pass** | 17.1 | 17.2 | 17.2 | 60 | 0.0% | 2.2 | 17.1 |
| docker | firefox 155.0 | 2 | direct | 3 | **pass** | 17.1 | 17.2 | 17.2 | 60 | 0.0% | 2.3 | 17.1 |
| host | chrome 153.0.8010.36 | 1 | direct | 3 | **pass** | 16.7 | 16.7 | 16.7 | 60 | 0.0% | 2.9 | 16.7 |
| host | chrome 153.0.8010.36 | 2 | direct | 3 | **pass** | 16.7 | 16.7 | 16.7 | 60 | 0.0% | 3.6 | 16.7 |
| host | chrome-uncapped 153.0.8010.36 | 1 | direct | 3 | **pass** | 2.8 | 3.9 | 7.1 | 346 | 0.0% | 2.6 | 0.4 |
| host | chrome-uncapped 153.0.8010.36 | 2 | direct | 3 | **pass** | 4.6 | 6.0 | 16.8 | 211 | 0.0% | 4.3 | 1.4 |
| host | chrome-gpu 153.0.8010.36 | 1 | direct | 3 | **pass** | 16.7 | 16.7 | 16.7 | 59 | 1.3% | 1.2 | 16.7 |
| host | chrome-gpu 153.0.8010.36 | 2 | direct | 3 | **pass** | 16.7 | 16.7 | 16.7 | 60 | 0.0% | 1.2 | 16.7 |
| host | chrome-gpu-uncapped 153.0.8010.36 | 1 | direct | 3 | **pass** | 2.0 | 3.0 | 5.7 | 485 | 0.0% | 1.8 | 0.1 |
| host | chrome-gpu-uncapped 153.0.8010.36 | 2 | direct | 3 | **pass** | 2.1 | 3.1 | 5.9 | 468 | 0.0% | 1.8 | 0.1 |
| host Xvfb | tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1 | 1 | direct | 3 | **pass** | 16.0 | 17.0 | 17.0 | 62 | 0.0% | 6.0 | 4.0 |
| host Xvfb | tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1 | 2 | direct | 3 | **FAIL** | 20.0 | 26.0 | 29.0 | 50 | 13.4% | 17.0 | 17.0 |
| host Xvfb | tauri-webkitgtk-gpu-shm WebKitGTK 2.52.6 / Tauri 2.12.1 | 1 | direct | 3 | **pass** | 17.0 | 18.0 | 18.0 | 60 | 0.0% | 5.0 | 17.0 |
| host Xvfb | tauri-webkitgtk-gpu-shm WebKitGTK 2.52.6 / Tauri 2.12.1 | 2 | direct | 3 | **FAIL** | 34.0 | 60.0 | 68.0 | 25 | 62.0% | 13.0 | 29.0 |

### Painters

Frame-interval median / main-thread cost median / JS render median (ms). `direct` is the 3-run median from the gate table; `atlas` and `rowcache` ran once each on a quiet machine. `docker-uncapped-painters` ran all three back to back, uncapped, which makes it the cleanest comparison of total frame cost.

| Where | Engine | DPR | Scenario | direct | atlas | rowcache |
|---|---|---|---|---|---|---|
| docker | chromium | 1 | steady-12000 | 16.7 / 1.7 / 0.4 | 16.7 / 3.9 / 1.1 | 16.7 / 1.4 / 0.5 |
| docker | chromium | 1 | random-jumps | 16.7 / 1.2 / 0.2 | 16.7 / 3.8 / 1.1 | 16.7 / 1.0 / 0.1 |
| docker | chromium | 1 | hover-scroll | 16.7 / 1.4 / 0.3 | 16.7 / 3.9 / 1.1 | 16.7 / 1.2 / 0.2 |
| docker | chromium | 2 | steady-12000 | 16.7 / 3.0 / 0.4 | 16.7 / 6.0 / 1.1 | 16.7 / 3.8 / 0.7 |
| docker | chromium | 2 | random-jumps | 16.7 / 2.8 / 0.3 | 16.7 / 5.9 / 1.2 | 16.7 / 3.3 / 0.1 |
| docker | chromium | 2 | hover-scroll | 16.7 / 2.9 / 0.3 | 16.7 / 6.1 / 1.1 | 16.7 / 3.4 / 0.2 |
| docker | webkit | 1 | steady-12000 | 16.1 / 1.9 / 0.6 | 16.1 / 2.0 / 0.6 | 16.1 / 2.6 / 0.5 |
| docker | webkit | 1 | random-jumps | 16.1 / 1.6 / 0.4 | 16.1 / 1.7 / 0.6 | 16.1 / 1.1 / 0.2 |
| docker | webkit | 1 | hover-scroll | 16.1 / 1.8 / 0.5 | 16.1 / 2.0 / 0.6 | 16.1 / 1.7 / 0.2 |
| docker | webkit | 2 | steady-12000 | 16.1 / 2.2 / 0.7 | 16.1 / 2.1 / 0.6 | 16.1 / 2.8 / 0.5 |
| docker | webkit | 2 | random-jumps | 16.1 / 2.3 / 0.7 | 16.1 / 2.0 / 0.6 | 16.1 / 1.3 / 0.2 |
| docker | webkit | 2 | hover-scroll | 16.1 / 2.3 / 0.6 | 16.1 / 2.3 / 0.7 | 16.1 / 1.9 / 0.3 |
| docker | firefox | 1 | steady-12000 | 17.1 / 1.6 / 1.3 | 17.1 / 2.7 / 2.4 | 17.1 / 1.5 / 1.1 |
| docker | firefox | 1 | random-jumps | 17.1 / 1.5 / 1.3 | 17.0 / 2.8 / 2.5 | 17.0 / 1.2 / 0.9 |
| docker | firefox | 1 | hover-scroll | 17.0 / 1.8 / 1.2 | 17.0 / 2.9 / 2.4 | 17.1 / 1.5 / 0.9 |
| docker | firefox | 2 | steady-12000 | 17.1 / 1.6 / 1.3 | 17.1 / 2.7 / 2.4 | 17.1 / 1.5 / 1.2 |
| docker | firefox | 2 | random-jumps | 17.0 / 1.6 / 1.3 | 17.1 / 2.9 / 2.6 | 17.0 / 1.1 / 0.9 |
| docker | firefox | 2 | hover-scroll | 17.1 / 2.0 / 1.3 | 17.0 / 3.0 / 2.4 | 17.1 / 1.5 / 0.9 |
| host Xvfb | tauri-webkitgtk | 1 | steady-12000 | 16.0 / 5.0 / 2.0 | 16.0 / 6.0 / 3.0 | 16.0 / 4.0 / 1.0 |
| host Xvfb | tauri-webkitgtk | 1 | random-jumps | 16.0 / 5.0 / 2.0 | 16.0 / 6.0 / 3.0 | 16.0 / 3.0 / 1.0 |
| host Xvfb | tauri-webkitgtk | 1 | hover-scroll | 16.0 / 5.0 / 2.0 | 16.0 / 6.0 / 3.0 | 16.0 / 4.0 / 1.0 |
| host Xvfb | tauri-webkitgtk | 2 | steady-12000 | 19.0 / 16.0 / 3.0 | 20.0 / 18.0 / 6.0 | 19.0 / 16.0 / 4.0 |
| host Xvfb | tauri-webkitgtk | 2 | random-jumps | 18.0 / 15.0 / 3.0 (13% dropped) | 20.0 / 17.0 / 6.0 (13% dropped) | 18.0 / 15.0 / 4.0 (12% dropped) |
| host Xvfb | tauri-webkitgtk | 2 | hover-scroll | 18.0 / 15.0 / 3.0 | 20.0 / 18.0 / 6.0 | 19.0 / 16.0 / 4.0 |
| docker-uncapped-painters | chromium-uncapped | 1 | steady-12000 | 1.0 / 1.0 / 0.2 | 3.8 / 3.7 / 1.1 | 0.9 / 0.9 / 0.1 |
| docker-uncapped-painters | chromium-uncapped | 1 | random-jumps | 0.9 / 0.8 / 0.2 | 3.6 / 3.5 / 1.1 | 0.7 / 0.7 / 0.1 |
| docker-uncapped-painters | chromium-uncapped | 1 | hover-scroll | 0.9 / 0.8 / 0.2 | 3.6 / 3.6 / 1.1 | 0.7 / 0.7 / 0.1 |
| docker-uncapped-painters | chromium-uncapped | 2 | steady-12000 | 2.6 / 2.5 / 0.2 | 5.9 / 5.8 / 1.1 | 3.3 / 3.1 / 0.2 |
| docker-uncapped-painters | chromium-uncapped | 2 | random-jumps | 2.3 / 2.2 / 0.2 | 5.7 / 5.6 / 1.1 | 2.9 / 2.9 / 0.1 |
| docker-uncapped-painters | chromium-uncapped | 2 | hover-scroll | 2.3 / 2.3 / 0.2 | 5.9 / 5.8 / 1.1 | 2.9 / 2.9 / 0.1 |

### Variants: 25 ms daemon latency, JSON encoding

`docker-latency25ms`: mock started with `--latency 25` (every unary call delayed 25 ms). `docker-json`: `?format=json` (Connect JSON instead of binary protobuf).

| Where | Engine | DPR | Painter | Runs | Gate | Worst-scenario median frame (ms) | Worst p95 | Worst p99 | Lowest fps | Max dropped | Main-thread cost median (worst) | Control: flat fill median frame |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| docker-latency25ms | chromium 153.0.8010.12 | 1 | direct | 1 | **pass** | 16.7 | 16.7 | 16.7 | 60 | 0.0% | 2.0 | n/a |
| docker-latency25ms | webkit 26.6 | 1 | direct | 1 | **pass** | 16.1 | 16.2 | 16.9 | 62 | 0.3% | 3.2 | n/a |
| docker-json | chromium 153.0.8010.12 | 1 | direct | 1 | **pass** | 16.7 | 16.7 | 16.7 | 60 | 0.0% | 2.3 | n/a |
| docker-json | webkit 26.6 | 1 | direct | 1 | **pass** | 16.1 | 16.2 | 17.5 | 62 | 0.0% | 4.7 | n/a |

##### Variant: chromium 153.0.8010.12, DPR 1, direct painter (docker-latency25ms, 1 run, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-12000 | 16.7 / 16.7 / 16.7 | 60 | 1.7 / 2.5 / 2.9 | 0.4 / 0.6 | 0.0% | 0.0% | 0.0% | 28.9 ms | 0 |
| fling | 16.7 / 16.7 / 16.7 | 60 | 1.5 / 1.9 / 2.5 | 0.3 / 0.4 | 0.0% | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 | 60 | 2.0 / 2.3 / 3.3 | 0.7 / 0.9 | 0.0% | 0.0% | 99.6% (16.7 ms) | 27.7 ms | 0 |
| random-jumps (jump→filled 32.9/33.5 ms) | 16.7 / 16.7 / 16.7 | 60 | 1.4 / 2.6 / 3.0 | 0.3 / 0.8 | 0.0% | 0.0% | 0.0% | 28.9 ms | 0 |

##### Variant: webkit 26.6, DPR 1, direct painter (docker-latency25ms, 1 run, idle interval 16.16 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-12000 | 16.1 / 16.1 / 16.2 | 62 | 3.2 / 4.1 / 5.1 | 1.2 / 1.7 | 0.0% | 0.0% | 0.0% | 29.1 ms | n/a |
| fling | 16.1 / 16.1 / 16.2 | 62 | 1.9 / 3.0 / 3.1 | 0.5 / 0.9 | 0.0% | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.1 / 16.2 / 16.3 | 62 | 2.8 / 5.1 / 6.4 | 1.4 / 2.6 | 0.0% | 0.0% | 99.6% (32.1 ms) | 28.6 ms | n/a |
| random-jumps (jump→filled 31.9/33.9 ms) | 16.1 / 16.2 / 16.9 | 62 | 1.9 / 4.5 / 5.2 | 0.5 / 1.3 | 0.3% | 0.0% | 0.0% | 29.3 ms | n/a |

##### Variant: chromium 153.0.8010.12, DPR 1, direct painter (docker-json, 1 run, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-12000 | 16.7 / 16.7 / 16.7 | 60 | 1.6 / 2.5 / 2.8 | 0.3 / 0.6 | 0.0% | 0.0% | 0.0% | 3.7 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 | 60 | 2.3 / 3.4 / 3.9 | 0.8 / 1.3 | 0.0% | 0.0% | 7.8% (16.8 ms) | 3.7 ms | 0 |
| random-jumps (jump→filled 15.7/16.4 ms) | 16.7 / 16.7 / 16.7 | 60 | 1.5 / 3.0 / 4.5 | 0.3 / 0.9 | 0.0% | 0.0% | 0.0% | 5.5 ms | 0 |

##### Variant: webkit 26.6, DPR 1, direct painter (docker-json, 1 run, idle interval 16.18 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-12000 | 16.1 / 16.1 / 16.2 | 62 | 2.1 / 3.7 / 5.2 | 0.7 / 1.3 | 0.0% | 0.0% | 0.0% | 4.3 ms | n/a |
| scrollbar-drag | 16.1 / 16.2 / 17.5 | 62 | 4.7 / 8.7 / 10.4 | 1.6 / 3.0 | 0.0% | 0.0% | 72.0% (16.1 ms) | 6.0 ms | n/a |
| random-jumps (jump→filled 15.9/17.0 ms) | 16.1 / 16.2 / 16.3 | 62 | 2.1 / 7.0 / 9.4 | 0.7 / 1.4 | 0.0% | 0.0% | 0.0% | 6.3 ms | n/a |

### Per-scenario detail (gate configurations)

##### chromium 153.0.8010.12, DPR 1, direct painter (docker, 3 runs, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.1 / 1.4 / 1.5 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.3 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.6 / 2.3 / 2.6 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.6 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.7 / 1.9 / 2.2 | 0.4 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.3 ms | 0 |
| fling | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.4 / 1.9 / 2.2 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.0 / 2.5 / 2.8 | 0.7 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 8.7% (16.8 ms) | 2.8 ms | 0 |
| random-jumps (jump→filled 16.0/16.8 ms) | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.2 / 2.7 / 3.7 | 0.2 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.2 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.4 / 1.9 / 2.4 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.3 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.5 / 0.7 / 1.3 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chromium 153.0.8010.12, DPR 2, direct painter (docker, 3 runs, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 3.4 / 4.0 / 5.0 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.6 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 3.6 / 4.2 / 4.4 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.4 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 3.0 / 4.0 / 4.2 | 0.4 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.3 ms | 0 |
| fling | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 3.0 / 3.7 / 5.0 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 3.6 / 4.2 / 4.6 | 0.8 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 9.1% (16.8 ms) | 4.4 ms | 0 |
| random-jumps (jump→filled 14.5/14.8 ms) | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.8 / 4.5 / 5.7 | 0.3 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.9 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.9 / 3.5 / 3.7 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.3 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.9 / 1.1 / 2.4 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chromium-uncapped 153.0.8010.12, DPR 1, direct painter (docker, 3 runs, idle interval 17.44 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 0.8 / 1.0 / 1.3 (medians 0.8–2.2) | 1145 | 0.8 / 0.9 / 1.1 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.4 ms | 0 |
| steady-3000 | 0.9 / 1.2 / 1.3 (medians 0.9–2.5) | 1080 | 0.8 / 1.0 / 1.1 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.5 ms | 0 |
| steady-12000 | 1.0 / 1.2 / 1.5 (medians 1.0–2.7) | 970 | 1.0 / 1.1 / 1.2 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.3 ms | 0 |
| fling | 0.9 / 1.1 / 1.3 (medians 0.9–2.3) | 1095 | 0.8 / 1.0 / 1.1 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 2.8 / 3.9 / 7.0 (medians 2.8–4.5) | 348 | 2.5 / 3.3 / 5.5 | 0.5 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 99.9% (11.3 ms) | 8.9 ms | 0 |
| random-jumps (jump→filled 19.8/20.5 ms) | 0.9 / 1.1 / 2.4 (medians 0.9–2.3) | 1015 | 0.8 / 1.0 / 1.8 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.8 ms | 0 |
| hover-scroll | 0.9 / 1.3 / 1.5 (medians 0.9–2.2) | 1054 | 0.9 / 1.1 / 1.4 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.9 ms | 0 |
| fill-baseline | 0.4 / 0.6 / 0.8 (medians 0.3–0.9) | 2532 | 0.2 / 0.4 / 0.5 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chromium-uncapped 153.0.8010.12, DPR 2, direct painter (docker, 3 runs, idle interval 17.485 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 2.2 / 2.6 / 2.9 (medians 2.2–7.6) | 433 | 2.2 / 2.5 / 2.7 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.4 ms | 0 |
| steady-3000 | 2.4 / 2.7 / 3.2 (medians 2.4–7.8) | 413 | 2.3 / 2.5 / 2.9 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.8 ms | 0 |
| steady-12000 | 2.7 / 4.7 / 10.6 (medians 2.5–7.8) | 324 | 2.5 / 4.3 / 9.4 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 10.9 ms | 0 |
| fling | 2.3 / 2.9 / 3.3 (medians 2.3–2.4) | 405 | 2.2 / 2.8 / 3.1 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 4.6 / 5.9 / 9.4 (medians 4.6–5.0) | 212 | 4.3 / 5.6 / 7.7 | 0.5 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 99.8% (18.7 ms) | 14.3 ms | 0 |
| random-jumps (jump→filled 21.3/21.8 ms) | 2.3 / 4.4 / 16.8 (medians 2.3–2.8) | 369 | 2.3 / 3.4 / 6.0 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 10.2 ms | 0 |
| hover-scroll | 2.3 / 3.1 / 5.7 (medians 2.3–2.5) | 399 | 2.3 / 2.9 / 5.5 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 9.1 ms | 0 |
| fill-baseline | 1.4 / 2.0 / 5.1 (medians 1.4–1.9) | 652 | 0.8 / 0.9 / 4.5 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### webkit 26.6, DPR 1, direct painter (docker, 3 runs, idle interval 16.12 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 1.7 / 2.6 / 3.0 | 0.4 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.3 ms | n/a |
| steady-3000 | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 1.7 / 2.8 / 3.1 | 0.4 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.2 ms | n/a |
| steady-12000 | 16.1 / 16.2 / 16.2 (medians 16.1–16.1) | 62 | 1.9 / 3.3 / 3.9 | 0.6 / 1.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.5 ms | n/a |
| fling | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 1.6 / 2.6 / 3.1 | 0.4 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.1 / 16.2 / 16.2 (medians 16.1–16.1) | 62 | 4.0 / 6.7 / 8.1 | 1.4 / 2.7 | 0.0% (0.0–0.0) | 0.0% | 76.4% (16.1 ms) | 4.3 ms | n/a |
| random-jumps (jump→filled 15.9/16.9 ms) | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 1.6 / 5.6 / 7.7 | 0.4 / 1.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.4 ms | n/a |
| hover-scroll | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 1.8 / 2.8 / 3.1 | 0.5 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.4 ms | n/a |
| fill-baseline | 16.1 / 16.2 / 16.2 (medians 16.1–16.1) | 62 | 0.2 / 0.3 / 0.3 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

##### webkit 26.6, DPR 2, direct painter (docker, 3 runs, idle interval 16.12 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 2.0 / 3.2 / 3.4 | 0.5 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.6 ms | n/a |
| steady-3000 | 16.1 / 16.2 / 16.3 (medians 16.1–16.1) | 62 | 2.1 / 3.3 / 3.5 | 0.5 / 1.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.6 ms | n/a |
| steady-12000 | 16.1 / 16.2 / 16.2 (medians 16.1–17.3) | 62 | 2.2 / 3.9 / 4.9 | 0.7 / 1.4 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 3.8 ms | n/a |
| fling | 16.1 / 21.4 / 22.5 (medians 16.1–16.1) | 59 | 2.2 / 4.5 / 5.0 | 0.6 / 1.3 | 0.0% (0.0–15.1) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.1 / 17.1 / 20.4 (medians 16.1–29.8) | 62 | 6.4 / 9.2 / 11.2 | 2.3 / 4.0 | 0.0% (0.0–47.3) | 0.0% | 83.1% (16.1 ms) | 6.6 ms | n/a |
| random-jumps (jump→filled 15.9/19.0 ms) | 16.1 / 16.2 / 17.1 (medians 16.1–16.2) | 62 | 2.3 / 7.7 / 11.1 | 0.7 / 1.5 | 0.3% (0.0–3.1) | 0.0% | 0.0% | 5.8 ms | n/a |
| hover-scroll | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 2.3 / 3.5 / 3.9 | 0.6 / 1.1 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.0 ms | n/a |
| fill-baseline | 16.1 / 16.1 / 16.2 (medians 16.1–16.1) | 62 | 0.3 / 0.3 / 0.4 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

##### firefox 155.0, DPR 1, direct painter (docker, 3 runs, idle interval 17 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.7 / 3.0 / 3.2 | 1.4 / 2.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.4 ms | n/a |
| steady-3000 | 17.0 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.6 / 2.9 / 3.1 | 1.3 / 2.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.3 ms | n/a |
| steady-12000 | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.6 / 2.8 / 3.1 | 1.3 / 2.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.1 ms | n/a |
| fling | 17.1 / 17.2 / 17.2 (medians 17.1–17.1) | 60 | 1.4 / 1.6 / 2.4 | 1.2 / 1.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 2.2 / 4.0 / 4.2 | 1.9 / 3.5 | 0.0% (0.0–0.0) | 0.0% | 92.5% (16.9 ms) | 5.0 ms | n/a |
| random-jumps (jump→filled 16.6/18.2 ms) | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.5 / 3.6 / 6.8 | 1.3 / 2.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.8 ms | n/a |
| hover-scroll | 17.0 / 17.2 / 17.2 (medians 17.0–17.0) | 60 | 1.8 / 2.2 / 3.5 | 1.2 / 1.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.9 ms | n/a |
| fill-baseline | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 0.0 / 0.1 / 0.1 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

##### firefox 155.0, DPR 2, direct painter (docker, 3 runs, idle interval 16.38 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 17.0 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.4 / 2.5 / 2.9 | 1.2 / 2.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.4 ms | n/a |
| steady-3000 | 17.0 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.5 / 3.0 / 3.2 | 1.2 / 2.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.6 ms | n/a |
| steady-12000 | 17.1 / 17.1 / 17.2 (medians 17.0–17.1) | 60 | 1.6 / 3.1 / 3.4 | 1.3 / 2.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.6 ms | n/a |
| fling | 17.0 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.4 / 1.9 / 2.9 | 1.2 / 1.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 17.1 / 17.1 / 17.2 (medians 17.1–17.1) | 60 | 2.3 / 3.9 / 4.2 | 1.9 / 3.3 | 0.0% (0.0–0.0) | 0.0% | 88.4% (17.0 ms) | 4.5 ms | n/a |
| random-jumps (jump→filled 16.5/18.0 ms) | 17.0 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 1.6 / 3.7 / 6.4 | 1.3 / 2.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.4 ms | n/a |
| hover-scroll | 17.1 / 17.1 / 17.2 (medians 17.0–17.1) | 60 | 2.0 / 3.3 / 3.8 | 1.3 / 2.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.8 ms | n/a |
| fill-baseline | 17.1 / 17.2 / 17.2 (medians 17.0–17.1) | 60 | 0.0 / 0.1 / 0.1 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

##### chrome 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.6 / 3.0 / 3.1 | 0.4 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.8 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.9 / 3.2 / 3.5 | 0.5 / 0.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.5 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.7 / 2.3 / 3.1 | 0.3 / 0.6 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.7 ms | 0 |
| fling | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.5 / 1.7 / 1.9 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.2 / 2.5 / 2.8 | 0.8 / 1.0 | 0.0% (0.0–0.0) | 0.0% | 7.8% (16.8 ms) | 3.0 ms | 0 |
| random-jumps (jump→filled 16.1/16.5 ms) | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.1 / 2.7 / 3.5 | 0.2 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.3 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.3 / 1.5 / 1.7 | 0.3 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.3 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.3 / 0.4 / 0.6 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chrome 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.8 / 3.2 / 3.6 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.2 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.9 / 3.5 / 4.6 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.4 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.9 / 3.5 / 3.8 | 0.4 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.4 ms | 0 |
| fling | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.8 / 3.2 / 3.5 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 3.6 / 4.2 / 6.2 | 0.8 / 0.9 | 0.0% (0.0–0.0) | 0.0% | 8.7% (16.8 ms) | 4.3 ms | 0 |
| random-jumps (jump→filled 14.4/14.9 ms) | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.8 / 4.6 / 5.6 | 0.3 / 0.8 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 2.9 / 3.2 / 3.7 | 0.3 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.5 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.9 / 1.0 / 2.3 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chrome-uncapped 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 17.445 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 0.9 / 1.0 / 1.2 (medians 0.8–2.6) | 1143 | 0.8 / 0.9 / 1.1 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.4 ms | 0 |
| steady-3000 | 0.9 / 1.2 / 1.4 (medians 0.9–3.1) | 1062 | 0.9 / 1.0 / 1.2 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | 0 |
| steady-12000 | 1.1 / 1.2 / 1.6 (medians 1.0–3.2) | 951 | 1.0 / 1.1 / 1.4 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.6 ms | 0 |
| fling | 0.9 / 1.2 / 1.3 (medians 0.9–2.7) | 1072 | 0.9 / 1.1 / 1.1 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 2.8 / 3.9 / 7.1 (medians 2.8–4.5) | 346 | 2.6 / 3.5 / 6.6 | 0.5 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 99.9% (11.3 ms) | 8.8 ms | 0 |
| random-jumps (jump→filled 19.8/20.1 ms) | 0.9 / 1.2 / 2.4 (medians 0.9–2.8) | 989 | 0.8 / 1.0 / 1.7 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.5 ms | 0 |
| hover-scroll | 0.9 / 1.2 / 1.4 (medians 0.9–2.8) | 1066 | 0.9 / 1.1 / 1.2 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.5 ms | 0 |
| fill-baseline | 0.4 / 0.4 / 0.5 (medians 0.4–1.2) | 2762 | 0.2 / 0.2 / 0.3 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chrome-uncapped 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 17.33 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 2.2 / 2.6 / 2.9 (medians 2.2–9.4) | 436 | 2.2 / 2.4 / 2.6 | 0.2 / 0.2 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 9.4 ms | 0 |
| steady-3000 | 2.4 / 2.7 / 3.0 (medians 2.4–8.7) | 408 | 2.3 / 2.5 / 2.7 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 9.3 ms | 0 |
| steady-12000 | 2.6 / 3.0 / 4.7 (medians 2.5–9.0) | 377 | 2.5 / 2.8 / 4.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 9.1 ms | 0 |
| fling | 2.3 / 2.8 / 3.0 (medians 2.3–8.4) | 418 | 2.2 / 2.5 / 2.8 | 0.2 / 0.2 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 4.6 / 6.0 / 9.1 (medians 4.5–12.3) | 211 | 4.3 / 5.5 / 7.9 | 0.5 / 0.7 | 0.0% (0.0–0.4) | 0.0% | 99.7% (18.8 ms) | 14.8 ms | 0 |
| random-jumps (jump→filled 21.1/22.3 ms) | 2.3 / 4.6 / 16.8 (medians 2.3–8.7) | 375 | 2.2 / 3.5 / 5.6 | 0.2 / 0.2 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 10.6 ms | 0 |
| hover-scroll | 2.3 / 2.7 / 3.5 (medians 2.3–8.9) | 415 | 2.3 / 2.6 / 2.9 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 8.2 ms | 0 |
| fill-baseline | 1.4 / 2.1 / 4.8 (medians 1.4–6.3) | 643 | 0.8 / 1.2 / 4.2 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chrome-gpu 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 59 | 0.6 / 0.8 / 1.1 | 0.2 / 0.3 | 1.3% (1.0–2.0) | 0.0% | 0.0% | 3.1 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.7 / 1.0 / 1.2 | 0.2 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 2.7 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.7 / 1.1 / 1.2 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 2.5 ms | 0 |
| fling | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.6 / 0.9 / 1.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.2 / 1.9 / 2.2 | 0.7 / 1.1 | 0.0% (0.0–0.0) | 0.0% | 9.1% (16.8 ms) | 2.4 ms | 0 |
| random-jumps (jump→filled 16.7/17.3 ms) | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.6 / 1.9 / 2.6 | 0.2 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.5 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.7 / 0.9 / 1.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.2 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.0 / 0.1 / 0.1 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chrome-gpu 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 16.665 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.6 / 1.0 / 1.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.2 ms | 0 |
| steady-3000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.7 / 0.9 / 1.1 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 2.9 ms | 0 |
| steady-12000 | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.7 / 1.0 / 1.2 | 0.3 / 0.5 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 2.7 ms | 0 |
| fling | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.6 / 0.9 / 1.2 | 0.2 / 0.3 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 1.2 / 1.7 / 2.1 | 0.7 / 1.0 | 0.0% (0.0–0.0) | 0.0% | 10.7% (16.7 ms) | 2.2 ms | 0 |
| random-jumps (jump→filled 16.7/17.1 ms) | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.6 / 1.8 / 2.8 | 0.2 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.2 ms | 0 |
| hover-scroll | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.7 / 1.0 / 1.2 | 0.2 / 0.4 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.1 ms | 0 |
| fill-baseline | 16.7 / 16.7 / 16.7 (medians 16.7–16.7) | 60 | 0.0 / 0.1 / 0.1 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chrome-gpu-uncapped 153.0.8010.36, DPR 1, direct painter (host, 3 runs, idle interval 17.53 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 0.5 / 0.6 / 0.8 (medians 0.5–1.0) | 2062 | 0.4 / 0.5 / 0.7 | 0.1 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.0 ms | 0 |
| steady-3000 | 0.5 / 0.7 / 0.9 (medians 0.5–1.1) | 1980 | 0.4 / 0.6 / 0.8 | 0.1 / 0.2 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 3.8 ms | 0 |
| steady-12000 | 0.5 / 0.7 / 0.9 (medians 0.5–1.3) | 1770 | 0.5 / 0.6 / 0.6 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.1 ms | 0 |
| fling | 0.5 / 0.7 / 0.8 (medians 0.5–1.1) | 1961 | 0.5 / 0.6 / 0.6 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 2.0 / 3.0 / 5.7 (medians 2.0–4.8) | 485 | 1.8 / 2.5 / 5.0 | 0.5 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 99.9% (8.1 ms) | 6.2 ms | 0 |
| random-jumps (jump→filled 19.0/19.5 ms) | 0.5 / 0.7 / 1.2 (medians 0.5–1.1) | 1757 | 0.5 / 0.5 / 0.8 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.3 ms | 0 |
| hover-scroll | 0.5 / 0.7 / 0.9 (medians 0.5–1.1) | 1931 | 0.5 / 0.6 / 0.7 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.0 ms | 0 |
| fill-baseline | 0.1 / 0.1 / 0.1 (medians 0.1–0.1) | 18182 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### chrome-gpu-uncapped 153.0.8010.36, DPR 2, direct painter (host, 3 runs, idle interval 17.515 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 0.5 / 0.6 / 0.8 (medians 0.5–1.1) | 1996 | 0.4 / 0.5 / 0.7 | 0.1 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.9 ms | 0 |
| steady-3000 | 0.5 / 0.7 / 0.8 (medians 0.5–1.0) | 1905 | 0.5 / 0.6 / 0.7 | 0.2 / 0.2 | 0.0% (0.0–0.3) | 0.0% | 0.0% | 3.8 ms | 0 |
| steady-12000 | 0.6 / 0.7 / 1.0 (medians 0.6–1.4) | 1684 | 0.5 / 0.6 / 0.8 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.1 ms | 0 |
| fling | 0.5 / 0.7 / 0.8 (medians 0.5–1.1) | 1862 | 0.5 / 0.6 / 0.7 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |
| scrollbar-drag | 2.1 / 3.1 / 5.9 (medians 2.1–2.9) | 468 | 1.8 / 2.6 / 5.0 | 0.5 / 0.7 | 0.0% (0.0–0.0) | 0.0% | 100.0% (8.5 ms) | 6.5 ms | 0 |
| random-jumps (jump→filled 18.9/19.5 ms) | 0.5 / 0.7 / 1.3 (medians 0.5–1.1) | 1692 | 0.5 / 0.6 / 0.8 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.3 ms | 0 |
| hover-scroll | 0.5 / 0.8 / 0.9 (medians 0.5–1.1) | 1842 | 0.5 / 0.6 / 0.8 | 0.2 / 0.2 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.9 ms | 0 |
| fill-baseline | 0.1 / 0.1 / 0.1 (medians 0.1–0.1) | 16949 | 0.0 / 0.0 / 0.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | 0 |

##### tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 1, direct painter (host Xvfb, 3 runs, idle interval 16 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 5.0 / 6.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| steady-3000 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 5.0 / 6.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| steady-12000 | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 6.0 / 6.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| fling | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 6.0 / 8.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 6.0 / 7.0 / 10.0 | 2.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 26.0% (16.0 ms) | 6.0 ms | n/a |
| random-jumps (jump→filled 13.0/14.0 ms) | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 71 | 5.0 / 7.0 / 8.0 | 2.0 / 3.0 | 0.0% (0.0–2.5) | 0.0% | 0.0% | 6.0 ms | n/a |
| hover-scroll | 16.0 / 17.0 / 17.0 (medians 16.0–16.0) | 62 | 5.0 / 8.0 / 9.0 | 2.0 / 4.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| fill-baseline | 4.0 / 7.0 / 8.0 (medians 3.0–7.0) | 230 | 3.0 / 4.0 / 5.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

##### tauri-webkitgtk WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 2, direct painter (host Xvfb, 3 runs, idle interval 16 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 18.0 / 22.0 / 24.0 (medians 18.0–42.0) | 53 | 15.0 / 17.0 / 19.0 | 3.0 / 4.0 | 1.0% (0.3–68.8) | 0.0% | 0.0% | 15.0 ms | n/a |
| steady-3000 | 19.0 / 22.0 / 24.0 (medians 18.0–41.0) | 53 | 16.0 / 16.0 / 18.0 | 3.0 / 4.0 | 1.3% (0.3–70.5) | 0.0% | 0.0% | 14.0 ms | n/a |
| steady-12000 | 19.0 / 22.0 / 24.0 (medians 18.0–41.0) | 53 | 16.0 / 17.0 / 21.0 | 3.0 / 4.0 | 0.9% (0.3–72.0) | 0.0% | 0.0% | 15.0 ms | n/a |
| fling | 18.0 / 22.0 / 24.0 (medians 18.0–41.0) | 54 | 15.0 / 17.0 / 20.0 | 3.0 / 5.0 | 1.3% (0.9–66.9) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 20.0 / 23.0 / 25.0 (medians 19.0–41.0) | 50 | 17.0 / 18.0 / 18.0 | 4.0 / 4.0 | 2.4% (0.0–64.6) | 0.0% | 80.4% (20.0 ms) | 15.0 ms | n/a |
| random-jumps (jump→filled 18.0/29.0 ms) | 18.0 / 26.0 / 29.0 (medians 18.0–43.0) | 51 | 15.0 / 23.0 / 27.0 | 3.0 / 5.0 | 13.4% (11.8–68.0) | 0.0% | 0.0% | 19.0 ms | n/a |
| hover-scroll | 18.0 / 22.0 / 23.0 (medians 18.0–42.0) | 54 | 15.0 / 16.0 / 17.0 | 3.0 / 4.0 | 0.0% (0.0–70.5) | 0.0% | 0.0% | 14.0 ms | n/a |
| fill-baseline | 17.0 / 18.0 / 21.0 (medians 17.0–35.0) | 60 | 11.0 / 12.0 / 16.0 | 0.0 / 0.0 | 0.0% (0.0–45.8) | 0.0% | 0.0% | 0.0 ms | n/a |

##### tauri-webkitgtk-gpu-shm WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 1, direct painter (host Xvfb, 3 runs, idle interval 16 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 17.0 / 18.0 / 18.0 (medians 16.0–17.0) | 60 | 4.0 / 5.0 / 6.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.0 ms | n/a |
| steady-3000 | 17.0 / 17.0 / 18.0 (medians 17.0–17.0) | 60 | 5.0 / 5.0 / 6.0 | 1.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| steady-12000 | 17.0 / 18.0 / 18.0 (medians 17.0–17.0) | 60 | 5.0 / 5.0 / 6.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 5.0 ms | n/a |
| fling | 17.0 / 17.0 / 18.0 (medians 17.0–17.0) | 60 | 4.0 / 5.0 / 5.0 | 1.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 17.0 / 18.0 / 18.0 (medians 17.0–17.0) | 60 | 5.0 / 6.0 / 7.0 | 2.0 / 2.0 | 0.0% (0.0–0.0) | 0.0% | 61.7% (17.0 ms) | 5.0 ms | n/a |
| random-jumps (jump→filled 15.0/16.0 ms) | 17.0 / 18.0 / 18.0 (medians 17.0–17.0) | 60 | 5.0 / 8.0 / 11.0 | 1.0 / 3.0 | 0.0% (0.0–1.0) | 0.0% | 0.0% | 6.0 ms | n/a |
| hover-scroll | 17.0 / 18.0 / 18.0 (medians 17.0–17.0) | 60 | 5.0 / 6.0 / 6.0 | 1.0 / 3.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 4.0 ms | n/a |
| fill-baseline | 17.0 / 17.0 / 18.0 (medians 16.0–17.0) | 60 | 1.0 / 1.0 / 3.0 | 0.0 / 0.0 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0 ms | n/a |

##### tauri-webkitgtk-gpu-shm WebKitGTK 2.52.6 / Tauri 2.12.1, DPR 2, direct painter (host Xvfb, 3 runs, idle interval 16 ms)

| Scenario | Frame interval med / p95 / p99 | fps | Main-thread cost med / p95 / p99 | JS render med / p95 | Dropped | Blank frames | Stale frames (lag med) | Fetch med | Long tasks |
|---|---|---|---|---|---|---|---|---|---|
| steady-600 | 33.0 / 38.0 / 48.0 (medians 33.0–61.0) | 31 | 9.0 / 14.0 / 15.0 | 3.0 / 3.0 | 49.6% (49.0–75.4) | 0.0% | 0.0% | 11.0 ms | n/a |
| steady-3000 | 31.0 / 42.0 / 51.0 (medians 29.0–60.0) | 31 | 13.0 / 14.0 / 15.0 | 1.0 / 3.0 | 53.2% (52.4–77.3) | 0.0% | 0.0% | 13.0 ms | n/a |
| steady-12000 | 34.0 / 60.0 / 64.0 (medians 33.0–54.0) | 25 | 13.0 / 14.0 / 15.0 | 2.0 / 4.0 | 62.0% (57.6–71.3) | 0.0% | 0.0% | 13.0 ms | n/a |
| fling | 32.0 / 60.0 / 68.0 (medians 29.0–54.0) | 27 | 13.0 / 14.0 / 15.0 | 2.0 / 3.0 | 57.9% (54.6–71.0) | 0.0% | 0.0% | 0.0 ms | n/a |
| scrollbar-drag | 31.0 / 34.0 / 38.0 (medians 29.0–61.0) | 33 | 13.0 / 15.0 / 15.0 | 2.0 / 3.0 | 54.6% (51.1–73.5) | 0.0% | 65.2% (31.0 ms) | 13.0 ms | n/a |
| random-jumps (jump→filled 19.0/29.0 ms) | 30.0 / 32.0 / 32.0 (medians 29.0–61.0) | 33 | 13.0 / 16.0 / 17.0 | 1.0 / 2.0 | 54.8% (52.2–76.9) | 0.0% | 0.0% | 14.0 ms | n/a |
| hover-scroll | 29.0 / 30.0 / 31.0 (medians 29.0–60.0) | 35 | 13.0 / 14.0 / 14.0 | 1.0 / 2.0 | 54.7% (54.0–76.8) | 0.0% | 0.0% | 13.0 ms | n/a |
| fill-baseline | 29.0 / 30.0 / 32.0 (medians 29.0–61.0) | 35 | 1.0 / 1.0 / 2.0 | 0.0 / 0.0 | 54.5% (54.2–72.5) | 0.0% | 0.0% | 0.0 ms | n/a |

### Reproducing

The spike's mock daemon and `revkit.ui.v1` protocol were removed in UI v1, so these runs are reproducible only from the spike's commit (branch `phase0/ui-spike`). `bench/results-spike.json` holds every run plus the aggregated rows. The bundle that was measured is commit `02e767a`. Later commits change only the harness's idle-cadence estimate (mean instead of median, for 1 ms timers), CSS ligatures in the C pane, and docs.
