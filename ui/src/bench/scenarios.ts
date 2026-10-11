// The scenario set (each starts 30 % into the listing), shared by the Playwright runner and the in-app
// autobench mode (used for engines Playwright can't drive, e.g. the Tauri
// shell's WebKitGTK).

export interface ScenarioSpec {
  id: string;
  scenario: string;
  params: Record<string, number>;
  label: string;
}

export const SCENARIOS: ScenarioSpec[] = [
  { id: "steady-600", scenario: "steady", params: { speed: 600, durationMs: 5000 }, label: "steady scroll 600 px/s (~33 rows/s)" },
  { id: "steady-3000", scenario: "steady", params: { speed: 3000, durationMs: 5000 }, label: "steady scroll 3000 px/s (~170 rows/s)" },
  { id: "steady-12000", scenario: "steady", params: { speed: 12000, durationMs: 5000 }, label: "steady scroll 12000 px/s (~670 rows/s)" },
  { id: "fling", scenario: "fling", params: { v0: 25000, tauMs: 400, count: 4 }, label: "4 trackpad flings, 25000 px/s decaying (tau 400 ms)" },
  { id: "scrollbar-drag", scenario: "scrollbar-drag", params: { durationMs: 4000 }, label: "scrollbar thumb dragged bottom then top over 4 s (every row)" },
  { id: "random-jumps", scenario: "random-jumps", params: { count: 24, intervalMs: 250 }, label: "24 jumps to random function entries, 250 ms apart" },
  { id: "hover-scroll", scenario: "hover-scroll", params: { speed: 1500, durationMs: 5000 }, label: "operand hover highlight while scrolling 1500 px/s" },
  { id: "fill-baseline", scenario: "fill-baseline", params: { durationMs: 3000 }, label: "control: flat full-canvas fill each frame, no text (engine floor)" },
];
