export interface Theme {
  bg: string;
  fg: string;
  addr: string;
  bytes: string;
  mnemonic: string;
  flowMnemonic: string;
  register: string;
  immediate: string;
  address: string;
  symbol: string;
  punct: string;
  comment: string;
  xref: string;
  header: string;
  headerBg: string;
  label: string;
  selRow: string;
  hoverTok: string;
  selTok: string;
  syncRow: string;
  placeholder: string;
  track: string;
  thumb: string;
  thumbActive: string;
  marker: string;
  /** Names a user asserted. */
  userName: string;
  /** Names an agent asserted. */
  agentName: string;
  /** Rule above a function's entry row. */
  entryRule: string;
  syncAddr: string;
  /** Types shown on data rows (a global's asserted type). */
  type: string;
  /** The flow override marker. */
  override: string;
  /** Flow arrows: unconditional, conditional, and the selection's. */
  arrow: string;
  arrowCond: string;
  arrowSel: string;
  /** Header rows of a function (plate, signature, label). */
  headerRowBg: string;
  /** The marker of rows with notes. */
  note: string;
  /** Search hits in the gutter. */
  searchMark: string;
  /** The decompiler's slice mirrored here (a bar and a tint on its instructions). */
  sliceMark: string;
  sliceRow: string;
  /** Patched rows (PatchService): the row's tint, the gutter mark, the changed bytes. */
  patchedRow: string;
  patchMark: string;
  patchedByte: string;
}

// Colours meet WCAG AA (4.5:1) on the background, header rows and the
// selected row, in both themes (phase 7 accessibility pass).
export const DARK: Theme = {
  bg: "#10141b",
  fg: "#c9d1d9",
  addr: "#9da5ae",
  bytes: "#939ba5",
  mnemonic: "#79c0ff",
  flowMnemonic: "#ff9e64",
  register: "#d2a8ff",
  immediate: "#a5d6a7",
  address: "#e5c07b",
  symbol: "#e5c07b",
  punct: "#9da5ae",
  comment: "#8fbf7a",
  xref: "#56b6c2",
  header: "#f0f6fc",
  headerBg: "#1a202a",
  label: "#e5c07b",
  selRow: "#1a3455",
  hoverTok: "rgba(255, 213, 79, 0.28)",
  selTok: "rgba(255, 213, 79, 0.55)",
  syncRow: "rgba(88, 166, 255, 0.16)",
  placeholder: "#1f2530",
  track: "#151a22",
  thumb: "#3b4250",
  thumbActive: "#5a6475",
  marker: "#ff9e64",
  userName: "#58a6ff",
  agentName: "#d2a8ff",
  entryRule: "#3b4250",
  syncAddr: "rgba(88, 166, 255, 0.10)",
  type: "#79c0ff",
  override: "#f0883e",
  arrow: "#6e7681",
  arrowCond: "#8b949e",
  arrowSel: "#ffd54f",
  headerRowBg: "#161b24",
  note: "#e3b341",
  searchMark: "#f0883e",
  sliceMark: "#d2a8ff",
  sliceRow: "rgba(210, 168, 255, 0.10)",
  patchedRow: "rgba(240, 136, 62, 0.10)",
  patchMark: "#f0883e",
  patchedByte: "rgba(240, 136, 62, 0.16)",
};

export const LIGHT: Theme = {
  bg: "#ffffff",
  fg: "#1f2328",
  addr: "#5c6670",
  bytes: "#5c6670",
  mnemonic: "#0550ae",
  flowMnemonic: "#a94400",
  register: "#6e40c9",
  immediate: "#116329",
  address: "#953800",
  symbol: "#953800",
  punct: "#57606a",
  comment: "#176f2c",
  xref: "#086a8c",
  header: "#1f2328",
  headerBg: "#ebeff4",
  label: "#953800",
  selRow: "#ddebfd",
  hoverTok: "rgba(255, 196, 0, 0.30)",
  selTok: "rgba(255, 196, 0, 0.60)",
  syncRow: "rgba(9, 105, 218, 0.10)",
  placeholder: "#eef0f3",
  track: "#f5f7fa",
  thumb: "#c4c9d0",
  thumbActive: "#9aa1ab",
  marker: "#bc4c00",
  userName: "#0757b8",
  agentName: "#6e40c9",
  entryRule: "#c4c9d0",
  syncAddr: "rgba(9, 105, 218, 0.07)",
  type: "#0550ae",
  override: "#a94400",
  arrow: "#8c959f",
  arrowCond: "#afb8c1",
  arrowSel: "#bf8700",
  headerRowBg: "#f5f7fa",
  note: "#bf8700",
  searchMark: "#bc4c00",
  sliceMark: "#8250df",
  sliceRow: "rgba(130, 80, 223, 0.08)",
  patchedRow: "rgba(188, 76, 0, 0.08)",
  patchMark: "#bc4c00",
  patchedByte: "rgba(188, 76, 0, 0.12)",
};
