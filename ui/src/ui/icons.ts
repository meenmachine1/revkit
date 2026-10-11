// Small line icons (16 px, currentColor), drawn here: no icon font or
// package. icon("folder") is a <span class="ic"> holding the SVG, with no
// text, so a row's text is its label alone.

const PATHS: Record<string, string> = {
  file: '<path d="M4 1.75h5.25L12.5 5v9.25H4z"/><path d="M9 1.75V5.25h3.5"/>',
  folder: '<path d="M1.75 3.75h4.5l1.5 1.5h6.5v7.5H1.75z"/>',
  "folder-open": '<path d="M1.75 12.75v-9h4.5l1.5 1.5h5v2"/><path d="M1.75 12.75l2-5.5h10.5l-2 5.5z"/>',
  search: '<circle cx="7" cy="7" r="4.25"/><path d="M10.25 10.25l3.5 3.5"/>',
  upload: '<path d="M8 10.5V2.25M4.75 5.25L8 2l3.25 3.25"/><path d="M2.25 10.5v3.25h11.5V10.5"/>',
  chevron: '<path d="M6 3.5l4.5 4.5L6 12.5"/>',
  "chevron-down": '<path d="M3.5 6l4.5 4.5L12.5 6"/>',
  close: '<path d="M3.75 3.75l8.5 8.5M12.25 3.75l-8.5 8.5"/>',
  more: '<circle cx="3.5" cy="8" r=".9" fill="currentColor"/><circle cx="8" cy="8" r=".9" fill="currentColor"/><circle cx="12.5" cy="8" r=".9" fill="currentColor"/>',
  copy: '<rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25"/><path d="M10.75 5.25v-3h-8.5v8.5h3"/>',
  server: '<rect x="2" y="2.5" width="12" height="4.5" rx="1"/><rect x="2" y="9" width="12" height="4.5" rx="1"/><path d="M4.5 4.75h.01M4.5 11.25h.01"/>',
  back: '<path d="M13.5 8h-11M6.5 4l-4 4 4 4"/>',
  plus: '<path d="M8 3v10M3 8h10"/>',
  "folder-plus": '<path d="M1.75 3.75h4.5l1.5 1.5h6.5v7.5H1.75z"/><path d="M8 7v4M6 9h4"/>',
  enter: '<path d="M13 3.5v4.75a1.5 1.5 0 0 1-1.5 1.5H3.5"/><path d="M6 7l-3 2.75 3 2.75"/>',
  chip: '<rect x="4" y="4" width="8" height="8" rx="1"/><path d="M6 1.5v2.5M10 1.5v2.5M6 12v2.5M10 12v2.5M1.5 6h2.5M1.5 10h2.5M12 6h2.5M12 10h2.5"/>',
  link: '<path d="M6.75 9.25a2.75 2.75 0 0 0 3.9 0l2-2a2.75 2.75 0 0 0-3.9-3.9l-.75.75"/><path d="M9.25 6.75a2.75 2.75 0 0 0-3.9 0l-2 2a2.75 2.75 0 0 0 3.9 3.9l.75-.75"/>',
  filter: '<path d="M2 3h12l-4.75 5.5v4.75l-2.5 1.25V8.5z"/>',
  expand: '<path d="M9.5 2.5h4v4M6.5 13.5h-4v-4M13.5 2.5L9 7M2.5 13.5L7 9"/>',
};

/** An icon by name (an empty one for a name not drawn here). */
export function icon(name: string, cls = ""): HTMLSpanElement {
  const s = document.createElement("span");
  s.className = `ic ic-${name}${cls ? " " + cls : ""}`;
  s.setAttribute("aria-hidden", "true");
  s.innerHTML = `<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">${PATHS[name] ?? ""}</svg>`;
  return s;
}
