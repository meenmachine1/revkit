// Keeps the keyboard focus inside the topmost modal dialog (a .backdrop in
// #overlays): Tab past its last control comes back to its first, Shift+Tab
// before its first goes to its last, and focus that lands on the page behind
// (a click on the toolbar, Tab out of the window and back) returns to the
// dialog. Menus and popovers opened above the dialog keep their focus.

const FOCUSABLE = 'button:not(:disabled), input:not(:disabled):not([type="hidden"]), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])';

/** The modal dialog on top, if any. */
function topBackdrop(): HTMLElement | null {
  const all = document.querySelectorAll<HTMLElement>("#overlays > .backdrop, body > .backdrop");
  return all.length ? all[all.length - 1] : null;
}

function focusables(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.getClientRects().length > 0 && !el.closest("[hidden], [inert]"));
}

/** Is `el` in the dialog, or in an overlay opened after it (its menus, a popover)? */
function within(top: HTMLElement, el: Element | null): boolean {
  if (!el || el === document.body) return false;
  if (top.contains(el)) return true;
  return !!el.closest("#overlays") && !!(top.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING);
}

function refocus(top: HTMLElement, backward: boolean) {
  const list = focusables(top);
  const to = list.length ? (backward ? list[list.length - 1] : list[0]) : (top.querySelector<HTMLElement>(".modal") ?? top);
  if (!list.length && !to.hasAttribute("tabindex")) to.tabIndex = -1;
  to.focus({ preventScroll: true });
}

export function installFocusTrap() {
  let backward = false;
  // After the browser moved the focus for Tab (a dialog's own Tab, a type
  // completion, keeps it): out of the dialog, or out of the page, wraps around.
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Tab") return;
      backward = e.shiftKey;
      const top = topBackdrop();
      if (!top) return;
      setTimeout(() => {
        if (top.isConnected && top === topBackdrop() && !within(top, document.activeElement)) refocus(top, backward);
      }, 0);
    },
    true,
  );
  document.addEventListener("focusin", (e) => {
    const top = topBackdrop();
    if (top && !within(top, e.target as Element | null)) refocus(top, backward);
  });
}
