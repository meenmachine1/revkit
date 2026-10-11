// The login page, shown when the daemon requires authentication and this
// browser has no session (docs/security.md). It covers the whole window;
// after a successful login the page reloads with the session.

import { h, overlayRoot } from "./dom";

export interface LoginOptions {
  daemon: string;
  /** Why the page is shown again ("Your session ended"). */
  message?: string;
  /** Resolves to an error to show, or null once logged in. */
  login: (user: string, password: string) => Promise<string | null>;
}

export function showLogin(o: LoginOptions): void {
  overlayRoot().querySelector("[data-testid=login]")?.parentElement?.remove();
  const user = h("input", { class: "ask-input", name: "username", autocomplete: "username", spellcheck: "false", "data-testid": "login-user", "aria-label": "Account" });
  const password = h("input", { class: "ask-input", name: "password", type: "password", autocomplete: "current-password", "data-testid": "login-password", "aria-label": "Password" });
  const err = h("div", { class: "ask-error", role: "alert", "data-testid": "login-error" }, o.message ?? "");
  const submit = h("button", { class: "btn primary", type: "submit", "data-testid": "login-submit" }, "Sign in");
  const form = h(
    "form",
    { class: "modal login", "data-testid": "login", "aria-label": "Sign in" },
    h("div", { class: "modal-title" }, "Sign in to revkit"),
    h("label", { class: "login-label dim" }, "Account", user),
    h("label", { class: "login-label dim" }, "Password", password),
    err,
    h("div", { class: "login-actions" }, h("span", { class: "dim login-daemon" }, o.daemon), submit),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!user.value.trim() || !password.value) {
      err.textContent = "Enter your account name and password.";
      return;
    }
    submit.disabled = true;
    err.textContent = "";
    try {
      const problem = await o.login(user.value.trim(), password.value);
      if (problem) {
        err.textContent = problem;
        password.select();
      }
    } finally {
      submit.disabled = false;
    }
  });
  overlayRoot().append(h("div", { class: "backdrop login-backdrop" }, form));
  document.body.dataset.ready = "login";
  user.focus();
}
