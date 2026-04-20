/**
 * Native-picker click interceptor.
 *
 * When a user clicks this plugin's provider row on HA's native login
 * picker (reachable via /auth/authorize?...&skip_oidc_redirect=true and
 * via the welcome page's "alternative sign-in method" link), HA posts to
 * /auth/login_flow and provider.async_step_init aborts with
 * `no_oidc_cookie_found` because the auth_oidc_state cookie is only set
 * by a prior visit to /auth/oidc/welcome. HA's login-flow frontend does
 * not handle flow results of type `external`, so a provider-side redirect
 * is not possible -- the fix has to happen here, at the frontend layer
 * which this plugin already owns.
 *
 * Narrow scope: targets only the row whose normalized text equals the
 * configured display name from window.__AUTH_OIDC__ (injected inline by
 * endpoints/injected_auth_page.py). Any other row (for instance HA's
 * "Home Assistant Local" provider, or a future second OIDC provider) is
 * left alone, so users who want to fall back to local auth can always do
 * so without this script getting in the way.
 */
(function () {
  const cfg = window.__AUTH_OIDC__;
  if (!cfg || !cfg.displayName || !cfg.welcomePath) return;
  // Defensive scope guard: this script is only injected onto the
  // authorize page today, but pin it to that path so accidental reuse in
  // another template cannot silently hijack unrelated pickers.
  if (!window.location.pathname.startsWith("/auth/authorize")) return;

  // Collapse internal whitespace and trim so strict equality survives
  // idiosyncratic shadow-DOM rendering of the row label.
  const norm = (s) => (s || "").replace(/\s+/g, " ").trim();
  const wanted = norm(cfg.displayName);

  // Tracks whether we've already triggered a navigation. Separate from
  // the per-item dataset marker which only records "listener attached".
  let redirected = false;

  function hijackOnce() {
    const picker = document.querySelector("ha-pick-auth-provider");
    if (!picker || !picker.shadowRoot) return false;
    const items = picker.shadowRoot.querySelectorAll("ha-list-item");
    for (const item of items) {
      if (item.dataset.oidcHijacked) continue;
      if (norm(item.innerText || item.textContent) !== wanted) continue;
      item.dataset.oidcHijacked = "1";
      item.addEventListener("click", (e) => {
        if (redirected) return;
        redirected = true;
        e.stopImmediatePropagation();
        e.preventDefault();
        // Matches the existing endpoints/welcome.py:_process_url contract:
        //   redirect_uri = encodeURIComponent(btoa(original_authorize_url))
        // which preserves storeToken=true handling and the is_mobile branch.
        const target =
          cfg.welcomePath +
          "?redirect_uri=" +
          encodeURIComponent(btoa(window.location.href));
        window.location.href = target;
      }, /* capture */ true);
      return true;
    }
    return false;
  }

  // MutationObserver on document.body does not see shadow-DOM mutations
  // (they don't bubble up), so poll every 100ms up to 8s until we've
  // attached a listener to the matching row. Stops as soon as we succeed.
  const start = Date.now();
  const poll = setInterval(() => {
    if (hijackOnce() || Date.now() - start > 8000) clearInterval(poll);
  }, 100);
})();

/**
 * hass-oidc-auth - UX script to automatically select the Home Assistant auth provider when the "Login aborted" message is shown.
 */

let authFlowElement = null

function update() {
  // Find ha-auth-flow
    authFlowElement = document.querySelector('ha-auth-flow');

    if (!authFlowElement) {
      return;
    }

    // Check if the text "Login aborted" is present on the page
    if (!authFlowElement.innerText.includes('Login aborted')) {
      return;
    }

    // Find the ha-pick-auth-provider element
    const authProviderElement = document.querySelector('ha-pick-auth-provider');

    if (!authProviderElement) {
      return;
    }

    // Click the first ha-list-item element inside the ha-pick-auth-provider
    const firstListItem = authProviderElement.shadowRoot?.querySelector('ha-list-item');
    if (!firstListItem) {
      console.warn("[OIDC] No ha-list-item found inside ha-pick-auth-provider. Not automatically selecting HA provider.");
      return;
    }

    firstListItem.click();
}

// Hide the content until ready
let ready = false
document.querySelector(".content").style.display = "none"

const observer = new MutationObserver((mutationsList, observer) => {
  update();

  if (!ready) {
    ready = Boolean(authFlowElement)
    if (ready) {
      document.querySelector(".content").style.display = ""
    }
  }
})

observer.observe(document.body, { childList: true, subtree: true })

setTimeout(() => {
  if (!ready) {
    console.warn("[hass-oidc-auth]: Document was not ready after 300ms seconds, showing content anyway.")
  }

  // Force display the content
  document.querySelector(".content").style.display = "";
}, 300)