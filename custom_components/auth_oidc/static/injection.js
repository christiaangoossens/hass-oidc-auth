/**
 * Frontend helpers for /auth/authorize: auto-select on aborted login,
 * and route picker clicks on our provider through /auth/oidc/welcome.
 */

const OIDC_PROVIDER_NAME = "OpenID Connect (SSO)"  // matches provider.py CONF_NAME
const OIDC_WELCOME_PATH = "/auth/oidc/welcome"

let authFlowElement = null
let pickerIntercepted = false

function interceptPickerRow(authProviderElement) {
  if (pickerIntercepted) return
  if (!authProviderElement) return
  if (!authProviderElement.shadowRoot) {
    console.warn("[OIDC] ha-pick-auth-provider has no shadowRoot; HA frontend may have changed.")
    return
  }
  const items = authProviderElement.shadowRoot.querySelectorAll('ha-list-item')
  if (items.length === 0) return  // not yet populated; retry on next mutation
  for (const item of items) {
    if ((item.innerText || '').trim() !== OIDC_PROVIDER_NAME) continue
    item.addEventListener('click', (e) => {
      e.stopImmediatePropagation()
      e.preventDefault()
      window.location.href =
        OIDC_WELCOME_PATH +
        '?redirect_uri=' + encodeURIComponent(btoa(window.location.href))
    }, true)
    pickerIntercepted = true
    return
  }
}

function update() {
  authFlowElement = document.querySelector('ha-auth-flow')
  if (!authFlowElement) return

  const authProviderElement = document.querySelector('ha-pick-auth-provider')

  // Intercept picker clicks so the OIDC cookie is set before submit.
  interceptPickerRow(authProviderElement)

  // Auto-select on "Login aborted".
  if (!authFlowElement.innerText.includes('Login aborted')) return
  if (!authProviderElement) return
  const firstListItem = authProviderElement.shadowRoot?.querySelector('ha-list-item')
  if (!firstListItem) {
    console.warn("[OIDC] No ha-list-item found inside ha-pick-auth-provider. Not automatically selecting OIDC provider.")
    return
  }
  firstListItem.click()
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
  update();
}, 300)
