/**
 * hass-oidc-auth - injected UX script for /auth/authorize.
 * Auto-selects the OIDC provider when HA's login flow shows "Login aborted",
 * and redirects clicks on the OIDC provider row in the picker to
 * /auth/oidc/welcome (so the OIDC cookie gets set before async_step_init
 * fires, instead of dead-ending with no_oidc_cookie_found).
 */

const OIDC_PROVIDER_NAME = "OpenID Connect (SSO)"  // matches provider.py CONF_NAME
const OIDC_WELCOME_PATH = "/auth/oidc/welcome"

let authFlowElement = null
let pickerHijacked = false

function hijackPickerRow() {
  if (pickerHijacked) return
  const picker = document.querySelector('ha-pick-auth-provider')
  const items = picker?.shadowRoot?.querySelectorAll('ha-list-item') || []
  for (const item of items) {
    if ((item.innerText || '').trim() !== OIDC_PROVIDER_NAME) continue
    item.addEventListener('click', (e) => {
      e.stopImmediatePropagation()
      e.preventDefault()
      window.location.href =
        OIDC_WELCOME_PATH +
        '?redirect_uri=' + encodeURIComponent(btoa(window.location.href))
    }, true)
    pickerHijacked = true
    break
  }
}

function update() {
  // Find ha-auth-flow
  authFlowElement = document.querySelector('ha-auth-flow')

  if (!authFlowElement) {
    return
  }

  // Route a click on our provider row through the welcome flow so the
  // OIDC state cookie gets set before async_step_init runs.
  hijackPickerRow()

  // Check if the text "Login aborted" is present on the page
  if (!authFlowElement.innerText.includes('Login aborted')) {
    return
  }

  // Find the ha-pick-auth-provider element
  const authProviderElement = document.querySelector('ha-pick-auth-provider')

  if (!authProviderElement) {
    return
  }

  // Click the first ha-list-item element inside the ha-pick-auth-provider
  const firstListItem = authProviderElement.shadowRoot?.querySelector('ha-list-item')
  if (!firstListItem) {
    console.warn("[OIDC] No ha-list-item found inside ha-pick-auth-provider. Not automatically selecting HA provider.")
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
