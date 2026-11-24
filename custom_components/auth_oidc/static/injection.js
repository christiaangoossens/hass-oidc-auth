/**
 * Frontend helpers for /auth/authorize: auto-select on aborted login,
 * and route picker clicks on our provider through /auth/oidc/welcome.
 */

const OIDC_PROVIDER_NAME = "OpenID Connect (SSO)"  // matches provider.py CONF_NAME
const OIDC_WELCOME_PATH = "/auth/oidc/welcome"
const SSO_RETURN_LINK_ID = "oidc-sso-return-link"

let authFlowElement = null
let pickerIntercepted = false

// The picker row is hidden on purpose (see interceptPickerRow), which leaves a
// parked `skip_oidc_redirect` authorize URL without any way back to SSO.
// Render a link next to the picker instead: it starts a fresh handshake.
function addSsoReturnLink(authProviderElement) {
  if (document.getElementById(SSO_RETURN_LINK_ID)) return  // already injected

  const link = document.createElement("a")
  link.id = SSO_RETURN_LINK_ID
  link.href = OIDC_WELCOME_PATH
  link.innerText = "Sign in with SSO"
  link.style.display = "block"
  link.style.marginTop = "12px"
  link.style.textAlign = "center"

  const parent = authProviderElement && authProviderElement.parentNode
  if (parent) {
    // Sibling of the picker, so it stays visible when the picker itself is hidden
    parent.insertBefore(link, authProviderElement.nextSibling)
  } else {
    document.querySelector(".content")?.appendChild(link)
  }
}

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

    // We should hide it entirely as making it clickable
    // causes so many weird loop issues
    item.style.display = "none"
    pickerIntercepted = true

    break
  }

  // If we have found it and we are the only provider,
  // hide the entire picker for better UX
  if (pickerIntercepted && items.length == 1) {
    authProviderElement.style.display = "none"
  }

  if (pickerIntercepted) {
    addSsoReturnLink(authProviderElement)
  }
}

function update() {
  authFlowElement = document.querySelector('ha-auth-flow')
  if (!authFlowElement) return

  const authProviderElement = document.querySelector('ha-pick-auth-provider')

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
