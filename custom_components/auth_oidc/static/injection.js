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