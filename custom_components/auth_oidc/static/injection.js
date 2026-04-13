/**
 * OIDC Frontend Redirect injection script
 * This script is injected because the 'hass-oidc-auth' custom component is active.
 */

function attempt_oidc_redirect() {
  // Get URL parameters
  const urlParams = new URLSearchParams(window.location.search);

  // Check if we have skip_oidc_redirect directly here
  if (urlParams.get('skip_oidc_redirect') === 'true') {
      // No console log because this is intended behavior
      return;
  }

  const originalUrl = urlParams.get('redirect_uri');
  if (!originalUrl) {
    console.warn('[OIDC] No OAuth2 redirect_uri parameter found in the URL. Frontend redirect cancelled.');
    return;
  }

  try {
    // Parse the redirect URI
    const redirectUrl = new URL(originalUrl);

    // Check if redirect URI has a query parameter to stop OIDC injection
    if (redirectUrl.searchParams.get('skip_oidc_redirect') === 'true') {
      // No console log because this is intended behavior
      return;
    }
  } catch (error) {
    console.error('[OIDC] Invalid redirect_uri parameter:', error);
  }

  window.stop(); // Stop loading the current page before redirecting

  // Redirect to the OIDC auth URL
  const base64encodeUrl = btoa(window.location.href);
  const oidcAuthUrl = '/auth/oidc/welcome?redirect_uri=' + encodeURIComponent(base64encodeUrl);
  window.location.href = oidcAuthUrl;
}

function click_alternative_provider_instead() {
  setTimeout(() => {
    // Find ha-auth-flow
    const authFlowElement = document.querySelector('ha-auth-flow');

    if (!authFlowElement) {
      console.warn("[OIDC] ha-auth-flow element not found. Not automatically selecting HA provider.");
      return;
    }

    // Check if the text "Login aborted" is present on the page
    if (!authFlowElement.innerText.includes('Login aborted')) {
      console.warn("[OIDC] 'Login aborted' text not found. Not automatically selecting HA provider.");
      return;
    }

    // Find the ha-pick-auth-provider element
    const authProviderElement = document.querySelector('ha-pick-auth-provider');

    if (!authProviderElement) {
      console.warn("[OIDC] ha-pick-auth-provider not found. Not automatically selecting HA provider.");
      return;
    }

    // Click the first ha-list-item element inside the ha-pick-auth-provider
    const firstListItem = authProviderElement.shadowRoot?.querySelector('ha-list-item');
    if (!firstListItem) {
      console.warn("[OIDC] No ha-list-item found inside ha-pick-auth-provider. Not automatically selecting HA provider.");
      return;
    }

    firstListItem.click();
  }, 300);
}

// Run OIDC injection upon load
(() => {
  attempt_oidc_redirect();
  click_alternative_provider_instead();
})();