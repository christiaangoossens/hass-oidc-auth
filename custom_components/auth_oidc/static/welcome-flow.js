import { decideStrategy, PresentationStrategy } from "./ux-router-eval.js";

/**
 * Completes the OIDC login by submitting a POST form to /auth/oidc/finish.
 * @param {EventSource | null} source
 */
export function finishLogin(source = null) {
    if (source) {
        source.close();
    }

    // Perform a POST request to the finish endpoint to complete the login.
    const form = document.createElement("form");
    form.method = "POST";
    form.action = "/auth/oidc/finish";
    document.body.appendChild(form);
    form.submit();
}

/**
 * Opens an SSE connection to listen for device code approval.
 * @returns {EventSource}
 */
export function startDeviceSse() {
    const source = new EventSource("/auth/oidc/device-sse");

    source.addEventListener("ready", () => finishLogin(source));

    // No 'error' handler that closes the source: EventSource
    // reconnects automatically after a dropped connection, e.g.
    // when the OS suspends this webview while the user enters the
    // code in their browser (#363). On reconnect, the server
    // immediately sends 'ready' if the code was approved in the
    // meantime. Fatal responses (such as a 400 after state expiry)
    // stop the automatic reconnection on their own.

    // Manual fallback in case the connection cannot be resumed.
    const manualFinishLink = document.getElementById("manual-finish-link");
    if (manualFinishLink) {
        manualFinishLink.addEventListener("click", (event) => {
            event.preventDefault();
            finishLogin(source);
        });
    }

    return source;
}


