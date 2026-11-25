// Waits on a mobile device until its code is approved on another device, then
// finishes the login here. App webviews may close the stream for good while the
// app is in the background, so it is reopened when needed.
(() => {
    const STREAM_URL = "/auth/oidc/device-sse";
    const MAX_RETRIES = 5;
    const CHECKING_MS = 1000;

    const button = document.getElementById("device-check-again");
    const checkAgainLabel = button.textContent;

    let source = null;
    let retries = 0;
    let retryTimer = null;
    let stopped = false;
    let expired = false;
    let checking = false;

    function stop() {
        stopped = true;
        clearTimeout(retryTimer);
        source.close();
    }

    // aria-disabled instead of disabled, so the button keeps keyboard focus
    function showChecking(isChecking) {
        if (expired) {
            return;
        }

        checking = isChecking;
        button.ariaDisabled = String(isChecking);
        button.textContent = isChecking ? button.dataset.checking : checkAgainLabel;
    }

    function showExpired() {
        stop();
        expired = true;

        for (const id of ["device-instructions", "device-code", "device-waiting"]) {
            document.getElementById(id).hidden = true;
        }
        document.getElementById("device-expired").hidden = false;
        button.ariaDisabled = "false";
        button.textContent = button.dataset.newCode;
    }

    function finishLogin() {
        stop();

        const form = document.createElement("form");
        form.method = "POST";
        form.action = "/auth/oidc/finish";
        document.body.appendChild(form);
        form.submit();
    }

    function retryLater() {
        // Only a closed stream needs our help, EventSource retries the others itself
        if (stopped || source.readyState !== EventSource.CLOSED) {
            return;
        }

        if (retries >= MAX_RETRIES) {
            showExpired();
            return;
        }

        retryTimer = setTimeout(connect, 1000 * 2 ** retries);
        retries += 1;
    }

    function connect() {
        clearTimeout(retryTimer);
        if (source) {
            source.close();
        }

        source = new EventSource(STREAM_URL);
        source.addEventListener("open", () => { retries = 0; });
        source.addEventListener("ready", finishLogin);
        source.addEventListener("expired", showExpired);
        source.addEventListener("error", retryLater);
    }

    function reconnect() {
        if (stopped) {
            return;
        }

        retries = 0;
        connect();
    }

    function checkAgain() {
        if (checking) {
            return;
        }

        showChecking(true);
        setTimeout(() => showChecking(false), CHECKING_MS);
        reconnect();
    }

    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
            reconnect();
        }
    });
    button.addEventListener("click", () => (expired ? location.reload() : checkAgain()));

    connect();
})();
