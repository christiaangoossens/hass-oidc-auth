// Tests for the device login page script, run with `npm test` (node:test, no dependencies).
// The script runs in a sandbox with a fake EventSource, document and timers.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const SCRIPT = readFileSync(
    new URL("../../custom_components/auth_oidc/static/device.js", import.meta.url),
    "utf8",
);

const RETRY_DELAYS = [1000, 2000, 4000, 8000, 16000];

class FakeEventSource {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSED = 2;

    constructor(url) {
        this.url = url;
        this.readyState = FakeEventSource.CONNECTING;
        this.listeners = {};
    }

    addEventListener(type, listener) {
        this.listeners[type] = [...(this.listeners[type] ?? []), listener];
    }

    close() {
        this.readyState = FakeEventSource.CLOSED;
    }

    /** Dispatch like a browser: a closed stream only reports its final error. */
    emit(type) {
        if (this.readyState === FakeEventSource.CLOSED && type !== "error") {
            return;
        }

        for (const listener of this.listeners[type] ?? []) {
            listener();
        }
    }
}

/** A page element with just enough of the DOM for device.js. */
function fakeElement(properties = {}) {
    const element = { hidden: false, ariaDisabled: null, listeners: {}, ...properties };
    element.addEventListener = (type, listener) => { element.listeners[type] = listener; };
    return element;
}

/** Run device.js and return handles to everything it touches. */
function loadPage() {
    const page = { sources: [], timers: [], forms: [], documentListeners: {}, reloads: 0 };

    page.elements = {
        "device-instructions": fakeElement(),
        "device-code": fakeElement(),
        "device-waiting": fakeElement(),
        "device-expired": fakeElement({ hidden: true }),
        "device-check-again": fakeElement({
            textContent: "Check again",
            dataset: { checking: "Checking", newCode: "Get a new code" },
        }),
    };
    page.button = page.elements["device-check-again"];

    class TrackedEventSource extends FakeEventSource {
        constructor(url) {
            super(url);
            page.sources.push(this);
        }
    }

    const document = {
        visibilityState: "visible",
        addEventListener: (type, listener) => { page.documentListeners[type] = listener; },
        getElementById: (id) => page.elements[id],
        createElement: () => {
            const form = { submitted: false, submit() { this.submitted = true; } };
            page.forms.push(form);
            return form;
        },
        body: { appendChild: () => {} },
    };

    vm.runInNewContext(SCRIPT, {
        document,
        location: { reload: () => { page.reloads += 1; } },
        EventSource: TrackedEventSource,
        setTimeout: (callback, delay) => page.timers.push({ callback, delay, cancelled: false }),
        clearTimeout: (id) => {
            if (page.timers[id - 1]) {
                page.timers[id - 1].cancelled = true;
            }
        },
    });

    page.latest = () => page.sources.at(-1);
    page.runTimer = (index) => {
        const timer = page.timers[index];
        if (!timer.cancelled) {
            timer.callback();
        }
    };
    page.click = () => page.button.listeners.click();
    page.setVisibility = (state) => {
        document.visibilityState = state;
        page.documentListeners.visibilitychange();
    };
    page.closeLatest = () => {
        page.latest().readyState = FakeEventSource.CLOSED;
        page.latest().emit("error");
    };
    page.isExpiredShown = () => (
        ["device-instructions", "device-code", "device-waiting"].every((id) => page.elements[id].hidden)
        && !page.elements["device-expired"].hidden
    );
    return page;
}

/** Close the stream for good after every retry, until the script gives up. */
function exhaustRetries(page) {
    for (let attempt = 0; attempt <= RETRY_DELAYS.length; attempt += 1) {
        const scheduled = page.timers.length;
        page.closeLatest();

        if (page.timers.length > scheduled) {
            page.runTimer(page.timers.length - 1);
        }
    }
}

test("opens the stream on load", () => {
    const page = loadPage();

    assert.equal(page.sources.length, 1);
    assert.equal(page.latest().url, "/auth/oidc/device-sse");
});

test("finishes the login with a POST once the code is approved", () => {
    const page = loadPage();

    page.latest().emit("ready");

    assert.equal(page.forms.length, 1);
    assert.equal(page.forms[0].method, "POST");
    assert.equal(page.forms[0].action, "/auth/oidc/finish");
    assert.ok(page.forms[0].submitted);
    assert.equal(page.latest().readyState, FakeEventSource.CLOSED);
});

test("leaves reconnecting to EventSource while it is still trying", () => {
    const page = loadPage();

    page.latest().emit("error");

    assert.equal(page.timers.length, 0);
});

test("reopens a closed stream with a growing delay, at most five times", () => {
    const page = loadPage();

    exhaustRetries(page);

    assert.deepEqual(page.timers.map((timer) => timer.delay), RETRY_DELAYS);
    assert.equal(page.sources.length, 6);
});

test("a successful connection resets the retry delay", () => {
    const page = loadPage();

    page.closeLatest();
    page.runTimer(0);
    page.latest().emit("open");
    page.closeLatest();

    assert.deepEqual(page.timers.map((timer) => timer.delay), [1000, 1000]);
});

test("reconnects when the page becomes visible again, but not when hidden", () => {
    const page = loadPage();
    const first = page.latest();

    page.setVisibility("hidden");
    assert.equal(page.sources.length, 1);

    page.setVisibility("visible");
    assert.equal(page.sources.length, 2);
    assert.equal(first.readyState, FakeEventSource.CLOSED);
});

test("a reconnect cancels a pending retry", () => {
    const page = loadPage();

    page.closeLatest();
    page.setVisibility("visible");
    page.runTimer(0);

    assert.equal(page.sources.length, 2);
});

test("a ready event after a reconnect finishes the login once", () => {
    const page = loadPage();

    page.setVisibility("visible");
    page.latest().emit("ready");
    page.sources[0].emit("ready");

    assert.equal(page.forms.length, 1);
});

test("check again reconnects and shows that it is checking, without finishing early", () => {
    const page = loadPage();

    page.click();

    assert.equal(page.sources.length, 2);
    assert.equal(page.forms.length, 0);
    assert.equal(page.button.ariaDisabled, "true");
    assert.equal(page.button.textContent, "Checking");

    page.runTimer(page.timers.length - 1);

    assert.equal(page.button.ariaDisabled, "false");
    assert.equal(page.button.textContent, "Check again");
});

test("check again is ignored while it is still checking", () => {
    const page = loadPage();

    page.click();
    page.click();

    assert.equal(page.sources.length, 2);
});

test("check again resets the retry delay", () => {
    const page = loadPage();

    page.closeLatest();
    page.runTimer(0);
    page.closeLatest();
    page.click();
    page.closeLatest();

    const retryDelays = page.timers.filter((timer) => timer.callback.name === "connect");
    assert.deepEqual(retryDelays.map((timer) => timer.delay), [1000, 2000, 1000]);
});

test("an expired login offers a new code and stops reconnecting", () => {
    const page = loadPage();

    page.latest().emit("expired");
    page.setVisibility("visible");
    page.closeLatest();

    assert.ok(page.isExpiredShown());
    assert.equal(page.button.textContent, "Get a new code");
    assert.equal(page.sources.length, 1);
    assert.equal(page.timers.length, 0);

    page.click();

    assert.equal(page.reloads, 1);
    assert.equal(page.sources.length, 1);
});

test("offers a new code once every retry failed", () => {
    const page = loadPage();

    exhaustRetries(page);

    assert.ok(page.isExpiredShown());
});

test("the checking label does not hide an expired login", () => {
    const page = loadPage();

    page.click();
    page.latest().emit("expired");
    page.runTimer(0);

    assert.equal(page.button.textContent, "Get a new code");
    assert.equal(page.button.ariaDisabled, "false");
});
