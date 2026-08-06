# High level notes on refactoring

## Big things to keep in mind

- [ ] client_id is still important to identify the home assistant mobile app companion
  - [ ] Backend will need to pass html metadata for front end to interpret and change presentation
- [x] Investigate how backend session tracking works and adapt it to track device code status (See [investigate backend notes](#investigate-backend-tracking-notes))
- [ ] Device code endpoint with for post url encoded and get app html needs to be strictly authenticated via external IdP and tracked via session cookie
  - Might move this to a dedicated endpoint opposed to the PR description as `/auth/oidc/log-device`. We have `/auth/oidc/device` doing 4 things (2 get and 2 post each) which makes things a bit confusing. Just a bit 😛.
- [ ] Migrate the SSE logic that exists to a pub/sub model rather than polling
- [ ] Move html and js code to dedicated files for cleaner code (I personally feel that combining JS into HTML is messy and should only be down as absolutely necessary [ie. templating via Jinja2 or PHP])
- [ ] Code for front end and device workers should be written deliberately open to allow for mixins in future PRs. I'm favoring class inheritance.


### Investigate backend tracking notes

#### Current Mechanism
- **Storage Engine**: `StateStore` uses Home Assistant's `Store` helper (`homeassistant.helpers.storage.Store`) persisting to `.storage/auth_provider.auth_oidc.states`.
- **Cookie Link**: Sessions are bound to the `auth_oidc_state` HTTP cookie (`state_id`).
- **JSON Serialization**: `OIDCState` inherits directly from `dict` (`class OIDCState(dict)`), allowing HA to save/load it directly to/from JSON without custom converters.
- **Donor Pattern**: Device linking currently copies `user_details` from an authenticated secondary device session into the waiting session and deletes the secondary device session.

#### Categorizing Sessions via `flow_type` & Nested `flow_data`
To prevent `OIDCState` from becoming an unstructured flat dictionary, sessions are categorized into 3 explicit flow types:
1. **`redirect`**: Standard OAuth browser redirect flow.
2. **`device_waiting`**: Client/TV waiting for authorization (`POST /auth/oidc/device` -> `GET /auth/oidc/device-sse`).
3. **`device_approving`**: Secondary device (phone/PC) authenticating via OIDC first, then entering the user code at `/auth/oidc/log-device`.

#### Extended Session Schema Proposal
When `POST /auth/oidc/device` initiates a `device_waiting` flow, it populates a nested `flow_data` dictionary:
- `status`: `"pending" | "ready" | "expired" | "denied"`
- `user_code` & `verification_uri`: Returned in POST response & displayed on screen.
- `device_code`: Kept in backend for IdP polling or local matching.
- `expires_in` & `interval`: Provided by external IdP (or default 300s / 5min for local fallback).
- `started_at`: Epoch timestamp for dynamic SSE & polling timeout calculations.

#### Key Architectural Rules
- **Strict Execution Order**: `POST /auth/oidc/device` **must** happen before `GET /auth/oidc/device-sse`. The SSE endpoint validates the session created during `POST` and calculates remaining TTL dynamically using `expires_in` and `started_at`.
- **Pub/Sub Event Signaling**: Replaces the `while True: await asyncio.sleep(0.5)` busy-wait loop in `device_sse.py`. When `/auth/oidc/log-device` transfers `user_details` to the recipient `state_id`, it sets `status = "ready"` and triggers an `asyncio.Event` signal to unblock the SSE stream instantly.