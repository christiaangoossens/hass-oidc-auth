This is a draft PR to refractor the existing device code functionality into enabling support for external idP device code flows. This PR is focused on setting the foundation, including front end routing logic, for the device auth flow. But, the specialized front end routing logic will be deferred to later PR's. The focus of this PR is to create additional endpoints to increase separation of concerns between normal OAuth/OIDC flows and device code flows and setting the bedrock for the front end routing logic for detecting the device type and UX of the client requesting authentication/authorization. Finally, this PR will introduce an endpoint at `/device` that will allow the device code fallback (incase the IdP does not support device codes) to use the built-in device code flow. Finally, the device code flow that the front end (the user device) connects to the backend (the Home Assistant instance) may favor using SSE over polling despite the standard being for polling while the backend will handle the polling to the IdP (Authentik/another provider).

> [!NOTE]
> This PR will not address discussion #350 at this time and will be followed up in a separate PR.

## Proposed endpoints:

- `/device`: endpoint that user is directed to enter activation code in case that the IdP device code flow is unavailable. This is strictly authenticated and requires the user to get authorized through normal OAuth/OIDC flow first, even if they have a valid session cookie with the main HA instance.
- `/auth/oidc/device`: endpoint for the front end to begin the device code flow after UX routing logic completes on the front end. This endpoint begins the SSE where the backend handles the polling for as long as the SSE connection remains open. This connection closes automatically after the flow completes and the client is redirected.
- `/auth/oidc/redirect`: Remains functionally the same, except that it is still explicitly choosen by the front end UX logic. The backend does not know nor does it care if it is a device flow or normal flow. It is up to the front end to route accordingly, whether that be by user input or the front end routing logic completing automatically.

## PR Context

This PR is supposed to address issue #300 and move discussion from #349 to this PR. Furthmore, this proposal is peliminary and will be updated as I further research the codebase.

