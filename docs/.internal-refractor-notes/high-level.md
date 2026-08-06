# High level notes on refactoring

## Big things to keep in mind

- [ ] client_id is still important to identify the home assistant mobile app companion
  - [ ] Backend will need to pass html metadata for front end to interpret and change presentation
- [ ] Investigate how backend session tracking works and adapt it to track device code status
- [ ] Device code endpoint with for post url encoded and get app html needs to be strictly authenticated via external IdP and tracked via session cookie
  - Might move this to a dedicated endpoint opposed to the PR description as `/auth/oidc/log-device`. We have `/auth/oidc/device` doing 4 things (2 get and 2 post each) which makes things a bit confusing. Just a bit 😛.
- [ ] Migrate the SSE logic that exists to a pub/sub model rather than polling
- [ ] Move html and js code to dedicated files for cleaner code (I personally feel that combining JS into HTML is messy and should only be down as absolutely necessary [ie. templating via Jinja2 or PHP])
- [ ] Code for front end and device workers should be written deliberately open to allow for mixins in future PRs. I'm favoring class inheritance.