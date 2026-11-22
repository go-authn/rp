# Changelog

## v0.5.0

Security audit 2026-11-21 (go-authn/rp#20).

- Loopback: `open` receives a single-use link on the loopback listener that
  redirects once to the authorization URL, so the state, nonce and PKCE
  challenge are no longer in the arguments of `open` / `xdg-open`, which any
  local user can read. Breaking for a caller whose `open` function inspects
  the URL it is given.
- VerifyID: an `azp` claim that is present must be this client's, with one
  audience as with several (OIDC Core §3.1.3.7). Such a token is now refused.
- A hand-built `Provider` (no HTTP client) uses `http.DefaultClient` instead of
  panicking.
- `Error.Error()` drops control characters from the provider's `error` and
  `error_description` and cuts each at 256 runes.
