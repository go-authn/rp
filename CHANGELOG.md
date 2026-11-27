# Changelog

## v0.6.0

- New package `rptest`: a fake OpenID provider (discovery, JWKS, authorization
  code with PKCE S256) with a field for each fault: bad signature, nonce,
  issuer, audience, expiry, `alg` none / HS256, `iss` response parameter, no
  S256, wrong discovery issuer, no ID token. Replaces go-vcs/forge's
  `internal/idptest`. No parser added, so no fuzz target.

## v0.5.1

- The https-or-loopback rule comes from `github.com/go-authn/harden/redirect`,
  shared with oidc, awscred, saml and wireguard. Loopback now also means
  `*.localhost`, in any letter case and with a trailing dot; an IPv6 zone is
  refused; the error names the scheme and host, no longer the whole URL (it may
  carry a secret). The refusal of every redirect on the token endpoint is
  unchanged.

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
