# rp

Log people in with OpenID Connect from Go. This is the **relying-party** half:
discovery, the authorization code with PKCE, the ID token checked against the
login it answers, a **loopback login for native applications** (RFC 8252), and
**refresh for one resource at a time** (RFC 8707). Pure Go, `CGO_ENABLED=0`.

[go-authn/oidc](https://github.com/go-authn/oidc) is the other half, the
resource-server one: it verifies a token that arrives, and gets nobody one. It
is kept small on purpose, so the half that logs people in lives here.

```go
p, err := rp.Discover(ctx, nil, "https://login.example.org")
c, err := rp.NewClient(ctx, p, rp.Config{ClientID: "portal", Secret: secret,
	RedirectURI: "https://files.example.org/callback", Scopes: []string{"openid", "offline_access"}})

f := rp.NewFlow()                         // keep it where only this browser brings it back
http.Redirect(w, r, c.AuthCodeURL(f, nil), http.StatusFound)
// at the redirect URI, once state is checked:
tok, id, err := c.Exchange(ctx, code, f)  // the ID token verified, with this login's nonce

// a token for one server; the refresh token keeps the whole grant
at, err := c.Refresh(ctx, tok.RefreshToken, rp.For{Resource: "https://fs-paris.example.org/"})
```

A native application logs in through the system browser:

```go
c, tok, id, err := rp.Loopback(ctx, p, rp.Config{ClientID: "console"}, rp.OpenBrowser, nil)
```

## What it always does

| | |
|---|---|
| **PKCE with S256** | for every client, confidential ones too (RFC 9700 §2.1.1). A provider whose discovery document lists its PKCE methods without S256 is refused: it would ignore the challenge. |
| **state and nonce** | 32 random bytes each per login. The ID token must carry the login's nonce, and with several audiences its `azp` must be this client (OIDC Core §3.1.3.7). |
| **discovery** | the document must name the issuer it was fetched for, exactly (OIDC Discovery §4.3); every endpoint must be https or loopback; an end-session endpoint in the clear is dropped. |
| **client authentication** | `client_secret_basic`, both parts form-encoded first (RFC 6749 §2.3.1). With no secret the client is **public** and names itself in the body (§3.2.1), as a native app must. |
| **no redirect at the token endpoint** | (since v0.1.1) a 3xx is an error, not followed. On a 307 or 308 Go's client sends the body again -- the refresh token, or the code and its verifier -- wherever it points, and Basic credentials with it to the same host on any scheme or port. The caller's `http.Client` is not changed. |
| **refresh** | `resource` and/or `scope` say what the token is for. `IsInvalidGrant` tells a grant that has ended from a refusal that has not (`invalid_target`). |

## The loopback login (RFC 8252)

- It listens on **127.0.0.1**, or **[::1]** when there is no IPv4 loopback, on a
  port the system picks (§7.3). It never listens on `localhost` (§8.3) or on
  any other interface.
- It opens the **system browser**, never a web view (§8.12), and redirects to
  `http://127.0.0.1:<port>/callback`. The provider must accept any port for a
  loopback redirect; [go-authn/bridge](https://github.com/go-authn/bridge) does.
- A request on that port whose `state` is not this login's gets a **400 and is
  ignored**: any local process can reach the port, so only the provider's
  answer ends the wait. An answer naming another issuer (RFC 9207), or carrying
  an error, ends it with that error.
- The client is **public**: a secret shipped inside an application is no secret
  (§8.5). Its refresh tokens rotate (RFC 9700 §4.14.2), so refresh with one of
  them at a time.

## Tests

```sh
go test -race ./...
```

The tests run against an in-process OpenID provider that is as strict as a real
one:

- exact redirect URIs, or any loopback port for a public client;
- S256 only;
- `client_secret_basic` for a confidential client, `client_id` in the body for a
  public one;
- rotating refresh tokens with reuse detection;
- `resource` becomes the only audience.

The loopback login is driven like a browser would: the authorization URL, the
provider's redirect to the listener, and a local process knocking with another
`state` first.

Each check was removed in turn, and a test failed each time:

- `state`;
- `iss`;
- listening on loopback only;
- `nonce`;
- `azp`;
- the issuer match at discovery;
- S256 at discovery;
- a public client's `client_id`;
- an S256 rather than a plain challenge.

Removing the empty-ID-token check changes nothing, because go-authn/oidc refuses
an empty token anyway; that check stays for its message.

## Licence

BSD 3-Clause.
