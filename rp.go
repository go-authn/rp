// SPDX-License-Identifier: BSD-3-Clause

// Package rp logs people in with OpenID Connect: it is the relying-party half
// that go-authn/oidc deliberately leaves out.
//
//	p, err := rp.Discover(ctx, http.DefaultClient, "https://login.example.org")
//	c, err := rp.NewClient(ctx, p, rp.Config{ClientID: "console", RedirectURI: redirect})
//	f := rp.NewFlow()
//	http.Redirect(w, r, c.AuthCodeURL(f, nil), http.StatusFound)
//	// ... at the redirect URI, with the flow found again:
//	tok, id, err := c.Exchange(ctx, code, f)
//	// ... later, a token for one resource server (RFC 8707 §2.2):
//	at, err := c.Refresh(ctx, tok.RefreshToken, rp.For{Resource: "https://fs-a.example.org/"})
//
// What it always does, because each is a defence somebody once skipped:
//
//   - PKCE with S256 (RFC 7636), for confidential clients too (RFC 9700
//     §2.1.1), and a provider that publishes its methods without S256 is
//     refused at discovery: it would ignore the challenge.
//   - A state and a nonce per login. The ID token is verified -- signature,
//     issuer, audience, times, by go-authn/oidc -- and must carry this login's
//     nonce; with several audiences, azp must be this client.
//   - The discovery document must name the issuer it was fetched for, exactly
//     (OIDC Discovery §4.3), and every endpoint must be https or loopback.
//
// A native application uses [Loopback], which runs the whole login through
// the system browser and a listener on 127.0.0.1 (RFC 8252). Such a client is
// public: a secret shipped inside an application is no secret (RFC 8252 §8.5).
package rp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/oidc"
)

// Provider is what discovery says about an OpenID provider.
type Provider struct {
	Issuer        string
	AuthURL       string
	TokenURL      string
	EndSessionURL string // "" when the provider has none, or one in the clear
	client        *http.Client
}

type discovery struct {
	Issuer  string   `json:"issuer"`
	Auth    string   `json:"authorization_endpoint"`
	Token   string   `json:"token_endpoint"`
	EndSess string   `json:"end_session_endpoint"`
	Methods []string `json:"code_challenge_methods_supported"`
}

// Discover reads issuer's /.well-known/openid-configuration.
func Discover(ctx context.Context, hc *http.Client, issuer string) (*Provider, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if err := httpsOrLoopback(issuer); err != nil {
		return nil, fmt.Errorf("rp: issuer: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rp: discovery: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rp: discovery: %s", res.Status)
	}
	var d discovery
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("rp: discovery: %w", err)
	}
	// OIDC Discovery §4.3: the issuer in the document must be the one it was
	// fetched for, exactly; otherwise one provider could speak for another.
	if d.Issuer != issuer {
		return nil, fmt.Errorf("rp: discovery: the document says issuer %q, not %q", d.Issuer, issuer)
	}
	for _, u := range []string{d.Auth, d.Token} {
		if err := httpsOrLoopback(u); err != nil {
			return nil, fmt.Errorf("rp: discovery: %w", err)
		}
	}
	if d.EndSess != "" && httpsOrLoopback(d.EndSess) != nil {
		d.EndSess = ""
	}
	if d.Methods != nil && !slices.Contains(d.Methods, "S256") {
		return nil, errors.New("rp: discovery: the provider does not offer PKCE with S256")
	}
	return &Provider{Issuer: issuer, AuthURL: d.Auth, TokenURL: d.Token, EndSessionURL: d.EndSess, client: hc}, nil
}

// Config is a client of a provider.
type Config struct {
	ClientID string
	// Secret is a confidential client's, sent with client_secret_basic
	// (RFC 6749 §2.3.1). Empty is a PUBLIC client: its client_id goes in the
	// token request instead, as a native app's must (RFC 8252 §8.5).
	Secret      string
	RedirectURI string
	// Scopes asked for at the login. Default openid. A refresh token usually
	// needs offline_access, or the provider's equivalent.
	Scopes []string
}

// Client logs people in at one provider.
type Client struct {
	p        *Provider
	cfg      Config
	idTokens *oidc.Verifier
}

// NewClient is a client of p. It reads the provider's keys now, to verify ID
// tokens with.
func NewClient(ctx context.Context, p *Provider, cfg Config) (*Client, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("rp: no client ID")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid"}
	}
	if !slices.Contains(cfg.Scopes, "openid") {
		return nil, errors.New("rp: the scopes must include openid")
	}
	v, err := oidc.New(ctx, oidc.Config{Issuer: p.Issuer, Audience: cfg.ClientID, Client: p.client})
	if err != nil {
		return nil, err
	}
	return &Client{p: p, cfg: cfg, idTokens: v}, nil
}

// Provider is the provider this client logs in at.
func (c *Client) Provider() *Provider { return c.p }

// A Flow is one login in progress: what the redirect must be checked against
// and the code exchanged with. Keep it where only this browser can bring it
// back -- a sealed cookie, or the memory of the native app that started it.
type Flow struct {
	State, Nonce, Verifier string
}

// NewFlow is a login with a fresh state, nonce and PKCE verifier: 32 bytes
// each from the system's generator (RFC 7636 §4.1: 43 characters, 256 bits).
func NewFlow() Flow { return Flow{State: random(), Nonce: random(), Verifier: random()} }

// AuthCodeURL is where to send the browser. extra adds parameters, such as
// RFC 8707 resource indicators or a prompt.
func (c *Client) AuthCodeURL(f Flow, extra url.Values) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {c.cfg.RedirectURI},
		"scope":                 {strings.Join(c.cfg.Scopes, " ")},
		"state":                 {f.State},
		"nonce":                 {f.Nonce},
		"code_challenge":        {Challenge(f.Verifier)},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = append(q[k], vs...)
	}
	sep := "?"
	if strings.Contains(c.p.AuthURL, "?") {
		sep = "&"
	}
	return c.p.AuthURL + sep + q.Encode()
}

// Token is a token endpoint's answer (RFC 6749 §5.1, OIDC Core §3.1.3.3).
type Token struct {
	AccessToken  string
	RefreshToken string // "" when none was issued, or the old one stays good
	IDToken      string
	Expiry       time.Time
}

// Error is the provider's refusal (RFC 6749 §5.2). invalid_grant means the
// grant is over and the person has to log in again; invalid_target, that a
// resource was refused (RFC 8707 §2).
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return "rp: " + e.Code + ": " + e.Description
	}
	return "rp: " + e.Code
}

// IsInvalidGrant says whether err is the provider ending the grant.
func IsInvalidGrant(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "invalid_grant"
}

// Exchange trades the code the redirect brought for tokens, and verifies the
// ID token against the flow's nonce.
func (c *Client) Exchange(ctx context.Context, code string, f Flow) (*Token, *oidc.Token, error) {
	tok, err := c.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURI},
		"code_verifier": {f.Verifier},
	})
	if err != nil {
		return nil, nil, err
	}
	id, err := c.VerifyID(ctx, tok.IDToken, f.Nonce)
	if err != nil {
		return nil, nil, err
	}
	return tok, id, nil
}

// For names what a refreshed token is for: a resource server (RFC 8707
// §2.2: the token is for that one, the refresh token keeps the whole grant),
// and/or a scope, for a provider that sets the audience from a scope.
type For struct {
	Resource string
	Scope    string
}

// Refresh buys an access token with a refresh token. A provider that rotates
// refresh tokens returns a new one, and revokes the whole grant when a retired
// one comes back (RFC 9700 §4.14.2): keep the new one, and never refresh twice
// at once with the same.
func (c *Client) Refresh(ctx context.Context, refreshToken string, f For) (*Token, error) {
	v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if f.Resource != "" {
		v.Set("resource", f.Resource)
	}
	if f.Scope != "" {
		v.Set("scope", f.Scope)
	}
	return c.token(ctx, v)
}

func (c *Client) token(ctx context.Context, form url.Values) (*Token, error) {
	if c.cfg.Secret == "" {
		// A public client identifies itself in the body (RFC 6749 §3.2.1).
		form.Set("client_id", c.cfg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.cfg.Secret != "" {
		// RFC 6749 §2.3.1: both are form-encoded BEFORE they go into Basic.
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.Secret))
	}
	// ⛔ A redirect is not followed. On a 307 or 308 Go's client sends this
	// body again -- the refresh token, or the code and its verifier --
	// wherever it points, and the Basic credentials with it to the same host
	// on any scheme or port. A token endpoint has no reason to redirect
	// (RFC 6749 §3.2; RFC 9700 §4.12 is this replay on the front channel).
	// A copy of the caller's client, which may follow redirects elsewhere.
	hc := *c.p.client
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, fmt.Errorf("rp: token endpoint: %s: a redirect, not followed", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		var e Error
		if json.Unmarshal(body, &e) == nil && e.Code != "" {
			return nil, &e
		}
		return nil, fmt.Errorf("rp: token endpoint: %s", res.Status)
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("rp: token endpoint: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, errors.New("rp: token endpoint: no bearer access token in the answer")
	}
	t := &Token{AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken, IDToken: tr.IDToken}
	if tr.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return t, nil
}

// VerifyID checks an ID token: signature, issuer, audience (this client),
// times -- go-authn/oidc -- and the nonce of the login it answers, so that an
// ID token from another login cannot be played into this one (OIDC Core
// §3.1.3.7). With several audiences, azp must be this client.
func (c *Client) VerifyID(ctx context.Context, raw, nonce string) (*oidc.Token, error) {
	if raw == "" {
		// go-authn/oidc refuses an empty token too; this says why.
		return nil, errors.New("rp: the provider returned no ID token")
	}
	tok, err := c.idTokens.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var got string
	if err := tok.Claim("nonce", &got); err != nil || got == "" || got != nonce {
		return nil, errors.New("rp: the ID token does not carry this login's nonce")
	}
	if aud := tok.Audience(); len(aud) > 1 {
		var azp string
		if tok.Claim("azp", &azp) != nil || azp != c.cfg.ClientID {
			return nil, errors.New("rp: the ID token has several audiences and is not authorised to this client")
		}
	}
	return tok, nil
}

// EndSessionURL is where to send a browser to end the session at the
// provider too (OIDC RP-Initiated Logout §2), or "" when it has no such
// endpoint.
func (c *Client) EndSessionURL(postLogout string) string {
	if c.p.EndSessionURL == "" {
		return ""
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if postLogout != "" {
		q.Set("post_logout_redirect_uri", postLogout)
	}
	sep := "?"
	if strings.Contains(c.p.EndSessionURL, "?") {
		sep = "&"
	}
	return c.p.EndSessionURL + sep + q.Encode()
}

// Challenge is the S256 code challenge of verifier (RFC 7636 §4.2).
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// httpsOrLoopback refuses a URL a token or a key would cross in the clear.
func httpsOrLoopback(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("%q is not an https URL", raw)
}
