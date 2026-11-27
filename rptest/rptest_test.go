// SPDX-License-Identifier: BSD-3-Clause

package rptest_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-authn/rp"
	"github.com/go-authn/rp/rptest"
)

const redirect = "https://app.example/callback"

func newIdP(t *testing.T) *rptest.IdP {
	p := rptest.New(t)
	p.Redirect = redirect
	return p
}

// client discovers p and builds rp's own client for it.
func client(t *testing.T, p *rptest.IdP) (*rp.Client, error) {
	t.Helper()
	prov, err := rp.Discover(t.Context(), p.Client(), p.Issuer)
	if err != nil {
		return nil, err
	}
	return rp.NewClient(t.Context(), prov, rp.Config{ClientID: p.ClientID, Secret: p.Secret, RedirectURI: redirect})
}

// authorize follows the authorization request without following the redirect
// to the application, and returns the query it carries.
func authorize(t *testing.T, p *rptest.IdP, c *rp.Client, f rp.Flow) url.Values {
	t.Helper()
	hc := &http.Client{Transport: p.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := hc.Get(c.AuthCodeURL(f, nil))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorization request: %s", res.Status)
	}
	u, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// login runs a whole login of p's current faults through rp.
func login(t *testing.T, p *rptest.IdP) error {
	t.Helper()
	c, err := client(t, p)
	if err != nil {
		return err
	}
	f := rp.NewFlow()
	q := authorize(t, p, c, f)
	if q.Get("state") != f.State {
		t.Fatalf("state %q, want %q", q.Get("state"), f.State)
	}
	if err := c.CheckIssuer(q); err != nil {
		return err
	}
	_, _, err = c.Exchange(context.Background(), q.Get("code"), f)
	return err
}

func TestGood(t *testing.T) {
	p := newIdP(t)
	p.Email = "alice@example.org"
	c, err := client(t, p)
	if err != nil {
		t.Fatal(err)
	}
	f := rp.NewFlow()
	q := authorize(t, p, c, f)
	if err := c.CheckIssuer(q); err != nil {
		t.Fatal(err)
	}
	_, id, err := c.Exchange(t.Context(), q.Get("code"), f)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject() != "alice-sub" || id.Issuer() != p.Issuer || id.Email() != "alice@example.org" || id.Username() != "alice" {
		t.Fatalf("ID token %q %q %q %q", id.Subject(), id.Issuer(), id.Email(), id.Username())
	}
	if len(p.AuthURLs) != 1 || len(p.TokenReq) != 1 || p.Discoveries == 0 {
		t.Fatalf("recorded %d authorization, %d token requests, %d discoveries", len(p.AuthURLs), len(p.TokenReq), p.Discoveries)
	}
	// single-use code
	if _, _, err := c.Exchange(t.Context(), q.Get("code"), f); !rp.IsInvalidGrant(err) {
		t.Fatalf("second use of the code: %v", err)
	}
}

// TestFaults: rp's client refuses every fault the fake can inject.
func TestFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*rptest.IdP)
	}{
		{"bad signature", func(p *rptest.IdP) { p.BadSig = true }},
		{"wrong audience", func(p *rptest.IdP) { p.WrongAudience = true }},
		{"expired", func(p *rptest.IdP) { p.Expired = true }},
		{"nonce mismatch", func(p *rptest.IdP) { p.BadNonce = true }},
		{"wrong issuer", func(p *rptest.IdP) { p.WrongIssuer = true }},
		{"alg none", func(p *rptest.IdP) { p.Alg = "none" }},
		{"HS256 keyed with the public key", func(p *rptest.IdP) { p.Alg = "HS256" }},
		{"no ID token", func(p *rptest.IdP) { p.NoIDToken = true }},
		{"wrong iss parameter", func(p *rptest.IdP) { p.IssParam = "https://evil.example" }},
		{"missing iss parameter when advertised", func(p *rptest.IdP) { p.IssParamAdvert, p.NoIssParam = true, true }},
		{"no S256", func(p *rptest.IdP) { p.NoS256 = true }},
		{"discovery names another issuer", func(p *rptest.IdP) { p.DiscoveryIss = "https://other.example" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIdP(t)
			tc.set(p)
			if err := login(t, p); err == nil {
				t.Fatal("rp accepted it")
			}
		})
	}
}

// TestStrict: the provider refuses what a real one refuses.
func TestStrict(t *testing.T) {
	p := newIdP(t)
	prov, err := rp.Discover(t.Context(), p.Client(), p.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(secret, redir string) *rp.Client {
		c, err := rp.NewClient(t.Context(), prov, rp.Config{ClientID: p.ClientID, Secret: secret, RedirectURI: redir})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	hc := &http.Client{Transport: p.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// another redirect URI: the authorization request is refused
	res, err := hc.Get(mk(p.Secret, "https://evil.example/cb").AuthCodeURL(rp.NewFlow(), nil))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("another redirect URI: %s", res.Status)
	}

	// another secret: invalid_client
	c := mk("other", redirect)
	f := rp.NewFlow()
	q := authorize(t, p, c, f)
	_, _, err = c.Exchange(t.Context(), q.Get("code"), f)
	var e *rp.Error
	if !errors.As(err, &e) || e.Code != "invalid_client" {
		t.Fatalf("another secret: %v", err)
	}

	// another PKCE verifier: invalid_grant
	c = mk(p.Secret, redirect)
	q = authorize(t, p, c, f)
	_, _, err = c.Exchange(t.Context(), q.Get("code"), rp.Flow{State: f.State, Nonce: f.Nonce, Verifier: "another-verifier"})
	if !rp.IsInvalidGrant(err) {
		t.Fatalf("another verifier: %v", err)
	}
}

// TestFaultIsTheCause: the same flow without the fault succeeds, so each
// refusal above comes from the fault and not from the harness.
func TestFaultIsTheCause(t *testing.T) {
	p := newIdP(t)
	p.IssParamAdvert = true
	if err := login(t, p); err != nil {
		t.Fatal(err)
	}
}
