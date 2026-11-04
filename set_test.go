// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

// two providers behind one Set, each with its own redirect URI.
func twoProviders(t *testing.T) (*Set, *testIdP, *testIdP) {
	t.Helper()
	mk := func(path string) (*testIdP, *Client) {
		idp := newTestIdP(t)
		idp.redirect = redirect + path
		p, err := Discover(context.Background(), nil, idp.issuer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewClient(context.Background(), p, Config{ClientID: idp.clientID, Secret: idp.secret, RedirectURI: idp.redirect})
		if err != nil {
			t.Fatal(err)
		}
		return idp, c
	}
	a, ca := mk("/a")
	b, cb := mk("/b")
	s := NewSet()
	if err := s.Add("a", ca); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("b", cb); err != nil {
		t.Fatal(err)
	}
	return s, a, b
}

// begin starts a login at name and returns the redirect the provider sends
// back (its query: code, state, iss) and the flow.
func begin(t *testing.T, s *Set, name string) (url.Values, Flow) {
	t.Helper()
	f, err := s.NewFlow(name)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.AuthCodeURL(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	return follow(t, u).Query(), f
}

func TestSetLogin(t *testing.T) {
	s, _, _ := twoProviders(t)
	for _, n := range []string{"a", "b"} {
		q, f := begin(t, s, n)
		if f.Provider != n {
			t.Fatalf("flow for %s: %+v", n, f)
		}
		if _, id, err := s.Exchange(context.Background(), n, q.Get("code"), f, q); err != nil || id.Issuer() != s.Client(n).Provider().Issuer {
			t.Fatalf("%s: %v", n, err)
		}
	}
	if got := s.Names(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("names: %v", got)
	}
}

// RFC 9700 §4.4: a flow started at a, whatever answers, is not finished at b.
func TestSetMixUp(t *testing.T) {
	s, _, _ := twoProviders(t)
	ctx := context.Background()
	q, f := begin(t, s, "a")
	if _, _, err := s.Exchange(ctx, "b", q.Get("code"), f, q); !errors.Is(err, ErrMixUp) {
		t.Fatalf("a's flow at b's callback: %v", err)
	}
	// A flow that claims to be for b (as a forged cookie or state might), with
	// a's answer: b's token endpoint does not know the code.
	f2 := f
	f2.Provider = "b"
	if _, _, err := s.Exchange(ctx, "b", q.Get("code"), f2, q); err == nil {
		t.Fatal("a code from a bought tokens at b")
	}
	// The iss parameter of another provider.
	q, f = begin(t, s, "a")
	q.Set("iss", s.Client("b").Provider().Issuer)
	if _, _, err := s.Exchange(ctx, "a", q.Get("code"), f, q); !errors.Is(err, ErrMixUp) {
		t.Fatalf("iss of b at a: %v", err)
	}
	q.Add("iss", s.Client("a").Provider().Issuer)
	if _, _, err := s.Exchange(ctx, "a", q.Get("code"), f, q); !errors.Is(err, ErrMixUp) {
		t.Fatalf("two iss: %v", err)
	}
	if _, _, err := s.Exchange(ctx, "nope", "c", f, q); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unknown provider: %v", err)
	}
}

// RFC 9207 §2.4 for a client of one provider: CheckIssuer.
func TestCheckIssuer(t *testing.T) {
	_, c := confidential(t)
	iss := c.Provider().Issuer
	for _, tc := range []struct {
		name string
		q    url.Values
		want bool
	}{
		{"absent, not promised", url.Values{}, true},
		{"right", url.Values{"iss": {iss}}, true},
		{"other", url.Values{"iss": {iss + "/x"}}, false},
		{"two", url.Values{"iss": {iss, iss}}, false},
		{"empty", url.Values{"iss": {""}}, false},
	} {
		if err := c.CheckIssuer(tc.q); (err == nil) != tc.want {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A provider that says it sends iss: a response without one is refused.
	c.p.IssParamSupported = true
	if err := c.CheckIssuer(url.Values{}); err == nil {
		t.Error("no iss from a provider that promises it")
	}
}

func TestSetRefusals(t *testing.T) {
	s, _, _ := twoProviders(t)
	if err := s.Add("a", s.Client("b")); err == nil {
		t.Error("a name twice")
	}
	if err := s.Add("c", s.Client("b")); err == nil {
		t.Error("one issuer under two names")
	}
	for _, n := range []string{"", "x/y", "x?y", "x#y"} {
		if err := s.Add(n, s.Client("a")); err == nil {
			t.Errorf("name %q", n)
		}
	}
	if _, err := s.NewFlow("nope"); !errors.Is(err, ErrUnknownProvider) {
		t.Error("flow for an unknown provider")
	}
}

func TestDiscoveryReadsIssParamSupport(t *testing.T) {
	idp := newTestIdP(t)
	p, err := Discover(context.Background(), nil, idp.issuer)
	if err != nil || p.IssParamSupported {
		t.Fatalf("default: %v %v", p, err)
	}
	idp.issParam = true
	if p, err = Discover(context.Background(), nil, idp.issuer); err != nil || !p.IssParamSupported {
		t.Fatalf("promised: %v %v", p, err)
	}
}

func FuzzCheckIssuer(f *testing.F) {
	f.Add("https://a", "https://a")
	f.Fuzz(func(t *testing.T, issuer, got string) {
		c := &Client{p: &Provider{Issuer: issuer}}
		err := c.CheckIssuer(url.Values{"iss": {got}})
		if (err == nil) != (got == issuer) {
			t.Fatalf("issuer %q, iss %q: %v", issuer, got, err)
		}
	})
}
