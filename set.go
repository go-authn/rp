// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-authn/oidc"
)

// Several providers.
//
// A client of two or more authorization servers is open to mix-up attacks
// (RFC 9700 §4.4): a malicious server makes the client send the code it got
// from an honest one to the attacker's. The defences are the ones RFC 9700
// §4.4.2 lists: the client stores, for each authorization request, the issuer
// it was sent to, bound to the browser, and aborts when the answer is from
// another -- by the "iss" authorization-response parameter (RFC 9207), by the
// "iss" of the ID token, or by a distinct redirect URI for each issuer.
//
// A [Set] does the first two and leaves the third to the caller, who owns the
// routes: register one redirect URI per provider and hand each callback the
// provider's name.

// CheckIssuer verifies the "iss" authorization-response parameter of the
// redirect's query against this client's provider (RFC 9207 §2.4): when it is
// present it must be exactly the provider's issuer, and present once. A
// response without one is refused when the provider's metadata says it sends it
// ([Provider.IssParamSupported]); otherwise it is accepted, as the RFC allows
// and the ID token's "iss" is still verified. Use it in any redirect handler,
// whether or not there are several providers.
func (c *Client) CheckIssuer(q url.Values) error {
	isses := q["iss"]
	switch {
	case len(isses) > 1:
		return errors.New("rp: several iss parameters in the authorization response")
	case len(isses) == 1 && isses[0] != c.p.Issuer:
		return fmt.Errorf("rp: the authorization response is from issuer %q, not %q", truncate(isses[0], 128), c.p.Issuer)
	case len(isses) == 0 && c.p.IssParamSupported:
		return errors.New("rp: the provider sends iss in its authorization responses and this one has none")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// A Set is the providers a service logs people in at, by name.
type Set struct {
	names []string
	cs    map[string]*Client
}

// NewSet is an empty set.
func NewSet() *Set { return &Set{cs: map[string]*Client{}} }

// Add registers a client under name. Two names for one issuer, or one name
// twice, are refused: a login would not say which provider it is for.
func (s *Set) Add(name string, c *Client) error {
	if name == "" || strings.ContainsAny(name, "/?#") {
		return fmt.Errorf("rp: provider name %q: want a non-empty name without / ? #", name)
	}
	if _, ok := s.cs[name]; ok {
		return fmt.Errorf("rp: provider %q is registered twice", name)
	}
	for n, o := range s.cs {
		if o.p.Issuer == c.p.Issuer {
			return fmt.Errorf("rp: providers %q and %q have one issuer", n, name)
		}
	}
	s.cs[name] = c
	s.names = append(s.names, name)
	return nil
}

// Names are the providers, in the order they were added.
func (s *Set) Names() []string { return append([]string(nil), s.names...) }

// Client is the provider's client, or nil.
func (s *Set) Client(name string) *Client { return s.cs[name] }

// ErrUnknownProvider is a name that is not in the set.
var ErrUnknownProvider = errors.New("rp: unknown provider")

// NewFlow is a login at provider name: [NewFlow] with the provider recorded.
// Keep the Flow where only this browser can bring it back, as for a single
// provider.
func (s *Set) NewFlow(name string) (Flow, error) {
	if s.cs[name] == nil {
		return Flow{}, ErrUnknownProvider
	}
	f := NewFlow()
	f.Provider = name
	return f, nil
}

// AuthCodeURL is where to send the browser for the flow's provider.
func (s *Set) AuthCodeURL(f Flow, extra url.Values) (string, error) {
	c := s.cs[f.Provider]
	if c == nil {
		return "", ErrUnknownProvider
	}
	return c.AuthCodeURL(f, extra), nil
}

// ErrMixUp is a redirect delivered to the callback of a provider other than the
// one the login was sent to, or carrying another provider's issuer.
var ErrMixUp = errors.New("rp: the authorization response is not from the provider this login was sent to")

// Exchange finishes a login at the callback of provider name. query is the
// redirect's query (for its "iss"). It refuses, before any request leaves,
// a flow that was started at another provider and a response whose iss is not
// this provider's; then it is [Client.Exchange] at that provider, whose ID
// token is verified against that provider's issuer and this login's nonce.
func (s *Set) Exchange(ctx context.Context, name, code string, f Flow, query url.Values) (*Token, *oidc.Token, error) {
	c := s.cs[name]
	if c == nil {
		return nil, nil, ErrUnknownProvider
	}
	if f.Provider != name {
		return nil, nil, fmt.Errorf("%w: started at %q, delivered to %q", ErrMixUp, f.Provider, name)
	}
	if err := c.CheckIssuer(query); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMixUp, err)
	}
	return c.Exchange(ctx, code, f)
}
