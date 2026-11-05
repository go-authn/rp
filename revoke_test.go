// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func revokeClient(t *testing.T, idp *testIdP, secret string) *Client {
	t.Helper()
	p, err := Discover(context.Background(), idp.srv.Client(), idp.issuer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(context.Background(), p, Config{ClientID: idp.clientID, Secret: secret, RedirectURI: "http://localhost/cb"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// RFC 7009 §2.1: the token and its hint, the client authenticated as at the
// token endpoint; §2.2: 200 is success.
func TestRevokeSendsTheTokenAndAuthenticatesTheClient(t *testing.T) {
	idp := newTestIdP(t)
	idp.revocation = true
	c := revokeClient(t, idp, idp.secret)
	if c.Provider().RevocationURL == "" {
		t.Fatal("the revocation endpoint was not discovered")
	}
	if err := c.Revoke(context.Background(), "rt-123", RefreshTokenHint); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if idp.revokeGot.Get("token") != "rt-123" || idp.revokeGot.Get("token_type_hint") != "refresh_token" || !idp.revokeBasic || idp.revokeBasicUser != "portal" {
		t.Errorf("request: %v basic=%v user=%q", idp.revokeGot, idp.revokeBasic, idp.revokeBasicUser)
	}
	// A public client names itself in the body.
	pub := revokeClient(t, idp, "")
	if err := pub.Revoke(context.Background(), "rt-9", ""); err != nil {
		t.Fatal(err)
	}
	if idp.revokeBasic || idp.revokeGot.Get("client_id") != "portal" || idp.revokeGot.Has("token_type_hint") {
		t.Errorf("public client request: %v basic=%v", idp.revokeGot, idp.revokeBasic)
	}
}

func TestRevokeWithoutAnEndpointSaysSo(t *testing.T) {
	idp := newTestIdP(t)
	c := revokeClient(t, idp, idp.secret)
	if err := c.Revoke(context.Background(), "rt", RefreshTokenHint); !errors.Is(err, ErrNoRevocation) {
		t.Fatalf("Revoke with no endpoint = %v, want ErrNoRevocation", err)
	}
	idp.revocation = true
	c = revokeClient(t, idp, idp.secret)
	if err := c.Revoke(context.Background(), "", RefreshTokenHint); err == nil {
		t.Error("an empty token was sent")
	}
}

func TestRevokeProviderErrors(t *testing.T) {
	idp := newTestIdP(t)
	idp.revocation = true
	c := revokeClient(t, idp, idp.secret)
	idp.mu.Lock()
	idp.revokeStatus = 503
	idp.mu.Unlock()
	if err := c.Revoke(context.Background(), "rt", RefreshTokenHint); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("a 503 (RFC 7009 §2.2.1, retry later): %v", err)
	}
	idp.mu.Lock()
	idp.revokeStatus = 400
	idp.mu.Unlock()
	var e *Error
	if err := c.Revoke(context.Background(), "rt", RefreshTokenHint); !errors.As(err, &e) || e.Code != "unsupported_token_type" {
		t.Errorf("an error answer: %v", err)
	}
}

func FuzzParseRevocationError(f *testing.F) {
	f.Add([]byte(`{"error":"unsupported_token_type"}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if revocationError(400, b) == nil {
			t.Fatal("a refusal without an error")
		}
	})
}
