// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// browser plays the system browser: it visits the authorization URL and
// follows the provider's redirect to the application's loopback listener.
func browser(t *testing.T, before func(callback *url.URL)) func(string) error {
	return func(auth string) error {
		go func() {
			back := follow(t, auth)
			if before != nil {
				before(back)
			}
			res, err := http.Get(back.String())
			if err == nil {
				res.Body.Close()
			}
		}()
		return nil
	}
}

func publicIdP(t *testing.T) (*testIdP, *Provider) {
	t.Helper()
	idp := newTestIdP(t)
	idp.public = true
	p, err := Discover(context.Background(), nil, idp.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return idp, p
}

func TestLoopbackLogin(t *testing.T) {
	idp, p := publicIdP(t)
	idp.resources = []string{"https://a.example/"}
	var seen *url.URL
	// Another local process knocks first, with no state: answered 400, and
	// the login goes on.
	open := browser(t, func(cb *url.URL) {
		seen = cb
		knock := *cb
		knock.RawQuery = "code=forged&state=wrong"
		if res, err := http.Get(knock.String()); err == nil {
			if res.StatusCode != http.StatusBadRequest {
				t.Errorf("a knock with another state: %s", res.Status)
			}
			res.Body.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, tok, id, err := Loopback(ctx, p, Config{ClientID: idp.clientID, Scopes: []string{"openid", "offline_access"}}, open, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject() != "alice-sub" || tok.RefreshToken == "" {
		t.Fatalf("%+v", tok)
	}
	if seen.Scheme != "http" || seen.Hostname() != "127.0.0.1" || seen.Path != "/callback" || seen.Port() == "" {
		t.Fatalf("redirected to %s: RFC 8252 wants http://127.0.0.1:<port>/callback", seen)
	}
	// And the client refreshes, as a public client.
	if _, err := c.Refresh(ctx, tok.RefreshToken, For{Resource: "https://a.example/"}); err != nil {
		t.Fatal(err)
	}
}

func TestLoopbackRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("the provider says no", func(t *testing.T) {
		idp, p := publicIdP(t)
		open := browser(t, func(cb *url.URL) {
			q := cb.Query()
			q.Del("code")
			q.Set("error", "access_denied")
			cb.RawQuery = q.Encode()
		})
		_, _, _, err := Loopback(ctx, p, Config{ClientID: idp.clientID}, open, nil)
		var e *Error
		if !errors.As(err, &e) || e.Code != "access_denied" {
			t.Fatal(err)
		}
	})
	t.Run("an answer from another issuer", func(t *testing.T) {
		idp, p := publicIdP(t)
		open := browser(t, func(cb *url.URL) {
			q := cb.Query()
			q.Set("iss", "https://evil.example")
			cb.RawQuery = q.Encode()
		})
		if _, _, _, err := Loopback(ctx, p, Config{ClientID: idp.clientID}, open, nil); err == nil || !strings.Contains(err.Error(), "another issuer") {
			t.Fatal(err)
		}
	})
	t.Run("no code", func(t *testing.T) {
		idp, p := publicIdP(t)
		open := browser(t, func(cb *url.URL) {
			q := cb.Query()
			q.Del("code")
			cb.RawQuery = q.Encode()
		})
		if _, _, _, err := Loopback(ctx, p, Config{ClientID: idp.clientID}, open, nil); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("a code that does not exchange", func(t *testing.T) {
		idp, p := publicIdP(t)
		open := browser(t, func(cb *url.URL) {
			q := cb.Query()
			q.Set("code", "never-issued")
			cb.RawQuery = q.Encode()
		})
		if _, _, _, err := Loopback(ctx, p, Config{ClientID: idp.clientID}, open, nil); !IsInvalidGrant(err) {
			t.Fatal(err)
		}
	})
	t.Run("nobody answers", func(t *testing.T) {
		idp, p := publicIdP(t)
		short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		_, _, _, err := Loopback(short, p, Config{ClientID: idp.clientID}, func(string) error { return nil }, nil)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
	t.Run("no browser", func(t *testing.T) {
		idp, p := publicIdP(t)
		_, _, _, err := Loopback(ctx, p, Config{ClientID: idp.clientID}, func(string) error { return errors.New("none") }, nil)
		if err == nil || !strings.Contains(err.Error(), "opening the browser") {
			t.Fatal(err)
		}
	})
	t.Run("no client ID", func(t *testing.T) {
		_, p := publicIdP(t)
		if _, _, _, err := Loopback(ctx, p, Config{}, func(string) error { return nil }, nil); err == nil {
			t.Fatal("accepted")
		}
	})
}
