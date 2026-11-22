// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Suspicion 1: what open receives ends up in a process's arguments, which any
// local user can read. It must carry neither the state, the nonce nor the
// PKCE challenge, and must work once.
func TestLoopbackOpenGetsNoSecretAndWorksOnce(t *testing.T) {
	idp, p := publicIdP(t)
	var opened string
	var second int
	open := func(u string) error {
		opened = u
		go func() {
			back := follow(t, follow(t, u).String())
			// A reader of the arguments comes after the browser did.
			res, err := http.Get(u)
			if err == nil {
				second = res.StatusCode
				res.Body.Close()
			}
			if res, err := http.Get(back.String()); err == nil {
				res.Body.Close()
			}
		}()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, _, err := Loopback(ctx, p, Config{ClientID: idp.clientID}, open, nil); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"state=", "nonce=", "code_challenge"} {
		if strings.Contains(opened, k) {
			t.Errorf("the argument of the browser command carries %s: %s", k, opened)
		}
	}
	if second != http.StatusGone {
		t.Errorf("the launcher answered a second visit with %d, want %d", second, http.StatusGone)
	}
}

// Suspicion 2: OIDC Core §3.1.3.7 item 5, an azp that is present is this client.
func TestVerifyIDRefusesAForeignAzpWithOneAudience(t *testing.T) {
	idp, c := confidential(t)
	idp.azp = "someone-else"
	f := NewFlow()
	if _, _, err := c.Exchange(context.Background(), login(t, c, f, nil), f); err == nil {
		t.Fatal("an ID token with one audience and another client's azp was accepted")
	}
	idp.azp = idp.clientID
	f = NewFlow()
	if _, _, err := c.Exchange(context.Background(), login(t, c, f, nil), f); err != nil {
		t.Fatalf("azp naming this client: %v", err)
	}
}

// Suspicion 3: a Provider built by hand has no HTTP client.
func TestHandBuiltProviderDoesNotPanic(t *testing.T) {
	idp := newTestIdP(t)
	idp.redirect = redirect
	d, err := Discover(context.Background(), nil, idp.issuer)
	if err != nil {
		t.Fatal(err)
	}
	if (&Provider{}).httpClient() != http.DefaultClient {
		t.Fatal("a Provider without a client does not use the default")
	}
	hc := &http.Client{}
	if (&Provider{client: hc}).httpClient() != hc {
		t.Error("the Provider's own client is not used")
	}
	p := &Provider{Issuer: d.Issuer, AuthURL: d.AuthURL, TokenURL: d.TokenURL}
	c, err := NewClient(context.Background(), p, Config{ClientID: idp.clientID, Secret: idp.secret})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Refresh(context.Background(), "nope", For{})
	if err == nil {
		t.Fatal("accepted")
	}
}

// Suspicion 4: the provider's words are cut and cleaned before they reach a
// message, a log or a terminal.
func TestErrorTextIsBoundedAndPrintable(t *testing.T) {
	e := &Error{Code: "invalid_request", Description: "bad\nrp: forged log line\x1b[31m" + strings.Repeat("x", 100000)}
	msg := e.Error()
	if got := printable("a b c", 10); got != "abc" {
		t.Errorf("line separators kept: %q", got)
	}
	if got := printable("abcdef", 3); got != "abc..." {
		t.Errorf("cut at 3: %q", got)
	}
	if got := printable("abc", 3); got != "abc" {
		t.Errorf("exactly the bound: %q", got)
	}
	if strings.ContainsAny(msg, "\n\r\x1b") {
		t.Errorf("control characters in %q", msg[:80])
	}
	if len(msg) > 400 {
		t.Errorf("%d bytes", len(msg))
	}
	if !strings.HasPrefix(msg, "rp: invalid_request: badrp: forged") {
		t.Errorf("the text is not kept: %q", msg[:60])
	}
	if (&Error{Code: "access_denied"}).Error() != "rp: access_denied" {
		t.Error("no description")
	}
}
