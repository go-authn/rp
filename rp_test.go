// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const redirect = "https://app.example.org/callback"

// follow GETs u without following redirects, and returns where it points.
func follow(t *testing.T, u string) *url.URL {
	t.Helper()
	nc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := nc.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatalf("%s: %s", u, res.Status)
	}
	return loc
}

func confidential(t *testing.T) (*testIdP, *Client) {
	t.Helper()
	idp := newTestIdP(t)
	idp.redirect = redirect
	idp.resources = []string{"https://a.example/", "https://b.example/"}
	p, err := Discover(context.Background(), nil, idp.issuer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(context.Background(), p, Config{ClientID: idp.clientID, Secret: idp.secret, RedirectURI: redirect,
		Scopes: []string{"openid", "offline_access"}})
	if err != nil {
		t.Fatal(err)
	}
	return idp, c
}

func login(t *testing.T, c *Client, f Flow, extra url.Values) string {
	t.Helper()
	back := follow(t, c.AuthCodeURL(f, extra))
	if back.Query().Get("state") != f.State {
		t.Fatal("state lost")
	}
	return back.Query().Get("code")
}

func TestCodeFlowAndRefreshForOneResource(t *testing.T) {
	idp, c := confidential(t)
	f := NewFlow()
	u, _ := url.Parse(c.AuthCodeURL(f, url.Values{"prompt": {"login"}}))
	if q := u.Query(); q.Get("code_challenge") != Challenge(f.Verifier) || q.Get("code_challenge_method") != "S256" ||
		q.Get("nonce") != f.Nonce || q.Get("scope") != "openid offline_access" || q.Get("prompt") != "login" {
		t.Fatalf("authorization URL %s", u)
	}
	tok, id, err := c.Exchange(context.Background(), login(t, c, f, nil), f)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject() != "alice-sub" || tok.RefreshToken == "" || tok.Expiry.IsZero() {
		t.Fatalf("%+v", tok)
	}
	// A token for B alone; the refresh token rotates.
	at, err := c.Refresh(context.Background(), tok.RefreshToken, For{Resource: "https://b.example/"})
	if err != nil {
		t.Fatal(err)
	}
	if audOf(t, at.AccessToken) != "https://b.example/" || at.RefreshToken == "" || at.RefreshToken == tok.RefreshToken {
		t.Fatalf("aud %v", audOf(t, at.AccessToken))
	}
	// The retired one again: the provider ends the grant.
	if _, err := c.Refresh(context.Background(), tok.RefreshToken, For{Resource: "https://a.example/"}); !IsInvalidGrant(err) {
		t.Fatalf("a replayed refresh token: %v", err)
	}
	// A resource it does not know: invalid_target, which is not the end.
	_, err = c.Refresh(context.Background(), "x", For{Resource: "https://elsewhere/", Scope: "s"})
	var e *Error
	if !errors.As(err, &e) || IsInvalidGrant(errors.New("x")) {
		t.Fatalf("%v", err)
	}
	if c.Provider().Issuer != idp.issuer || !strings.HasPrefix(c.EndSessionURL("https://app/"), idp.issuer+"/logout?x=1&") || !strings.Contains(c.EndSessionURL(""), "client_id=") {
		t.Fatal(c.EndSessionURL(""))
	}
}

// A public client sends no secret, and names itself in the body.
func TestPublicClient(t *testing.T) {
	idp := newTestIdP(t)
	idp.public, idp.redirect = true, redirect
	p, err := Discover(context.Background(), nil, idp.issuer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(context.Background(), p, Config{ClientID: idp.clientID, RedirectURI: redirect})
	if err != nil {
		t.Fatal(err)
	}
	f := NewFlow()
	if _, _, err := c.Exchange(context.Background(), login(t, c, f, nil), f); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeRefusals(t *testing.T) {
	for name, knob := range map[string]func(*testIdP){
		"another login's nonce":          func(p *testIdP) { p.badNonce = true },
		"two audiences, no azp":          func(p *testIdP) { p.extraAud = true },
		"no ID token (no openid answer)": func(p *testIdP) { p.noIDToken = true },
	} {
		t.Run(name, func(t *testing.T) {
			idp, c := confidential(t)
			knob(idp)
			f := NewFlow()
			if _, _, err := c.Exchange(context.Background(), login(t, c, f, nil), f); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("the wrong verifier", func(t *testing.T) {
		_, c := confidential(t)
		f := NewFlow()
		code := login(t, c, f, nil)
		f.Verifier = NewFlow().Verifier
		if _, _, err := c.Exchange(context.Background(), code, f); !IsInvalidGrant(err) {
			t.Fatal(err)
		}
	})
}

func TestNewClientRefusals(t *testing.T) {
	idp := newTestIdP(t)
	p, _ := Discover(context.Background(), nil, idp.issuer)
	if _, err := NewClient(context.Background(), p, Config{}); err == nil {
		t.Error("no client ID")
	}
	if _, err := NewClient(context.Background(), p, Config{ClientID: "c", Scopes: []string{"profile"}}); err == nil {
		t.Error("no openid")
	}
	idp.srv.Close()
	if _, err := NewClient(context.Background(), p, Config{ClientID: "c"}); err == nil {
		t.Error("keys unreachable")
	}
}

func TestDiscoveryRefusals(t *testing.T) {
	for name, knob := range map[string]func(*testIdP){
		"another issuer": func(p *testIdP) { p.wrongIssuer = true },
		"no S256":        func(p *testIdP) { p.noS256 = true },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newTestIdP(t)
			knob(idp)
			if _, err := Discover(context.Background(), nil, idp.issuer); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	var doc any
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if s, ok := doc.(string); ok {
			_, _ = w.Write([]byte(s))
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	for name, set := range map[string]func(){
		"a 404":    func() { status = 404 },
		"not JSON": func() { doc = "<html>" },
		"a token endpoint in clear": func() {
			doc = map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL, "token_endpoint": "http://idp.example/t"}
		},
	} {
		status, doc = 200, nil
		set()
		if _, err := Discover(context.Background(), nil, srv.URL); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An end-session endpoint in the clear is dropped, not kept.
	status, doc = 200, map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/a", "token_endpoint": srv.URL + "/t",
		"end_session_endpoint": "http://idp.example/logout"}
	if p, err := Discover(context.Background(), nil, srv.URL); err != nil || p.EndSessionURL != "" {
		t.Errorf("%v %+v", err, p)
	}
	for _, bad := range []string{"http://idp.example", "::", "http://127.0.0.1:1"} {
		if _, err := Discover(context.Background(), nil, bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestTokenEndpointAnswers(t *testing.T) {
	var answer func(w http.ResponseWriter)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w) }))
	defer srv.Close()
	c := &Client{p: &Provider{TokenURL: srv.URL, client: http.DefaultClient}, cfg: Config{ClientID: "c", Secret: "s"}}
	for name, a := range map[string]func(w http.ResponseWriter){
		"a 500":         func(w http.ResponseWriter) { http.Error(w, "x", 500) },
		"not JSON":      func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) },
		"no token":      func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"token_type":"Bearer"}`)) },
		"not bearer":    func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"access_token":"x","token_type":"DPoP"}`)) },
		"an error code": func(w http.ResponseWriter) { tokenErr(w, "invalid_client") },
	} {
		answer = a
		if _, err := c.Refresh(context.Background(), "rt", For{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	answer = func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"access_token":"x","token_type":"bearer"}`)) }
	if tok, err := c.Refresh(context.Background(), "rt", For{}); err != nil || !tok.Expiry.IsZero() {
		t.Fatalf("%v %+v", err, tok)
	}
	c.p.TokenURL = "http://127.0.0.1:1"
	if _, err := c.Refresh(context.Background(), "rt", For{}); err == nil {
		t.Error("unreachable")
	}
	c.p.TokenURL = "::"
	if _, err := c.Refresh(context.Background(), "rt", For{}); err == nil {
		t.Error("malformed")
	}
	if (&Error{Code: "x"}).Error() != "rp: x" || (&Error{Code: "x", Description: "y"}).Error() != "rp: x: y" {
		t.Error("Error()")
	}
	if c.EndSessionURL("x") != "" {
		t.Error("an end-session URL without an endpoint")
	}
}

func TestBrowserCommand(t *testing.T) {
	for goos, want := range map[string]string{"darwin": "open", "windows": "rundll32", "linux": "xdg-open", "freebsd": "xdg-open"} {
		if cmd := browserCommand(goos, "https://x/?a=1&b=2"); !strings.HasSuffix(cmd.Path, want) && cmd.Args[0] != want {
			t.Errorf("%s: %v", goos, cmd.Args)
		} else if cmd.Args[len(cmd.Args)-1] != "https://x/?a=1&b=2" {
			t.Errorf("%s: the URL is not passed whole: %v", goos, cmd.Args)
		}
	}
}

// A token endpoint that redirects is not followed. On a 307 or 308 Go's
// client sends the POST body again -- the refresh token, or the code and its
// verifier -- wherever the redirect points, and Basic credentials with it to
// the same host on any scheme or port. Nothing in RFC 6749 has a token
// endpoint redirect; RFC 9700 §4.12 is this replay on the front channel.
// The listener on the other end records what reaches it.
func TestTokenEndpointRedirectIsNotFollowed(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		var got []string
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			got = append(got, r.PostForm.Get("refresh_token")+r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"access_token":"x","token_type":"bearer"}`))
		}))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/token", code)
		}))
		c := &Client{p: &Provider{TokenURL: srv.URL, client: http.DefaultClient}, cfg: Config{ClientID: "c", Secret: "s"}}
		_, err := c.Refresh(context.Background(), "the-refresh-token", For{})
		srv.Close()
		other.Close()
		if len(got) != 0 {
			t.Fatalf("%d: the redirect was followed, and carried %q", code, got)
		}
		if err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("%d: %v", code, err)
		}
	}
	// The caller's client is left as it was: it may follow redirects
	// elsewhere (discovery does).
	if http.DefaultClient.CheckRedirect != nil {
		t.Fatal("the caller's client was changed")
	}
}
