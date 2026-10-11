// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/go-authn/oidc"
)

// Loopback logs a person in from a native application, as RFC 8252 says to:
//
//   - it listens on the loopback IP literal, 127.0.0.1, or [::1] when there
//     is no IPv4 loopback, on a port the system picks (§7.3); never on
//     "localhost" (§8.3), and on no other interface;
//   - it opens the authorization URL in the system browser with open -- never
//     a web view inside the application (§8.12) -- and PKCE protects the code
//     on its way back (§6);
//   - it waits for the redirect at http://127.0.0.1:<port>/callback until ctx
//     ends. A request whose state is not this login's is answered 400 and
//     ignored -- any local process can reach the port -- so only the
//     provider's answer ends the wait.
//
// cfg.RedirectURI is set here; leave it empty. A native app is a public client
// (cfg.Secret empty, §8.5); go-authn/bridge accepts any loopback port for a
// client registered with http://127.0.0.1/callback. extra adds authorization
// parameters, such as RFC 8707 resources.
//
// It returns the client (to refresh with), the tokens, and the verified ID
// token.
func Loopback(ctx context.Context, p *Provider, cfg Config, open func(string) error, extra url.Values) (*Client, *Token, *oidc.Token, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if ln, err = net.Listen("tcp", "[::1]:0"); err != nil {
			return nil, nil, nil, fmt.Errorf("rp: no loopback interface to listen on: %w", err)
		}
	}
	defer ln.Close()
	cfg.RedirectURI = "http://" + ln.Addr().String() + "/callback"
	c, err := NewClient(ctx, p, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	f := NewFlow()

	type answer struct {
		code string
		err  error
	}
	answers := make(chan answer, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/callback" || r.Method != http.MethodGet ||
			subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
			// Not the answer to this login: somebody else knocking.
			http.Error(w, "not the answer to this login", http.StatusBadRequest)
			return
		}
		var a answer
		switch {
		case q.Get("iss") != "" && q.Get("iss") != p.Issuer:
			// RFC 9207: an answer naming another issuer is not this one's.
			a.err = errors.New("rp: the answer came from another issuer")
		case q.Get("error") != "":
			a.err = &Error{Code: q.Get("error"), Description: q.Get("error_description")}
		case q.Get("code") == "":
			a.err = errors.New("rp: the answer carries no code")
		default:
			a.code = q.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if a.err != nil {
			w.WriteHeader(http.StatusUnauthorized)
		}
		_ = donePage.Execute(w, a.err == nil)
		select {
		case answers <- a:
		default: // an answer was taken already
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	if err := open(c.AuthCodeURL(f, extra)); err != nil {
		return nil, nil, nil, fmt.Errorf("rp: opening the browser: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, nil, nil, ctx.Err()
	case a := <-answers:
		if a.err != nil {
			return nil, nil, nil, a.err
		}
		tok, id, err := c.Exchange(ctx, a.code, f)
		if err != nil {
			return nil, nil, nil, err
		}
		return c, tok, id, nil
	}
}

var donePage = template.Must(template.New("").Parse(`<!doctype html>
<meta charset="utf-8"><title>{{if .}}Logged in{{else}}Not logged in{{end}}</title>
<p>{{if .}}You are logged in. You can close this tab and go back to the application.{{else}}The login did not succeed. Go back to the application to try again.{{end}}`))

// OpenBrowser opens u in the system's default browser.
func OpenBrowser(u string) error {
	return browserCommand(runtime.GOOS, u).Start()
}

func browserCommand(goos, u string) *exec.Cmd {
	switch goos {
	case "darwin":
		return exec.Command("open", u)
	case "windows":
		// Not "cmd /c start": cmd would read the & of the query as its own.
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	}
	return exec.Command("xdg-open", u)
}
