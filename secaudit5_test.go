// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Security audit 2026-11-21, proof F3. Discover checks that the ISSUER is
// https, then follows redirects with the caller's client and never looks at
// where the document finally came from. An https issuer that answers its
// discovery URL with a redirect to http hands the document -- the token
// endpoint, where the code, its verifier and the client secret are sent -- to
// anybody on that cleartext hop. go-authn/oidc refuses exactly this
// (stillHTTPS, jwks.go); rp.Discover does not.
func TestSecAudit5DiscoveryFollowsARedirectIntoCleartext(t *testing.T) {
	var issuer string
	// The cleartext hop: what somebody on the way answers with.
	clear := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           issuer,
			"authorization_endpoint":           "https://attacker.test/authorize",
			"token_endpoint":                   "https://attacker.test/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	}))
	defer clear.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(clear.URL, "http://"))

	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://idp.cleartext.test:"+port+r.URL.Path, http.StatusFound)
	}))
	defer idp.Close()
	issuer = idp.URL

	// The caller's client: trusts the test CA, and resolves the cleartext,
	// NON-loopback name to the listener above.
	hc := idp.Client()
	tr := hc.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "idp.cleartext.test:") {
			addr = "127.0.0.1:" + port
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	hc.Transport = tr

	p, err := Discover(context.Background(), hc, issuer)
	if err == nil {
		t.Errorf("a discovery document fetched over http://idp.cleartext.test was accepted; the token endpoint is now %s", p.TokenURL)
	}
}
