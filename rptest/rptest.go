// SPDX-License-Identifier: BSD-3-Clause

// Package rptest is a fake OpenID provider for the tests of a relying party
// built on go-authn/rp. It serves discovery (OpenID Connect Discovery 1.0 §4),
// the key set (RFC 7517) and an authorization-code flow with PKCE S256, and it
// is strict where a real provider is strict: exact redirect URI, the PKCE
// verifier checked, client_secret_basic, single-use codes.
//
// Each way a provider or an attacker can misbehave is a field of [IdP]: a wrong
// nonce, issuer or audience, an expired token (OpenID Connect Core 1.0
// §3.1.3.7), "alg":"none", an HS256 token keyed with the public key's bytes, a
// missing or wrong "iss" response parameter (RFC 9207). The package's own test
// runs rp's client against every one, so the fake cannot drift from what rp
// accepts and refuses.
//
// It serves HTTPS on a loopback address; [IdP.Client] trusts its certificate.
//
//	p := rptest.New(t)
//	p.Redirect = "https://app.example/callback"
//	prov, err := rp.Discover(ctx, p.Client(), p.Issuer)
package rptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// IdP is a fake provider. Set the fields before the step they affect.
type IdP struct {
	Server   *httptest.Server
	Issuer   string
	ClientID string
	Secret   string
	Redirect string // the one redirect URI the provider accepts

	// Sub, Username and Email are the claims of the next ID token.
	Sub, Username, Email string

	// Faults. Each is read when the request it affects arrives.
	Alg            string // "" or "ES256"; "none"; "HS256"
	BadSig         bool   // ES256 signed by a key the key set does not hold
	BadNonce       bool
	WrongIssuer    bool // ID token iss
	WrongAudience  bool
	Expired        bool
	NoIssParam     bool   // the authorization response has no iss
	IssParam       string // a wrong iss in the authorization response
	IssParamAdvert bool   // discovery promises the iss parameter
	NoS256         bool   // discovery lists only "plain"
	DiscoveryIss   string // discovery names this issuer instead
	NoIDToken      bool

	key *ecdsa.PrivateKey

	mu       sync.Mutex
	codes    map[string]grant
	AuthURLs []url.Values // the query of every authorization request
	TokenReq []url.Values // the form of every token request
	// Discoveries counts the requests for the discovery document.
	Discoveries int
}

type grant struct{ challenge, nonce, redirect string }

// New starts a provider with client "rptest" and secret "s3cret", and closes it
// when t ends.
func New(t testing.TB) *IdP {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{key: k, ClientID: "rptest", Secret: "s3cret", Sub: "alice-sub", Username: "alice", codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Server.Close)
	p.Issuer = p.Server.URL
	return p
}

// Client is an HTTP client that trusts the provider's certificate.
func (p *IdP) Client() *http.Client { return p.Server.Client() }

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	p.Discoveries++
	p.mu.Unlock()
	iss := p.Issuer
	if p.DiscoveryIss != "" {
		iss = p.DiscoveryIss
	}
	d := map[string]any{"issuer": iss, "authorization_endpoint": p.Issuer + "/authorize",
		"token_endpoint": p.Issuer + "/token", "jwks_uri": p.Issuer + "/jwks"}
	if p.IssParamAdvert {
		d["authorization_response_iss_parameter_supported"] = true
	}
	if p.NoS256 {
		d["code_challenge_methods_supported"] = []string{"plain"}
	} else {
		d["code_challenge_methods_supported"] = []string{"S256"}
	}
	_ = json.NewEncoder(w).Encode(d)
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
		"x": b64(pub.X.FillBytes(make([]byte, 32))), "y": b64(pub.Y.FillBytes(make([]byte, 32))),
	}}})
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	p.AuthURLs = append(p.AuthURLs, q)
	p.mu.Unlock()
	if q.Get("client_id") != p.ClientID || q.Get("redirect_uri") != p.Redirect ||
		q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := random()
	p.mu.Lock()
	p.codes[code] = grant{q.Get("code_challenge"), q.Get("nonce"), q.Get("redirect_uri")}
	p.mu.Unlock()
	v := url.Values{"code": {code}, "state": {q.Get("state")}}
	switch {
	case p.IssParam != "":
		v.Set("iss", p.IssParam)
	case !p.NoIssParam:
		v.Set("iss", p.Issuer)
	}
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+v.Encode(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	p.TokenReq = append(p.TokenReq, r.PostForm)
	p.mu.Unlock()
	id, secret, basic := r.BasicAuth()
	id, _ = url.QueryUnescape(id)
	secret, _ = url.QueryUnescape(secret)
	if !basic || id != p.ClientID || secret != p.Secret {
		tokenErr(w, "invalid_client")
		return
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	verifier := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if r.PostForm.Get("grant_type") != "authorization_code" || !ok || g.redirect != r.PostForm.Get("redirect_uri") ||
		b64(sum[:]) != g.challenge || verifier == "" {
		tokenErr(w, "invalid_grant")
		return
	}
	nonce, iss, aud := g.nonce, p.Issuer, p.ClientID
	if p.BadNonce {
		nonce = "not-" + nonce
	}
	if p.WrongIssuer {
		iss += "/other"
	}
	if p.WrongAudience {
		aud = "someone-else"
	}
	now := time.Now()
	exp := now.Add(time.Hour)
	if p.Expired {
		now, exp = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	claims := map[string]any{"iss": iss, "sub": p.Sub, "aud": aud, "nonce": nonce,
		"preferred_username": p.Username, "iat": now.Unix(), "exp": exp.Unix()}
	if p.Email != "" {
		claims["email"], claims["email_verified"] = p.Email, true
	}
	resp := map[string]any{"access_token": random(), "token_type": "Bearer", "expires_in": 300,
		"id_token": p.Sign(claims)}
	if p.NoIDToken {
		delete(resp, "id_token")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Sign makes an ID token with the [IdP.Alg] fault's algorithm.
func (p *IdP) Sign(claims map[string]any) string {
	alg := p.Alg
	if alg == "" {
		alg = "ES256"
	}
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	switch alg {
	case "none":
		return in + "."
	case "HS256":
		// the classic confusion: a MAC keyed with the public key's bytes
		pub := append(p.key.PublicKey.X.FillBytes(make([]byte, 32)), p.key.PublicKey.Y.FillBytes(make([]byte, 32))...)
		m := hmac.New(sha256.New, pub)
		m.Write([]byte(in))
		return in + "." + b64(m.Sum(nil))
	}
	key := p.key
	if p.BadSig { // a well-formed ES256 signature by a key the JWKS does not hold
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		panic(err)
	}
	return in + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return b64(b)
}

func tokenErr(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "test"})
}
