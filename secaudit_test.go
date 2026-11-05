// SPDX-License-Identifier: BSD-3-Clause

package rp

import (
	"context"
	"net/url"
	"testing"
	"time"
)

// Security audit 2026-11-05 (untracked proof). The provider's discovery
// promises the RFC 9207 iss parameter (authorization_response_iss_parameter_
// supported), which Provider.IssParamSupported documents as "a response
// without one is refused" and CheckIssuer enforces. Loopback does its own
// iss check (loopback.go:71) and accepts an answer that dropped iss.
func TestSecAuditLoopbackIgnoresIssParamSupported(t *testing.T) {
	idp := newTestIdP(t)
	idp.public = true
	idp.issParam = true
	p, err := Discover(context.Background(), nil, idp.issuer)
	if err != nil || !p.IssParamSupported {
		t.Fatalf("setup: %v %v", err, p)
	}
	open := browser(t, func(cb *url.URL) {
		q := cb.Query()
		q.Del("iss")
		cb.RawQuery = q.Encode()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, _, err := Loopback(ctx, p, Config{ClientID: idp.clientID}, open, nil); err == nil {
		t.Error("an authorization response without iss was accepted from a provider that promises one")
	}
}
