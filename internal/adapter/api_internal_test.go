// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kalahroudi/parley/internal/bot"
)

func TestAPITransportSettings(t *testing.T) {
	a, err := NewAPI(APIConfig{URL: "https://example.com/bot"})
	if err != nil {
		t.Fatal(err)
	}
	tr := a.client.Transport.(*http.Transport)
	if tr.Proxy != nil || !tr.DisableKeepAlives || !tr.DisableCompression || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("transport %+v", tr)
	}
}

// https works and is verified: the test server's certificate is accepted only
// when its CA is trusted.
func TestAPIOverTLSVerifiesTheServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"type":"result","content":"b2s="}`+"\n")
	}))
	defer srv.Close()
	a, err := NewAPI(APIConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Handle(context.Background(), bot.Task{}, nil); err == nil {
		t.Fatal("an unknown certificate authority was accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	a.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	res, err := a.Handle(context.Background(), bot.Task{}, nil)
	if err != nil || string(res) != "ok" {
		t.Fatalf("%q %v", res, err)
	}
}
