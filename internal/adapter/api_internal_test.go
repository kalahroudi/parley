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
	"time"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/pipeline"
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

// The dial of a plain-http bot service is refused unless the resolved address is loopback.
func TestLoopbackOnlyRefusesOtherAddresses(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:80": true, "[::1]:80": true, "10.0.0.5:80": false, "[2001:db8::1]:80": false,
		"localhost:80": false, "nonsense": false} {
		if err := loopbackOnly("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestAPIRefusesANilContext(t *testing.T) {
	a, err := NewAPI(APIConfig{URL: "https://example.com/bot"})
	if err != nil {
		t.Fatal(err)
	}
	var ctx context.Context // the request cannot be built without one
	if _, err := a.Handle(ctx, bot.Task{}, nil); err == nil {
		t.Fatal("no error")
	}
}

// Only plain http gets the loopback-only dial; https goes where its certificate says.
func TestDialerForRestrictsPlainHTTPOnly(t *testing.T) {
	if dialerFor("http").Control == nil || dialerFor("https").Control != nil {
		t.Fatal("the loopback-only dial belongs to http and only http")
	}
}

// The buffers the bot's output is read through have the size the line limit assumes.
func TestReadBuffersAreSixtyFourKilobytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"type":"question","content":"cQ=="}`+"\n")
	}))
	defer srv.Close()
	a, err := NewAPI(APIConfig{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	p := &apiPeer{a: a}
	if err := p.post(context.Background(), []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if p.r.Size() != 64<<10 || readBuffer != 64<<10 {
		t.Fatalf("buffer %d", p.r.Size())
	}
}

// The values that have no statement for mutation testing to cover.
func TestConstantsArePinned(t *testing.T) {
	if cancelTimeout != 2*time.Second || reapDelay != 2*time.Second || MaxStatuses != 1024 || MaxQuestions != 16 {
		t.Fatal("a limit changed")
	}
	if MaxACPIgnored != 4096 || MaxACPPermissions != 64 || MaxACPFile != 1<<20 || MaxACPStatus != 1024 || maxACPSession != 256 ||
		maxACPID != 64 || maxACPPath != 1024 || maxACPTitle != 256 || maxACPKind != 32 || cancelGrace != 250*time.Millisecond {
		t.Fatal("an ACP limit changed")
	}
	if pipeline.MaxContent != 522240 || MaxLine != 174081*4+4096 {
		t.Fatalf("MaxLine %d", MaxLine)
	}
}

// A request that could not even be built releases its line at once (the transport never had it).
func TestPostThatCannotBuildTheRequestReleasesItsLine(t *testing.T) {
	a, err := NewAPI(APIConfig{URL: "https://example.com/bot"})
	if err != nil {
		t.Fatal(err)
	}
	p := &apiPeer{a: a}
	var ctx context.Context
	if p.post(ctx, []byte("x\n")) == nil {
		t.Fatal("no error")
	}
	select {
	case <-p.scrub[0].done:
	default:
		t.Fatal("the line was not released")
	}
}
