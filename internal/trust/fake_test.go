// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGateway mirrors the gateway's enrollment, binding and revocation routes
// closely enough to run the same scenario offline. The real Worker runs the
// scenario too (PARLEY_TEST_GATEWAY_HTTP, see tests/trust.test.mjs), which keeps
// this fake honest.
type fakeGateway struct {
	mu    sync.Mutex
	enr   map[string]map[string]any
	polls map[string]string
	list  map[string]any
	n     int
}

func newFake(t *testing.T, tenant string) string {
	f := &fakeGateway{enr: map[string]map[string]any{}, polls: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(w, r, tenant) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakeGateway) serve(w http.ResponseWriter, r *http.Request, tenant string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b map[string]any
	_ = json.NewDecoder(r.Body).Decode(&b)
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	auth := r.Header.Get("Authorization")
	admin := strings.HasPrefix(auth, "Bearer fake-admin:"+tenant+":")
	switch r.URL.Path {
	case "/v1/enroll/request":
		email, ok := strings.CutPrefix(auth, "Bearer fake-user:"+tenant+":")
		if !ok {
			reply(401, nil)
			return
		}
		f.n++
		id := hex.EncodeToString([]byte{byte(f.n), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
		sum := sha256.Sum256([]byte(b["signing_key"].(string)))
		f.enr[id] = map[string]any{"id": id, "owner": email, "name": b["name"], "signing_key": b["signing_key"], "fingerprint": hex.EncodeToString(sum[:]), "status": "pending"}
		f.polls[id] = "poll" + id
		reply(202, map[string]any{"id": id, "poll": f.polls[id]})
	case "/v1/enroll/status":
		e := f.enr[b["id"].(string)]
		if e == nil || f.polls[e["id"].(string)] != b["poll"] {
			reply(404, nil)
			return
		}
		reply(200, map[string]any{"status": e["status"], "fingerprint": e["fingerprint"], "binding": e["binding"]})
	case "/v1/revocations":
		if f.list == nil {
			reply(404, nil)
			return
		}
		reply(200, f.list)
	default:
		if !admin {
			reply(401, nil)
			return
		}
		f.admin(r.URL.Path, b, reply)
	}
}

func (f *fakeGateway) admin(path string, b map[string]any, reply func(int, any)) {
	switch path {
	case "/v1/admin/enrollments":
		var out []map[string]any
		for _, e := range f.enr {
			if e["status"] == "pending" {
				out = append(out, e)
			}
		}
		reply(200, map[string]any{"pending": out})
	case "/v1/admin/enrollments/decide":
		e := f.enr[b["id"].(string)]
		if e == nil {
			reply(404, nil)
		} else if e["status"] != "pending" && e["status"] != b["decision"] {
			reply(409, nil)
		} else {
			e["status"] = b["decision"]
			reply(200, e)
		}
	case "/v1/admin/bindings":
		e, nb := f.enr[b["id"].(string)], b["binding"].(map[string]any)
		if e == nil {
			reply(404, nil)
			return
		}
		if old, ok := e["binding"].(map[string]any); e["status"] != "approved" || nb["signing_key"] != e["signing_key"] ||
			(ok && (nb["version"].(float64) < old["version"].(float64) || (nb["version"] == old["version"] && !same(nb, old)))) {
			reply(409, nil)
			return
		}
		e["binding"] = nb
		reply(200, map[string]any{"ok": true})
	case "/v1/admin/revocations":
		l := b["list"].(map[string]any)
		if f.list != nil && (l["version"].(float64) < f.list["version"].(float64) || (l["version"] == f.list["version"] && !same(l, f.list))) {
			reply(409, nil)
			return
		}
		f.list = l
		reply(200, map[string]any{"ok": true})
	}
}

func same(a, b map[string]any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func jsonOf(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
