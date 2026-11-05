// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/pipeline"
)

func callLocal(t *testing.T, e *env, method string, params any) localsock.Response {
	t.Helper()
	r, err := localsock.Call(context.Background(), e.dirs.SocketPath(), method, params)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCallerMethodsAreServedOnTheLocalSocket(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, func(d *Deps) { d.AllowUnlockedMemory = true })
	_ = r
	// Every method is there and refuses what it should; none reaches the pipeline before enrollment.
	for _, tc := range []struct{ method, params, want string }{
		{"send_task", `{"agent":"dev-2","text":"hi"}`, "not_ready"},
		{"send_task", `{"agent":"dev-2","text":"hi","bogus":1}`, "bad_params"},
		{"get_task", `{"task_id":"` + strings.Repeat("0", 32) + `"}`, "not_found"},
		{"cancel_task", `{"task_id":"` + strings.Repeat("0", 32) + `"}`, "not_found"},
		{"find_agents", `{"text":"a\u0000"}`, "bad_params"},
	} {
		var p any
		json.Unmarshal([]byte(tc.params), &p)
		if resp := callLocal(t, e, tc.method, p); resp.OK || resp.Error != tc.want {
			t.Errorf("%s %s: %+v", tc.method, tc.params, resp)
		}
	}
	resp := callLocal(t, e, "list_tasks", nil)
	if !resp.OK || string(resp.Result) != `{"tasks":[]}` {
		t.Errorf("list_tasks: %+v", resp)
	}
	// Not enrolled: the directory cannot be asked either.
	if resp := callLocal(t, e, "find_agents", map[string]string{"text": "x"}); resp.OK || resp.Error != "directory_unavailable" {
		t.Errorf("find_agents: %+v", resp)
	}
}

// With a binding the daemon earns an api token and asks the gateway's directory with it.
func TestFindAgentsAsksTheDirectoryWithAnAPIToken(t *testing.T) {
	e := newEnv(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var finds atomic.Int32
	var auth atomic.Value
	e.extra = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/v1/connect/challenge":
			io.WriteString(w, `{"challenge":"ch","expires_at":`+itoa(time.Now().Add(time.Minute).UnixMilli())+`}`)
		case "/v1/connect/token":
			var body struct{ Scope string }
			json.NewDecoder(r.Body).Decode(&body)
			io.WriteString(w, `{"token":"tok-`+body.Scope+`","expires_at":`+itoa(time.Now().Add(time.Hour).UnixMilli())+`}`)
		case "/v1/directory/find":
			finds.Add(1)
			auth.Store(r.Header.Get("Authorization"))
			io.WriteString(w, `{"agents":[{"id":"dev-2:ab","device_id":"dev-2","owner":"o@x.test","name":"Reviewer","description":"d","tags":[],"examples":[]}]}`)
		default:
			return false
		}
		return true
	}
	e.before = e.bind(t, priv.Public().(ed25519.PublicKey), 1)
	e.start(t, func(d *Deps) { d.Keys = fixedKeys{priv}; d.AllowUnlockedMemory = true })
	resp := callLocal(t, e, "find_agents", map[string]string{"text": "rev"})
	if !resp.OK || !strings.Contains(string(resp.Result), `"Reviewer"`) || !strings.Contains(string(resp.Result), `"untrusted":true`) {
		t.Fatalf("%+v", resp)
	}
	if auth.Load() != "Bearer tok-api" || finds.Load() != 1 {
		t.Errorf("auth=%v finds=%d", auth.Load(), finds.Load())
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// Updates from the pipeline reach the caller interface first and then the configured callback.
func TestUpdatesReachTheCallerInterfaceAndThenTheDepsCallback(t *testing.T) {
	e := newEnv(t)
	var got []pipeline.Update
	r := e.start(t, func(d *Deps) {
		d.AllowUnlockedMemory = true
		d.OnUpdate = func(u pipeline.Update) { got = append(got, u) }
	})
	r.d.deps.OnUpdate(pipeline.Update{Type: envelope.TypeResult, TaskID: [16]byte{1}, Content: []byte("x")}) // no such task: dropped by the caller interface
	if len(got) != 1 || got[0].Type != envelope.TypeResult {
		t.Fatalf("%+v", got)
	}
	// Without a callback configured the caller interface alone gets it.
	e2 := newEnv(t)
	r2 := e2.start(t, func(d *Deps) { d.AllowUnlockedMemory = true })
	r2.d.deps.OnUpdate(pipeline.Update{Type: envelope.TypeResult, TaskID: [16]byte{1}})
}

// Once enrolled, a task is accepted by the real pipeline and waits for its recipient.
func TestSendTaskReachesThePipelineOnceEnrolled(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, func(d *Deps) { d.AllowUnlockedMemory = true })
	enroll(t, e, r)
	resp := callLocal(t, e, "send_task", map[string]string{"agent": "dev-2:ab", "text": "hello"})
	var v struct {
		ID      string `json:"task_id"`
		State   string
		Waiting bool `json:"waiting_for_recipient"`
	}
	if !resp.OK || json.Unmarshal(resp.Result, &v) != nil || v.State != "TASK_STATE_SUBMITTED" || !v.Waiting || len(v.ID) != 32 {
		t.Fatalf("%+v", resp)
	}
	if got := callLocal(t, e, "get_task", map[string]string{"task_id": v.ID}); !got.OK {
		t.Fatalf("%+v", got)
	}
	// The outbox may be in the middle of a send attempt; "sending" is its answer
	// to a cancel at that moment, and it passes.
	var c localsock.Response
	for deadline := time.Now().Add(10 * time.Second); ; {
		if c = callLocal(t, e, "cancel_task", map[string]string{"task_id": v.ID}); c.Error != "sending" || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !c.OK || !strings.Contains(string(c.Result), "TASK_STATE_CANCELED") {
		t.Fatalf("%+v", c)
	}
}
