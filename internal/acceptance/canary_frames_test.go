// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T209 (spike 4): the canary test's content side. tests/canary-acceptance.test.mjs
// mints one canary per task content field, runs this test to have the real
// daemon-side code seal a task and its replies with them, then sends every
// frame the gateway would carry through a real gateway and scans everything
// the gateway holds. This test only produces the frames (it is a no-op without
// PARLEY_CANARY_OUT) and checks, with the canaries as needles, that the wire
// bytes and the file blob do not contain them in the clear.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/receive"
)

type canaryFrame struct {
	Type string `json:"type"`
	Body string `json:"body"`           // base64 of the wire bytes
	Task string `json:"task,omitempty"` // the task id in hex, as the A2A task id
}

// canaryStep is one message of an A2A chain; the TASK is built from the first frame's header.
type canaryStep struct {
	kind string
	typ  envelope.Type
	from string
	to   string
	seq  uint64
	text string
}

type canaryBlob struct {
	Key  string `json:"key"`  // random object key, as R2 would hold it
	Data string `json:"data"` // base64 of the sealed file
}

func TestEmitCanaryFrames(t *testing.T) {
	out := os.Getenv("PARLEY_CANARY_OUT")
	if out == "" {
		t.Skip("driven by tests/canary-acceptance.test.mjs")
	}
	raw, err := os.ReadFile(os.Getenv("PARLEY_CANARY_IN"))
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]string
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"input", "result", "status", "question", "error", "filename"} {
		if c[f] == "" {
			t.Fatalf("no canary for %s", f)
		}
	}

	// The gateway names devices itself (enrollment ids), so the test names the caller and the target the way the
	// gateway will see them; alone, the readable names are used.
	caller, target := "caller", "target"
	if v := os.Getenv("PARLEY_CANARY_CALLER"); v != "" {
		caller = v
	}
	if v := os.Getenv("PARLEY_CANARY_TARGET"); v != "" {
		target = v
	}

	w := newCrashWorld(t)
	var frames []canaryFrame
	var needles [][]byte
	for _, v := range c {
		needles = append(needles, []byte(v))
	}
	add := func(kind string, m *envelope.Message) {
		wire := m.Marshal()
		for _, n := range needles {
			if bytes.Contains(wire, n) {
				t.Fatalf("%s frame holds a canary in the clear", kind)
			}
		}
		frames = append(frames, canaryFrame{kind, base64.StdEncoding.EncodeToString(wire), ""})
	}

	// The file: sealed under a random key, uploaded under a random object key.
	fkey, err := envelope.NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	sum, size, err := envelope.EncryptFile(fkey[:], bytes.NewReader([]byte("file body "+c["input"])), &blob)
	if err != nil {
		t.Fatal(err)
	}
	objKey := make([]byte, 16)
	rand.Read(objKey)
	blobs := []canaryBlob{{Key: base64.RawURLEncoding.EncodeToString(objKey), Data: base64.StdEncoding.EncodeToString(blob.Bytes())}}
	for _, n := range needles {
		if bytes.Contains(blob.Bytes(), n) {
			t.Fatal("file blob holds a canary in the clear")
		}
	}

	// TASK: input, the file's name, its key and hash travel inside inner.
	inner, _ := json.Marshal(map[string]any{"input": c["input"], "file": map[string]any{
		"name": c["filename"], "key": fkey[:], "sha256": sum[:], "size": size, "object": blobs[0].Key}})
	sp, exp := w.fetch()
	rsk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	taskID := newTask()
	h := envelope.Header{Tenant: "acme", SenderDevice: caller, SenderKeyID: "k-c", BindingVersion: 1,
		TargetDevice: target, PrekeyID: receive.PrekeyID(sp.ID), ContextID: "ctx", TaskID: taskID,
		Type: envelope.TypeTask, IssuedAt: w.now, Expiry: exp, RPK: rsk.PublicKey().Bytes(), Prekey: sp.Encode()}
	task, err := envelope.SealPadded(w.callerK, sp.PublicKey, h, inner)
	if err != nil {
		t.Fatal(err)
	}
	add("TASK", task)

	// Replies from the target to the caller's reply key, chained by hash.
	prev := task.Header.Hash()
	for i, r := range []struct {
		kind string
		typ  envelope.Type
		text string
	}{
		{"STATUS", envelope.TypeStatus, c["status"]},
		{"INPUT_REQUIRED", envelope.TypeInputRequired, c["question"]},
		{"RESULT", envelope.TypeResult, c["result"]},
		{"ERROR", envelope.TypeError, c["error"]},
	} {
		rh := envelope.Header{Tenant: "acme", SenderDevice: target, SenderKeyID: "k-t", BindingVersion: 1,
			TargetDevice: caller, PrekeyID: "reply", ContextID: "ctx", TaskID: taskID, Seq: uint64(i + 1),
			Type: r.typ, IssuedAt: w.now, Expiry: exp, PrevHash: prev[:]}
		m, err := envelope.SealPadded(ed25519.PrivateKey(w.targetK), rsk.PublicKey().Bytes(), rh, []byte(r.text))
		if err != nil {
			t.Fatal(err)
		}
		add(r.kind, m)
		prev = m.Header.Hash()
	}

	// The A2A transport carries the same messages one task at a time, and the
	// caller's answer to the question (a REPLY), so each content field is sent
	// over POST /a2a too: a full chain, then tasks that end in ERROR and in a
	// refusal (also an ERROR on the wire).
	chains := [][]canaryFrame{{}, {}, {}, {}}
	chain := func(i int, taskID [16]byte, steps []canaryStep) {
		var prev [envelope.HashSize]byte
		for j, st := range steps {
			var m *envelope.Message
			if st.typ == envelope.TypeTask {
				th := h
				th.TaskID = taskID
				m, err = envelope.SealPadded(w.callerK, sp.PublicKey, th, inner)
			} else {
				hh := envelope.Header{Tenant: "acme", SenderDevice: st.from, SenderKeyID: "k-" + st.from, BindingVersion: 1,
					TargetDevice: st.to, PrekeyID: "next", ContextID: "ctx", TaskID: taskID, Seq: st.seq,
					Type: st.typ, IssuedAt: w.now, Expiry: exp, PrevHash: prev[:]}
				key := w.callerK
				if st.from == target {
					key = ed25519.PrivateKey(w.targetK)
				}
				m, err = envelope.SealPadded(key, rsk.PublicKey().Bytes(), hh, []byte(st.text))
			}
			if err != nil {
				t.Fatalf("chain %d step %d: %v", i, j, err)
			}
			for _, n := range needles {
				if bytes.Contains(m.Marshal(), n) {
					t.Fatalf("chain %d step %d holds a canary in the clear", i, j)
				}
			}
			chains[i] = append(chains[i], canaryFrame{st.kind, base64.StdEncoding.EncodeToString(m.Marshal()), hex.EncodeToString(taskID[:])})
			prev = m.Header.Hash()
		}
	}
	chain(0, newTask(), []canaryStep{
		{kind: "TASK", typ: envelope.TypeTask},
		{"STATUS", envelope.TypeStatus, target, caller, 1, c["status"]},
		{"INPUT_REQUIRED", envelope.TypeInputRequired, target, caller, 2, c["question"]},
		{"REPLY", envelope.TypeReply, caller, target, 1, "the answer is " + c["input"]},
		{"RESULT", envelope.TypeResult, target, caller, 3, c["result"]},
	})
	chain(1, newTask(), []canaryStep{{kind: "TASK", typ: envelope.TypeTask}, {"ERROR", envelope.TypeError, target, caller, 1, c["error"]}})
	chain(2, newTask(), []canaryStep{{kind: "TASK", typ: envelope.TypeTask}, {"REJECTED", envelope.TypeError, target, caller, 1, c["error"]}})

	chain(3, newTask(), []canaryStep{{kind: "TASK", typ: envelope.TypeTask}, {"CANCEL", envelope.TypeCancel, caller, target, 1, ""}})

	b, _ := json.Marshal(map[string]any{"frames": frames, "blobs": blobs, "chains": chains})
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
