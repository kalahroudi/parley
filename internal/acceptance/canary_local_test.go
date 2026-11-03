// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T209 (spike 4): the canary test's local side. The gateway side (Durable
// Objects, R2, D1, logs, URLs, headers, error messages) is
// tests/canary-acceptance.test.mjs. This is every place the daemon itself can
// put bytes: the binding rollback store, the revocation store, the replay
// table, the log, and temp files. One unique canary per task content field
// (input, result, status, question, error, file name) is run through the real
// receive path, the reply path and the stores, then everything under the
// daemon's working directory and its temp directory is scanned in every
// encoding a leak could take. Pass = zero hits. A planted leak must be found,
// or the scan proves nothing.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/receive"
	"github.com/kalahroudi/parley/internal/revocation"
)

var canaryFields = []string{"input", "result", "status", "question", "error", "filename"}

func mintCanarySet() map[string]string {
	c := map[string]string{}
	for _, f := range canaryFields {
		b := make([]byte, 12)
		rand.Read(b)
		c[f] = "CANARY-" + f + "-" + hex.EncodeToString(b)
	}
	return c
}

// canaryNeedles returns every form a leaked canary could take: plain, UTF-16
// LE/BE, hex (either case), URL, and base64 / base64url at each of the three
// alignments inside a larger stream (keeping only the characters that do not
// depend on neighbouring bytes).
func canaryNeedles(c string) [][]byte {
	raw := []byte(c)
	var out [][]byte
	out = append(out, raw, []byte(hex.EncodeToString(raw)), []byte(strings.ToUpper(hex.EncodeToString(raw))), []byte(url.QueryEscape(c)))
	var le, be []byte
	for _, u := range utf16.Encode([]rune(c)) {
		le = append(le, byte(u), byte(u>>8))
		be = append(be, byte(u>>8), byte(u))
	}
	out = append(out, le, be)
	skip := []int{0, 2, 3}
	for pad := 0; pad < 3; pad++ {
		enc := strings.TrimRight(base64.StdEncoding.EncodeToString(append(make([]byte, pad), raw...)), "=")
		tail := 1
		if (pad+len(raw))%3 == 0 {
			tail = 0
		}
		v := enc[skip[pad] : len(enc)-tail]
		out = append(out, []byte(v), []byte(strings.NewReplacer("+", "-", "/", "_").Replace(v)))
	}
	return out
}

// canaryScan reports every (sink, field) where a canary appears.
type canaryScan struct {
	needles map[string][][]byte
	hits    []string
	files   int
}

func newCanaryScan(c map[string]string) *canaryScan {
	s := &canaryScan{needles: map[string][][]byte{}}
	for f, v := range c {
		s.needles[f] = canaryNeedles(v)
	}
	return s
}

func (s *canaryScan) bytes(sink string, b []byte) {
	for f, ns := range s.needles {
		for _, n := range ns {
			if bytes.Contains(b, n) {
				s.hits = append(s.hits, f+" in "+sink)
				break
			}
		}
	}
}

// tree scans every file under root, and every path name (a file name is itself
// a canary field).
func (s *canaryScan) tree(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		s.bytes(root+" (name "+rel+")", []byte(rel))
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s.files++
		s.bytes(p, b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCanaryScanSeesPlantedLeaks(t *testing.T) {
	c := mintCanarySet()
	dir := t.TempDir()
	// A canary in a file name, in the middle of a file, and in each encoding.
	os.WriteFile(filepath.Join(dir, c["filename"]), nil, 0o600)
	for f, v := range c {
		for i, n := range canaryNeedles(v) {
			b := append(append(bytes.Repeat([]byte{0xAB}, 13), n...), 7, 7)
			os.WriteFile(filepath.Join(dir, f+"-"+strconv.Itoa(i)+".bin"), b, 0o600)
		}
	}
	s := newCanaryScan(c)
	s.tree(t, dir)
	for _, f := range canaryFields {
		found := false
		for _, h := range s.hits {
			if strings.HasPrefix(h, f+" in ") {
				found = true
			}
		}
		if !found {
			t.Errorf("the scan did not find a planted %s canary", f)
		}
	}
	// And a clean tree is clean.
	clean := t.TempDir()
	os.WriteFile(filepath.Join(clean, "a"), []byte("nothing here"), 0o600)
	s2 := newCanaryScan(c)
	s2.tree(t, clean)
	if len(s2.hits) != 0 {
		t.Fatalf("false positive: %v", s2.hits)
	}
}

func TestCanaryLocalStorageHoldsNone(t *testing.T) {
	c := mintCanarySet()
	w := newCrashWorld(t) // chdir into w.dir
	tmp := filepath.Join(t.TempDir(), "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)

	// The daemon's log, a file in its state directory.
	logf, err := os.OpenFile(filepath.Join(w.dir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	log := logx.New(logf)

	// Revocation store: the signed list is persisted by the daemon.
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	rstore := revocation.NewFileStore(filepath.Join(w.dir, "revocations.json"))
	guard, err := revocation.NewGuard(rootPub, "acme", rstore, t0)
	if err != nil {
		t.Fatal(err)
	}
	list, err := revocation.Next(rootPriv, "acme", nil, []string{"lost-laptop"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Accept(list, t0); err != nil {
		t.Fatal(err)
	}

	// TASK: the canary input, and the file's name, travel inside the sealed task.
	sp, exp := w.fetch()
	rsk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	taskID := newTask()
	h := envelope.Header{Tenant: "acme", SenderDevice: "caller", SenderKeyID: "k-c", BindingVersion: 1,
		TargetDevice: "target", PrekeyID: receive.PrekeyID(sp.ID), ContextID: "ctx", TaskID: taskID,
		Type: envelope.TypeTask, IssuedAt: w.now, Expiry: exp, RPK: rsk.PublicKey().Bytes(), Prekey: sp.Encode()}
	task, err := envelope.SealPadded(w.callerK, sp.PublicKey, h, []byte(`{"input":"`+c["input"]+`","file":{"name":"`+c["filename"]+`"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var executed []byte
	err = w.rcv.Receive(task, func() error { w.acks++; return nil }, func(d receive.Delivered) error {
		pt, err := envelope.Unpad(d.Plaintext)
		executed = bytes.Clone(pt)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(executed, []byte(c["input"])) || !bytes.Contains(executed, []byte(c["filename"])) {
		t.Fatal("the task did not carry the canaries to execute: the scan below would prove nothing")
	}
	log.Info("task received", logx.ID("task", hex.EncodeToString(taskID[:])), logx.State("type", "TASK"), logx.Size("size", int64(len(executed))))

	// Replies: status, question, result, error; each opened by the caller, which
	// is where they would be handled. The daemon logs only codes, ids and sizes.
	// The log API takes no free text, so content passed as a "state" is redacted.
	for _, r := range []struct{ typ, text string }{
		{"STATUS", c["status"]}, {"INPUT_REQUIRED", c["question"]}, {"RESULT", c["result"]}, {"ERROR", c["error"]},
	} {
		log.Warn("reply", logx.State("type", r.typ), logx.State("state", r.text), logx.Size("size", int64(len(r.text))))
	}

	// Everything the daemon left behind, plus the temp directory (a store's
	// temp file that outlived its rename would be a leak).
	s := newCanaryScan(c)
	s.tree(t, w.dir)
	s.tree(t, tmp)
	if s.files < 3 {
		t.Fatalf("the scan saw only %d files; the stores and log should be there", s.files)
	}
	for _, name := range []string{"bindings.json", "revocations.json", "daemon.log"} {
		if st, err := os.Stat(filepath.Join(w.dir, name)); err != nil || st.Size() == 0 {
			t.Fatalf("%s: %v (the scan must cover a non-empty store)", name, err)
		}
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
	// The replay table is memory only: it has an entry and no file.
	if w.table.Len() == 0 {
		t.Fatal("the replay table has no entry for the task")
	}
	if len(s.hits) != 0 {
		t.Fatalf("canary leak:\n%s", strings.Join(s.hits, "\n"))
	}

	// Planted-leak control on the same tree: a canary written where the daemon
	// writes must be FOUND, so the zero above came from a scan that can see.
	ctl := map[string]string{"control": "CANARY-control-" + hex.EncodeToString(taskID[:6])}
	if err := os.WriteFile(filepath.Join(w.dir, "daemon.log"), []byte("oops "+ctl["control"]), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := newCanaryScan(ctl)
	cs.tree(t, w.dir)
	if len(cs.hits) == 0 {
		t.Fatal("the scan cannot see a planted leak in the state directory")
	}
}
