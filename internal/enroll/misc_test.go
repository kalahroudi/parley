// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/daemon"
)

func TestEnrollDefaultsNeedNoHooks(t *testing.T) {
	e := newEnv(t)
	o := e.opts
	o.Progress, o.Log, o.Rand, o.Now, o.Poll = nil, nil, nil, nil, 0
	if _, err := Enroll(bg, o); err != nil {
		t.Fatal(err)
	}
}

// A state save that fails at each step ends the run there with the earlier state intact (nothing half-written),
// and the next run finishes with one key and one request.
func TestAFailedStateSaveStopsTheRunAtThatStepAndTheNextRunFinishes(t *testing.T) {
	order := []string{PhasePinned, PhaseKeyed, PhaseRequesting, PhaseRequested, PhaseApproved, PhaseBound}
	for i, phase := range order {
		t.Run(phase, func(t *testing.T) {
			e := newEnv(t)
			boom := errors.New("disk full")
			e.opts.beforeSave = func(p string) error {
				if p == phase {
					return boom
				}
				return nil
			}
			if _, err := Enroll(bg, e.opts); !errors.Is(err, boom) {
				t.Fatalf("got %v", err)
			}
			want := "none:" + os.ErrNotExist.Error()
			if i > 0 {
				want = order[i-1]
			}
			if got := e.phase(); i > 0 && got != want || i == 0 && !strings.HasPrefix(got, "none:") {
				t.Fatalf("phase %q, want %q", got, want)
			}
			if i == 0 {
				e.opts.beforeSave = nil
				_, err := Enroll(bg, e.opts)
				if err != nil || e.gw.distinct() != 1 {
					t.Fatalf("%v requests=%d", err, e.gw.distinct())
				}
				return
			}
			o := e.resume()
			if _, err := Enroll(bg, o); err != nil {
				t.Fatal(err)
			}
			if e.keys.saves != 1 || e.gw.distinct() != 1 || e.phase() != PhaseBound {
				t.Errorf("saves=%d requests=%d phase=%s", e.keys.saves, e.gw.distinct(), e.phase())
			}
		})
	}
	t.Run("clearing the session fails", func(t *testing.T) {
		e := newEnv(t)
		e.sess.clearErr = errors.New("keychain locked")
		if _, err := Enroll(bg, e.opts); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(e.text(), "could not be removed") {
			t.Errorf("the user must be told: %q", e.text())
		}
	})
}

func TestStateSaveFailsOverADirectory(t *testing.T) {
	e := newEnv(t)
	st := &state{Format: 1, Phase: PhasePinned, Gateway: e.gw.srv.URL, Tenant: "acme", RootPublicKey: e.gw.rootPub, Name: "n", KeyStore: daemon.KeyStoreFile, KeyAccount: "k-1"}
	if err := os.MkdirAll(filepath.Join(e.path(stateFile), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.save(e.dirs.State); err == nil {
		t.Error("saved over a directory")
	}
}

func TestValidName(t *testing.T) {
	ok := []string{"laptop", "Ana's MacBook Pro", "日本語のノート", strings.Repeat("n", 100), strings.Repeat("😀", 50), "a  b"}
	bad := map[string]string{
		"empty": "", "leading space": " a", "trailing space": "a ", "tab": "a\tb", "newline": "a\nb", "nul": "a\x00b", "escape": "a\x1bb",
		"zero width": "a​b", "bidi override": "a‮b", "line sep": "a b", "para sep": "a b", "private use": "ab",
		"nbsp": "a b", "invalid utf8": "a\xffb", "too long": strings.Repeat("n", 101), "emoji too long": strings.Repeat("😀", 51),
	}
	for _, s := range ok {
		if err := ValidName(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	for name, s := range bad {
		if err := ValidName(s); !errors.Is(err, ErrBadName) {
			t.Errorf("%s: %q accepted", name, s)
		}
	}
}

type fakeKR struct {
	m              map[string]string
	getErr, setErr error
	delErr         error
}

func (k *fakeKR) Get(s, u string) (string, error) {
	if k.getErr != nil {
		return "", k.getErr
	}
	v, ok := k.m[s+"/"+u]
	if !ok {
		return "", ErrKeyringNotFound
	}
	return v, nil
}
func (k *fakeKR) Set(s, u, v string) error {
	if k.setErr != nil {
		return k.setErr
	}
	k.m[s+"/"+u] = v
	return nil
}
func (k *fakeKR) Delete(s, u string) error {
	if k.delErr != nil {
		return k.delErr
	}
	if _, ok := k.m[s+"/"+u]; !ok {
		return ErrKeyringNotFound
	}
	delete(k.m, s+"/"+u)
	return nil
}

func TestKeyringSessions(t *testing.T) {
	kr := &fakeKR{m: map[string]string{}}
	s := KeyringSessions{KR: kr}
	good := "ps_acme." + strings.Repeat("0", 64)
	if _, err := s.Load("acme"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("empty: %v", err)
	}
	if err := s.Save("acme", good); err != nil {
		t.Fatal(err)
	}
	if kr.m[SessionService+"/acme"] != good {
		t.Error("filed under the wrong entry")
	}
	if got, err := s.Load("acme"); err != nil || got != good {
		t.Fatalf("%q %v", got, err)
	}
	// A token for another tenant, a short secret and junk are not stored or loaded.
	for _, tok := range []string{"ps_other." + strings.Repeat("0", 64), "ps_acme.abc", "", "ps_acme." + strings.Repeat("G", 64), "ps_acme." + strings.Repeat("0", 64) + "\n", "ps_.", "ps_acme.", good + "x"} {
		if err := s.Save("acme", tok); err == nil {
			t.Errorf("saved %q", tok)
		}
		kr.m[SessionService+"/acme"] = tok
		if _, err := s.Load("acme"); err == nil || errors.Is(err, ErrNoSession) {
			t.Errorf("loaded %q: %v", tok, err)
		}
	}
	kr.m[SessionService+"/acme"] = good
	if err := s.Clear("acme"); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear("acme"); err != nil {
		t.Errorf("clearing nothing: %v", err)
	}
	boom := errors.New("secret service says: " + good)
	kr.getErr, kr.setErr, kr.delErr = boom, boom, boom
	for name, err := range map[string]error{"load": func() error { _, e := s.Load("acme"); return e }(), "save": s.Save("acme", good), "clear": s.Clear("acme")} {
		if err == nil || strings.Contains(err.Error(), "secret service") {
			t.Errorf("%s: %v (the keychain's text must not be passed on)", name, err)
		}
	}
}

func TestBindingIsOnlyRecordedForTheCorrectRoot(t *testing.T) {
	// The tracker the enrollment uses is pinned to the state's root, so another root's binding never lands in the store.
	e := newEnv(t)
	e.gw.set(func(g *fakeGateway) {
		g.bind = func(id string, k []byte) *binding.Signed {
			_, rogue, _ := newKey()
			b, _ := binding.Sign(rogue, binding.Binding{Tenant: "acme", Owner: "a@b", DeviceID: id, SigningKey: k, Version: 1, NotAfter: time.Now().Add(time.Hour)})
			return b
		}
	})
	if _, err := Enroll(bg, e.opts); err == nil {
		t.Fatal("accepted")
	}
	tr, err := binding.NewTracker(e.gw.rootPub, binding.NewFileStore(e.path("bindings.json")))
	if err != nil {
		t.Fatal(err)
	}
	for id := range e.gw.snapshot() {
		if _, ok := tr.Version("acme", id); ok {
			t.Error("a binding from another root was recorded")
		}
	}
}
