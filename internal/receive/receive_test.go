// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package receive

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/replay"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

type fixture struct {
	t        *testing.T
	r        *Receiver
	cfg      Config
	pool     *prekey.Pool
	table    *replay.Table
	rootPub  ed25519.PublicKey
	rootPriv ed25519.PrivateKey
	senderSk ed25519.PrivateKey
	bind     *binding.Signed
	mu       sync.Mutex
	now      time.Time
}

func (f *fixture) clock() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func gen(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newFixture(t *testing.T, mod func(*Config)) *fixture {
	t.Helper()
	f := &fixture{t: t, now: t0}
	f.rootPub, f.rootPriv = gen(t)
	var spub ed25519.PublicKey
	spub, f.senderSk = gen(t)
	var err error
	f.bind, err = binding.Sign(f.rootPriv, binding.Binding{Tenant: "t1", Owner: "alice@example.com",
		DeviceID: "dev-a", SigningKey: spub, Version: 3, NotAfter: t0.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	_, tpriv := gen(t)
	f.pool, err = prekey.New(prekey.Config{Tenant: "t1", DeviceID: "dev-b", SigningKeyID: "k-b", BindingVersion: 1,
		Signer: tpriv, AllowUnlocked: true, SweepEvery: time.Hour, Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.pool.Close)
	f.table = replay.New(replay.Config{Now: f.clock})
	tr, err := binding.NewTracker(f.rootPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = Config{Tenant: "t1", Device: "dev-b", Pool: f.pool, Replay: f.table, Bindings: tr,
		Lookup:  func(string) (*binding.Signed, error) { return f.bind, nil },
		Revoked: func(string) bool { return false },
		Allow:   func(o string) bool { return o == "alice@example.com" },
		Now:     f.clock}
	if mod != nil {
		mod(&f.cfg)
	}
	f.r = f.build(f.cfg)
	return f
}

func (f *fixture) build(cfg Config) *Receiver {
	f.t.Helper()
	r, err := New(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// seal issues a prekey and seals a TASK to it.
func (f *fixture) seal(mod func(*envelope.Header)) (*envelope.Message, *prekey.Signed) {
	f.t.Helper()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	sp, err := f.pool.Issue(prekey.Request{Caller: "dev-a", Nonce: nonce, TaskExpiry: t0.Add(15 * time.Minute)})
	if err != nil {
		f.t.Fatal(err)
	}
	h := envelope.Header{Tenant: "t1", SenderDevice: "dev-a", SenderKeyID: "k-a", BindingVersion: 3,
		TargetDevice: "dev-b", PrekeyID: PrekeyID(sp.ID), ContextID: "ctx", Type: envelope.TypeTask,
		IssuedAt: t0, Expiry: t0.Add(15 * time.Minute), RPK: bytes.Repeat([]byte{7}, 32), Prekey: sp.Encode()}
	rand.Read(h.TaskID[:])
	if mod != nil {
		mod(&h)
	}
	m, err := envelope.Seal(f.senderSk, sp.PublicKey, h, []byte("secret task"))
	if err != nil {
		f.t.Fatal(err)
	}
	return m, sp
}

type run struct {
	events []string
	got    Delivered
	plain  []byte // the slice execute saw, to check it is zeroed afterwards
}

func (f *fixture) receive(m *envelope.Message, ackErr, execErr error) (*run, error) {
	ru := &run{}
	err := f.r.Receive(m,
		func() error {
			ru.events = append(ru.events, "ack")
			return ackErr
		},
		func(d Delivered) error {
			ru.events = append(ru.events, "exec")
			ru.got = d
			ru.got.Plaintext = bytes.Clone(d.Plaintext)
			ru.plain = d.Plaintext
			return execErr
		})
	return ru, err
}

func (f *fixture) intact() bool { return f.pool.Outstanding() == 1 }

func TestOrderOpenVerifyEraseAckExecute(t *testing.T) {
	f := newFixture(t, nil)
	m, sp := f.seal(nil)
	var erasedAtAck bool
	var plain []byte
	err := f.r.Receive(m,
		func() error {
			// Erased before the acknowledgment: the id is already spent.
			erasedAtAck = errors.Is(f.pool.Consume(sp.ID), prekey.ErrConsumed)
			return nil
		},
		func(d Delivered) error {
			if !erasedAtAck {
				t.Error("execute ran before the key was erased and acknowledged")
			}
			if d.Owner != "alice@example.com" || string(d.Plaintext) != "secret task" || d.Header.TaskID != m.Header.TaskID {
				t.Errorf("delivered %+v", d)
			}
			plain = d.Plaintext
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if !erasedAtAck {
		t.Fatal("key was not erased when ack ran")
	}
	if !bytes.Equal(plain, make([]byte, len(plain))) {
		t.Fatal("plaintext not zeroed after execute")
	}
}

func TestExecuteErrorPropagates(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	boom := errors.New("boom")
	ru, err := f.receive(m, nil, boom)
	if !errors.Is(err, boom) || len(ru.events) != 2 {
		t.Fatalf("%v %v", err, ru.events)
	}
}

func TestAckFailureSkipsExecuteAndKeyStaysErased(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	ru, err := f.receive(m, errors.New("socket closed"), nil)
	if !errors.Is(err, ErrAck) || len(ru.events) != 1 {
		t.Fatalf("%v %v", err, ru.events)
	}
	if f.pool.Outstanding() != 0 {
		t.Fatal("key survived")
	}
	// A resend of the same frame is dropped, not executed.
	if ru, err = f.receive(m, nil, nil); !errors.Is(err, ErrDropped) || len(ru.events) != 0 {
		t.Fatalf("redelivery: %v %v", err, ru.events)
	}
}

// Nothing ran, so the caller's resend (same task and sequence, fresh prekey)
// must not be dropped by our own replay entry.
func TestResendAfterAckFailureExecutes(t *testing.T) {
	f := newFixture(t, nil)
	var task [16]byte
	rand.Read(task[:])
	fix := func(h *envelope.Header) { h.TaskID = task }
	m, _ := f.seal(fix)
	if _, err := f.receive(m, errors.New("socket closed"), nil); !errors.Is(err, ErrAck) {
		t.Fatal(err)
	}
	m, _ = f.seal(fix)
	if ru, err := f.receive(m, nil, nil); err != nil || len(ru.events) != 2 {
		t.Fatalf("resend: %v %v", err, ru.events)
	}
}

func TestRedeliveryDropped(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	if _, err := f.receive(m, nil, nil); err != nil {
		t.Fatal(err)
	}
	ru, err := f.receive(m, nil, nil)
	if !errors.Is(err, ErrDropped) || !errors.Is(err, replay.ErrReplay) || len(ru.events) != 0 {
		t.Fatalf("%v %v", err, ru.events)
	}
}

func TestHeaderChecksBeforeAnyKeyUse(t *testing.T) {
	f := newFixture(t, nil)
	cases := map[string]struct {
		mod  func(*envelope.Header)
		want error
	}{
		"tenant":    {func(h *envelope.Header) { h.Tenant = "other" }, ErrNotForUs},
		"target":    {func(h *envelope.Header) { h.TargetDevice = "dev-z" }, ErrNotForUs},
		"prekey id": {func(h *envelope.Header) { h.PrekeyID = "nothex" }, ErrNotForUs},
		"short id":  {func(h *envelope.Header) { h.PrekeyID = "abcd" }, ErrNotForUs},
		"at expiry": {func(h *envelope.Header) { h.IssuedAt, h.Expiry = t0.Add(-time.Hour), t0 }, ErrExpired},
		"expired":   {func(h *envelope.Header) { h.IssuedAt, h.Expiry = t0.Add(-time.Hour), t0.Add(-time.Minute) }, ErrExpired},
		"future":    {func(h *envelope.Header) { h.IssuedAt = t0.Add(time.Hour); h.Expiry = t0.Add(2 * time.Hour) }, ErrExpired},
	}
	for name, c := range cases {
		m, sp := f.seal(c.mod)
		ru, err := f.receive(m, nil, nil)
		if !errors.Is(err, c.want) || len(ru.events) != 0 {
			t.Errorf("%s: %v %v", name, err, ru.events)
		}
		if !f.intact() {
			t.Errorf("%s: key burned", name)
		}
		f.pool.Consume(sp.ID)
	}
}

func TestJunkCannotBurnKey(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	junk := *m
	junk.Ciphertext = bytes.Clone(m.Ciphertext)
	junk.Ciphertext[0] ^= 1
	// Unauthenticated ciphertext is refused before it is opened or recorded.
	if _, err := f.receive(&junk, nil, nil); !errors.Is(err, ErrRejected) || !errors.Is(err, envelope.ErrBadSignature) ||
		!f.intact() || f.table.Len() != 0 {
		t.Fatalf("%v intact=%v", err, f.intact())
	}
	bad := *m
	bad.Header.Type = 0 // fails header validation
	if _, err := f.receive(&bad, nil, nil); !errors.Is(err, ErrRejected) || !errors.Is(err, envelope.ErrInvalid) ||
		!f.intact() || f.table.Len() != 0 {
		t.Fatalf("%v intact=%v", err, f.intact())
	}
	// Even a correctly signed frame that does not decrypt leaves the key and
	// the replay table as they were.
	signed := *m
	signed.Ciphertext = bytes.Clone(m.Ciphertext)
	signed.Ciphertext[0] ^= 1
	signed.Signature = ed25519.Sign(f.senderSk, signed.Transcript())
	if _, err := f.receive(&signed, nil, nil); !errors.Is(err, envelope.ErrOpen) || !f.intact() || f.table.Len() != 0 {
		t.Fatalf("%v intact=%v len=%d", err, f.intact(), f.table.Len())
	}
	if _, err := f.receive(m, nil, nil); err != nil {
		t.Fatal("legitimate frame after junk:", err)
	}
}

func TestUnknownAndClosedAndExpiredPrekey(t *testing.T) {
	f := newFixture(t, nil)
	m, sp := f.seal(func(h *envelope.Header) { h.PrekeyID = PrekeyID([16]byte{1}) })
	if _, err := f.receive(m, nil, nil); !errors.Is(err, ErrDropped) || !errors.Is(err, prekey.ErrUnknown) || f.table.Len() != 0 {
		t.Fatal(err)
	}
	f.pool.Consume(sp.ID)

	// The message outlives its prekey: refused, and the key is zeroed.
	f = newFixture(t, nil)
	nonce := []byte("n")
	sp, err := f.pool.Issue(prekey.Request{Caller: "dev-a", Nonce: nonce, TaskExpiry: t0.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	h := envelope.Header{Tenant: "t1", SenderDevice: "dev-a", SenderKeyID: "k-a", BindingVersion: 3,
		TargetDevice: "dev-b", PrekeyID: PrekeyID(sp.ID), ContextID: "c", Type: envelope.TypeTask,
		IssuedAt: t0, Expiry: t0.Add(time.Hour), RPK: bytes.Repeat([]byte{7}, 32), Prekey: sp.Encode()}
	m, err = envelope.Seal(f.senderSk, sp.PublicKey, h, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	f.advance(10 * time.Minute)
	if _, err := f.receive(m, nil, nil); !errors.Is(err, ErrExpired) || !errors.Is(err, prekey.ErrExpired) {
		t.Fatal(err)
	}

	f = newFixture(t, nil)
	m, _ = f.seal(nil)
	f.pool.Close()
	if _, err := f.receive(m, nil, nil); !errors.Is(err, ErrDropped) || !errors.Is(err, prekey.ErrClosed) {
		t.Fatal(err)
	}
}

func TestSenderRejectedKeepsKey(t *testing.T) {
	_, otherRootPriv := gen(t)
	otherSignerPub, otherSigner := gen(t)
	wrongRoot, _ := binding.Sign(otherRootPriv, f0Binding(otherSignerPub, 3))
	cases := map[string]struct {
		mod func(*Config, *fixture)
		hdr func(*envelope.Header)
		key ed25519.PrivateKey // sign with a key that is not in the binding
	}{
		"self":    {hdr: func(h *envelope.Header) { h.SenderDevice = "dev-b" }},
		"revoked": {mod: func(c *Config, _ *fixture) { c.Revoked = func(string) bool { return true } }},
		"no lookup": {mod: func(c *Config, _ *fixture) {
			c.Lookup = func(string) (*binding.Signed, error) { return nil, errors.New("404") }
		}},
		"nil": {mod: func(c *Config, _ *fixture) { c.Lookup = func(string) (*binding.Signed, error) { return nil, nil } }},
		"tenant": {mod: func(c *Config, f *fixture) {
			b := f0Binding(f.bind.SigningKey, 3)
			b.Tenant = "t2"
			f.bind, _ = binding.Sign(f.rootPriv, b)
		}},
		"device": {mod: func(c *Config, f *fixture) {
			b := f0Binding(f.bind.SigningKey, 3)
			b.DeviceID = "dev-x"
			f.bind, _ = binding.Sign(f.rootPriv, b)
		}},
		"version":     {hdr: func(h *envelope.Header) { h.BindingVersion = 2 }},
		"wrong root":  {mod: func(c *Config, f *fixture) { f.bind = wrongRoot }},
		"not allowed": {mod: func(c *Config, _ *fixture) { c.Allow = func(string) bool { return false } }},
		"bad sig":     {key: otherSigner},
	}
	for name, c := range cases {
		f := newFixture(t, nil)
		if c.mod != nil {
			// The default Lookup closes over f.bind, so mods may replace either.
			c.mod(&f.cfg, f)
			f.r = f.build(f.cfg)
		}
		if c.key != nil {
			f.senderSk = c.key
		}
		m, _ := f.seal(c.hdr)
		ru, err := f.receive(m, nil, nil)
		if !errors.Is(err, ErrRejected) || len(ru.events) != 0 {
			t.Errorf("%s: %v %v", name, err, ru.events)
		}
		if !f.intact() || f.table.Len() != 0 {
			t.Errorf("%s: key burned or replay entry kept for a rejected sender", name)
		}
	}
}

func f0Binding(key ed25519.PublicKey, v uint64) binding.Binding {
	return binding.Binding{Tenant: "t1", Owner: "alice@example.com", DeviceID: "dev-a",
		SigningKey: key, Version: v, NotAfter: t0.Add(24 * time.Hour)}
}

func TestBindingRollbackRejected(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	if _, err := f.receive(m, nil, nil); err != nil {
		t.Fatal(err)
	}
	old, _ := binding.Sign(f.rootPriv, f0Binding(f.bind.SigningKey, 2))
	f.bind = old
	m, _ = f.seal(func(h *envelope.Header) { h.BindingVersion = 2 })
	if _, err := f.receive(m, nil, nil); !errors.Is(err, ErrRejected) || !errors.Is(err, binding.ErrRollback) || !f.intact() {
		t.Fatal(err)
	}
}

func TestReplayTable(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	// Already accepted (for example by an earlier delivery whose prekey was
	// lost): dropped, key intact.
	f.table.Accept(replay.Key{Sender: "dev-a", Task: m.Header.TaskID, Seq: 0}, m.Header.Expiry)
	if _, err := f.receive(m, nil, nil); !errors.Is(err, ErrDropped) || !errors.Is(err, replay.ErrReplay) || !f.intact() {
		t.Fatal(err)
	}

	// Table full: fail closed, key intact.
	f = newFixture(t, nil)
	f.table = replay.New(replay.Config{MaxEntries: 1, Now: f.clock})
	f.table.Accept(replay.Key{Sender: "dev-q", Seq: 1}, t0.Add(time.Hour))
	cfg := f.cfg
	cfg.Replay = f.table
	f.r = f.build(cfg)
	m, _ = f.seal(nil)
	if _, err := f.receive(m, nil, nil); !errors.Is(err, ErrRejected) || !errors.Is(err, replay.ErrFull) || !f.intact() {
		t.Fatal(err)
	}
}

func TestConcurrentDuplicateWinsOnce(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	execs, drops := 0, 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := f.r.Receive(m, func() error { return nil }, func(Delivered) error {
				mu.Lock()
				execs++
				mu.Unlock()
				return nil
			})
			if errors.Is(err, ErrDropped) {
				mu.Lock()
				drops++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if execs != 1 || drops != 7 {
		t.Fatalf("execs=%d drops=%d", execs, drops)
	}
}

func TestLostRaceAtErase(t *testing.T) {
	var f *fixture
	var sp *prekey.Signed
	f = newFixture(t, func(c *Config) {
		// Another delivery consumes the key between open and erase.
		c.Fault = func(st Stage) error {
			if st == StageOpened {
				f.pool.Consume(sp.ID)
			}
			return nil
		}
	})
	var m *envelope.Message
	m, sp = f.seal(nil)
	ru, err := f.receive(m, nil, nil)
	if !errors.Is(err, ErrDropped) || !errors.Is(err, prekey.ErrConsumed) || len(ru.events) != 0 {
		t.Fatalf("%v %v", err, ru.events)
	}
	if f.table.Len() != 0 {
		t.Fatal("replay entry kept for a message that never ran")
	}
}

func TestNewDefaultsAndRequiredFields(t *testing.T) {
	f := newFixture(t, nil)
	if f.r.cfg.Skew != DefaultSkew {
		t.Fatal("skew default not applied")
	}
	c := f.cfg
	c.Now, c.Skew = nil, 0
	if r := f.build(c); r.cfg.Now == nil {
		t.Fatal("clock default not applied")
	}
	for name, mod := range map[string]func(*Config){
		"tenant": func(c *Config) { c.Tenant = "" }, "device": func(c *Config) { c.Device = "" },
		"pool": func(c *Config) { c.Pool = nil }, "replay": func(c *Config) { c.Replay = nil },
		"lookup": func(c *Config) { c.Lookup = nil }, "bindings": func(c *Config) { c.Bindings = nil },
		"revoked": func(c *Config) { c.Revoked = nil }, "allow": func(c *Config) { c.Allow = nil },
	} {
		c := f.cfg
		mod(&c)
		if r, err := New(c); r != nil || !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNilMessage(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.r.Receive(nil, nil, nil); !errors.Is(err, ErrNotForUs) {
		t.Fatal(err)
	}
}

// Every crash point: nothing executes, a key is erased exactly from the erase
// stage on, and the sender's resend with a fresh prekey runs.
func TestCrashPoints(t *testing.T) {
	stages := []struct {
		st     Stage
		erased bool
	}{
		{StageAuthenticated, false}, {StageRecorded, false}, {StageOpened, false},
		{StageErased, true}, {StageAcked, true},
	}
	for _, c := range stages {
		var inject Stage
		f := newFixture(t, func(cfg *Config) {
			cfg.Fault = func(st Stage) error {
				if st == inject {
					return errors.New("crash")
				}
				return nil
			}
		})
		var task [16]byte
		rand.Read(task[:])
		fix := func(h *envelope.Header) { h.TaskID = task }
		inject = c.st
		m, _ := f.seal(fix)
		ru, err := f.receive(m, nil, nil)
		wantEvents := 0
		if c.st == StageAcked {
			wantEvents = 1 // acknowledged, then died before execute
		}
		if !errors.Is(err, ErrFault) || len(ru.events) != wantEvents || ru.got.Plaintext != nil {
			t.Errorf("stage %d: %v %v", c.st, err, ru.events)
		}
		if got := f.pool.Outstanding() == 0; got != c.erased {
			t.Errorf("stage %d: erased=%v want %v", c.st, got, c.erased)
		}
		// The same frame is retried if the key survived, else it is dropped.
		inject = 0
		if !c.erased {
			if _, err := f.receive(m, nil, nil); err != nil {
				t.Errorf("stage %d: retry of same frame: %v", c.st, err)
			}
			continue
		}
		if _, err := f.receive(m, nil, nil); !errors.Is(err, ErrDropped) {
			t.Errorf("stage %d: redelivery %v", c.st, err)
		}
		m2, _ := f.seal(fix)
		if ru, err := f.receive(m2, nil, nil); err != nil || len(ru.events) != 2 {
			t.Errorf("stage %d: resend %v %v", c.st, err, ru.events)
		}
	}
}

func TestPanicsEraseAndZero(t *testing.T) {
	for _, where := range []string{"ack", "execute"} {
		f := newFixture(t, nil)
		m, _ := f.seal(nil)
		var plain []byte
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: panic swallowed", where)
				}
			}()
			f.r.Receive(m,
				func() error {
					if where == "ack" {
						panic("ack")
					}
					return nil
				},
				func(d Delivered) error { plain = d.Plaintext; panic("execute") })
		}()
		if f.pool.Outstanding() != 0 {
			t.Errorf("%s: key survived a panic", where)
		}
		if where == "execute" {
			if !bytes.Equal(plain, make([]byte, len(plain))) {
				t.Error("plaintext not zeroed after a panic")
			}
			// Execute may have run: the entry stays, a replay is dropped.
			if f.table.Len() != 1 {
				t.Error("replay entry forgotten after execute started")
			}
		} else if f.table.Len() != 0 {
			t.Error("replay entry kept though nothing ran")
		}
	}
}

// Execute failing keeps the replay entry: the task may have run.
func TestExecuteErrorKeepsReplayEntry(t *testing.T) {
	f := newFixture(t, nil)
	m, _ := f.seal(nil)
	f.receive(m, nil, errors.New("boom"))
	if f.table.Len() != 1 {
		t.Fatal("entry forgotten")
	}
}

// Prekeys and the replay table are memory only. A restarted receiver has an
// empty table and no keys, so a frame captured before the restart cannot be
// opened or executed, whether or not it ran before.
func TestRestartCannotOpenCapturedMessage(t *testing.T) {
	f := newFixture(t, nil)
	pending, _ := f.seal(nil) // captured, never delivered
	done, _ := f.seal(nil)    // captured after it ran
	if _, err := f.receive(done, nil, nil); err != nil {
		t.Fatal(err)
	}
	f.pool.Close() // restart: fresh pool (new random keys) and empty table
	_, tpriv := gen(t)
	pool, err := prekey.New(prekey.Config{Tenant: "t1", DeviceID: "dev-b", SigningKeyID: "k-b", BindingVersion: 1,
		Signer: tpriv, AllowUnlocked: true, SweepEvery: time.Hour, Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	cfg := f.cfg
	cfg.Pool, cfg.Replay = pool, replay.New(replay.Config{Now: f.clock})
	f.r = f.build(cfg)
	for name, m := range map[string]*envelope.Message{"pending": pending, "executed": done} {
		ru, err := f.receive(m, nil, nil)
		if !errors.Is(err, ErrDropped) || !errors.Is(err, prekey.ErrUnknown) || len(ru.events) != 0 {
			t.Errorf("%s: %v %v", name, err, ru.events)
		}
		if cfg.Replay.Len() != 0 {
			t.Errorf("%s: entry left behind", name)
		}
	}
}

// No error carries payload, identifiers, keys or the owner.
func TestErrorsCarryNoPayload(t *testing.T) {
	secrets := []string{"secret task", "alice@example.com", "dev-a", "dev-b", "t1", "ctx", "k-a"}
	check := func(what string, err error) {
		if err == nil {
			return
		}
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: %q leaks %q", what, err, s)
			}
		}
	}
	f := newFixture(t, nil)
	m, sp := f.seal(nil)
	bad := *m
	bad.Ciphertext = bytes.Clone(m.Ciphertext)
	bad.Ciphertext[0] ^= 1
	_, err := f.receive(&bad, nil, nil)
	check("bad sig", err)
	_, err = f.receive(m, errors.New("socket"), nil)
	check("ack", err)
	_, err = f.receive(m, nil, nil)
	check("redelivery", err)
	m2, _ := f.seal(func(h *envelope.Header) { h.Tenant = "t1x" })
	_, err = f.receive(m2, nil, nil)
	check("not for us", err)
	if strings.Contains(err.Error(), PrekeyID(sp.ID)) {
		t.Error("prekey id leaked")
	}
}
