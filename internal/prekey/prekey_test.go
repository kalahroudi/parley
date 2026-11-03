// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	pool *Pool
	pub  ed25519.PublicKey
	mu   sync.Mutex
	now  time.Time
}

func (f *fixture) clock() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fixture) set(t time.Time)  { f.mu.Lock(); f.now = t; f.mu.Unlock() }

func newFixture(t testing.TB, mod func(*Config)) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{pub: pub, now: time.Unix(1_800_000_000, 0).UTC()}
	cfg := Config{Tenant: "t1", DeviceID: "dev-target", SigningKeyID: "k1", BindingVersion: 3,
		Signer: priv, SweepEvery: time.Hour, Now: f.clock}
	if mod != nil {
		mod(&cfg)
	}
	f.pool, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.pool.Close)
	return f
}

func req(caller string) Request {
	n := make([]byte, 16)
	rand.Read(n)
	return Request{Caller: caller, Nonce: n}
}

func (f *fixture) expect(r Request) Expect {
	return Expect{Tenant: "t1", DeviceID: "dev-target", SigningKeyID: "k1", Caller: r.Caller,
		Nonce: r.Nonce, BindingVersion: 3, Now: f.clock()}
}

// slotOf returns the slot index of a live id.
func (f *fixture) slotOf(id [idSize]byte) int {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return f.pool.live[id].index
}

// zeroed reports whether the slot's scalar is all zero.
func (f *fixture) zeroed(i int) bool {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return *f.pool.scalar(i) == [scalarSize]byte{}
}

func (f *fixture) tombstones() int {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return len(f.pool.spent)
}

func (f *fixture) freeSlots() int {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return len(f.pool.free)
}

func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func TestIssueVerifyAndAgreement(t *testing.T) {
	f := newFixture(t, nil)
	if !f.pool.Locked() {
		t.Fatal("key memory not locked on this OS")
	}
	r := req("dev-caller")
	s, err := f.pool.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(f.pub, s, f.expect(r)); err != nil {
		t.Fatal(err)
	}
	if got := s.ExpiresAt.Sub(s.CreatedAt); got != DefaultTTL {
		t.Fatalf("ttl %v", got)
	}
	// A sender who seals to the public half agrees with the stored scalar.
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pk, err := ecdh.X25519().NewPublicKey(s.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := eph.ECDH(pk)
	err = f.pool.With(s.ID, func(sc *[32]byte) error {
		priv, err := ecdh.X25519().NewPrivateKey(sc[:])
		if err != nil {
			return err
		}
		got, err := priv.ECDH(eph.PublicKey())
		if !bytes.Equal(got, want) {
			t.Error("shared secret differs")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFixture(t, nil)
	r := req("dev-caller")
	s, _ := f.pool.Issue(r)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	short := *s
	short.PublicKey = short.PublicKey[:31]

	cases := []struct {
		name string
		pub  ed25519.PublicKey
		s    *Signed
		mod  func(*Expect)
		want error
	}{
		{"wrong signer", otherPub, s, nil, ErrBadSig},
		{"bad key length", nil, s, nil, ErrBadSig},
		{"short public key", f.pub, &short, nil, ErrBadSig},
		{"nil prekey", f.pub, nil, nil, ErrBadSig},
		{"tenant", f.pub, s, func(e *Expect) { e.Tenant = "t2" }, ErrMismatch},
		{"target", f.pub, s, func(e *Expect) { e.DeviceID = "other" }, ErrMismatch},
		{"signing key id", f.pub, s, func(e *Expect) { e.SigningKeyID = "k2" }, ErrMismatch},
		{"caller", f.pub, s, func(e *Expect) { e.Caller = "other" }, ErrMismatch},
		{"nonce", f.pub, s, func(e *Expect) { e.Nonce = []byte("stale") }, ErrMismatch},
		{"binding version", f.pub, s, func(e *Expect) { e.BindingVersion = 2 }, ErrMismatch},
		{"created in the future", f.pub, s, func(e *Expect) { e.Now = f.clock().Add(-time.Hour) }, ErrMismatch},
		{"expired", f.pub, s, func(e *Expect) { e.Now = s.ExpiresAt }, ErrExpired},
	}
	for _, c := range cases {
		e := f.expect(r)
		if c.mod != nil {
			c.mod(&e)
		}
		if err := Verify(c.pub, c.s, e); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	// A custom skew widens the future-dated window.
	e := f.expect(r)
	e.Now = f.clock().Add(-time.Hour)
	e.Skew = 2 * time.Hour
	if err := Verify(f.pub, s, e); err != nil {
		t.Errorf("custom skew: %v", err)
	}

	// Tampering with any signed field breaks the signature.
	tam := *s
	tam.PublicKey = bytes.Clone(s.PublicKey)
	tam.PublicKey[0] ^= 1
	if err := Verify(f.pub, &tam, f.expect(r)); !errors.Is(err, ErrBadSig) {
		t.Errorf("tampered key: %v", err)
	}
	tam = *s
	tam.ExpiresAt = tam.ExpiresAt.Add(time.Hour)
	if err := Verify(f.pub, &tam, f.expect(r)); !errors.Is(err, ErrBadSig) {
		t.Errorf("tampered expiry: %v", err)
	}

	// A bad validity window is refused even when correctly signed.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, mod := range map[string]func(*Prekey){
		"empty window": func(p *Prekey) { p.ExpiresAt = p.CreatedAt },
		"over max ttl": func(p *Prekey) { p.ExpiresAt = p.CreatedAt.Add(MaxTTL + time.Second) },
	} {
		bad := s.Prekey
		mod(&bad)
		sb := &Signed{Prekey: bad, Signature: ed25519.Sign(priv, bad.Encode())}
		if err := Verify(pub, sb, f.expect(r)); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The scalar is zeroed in the locked region on Consume, and a second use or a
// redelivered frame for the same id fails.
func TestConsumeZeroesAndTombstones(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	idx := f.slotOf(s.ID)
	if f.zeroed(idx) {
		t.Fatal("scalar not stored")
	}
	if err := f.pool.With(s.ID, func(*[32]byte) error { return errors.New("junk frame") }); err == nil {
		t.Fatal("fn error lost")
	}
	if f.pool.Outstanding() != 1 || f.zeroed(idx) {
		t.Fatal("a failed open burned the key")
	}
	if err := f.pool.Consume(s.ID); err != nil {
		t.Fatal(err)
	}
	if !f.zeroed(idx) {
		t.Fatal("scalar not zeroed after Consume")
	}
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume: %v", err)
	}
	if err := f.pool.With(s.ID, func(*[32]byte) error { t.Fatal("fn ran"); return nil }); !errors.Is(err, ErrConsumed) {
		t.Fatalf("with after consume: %v", err)
	}
	if err := f.pool.With([16]byte{9}, nil); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	// The tombstone outlives reuse of the slot and goes away at expiry.
	s2, _ := f.pool.Issue(req("c"))
	if s2.ID == s.ID {
		t.Fatal("id reused")
	}
	f.set(s.ExpiresAt)
	f.pool.Sweep()
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrUnknown) {
		t.Fatalf("after tombstone expiry: %v", err)
	}
}

func TestExpiryZeroesAndRefuses(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	idx := f.slotOf(s.ID)
	f.set(s.ExpiresAt.Add(-time.Second))
	if err := f.pool.With(s.ID, func(*[32]byte) error { return nil }); err != nil {
		t.Fatalf("still valid: %v", err)
	}
	f.set(s.ExpiresAt)
	if err := f.pool.With(s.ID, func(*[32]byte) error { t.Fatal("fn ran"); return nil }); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if !f.zeroed(idx) {
		t.Fatal("expired scalar not zeroed")
	}
	if f.pool.Outstanding() != 0 || f.tombstones() != 0 {
		t.Fatal("expired key lingers")
	}
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrUnknown) {
		t.Fatalf("after expiry: %v", err)
	}

	// Consume of an expired key reports it, too; Sweep and Outstanding zero idle ones.
	a, _ := f.pool.Issue(req("c"))
	b, _ := f.pool.Issue(req("c"))
	c, _ := f.pool.Issue(req("c"))
	f.set(c.ExpiresAt)
	if err := f.pool.Consume(a.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("consume expired: %v", err)
	}
	ib := f.slotOf(b.ID)
	f.pool.Sweep()
	if !f.zeroed(ib) {
		t.Fatal("Sweep left an expired scalar")
	}
	d, _ := f.pool.Issue(req("c"))
	ic := f.slotOf(d.ID)
	f.set(d.ExpiresAt)
	if f.pool.Outstanding() != 0 || !f.zeroed(ic) {
		t.Fatal("Outstanding left an expired scalar")
	}
}

// Expired keys are wiped by the background sweeper even if nobody calls in.
func TestSweeperZeroesIdleKeys(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.SweepEvery = time.Millisecond })
	s, _ := f.pool.Issue(req("c"))
	idx := f.slotOf(s.ID)
	f.set(s.ExpiresAt)
	for i := 0; i < 5000 && !f.zeroed(idx); i++ {
		time.Sleep(time.Millisecond)
	}
	if !f.zeroed(idx) {
		t.Fatal("idle expired key not wiped")
	}
}

func TestTTLFromTaskExpiry(t *testing.T) {
	f := newFixture(t, nil)
	r := req("c")
	r.TaskExpiry = f.clock().Add(5 * time.Minute)
	s, _ := f.pool.Issue(r)
	if got := s.ExpiresAt.Sub(f.clock()); got != 5*time.Minute+DefaultSkew {
		t.Fatalf("got %v", got)
	}
	r.TaskExpiry = f.clock().Add(72 * time.Hour)
	s, _ = f.pool.Issue(r)
	if got := s.ExpiresAt.Sub(f.clock()); got != MaxTTL {
		t.Fatalf("not capped: %v", got)
	}
	r.TaskExpiry = f.clock()
	if _, err := f.pool.Issue(r); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("past expiry: %v", err)
	}
}

func TestIssueValidationAndLimits(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Capacity = 4; c.PerCaller = 2 })
	bad := []Request{
		{Nonce: []byte{1}},
		{Caller: "c"},
		{Caller: "c", Nonce: make([]byte, MaxNonce+1)},
		{Caller: string(make([]byte, MaxCaller+1)), Nonce: []byte{1}},
	}
	for i, r := range bad {
		if _, err := f.pool.Issue(r); !errors.Is(err, ErrBadRequest) {
			t.Fatalf("bad request %d: %v", i, err)
		}
	}
	if _, err := f.pool.Issue(Request{Caller: "c", Nonce: make([]byte, MaxNonce)}); err != nil {
		t.Fatalf("max nonce: %v", err)
	}
	f.pool.Consume(func() [16]byte { s, _ := f.pool.Issue(req("x")); return s.ID }())
	a, _ := f.pool.Issue(req("flood"))
	f.pool.Issue(req("flood"))
	if _, err := f.pool.Issue(req("flood")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("flood: %v", err)
	}
	// Another caller is unaffected until the pool itself is full.
	f.pool.Issue(req("b"))
	if _, err := f.pool.Issue(req("c")); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("full: %v", err)
	}
	// Using a key, or letting one expire, frees capacity.
	f.pool.Consume(a.ID)
	if _, err := f.pool.Issue(req("c")); err != nil {
		t.Fatal(err)
	}
	f.set(f.clock().Add(time.Hour))
	if f.pool.Outstanding() != 0 {
		t.Fatal("expired keys linger")
	}
	if _, err := f.pool.Issue(req("flood")); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// A hostile requester cannot hold more than its share, and junk lookups never
// burn or exhaust keys (T208).
func TestJunkCannotBurnKeys(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Capacity = 16; c.PerCaller = 4 })
	good, _ := f.pool.Issue(req("legit"))
	for i := 0; i < 100; i++ {
		f.pool.Issue(req("evil"))
	}
	if got := f.pool.Outstanding(); got != 5 {
		t.Fatalf("outstanding %d, hostile caller exceeded its share", got)
	}
	for i := 0; i < 2000; i++ {
		var id [16]byte
		rand.Read(id[:])
		if err := f.pool.With(id, func(*[32]byte) error { t.Fatal("ran"); return nil }); !errors.Is(err, ErrUnknown) {
			t.Fatal(err)
		}
		if err := f.pool.Consume(id); !errors.Is(err, ErrUnknown) {
			t.Fatal(err)
		}
		// A frame for the right id that fails to open leaves it intact.
		f.pool.With(good.ID, func(*[32]byte) error { return errors.New("bad tag") })
	}
	if f.pool.Outstanding() != 5 || f.freeSlots() != 11 {
		t.Fatal("junk changed the pool")
	}
	if err := f.pool.With(good.ID, func(*[32]byte) error { return nil }); err != nil {
		t.Fatalf("legit key burned: %v", err)
	}
}

func TestTombstonesAreBounded(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxTombstones = 3; c.PerCaller = 100 })
	var ids [][16]byte
	for i := 0; i < 10; i++ {
		s, _ := f.pool.Issue(req("c"))
		ids = append(ids, s.ID)
	}
	for _, id := range ids {
		f.pool.Consume(id)
		if f.tombstones() > 3 {
			t.Fatalf("tombstones %d", f.tombstones())
		}
	}
	// Whatever was forgotten still fails, as unknown or consumed.
	for _, id := range ids {
		if err := f.pool.Consume(id); !errors.Is(err, ErrConsumed) && !errors.Is(err, ErrUnknown) {
			t.Fatalf("reuse: %v", err)
		}
	}
}

func TestPruneSpentOncePerSecond(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	f.pool.Consume(s.ID)
	f.pool.Sweep() // prunes, arms the throttle
	f.set(s.ExpiresAt)
	f.pool.Sweep() // runs: the tombstone is dropped
	if f.tombstones() != 0 {
		t.Fatal("tombstone kept past expiry")
	}
	s2, _ := f.pool.Issue(req("c"))
	f.pool.Consume(s2.ID)
	f.set(s2.ExpiresAt)
	f.pool.Sweep()
	f.pool.Sweep() // within the same second: skipped
	if f.tombstones() != 0 {
		t.Fatal("tombstone kept past expiry")
	}
}

// Of any number of concurrent uses of one id, exactly one wins.
func TestSingleUseUnderConcurrency(t *testing.T) {
	f := newFixture(t, nil)
	for round := 0; round < 50; round++ {
		s, _ := f.pool.Issue(req("c"))
		var wins, consumed, opens atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if i%2 == 0 {
					f.pool.With(s.ID, func(*[32]byte) error { opens.Add(1); return nil })
				}
				switch err := f.pool.Consume(s.ID); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, ErrConsumed):
					consumed.Add(1)
				default:
					t.Errorf("consume: %v", err)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || consumed.Load() != 31 {
			t.Fatalf("round %d: %d winners, %d refused", round, wins.Load(), consumed.Load())
		}
		if opens.Load() > 16 {
			t.Fatalf("opened %d times", opens.Load())
		}
	}
	if f.pool.Outstanding() != 0 {
		t.Fatal("keys left")
	}
}

// Concurrent issuers cannot push the pool past its bounds.
func TestIssueUnderConcurrency(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Capacity = 32; c.PerCaller = 5 })
	var wg sync.WaitGroup
	var ok atomic.Int32
	for c := 0; c < 16; c++ {
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(c int) {
				defer wg.Done()
				if _, err := f.pool.Issue(req(string(rune('a' + c)))); err == nil {
					ok.Add(1)
				}
			}(c)
		}
	}
	wg.Wait()
	if ok.Load() != 32 || f.pool.Outstanding() != 32 {
		t.Fatalf("issued %d, outstanding %d", ok.Load(), f.pool.Outstanding())
	}
}

// A panic in the callback wipes the key, burns the id and leaves the pool usable.
func TestWithPanicZeroes(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	idx := f.slotOf(s.ID)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		f.pool.With(s.ID, func(*[32]byte) error { panic("boom") })
	}()
	if !f.zeroed(idx) {
		t.Fatal("scalar survived a panic")
	}
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrConsumed) {
		t.Fatalf("after panic: %v", err)
	}
	if _, err := f.pool.Issue(req("c")); err != nil {
		t.Fatalf("pool wedged: %v", err)
	}
}

// Every way Issue can fail or panic after writing the scalar wipes the slot.
func TestIssueFailuresWipe(t *testing.T) {
	fillErr := errors.New("rand")
	calls := func(failAt int) func([]byte) (int, error) {
		n := 0
		return func(b []byte) (int, error) {
			n++
			if n == failAt {
				return 0, fillErr
			}
			for i := range b {
				b[i] = 0xAA
			}
			return len(b), nil
		}
	}
	cases := []struct {
		name  string
		setup func(*testing.T)
		want  error
	}{
		{"scalar rand", func(t *testing.T) { swap(t, &randRead, calls(1)) }, fillErr},
		{"id rand", func(t *testing.T) { swap(t, &randRead, calls(2)) }, fillErr},
		{"derive", func(t *testing.T) {
			swap(t, &derivePublic, func([]byte) ([]byte, error) { return nil, errDerivation })
			swap(t, &randRead, calls(0))
		}, errDerivation},
		{"derive panic", func(t *testing.T) {
			swap(t, &derivePublic, func([]byte) ([]byte, error) { panic("boom") })
			swap(t, &randRead, calls(0))
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			c.setup(t)
			func() {
				defer func() { recover() }()
				if _, err := f.pool.Issue(req("c")); !errors.Is(err, c.want) || c.want == nil {
					t.Fatalf("got %v", err)
				}
			}()
			f.pool.mu.Lock()
			clean := bytes.Equal(f.pool.mem, make([]byte, len(f.pool.mem)))
			f.pool.mu.Unlock()
			if !clean || f.freeSlots() != DefaultCapacity || f.pool.Outstanding() != 0 {
				t.Fatal("failed Issue left key bytes or changed the pool")
			}
			// The pool still works once the fault is gone.
			randRead, derivePublic = rand.Read, x25519Public
			if _, err := f.pool.Issue(req("c")); err != nil {
				t.Fatalf("pool wedged: %v", err)
			}
		})
	}
}

func TestIDCollisionRetries(t *testing.T) {
	f := newFixture(t, nil)
	first, _ := f.pool.Issue(req("c"))
	spent, _ := f.pool.Issue(req("c"))
	f.pool.Consume(spent.ID)
	// Scalar draw, then the id repeats a live id, then a tombstoned one, then a fresh one.
	seq := [][]byte{nil, first.ID[:], spent.ID[:], bytes.Repeat([]byte{7}, idSize)}
	n := 0
	swap(t, &randRead, func(b []byte) (int, error) {
		src := seq[n]
		n++
		if src == nil {
			return rand.Read(b)
		}
		copy(b, src)
		return len(b), nil
	})
	s, err := f.pool.Issue(req("c"))
	if err != nil || n != 4 || s.ID != [16]byte(bytes.Repeat([]byte{7}, idSize)) {
		t.Fatalf("err %v draws %d id %x", err, n, s.ID)
	}
}

func TestNewConfig(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, cfg := range map[string]Config{
		"no signer":   {Tenant: "t", DeviceID: "d"},
		"no tenant":   {Signer: priv, DeviceID: "d"},
		"no device":   {Signer: priv, Tenant: "t"},
		"huge region": {Signer: priv, Tenant: "t", DeviceID: "d", Capacity: MaxCapacity + 1},
	} {
		if _, err := New(cfg); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p, err := New(Config{Signer: priv, Tenant: "t", DeviceID: "d"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if len(p.free) != DefaultCapacity || p.cfg.PerCaller != DefaultPerCaller ||
		p.cfg.MaxTombstones != DefaultTombstones || p.cfg.SweepEvery != DefaultSweep || p.cfg.Skew != DefaultSkew {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
}

func TestClose(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	f.pool.Close()
	f.pool.Close()
	f.pool.Sweep()
	if _, err := f.pool.Issue(req("c")); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := f.pool.With(s.ID, nil); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if f.pool.Outstanding() != 0 {
		t.Fatal("keys after close")
	}
}

// Keys are generated fresh each time, so two requests never share a key or id.
func TestKeysAreFresh(t *testing.T) {
	f := newFixture(t, nil)
	a, _ := f.pool.Issue(req("c"))
	b, _ := f.pool.Issue(req("c"))
	if a.ID == b.ID || bytes.Equal(a.PublicKey, b.PublicKey) {
		t.Fatal("reused key material")
	}
}

func TestX25519PublicRejectsBadScalar(t *testing.T) {
	if _, err := x25519Public(make([]byte, 31)); !errors.Is(err, errDerivation) {
		t.Fatal(err)
	}
}

func TestErrorsCarryNoKeyMaterial(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	var sc [32]byte
	f.pool.With(s.ID, func(p *[32]byte) error { sc = *p; return nil })
	f.pool.Consume(s.ID)
	err := f.pool.Consume(s.ID)
	if bytes.Contains([]byte(err.Error()), sc[:]) || bytes.Contains([]byte(err.Error()), s.ID[:]) {
		t.Fatal("error carries key or id bytes")
	}
}
