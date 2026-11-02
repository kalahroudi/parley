// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package receive

import (
	"bytes"
	"testing"

	"github.com/kalahroudi/parley/internal/envelope"
)

// FuzzReceive pushes hostile frames through Unmarshal and the whole receive
// path of a real receiver (real pool, replay table and binding tracker).
// Nothing may panic, and a frame that is not byte for byte the genuine one may
// not be acknowledged, executed, or cost a prekey.
//
// Two shapes of input. A raw frame exercises the parsers and rejection paths;
// the committed corpus (testdata/fuzz/FuzzReceive) holds only these, because a
// genuine frame is signed with keys made per run. A mutation is applied to a
// genuine frame issued fresh for that very input (so it cannot be rejected as
// a replay of an earlier one): one byte flipped, then a cut, then trailing
// bytes. That is what reaches the signature, binding and header checks.
func FuzzReceive(f *testing.F) {
	// The fixture is rebuilt inside the fuzz target, where *testing.F methods
	// (Helper, Cleanup) are forbidden; pools are closed by hand instead.
	q := quiet{f}
	fx := newFixture(q, nil)
	f.Cleanup(func() { fx.pool.Close() })
	fresh := func() *fixture {
		// A rejected frame keeps its prekey, so a long run would hit the
		// per-caller limit; start over well before that.
		if fx.pool.Outstanding() >= 6 {
			fx.pool.Close()
			fx = newFixture(q, nil)
		}
		return fx
	}
	genuine, _ := fx.seal(nil)
	raw := genuine.Marshal()
	f.Add([]byte{}, uint(0), byte(0), uint(0), uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 64), uint(0), byte(0), uint(0), uint8(0))
	for _, pos := range []uint{0, 5, uint(len(raw) / 2), uint(len(raw) - 70), uint(len(raw) - 1)} {
		f.Add([]byte{}, pos, byte(0x01), uint(0), uint8(1))
	}
	f.Add([]byte{}, uint(0), byte(0), uint(1), uint8(1))
	f.Add([]byte{}, uint(0), byte(0), uint(0), uint8(1))
	f.Fuzz(func(t *testing.T, junk []byte, pos uint, x byte, cut uint, mode uint8) {
		fx := fresh()
		frame := junk
		isGenuine := false
		if mode%2 == 1 {
			m, _ := fx.seal(nil)
			g := m.Marshal()
			frame = bytes.Clone(g)
			frame[pos%uint(len(frame))] ^= x
			frame = frame[:len(frame)-int(cut%uint(len(frame)))]
			if cut%3 == 0 {
				frame = append(frame, junk...)
			}
			isGenuine = bytes.Equal(frame, g)
		}
		m, err := envelope.Unmarshal(frame)
		if err != nil {
			return
		}
		before := fx.pool.Outstanding()
		acked, ran := false, false
		_ = fx.r.Receive(m, func() error { acked = true; return nil }, func(Delivered) error { ran = true; return nil })
		if isGenuine {
			if !ran {
				t.Fatal("the genuine frame was refused")
			}
			return
		}
		if acked || ran {
			t.Fatalf("a frame that is not genuine was accepted (ack %v, exec %v)", acked, ran)
		}
		if fx.pool.Outstanding() != before {
			t.Fatal("a frame that is not genuine spent a prekey")
		}
	})
}

// quiet drops the calls the fuzzing engine forbids inside a fuzz target.
type quiet struct{ testing.TB }

func (quiet) Helper()        {}
func (quiet) Cleanup(func()) {}
