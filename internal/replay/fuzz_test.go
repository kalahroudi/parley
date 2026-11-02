// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"errors"
	"testing"
	"time"
)

// FuzzAccept feeds arbitrary sender ids, task ids, sequence numbers and expiry
// times to a table that persists across inputs. Nothing may panic; an invalid
// sender is refused; a message accepted once is a replay the second time; a
// failed Accept records nothing; and the table never outgrows its bound.
func FuzzAccept(f *testing.F) {
	now := time.Unix(1_800_000_000, 0).UTC()
	tb := New(Config{MaxEntries: 64, MaxPerSender: 8, Now: func() time.Time { return now }})
	f.Add("dev-a", []byte{1}, uint64(0), int64(60))
	f.Add("", []byte{}, uint64(1), int64(60))
	f.Add("dev-a", []byte{1}, ^uint64(0), int64(-1))
	f.Add("dev-a", []byte{1}, uint64(2), int64(1<<62))
	f.Add(string(make([]byte, MaxSenderLen+1)), []byte{2}, uint64(3), int64(60))
	f.Fuzz(func(t *testing.T, sender string, task []byte, seq uint64, secs int64) {
		k := Key{Sender: sender, Seq: seq}
		copy(k.Task[:], task)
		// Keep the offset in range of time.Duration so the test itself cannot overflow.
		expiry := now.Add(time.Duration(secs%(1<<40)) * time.Second)
		before := tb.Len()
		err := tb.Accept(k, expiry)
		switch {
		case sender == "" || len(sender) > MaxSenderLen:
			if !errors.Is(err, ErrKey) {
				t.Fatalf("invalid sender: %v", err)
			}
		case err == nil:
			if again := tb.Accept(k, expiry); !errors.Is(again, ErrReplay) {
				t.Fatalf("second accept: %v", again)
			}
			if !tb.Forget(k) {
				t.Fatal("an accepted key cannot be forgotten")
			}
		default:
			if tb.Len() != before {
				t.Fatalf("failed accept (%v) changed the table", err)
			}
		}
		if tb.Len() > 64 {
			t.Fatal("table outgrew its bound")
		}
	})
}
