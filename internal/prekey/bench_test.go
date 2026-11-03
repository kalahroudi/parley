// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import "testing"

// BenchmarkIssue and BenchmarkWith measure the cost of the key path, including
// the thread lock, signal masking and register scrub added for T209.
func BenchmarkIssue(b *testing.B) {
	f := newFixture(b, nil)
	r := req("c")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sp, err := f.pool.Issue(r)
		if err != nil {
			b.Fatal(err)
		}
		if err := f.pool.Consume(sp.ID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWith(b *testing.B) {
	f := newFixture(b, nil)
	sp, err := f.pool.Issue(req("c"))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := f.pool.With(sp.ID, func(*[scalarSize]byte) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}
