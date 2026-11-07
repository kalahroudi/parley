// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import "testing"

func TestParseVersion(t *testing.T) {
	for s, want := range map[string]string{"v1.2.3": "v1.2.3", "1.2.3": "v1.2.3", "v0.0.0": "v0.0.0", "v10.20.30": "v10.20.30", "v999999999.0.1": "v999999999.0.1"} {
		v, err := ParseVersion(s)
		if err != nil || v.String() != want {
			t.Errorf("%q: %v %v", s, v, err)
		}
	}
	for _, s := range []string{"", "v", "1.2", "1.2.3.4", "v1.2.x", "v1.2.3-rc1", "v01.2.3", "v1..3", "v1.2.-3", "v+1.2.3", "v1.2.3 ", "vv1.2.3", "v1000000000.0.0", "dev"} {
		if _, err := ParseVersion(s); err != ErrVersion {
			t.Errorf("%q accepted (%v)", s, err)
		}
	}
}

func TestVersionLess(t *testing.T) {
	order := []string{"v0.0.1", "v0.1.0", "v0.1.1", "v1.0.0", "v1.0.1", "v1.1.0", "v2.0.0"}
	for i, a := range order {
		for j, b := range order {
			va, _ := ParseVersion(a)
			vb, _ := ParseVersion(b)
			if va.Less(vb) != (i < j) {
				t.Errorf("%s < %s: %v", a, b, va.Less(vb))
			}
		}
	}
}
