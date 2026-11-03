// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64 && linux

package prekey

import (
	"os"
	"strings"
	"testing"
)

// The assembly's feature detection must agree with the kernel's view in
// /proc/cpuinfo (which also reflects an OS that does not save the state).
func TestFeatureDetectionAgreesWithCPUInfo(t *testing.T) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		t.Skip(err)
	}
	var flags map[string]bool
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "flags"); ok {
			flags = map[string]bool{}
			for _, f := range strings.Fields(v[strings.Index(v, ":")+1:]) {
				flags[f] = true
			}
			break
		}
	}
	if flags == nil {
		t.Skip("no flags line")
	}
	if flags["avx"] != haveAVX {
		t.Errorf("haveAVX=%v but /proc/cpuinfo avx=%v", haveAVX, flags["avx"])
	}
	if flags["avx512f"] != haveAVX512 {
		t.Errorf("haveAVX512=%v but /proc/cpuinfo avx512f=%v", haveAVX512, flags["avx512f"])
	}
}
