// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var debName = regexp.MustCompile(`^parley_([0-9]+\.[0-9]+\.[0-9]+)_(amd64|arm64)\.deb$`)

// AptIndex writes the index of a flat apt repository holding the parley_<version>_<arch>.deb files in dir:
// Packages (each stanza is the package's control fields plus its Filename, Size and SHA256) and Release, which
// lists the hash and size of Packages (apt checks everything else through it). Release must then be signed with
// the repository key (SignRelease). date is the Release date, passed in so the output is reproducible. Files whose
// names do not match exactly are ignored.
func AptIndex(dir string, date time.Time) (packages, releaseFile []byte, err error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, e := range ents {
		if debName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("release: no parley_*.deb files in %s", dir)
	}
	sort.Strings(names)
	var pk bytes.Buffer
	archs := map[string]bool{}
	for _, n := range names {
		m := debName.FindStringSubmatch(n)
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(data)
		archs[m[2]] = true
		fmt.Fprintf(&pk, "%sFilename: ./%s\nSize: %d\nSHA256: %s\n\n", debControl(m[1], m[2], 0), n, len(data), hex.EncodeToString(sum[:]))
	}
	var a []string
	for k := range archs {
		a = append(a, k)
	}
	sort.Strings(a)
	var rel bytes.Buffer
	fmt.Fprintf(&rel, "Origin: Parley\nLabel: Parley\nSuite: stable\nCodename: stable\nDate: %s\nArchitectures: %s\nComponents: main\nDescription: Parley release packages\nSHA256:\n",
		date.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC"), strings.Join(a, " "))
	sum := sha256.Sum256(pk.Bytes())
	fmt.Fprintf(&rel, " %s %d Packages\n", hex.EncodeToString(sum[:]), pk.Len())
	return pk.Bytes(), rel.Bytes(), nil
}
