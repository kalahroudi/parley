// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Checksums returns a deterministic SHA256SUMS body (sha256sum format, sorted
// by name) for the named files inside dir.
func Checksums(dir string, names []string) ([]byte, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	var b bytes.Buffer
	for _, n := range sorted {
		sum, err := fileSum(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, n)
	}
	return b.Bytes(), nil
}

// VerifyChecksums checks every entry of a SHA256SUMS body against files in dir.
func VerifyChecksums(dir string, sums []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		want, name, ok := strings.Cut(line, "  ")
		if !ok || len(want) != 64 || name == "" || name != filepath.Base(name) {
			return fmt.Errorf("checksums: bad line %q", line)
		}
		got, err := fileSum(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("checksums: %s does not match", name)
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("checksums: no entries")
	}
	return sc.Err()
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
