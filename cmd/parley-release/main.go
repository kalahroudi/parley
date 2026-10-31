// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parley-release is the release pipeline helper: key generation,
// SHA256SUMS, SBOM, signing and verification with the project's own key.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/release"
)

const usage = `usage:
  parley-release keygen <secret-file> <public-file>
  parley-release checksums <dir> <out> <file>...
  parley-release sbom <version> <out> <binary>...
  parley-release sign <secret-file> <file> <trusted-comment>   (writes <file>.minisig)
  parley-release verify <public-file> <file>                   (reads <file>.minisig)
  parley-release verify-checksums <sums-file>                  (files next to it)
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "parley-release:", err)
		os.Exit(1)
	}
}

func run(a []string) error {
	if len(a) == 0 {
		return fmt.Errorf("%s", usage)
	}
	cmd, a := a[0], a[1:]
	switch {
	case cmd == "keygen" && len(a) == 2:
		sk, pk, err := release.GenerateKey()
		if err != nil {
			return err
		}
		if err := os.WriteFile(a[0], sk.Marshal(), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(a[1], pk.Marshal(), 0o644); err != nil {
			return err
		}
		fmt.Println("key id:", pk.ID)
		return nil
	case cmd == "checksums" && len(a) >= 3:
		out, err := release.Checksums(a[0], a[2:])
		if err != nil {
			return err
		}
		return os.WriteFile(a[1], out, 0o644)
	case cmd == "sbom" && len(a) >= 3:
		out, err := release.SBOM(a[0], a[2:])
		if err != nil {
			return err
		}
		return os.WriteFile(a[1], out, 0o644)
	case cmd == "sign" && len(a) == 3:
		skData, err := os.ReadFile(a[0])
		if err != nil {
			return err
		}
		sk, err := release.ParseSecretKey(skData)
		if err != nil {
			return err
		}
		msg, err := os.ReadFile(a[1])
		if err != nil {
			return err
		}
		return os.WriteFile(a[1]+".minisig", sk.Sign(msg, a[2]), 0o644)
	case cmd == "verify" && len(a) == 2:
		pkData, err := os.ReadFile(a[0])
		if err != nil {
			return err
		}
		pk, err := release.ParsePublicKey(pkData)
		if err != nil {
			return err
		}
		msg, err := os.ReadFile(a[1])
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(a[1] + ".minisig")
		if err != nil {
			return err
		}
		c, err := pk.Verify(msg, sig)
		if err != nil {
			return err
		}
		fmt.Println("signature ok:", c)
		return nil
	case cmd == "verify-checksums" && len(a) == 1:
		data, err := os.ReadFile(a[0])
		if err != nil {
			return err
		}
		return release.VerifyChecksums(filepath.Dir(a[0]), data)
	}
	return fmt.Errorf("%s", usage)
}
