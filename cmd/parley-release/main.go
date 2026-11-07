// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parley-release is the release pipeline helper: key generation,
// SHA256SUMS, SBOM, signing and verification with the project's own key.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kalahroudi/parley/internal/release"
)

const usage = `usage:
  parley-release keygen <secret-file> <public-file>
  parley-release checksums <dir> <out> <file>...
  parley-release sbom <version> <out> <binary>...
  parley-release sign <secret-file> <file> <trusted-comment>   (writes <file>.minisig)
  parley-release verify <public-file> <file>                   (reads <file>.minisig)
  parley-release verify-checksums <sums-file>                  (files next to it)
  parley-release formula <tag> <dir> <out>                     (Homebrew formula from the binaries in <dir>)
  parley-release deb <tag> <amd64|arm64> <dir> <out>           (Debian package from the Linux binaries in <dir>)
  parley-release apt <dir> <unix-time>                         (Packages and Release for the .deb files in <dir>)
  parley-release apt-sign <secret-file> <dir>                  (Release.gpg and InRelease for <dir>/Release, signed with the release key)
  parley-release apt-key <secret-file> <out>                   (the release key as an OpenPGP public key, armored; prints its fingerprint)

The secret key file is encrypted; keygen and sign read its password from the
environment variable ` + passwordEnv + ` (never from the command line).
`

const passwordEnv = "PARLEY_RELEASE_KEY_PASSWORD"

func password() (string, error) {
	p := os.Getenv(passwordEnv)
	if p == "" {
		return "", fmt.Errorf("set %s to the secret key password", passwordEnv)
	}
	return p, nil
}

//cover:ignore main only wires the process (arguments, os.Exit) to run, which is tested
func main() {
	if err := run(os.Args[1:]); err != nil {
		//logx:allow fatal startup/CLI error for the operator's terminal; no task content exists in this process path
		fmt.Fprintln(os.Stderr, "parley-release:", err)
		os.Exit(1)
	}
}

// createFile writes data to a new file and fails if path already exists.
func createFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// loadSecret reads the encrypted release key with the password from the environment.
func loadSecret(path string) (release.SecretKey, error) {
	pw, err := password()
	if err != nil {
		return release.SecretKey{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return release.SecretKey{}, err
	}
	return release.ParseSecretKey(data, pw)
}

func run(a []string) error {
	if len(a) == 0 {
		return fmt.Errorf("%s", usage)
	}
	cmd, a := a[0], a[1:]
	switch {
	case cmd == "keygen" && len(a) == 2:
		pw, err := password()
		if err != nil {
			return err
		}
		sk, pk, err := release.GenerateKey()
		if err != nil {
			return err
		}
		enc, err := sk.MarshalEncrypted(pw)
		if err != nil {
			return err
		}
		// Never overwrite an existing key: that could destroy the release key.
		if err := createFile(a[0], enc, 0o600); err != nil {
			return err
		}
		if err := createFile(a[1], pk.Marshal(), 0o644); err != nil {
			os.Remove(a[0])
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
		pw, err := password()
		if err != nil {
			return err
		}
		skData, err := os.ReadFile(a[0])
		if err != nil {
			return err
		}
		sk, err := release.ParseSecretKey(skData, pw)
		if err != nil {
			return err
		}
		msg, err := os.ReadFile(a[1])
		if err != nil {
			return err
		}
		sig, err := sk.Sign(msg, a[2])
		if err != nil {
			return err
		}
		return os.WriteFile(a[1]+".minisig", sig, 0o644)
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
	case cmd == "formula" && len(a) == 3:
		out, err := release.Formula(a[0], a[1])
		if err != nil {
			return err
		}
		return os.WriteFile(a[2], out, 0o644)
	case cmd == "deb" && len(a) == 4:
		out, err := release.BuildDeb(a[0], a[1], a[2])
		if err != nil {
			return err
		}
		return os.WriteFile(a[3], out, 0o644)
	case cmd == "apt" && len(a) == 2:
		secs, err := strconv.ParseInt(a[1], 10, 64)
		if err != nil || secs < 0 {
			return fmt.Errorf("apt: %q is not a unix time", a[1])
		}
		packages, rel, err := release.AptIndex(a[0], time.Unix(secs, 0))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(a[0], "Packages"), packages, 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(a[0], "Release"), rel, 0o644)
	case cmd == "apt-sign" && len(a) == 2:
		sk, err := loadSecret(a[0])
		if err != nil {
			return err
		}
		rel, err := os.ReadFile(filepath.Join(a[1], "Release"))
		if err != nil {
			return err
		}
		detached, inRelease := release.SignRelease(sk, rel)
		if err := os.WriteFile(filepath.Join(a[1], "Release.gpg"), detached, 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(a[1], "InRelease"), inRelease, 0o644)
	case cmd == "apt-key" && len(a) == 2:
		sk, err := loadSecret(a[0])
		if err != nil {
			return err
		}
		block, fp := release.PublicKeyBlock(sk)
		if err := os.WriteFile(a[1], block, 0o644); err != nil {
			return err
		}
		fmt.Println("fingerprint:", fp)
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
