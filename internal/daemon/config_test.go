// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func goodJSON(extra string) string {
	pub := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	return `{"format":1,"tenant":"t1","device_id":"dev-1","gateway_url":"https://gw.example.test","root_public_key":"` + pub + `"` + extra + `}`
}

func TestParseConfigDefaults(t *testing.T) {
	c, err := ParseConfig([]byte(goodJSON("")))
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyStore != KeyStoreKeychain || c.RefreshEvery() != DefaultRefresh {
		t.Errorf("defaults: %q %v", c.KeyStore, c.RefreshEvery())
	}
	if (Config{}).RefreshEvery() != DefaultRefresh {
		t.Error("zero Config must use the default refresh")
	}
}

func TestParseConfigOptions(t *testing.T) {
	c, err := ParseConfig([]byte(goodJSON(`,"key_store":"file","refresh_interval":"90s","log_level":"warn"`)))
	if err != nil || c.KeyStore != KeyStoreFile || c.RefreshEvery() != 90*time.Second {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ParseConfig([]byte(strings.Replace(goodJSON(""), "https://gw.example.test", "http://localhost:8787", 1))); err != nil {
		t.Errorf("http to localhost must be allowed: %v", err)
	}
	for _, h := range []string{"127.0.0.1:1", "[::1]:1"} {
		if _, err := ParseConfig([]byte(strings.Replace(goodJSON(""), "https://gw.example.test", "http://"+h, 1))); err != nil {
			t.Errorf("http to %s: %v", h, err)
		}
	}
}

func TestParseConfigRejects(t *testing.T) {
	good := goodJSON("")
	rep := func(a, b string) string { return strings.Replace(good, a, b, 1) }
	cases := map[string]string{
		"empty":            ``,
		"not json":         `nope`,
		"unknown field":    goodJSON(`,"extra":1`),
		"trailing":         good + ` {}`,
		"format":           rep(`"format":1`, `"format":2`),
		"tenant empty":     rep(`"tenant":"t1"`, `"tenant":""`),
		"tenant chars":     rep(`"tenant":"t1"`, `"tenant":"a b"`),
		"tenant long":      rep(`"tenant":"t1"`, `"tenant":"`+strings.Repeat("a", 65)+`"`),
		"device chars":     rep(`"device_id":"dev-1"`, `"device_id":"a/b"`),
		"root short":       rep(`"root_public_key":"`+base64.StdEncoding.EncodeToString(make([]byte, 32)), `"root_public_key":"`+base64.StdEncoding.EncodeToString(make([]byte, 31))),
		"http remote":      rep("https://gw.example.test", "http://gw.example.test"),
		"ftp":              rep("https://gw.example.test", "ftp://gw.example.test"),
		"no host":          rep("https://gw.example.test", "https://"),
		"userinfo":         rep("https://gw.example.test", "https://u:p@gw.example.test"),
		"query":            rep("https://gw.example.test", "https://gw.example.test?a=1"),
		"fragment":         rep("https://gw.example.test", "https://gw.example.test#a"),
		"bad url":          rep("https://gw.example.test", "https://gw.example.test/%zz"),
		"key store":        goodJSON(`,"key_store":"cloud"`),
		"refresh garbage":  goodJSON(`,"refresh_interval":"soon"`),
		"refresh too fast": goodJSON(`,"refresh_interval":"1s"`),
		"log level":        goodJSON(`,"log_level":"trace"`),
	}
	for name, in := range cases {
		if _, err := ParseConfig([]byte(in)); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: want ErrConfig, got %v", name, err)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadConfig(dir); !errors.Is(err, ErrConfig) {
		t.Errorf("missing file: %v", err)
	}
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(goodJSON("")), 0o600)
	if _, err := LoadConfig(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte(goodJSON(`,"log_level":"`+strings.Repeat("x", maxConfigBytes)+`"`)), 0o600)
	if _, err := LoadConfig(dir); !errors.Is(err, ErrConfig) {
		t.Errorf("oversize: %v", err)
	}
	os.Remove(p)
	os.Mkdir(p, 0o700) // a directory where the file should be: the read fails
	if _, err := LoadConfig(dir); !errors.Is(err, ErrConfig) {
		t.Errorf("unreadable: %v", err)
	}
}

func TestDefaultDirs(t *testing.T) {
	none := func(string) string { return "" }
	d, err := DefaultDirs(none, func() (string, error) { return "/cfg", nil })
	if err != nil || d.Config != filepath.Join("/cfg", "parley") || d.State != d.Config {
		t.Errorf("%+v %v", d, err)
	}
	if _, err := DefaultDirs(none, func() (string, error) { return "", errors.New("x") }); err == nil {
		t.Error("want error")
	}
	home := func(k string) string {
		if k == "PARLEY_HOME" {
			return "/h"
		}
		return ""
	}
	abs, _ := filepath.Abs("/h") // a drive letter is added on Windows
	if d, err := DefaultDirs(home, func() (string, error) { return "", errors.New("unused") }); err != nil || d.Config != abs || d.State != abs {
		t.Errorf("PARLEY_HOME: %+v %v", d, err)
	}
}

func TestDefaultDirsAreAbsolute(t *testing.T) {
	d, err := DefaultDirs(func(string) string { return "@home" }, nil)
	if err != nil || !filepath.IsAbs(d.Config) || !filepath.IsAbs(d.State) || !filepath.IsAbs(d.SocketPath()) {
		t.Errorf("PARLEY_HOME=@home gave %+v, %v", d, err)
	}
}

func TestRefreshIntervalHasAnUpperBound(t *testing.T) {
	if _, err := ParseConfig([]byte(goodJSON(`,"refresh_interval":"25h"`))); !errors.Is(err, ErrConfig) {
		t.Errorf("a refresh interval longer than 24h must be refused: %v", err)
	}
	if _, err := ParseConfig([]byte(goodJSON(`,"refresh_interval":"24h"`))); err != nil {
		t.Errorf("24h is allowed: %v", err)
	}
}
