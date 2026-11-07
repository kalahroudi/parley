// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseConfigUpdate(t *testing.T) {
	c, err := ParseConfig([]byte(goodJSON("")))
	if err != nil || c.Update != nil {
		t.Fatalf("default: %+v %v", c.Update, err)
	}
	c, err = ParseConfig([]byte(goodJSON(`,"update":{}`)))
	if err != nil || c.Update.Mode != UpdateAuto || c.Update.interval != DefaultUpdateInterval {
		t.Fatalf("empty section: %+v %v", c.Update, err)
	}
	c, err = ParseConfig([]byte(goodJSON(`,"update":{"mode":"check","pin":"v1.2.3","interval":"24h","source":"https://mirror.example/rel"}`)))
	if err != nil || c.Update.Mode != UpdateCheck || c.Update.interval != 24*time.Hour || c.Update.Pin != "v1.2.3" {
		t.Fatalf("full: %+v %v", c.Update, err)
	}
	for _, edge := range []string{`"interval":"1h"`, `"interval":"168h"`, `"mode":"off"`, `"source":"http://127.0.0.1:8080/rel"`} {
		if _, err := ParseConfig([]byte(goodJSON(`,"update":{` + edge + `}`))); err != nil {
			t.Errorf("%s: %v", edge, err)
		}
	}
	for _, bad := range []string{`"mode":"sometimes"`, `"mode":"AUTO"`, `"pin":"1.2.3"`, `"pin":"v1.2"`, `"pin":"latest"`, `"pin":"v1.2.3-rc1"`,
		`"interval":"59m"`, `"interval":"169h"`, `"interval":"soon"`, `"source":"http://example.com/rel"`, `"source":"ftp://example.com"`, `"unknown":1`} {
		if _, err := ParseConfig([]byte(goodJSON(`,"update":{` + bad + `}`))); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func getenvOf(v string) func(string) string {
	return func(k string) string {
		if k == UpdateEnv {
			return v
		}
		return ""
	}
}

// The operator's environment can tighten the configured mode and never loosen it.
func TestPolicyEnvironmentOnlyRestricts(t *testing.T) {
	for _, c := range []struct {
		cfg, env, want string
	}{
		{"", "", UpdateAuto}, {"", "auto", UpdateAuto}, {"", "check", UpdateCheck}, {"", "off", UpdateOff},
		{"auto", "check", UpdateCheck}, {"auto", "off", UpdateOff},
		{"check", "", UpdateCheck}, {"check", "auto", UpdateCheck}, {"check", "check", UpdateCheck}, {"check", "off", UpdateOff},
		{"off", "", UpdateOff}, {"off", "auto", UpdateOff}, {"off", "check", UpdateOff}, {"off", "off", UpdateOff},
	} {
		cfg := Config{}
		if c.cfg != "" {
			cfg.Update = &UpdateConfig{Mode: c.cfg, interval: time.Hour}
		}
		p, err := cfg.Policy(getenvOf(c.env))
		if err != nil || p.Mode != c.want {
			t.Errorf("config %q env %q: got %q %v, want %q", c.cfg, c.env, p.Mode, err, c.want)
		}
	}
}

// A value the environment cannot be understood as turns updates off and says so.
func TestPolicyBadEnvironmentFailsClosed(t *testing.T) {
	for _, v := range []string{"on", "AUTO", "yes", "1", "off "} {
		p, err := Config{}.Policy(getenvOf(v))
		if err == nil || p.Mode != UpdateOff {
			t.Errorf("%q: got %q %v", v, p.Mode, err)
		}
	}
}

func TestPolicyCarriesTheConfiguration(t *testing.T) {
	d, err := ParseConfig([]byte(goodJSON(`,"update":{"pin":"v1.4.2","interval":"12h","source":"https://mirror.example/rel"}`)))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := d.Policy(getenvOf(""))
	if p != (UpdatePolicy{Mode: UpdateAuto, Pin: "v1.4.2", Interval: 12 * time.Hour, Source: "https://mirror.example/rel"}) {
		t.Fatalf("%+v", p)
	}
	def, _ := Config{}.Policy(getenvOf(""))
	if def != (UpdatePolicy{Mode: UpdateAuto, Interval: DefaultUpdateInterval}) {
		t.Fatalf("defaults: %+v", def)
	}
}

// A Config that never went through ParseConfig (so was not validated) cannot leave updates running on a wrong value.
func TestPolicyDistrustsUnvalidatedSection(t *testing.T) {
	for _, u := range []*UpdateConfig{{Mode: "sometimes"}, {Pin: "latest"}, {Source: "http://example.com"}, {Interval: "1s"}} {
		p, err := Config{Update: u}.Policy(getenvOf(""))
		if err == nil || p.Mode != UpdateOff {
			t.Errorf("%+v: got %+v %v", u, p, err)
		}
	}
	p, err := Config{Update: &UpdateConfig{Mode: UpdateCheck, Interval: "2h"}}.Policy(getenvOf(""))
	if err != nil || p.Mode != UpdateCheck || p.Interval != 2*time.Hour {
		t.Errorf("unvalidated but valid section: %+v %v", p, err)
	}
	p, err = Config{Update: &UpdateConfig{}}.Policy(getenvOf(""))
	if err != nil || p.Mode != UpdateAuto || p.Interval != DefaultUpdateInterval {
		t.Errorf("empty section: %+v %v", p, err)
	}
}

func TestParseConfigUpdateSourceErrorNamesTheField(t *testing.T) {
	_, err := ParseConfig([]byte(goodJSON(`,"update":{"source":"http://example.com/rel"}`)))
	if err == nil || !strings.Contains(err.Error(), "update.source") {
		t.Fatalf("%v", err)
	}
}
