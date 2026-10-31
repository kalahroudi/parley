// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"sort"
)

type bomComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// SBOM returns a deterministic CycloneDX 1.5 JSON document describing the Go
// binaries at paths: each binary's main module and every module compiled in.
// It carries no timestamp or serial number so that it is reproducible.
func SBOM(version string, paths []string) ([]byte, error) {
	seen := map[string]bomComponent{}
	for _, p := range paths {
		bi, err := buildinfo.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("sbom: %w", err)
		}
		add := func(name, ver, typ string) {
			if ver == "" || ver == "(devel)" {
				ver = version
			}
			purl := "pkg:golang/" + name + "@" + ver
			seen[purl] = bomComponent{Type: typ, Name: name, Version: ver, PURL: purl}
		}
		add(bi.Main.Path, version, "application")
		for _, d := range bi.Deps {
			if d.Replace != nil {
				d = d.Replace
			}
			add(d.Path, d.Version, "library")
		}
	}
	comps := make([]bomComponent, 0, len(seen))
	for _, c := range seen {
		comps = append(comps, c)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].PURL < comps[j].PURL })
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"components":  comps,
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
