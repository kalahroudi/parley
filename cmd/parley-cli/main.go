// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parley-cli is the user-facing Parley command.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/root"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("parley-cli", version)
		return
	}
	if len(os.Args) >= 3 && os.Args[1] == "admin" && os.Args[2] == "init" {
		dir, err := os.UserConfigDir()
		if err != nil {
			//logx:allow fatal CLI error for the operator's terminal; no task content exists in this process path
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		dir = filepath.Join(dir, "parley")
		os.Exit(adminInit(os.Args[3:], os.Stdout, os.Stderr, root.FileStore{Dir: dir}, filepath.Join(dir, "root-backup.json")))
	}
}
