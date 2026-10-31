// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parley-cli is the user-facing Parley command.
package main

import (
	"fmt"
	"os"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("parley-cli", version)
	}
}
