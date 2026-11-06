// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package toolrun_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

const helperEnv = "PARLEY_TOOL_HELPER"

// TestMain lets this test binary play the tool: the runner starts os.Args[0] (through the sandbox) with
// PARLEY_TOOL_HELPER=<mode> in its environment.
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		helper(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(mode string) {
	args := os.Args[1:]
	switch mode {
	case "args": // the arguments, and how many variables the environment has (Windows adds SYSTEMROOT to any explicit one)
		n := 0
		for _, e := range os.Environ() {
			if !strings.EqualFold(strings.SplitN(e, "=", 2)[0], "SYSTEMROOT") {
				n++
			}
		}
		fmt.Print(strings.Join(args, "|"), ";", n)
	case "cwd":
		d, _ := os.Getwd()
		fmt.Print(d)
	case "write": // create the file named by the first argument
		if err := os.WriteFile(args[0], []byte("x"), 0o600); err != nil {
			fmt.Print("denied")
			return
		}
		fmt.Print("ok")
	case "read": // read the file named by the first argument
		b, err := os.ReadFile(args[0])
		if err != nil {
			fmt.Print("denied")
			return
		}
		fmt.Print("ok:", string(b))
	case "dial": // connect to the network and address given
		c, err := net.DialTimeout(args[0], args[1], 2*time.Second)
		if err != nil {
			fmt.Print("denied")
			return
		}
		c.Close()
		fmt.Print("ok")
	case "sleep":
		time.Sleep(time.Minute)
	case "big":
		io.WriteString(os.Stdout, strings.Repeat("a", 1<<20))
	case "exit":
		var n int
		fmt.Sscan(args[0], &n)
		os.Exit(n)
	}
}
