// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package toolrun

// plain starts the tool as it is: the tests use it to check the parts of the runner that do not depend on a sandbox, on
// every operating system.
type plain struct{}

func (plain) wrap(s Spec, args []string, _ bool) (string, []string) { return s.Command, args }

// NewUnsandboxed builds a Runner without a sandbox. Tests only.
func NewUnsandboxed(specs map[string]Spec) (*Runner, error) { return newRunner(specs, plain{}) }
