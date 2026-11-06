// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package botproc knows which processes belong to a bot that Parley started, so
// the daemon can refuse them the commands that change what it trusts (approving a
// task). The CLI adapter starts every bot through Launch; the local socket's Guard
// asks Owns about the process at the other end of a connection.
//
// A process belongs to a bot if it is the bot's process, a descendant of it, or in
// the session (Linux) or process group (macOS) the bot was started in (a new one,
// see the adapter), which also catches a descendant whose parent has exited. On
// Windows it belongs if it is in the job object the bot was assigned to, which a
// descendant cannot leave.
//
// What this does not do: a bot that deliberately leaves its session and process
// group and loses its parent (a double fork with setsid) is no longer recognised
// on Linux and macOS. It is also blind to a process of the same user that Parley
// did not start. Only an operating-system sandbox covers those (see the README).
package botproc

import (
	"errors"
	"sync"
)

// maxDepth bounds the walk up a process's parents.
const maxDepth = 64

// ErrUnknown is returned when the lineage of a process cannot be read (it has exited, or the system refused). A caller
// that decides something trust-changing must treat it as a refusal.
var ErrUnknown = errors.New("botproc: cannot tell whether the process belongs to a bot")

// Registry is the set of running bots. The zero value is ready; the daemon and the CLI adapter share Default.
type Registry struct {
	mu   sync.Mutex
	pids map[int]int // root pid of a running bot -> how many are registered under it (a pid is reused only after removal)
}

// Default is the registry the adapter registers with and the daemon asks.
var Default = new(Registry)

// Launch runs start, which must start the bot and return its pid, while holding the registry: Owns waits until the bot is
// registered, so the bot cannot reach the socket in the instant between its start and its registration. The returned
// function removes the registration; call it after the bot has been reaped.
func (r *Registry) Launch(start func() (pid int, err error)) (remove func(), err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pid, err := start()
	if err != nil {
		return nil, err
	}
	if r.pids == nil {
		r.pids = map[int]int{}
	}
	r.pids[pid]++
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.pids[pid]--; r.pids[pid] <= 0 {
				delete(r.pids, pid)
			}
		})
	}, nil
}

// Owns reports whether pid belongs to a running bot. An error means it could not be decided (ErrUnknown).
func (r *Registry) Owns(pid int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pids) == 0 {
		// No bot runs, so none can be the caller. The pid still has to be a live process: a caller that has gone cannot be judged.
		if _, err := lookup(pid); err != nil {
			return false, ErrUnknown
		}
		return false, nil
	}
	return owns(r.pids, pid)
}
