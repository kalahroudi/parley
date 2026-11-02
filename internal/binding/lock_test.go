// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Two trackers (two daemons) share one store and accept different devices at
// the same time. Without the lock each saves its own stale snapshot and drops
// the other's records.
func TestSharedStoreNoLostUpdates(t *testing.T) {
	rpub, rpriv := keys(t)
	path := filepath.Join(t.TempDir(), "seen.json")
	const n = 20
	var wg sync.WaitGroup
	for p := 0; p < 2; p++ {
		tr, err := NewTracker(rpub, NewFileStore(path))
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				b := sample(t, 1)
				b.DeviceID = fmt.Sprintf("p%d-d%d", p, i)
				s, _ := Sign(rpriv, b)
				if err := tr.Accept(s, now); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	recs, err := NewFileStore(path).Load()
	if err != nil || len(recs) != 2*n {
		t.Fatalf("got %d records (err %v), want %d", len(recs), err, 2*n)
	}
}

// A second tracker sees a version the first recorded after it started, and
// rejects a rollback against it.
func TestSharedStoreSeesOtherProcessRecords(t *testing.T) {
	rpub, rpriv := keys(t)
	path := filepath.Join(t.TempDir(), "seen.json")
	a, _ := NewTracker(rpub, NewFileStore(path))
	b, _ := NewTracker(rpub, NewFileStore(path)) // loaded before a writes
	bd := sample(t, 2)
	v2, _ := Sign(rpriv, bd)
	bd.Version = 1
	v1, _ := Sign(rpriv, bd)
	if err := a.Accept(v2, now); err != nil {
		t.Fatal(err)
	}
	if err := b.Accept(v1, now); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
}

// The lock excludes other processes: a child holds it, we cannot get it until
// the child exits (which also shows a dead holder leaves no stale lock).
func TestLockExcludesOtherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	cmd := exec.Command(os.Args[0], "-test.run=TestLockHolderHelper", "-test.v")
	cmd.Env = append(os.Environ(), "PARLEY_LOCK_HELPER="+path)
	stdin, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	sc := bufio.NewScanner(out)
	for sc.Scan() && sc.Text() != "LOCKED" {
	}

	fs := NewFileStore(path)
	fs.lockTimeout = 200 * time.Millisecond
	if _, err := fs.Lock(); !errors.Is(err, ErrStore) {
		t.Fatalf("lock held by another process: got %v", err)
	}
	stdin.Close()
	cmd.Wait()
	fs.lockTimeout = 5 * time.Second
	release, err := fs.Lock()
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestLockHolderHelper(t *testing.T) {
	path := os.Getenv("PARLEY_LOCK_HELPER")
	if path == "" {
		t.Skip("helper process only")
	}
	if _, err := NewFileStore(path).Lock(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("LOCKED")
	bufio.NewReader(os.Stdin).ReadByte() // hold until the parent closes stdin
}
