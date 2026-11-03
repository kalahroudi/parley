// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package acceptance

// T209 (spike 3, last item): core-dump and swap scans find no key bytes.
//
// Each check runs the real prekey pool in a child process (this test binary
// re-executed), because what is under test is the process: its core-dump
// limits, its locked memory and what its address space holds.
//
//	TestHardenedCrashLeavesNoCore        a crashing hardened daemon writes no core file and no trace
//	TestHardenedLimitsCannotBeRaised     the core limit is zero and the process cannot raise it again
//	TestUnhardenedControlCanDump         control: without Harden the same crash can dump, and the scan reads it
//	TestKeyMemoryIsLockedAgainstSwap     key memory is locked in RAM (so it never reaches swap)
//	TestAddressSpaceHoldsNoErasedKey     (linux) a scan of the whole address space finds no erased scalar
//
// A scan only means something if it can find a key that is there, so each one
// is paired with a positive control. Keys are never printed by a hardened
// child: it reports a SHA-256 digest and an 8-byte prefix of each scalar, so
// the scanner holds no copy of the bytes it looks for.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/prekey"
)

const childEnv = "PARLEY_SCAN_CHILD"

// plantedHeap is the unhardened control's own 32 bytes in the Go heap, which a
// core dump of that process must contain.
var plantedHeap []byte

// fingerprint identifies a scalar without holding it.
type fingerprint struct {
	Prefix string   `json:"prefix"` // hex of the first 8 bytes
	Digest [32]byte `json:"digest"` // SHA-256 of all 32 bytes
}

func fingerprintOf(b []byte) fingerprint {
	return fingerprint{Prefix: hex.EncodeToString(b[:8]), Digest: sha256.Sum256(b)}
}

// childReport is what a child prints as its last stdout line.
type childReport struct {
	Locked     bool                   `json:"locked"`
	VmLockedKB int                    `json:"vm_locked_kb"`
	Dumpable   *int                   `json:"dumpable,omitempty"`
	CoreCur    uint64                 `json:"core_cur"`
	CoreMax    uint64                 `json:"core_max"`
	RaiseErr   string                 `json:"raise_err,omitempty"`
	Hits       map[string]int         `json:"hits,omitempty"`
	InRegion   map[string]int         `json:"in_region,omitempty"` // hits inside the locked key region
	AfterClose map[string]int         `json:"after_close,omitempty"`
	CloseInReg map[string]int         `json:"close_in_region,omitempty"` // hits in the key region after Close
	Raw        map[string]string      `json:"raw,omitempty"`             // unhardened control only
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

// newChildPool builds a pool the way the daemon does, issuing n prekeys to
// distinct callers. It returns the fingerprints of their scalars.
func newChildPool(n int) (*prekey.Pool, []*prekey.Signed, []fingerprint) {
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	p, err := prekey.New(prekey.Config{Tenant: "acme", DeviceID: "target", SigningKeyID: "k", BindingVersion: 1,
		Signer: signer, AllowUnlocked: true, SweepEvery: time.Hour})
	if err != nil {
		die(err)
	}
	var sps []*prekey.Signed
	var fps []fingerprint
	for i := 0; i < n; i++ {
		sp, err := p.Issue(prekey.Request{Caller: string(rune('a' + i)), Nonce: []byte{byte(i + 1)}})
		if err != nil {
			die(err)
		}
		err = p.With(sp.ID, func(sk *[32]byte) error { fps = append(fps, fingerprintOf(sk[:])); return nil })
		if err != nil {
			die(err)
		}
		sps = append(sps, sp)
	}
	return p, sps, fps
}

func die(err error) {
	os.Stderr.WriteString("child: " + err.Error() + "\n")
	os.Exit(3)
}

func emit(r childReport) {
	b, _ := json.Marshal(r)
	os.Stdout.Write(append(b, '\n'))
}

func coreLimit(r *childReport) {
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil {
		die(err)
	}
	r.CoreCur, r.CoreMax = uint64(l.Cur), uint64(l.Max)
}

// TestMemScanChild is the child entry point; it does nothing in a normal run.
func TestMemScanChild(t *testing.T) {
	mode := os.Getenv(childEnv)
	if mode == "" {
		t.Skip("helper process")
	}
	var r childReport
	switch mode {
	case "crash", "crash-unhardened":
		if mode == "crash" {
			if err := prekey.Harden(); err != nil {
				die(err)
			}
		}
		p, sps, fps := newChildPool(2)
		coreLimit(&r)
		r.Locked = p.Locked()
		if mode == "crash-unhardened" {
			r.Raw = map[string]string{}
			plantedHeap = make([]byte, 32)
			rand.Read(plantedHeap)
			r.Raw["planted"] = hex.EncodeToString(plantedHeap)
			for i, sp := range sps {
				p.With(sp.ID, func(sk *[32]byte) error { r.Raw[fps[i].Prefix] = hex.EncodeToString(sk[:]); return nil })
			}
		}
		// Try to put the limit back up: an unprivileged hardened process cannot.
		if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 1 << 30, Max: 1 << 30}); err != nil {
			r.RaiseErr = err.Error()
		}
		emit(r)
		// A real crash, the kind that writes a core when it is allowed to
		// (the parent sets GOTRACEBACK=crash for that).
		panic("crash test")
	case "locked":
		p, _, _ := newChildPool(2)
		r.Locked = p.Locked()
		r.VmLockedKB = vmLockedKB()
		emit(r)
	case "scan":
		scanChild(&r)
	default:
		t.Fatal("unknown child mode", mode)
	}
}

// runChild runs this test binary as mode, with the core limit raised to
// unlimited by the shell first (so a dump is possible if the child does not
// forbid it), and returns its report, its stderr and the exit state.
func runChild(t *testing.T, mode, dir string, traceback ...string) (childReport, string, *os.ProcessState) {
	t.Helper()
	cmd := exec.Command("sh", "-c", `ulimit -c unlimited 2>/dev/null; exec "$0" "$@"`,
		os.Args[0], "-test.run=^TestMemScanChild$", "-test.v=false")
	cmd.Dir = dir
	tb := "crash" // what the runtime needs to abort and dump core
	if len(traceback) > 0 {
		tb = traceback[0]
	}
	cmd.Env = append(os.Environ(), childEnv+"="+mode, "GOTRACEBACK="+tb)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	var r childReport
	var report string
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "{") {
			report = l
		}
	}
	if err := json.Unmarshal([]byte(report), &r); err != nil {
		t.Fatalf("%s child gave no report: %v\nstdout: %s\nstderr: %s", mode, err, out.String(), errb.String())
	}
	return r, errb.String(), cmd.ProcessState
}

// coresFor lists core files a process may have left: in its working directory
// and, on macOS, in /cores.
func coresFor(dir string, pid int) []string {
	var found []string
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "core") {
			found = append(found, filepath.Join(dir, e.Name()))
		}
	}
	if p := filepath.Join("/cores", "core."+itoa(pid)); fileExists(p) {
		found = append(found, p)
	}
	return found
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestHardenedCrashLeavesNoCore(t *testing.T) {
	// The service is started with GOTRACEBACK=none (plan: "GOTRACEBACK=none"), and
	// then a crash prints no goroutine dump. The second case is hostile: the
	// environment asks the runtime for a crash dump. debug.SetTraceback, which
	// Harden calls, can only raise the level, never lower what the environment
	// set, so the trace is NOT suppressed there (nor with the default
	// environment, which prints the crashing goroutine); only the core limit
	// holds. That gap is reported with this task, not hidden by the test.
	for _, tb := range []string{"none", "crash"} {
		t.Run("GOTRACEBACK="+tb, func(t *testing.T) {
			dir := t.TempDir()
			r, stderr, st := runChild(t, "crash", dir, tb)
			if r.CoreCur != 0 || r.CoreMax != 0 {
				t.Fatalf("core limit after Harden is %d/%d, want 0/0", r.CoreCur, r.CoreMax)
			}
			if st.Success() {
				t.Fatal("the child was meant to crash")
			}
			if cores := coresFor(dir, st.Pid()); len(cores) != 0 {
				t.Fatalf("a hardened crash left a core file: %v", cores)
			}
			if tb == "none" && strings.Contains(stderr, "goroutine ") {
				t.Fatalf("traceback on stderr after Harden:\n%s", stderr)
			}
			if left, _ := os.ReadDir(dir); len(left) != 0 {
				t.Fatalf("the child left files behind: %v", left)
			}
		})
	}
}

func TestHardenedLimitsCannotBeRaised(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may raise limits; the guarantee is for the unprivileged daemon user")
	}
	r, _, _ := runChild(t, "crash", t.TempDir())
	if r.RaiseErr == "" {
		t.Fatal("the hardened process raised its own core limit back up")
	}
}

// Control: the same crash without Harden. It exists so that the hardened result
// above cannot be a side effect of a restrictive test setup. A core file is the
// OS's choice, not ours: it needs a hard limit above zero (checked), a
// core_pattern that writes a file rather than piping to a handler (apport,
// systemd-coredump on most CI images), and on macOS a writable /cores and an
// unsigned binary. Where the host will write one, this test REQUIRES it, and the
// control must then find a 32-byte value planted in the child's heap: a scan that
// cannot see a planted value fails. Where the host will not, the test says so
// and the process-level checks (limit and its irreversibility, locked memory,
// the address-space scan) are what stand; it does not pretend a dump was read.
func TestUnhardenedControlCanDump(t *testing.T) {
	dir := t.TempDir()
	r, _, st := runChild(t, "crash-unhardened", dir)
	if r.CoreCur == 0 {
		t.Skip("this host forbids core files outright (hard limit 0), so the control cannot show a dump")
	}
	cores := coresFor(dir, st.Pid())
	if len(cores) == 0 {
		if runtime.GOOS == "linux" && coreFileExpected() {
			t.Fatalf("core_pattern writes files and the limit was %d, but the unhardened crash left none: the control is broken", r.CoreCur)
		}
		t.Skipf("limit was %d but this host wrote no core (piped core_pattern, code signing or unwritable /cores): no dump was scanned on %s", r.CoreCur, runtime.GOOS)
	}
	defer func() {
		for _, c := range cores {
			if strings.HasPrefix(c, dir) {
				continue // inside t.TempDir
			}
			os.Remove(c)
		}
	}()
	planted, _ := hex.DecodeString(r.Raw["planted"])
	if len(planted) != 32 {
		t.Fatal("the child did not report its planted value")
	}
	var found bool
	for _, c := range cores {
		b, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, planted) {
			found = true
		}
	}
	if !found {
		t.Fatal("a core file was written but the scan did not find the planted value in it: the scan cannot see a dump")
	}
}

// coreFileExpected reports whether the kernel is set to write a plain core file
// (not pipe to a handler) so that a missing one is a failure.
func coreFileExpected() bool {
	b, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		return false
	}
	p := strings.TrimSpace(string(b))
	return strings.HasPrefix(p, "core") && !strings.Contains(p, "/") // relative: lands in the child's working directory
}

// Swap. Key memory is mlock/VirtualLock-ed, so the OS cannot page it out. Where
// the host refuses the lock (a tiny RLIMIT_MEMLOCK) there is nothing to assert.
func TestKeyMemoryIsLockedAgainstSwap(t *testing.T) {
	r, _, _ := runChild(t, "locked", t.TempDir())
	if !r.Locked {
		t.Skip("this host refuses mlock for the test user; the daemon would refuse to start without AllowUnlocked")
	}
	if runtime.GOOS == "linux" && r.VmLockedKB < 4 {
		t.Fatalf("pool says locked but the kernel counts %d kB locked", r.VmLockedKB)
	}
}
