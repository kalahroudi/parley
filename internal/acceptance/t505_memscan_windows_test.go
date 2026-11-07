// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package acceptance

// T505: the key-memory scan on Windows (the counterpart of the Linux TestAddressSpaceHoldsNoErasedKey, T209).
// A child holds live and erased prekeys. It scans its own committed memory (VirtualQuery + ReadProcessMemory) and
// asks the kernel whether the key region is locked (QueryWorkingSetEx). Then the PARENT writes a full-memory
// minidump of the child with MiniDumpWriteDump (what a crash-dump tool or an attacker with PROCESS_VM_READ would
// get) and scans the file. Neither side holds a key: they look for fingerprints (an 8-byte prefix and a SHA-256
// digest). A scan only counts if it can find what is there, so a key planted in the Go heap and the live keys are
// controls: a scan that cannot see them fails.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
)

const winScanEnv = "PARLEY_WIN_SCAN_CHILD"

// maxWinHeapResidue: copies of an erased scalar the Go heap may still hold (see maxHeapResidue on Linux: the public
// key derivation and the HPKE open each leave a crypto/ecdh object that Go cannot zero). A ratchet.
const maxWinHeapResidue = 2

type winFP struct {
	Prefix string   `json:"prefix"`
	Digest [32]byte `json:"digest"`
}

type winScanReport struct {
	Locked        bool             `json:"locked"`
	KernelLocked  bool             `json:"kernel_locked"` // QueryWorkingSetEx says the key region's page is locked
	Pid           int              `json:"pid"`
	FPs           map[string]winFP `json:"fps"`
	Hits          map[string]int   `json:"hits"`
	InRegion      map[string]int   `json:"in_region"`
	AfterClose    map[string]int   `json:"after_close"`
	CloseInRegion map[string]int   `json:"close_in_region"`
	SlotZero      map[string]bool  `json:"slot_zero"`
}

func winFPOf(b []byte) winFP {
	return winFP{Prefix: hex.EncodeToString(b[:8]), Digest: sha256.Sum256(b)}
}

// winCount finds the addresses of every fingerprinted scalar in the committed, readable memory of this process,
// except the scanner's own read buffer (an artefact of measuring, not a copy the daemon holds).
func winCount(fps map[string]winFP) map[string][]uintptr {
	hits := map[string][]uintptr{}
	prefixes := map[string][]byte{}
	for n, fp := range fps {
		prefixes[n], _ = hex.DecodeString(fp.Prefix)
	}
	const chunk = 1 << 20
	buf := make([]byte, chunk+32)
	defer clear(buf)
	bufLo := uintptr(unsafe.Pointer(&buf[0]))
	bufHi := bufLo + uintptr(len(buf))
	self := windows.CurrentProcess()
	var mbi windows.MemoryBasicInformation
	for addr := uintptr(0); ; {
		if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		lo, hi := mbi.BaseAddress, mbi.BaseAddress+mbi.RegionSize
		if hi <= addr {
			break
		}
		addr = hi
		if mbi.State != windows.MEM_COMMIT || mbi.Protect&(windows.PAGE_NOACCESS|windows.PAGE_GUARD) != 0 {
			continue
		}
		for at := lo; at < hi; at += chunk {
			n := uintptr(len(buf))
			if at+n > hi {
				n = hi - at
			}
			var got uintptr
			if err := windows.ReadProcessMemory(self, at, &buf[0], n, &got); err != nil && got == 0 {
				break
			}
			window := buf[:got]
			for name, pre := range prefixes {
				for off := 0; ; {
					i := bytes.Index(window[off:], pre)
					if i < 0 {
						break
					}
					off += i
					if a := at + uintptr(off); off+32 <= len(window) && off < chunk && sha256.Sum256(window[off:off+32]) == fps[name].Digest &&
						!(a >= bufLo && a < bufHi) {
						hits[name] = append(hits[name], a)
					}
					off++
				}
			}
		}
	}
	return hits
}

// workingSetLocked asks the kernel whether the page at addr is locked in the working set (never paged out).
func workingSetLocked(addr uintptr) bool {
	type wsEx struct {
		VirtualAddress    uintptr
		VirtualAttributes uint64
	}
	e := wsEx{VirtualAddress: addr}
	r, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("K32QueryWorkingSetEx").Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&e)), unsafe.Sizeof(e))
	return r != 0 && e.VirtualAttributes&1 == 1 && (e.VirtualAttributes>>22)&1 == 1 // Valid and Locked
}

func winDie(err error) {
	os.Stderr.WriteString("child: " + err.Error() + "\n")
	os.Exit(3)
}

// TestWinMemScanChild is the child entry point; it does nothing in a normal run.
func TestWinMemScanChild(t *testing.T) {
	if os.Getenv(winScanEnv) == "" {
		t.Skip("helper process")
	}
	if err := prekey.Harden(); err != nil {
		winDie(err)
	}
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	p, err := prekey.New(prekey.Config{Tenant: "acme", DeviceID: "target", SigningKeyID: "k", BindingVersion: 1,
		Signer: signer, AllowUnlocked: true, SweepEvery: time.Hour})
	if err != nil {
		winDie(err)
	}
	r := winScanReport{Pid: os.Getpid(), FPs: map[string]winFP{}, SlotZero: map[string]bool{}}
	planted := make([]byte, 32) // positive control: a scalar in the Go heap
	rand.Read(planted)
	r.FPs["planted"] = winFPOf(planted)

	var sps []*prekey.Signed
	var slots []*[32]byte
	for i := 0; i < 6; i++ {
		sp, err := p.Issue(prekey.Request{Caller: string(rune('a' + i)), Nonce: []byte{byte(i + 1)}})
		if err != nil {
			winDie(err)
		}
		var fp winFP
		p.With(sp.ID, func(sk *[32]byte) error { fp = winFPOf(sk[:]); slots = append(slots, sk); return nil })
		r.FPs[strconv.Itoa(i)] = fp
		sps = append(sps, sp)
	}
	// The first three are opened (a real HPKE open with the scalar) and erased; the rest stay live.
	for i := 0; i < 3; i++ {
		h := envelope.Header{Tenant: "acme", SenderDevice: "caller", SenderKeyID: "k-c", BindingVersion: 1,
			TargetDevice: "target", PrekeyID: receive.PrekeyID(sps[i].ID), ContextID: "ctx", TaskID: newTask(),
			Type: envelope.TypeTask, IssuedAt: time.Now(), Expiry: time.Now().Add(time.Minute),
			RPK: bytes.Repeat([]byte{9}, 32), Prekey: sps[i].Encode()}
		m, err := envelope.SealPadded(signer, sps[i].PublicKey, h, []byte("scan me"))
		if err != nil {
			winDie(err)
		}
		if err := p.With(sps[i].ID, func(sk *[32]byte) error { _, err := m.Open(sk[:]); return err }); err != nil {
			winDie(err)
		}
		if err := p.Consume(sps[i].ID); err != nil {
			winDie(err)
		}
	}
	runtime.GC()
	debug.FreeOSMemory()

	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(uintptr(unsafe.Pointer(slots[3])), &mbi, unsafe.Sizeof(mbi)); err != nil {
		winDie(err)
	}
	lo, hi := mbi.BaseAddress, mbi.BaseAddress+mbi.RegionSize
	count := func() (total, inRegion map[string]int) {
		total, inRegion = map[string]int{}, map[string]int{}
		for name, as := range winCount(r.FPs) {
			total[name] = len(as)
			for _, a := range as {
				if a >= lo && a < hi {
					inRegion[name]++
				}
			}
		}
		return
	}
	r.Locked = p.Locked()
	r.KernelLocked = workingSetLocked(uintptr(unsafe.Pointer(slots[3])))
	r.Hits, r.InRegion = count()
	for i := 0; i < 3; i++ {
		r.SlotZero[strconv.Itoa(i)] = *slots[i] == [32]byte{}
	}
	runtime.KeepAlive(planted)

	// Tell the parent to dump this process now (the live keys are still live), and wait for it.
	b, _ := json.Marshal(r)
	os.Stdout.Write(append(b, '\n'))
	io.ReadAll(os.Stdin)

	// After Close nothing is live: the key region is released and wiped.
	p.Close()
	runtime.GC()
	r.AfterClose, r.CloseInRegion = count()
	b, _ = json.Marshal(r)
	os.Stdout.Write(append(b, '\n'))
}

// dumpFull writes a full-memory minidump of the process to path.
func dumpFull(t *testing.T, pid int, path string) {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		t.Fatalf("OpenProcess: %v", err)
	}
	defer windows.CloseHandle(h)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const miniDumpWithFullMemory = 0x2
	r, _, e := windows.NewLazySystemDLL("dbghelp.dll").NewProc("MiniDumpWriteDump").Call(uintptr(h), uintptr(pid), f.Fd(), miniDumpWithFullMemory, 0, 0, 0)
	if r == 0 {
		t.Fatalf("MiniDumpWriteDump: %v", e)
	}
}

// scanFile counts the occurrences of each fingerprinted scalar in a file.
func scanFile(t *testing.T, path string, fps map[string]winFP) map[string]int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hits := map[string]int{}
	prefixes := map[string][]byte{}
	for n, fp := range fps {
		prefixes[n], _ = hex.DecodeString(fp.Prefix)
	}
	const chunk = 4 << 20
	buf := make([]byte, chunk+32)
	for base := int64(0); ; base += chunk {
		n, err := f.ReadAt(buf, base)
		window := buf[:n]
		for name, pre := range prefixes {
			for off := 0; ; {
				i := bytes.Index(window[off:], pre)
				if i < 0 {
					break
				}
				off += i
				if off+32 <= len(window) && off < chunk && sha256.Sum256(window[off:off+32]) == fps[name].Digest {
					hits[name]++
				}
				off++
			}
		}
		if err != nil {
			break
		}
	}
	return hits
}

// The counts are exact (the scanner excludes its own buffer); every one of several runs must hold, so a noisy count
// shows up as a failure and is not averaged away.
func TestWindowsKeyMemoryScan(t *testing.T) {
	for run := 1; run <= 3; run++ {
		t.Logf("run %d", run)
		windowsKeyMemoryScanOnce(t)
	}
}

func windowsKeyMemoryScanOnce(t *testing.T) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWinMemScanChild$", "-test.v=false")
	cmd.Env = append(os.Environ(), winScanEnv+"=1")
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	rd := bufio.NewReader(out)
	readReport := func() winScanReport {
		line, err := rd.ReadBytes('\n')
		var r winScanReport
		if err != nil || json.Unmarshal(line, &r) != nil {
			t.Fatalf("the scan child gave no report: %v\n%s\n%s", err, line, stderr.String())
		}
		return r
	}
	r := readReport()
	t.Logf("in-process scan: hits %v, in key region %v, locked=%v kernelLocked=%v", r.Hits, r.InRegion, r.Locked, r.KernelLocked)

	// Controls: the scan sees a planted key and the live keys in the key region.
	if r.Hits["planted"] < 1 {
		t.Fatalf("the in-process scan cannot see a planted key: %v", r.Hits)
	}
	for _, k := range []string{"3", "4", "5"} {
		if r.InRegion[k] != 1 {
			t.Errorf("live key %s found %d times in the key region, want 1: %v", k, r.InRegion[k], r.InRegion)
		}
	}
	for _, k := range []string{"0", "1", "2"} {
		if r.InRegion[k] != 0 {
			t.Errorf("erased key %s is still in the key region (%d copies)", k, r.InRegion[k])
		}
		if r.Hits[k] > maxWinHeapResidue {
			t.Errorf("erased key %s has %d copies in the address space, the Go heap may hold %d", k, r.Hits[k], maxWinHeapResidue)
		}
		if !r.SlotZero[k] {
			t.Errorf("the slot of erased key %s is not zero", k)
		}
	}
	if !r.Locked || !r.KernelLocked {
		t.Errorf("the key region is not locked in RAM: pool says %v, the kernel's working set says %v", r.Locked, r.KernelLocked)
	}

	// The minidump of the same process, written by another process, scanned from the file.
	dump := filepath.Join(t.TempDir(), "child.dmp")
	dumpFull(t, r.Pid, dump)
	fi, _ := os.Stat(dump)
	d := scanFile(t, dump, r.FPs)
	t.Logf("minidump (%d bytes): %v", fi.Size(), d)
	if d["planted"] < 1 {
		t.Fatalf("the dump scan cannot see a planted key: %v", d)
	}
	for _, k := range []string{"3", "4", "5"} {
		if d[k] < 1 {
			t.Errorf("the dump scan cannot see live key %s: %v", k, d)
		}
	}
	for _, k := range []string{"0", "1", "2"} {
		if d[k] > maxWinHeapResidue {
			t.Errorf("a minidump holds %d copies of erased key %s, the Go heap may hold %d", d[k], k, maxWinHeapResidue)
		}
	}

	// After Close the live keys are gone from the key region too.
	in.Close()
	r2 := readReport()
	t.Logf("after Close: hits %v, in key region %v", r2.AfterClose, r2.CloseInRegion)
	for _, k := range []string{"3", "4", "5"} {
		if r2.CloseInRegion[k] != 0 {
			t.Errorf("after Close, live key %s is still in the key region (%d copies)", k, r2.CloseInRegion[k])
		}
		// Copies of a key that was live until Close in the Go heap are logged, not asserted: they are what the derivation and the
		// HPKE objects left, they vary from 1 to 5 from run to run on windows-latest, and nothing promises them away
		// (key-memory.md). What is promised, and asserted, is the key region and the erased keys.
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("the scan child failed: %v\n%s", err, stderr.String())
	}
}
