// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package acceptance

// The address-space scan (T209). A child that holds live and erased prekeys
// reads its own memory through /proc/self/mem, region by region, and looks for
// each scalar by fingerprint. That is what a core dump or a swap image of the
// process would contain, minus the kernel's choices about what to include.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
)

// vmLockedKB reads VmLck from /proc/self/status.
func vmLockedKB() int {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmLck:") {
			f := strings.Fields(l)
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}

// countInMemory finds the addresses of occurrences of each fingerprinted scalar in every
// readable mapping of this process.
func countInMemory(fps map[string]fingerprint) map[string][]uint64 {
	hits := map[string][]uint64{}
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		die(err)
	}
	defer maps.Close()
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		die(err)
	}
	defer mem.Close()
	prefixes := map[string][]byte{}
	for name, fp := range fps {
		prefixes[name], _ = hex.DecodeString(fp.Prefix)
	}
	const chunk = 1 << 20
	buf := make([]byte, chunk+32)
	// The scanner's own read buffer is in the address space it reads and holds
	// a copy of whatever it read last (and, uncleared, of the previous scan's
	// last chunks). Those are artefacts of measuring, not copies the daemon
	// holds: they made the counts vary from run to run (worse under -race), so
	// they are neither counted nor left behind.
	bufLo := uint64(uintptr(unsafe.Pointer(&buf[0])))
	bufHi := bufLo + uint64(len(buf))
	defer clear(buf)
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[1][0] != 'r' || (len(f) >= 6 && strings.HasPrefix(f[5], "[vsyscall]")) {
			continue
		}
		var lo, hi uint64
		rng := strings.SplitN(f[0], "-", 2)
		lo, _ = strconv.ParseUint(rng[0], 16, 64)
		hi, _ = strconv.ParseUint(rng[1], 16, 64)
		for at := lo; at < hi; at += chunk {
			n := uint64(len(buf))
			if at+n > hi {
				n = hi - at
			}
			got, err := mem.ReadAt(buf[:n], int64(at))
			if got == 0 && err != nil {
				break // unreadable (guard page, vvar): skip the rest of the region
			}
			window := buf[:got]
			for name, pre := range prefixes {
				for off := 0; ; {
					i := bytes.Index(window[off:], pre)
					if i < 0 {
						break
					}
					off += i
					// A match straddling the chunk edge is read again by the next chunk, which
					// starts 1 MiB later but whose window only reaches 32 bytes past this one:
					// count it here only.
					if a := at + uint64(off); off+32 <= len(window) && sha256.Sum256(window[off:off+32]) == fps[name].Digest && off < chunk &&
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

// regionOf returns the mapping that holds addr.
func regionOf(addr uint64) (lo, hi uint64) {
	b, _ := os.ReadFile("/proc/self/maps")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 1 {
			continue
		}
		rng := strings.SplitN(f[0], "-", 2)
		lo, _ = strconv.ParseUint(rng[0], 16, 64)
		hi, _ = strconv.ParseUint(rng[1], 16, 64)
		if addr >= lo && addr < hi {
			return lo, hi
		}
	}
	die(errors.New("address not mapped"))
	return
}

// vmFlagsOf returns the kernel's VmFlags for the mapping holding addr, from
// /proc/self/smaps: "lo" is locked in RAM (never swapped), "dd" is excluded from
// core dumps (MADV_DONTDUMP).
func vmFlagsOf(addr uint64) string {
	b, _ := os.ReadFile("/proc/self/smaps")
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 5 && strings.Contains(f[0], "-") && !strings.HasSuffix(f[0], ":") {
			rng := strings.SplitN(f[0], "-", 2)
			lo, _ := strconv.ParseUint(rng[0], 16, 64)
			hi, _ := strconv.ParseUint(rng[1], 16, 64)
			in = addr >= lo && addr < hi
			continue
		}
		if in && strings.HasPrefix(l, "VmFlags:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "VmFlags:"))
		}
	}
	return ""
}

// debugHit writes where a copy of a scalar lives to stderr: the mapping, and the
// words around it (return addresses and pointers around a stale stack copy look
// different from a heap object's neighbours). Enabled by PARLEY_SCAN_DEBUG.
func debugHit(label, name string, addr uint64) {
	maps, _ := os.ReadFile("/proc/self/maps")
	region := "?"
	for _, l := range strings.Split(string(maps), "\n") {
		f := strings.Fields(l)
		if len(f) < 1 {
			continue
		}
		rng := strings.SplitN(f[0], "-", 2)
		lo, _ := strconv.ParseUint(rng[0], 16, 64)
		hi, _ := strconv.ParseUint(rng[1], 16, 64)
		if addr >= lo && addr < hi {
			region = l
		}
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return
	}
	defer mem.Close()
	const before, after = 160, 96
	b := make([]byte, before+32+after)
	n, _ := mem.ReadAt(b, int64(addr-before))
	words := []string{}
	for i := 0; i+8 <= n; i += 8 {
		w := uint64(b[i]) | uint64(b[i+1])<<8 | uint64(b[i+2])<<16 | uint64(b[i+3])<<24 | uint64(b[i+4])<<32 | uint64(b[i+5])<<40 | uint64(b[i+6])<<48 | uint64(b[i+7])<<56
		mark := ""
		if i == before {
			mark = "<-key"
		}
		words = append(words, fmt.Sprintf("%+4d %016x%s", i-before, w, mark))
	}
	code, heapPtr, zero := 0, 0, 0
	for i := 0; i+8 <= n; i += 8 {
		if i == before || i == before+8 || i == before+16 || i == before+24 {
			continue
		}
		w := uint64(b[i]) | uint64(b[i+1])<<8 | uint64(b[i+2])<<16 | uint64(b[i+3])<<24 | uint64(b[i+4])<<32 | uint64(b[i+5])<<40 | uint64(b[i+6])<<48 | uint64(b[i+7])<<56
		switch {
		case w == 0:
			zero++
		case w >= 0x400000 && w < 0xc00000:
			code++
		case w >= 0xc000000000 && w < 0xc100000000:
			heapPtr++
		}
	}
	fmt.Fprintf(os.Stderr, "DEBUGHIT %s %s addr=%#x words: zero=%d code=%d goheap=%d\n  region: %s\n  %s\n", label, name, addr, zero, code, heapPtr, region, strings.Join(words, "\n  "))
	clear(b)
}

// fpStateAt reports whether addr is the XMM register slot k (0..14) of an
// FXSAVE/XSAVE image, the register state the kernel writes on a signal stack when
// it delivers a signal: x87 control word 0x37f at offset 0 and an MXCSR mask of
// 0xffff at 28, with XMM0 at offset 160. It returns the slot, or -1.
func fpStateAt(addr uint64) int {
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return -1
	}
	defer mem.Close()
	for k := 0; k < 15; k++ {
		var b [32]byte
		if n, _ := mem.ReadAt(b[:], int64(addr-160-uint64(16*k))); n < 32 {
			continue
		}
		if b[0] == 0x7f && b[1] == 0x03 && b[28] == 0xff && b[29] == 0xff {
			return k
		}
	}
	return -1
}

func scanChild(r *childReport) {
	if err := prekey.Harden(); err != nil {
		die(err)
	}
	p, sps, live := newChildPool(6)
	fps := map[string]fingerprint{}
	// Positive control: a scalar we put in the Go heap ourselves.
	planted := make([]byte, 32)
	rand.Read(planted)
	fps["planted"] = fingerprintOf(planted)

	// Where each scalar lives, as the daemon's receive path would use it.
	addr := make([]*[32]byte, len(sps))
	for i, sp := range sps {
		p.With(sp.ID, func(sk *[32]byte) error { addr[i] = sk; return nil })
	}
	// The first three are opened (a real HPKE open with the scalar) and erased,
	// the rest stay live.
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	for i := 0; i < 3; i++ {
		h := envelope.Header{Tenant: "acme", SenderDevice: "caller", SenderKeyID: "k-c", BindingVersion: 1,
			TargetDevice: "target", PrekeyID: receive.PrekeyID(sps[i].ID), ContextID: "ctx", TaskID: newTask(),
			Type: envelope.TypeTask, IssuedAt: time.Now(), Expiry: time.Now().Add(time.Minute),
			RPK: bytes.Repeat([]byte{9}, 32), Prekey: sps[i].Encode()}
		m, err := envelope.SealPadded(signer, sps[i].PublicKey, h, []byte("scan me"))
		if err != nil {
			die(err)
		}
		if err := p.With(sps[i].ID, func(sk *[32]byte) error { _, err := m.Open(sk[:]); return err }); err != nil {
			die(err)
		}
		if err := p.Consume(sps[i].ID); err != nil {
			die(err)
		}
		fps["erased"+strconv.Itoa(i)] = live[i]
	}
	for i := 3; i < 6; i++ {
		fps["live"+strconv.Itoa(i)] = live[i]
	}
	runtime.GC()
	debug.FreeOSMemory()
	// Harden made the process non-dumpable, which also stops it reading its own
	// /proc/self/mem. Record that, then lift it for the scan only.
	d, _, e := syscall.Syscall(syscall.SYS_PRCTL, 3 /* PR_GET_DUMPABLE */, 0, 0)
	if e == 0 {
		v := int(d)
		r.Dumpable = &v
	}
	syscall.Syscall(syscall.SYS_PRCTL, 4 /* PR_SET_DUMPABLE */, 1, 0)

	lo, hi := regionOf(uint64(uintptr(unsafe.Pointer(addr[0]))))
	count := func() (total, inRegion map[string]int) {
		total, inRegion = map[string]int{}, map[string]int{}
		for name, as := range countInMemory(fps) {
			total[name] = len(as)
			if os.Getenv("PARLEY_SCAN_DEBUG") != "" && len(as) > 1 && strings.HasPrefix(name, "erased") {
				for _, a := range as {
					fmt.Fprintf(os.Stderr, "CLASS %s %#x fpslot=%d\n", name, a, fpStateAt(a))
					debugHit("scan", name, a)
				}
			}
			for _, a := range as {
				if a >= lo && a < hi {
					inRegion[name]++
				}
			}
		}
		return
	}
	r.Hits, r.InRegion = count()
	r.Locked = p.Locked()
	r.VmLockedKB = vmLockedKB()
	// The erased slots themselves read as zero.
	zero := map[string]interface{}{}
	for i := 0; i < 3; i++ {
		zero["slot"+strconv.Itoa(i)] = *addr[i] == [32]byte{}
	}
	r.Extra = map[string]interface{}{"slot_zero": zero, "vmflags": vmFlagsOf(uint64(uintptr(unsafe.Pointer(addr[3]))))}
	runtime.KeepAlive(planted)

	// After Close nothing is live: the live keys' slots go too.
	p.Close()
	runtime.GC()
	r.AfterClose, r.CloseInReg = count()
	emit(*r)
}

// maxHeapResidue is the number of copies of an erased scalar the Go heap may
// still hold. Measured: one from deriving the public key at Issue and one from
// the HPKE open, both crypto/ecdh private key objects that copy the scalar and
// that Go cannot zero. The plan calls erasure "best effort" for exactly this
// reason (REPORTED in the task summary: it means a core dump or a swapped-out
// heap page could still hold a used key, which is why Harden and the hardening
// guide's encrypted swap matter). This is a ratchet: it can only go down, and a
// change that leaks further copies fails the test.
const maxHeapResidue = 2

func TestAddressSpaceHoldsNoErasedKey(t *testing.T) {
	// The counts are exact: the scanner excludes its own read buffer (see
	// countInMemory), which used to add copies that varied from run to run. A
	// few runs are still made and every one must hold, so a regression to a
	// noisy count shows up as a failure and is not averaged away.
	const runs = 3
	hits, afterClose := map[string]int{}, map[string]int{}
	var r childReport
	for run := 0; run < runs; run++ {
		var stderr string
		r, stderr, _ = runChild(t, "scan", t.TempDir())
		if strings.Contains(stderr, "DEBUGHIT") {
			t.Logf("debug:\n%s", stderr)
		}
		t.Logf("hits %v, in key region %v, after Close %v", r.Hits, r.InRegion, r.AfterClose)
		for k, v := range r.Hits {
			hits[k] = max(hits[k], v)
		}
		for k, v := range r.AfterClose {
			afterClose[k] = max(afterClose[k], v)
		}
		// The scan can see: a key we planted in the Go heap, and the live keys in
		// the locked region.
		if r.Hits["planted"] < 1 {
			t.Fatalf("the scan cannot see a planted key: %v", r.Hits)
		}
		for i := 3; i < 6; i++ {
			if r.InRegion["live"+strconv.Itoa(i)] != 1 {
				t.Fatalf("live key %d found %d times in the key region, want 1: %v", i, r.InRegion["live"+strconv.Itoa(i)], r.InRegion)
			}
		}
		for i := 0; i < 3; i++ {
			name := "erased" + strconv.Itoa(i)
			if n := r.InRegion[name]; n != 0 {
				t.Errorf("%s is still in the locked key region (%d copies)", name, n)
			}
			if z := r.Extra["slot_zero"].(map[string]interface{})["slot"+strconv.Itoa(i)]; z != true {
				t.Errorf("the slot of %s is not zero after erase", name)
			}
		}
		// The kernel's own view of the key region: locked (lo) and out of core
		// dumps (dd). This is what mlock and MADV_DONTDUMP actually did.
		flags := " " + r.Extra["vmflags"].(string) + " "
		if r.Locked && !strings.Contains(flags, " lo ") {
			t.Errorf("the key region is not locked in RAM according to the kernel: VmFlags %q", flags)
		}
		if !strings.Contains(flags, " dd ") {
			t.Errorf("the key region is not excluded from core dumps (MADV_DONTDUMP): VmFlags %q", flags)
		}
		// Close must erase the region itself, not just leave the heap residue
		// below the allowance: a surviving copy in the old region is a leak.
		for i := 3; i < 6; i++ {
			if n := r.CloseInReg["live"+strconv.Itoa(i)]; n != 0 {
				t.Errorf("after Close, live%d is still in the key region (%d copies)", i, n)
			}
		}
		if r.Dumpable == nil || *r.Dumpable != 0 {
			t.Errorf("PR_SET_DUMPABLE after Harden: %v, want 0", r.Dumpable)
		}
	}
	// What the scan must not find: more than the known residue anywhere.
	for i := 0; i < 3; i++ {
		name := "erased" + strconv.Itoa(i)
		if n := hits[name]; n > maxHeapResidue {
			t.Errorf("%s has %d copies in the address space, the Go heap may hold %d", name, n, maxHeapResidue)
		}
	}
	// After Close the live keys are gone from the region too.
	for i := 3; i < 6; i++ {
		name := "live" + strconv.Itoa(i)
		if n := afterClose[name]; n > maxHeapResidue {
			t.Errorf("after Close, %s has %d copies (heap residue allowed: %d)", name, n, maxHeapResidue)
		}
	}
}
