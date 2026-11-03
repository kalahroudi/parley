# memscan investigation notes (TestAddressSpaceHoldsNoErasedKey, amd64 Linux)

Handover file; update as findings change. Branch fix/memscan-amd64.

## Symptom
main is red on ubuntu-latest (amd64): one child of the address-space scan finds a
third copy of an erased scalar (allowance 2), about 1 child in 3. Passes on arm64
and macOS. Local amd64 emulation (docker --platform linux/amd64, qemu) crashes the
Go toolchain, so amd64 can only be investigated in CI.

## Findings
1. The third copy is a kernel signal frame in the Go heap. In every failing run
   where the copy could be classified, the extra copy of the second scalar used
   (erased1) sat at the XMM0/XMM1 slot (offset 160) of an FXSAVE image (x87 FCW
   0x037f at offset 0, MXCSR mask 0xffff at 28) at a low arena address
   (0xc000011d20, 0xc0000115e0, 0xc0000116e0): the signal stack of an M. The
   kernel wrote it when a signal interrupted the thread while the key was in
   X0/X1 after a 32-byte memmove. The signal is SIGURG, the runtime's
   preemption signal, sent to the running goroutine when a garbage collection
   starts; the child's second key operation is where the first GC of the process
   begins, hence "erased1" and "about 1 in 3".
2. Evidence: GODEBUG=asyncpreemptoff=1 gave 0 failures of 100 (default 32 of 100
   and 17 of 100) on amd64 CI. A register scrub *after* the operation (this
   branch, scrub_*.go) did not help (scrub on 22 of 60 failing, off 6 of 60; the
   difference is noise from where the GC lands), which showed the signal arrives
   *during* the operation, not after it.
3. Fix: Pool.With and Pool.Issue run on a locked OS thread with asynchronous
   signals blocked (quiesce_linux.go), scrub the vector registers, and only then
   unblock, so a held-back SIGURG finds zero registers. The runtime copes with a
   delayed preemption. Elsewhere (macOS, Windows) the window stays open and the
   docs say so. Not covered: general-purpose registers and stack spills.
4. Handy: amd64 cannot be run locally (qemu crashes the Go toolchain); use CI.
   FXSAVE detector: bytes 0x7f 0x03 at addr-160-16k and 0xff 0xff at +28.

## Result
After the fix (commit "Block preemption signals while a prekey scalar is in use"),
the address-space scan, built with -race and run 100 times in a row on amd64 Linux
CI (x86_64 runner, run 41678709507): 0 failures of 100 (before: 91 of 200, 22 of
60, 17 and 32 of 100). Build, vet and tests of internal/prekey, internal/receive
and internal/acceptance also passed on ubuntu, macos and windows (run
41680859670). The allowance (maxHeapResidue = 2) and the planted-key control are
unchanged, and there are no retries.
