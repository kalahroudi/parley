# memscan investigation notes (TestAddressSpaceHoldsNoErasedKey, amd64 Linux)

Handover file; update as findings change. Branch fix/memscan-amd64.

## Symptom
main is red on ubuntu-latest (amd64): one child of the address-space scan finds a
third copy of an erased scalar (allowance 2), about 1 child in 3. Passes on arm64
and macOS. Local amd64 emulation (docker --platform linux/amd64, qemu) crashes the
Go toolchain, so amd64 can only be investigated in CI.

## Findings so far
1. Stale kernel signal frames (run 41563975312, 41623665967): in the failing runs
   from the earlier loops, one extra copy sat at the XMM0/XMM1 slot (offset 160) of
   an FXSAVE image (x87 FCW 0x037f at offset 0, MXCSR mask 0xffff at 28) in the
   Go heap arena at a low address (0xc000011d20): a signal frame written by the
   kernel on a gsignal stack when SIGURG (runtime preemption, around runtime.GC)
   arrived while the key was in X0/X1 from a 32-byte memmove. With
   GODEBUG=asyncpreemptoff=1: 0 failures of 100; default: 32 and 17 of 100.
   Only about half of the failing runs had an FXSAVE-signature copy; the rest had
   no identified cause (classification at that time looked at slot 0..14 only).
2. A register scrub after each use (this branch, internal/prekey/scrub_*) did NOT
   fix it: run 41634123556 failed 91 of 200 (more than before, though that loop
   also ran the 3-run test on a different runner pool). erased1 is most often the
   culprit; erased0/erased2 also appear. Some runs show a count of 1 (erased2:1).
3. The scrub itself is deterministic (TestScrubVectorRegistersZeroesThem).

## Open
- Which mapping/object holds the extra copy when there is no FXSAVE signature.
- Whether the scrub changes the failure rate (workflow compares scrub on/off).
