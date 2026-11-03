# Private prekey memory: what is promised, what is tested (T209)

Private prekeys, reply keys and signing seeds live in memory only. This page
states, per OS, what the code does to keep them out of core dumps and swap,
what each mechanism does and does not promise, and which part of that the test
suite proves. Nothing here claims more than a test or the OS documentation
backs. The plan calls erasure best effort, and it is.

## What the code does

| Step | Linux | macOS | Windows |
|---|---|---|---|
| Keys held outside the Go heap in one locked region | `mlock` | `mlock` | `VirtualLock` |
| Core limit set to 0, and not raisable by an unprivileged process | `RLIMIT_CORE` | `RLIMIT_CORE` | none (no equivalent) |
| Process marked non-dumpable | `PR_SET_DUMPABLE=0` | none | none |
| Key region excluded from dumps | `MADV_DONTDUMP` | none | none |
| Crash dialog suppressed | n/a | n/a | `SetErrorMode` |

## What each one does and does not promise

- **mlock / VirtualLock** keep the pages resident while the process runs, so the
  pager does not write them to swap or the page file. They do not cover:
  hibernation (the whole of RAM is written to the hibernation image), VM or
  host memory snapshots, cold-boot reads, or a privileged reader of the live
  process. A locked region can also fail to lock (low `RLIMIT_MEMLOCK`); the
  pool then refuses to start unless `AllowUnlocked` is set, which only tests do.
- **RLIMIT_CORE=0** stops this process writing a core file. It does not stop
  another process (a debugger, `gcore`, a crash reporter) reading its memory.
- **PR_SET_DUMPABLE=0** (Linux) also stops same-user processes from ptrace-reading
  it and disables `/proc/<pid>/mem` for them; root can still read.
- **MADV_DONTDUMP** (Linux) leaves the key region out of core dumps. It does not
  prevent swapping (that is mlock's job) and does not stop a live reader.
- **macOS** has no `MADV_DONTDUMP` or `PR_SET_DUMPABLE`. The core limit is the
  only dump control the code applies. Keeping other processes out of the task
  port relies on the hardened runtime without `get-task-allow` in the signed
  build; no test here checks that.
- **Windows** has no core limit. `SetErrorMode` only suppresses the crash dialog.
  The code does **not** exclude the process from Windows Error Reporting dumps.
  The plan asks for that and it is not done. It needs machine policy (WER
  `LocalDumps` left unconfigured) until the daemon handles it. Do not read
  "the daemon hardens crash dumps on Windows" from this page. `VirtualLock` is
  also subject to the process working-set size; Windows may write locked pages
  at hibernation.
- **Erasure.** The raw scalar slots are zeroed on use. Go's `crypto/ecdh` key
  objects copy the scalar (at Issue, deriving the public key, and at each HPKE
  open) and cannot be zeroed, so up to `maxHeapResidue` copies of a used key can
  remain in the Go heap until it is overwritten. A core dump or a swapped-out
  heap page could therefore still hold a used key. That is why the hardening
  guide requires full-disk encryption and disabled or encrypted hibernation and swap.

## What the tests prove, per OS

| Test | Linux | macOS | Windows |
|---|---|---|---|
| `TestHardenedCrashLeavesNoCore`: a hardened crash writes no core file, core limit 0/0 | yes | yes | not built (unix only) |
| `TestHardenedLimitsCannotBeRaised` (skipped as root) | yes | yes | no |
| `TestUnhardenedControlCanDump`: without Harden the same crash writes a core and the scan finds a planted 32-byte value in it | yes, where `core_pattern` is a plain file name (CI images and the dev container); otherwise the test fails if the pattern says a file should appear | skipped when the host writes no core (usual: code signing, `/cores`) and says so | no |
| `TestKeyMemoryIsLockedAgainstSwap`: the pool is locked and the kernel counts it (`VmLck`) | yes | lock result only | no |
| `TestAddressSpaceHoldsNoErasedKey`: whole address space read through `/proc/self/mem`; a planted heap value must be FOUND; live keys found once in the locked region; erased keys never in the region and at most `maxHeapResidue` copies in the heap (worst of three runs; the scanner excludes its own buffer); nothing left in the region after `Close`; kernel `VmFlags` for the region show `lo` and `dd` | yes | skipped | skipped |

## What cannot be tested in CI

- That nothing reaches swap. CI runners have little or no swap and no memory
  pressure we control, so a "swap scan" would find nothing whether or not the
  keys were locked. The test proves the cause instead: the kernel reports the
  key region locked (`lo`), so it is not eligible for swap. The swap claim
  rests on that and on the OS documentation for mlock, not on an observed
  empty swap file.
- Hibernation images, VM snapshots and cold-boot reads. Out of reach; covered
  only by the hardening guide's disk-encryption and no-hibernation requirement.
- macOS and Windows address-space scans: no portable way to read a process's own
  memory there (Mach task ports, `ReadProcessMemory` on a hardened process).
  Those two rely on the Linux scan exercising the same pool code.
