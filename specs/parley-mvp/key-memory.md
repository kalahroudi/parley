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

## Registers and signal stacks (found on amd64 CI, T209 follow-up)

A copy of the scalar passes through the CPU's vector registers (a 32-byte memmove
uses X0 and X1). If a signal interrupts the thread then, the kernel writes the
registers onto the thread's signal stack, and Go allocates signal stacks in its
heap, so a copy of the key ends up in memory nothing zeroes. The runtime's
preemption signal (SIGURG) is sent at the start of every garbage collection.

| | Linux | macOS | Windows |
|---|---|---|---|
| Signals blocked while the scalar is in use (locked thread) | yes (`quiesce`) | no | no |
| Vector registers cleared after use (amd64: XMM, YMM and, where present, ZMM and mask registers; arm64: V0-V31) | amd64, arm64 | amd64, arm64 | amd64, arm64 |
| Window for a signal-frame copy | closed for asynchronous signals on amd64 and arm64; on other Linux architectures a held-back signal can still find the key in a register | open | open (Windows has no signal frames, but exception and crash paths are as above) |

Signals stay blocked for one `Issue` (tens of microseconds) or one `With` callback;
synchronous fault signals (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGSYS) are
never blocked. A signal held back is delivered when the mask is restored, after
the vector registers were cleared, but general-purpose registers are not.

Not covered anywhere: general-purpose registers and stack spills; code outside
`Pool.With` and `Pool.Issue` (reply keys, signing seed); synchronous faults. The
scan's allowance of two heap copies per erased key is unchanged. Details and the
evidence are in `memscan-notes.md`.

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

## The device signing key and the local control socket (T410)

The device signing key (Ed25519) is a different secret from the prekeys above:
it is long-lived and stored, not held in locked memory. `internal/keystore`
keeps its seed in the OS keychain (macOS Keychain, Windows Credential Manager,
Linux Secret Service) or, only when the config says `key_store: "file"`, in
`device.key` (mode 0600 in a private directory; a protected DACL on Windows).
The keychain keeps other users out; it does not keep out other processes of the
same user. The file store keeps out other users (checked: owner, mode, no
symlink) and nothing else; root and the same user can read it. In memory the
seed is zeroed on shutdown, but Go cannot promise that no copy remains.

The control socket (`internal/localsock`) is a request channel to the daemon,
not a boundary against the user's own processes:

| | Another standard local user | Same user's other processes | Administrator / root |
|---|---|---|---|
| Linux, macOS | cannot connect (0700 directory, 0600 socket, kernel-checked uid) | can connect and call every method | can connect |
| Windows | cannot open the directory (protected DACL) | can connect and call every method | can connect |

On Windows nothing re-checks the caller once the directory is reachable (AF_UNIX
there carries no peer credentials); a named pipe with a current-user ACL, or an
equivalent peer check, is task T505 (`TestPending_WindowsDaemonPeerRestriction`
fails CI once T505 is ticked).
