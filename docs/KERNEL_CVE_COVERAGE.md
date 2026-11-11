# Kernel and Binder CVE coverage

Dated research note, 2026-11-08. The goal was a Binder/kernel escape reachable
from the Android isolated widget process on a stock device, without root,
Frida, Magisk or a permissive SELinux policy. The result is negative: no
unreported Android 0day was verified, and every known CVE is reference only.
The Telegram host bug (shared SkPath race) is the remaining Telegram-owned
path; see `HOST_BINDER_ESCAPE_20261108.md`.

Full evidence: `<LAB>/artifacts_20261108/kernel_0day/REPORT.md` (section 10),
`sender_fuzz/`, `harness/`; and
`<LAB>/artifacts_20261108/kernel_nday/COVERAGE.md`, `RESULTS.md`, `poc/`,
`tools/`.

## Matrix

| CVE | Kernels | Android / SPL | Lab result | Reachable from `isolated_app` | Status |
|---|---|---|---|---|---|
| CVE-2019-2215 | 3.18, 4.4, 4.9, 4.14 | pre-2019-10 SPL | 3.18.91 / Android 8.0 / SPL 2018-04 vulnerable; waitqueue UAF leak works from `shell` | yes by design (Binder); Chrome renderer in-the-wild chain | reference n-day; full LPE open |
| CVE-2022-20421 (Bad Spin) | GKI 5.4, 5.10 | Android 12, 13 | public source; per-device config; Pixel 6 | yes | reference n-day, not the 4.19 target |
| CVE-2020-0041 | 4.14, 4.19 range | Android 9, 10 | deterministic OOB; narrower exposure | yes | reference n-day |
| CVE-2020-0423 | 4.14, 4.19 range | Android 10, 11 | race; no public source | yes | reference n-day |
| CVE-2023-20938 / 21255 | 5.10, 5.15 | Android 12, 13 | complex cross-cache; Google writeup, no public code | yes | reference n-day |
| CVE-2026-64469 / 64468 | 4.19 and newer | 2026 | public UAFs; three-process Binder graph and a broker | no graph/broker from `isolated_app` | reference n-day |
| 4.19 target | 4.19.157 | SPL 2023-07 | no public Binder LPE | - | needs original research |

## CVE-2019-2215, measured

The lab image is stock Android 8.0, API 26, kernel 3.18.91, SPL 2018-04-05,
SELinux enforcing, no root. The P0 waitqueue UAF works from `shell` (uid 2000):
the freed `binder_thread` is reclaimed by the kernel iovec array,
`EPOLL_CTL_DEL` rewrites the iovec entries and `writev` leaks the slab page.
The leak returned `0xffff8800540896a8` (wait+8) and
`0xffff88006aedb440` (`binder_thread->task`, the current `task_struct`).

The full LPE was not demonstrated end-to-end. The 8-byte kernel-write stage
(recvmsg iovec rewrite) deadlocks in the child's `EPOLL_CTL_DEL` on 3.18; the
freed `binder_thread` is not reliably reclaimed by `import_iovec()` there. The
credential patch is implemented but was not executed.

Version boundary: the stock Android 9 image (kernel 4.4.124, SPL 2019-01) is
already patched. A 4.14.175 kernel rebuilt with the fix reverted still fails
the leak because `iov_iter copyin()` checks `access_ok()`. The public
2019-2215 code is therefore confined to 3.18, 4.4 and 4.9.

## Sender-side Binder fuzzing, 4.19.288

To look for an unreported bug on the target generation, a sender-side Binder
parser fuzzer ran against a binderfs context manager with
`FLAT_BINDER_FLAG_ACCEPTS_FDS`, under a KASAN 4.19.288 QEMU kernel. The sender
generated `BC_TRANSACTION` with random data and offset sizes, random
`BINDER`/`WEAK_BINDER`/`HANDLE`/`WEAK_HANDLE`/`PTR`/`FD`/`FDA` objects, valid
and invalid parent graphs, fd arrays, unaligned offsets and zero-size buffers.
The target drained `BR_TRANSACTION`, freed the delivered buffers and closed
received fds. Kernel parameters: `nokaslr loglevel=4
binder.debug_mask=0 oops=panic`.

Results: 49,000 + 30,000 + 4 x 49,000 = about 275,000 delivered/attempted
transactions, plus many rejected. No KASAN, BUG, WARNING or oops. Logs:
`sender_fuzz_run4.log`, `sender_fuzz_run5.log`, `sender_fuzz_par1..4.log`.

Exact wall: the unprivileged/isolated Binder surface is a transaction to an
existing service. The parser paths reachable there produced no memory-safety
failure on 4.19.288. The residual source-present corruption classes require
either a Binder graph with a selected target process that can die in parallel,
or the context-manager role needed by the 2020 ref-0/self-transaction bug.
`isolated_app` cannot obtain either: no binderfs control, no `/dev/hwbinder`,
no way to displace servicemanager, no broker that accepts and later calls back
an arbitrary client node. The 2026 UAFs and the 2020 ref-0 bug are therefore
reference-only known issues, not 0days.

The only unprivileged-path source discrepancy found was the stock 4.19
`free_async_space` accounting leak for zero-size async buffers: a
space-accounting/DoS issue, not EoP.

## The 4.19 target

The target device is 4.19.157, SPL 2023-07-01. Every CVE in the matrix is fixed
at that SPL. The Binder/ashmem source is effectively AOSP 4.19.288.
CVE-2022-20421 is fixed; the 2023 Binder UAFs do not apply to the 4.19
whole-buffer path; CVE-2023-52438 does not apply; CVE-2023-52609 is a DoS;
the freeze UAFs are unreachable; the ashmem `len==0` path is not exploitable
in the C driver.

The Android 0day track is negative. A genuine unreported Android bug has value,
but this path did not produce one; known Sony/Android CVEs have no value for
the target. The Telegram-owned host bug (shared SkPath race with a Scudo
chunk-header write) is the remaining app-level path; see
`HOST_BINDER_ESCAPE_20261108.md`.

All lab work used user-space PoCs and a NativeActivity APK harness. Root and
Frida were used only for lab instrumentation, not as part of a chain.
