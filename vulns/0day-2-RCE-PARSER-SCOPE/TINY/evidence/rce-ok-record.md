# iPhone 6s RCE_OK record

Device: iPhone 6s (iPhone8,1), iOS 15.8.8.
Payload: the 4,600/2,124 inline ROP set,
`../payloads/inline-rop-h200.html`, with the real 3,617-byte stage B in the
same widget's `n1s2` storage.

Proof file on the device:

```
/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/rce.txt
-rw------- 1 mobile mobile 7  Nov 8 05:49:24
RCE_OK
```

The mtime is **2026-11-08 05:49:24**. The app stayed alive. The file is on the
device; the archived evidence is the stage-B hook log
(`hook-real-stage-b-6s.txt`) and the H400 probe screenshot
(`probe-h400-hit-20261108.png`).

The old `RCE_OK` from 2026-11-05 is the n-day proof
(`nday-1-RCE-V7-RGX-1827`). Check the mtime.
