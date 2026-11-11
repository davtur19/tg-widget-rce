# Non-RCE fixtures

Single fixtures referenced by `../NON_RCE.md`. They are not a corpus and are
not built. The full labs remain in the source archive.

| File | Finding |
|---|---|
| `css-01-root-font-weight.html` | CSS-01 root `font-weight` null dereference. |
| `css-03-gradient-oom.html` | CSS-03 repeating-gradient OOM. |
| `svg-01-path-z0.html` | SVG-01 `path d="Z0"` loop. |
| `svg-02-use-fanout.html` | SVG-02 `<use>` fan-out. |
| `svg-04-arc-inf.html` | SVG-04 non-finite arc UB. |
| `wc-2-hashmap-dictbomb.html` | WC-2 `HashmapE` dictionary bomb. |
| `wc-2b-hashmap-shiftbomb.html` | WC-2b label-shift allocation bomb. |
| `wc-1-blocked.log` | WC-1 rejected by `isValidCellBoc`. |
| `d-1-textarea-uaf.cpp` | D-1 host PoC. |
| `d-2-deep-stack.cpp` | D-2 host PoC. |
| `html-01-asan.log` | HTML-01 ASan report. |
| `html-01-reachability.txt` | HTML-01 reachability note. |
