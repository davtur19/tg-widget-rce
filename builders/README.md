# Builders

Payload builders for the RCE routes. They are runnable from this directory.
They write into the canonical `vulns/` payload trees by default. Each builder
accepts an environment variable to redirect the output for tests.

Requirements: Python 3.10+, `node`, `terser` (`npm install -g terser`).

| Directory | Route | Main checks |
|---|---|---|
| `0day-1/` | N1 fake-scope candidate | `gen_sc_gate.py ... --check` |
| `0day-2/xtag/` | Android cross-tag (`c2560s`) | `build_widgets.py --check` |
| `0day-2/stag/` | Android same-tag (`route2`) | `build_probe.py --check`, `check_parallel.sh` |
| `0day-2/tiny/` | iOS hole-reuse (6s) | `build_ios_way.py --H 400 --check` |
| `0day-2/ios27/` | iPhone 17e | `gen_probe.py`, `gen_probe_geometry.py` |
| `two_phase/` | P2 detector + final + fallback (ungated) | `gen_two_phase.py --check` |

The canonical payloads are in `vulns/` and `payloads/`. The builders assert
the shipped SHA-256 where a pin exists. The P3/gated two-phase pages in
`payloads/two_phase/` are **not** produced by `builders/two_phase/`; see the
critique. Current pins: `docs/PAYLOAD_HASHES.json`. The raw lab scripts are in
the per-ID `scripts/variants/` directories and in `original/` where noted.
