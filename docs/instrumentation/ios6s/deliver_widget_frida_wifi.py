#!/usr/bin/env python3
"""Deliver an in-chat tgwidget message to Telegram 13.2 (36535) on the iPhone 6s.

Delivery path (Frida only; no bot, no network, no SSH/AFC):

  TelegramCore.TelegramEngine.Messages.debugInsertLocalWidgetMessages(
      peerId: Postbox.PeerId, posts: [TelegramCore.EngineLocalWidgetPost])
    -> Signal<Int, NoError>

The method is exported by TelegramCoreFramework at file offset 0x6C077C; its
outlined body is local at 0x5F8538.  The UI's own Debug Settings action uses the
same call (confirmed in the shipped TelegramUIFramework at 0x10f6e2fa8).

Usage:
    deliver_n1_6s.py --pid <Telegram pid> [--html PATH]
                     [--account-peer 0] [--chat-peer 0]
                     [--no-start] [--capture-printf] [--settle 15]

The widget payload is embedded in the Frida script as UTF-8; the app process is
sandboxed away from /var/mobile/Media, so the host text is used.
"""
import argparse
import json
import os
import sys
import time

import frida

DEFAULT_HTML = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "widget", "n1_ios_s1safe.html",
)

# Module-relative offsets (Telegram 13.2, build 36535; verified against the
# decrypted app bundle whose binary sizes match the device modules exactly).
CORE_MESSAGES_META_ACCESSOR = 0x6D0448   # Messages metadata accessor (Mn)
CORE_ELWP_META_ACCESSOR = 0x5F7AE4       # EngineLocalWidgetPost metadata accessor
CORE_ACCOUNT_META_ACCESSOR = 0x2C250     # TelegramCore.Account metadata accessor (Mn/Ma)
CORE_DEBUG_INSERT_IMPL = 0x5F8538        # outlined debugInsertLocalWidgetMessages
SSK_SIGNAL_START = 0x122EC               # SwiftSignalKit.Signal.start

JS_TEMPLATE = r"""
'use strict';

var CONFIG = __CONFIG__;

function log(o) { send(o); }
function safe(desc, fn) {
  try { return { ok: true, value: fn() }; }
  catch (e) { return { ok: false, where: desc, error: String(e), stack: (e && e.stack) || '' }; }
}

var core = Process.getModuleByName('TelegramCoreFramework');
var ssk = Process.getModuleByName('SwiftSignalKitFramework');
var swift = Process.getModuleByName('libswiftCore.dylib');

var messagesMetaAccessor = core.base.add(CONFIG.coreMessagesMeta);
var elwpMetaAccessor = core.base.add(CONFIG.coreElwpMeta);
var implAddress = core.base.add(CONFIG.coreImpl);
var signalStartAddress = ssk.base.add(CONFIG.sskStart);

log({ stage: 'modules', core: core.base.toString(), ssk: ssk.base.toString(),
      swift: swift.base.toString(), impl: implAddress.toString(),
      start: signalStartAddress.toString() });

var messagesMeta = safe('MessagesMeta', function () {
  return new NativeFunction(messagesMetaAccessor, 'pointer', [])();
});
if (!messagesMeta.ok) { log(messagesMeta); throw new Error('Messages metadata accessor failed'); }
messagesMeta = messagesMeta.value;
log({ stage: 'messagesMeta', metadata: messagesMeta.toString() });

var elwpMeta = safe('ELWPMeta', function () {
  return new NativeFunction(elwpMetaAccessor, 'pointer', [])();
});
if (!elwpMeta.ok) { log(elwpMeta); throw new Error('EngineLocalWidgetPost metadata accessor failed'); }
elwpMeta = elwpMeta.value;
log({ stage: 'elwpMeta', metadata: elwpMeta.toString() });

var allocUninitialized = new NativeFunction(
  swift.findExportByName('$ss27_allocateUninitializedArrayySayxG_BptBwlF'),
  ['pointer', 'pointer'], ['size_t', 'pointer']);
var stringFromCString = new NativeFunction(
  swift.findExportByName('$sSS7cStringSSSPys4Int8VG_tcfC'),
  ['pointer', 'pointer'], ['pointer']);
var emptyArray = allocUninitialized(0, elwpMeta)[0];
log({ stage: 'emptyArray', value: emptyArray.toString() });

/* ---------- find the live Account (Messages instance preferred) ---------- */
function addrOf(m) { return (m && m.address) ? m.address : m; }
function bytesOfPointer(p) {
  var s = p.toString(16);
  if (s.length % 2) s = '0' + s;
  var out = '';
  for (var i = s.length - 2; i >= 0; i -= 2) out += s.substr(i, 2);
  while (out.length < 16) out += '00';
  return out;
}
function validAccount(a) {
  try {
    var ns = a.add(0xf8).readU32();
    var peer = a.add(0x100).readPointer();
    if (ns !== 0 || !peer.equals(ptr(CONFIG.accountPeer))) return false;
    var isa = a.readPointer();
    return !!Process.findRangeByAddress(isa);
  } catch (e) { return false; }
}
function scanRanges(pattern, cb) {
  var ranges = Process.enumerateRanges('rw-');
  for (var ri = 0; ri < ranges.length; ri++) {
    var ms;
    try { ms = Memory.scanSync(ranges[ri].base, ranges[ri].size, pattern); } catch (e) { continue; }
    for (var mi = 0; mi < ms.length; mi++) cb(addrOf(ms[mi]), ranges[ri]);
  }
}

var accountMeta = safe('AccountMeta', function () {
  return new NativeFunction(core.base.add(CONFIG.coreAccountMeta), 'pointer', [])();
});
var accountMetaPtr = accountMeta.ok ? accountMeta.value : ptr(0);
log({ stage: 'accountMeta', metadata: accountMetaPtr.toString(), error: accountMeta.ok ? null : accountMeta.error });

var messages = null;
var account = null;
var peerNamespace = 0;

/* 1) Messages instances via the class metadata. */
var messagesCandidates = [];
try {
  scanRanges(bytesOfPointer(messagesMeta), function (obj, range) {
    var rec = { obj: obj.toString(), range: range.base.toString() };
    try {
      var a = obj.add(16).readPointer();
      rec.account = a.toString();
      rec.ns = a.add(0xf8).readU32();
      rec.peer = a.add(0x100).readPointer().toString();
      rec.ok = validAccount(a);
    } catch (e) { rec.err = String(e); }
    messagesCandidates.push(rec);
    if (!account && rec.ok) {
      messages = obj;
      account = obj.add(16).readPointer();
      peerNamespace = 0;
    }
  });
} catch (e) { log({ stage: 'messagesScanError', error: String(e) }); }
log({ stage: 'messagesInstances', count: messagesCandidates.length, candidates: messagesCandidates.slice(0, 10) });

/* 2) Account instances via TelegramCore.Account metadata. */
var accountCandidates = [];
if (!account && !accountMetaPtr.isNull()) {
  try {
    scanRanges(bytesOfPointer(accountMetaPtr), function (obj, range) {
      var rec = { obj: obj.toString(), range: range.base.toString() };
      try {
        rec.ns = obj.add(0xf8).readU32();
        rec.peer = obj.add(0x100).readPointer().toString();
        rec.ok = validAccount(obj);
      } catch (e) { rec.err = String(e); }
      accountCandidates.push(rec);
      if (!account && rec.ok) { account = obj; peerNamespace = 0; }
    });
  } catch (e) { log({ stage: 'accountScanError', error: String(e) }); }
}
log({ stage: 'accounts', count: accountCandidates.length, candidates: accountCandidates.slice(0, 10) });

/* 3) Last resort: the peer value in memory, account = hit - 0x100. */
if (!account) {
  var peerCandidates = [];
  try {
    scanRanges(bytesOfPointer(ptr(CONFIG.accountPeer)), function (hit, range) {
      var cand = hit.sub(0x100);
      var rec = { hit: hit.toString(), account: cand.toString() };
      try {
        rec.isa = cand.readPointer().toString();
        rec.ns = cand.add(0xf8).readU32();
        rec.peer = cand.add(0x100).readPointer().toString();
        rec.ok = validAccount(cand);
      } catch (e) { rec.err = String(e); }
      peerCandidates.push(rec);
      if (!account && rec.ok) { account = cand; peerNamespace = 0; }
    });
  } catch (e) { log({ stage: 'peerScanError', error: String(e) }); }
  log({ stage: 'peerCandidates', count: peerCandidates.length, candidates: peerCandidates.slice(0, 10) });
}

if (!account) throw new Error('no live Account/Messages instance for account peer ' + CONFIG.accountPeer);
log({ stage: 'accountChosen', messages: messages ? messages.toString() : null,
      account: account.toString(), namespace: peerNamespace });

/* ---------- build [EngineLocalWidgetPost] (CONFIG.count elements) ---------- */
var arrayAlloc = allocUninitialized(CONFIG.count, elwpMeta);
var arrayStorage = arrayAlloc[0];
var elements = arrayAlloc[1];
log({ stage: 'array', count: CONFIG.count, storage: arrayStorage.toString(), elements: elements.toString() });

var htmlBytes = Memory.allocUtf8String(CONFIG.html);
var htmlString = stringFromCString(htmlBytes);
var emptyString = stringFromCString(Memory.allocUtf8String(''));

/* element layout (from the shipped metadata):
   0x00 html String (16) | 0x10 width i32 | 0x14 height i32 |
   0x18 caption String (16) | 0x28 photos Array |
   0x30 isCopy | 0x31 canQuery | 0x32 backgroundQuery |
   0x38 chatData Data? (16) | 0x48 publicData Data? (16) | 0x58 captionAbove */
for (var ei = 0; ei < CONFIG.count; ei++) {
  var el = elements.add(ei * 0x60);
  el.writeByteArray(new Uint8Array(0x60));
  el.writePointer(htmlString[0]);
  el.add(8).writePointer(htmlString[1]);
  el.add(0x10).writeU32(CONFIG.width | 0);
  el.add(0x14).writeU32(CONFIG.height | 0);
  el.add(0x18).writePointer(emptyString[0]);
  el.add(0x20).writePointer(emptyString[1]);
  el.add(0x28).writePointer(emptyArray);
  el.add(0x30).writeU8(0);
  el.add(0x31).writeU8(0);
  el.add(0x32).writeU8(0);
  el.add(0x38).writeByteArray(new Uint8Array(16));
  el.add(0x48).writeByteArray(new Uint8Array(16));
  el.add(0x58).writeU8(0);
}

/* ---------- call the outlined implementation ----------
   (account, chatPeer.namespace, chatPeer.id, posts)  [swiftself is not used]
   accountPeer is only used to FIND the live Account/Messages; the message is
   inserted into chatPeer (the bot chat for "test"). */
var impl = new NativeFunction(implAddress, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
var signalCall = safe('impl', function () {
  return impl(account, ptr(CONFIG.chatNamespace), ptr(CONFIG.chatPeer), arrayStorage);
});
if (!signalCall.ok) { log(signalCall); throw new Error('impl failed'); }
var signal = signalCall.value;
log({ stage: 'signal', value: signal.toString(), null: signal.isNull() });
if (signal.isNull()) throw new Error('null Signal');

if (CONFIG.capturePrintf) {
  var printfPtr = Module.findGlobalExportByName('printf');
  if (printfPtr) {
    try {
      Interceptor.attach(printfPtr, {
        onEnter: function (args) {
          try {
            var s = args[0].readCString();
            if (s && /N1IOS|IOS_N1|ABV k=|ABLEN|RESULT|NOCOR/.test(s)) {
              log({ stage: 'printf', text: s });
            }
          } catch (e) {}
        }
      });
      log({ stage: 'printfHook', address: printfPtr.toString() });
    } catch (e) { log({ stage: 'printfHook', error: String(e) }); }
  } else {
    log({ stage: 'printfHook', error: 'printf not found' });
  }
}

if (CONFIG.start) {
  /* x20 = swiftself trampoline: fn(arg0..) with x20 = arg1 */
  var page = Memory.alloc(Process.pageSize);
  function writeTrampoline() {
    var w = new Arm64Writer(page);
    w.putMovRegReg('x16', 'x0');
    w.putMovRegReg('x20', 'x1');
    w.putMovRegReg('x0', 'x2');
    w.putMovRegReg('x1', 'x3');
    w.putMovRegReg('x2', 'x4');
    w.putMovRegReg('x3', 'x5');
    w.putMovRegReg('x4', 'x6');
    w.putMovRegReg('x5', 'x7');
    w.putBrReg('x16');
    w.flush();
  }
  var patched = safe('patchCode', function () {
    Memory.patchCode(page, 64, writeTrampoline);
    return true;
  });
  if (!patched.ok) {
    log({ stage: 'patchCode', error: patched.error });
    var protectedPage = safe('protect', function () {
      Memory.protect(page, Process.pageSize, 'rwx');
      writeTrampoline();
      return true;
    });
    if (!protectedPage.ok) { log({ stage: 'protect', error: protectedPage.error }); throw new Error('no executable trampoline'); }
  }
  var trampoline = new NativeFunction(page, 'pointer',
    ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
  var started = safe('start', function () {
    return trampoline(signalStartAddress, signal,
                      ptr(0), ptr(0), ptr(0), ptr(0), ptr(0), ptr(0));
  });
  log({ stage: 'start', ok: started.ok, value: started.ok ? started.value.toString() : null,
        error: started.ok ? null : started.error });
} else {
  log({ stage: 'start', skipped: true });
}

log({ stage: 'done' });
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--html", default=DEFAULT_HTML)
    ap.add_argument("--account-peer", type=lambda s: int(s, 0), default=0,
                    help="account/self peer used to find the live Account/Messages (default 0)")
    ap.add_argument("--chat-peer", type=lambda s: int(s, 0), default=0,
                    help="chat peer the message is inserted into (default 0, <BOT_USERNAME>)")
    ap.add_argument("--chat-namespace", type=int, default=0,
                    help="PeerId namespace of the chat peer (0 for a user/bot)")
    ap.add_argument("--peer", type=lambda s: int(s, 0), default=None,
                    help=argparse.SUPPRESS)  # deprecated alias for --chat-peer
    ap.add_argument("--no-start", action="store_true")
    ap.add_argument("--capture-printf", action="store_true",
                    help="hook libc printf to capture the widget's N1IOS/ABV marker without DVT")
    ap.add_argument("--settle", type=float, default=6.0,
                    help="seconds to keep the script loaded after start (async transaction/widget)")
    ap.add_argument("--count", type=int, default=1,
                    help="number of EngineLocalWidgetPost elements to insert in one call")
    ap.add_argument("--width", type=int, default=0)
    ap.add_argument("--height", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    html = open(args.html, "r", encoding="utf-8").read()
    if "\x00" in html:
        raise SystemExit("HTML contains NUL; String(cString:) would truncate")
    if args.peer is not None:
        args.chat_peer = args.peer
    print("payload: %s (%d bytes)" % (args.html, len(html)))
    print("account peer (discovery): %d; chat peer (insert): %d ns=%d"
          % (args.account_peer, args.chat_peer, args.chat_namespace))

    config = {
        "html": html,
        "accountPeer": args.account_peer,
        "chatPeer": args.chat_peer,
        "chatNamespace": args.chat_namespace,
        "count": args.count,
        "width": args.width,
        "height": args.height,
        "coreMessagesMeta": CORE_MESSAGES_META_ACCESSOR,
        "coreElwpMeta": CORE_ELWP_META_ACCESSOR,
        "coreAccountMeta": CORE_ACCOUNT_META_ACCESSOR,
        "coreImpl": CORE_DEBUG_INSERT_IMPL,
        "sskStart": SSK_SIGNAL_START,
        "start": not args.no_start,
        "capturePrintf": args.capture_printf,
    }
    source = JS_TEMPLATE.replace("__CONFIG__", json.dumps(config))

    device = frida.get_device_manager().add_remote_device("<LAN_IP>:27043")
    session = device.attach(args.pid)
    done = {"v": False}

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload")
            print("JS:", json.dumps(payload, ensure_ascii=False))
            if isinstance(payload, dict) and payload.get("stage") == "done":
                done["v"] = True
        elif msg.get("type") == "error":
            print("JS ERROR:", msg.get("stack") or msg.get("description"))

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    deadline = time.time() + args.timeout
    while time.time() < deadline and not done["v"]:
        time.sleep(0.2)
    if done["v"]:
        # The Postbox transaction and the widget's execution are asynchronous;
        # keep the script (and the printf hook) loaded so they can be observed.
        settle_until = time.time() + args.settle
        while time.time() < settle_until:
            time.sleep(0.2)
    script.unload()
    session.detach()
    if not done["v"]:
        raise SystemExit("timeout before delivery completed")
    print("OK: signal created%s; message insert is asynchronous on the Postbox queue"
          % ("" if args.no_start else " and started"))


if __name__ == "__main__":
    main()
