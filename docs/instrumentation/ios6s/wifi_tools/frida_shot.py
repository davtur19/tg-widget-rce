#!/usr/bin/env python3
"""Screenshot the key window of a remote (Wi-Fi) iOS app via Frida; save PNG in the app tmp dir."""
import argparse, sys, time, json
import frida

JS = r"""
'use strict';
function send_(o){ send(o); }
function sym(n){
  try { if (Module.findGlobalExportByName) { var p = Module.findGlobalExportByName(n); if (p) return p; } } catch(e){}
  try { if (Module.getGlobalExportByName) { var p2 = Module.getGlobalExportByName(n); if (p2) return p2; } } catch(e){}
  try { if (Module.findExportByName) { var p3 = Module.findExportByName(null, n); if (p3) return p3; } } catch(e){}
  try { var p4 = DebugSymbol.getFunctionByName(n); if (p4) return p4; } catch(e){}
  return null;
}
var done=false, out={};
try {
  ObjC.schedule(ObjC.mainQueue, function(){
    try {
      var app = ObjC.classes.UIApplication.sharedApplication();
      var wins = app.windows();
      var win = null, n = wins.count();
      var clsList = [];
      for (var i=0;i<n;i++){ var w=wins.objectAtIndex_(i); clsList.push(String(w.$className)); if (w.isKeyWindow()) { win = w; break; } }
      if (!win) win = wins.objectAtIndex_(0);
      out.windows = clsList;
      out.winClass = String(win.$className);
      var vc = win.rootViewController();
      var chain = [];
      for (var j=0;j<8 && vc;j++){ chain.push(String(vc.$className)); vc = vc.presentedViewController(); }
      out.vcChain = chain;
      var bounds = win.bounds();
      var fBegin = sym('UIGraphicsBeginImageContextWithOptions');
      var fGet = sym('UIGraphicsGetImageFromCurrentImageContext');
      var fEnd = sym('UIGraphicsEndImageContext');
      var fPng = sym('UIImagePNGRepresentation');
      out.syms = { begin: !!fBegin, get: !!fGet, end: !!fEnd, png: !!fPng };
      if (!fBegin || !fGet || !fPng) { out.error='missing syms'; done=true; return; }
      var begin = new NativeFunction(fBegin, 'void', ['pointer','bool','double']);
      var getimg = new NativeFunction(fGet, 'pointer', []);
      var endctx = new NativeFunction(fEnd, 'void', []);
      var png = new NativeFunction(fPng, 'pointer', ['pointer']);
      begin(bounds, false, 0.0);
      win.drawViewHierarchyInRect_afterScreenUpdates_(bounds, true);
      var img = getimg();
      endctx();
      if (!img || img.isNull()) { out.error='null image'; done=true; return; }
      var data = png(img);
      if (!data || data.isNull()) { out.error='null png data'; done=true; return; }
      var tmp = ObjC.classes.NSFileManager.defaultManager().temporaryDirectory().path().toString();
      var path = tmp + '/shot_' + Date.now() + '.png';
      var ok = new ObjC.Object(data).writeToFile_atomically_(path, true);
      out.path = path; out.wrote = !!ok; out.len = new ObjC.Object(data).length().valueOf();
    } catch(e) { out.error = String(e); }
    done = true;
  });
  var t0 = Date.now();
  while(!done && Date.now()-t0 < 15000) { Thread.sleep(0.05); }
  send_({stage:'shot', done: done, out: out});
} catch(e) { send_({stage:'fatal', error:String(e)}); }
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--host", default="<LAN_IP>:27043")
    ap.add_argument("--timeout", type=float, default=40.0)
    a = ap.parse_args()
    dev = frida.get_device_manager().add_remote_device(a.host)
    s = dev.attach(a.pid)
    got = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            print("JS:", json.dumps(m.get("payload"), ensure_ascii=False))
            got["x"] = True
        else:
            print("ERR:", m.get("description"))
    sc = s.create_script(JS)
    sc.on("message", on_msg)
    sc.load()
    t0 = time.time()
    while time.time()-t0 < a.timeout and "x" not in got:
        time.sleep(0.2)
    sc.unload(); s.detach()

main()
