'use strict';
function sym(n){
  try { if (Module.findGlobalExportByName) { var p = Module.findGlobalExportByName(n); if (p) return p; } } catch(e){}
  try { if (Module.getGlobalExportByName) { var p2 = Module.getGlobalExportByName(n); if (p2) return p2; } } catch(e){}
  try { if (Module.findExportByName) { var p3 = Module.findExportByName(null, n); if (p3) return p3; } } catch(e){}
  return null;
}
function fn(name, ret, args){ var p = sym(name); if (!p) throw new Error('no sym '+name); return new NativeFunction(p, ret, args); }
var msg0 = fn('objc_msgSend','pointer',['pointer','pointer']);
var msgP = fn('objc_msgSend','pointer',['pointer','pointer','pointer']);
var msgPB = fn('objc_msgSend','pointer',['pointer','pointer','pointer','uchar']);
var msgB  = fn('objc_msgSend','uchar',['pointer','pointer']);
var msgU  = fn('objc_msgSend','ulong',['pointer','pointer']);
var sel = fn('sel_registerName','pointer',['pointer']);
var getClass = fn('objc_getClass','pointer',['pointer']);
var S = function(s){ return sel(Memory.allocUtf8String(s)); };
var C = function(c){ return getClass(Memory.allocUtf8String(c)); };
var out = {};
function P(k,v){ out[k]=v; send({stage:'p', k:k, v:String(v)}); }
try {
  var app = msg0(C('UIApplication'), S('sharedApplication')); P('app', app);
  var wins = msg0(app, S('windows')); P('wins', wins);
  var n = msgU(wins, S('count')).valueOf(); P('nwin', n);
  var win = null;
  for (var i=0;i<n;i++){ var w = msgP(wins, S('objectAtIndex:'), ptr(i)); if (msgB(w, S('isKeyWindow'))) { win = w; break; } }
  if (!win) win = msgP(wins, S('objectAtIndex:'), ptr(0));
  P('win', win);
  var layer = msg0(win, S('layer')); P('layer', layer);
  var begin = fn('UIGraphicsBeginImageContextWithOptions','void',['double','double','uchar','double']);
  var getctx = fn('UIGraphicsGetCurrentContext','pointer',[]);
  var getimg = fn('UIGraphicsGetImageFromCurrentImageContext','pointer',[]);
  var endctx = fn('UIGraphicsEndImageContext','void',[]);
  var png = fn('UIImagePNGRepresentation','pointer',['pointer']);
  begin(375.0, 667.0, 0, 2.0);
  var ctx = getctx(); P('ctx', ctx);
  msgP(layer, S('renderInContext:'), ctx);
  var img = getimg(); P('img', img);
  endctx();
  if (img.isNull()) { send({stage:'error', msg:'null image'}); }
  else {
    var data = png(img); P('data', data);
    var path = '/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/tmp/h100.png';
    var nsstr = msgP(C('NSString'), S('stringWithUTF8String:'), Memory.allocUtf8String(path));
    var ok = msgPB(data, S('writeToFile:atomically:'), nsstr, 1);
    P('wrote', ok);
    P('len', msgU(data, S('length')).valueOf());
    P('path', path);
    send({stage:'done'});
  }
} catch(e) { send({stage:'fatal', error:String(e), stack:e.stack||''}); }
