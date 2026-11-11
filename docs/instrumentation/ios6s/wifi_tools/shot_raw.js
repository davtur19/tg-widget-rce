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
var msgPB = fn('objc_msgSend','pointer',['pointer','pointer','pointer','bool']);
var msgB  = fn('objc_msgSend','bool',['pointer','pointer']);
var msgU  = fn('objc_msgSend','ulong',['pointer','pointer']);
var sel = fn('sel_registerName','pointer',['pointer']);
var getClass = fn('objc_getClass','pointer',['pointer']);
var S = function(s){ return sel(Memory.allocUtf8String(s)); };
var C = function(c){ return getClass(Memory.allocUtf8String(c)); };

var out = {stage:'go'};
var UIApplication = C('UIApplication');
var app = msg0(UIApplication, S('sharedApplication'));
out.app = app.toString();
var wins = msg0(app, S('windows'));
var n = msgU(wins, S('count')).valueOf();
out.nwin = n;
var win = null;
for (var i=0;i<n;i++){
  var w = msgP(wins, S('objectAtIndex:'), ptr(i));
  if (msgB(w, S('isKeyWindow'))) { win = w; break; }
}
if (!win) win = msgP(wins, S('objectAtIndex:'), ptr(0));
out.win = win.toString();
var layer = msg0(win, S('layer'));
out.layer = layer.toString();

var begin = fn('UIGraphicsBeginImageContextWithOptions','void',['double','double','uchar','double']);
var getctx = fn('UIGraphicsGetCurrentContext','pointer',[]);
var getimg = fn('UIGraphicsGetImageFromCurrentImageContext','pointer',[]);
var endctx = fn('UIGraphicsEndImageContext','void',[]);
var png = fn('UIImagePNGRepresentation','pointer',['pointer']);
var tmpdir = fn('NSTemporaryDirectory','pointer',[]);

begin(375.0, 667.0, 0, 2.0);
var ctx = getctx();
out.ctx = ctx.toString();
msgP(layer, S('renderInContext:'), ctx);
var img = getimg();
endctx();
out.img = img.toString();
if (img.isNull()) { send({stage:'error', msg:'null image', out:out}); }
else {
  var data = png(img);
  out.data = data.toString();
  var tp = tmpdir();
  var cstr = tp.readUtf8String();
  var nsstr = msgP(C('NSString'), S('stringWithUTF8String:'), tp);
  var path = cstr + '/shot_' + Date.now() + '.png';
  var ok = msgPB(data, S('writeToFile:atomically:'), msgP(C('NSString'), S('stringWithUTF8String:'), Memory.allocUtf8String(path)), true);
  out.path = path; out.ok = ok; out.len = msgU(data, S('length')).valueOf();
  send({stage:'done', out:out});
}
