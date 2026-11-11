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
var msgU  = fn('objc_msgSend','ulong',['pointer','pointer']);
var sel = fn('sel_registerName','pointer',['pointer']);
var getClass = fn('objc_getClass','pointer',['pointer']);
var S = function(s){ return sel(Memory.allocUtf8String(s)); };
var C = function(c){ return getClass(Memory.allocUtf8String(c)); };

var out = {stage:'introspect'};
// 1) class existence + method list
var cls = C('WRSession');
out.wrsession = cls.toString();
if (!cls.isNull()) {
  var class_copyMethodList = fn('class_copyMethodList','pointer',['pointer','pointer']);
  var method_getName = fn('method_getName','pointer',['pointer']);
  var method_getTypeEncoding = fn('method_getTypeEncoding','pointer',['pointer']);
  var sel_getName = fn('sel_getName','pointer',['pointer']);
  var cnt = Memory.alloc(4); cnt.writeU32(0);
  var arr = class_copyMethodList(cls, cnt);
  var n = cnt.readU32();
  var names = [];
  for (var i=0;i<n && i<200;i++){
    var m = arr.add(i*8).readPointer();
    var nm = sel_getName(method_getName(m)).readUtf8String();
    var enc = method_getTypeEncoding(m);
    names.push(nm + ' ' + (enc.isNull()?'?':enc.readUtf8String()));
  }
  out.methodCount = n;
  out.methods = names;
}
// 2) walk the view hierarchy for WR/widget views
var app = msg0(C('UIApplication'), S('sharedApplication'));
var wins = msg0(app, S('windows'));
var wn = msgU(wins, S('count')).valueOf();
var found = [];
function walk(v, depth, path){
  if (!v || depth > 40) return;
  var cn = '?';
  try { cn = new ObjC.Object(v).$className; } catch(e) { try { cn = 'cls@'+msg0(v, S('class')).toString(); } catch(e2){} }
  if (cn && (String(cn).indexOf('WR') >= 0 || String(cn).toLowerCase().indexOf('widget') >= 0)) found.push({d:depth, c:String(cn), p:v.toString(), path:path});
  try {
    var subs = msg0(v, S('subviews'));
    var k = msgU(subs, S('count')).valueOf();
    for (var j=0;j<k;j++){ walk(msgP(subs, S('objectAtIndex:'), ptr(j)), depth+1, path+'/'+j); }
  } catch(e){}
}
for (var w=0; w<wn; w++){ walk(msgP(wins, S('objectAtIndex:'), ptr(w)), 0, 'w'+w); }
out.found = found.slice(0, 60);
out.foundCount = found.length;
send(out);
