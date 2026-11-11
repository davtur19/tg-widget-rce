/* ===== iOS debug: verify rt->malloc_state.size write ===== */
  setR(rt + 48n);
  Rb[0] = 0xffffffffffffffffn;
  var chk = RD(rt + 48n);
  setres('MS=' + hex(chk) + ' rt=' + hex(rt) + ' free=' + hex(rd64(rt + 16n)));
