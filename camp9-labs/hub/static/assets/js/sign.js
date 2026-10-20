// NOTE: there are NO flags in this file.

function reveal(b) {
  // the signs are stored base64-encoded. Decode one round of base64.
  return atob(b);
}

function reveal2(b) {
  // the BACKUP relay scrambles twice — base64, then a byte mask (XOR 0x2a).
  var s = atob(b), out = "";
  for (var i = 0; i < s.length; i++) out += String.fromCharCode(s.charCodeAt(i) ^ 0x2a);
  return out;
}

(function () {
  try {
    var m = document.cookie.match(/(?:^|;\s*)__t=([^;]+)/);
    if (m) window.__s = m[1];
  } catch (e) {}
})();
