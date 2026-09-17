import * as C from "./crypto.js";
const $ = (id) => document.getElementById(id);
const log = (m) => { $("log").textContent += m + "\n"; };
let GK = null, ID = null, IDpubB64 = null;
const peers = {}; // senderId -> CryptoKey public

async function load() {
  const g = localStorage.getItem("gkey");
  if (g) { GK = await C.importGroupKey(g); log("kayıtlı grup anahtarı yüklendi"); }
  const privJwk = localStorage.getItem("priv");
  if (privJwk) {
    const priv = await crypto.subtle.importKey("jwk", JSON.parse(privJwk), {name:"ECDSA",namedCurve:"P-256"}, true, ["sign"]);
    const pub = await crypto.subtle.importKey("jwk", JSON.parse(localStorage.getItem("pub")), {name:"ECDSA",namedCurve:"P-256"}, true, ["verify"]);
    ID = { privateKey: priv, publicKey: pub };
    IDpubB64 = localStorage.getItem("pubB64");
  } else {
    ID = await C.generateIdentity();
    const pj = await crypto.subtle.exportKey("jwk", ID.privateKey);
    const qj = await crypto.subtle.exportKey("jwk", ID.publicKey);
    localStorage.setItem("priv", JSON.stringify(pj));
    localStorage.setItem("pub", JSON.stringify(qj));
    IDpubB64 = await C.exportIdentityPublic(ID);
    localStorage.setItem("pubB64", IDpubB64);
    log("bu cihaz kimliği: " + IDpubB64.slice(0,16) + "...");
  }
  peers["ben"] = ID.publicKey;
}
$("newkey").onclick = async () => { GK = await C.generateGroupKey(); localStorage.setItem("gkey", await C.exportGroupKey(GK)); log("yeni grup anahtarı üretildi + kaydedildi"); };
$("showkey").onclick = async () => { if(!GK) return log("önce anahtar üret"); prompt("bunu arkadaşına güvenli kanaldan ver (QR yerine):", await C.exportGroupKey(GK)); };
$("savekey").onclick = async () => { const v = $("inkey").value.trim(); GK = await C.importGroupKey(v); localStorage.setItem("gkey", v); log("anahtar kaydedildi"); };
$("send").onclick = async () => {
  if(!GK) return log("anahtar yok!");
  const pkt = await C.encryptText(GK, ID.privateKey, "ben", $("msg").value);
  localStorage.setItem("last", JSON.stringify(pkt));
  const back = await C.decryptText(GK, ID.publicKey, pkt); // lokal roundtrip
  log("ben: " + back);
  $("msg").value = "";
};
$("sendimg").onclick = async () => {
  if(!GK) return log("anahtar yok!");
  const f = $("img").files[0]; if(!f) return log("dosya seç");
  const buf = new Uint8Array(await f.arrayBuffer());
  const enc = await C.encryptBytes(GK, buf);
  const dec = await C.decryptBytes(GK, enc.nonce, enc.ct);
  log(`resim ${f.name} ${buf.length}B -> şifreli ${enc.ct.length}ch -> çözüldü ${dec.length}B OK:${dec.length===buf.length}`);
};
load();
