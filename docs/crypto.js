// Browser E2E çekirdek (node'lu dosyanın browser ikizi, globalThis.crypto kullanır)
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder(), td = new TextDecoder();
const b64e = (b) => btoa(String.fromCharCode(...b));
const b64d = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export const b64 = { e: b64e, d: b64d };
// Oda şifresi -> grup anahtarı (PBKDF2-SHA256, 200k tur). Üçünüz aynı cümlede
// anlaşırsınız, server'a asla gönderilmez. Salt açıktır (grup id), güvenlik şifrede.
export async function deriveGroupKey(passphrase, saltText){
  const base = await subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({name:"PBKDF2",salt:te.encode("bizim-grup-v1."+saltText),iterations:200000,hash:"SHA-256"}, base, {name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]);
}
export async function generateGroupKey(){ return subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]); }
export async function exportGroupKey(k){ return b64e(new Uint8Array(await subtle.exportKey("raw",k))); }
export async function importGroupKey(s){ return subtle.importKey("raw",b64d(s),{name:"AES-GCM"},true,["encrypt","decrypt"]); }
export async function generateIdentity(){ return subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]); }
export async function exportIdentityPublic(kp){ return b64e(new Uint8Array(await subtle.exportKey("raw",kp.publicKey))); }
export async function importIdentityPublic(s){ return subtle.importKey("raw",b64d(s),{name:"ECDSA",namedCurve:"P-256"},true,["verify"]); }
export async function encryptText(gk,priv,sender,plain){
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({name:"AES-GCM",iv:nonce},gk,te.encode(plain)));
  const payload = te.encode(sender+"."+b64e(nonce)+"."+b64e(ct));
  const sig = new Uint8Array(await subtle.sign({name:"ECDSA",hash:"SHA-256"},priv,payload));
  return {v:1,nonce:b64e(nonce),ct:b64e(ct),sig:b64e(sig),sender};
}
export async function decryptText(gk,pub,p){
  const ok = await subtle.verify({name:"ECDSA",hash:"SHA-256"},pub,b64d(p.sig),te.encode(p.sender+"."+p.nonce+"."+p.ct));
  if(!ok) throw new Error("İMZA GEÇERSİZ");
  return td.decode(await subtle.decrypt({name:"AES-GCM",iv:b64d(p.nonce)},gk,b64d(p.ct)));
}
export async function encryptBytes(gk,bytes){
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  return {nonce:b64e(nonce),ct:b64e(new Uint8Array(await subtle.encrypt({name:"AES-GCM",iv:nonce},gk,bytes)))};
}
export async function decryptBytes(gk,nonce,ct){
  return new Uint8Array(await subtle.decrypt({name:"AES-GCM",iv:b64d(nonce)},gk,b64d(ct)));
}
// ---- katılım protokolü: grup anahtarını yeni cihaza ECDH ile sarma ----
// Server sadece sarmalanmış anahtarı görür, açamaz.
export async function genJoinKey(){
  const kp = await subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]);
  return { priv: kp.privateKey, pub: b64e(new Uint8Array(await subtle.exportKey("raw",kp.publicKey))),
           jwk: await subtle.exportKey("jwk",kp.privateKey) };
}
export async function importJoinPriv(jwk){
  return subtle.importKey("jwk",jwk,{name:"ECDH",namedCurve:"P-256"},true,["deriveKey"]);
}
export async function importJoinPub(s){
  return subtle.importKey("raw",b64d(s),{name:"ECDH",namedCurve:"P-256"},true,[]);
}
export async function wrapGroupKey(gkRawB64, devicePubB64){
  const eph = await subtle.generateKey({name:"ECDH",namedCurve:"P-256"},false,["deriveKey"]);
  const aes = await subtle.deriveKey({name:"ECDH",public:await importJoinPub(devicePubB64)},eph.privateKey,{name:"AES-GCM",length:256},false,["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({name:"AES-GCM",iv:nonce},aes,b64d(gkRawB64)));
  return { eph: b64e(new Uint8Array(await subtle.exportKey("raw",eph.publicKey))), nonce: b64e(nonce), ct: b64e(ct) };
}
export async function unwrapGroupKey(wrap, joinPriv){
  const aes = await subtle.deriveKey({name:"ECDH",public:await importJoinPub(wrap.eph)},joinPriv,{name:"AES-GCM",length:256},false,["decrypt"]);
  return b64e(new Uint8Array(await subtle.decrypt({name:"AES-GCM",iv:b64d(wrap.nonce)},aes,b64d(wrap.ct))));
}
