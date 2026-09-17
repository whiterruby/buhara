// Full-safe grup kripto çekirdeği (referans implementasyon)
// Model: tek paylaşılan grup anahtarı (AES-GCM-256) + cihaz başına imza anahtarı (ECDSA P-256)
// Server SADECE ciphertext görür. Node 20 + modern Safari/Chrome'da WebCrypto ile çalışır.
// Not: PWA -> aynı kod browser'da, Capacitor -> aynı kod native'de çalışır.

import { webcrypto } from "node:crypto";
const subtle = webcrypto.subtle;

const te = new TextEncoder();
const td = new TextDecoder();

export function b64e(bytes) {
  return Buffer.from(bytes).toString("base64");
}
export function b64d(s) {
  return new Uint8Array(Buffer.from(s, "base64"));
}

// 0) Oda şifresi -> grup anahtarı (PBKDF2-SHA256, 200k tur, browser ile aynı)
export async function deriveGroupKey(passphrase, saltText) {
  const base = await subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt: te.encode("bizim-grup-v1." + saltText), iterations: 200000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
}

// 1) Grup anahtarı: 256-bit AES-GCM, QR ile paylaşılacak şey budur.
export async function generateGroupKey() {
  return subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
export async function exportGroupKey(key) {
  return b64e(new Uint8Array(await subtle.exportKey("raw", key)));
}
export async function importGroupKey(b64) {
  return subtle.importKey("raw", b64d(b64), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}

// 2) Kimlik anahtarı: her cihazda 1 tane üretilir, public kısım grupta duyurulur.
// Amaç: ortak anahtar herkeste olduğu için "bunu kim yazdı" sahteciliğini önlemek.
export async function generateIdentity() {
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}
export async function exportIdentityPublic(keypair) {
  return b64e(new Uint8Array(await subtle.exportKey("raw", keypair.publicKey)));
}
export async function importIdentityPublic(b64) {
  return subtle.importKey("raw", b64d(b64), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

// 3) Şifreli + imzalı mesaj paketi
// wire format (JSON): { v:1, nonce, ct, sig, sender }
export async function encryptText(groupKey, identityPriv, senderId, plaintext) {
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv: nonce }, groupKey, te.encode(plaintext))
  );
  // imzalanacak veri: senderId + nonce + ct
  const payload = te.encode(senderId + "." + b64e(nonce) + "." + b64e(ct));
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identityPriv, payload));
  return { v: 1, nonce: b64e(nonce), ct: b64e(ct), sig: b64e(sig), sender: senderId };
}

export async function decryptText(groupKey, identityPub, packet) {
  if (packet.v !== 1) throw new Error("bilinmeyen paket versiyonu");
  const payload = te.encode(packet.sender + "." + packet.nonce + "." + packet.ct);
  const ok = await subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, identityPub, b64d(packet.sig), payload
  );
  if (!ok) throw new Error("İMZA GEÇERSİZ: sahte/bozuk mesaj");
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: b64d(packet.nonce) }, groupKey, b64d(packet.ct));
  return { sender: packet.sender, text: td.decode(pt) };
}

// 4) Dosya/resim: baytları aynı grup anahtarıyla, her dos tectonic fresh nonce ile.
// Büyük dosyada browser'da chunk'lanır, çekirdek aynı kalır.
export async function encryptBytes(groupKey, bytes) {
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, groupKey, bytes));
  return { nonce: b64e(nonce), ct: b64e(ct) };
}
export async function decryptBytes(groupKey, nonceB64, ctB64) {
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: b64d(nonceB64) }, groupKey, b64d(ctB64));
  return new Uint8Array(pt);
}
