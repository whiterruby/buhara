import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateGroupKey, exportGroupKey, importGroupKey, deriveGroupKey,
  generateIdentity, exportIdentityPublic, importIdentityPublic,
  encryptText, decryptText, encryptBytes, decryptBytes,
} from "../src/crypto/groupCrypto.mjs";

describe("grup kripto çekirdeği", () => {
  it("text gidiş-dönüş çalışır + imza doğrulanır", async () => {
    const gk = await generateGroupKey();
    const alice = await generateIdentity();
    const alicePub = await importIdentityPublic(await exportIdentityPublic(alice));
    const pkt = await encryptText(gk, alice.privateKey, "alice", "selam kanka 🖼️");
    const out = await decryptText(gk, alicePub, pkt);
    assert.equal(out.text, "selam kanka 🖼️");
    assert.equal(out.sender, "alice");
  });

  it("yanlış grup anahtarıyla çözülemez", async () => {
    const gk = await generateGroupKey();
    const other = await generateGroupKey();
    const alice = await generateIdentity();
    const alicePub = await importIdentityPublic(await exportIdentityPublic(alice));
    const pkt = await encryptText(gk, alice.privateKey, "alice", "gizli");
    await assert.rejects(() => decryptText(other, alicePub, pkt));
  });

  it("ciphertext kurcalanırsa imza patlar", async () => {
    const gk = await generateGroupKey();
    const alice = await generateIdentity();
    const alicePub = await importIdentityPublic(await exportIdentityPublic(alice));
    const pkt = await encryptText(gk, alice.privateKey, "alice", "para burada");
    pkt.ct = pkt.ct.slice(0, -4) + "AAAA"; // MITM kurcalaması
    await assert.rejects(() => decryptText(gk, alicePub, pkt), /İMZA/);
  });

  it("başkasının imzasıyla sahte mesaj yutturulamaz", async () => {
    const gk = await generateGroupKey();
    const alice = await generateIdentity();
    const mallory = await generateIdentity();
    const malloryPub = await importIdentityPublic(await exportIdentityPublic(mallory));
    const pkt = await encryptText(gk, alice.privateKey, "alice", "ben alice'im");
    // saldırgan alice'in paketini mallory'nin anahtarıyla doğrulamaya çalışır
    await assert.rejects(() => decryptText(gk, malloryPub, pkt), /İMZA/);
  });

  it("QR ile paylaşılan anahtar export/import sonrası çalışır", async () => {
    const gk = await generateGroupKey();
    const qrPayload = await exportGroupKey(gk); // QR'a basılan şey
    const gk2 = await importGroupKey(qrPayload); // diğer telefonda okutulan
    const alice = await generateIdentity();
    const alicePub = await importIdentityPublic(await exportIdentityPublic(alice));
    const pkt = await encryptText(gk, alice.privateKey, "alice", "qr testi");
    const out = await decryptText(gk2, alicePub, pkt);
    assert.equal(out.text, "qr testi");
  });

  it("oda şifresi deterministir, yanlış şifre çözemez", async () => {
    const a = await deriveGroupKey("kedi balkonda uyur 2026", "salt-test");
    const b = await deriveGroupKey("kedi balkonda uyur 2026", "salt-test");
    const alice = await generateIdentity();
    const alicePub = await importIdentityPublic(await exportIdentityPublic(alice));
    const pkt = await encryptText(a, alice.privateKey, "alice", "oda testi");
    const out = await decryptText(b, alicePub, pkt);
    assert.equal(out.text, "oda testi");
    const wrong = await deriveGroupKey("farklı şifre", "salt-test");
    await assert.rejects(() => decryptText(wrong, alicePub, pkt));
  });

  it("resim baytı gidiş-dönüş (1MB sahte resim)", async () => {
    const gk = await generateGroupKey();
    const fake = new Uint8Array(1024 * 1024).map((_, i) => i % 251);
    const enc = await encryptBytes(gk, fake);
    // server'da görünen şey: sadece base64 gürültü
    assert.ok(!Buffer.from(enc.ct, "base64").includes(Buffer.from("selam")));
    const dec = await decryptBytes(gk, enc.nonce, enc.ct);
    assert.deepEqual(dec, fake);
  });
});
