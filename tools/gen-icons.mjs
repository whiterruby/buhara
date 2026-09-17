// Bağımlılıksız PNG ikon üretici (node stdlib). Koyu zemin + altın göz motifi.
import { writeFileSync, mkdirSync } from "fs";
import { deflateSync, crc32 } from "zlib";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "pwa", "icons");
mkdirSync(OUT, { recursive: true });

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td) >>> 0);
  return Buffer.concat([len, td, crc]);
}
function png(w, h, rgba) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 4 + 1)] = 0;
    rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  }
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", (() => { const b = Buffer.alloc(13); b.writeUInt32BE(w, 0); b.writeUInt32BE(h, 4); b[8] = 8; b[9] = 6; return b; })()),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}
// Altın göz: badem (elips halka) + iris + parıltı, lacivert-siyah zemin
function draw(size) {
  const buf = Buffer.alloc(size * size * 4);
  const px = (x, y, r, g, b, a = 255) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    const i = (y * size + x) * 4;
    buf[i] = r; buf[i + 1] = g; buf[i + 2] = b; buf[i + 3] = a;
  };
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) px(x, y, 20, 19, 17);
  const cx = size / 2, cy = size / 2, S = size / 512;
  const gold = [240, 192, 122], terra = [224, 122, 106];
  // dış halka
  for (let a = 0; a < Math.PI * 2; a += 0.002) {
    const r = 200 * S;
    px(Math.round(cx + Math.cos(a) * r), Math.round(cy + Math.sin(a) * r), ...gold);
    px(Math.round(cx + Math.cos(a) * (r - 3 * S)), Math.round(cy + Math.sin(a) * (r - 3 * S)), ...gold);
  }
  // göz bademi: iki yay
  for (let x = -130; x <= 130; x++) {
    const t = x / 130, yy = Math.sin(Math.acos(Math.max(-1, Math.min(1, t)))) * 62;
    for (const s of [-1, 1]) for (let w = -2; w <= 2; w++)
      px(Math.round(cx + x * S), Math.round(cy + s * yy * S) + w, ...(s < 0 ? gold : terra));
  }
  // iris
  for (let y = -42; y <= 42; y++) for (let x = -42; x <= 42; x++) {
    if (x * x + y * y <= 42 * 42 * S * S) px(Math.round(cx + x), Math.round(cy + y), ...gold);
  }
  for (let y = -22; y <= 22; y++) for (let x = -22; x <= 22; x++) {
    if (x * x + y * y <= 22 * 22 * S * S) px(Math.round(cx + x), Math.round(cy + y), 20, 19, 17);
  }
  for (let y = -8; y <= 8; y++) for (let x = -8; x <= 8; x++) {
    if (x * x + y * y <= 64 * S * S) px(Math.round(cx + 8 * S + x), Math.round(cy - 8 * S + y), ...gold);
  }
  return buf;
}
for (const s of [180, 192, 512]) {
  writeFileSync(join(OUT, `icon-${s}.png`), png(s, s, draw(s)));
  console.log("icon-" + s + ".png OK");
}
writeFileSync(join(OUT, "apple-touch-icon.png"), png(180, 180, draw(180)));
console.log("apple-touch-icon.png OK");
