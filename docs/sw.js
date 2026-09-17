/* v1 — local dosyaları cache'ler, CDN ve API'yi ağdan alır */
const V = "bizim-grup-v1";
const LOCAL = ["./", "./index.html", "./chat.html", "./styles.css", "./crypto.js", "./chat.js", "./config.js", "./manifest.webmanifest", "./pharaoh-bg.webp", "./icons/icon-192.png", "./icons/icon-512.png"];
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(V).then((c) => c.addAll(LOCAL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== V).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin) return; // supabase + esm.sh hep ağdan
  e.respondWith(
    fetch(e.request).then((r) => {
      const copy = r.clone();
      caches.open(V).then((c) => c.put(e.request, copy));
      return r;
    }).catch(() => caches.match(e.request).then((m) => m || caches.match("./index.html")))
  );
});
