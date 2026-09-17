import * as C from "./crypto.js";
import { SUPABASE_URL, SUPABASE_ANON, DEFAULT_GROUP_ID, NAMES } from "./config.js";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const $ = (id) => document.getElementById(id);
const GID = DEFAULT_GROUP_ID;
const sb = createClient(SUPABASE_URL, SUPABASE_ANON);

let GK = null, ID = null, IDpubB64 = null, UID = null;
let peers = JSON.parse(localStorage.getItem("peers") || "{}");
const seenIds = new Set();
const msgCache = []; // {id, ts, sender, kind, text, edited, row, box, seenEl}
let peerSeen = {};
let seenTimer = null, liveCh = null, typing = false, typeTimer = null;
let replyTo = null, editingId = null;
const SEND_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 3 10.5 13.5"/><path d="M21 3 14 21l-3.5-7.5L3 10 21 3Z"/></svg>`;
const myName = () => NAMES[UID] || "Arkadaş";
const nameOf = (uid) => (uid === UID ? "Sen" : (NAMES[uid] || "Arkadaş"));
const hhmm = (iso) => new Date(iso).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });

function show(view) {
  for (const v of ["login", "chat"]) $("view-" + v).classList.toggle("hidden", v !== view);
}
function setStatus(ok, text) {
  $("statusDot")?.classList.toggle("on", ok);
  if ($("statusText")) $("statusText").textContent = text;
}

async function loadIdentity() {
  const pj = localStorage.getItem("priv"), qj = localStorage.getItem("pub");
  if (pj && qj) {
    ID = { privateKey: await crypto.subtle.importKey("jwk", JSON.parse(pj), { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]),
           publicKey: await crypto.subtle.importKey("jwk", JSON.parse(qj), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]) };
    IDpubB64 = localStorage.getItem("pubB64");
  } else {
    const kp = await C.generateIdentity();
    ID = kp;
    localStorage.setItem("priv", JSON.stringify(await crypto.subtle.exportKey("jwk", kp.privateKey)));
    localStorage.setItem("pub", JSON.stringify(await crypto.subtle.exportKey("jwk", kp.publicKey)));
    IDpubB64 = await C.exportIdentityPublic(kp);
    localStorage.setItem("pubB64", IDpubB64);
  }
}
async function loadSavedKey() {
  const g = localStorage.getItem("gkey");
  if (g) GK = await C.importGroupKey(g);
}
async function peerKey(uid, pubB64) {
  if (!peers[uid]) { peers[uid] = pubB64; localStorage.setItem("peers", JSON.stringify(peers)); }
  else if (peers[uid] !== pubB64) throw new Error("kişi anahtarı değişmiş");
  return C.importIdentityPublic(peers[uid]);
}

async function ensureGroupKey() {
  if (GK) return true;
  const { data } = await sb.from("group_keys").select("enc_key").eq("group_id", GID).single();
  if (data?.enc_key) { GK = await C.importGroupKey(data.enc_key); return true; }
  const local = localStorage.getItem("gkey");
  const raw = local || await C.exportGroupKey(await C.generateGroupKey());
  const { error } = await sb.from("group_keys").insert({ group_id: GID, enc_key: raw });
  if (error) return false;
  localStorage.setItem("gkey", raw);
  GK = await C.importGroupKey(raw);
  return true;
}

/* ---- balonlar ---- */
function mountBubble(me, who, id) {
  const d = document.createElement("div");
  d.className = "bubble " + (me ? "me" : "them");
  d.dataset.mid = id;
  if (!me) { const w = document.createElement("div"); w.className = "who"; w.textContent = who; d.appendChild(w); }
  const seen = document.createElement("div"); seen.className = "seen"; d.appendChild(seen);
  d.addEventListener("click", (e) => {
    if (e.target.closest("a, video")) return; // link/video kendi işini yapar
    openSheet(id);
  });
  $("log").appendChild(d); $("log").scrollTop = 1e9;
  return { box: d, seen };
}
function clearBubble(box) {
  [...box.childNodes].forEach((n) => {
    if (n.nodeType === 3) n.remove();
    else if (!(n.classList?.contains("who") || n.classList?.contains("seen"))) n.remove();
  });
}
function addQuote(box, seen, reply) {
  const q = document.createElement("div"); q.className = "quote";
  const w = document.createElement("div"); w.className = "who"; w.textContent = reply.name;
  const t = document.createElement("div"); t.className = "txt"; t.textContent = reply.text;
  q.appendChild(w); q.appendChild(t);
  q.addEventListener("click", (e) => {
    e.stopPropagation();
    const target = document.querySelector(`[data-mid="${reply.id}"]`);
    if (target) { target.scrollIntoView({ behavior: "smooth", block: "center" }); target.classList.remove("flash"); void target.offsetWidth; target.classList.add("flash"); }
  });
  box.insertBefore(q, seen);
}
function paintMeta(m) {
  let s = hhmm(m.ts) + (m.edited ? " · düzenlendi" : "");
  const names = [];
  for (const [uid, ts] of Object.entries(peerSeen)) {
    if (uid === UID || !ts) continue;
    // bu balon, kişinin gördüğü en son balonsa ismini yaz
    let best = null;
    for (const x of msgCache) { if (x.ts <= ts && (!best || x.ts > best.ts)) best = x; }
    if (best && best.id === m.id) names.push(nameOf(uid));
  }
  if (names.length) s += "\nGördü: " + names.join(", ");
  m.seenEl.textContent = s;
}
function paintSeen() { for (const m of msgCache) paintMeta(m); $("log").scrollTop = $("log").scrollHeight; }
function touchSeen(latestTs) {
  if (!latestTs) return;
  clearTimeout(seenTimer);
  seenTimer = setTimeout(async () => {
    peerSeen[UID] = latestTs;
    await sb.from("read_state").upsert({ group_id: GID, user_id: UID, last_seen_at: latestTs }, { onConflict: "group_id,user_id" });
  }, 800);
}

async function decryptRow(row) {
  const pub = await peerKey(row.sender_id, row.packet.pub);
  if (row.kind === "text" || row.kind === "location") {
    return { text: await C.decryptText(GK, pub, row.packet) };
  }
  if (row.kind === "gif" && !row.media_path) {
    return { text: "", url: await C.decryptText(GK, pub, row.packet) };
  }
  const { data, error } = await sb.storage.from("chat-media").download(row.media_path);
  if (error) throw error;
  const pt = await C.decryptBytes(GK, row.media_nonce, await data.text());
  let cap = "";
  try { cap = await C.decryptText(GK, pub, row.packet); if (cap === "Resim" || cap === "Video" || cap === "📷" || cap === "🎬") cap = ""; } catch {}
  return { text: cap, url: URL.createObjectURL(new Blob([pt], { type: row.kind === "video" ? "video/mp4" : "image/*" })) };
}

function fillBubble(m, row, dec) {
  clearBubble(m.box);
  const { box, seenEl: seen } = m;
  if (row.packet?.reply) addQuote(box, seen, row.packet.reply);
  if (row.kind === "text") {
    box.insertBefore(document.createTextNode(dec.text), seen);
  } else if (row.kind === "location" && dec.text.startsWith("geo:")) {
    const [lat, lon] = dec.text.slice(4).split(",");
    const a = document.createElement("a"); a.className = "loc"; a.target = "_blank"; a.rel = "noopener";
    a.href = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`;
    a.textContent = "Konum paylaşıldı — haritada aç";
    box.insertBefore(a, seen);
  } else if (row.kind === "image" || row.kind === "gif" || row.kind === "video") {
    let el;
    if (row.kind === "video") { el = document.createElement("video"); el.controls = true; el.preload = "metadata"; el.src = dec.url; }
    else { el = document.createElement("img"); el.loading = "lazy"; el.src = dec.url; }
    box.insertBefore(el, seen);
    if (dec.text) box.insertBefore(document.createTextNode(dec.text), seen);
  }
  m.text = dec.text || ""; m.edited = !!row.edited; m.row = row;
  paintMeta(m);
}

async function renderRow(row) {
  if (!row || seenIds.has(row.id)) return true;
  try {
    const me = row.sender_id === UID;
    const { box, seen } = mountBubble(me, nameOf(row.sender_id), row.id);
    const m = { id: row.id, ts: row.created_at, sender: row.sender_id, kind: row.kind, text: "", edited: !!row.edited, row, box, seenEl: seen };
    msgCache.push(m);
    fillBubble(m, row, await decryptRow(row));
    seenIds.add(row.id);
    paintSeen(); touchSeen(row.created_at);
    return true;
  } catch { return false; }
}
async function updateRow(row) {
  const m = msgCache.find((x) => x.id === row.id);
  if (!m) return renderRow(row);
  try { fillBubble(m, row, await decryptRow(row)); paintSeen(); } catch {}
}
function removeRow(id) {
  const i = msgCache.findIndex((x) => x.id === id);
  if (i < 0) return;
  msgCache[i].box.remove();
  msgCache.splice(i, 1);
  seenIds.delete(id);
  paintSeen();
}

/* ---- mesaj işlemleri (Telegram tarzı) ---- */
function closeSheet() { $("sheet").classList.add("hidden"); $("sheetBtns").innerHTML = ""; }
$("sheetCancel").onclick = closeSheet;
$("sheet").addEventListener("click", (e) => { if (e.target.id === "sheet") closeSheet(); });
function sheetBtn(label, cls, fn) {
  const b = document.createElement("button");
  b.textContent = label; if (cls) b.className = cls;
  b.onclick = fn; $("sheetBtns").appendChild(b);
  return b;
}
function openSheet(id) {
  const m = msgCache.find((x) => x.id === id);
  if (!m) return;
  closeSheet();
  const mine = m.sender === UID;
  sheetBtn("Yanıtla", "ghost", () => {
    replyTo = { id: m.id, name: nameOf(m.sender), text: m.kind === "text" ? m.text : ({ image: "Resim", video: "Video", gif: "GIF", location: "Konum" }[m.kind] || "Mesaj") };
    editingId = null; $("send").innerHTML = SEND_SVG;
    $("composeTitle").textContent = "Yanıt: " + replyTo.name;
    $("composeText").textContent = replyTo.text.slice(0, 120);
    $("composeBar").classList.remove("hidden");
    closeSheet(); $("msg").focus();
  });
  if (m.kind === "text" || m.kind === "location") sheetBtn("Kopyala", "ghost", () => {
    navigator.clipboard?.writeText(m.text).catch(() => {});
    closeSheet();
  });
  if (mine && m.kind === "text") sheetBtn("Düzenle", "ghost", () => {
    editingId = m.id; replyTo = null;
    $("msg").value = m.text;
    $("send").textContent = "✓";
    $("composeTitle").textContent = "Düzenleniyor";
    $("composeText").textContent = m.text.slice(0, 120);
    $("composeBar").classList.remove("hidden");
    closeSheet(); $("msg").focus();
  });
  if (mine) {
    const del = sheetBtn("Sil", "ghost danger", () => {
      del.textContent = "Emin misin? Herkesten silinsin mi?";
      del.className = "confirm";
      del.onclick = async () => {
        closeSheet(); cancelCompose();
        const path = m.row.media_path;
        await sb.from("messages").delete().eq("id", m.id);
        if (path) sb.storage.from("chat-media").remove([path]).then(() => {});
      };
    });
  }
  $("sheet").classList.remove("hidden");
}
function cancelCompose() {
  replyTo = null; editingId = null;
  $("msg").value = "";
  $("send").innerHTML = SEND_SVG;
  $("composeBar").classList.add("hidden");
}
$("composeCancel").onclick = cancelCompose;

/* ---- çevrimiçi + yazıyor ---- */
function paintLive(state) {
  const others = [];
  for (const arr of Object.values(state)) for (const p of arr) {
    if (p.uid !== UID && !others.find((o) => o.uid === p.uid)) others.push(p);
  }
  const box = $("onlineBox");
  if (!others.length) box.classList.add("hidden");
  else {
    box.classList.remove("hidden");
    const row = $("onlineRow"); row.innerHTML = "";
    for (const o of others) {
      const c = document.createElement("span");
      c.className = "chip" + (o.typing ? " typing" : "");
      const dot = document.createElement("i"); c.appendChild(dot);
      c.appendChild(document.createTextNode(o.name + (o.typing ? " yazıyor" : " çevrimiçi")));
      row.appendChild(c);
    }
  }
  const writers = others.filter((o) => o.typing).map((o) => o.name);
  const tb = $("typingBar");
  if (!writers.length) { tb.classList.add("hidden"); tb.innerHTML = ""; }
  else {
    tb.classList.remove("hidden"); tb.innerHTML = "";
    tb.appendChild(document.createTextNode(writers.join(", ") + " yazıyor"));
    const d = document.createElement("span"); d.className = "dots"; tb.appendChild(d);
  }
}
function joinLive() {
  if (liveCh) sb.removeChannel(liveCh);
  liveCh = sb.channel("live-" + GID);
  liveCh.on("presence", { event: "sync" }, () => paintLive(liveCh.presenceState()));
  liveCh.subscribe(async (st) => {
    if (st === "SUBSCRIBED") { typing = false; await liveCh.track({ uid: UID, name: myName(), typing: false }); }
  });
}
function setTyping(on) {
  if (!liveCh || typing === on) return;
  typing = on;
  liveCh.track({ uid: UID, name: myName(), typing: on }).catch(() => {});
}
function pokeTyping() {
  setTyping(true);
  clearTimeout(typeTimer);
  typeTimer = setTimeout(() => setTyping(false), 2500);
}

/* ---- sohbet ---- */
async function enterChat() {
  show("chat"); setStatus(true, "bağlı ✓");
  $("log").innerHTML = ""; seenIds.clear(); msgCache.length = 0; peerSeen = {};
  cancelCompose();
  const { data, error } = await sb.from("messages").select("*").eq("group_id", GID).order("created_at", { ascending: true }).limit(200);
  if (error) { setStatus(false, "okunamadı"); return; }
  for (const r of data) await renderRow(r);
  const { data: seen } = await sb.from("read_state").select("*").eq("group_id", GID);
  for (const s of (seen || [])) peerSeen[s.user_id] = s.last_seen_at;
  paintSeen();
  if (msgCache.length) touchSeen(msgCache[msgCache.length - 1].ts);
  sb.channel("chat-" + GID)
    .on("postgres", { event: "*", schema: "public", table: "messages", filter: "group_id=eq." + GID }, (p) => {
      if (p.eventType === "INSERT") renderRow(p.new);
      else if (p.eventType === "UPDATE") updateRow(p.new);
      else if (p.eventType === "DELETE" && p.old?.id) removeRow(p.old.id);
    })
    .subscribe();
  sb.channel("seen-" + GID)
    .on("postgres", { event: "*", schema: "public", table: "read_state", filter: "group_id=eq." + GID }, (p) => {
      peerSeen[p.new.user_id] = p.new.last_seen_at; paintSeen();
    })
    .subscribe();
  joinLive();
}

/* ---- giriş ---- */
$("loginBtn").onclick = async () => {
  $("loginErr").textContent = "";
  const email = $("email").value.trim(), pass = $("pass").value;
  if (!email || !pass) { $("loginErr").textContent = "E-posta ve şifre gerekli."; return; }
  try {
    const { data, error } = await sb.auth.signInWithPassword({ email, password: pass });
    if (error) throw error;
    UID = data.user.id;
    peers[UID] = IDpubB64; localStorage.setItem("peers", JSON.stringify(peers));
    localStorage.setItem("email", email);
    if (!await ensureGroupKey()) throw new Error("grup anahtarı alınamadı");
    await enterChat();
  } catch (e) { $("loginErr").textContent = "Giriş olmadı: " + e.message; }
};
$("logoutBtn").onclick = async () => { if (liveCh) sb.removeChannel(liveCh); await sb.auth.signOut(); show("login"); setStatus(false, "çıkış yapıldı"); };

/* ---- gönderme (yeni / yanıt / düzenleme) ---- */
$("send").onclick = sendText;
$("msg").addEventListener("keydown", (e) => { if (e.key === "Enter") sendText(); });
$("msg").addEventListener("input", pokeTyping);
async function sendText() {
  const v = $("msg").value.trim();
  if (!v || !GK) return;
  setTyping(false);
  if (editingId) {
    const m = msgCache.find((x) => x.id === editingId);
    const pkt = await C.encryptText(GK, ID.privateKey, UID, v);
    pkt.pub = IDpubB64;
    if (m?.row.packet?.reply) pkt.reply = m.row.packet.reply;
    const cur = editingId;
    cancelCompose();
    const { data, error } = await sb.from("messages").update({ packet: pkt, edited: true }).eq("id", cur).select().single();
    if (!error && data) updateRow(data);
    return;
  }
  $("msg").value = "";
  const pkt = await C.encryptText(GK, ID.privateKey, UID, v);
  pkt.pub = IDpubB64;
  if (replyTo) pkt.reply = { id: replyTo.id, name: replyTo.name, text: replyTo.text.slice(0, 140) };
  cancelCompose();
  const { data, error } = await sb.from("messages").insert({ group_id: GID, sender_id: UID, kind: "text", packet: pkt }).select().single();
  if (!error && data) renderRow(data);
}

/* ---- ek menüsü ---- */
$("attachBtn").onclick = () => $("attachSheet").classList.toggle("hidden");
$("optPhoto").onclick = () => { $("attachSheet").classList.add("hidden"); $("img").click(); };
$("optVideo").onclick = () => { $("attachSheet").classList.add("hidden"); $("video").click(); };
$("optGif").onclick = async () => {
  $("attachSheet").classList.add("hidden");
  const url = prompt("GIF bağlantısını yapıştır (boş bırakırsan dosya seçilir):", "");
  if (url && url.trim()) {
    const pkt = await C.encryptText(GK, ID.privateKey, UID, url.trim());
    pkt.pub = IDpubB64;
    if (replyTo) pkt.reply = { id: replyTo.id, name: replyTo.name, text: replyTo.text.slice(0, 140) };
    cancelCompose();
    const { data } = await sb.from("messages").insert({ group_id: GID, sender_id: UID, kind: "gif", packet: pkt }).select().single();
    if (data) renderRow(data);
  } else $("gifFile").click();
};
$("optLocation").onclick = () => {
  $("attachSheet").classList.add("hidden");
  if (!navigator.geolocation) return alert("Bu cihaz konum vermiyor.");
  navigator.geolocation.getCurrentPosition(async (pos) => {
    const t = `geo:${pos.coords.latitude.toFixed(5)},${pos.coords.longitude.toFixed(5)}`;
    const pkt = await C.encryptText(GK, ID.privateKey, UID, t);
    pkt.pub = IDpubB64;
    if (replyTo) pkt.reply = { id: replyTo.id, name: replyTo.name, text: replyTo.text.slice(0, 140) };
    cancelCompose();
    const { data } = await sb.from("messages").insert({ group_id: GID, sender_id: UID, kind: "location", packet: pkt }).select().single();
    if (data) renderRow(data);
  }, () => alert("Konum izni verilmedi."), { enableHighAccuracy: false, timeout: 10000 });
};
async function sendFile(file, kind) {
  if (file.size > 100 * 1024 * 1024) { alert("Dosya çok büyük (100MB üstü)."); return; }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const enc = await C.encryptBytes(GK, bytes);
  const path = GID + "/" + Date.now() + "-" + Math.random().toString(36).slice(2) + ".enc";
  const { error: upErr } = await sb.storage.from("chat-media").upload(path, new Blob([enc.ct], { type: "text/plain" }));
  if (upErr) { alert("Yükleme olmadı: " + upErr.message); return; }
  const pkt = await C.encryptText(GK, ID.privateKey, UID, "");
  pkt.pub = IDpubB64;
  if (replyTo) pkt.reply = { id: replyTo.id, name: replyTo.name, text: replyTo.text.slice(0, 140) };
  cancelCompose();
  const { data, error } = await sb.from("messages").insert({ group_id: GID, sender_id: UID, kind, packet: pkt, media_path: path, media_nonce: enc.nonce }).select().single();
  if (!error && data) renderRow(data);
}
$("img").onchange = () => { const f = $("img").files[0]; $("img").value = ""; if (f) sendFile(f, "image"); };
$("video").onchange = () => { const f = $("video").files[0]; $("video").value = ""; if (f) sendFile(f, "video"); };
$("gifFile").onchange = () => { const f = $("gifFile").files[0]; $("gifFile").value = ""; if (f) sendFile(f, "gif"); };

(async () => {
  await loadIdentity();
  await loadSavedKey();
  if (localStorage.getItem("email")) $("email").value = localStorage.getItem("email");
  const { data } = await sb.auth.getSession();
  if (data.session) {
    UID = data.session.user.id;
    if (await ensureGroupKey()) enterChat();
    else show("login");
  }
  else show("login");
})();
