// ============================================================
// Insight Club — IOS backend (Cloudflare Worker + D1)
// تخزين عام: كل جدول منطقي يُخزَّن كصفوف JSON داخل جدول records الواحد
// ============================================================

const LEADER_ONLY_TABLES = ["committees", "positions", "club_info", "conflicts"];
const COMMITTEE_TABLES = {
  content_items: "الإعلام وصناعة الأثر",
  partners: "العلاقات",
  resources: "الموارد",
  members: "الموارد",
  quality_reviews: "التقييم والجودة",
  kpis: "التقييم والجودة",
  reports: "التقييم والجودة",
};
// كل الجداول الباقية (shared): أي عضو مسجّل دخول (أي لجنة أو قائد) يقدر يعدّل فيها
const NEVER_READABLE = ["auth_config"]; // ما يُقرأ أبدًا عبر GET العام

const DEFAULT_PASSWORDS = {
  leader: "insight2026",
  "الإعلام وصناعة الأثر": "media2026",
  "العلاقات": "relations2026",
  "الموارد": "resources2026",
  "التقييم والجودة": "quality2026",
};

function getSecret(env) { return env.AUTH_SECRET || "insight-club-ios-2026-default-secret-change-me"; }

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
  });
}
function err(message, status = 400) {
  return json({ error: message }, status);
}

// ---------- تشفير كلمات المرور (PBKDF2) ----------
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);
  return `${b64(salt)}.${b64(new Uint8Array(key))}`;
}
async function verifyPassword(password, stored) {
  const [saltB64, hashB64] = (stored || "").split(".");
  if (!saltB64 || !hashB64) return false;
  const salt = unb64(saltB64);
  const key = new Uint8Array(await deriveKey(password, salt));
  const expected = unb64(hashB64);
  if (key.byteLength !== expected.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < key.length; i++) diff |= key[i] ^ expected[i];
  return diff === 0;
}
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
}
function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }

// ---------- توكن الجلسة (HMAC، بدون مكتبات خارجية) ----------
async function signToken(payload, secret) {
  const encHeader = b64url(JSON.stringify({ alg: "HS256" }));
  const encPayload = b64url(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;
  return `${data}.${await hmac(data, secret)}`;
}
async function verifyToken(token, secret) {
  const parts = (token || "").split(".");
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  if (await hmac(`${h}.${p}`, secret) !== sig) return null;
  const payload = JSON.parse(atobUrl(p));
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}
async function hmac(data, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(String.fromCharCode(...new Uint8Array(sig)));
}
function b64url(str) { return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function atobUrl(str) { return atob(str.replace(/-/g, "+").replace(/_/g, "/")); }

function getAuth(request) {
  const h = request.headers.get("Authorization") || "";
  return h.replace("Bearer ", "");
}

async function getAuthConfig(env) {
  const row = await env.DB.prepare("SELECT data FROM records WHERE table_name = 'auth_config' AND id = '1'").first();
  if (row) return JSON.parse(row.data);
  // أول تشغيل: أنشئ كلمات المرور الافتراضية مُشفّرة
  const cfg = {
    leaderPasswordHash: await hashPassword(DEFAULT_PASSWORDS.leader),
    committeePasswordHashes: {
      "الإعلام وصناعة الأثر": await hashPassword(DEFAULT_PASSWORDS["الإعلام وصناعة الأثر"]),
      "العلاقات": await hashPassword(DEFAULT_PASSWORDS["العلاقات"]),
      "الموارد": await hashPassword(DEFAULT_PASSWORDS["الموارد"]),
      "التقييم والجودة": await hashPassword(DEFAULT_PASSWORDS["التقييم والجودة"]),
    },
  };
  await env.DB.prepare("INSERT INTO records (table_name, id, data) VALUES ('auth_config','1',?)").bind(JSON.stringify(cfg)).run();
  return cfg;
}

function canWrite(role, table) {
  if (role === "leader") return true;
  if (LEADER_ONLY_TABLES.includes(table)) return false;
  const requiredCommittee = COMMITTEE_TABLES[table];
  if (requiredCommittee) return role === requiredCommittee;
  return !!role; // أي دور مسجّل دخول يقدر يعدّل الجداول المشتركة الباقية
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    // ---------- تسجيل الدخول ----------
    if (request.method === "POST" && path === "/auth/login") {
      const { role, password } = await request.json().catch(() => ({}));
      if (!role || !password) return err("الدور وكلمة المرور مطلوبة");
      const cfg = await getAuthConfig(env);
      let ok = false;
      if (role === "leader") ok = await verifyPassword(password, cfg.leaderPasswordHash);
      else ok = await verifyPassword(password, cfg.committeePasswordHashes[role] || "");
      if (!ok) return err("كلمة المرور غير صحيحة", 401);
      const token = await signToken({ role, exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 }, getSecret(env));
      return json({ token, role });
    }

    // ---------- تغيير كلمات المرور (قائد النادي فقط) ----------
    if (request.method === "POST" && path === "/auth/passwords") {
      const payload = await verifyToken(getAuth(request), getSecret(env));
      if (!payload || payload.role !== "leader") return err("غير مصرّح", 403);
      const body = await request.json().catch(() => ({}));
      const cfg = await getAuthConfig(env);
      if (body.leaderPassword) cfg.leaderPasswordHash = await hashPassword(body.leaderPassword);
      if (body.committeePasswords) {
        for (const [name, pw] of Object.entries(body.committeePasswords)) {
          if (pw) cfg.committeePasswordHashes[name] = await hashPassword(pw);
        }
      }
      await env.DB.prepare("UPDATE records SET data = ?, updated_at = datetime('now') WHERE table_name='auth_config' AND id='1'")
        .bind(JSON.stringify(cfg)).run();
      return json({ ok: true });
    }

    // ---------- CRUD عام لأي جدول منطقي ----------
    const m = path.match(/^\/api\/([a-z_]+)(?:\/([^/]+))?$/);
    if (m) {
      const table = m[1];
      const id = m[2];
      if (NEVER_READABLE.includes(table)) return err("غير مسموح", 403);

      if (request.method === "GET" && !id) {
        const { results } = await env.DB.prepare("SELECT data FROM records WHERE table_name = ?").bind(table).all();
        return json(results.map(r => JSON.parse(r.data)));
      }
      if (request.method === "GET" && id) {
        const row = await env.DB.prepare("SELECT data FROM records WHERE table_name = ? AND id = ?").bind(table, id).first();
        return row ? json(JSON.parse(row.data)) : err("غير موجود", 404);
      }

      // كل عمليات الكتابة تتطلب تسجيل دخول وصلاحية على الجدول
      const payload = await verifyToken(getAuth(request), getSecret(env));
      if (!payload) return err("غير مصرّح — يلزم تسجيل الدخول", 401);
      if (!canWrite(payload.role, table)) return err("لا تملك صلاحية التعديل على هذه الوحدة", 403);

      if (request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const rowId = body.id || crypto.randomUUID();
        await env.DB.prepare("INSERT INTO records (table_name, id, data) VALUES (?, ?, ?)")
          .bind(table, rowId, JSON.stringify({ ...body, id: rowId })).run();
        return json({ ...body, id: rowId }, 201);
      }
      if (request.method === "PUT" && id) {
        const body = await request.json().catch(() => ({}));
        await env.DB.prepare(
          "INSERT INTO records (table_name, id, data) VALUES (?, ?, ?) ON CONFLICT(table_name, id) DO UPDATE SET data = excluded.data, updated_at = datetime('now')"
        ).bind(table, id, JSON.stringify({ ...body, id })).run();
        return json({ ok: true });
      }
      if (request.method === "DELETE" && id) {
        await env.DB.prepare("DELETE FROM records WHERE table_name = ? AND id = ?").bind(table, id).run();
        return json({ ok: true });
      }
    }

    return err("المسار غير موجود", 404);
  },
};
