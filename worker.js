// EVERYDAY Multi-User Cloudflare Worker
// KV Binding: EVERYDAY (Cloudflare KV Namespace)
// Secret: TOKEN_SECRET (env variable, e.g. a random 64-char string)

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

// --- Crypto Helpers ---

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
}

async function createToken(username, secret) {
  const enc = new TextEncoder();
  const payload = JSON.stringify({ sub: username, iat: Date.now(), exp: Date.now() + 90 * 24 * 60 * 60 * 1000 }); // 90 days
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return btoa(payload) + "." + toHex(sig);
}

async function verifyToken(token, secret) {
  try {
    const [payloadB64, sigHex] = token.split(".");
    if (!payloadB64 || !sigHex) return null;
    const enc = new TextEncoder();
    const payload = atob(payloadB64);
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, fromHex(sigHex), enc.encode(payload));
    if (!valid) return null;
    const data = JSON.parse(payload);
    if (data.exp && data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}

// --- Route Handlers ---

async function handleRegister(request, env) {
  const { username, password, displayName } = await request.json();
  if (!username || !password) return json({ error: "Benutzername und Passwort erforderlich" }, 400);
  if (username.length < 3) return json({ error: "E-Mail muss min. 3 Zeichen lang sein" }, 400);
  if (password.length < 6) return json({ error: "Passwort muss min. 6 Zeichen lang sein" }, 400);
  if (!/^[a-zA-Z0-9_.@+-]+$/.test(username)) return json({ error: "Ungültige E-Mail-Adresse" }, 400);

  const key = "user:" + username.toLowerCase();
  const existing = await env.EVERYDAY.get(key);
  if (existing) return json({ error: "Benutzername bereits vergeben" }, 409);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);

  await env.EVERYDAY.put(key, JSON.stringify({
    username: username.toLowerCase(),
    displayName: displayName || username,
    hash: toHex(hash),
    salt: toHex(salt),
    created: new Date().toISOString(),
  }));

  const token = await createToken(username.toLowerCase(), env.TOKEN_SECRET || "everyday-default-secret-change-me");
  return json({ ok: true, token, username: username.toLowerCase(), displayName: displayName || username });
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) return json({ error: "Benutzername und Passwort erforderlich" }, 400);

  const key = "user:" + username.toLowerCase();
  const raw = await env.EVERYDAY.get(key);
  if (!raw) return json({ error: "Benutzername oder Passwort falsch" }, 401);

  const user = JSON.parse(raw);
  const hash = await hashPassword(password, fromHex(user.salt));
  if (toHex(hash) !== user.hash) return json({ error: "Benutzername oder Passwort falsch" }, 401);

  const token = await createToken(username.toLowerCase(), env.TOKEN_SECRET || "everyday-default-secret-change-me");
  return json({ ok: true, token, username: user.username, displayName: user.displayName });
}

async function handleGetData(request, env, username) {
  const raw = await env.EVERYDAY.get("data:" + username);
  if (!raw) return json(null);
  return new Response(raw, {
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

async function handlePostData(request, env, username) {
  const body = await request.text();
  // Limit: 25MB per user
  if (body.length > 25 * 1024 * 1024) return json({ error: "Daten zu gross (max 25MB)" }, 413);
  await env.EVERYDAY.put("data:" + username, body);
  return json({ ok: true, saved: new Date().toISOString() });
}

async function handleChangePassword(request, env, username) {
  const { oldPassword, newPassword } = await request.json();
  if (!oldPassword || !newPassword) return json({ error: "Altes und neues Passwort erforderlich" }, 400);
  if (newPassword.length < 6) return json({ error: "Neues Passwort muss min. 6 Zeichen lang sein" }, 400);

  const key = "user:" + username;
  const raw = await env.EVERYDAY.get(key);
  if (!raw) return json({ error: "Benutzer nicht gefunden" }, 404);

  const user = JSON.parse(raw);
  const hash = await hashPassword(oldPassword, fromHex(user.salt));
  if (toHex(hash) !== user.hash) return json({ error: "Altes Passwort falsch" }, 401);

  const newSalt = crypto.getRandomValues(new Uint8Array(16));
  const newHash = await hashPassword(newPassword, newSalt);
  user.hash = toHex(newHash);
  user.salt = toHex(newSalt);
  await env.EVERYDAY.put(key, JSON.stringify(user));

  return json({ ok: true });
}

// --- Main Router ---

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Public routes
    if (path === "/api/register" && request.method === "POST") {
      return handleRegister(request, env);
    }
    if (path === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }

    // Health check
    if (path === "/api/health") {
      return json({ status: "ok", time: new Date().toISOString() });
    }

    // --- Authenticated routes ---
    const auth = request.headers.get("Authorization");
    if (!auth || !auth.startsWith("Bearer ")) {
      return json({ error: "Nicht authentifiziert" }, 401);
    }

    const token = auth.slice(7);
    const payload = await verifyToken(token, env.TOKEN_SECRET || "everyday-default-secret-change-me");
    if (!payload) return json({ error: "Token ungültig oder abgelaufen" }, 401);

    const username = payload.sub;

    if (path === "/api/data" && request.method === "GET") {
      return handleGetData(request, env, username);
    }
    if (path === "/api/data" && request.method === "POST") {
      return handlePostData(request, env, username);
    }
    if (path === "/api/password" && request.method === "POST") {
      return handleChangePassword(request, env, username);
    }
    if (path === "/api/me") {
      const raw = await env.EVERYDAY.get("user:" + username);
      if (!raw) return json({ error: "Benutzer nicht gefunden" }, 404);
      const user = JSON.parse(raw);
      return json({ username: user.username, displayName: user.displayName, created: user.created });
    }

    return json({ error: "Nicht gefunden" }, 404);
  },
};
