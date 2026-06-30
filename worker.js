// Everyday — Cloudflare Worker mit KV-Sync und Passwortschutz
// Alle Daten liegen zentral in Cloudflare KV (Namespace: EVERYDAY_KV)
// Ein einziger Datensatz pro Account, geschützt durch ein serverseitig geprüftes Passwort

const DATA_KEY = "everyday:data";
const PASSWORD_HASH_KEY = "everyday:pwhash";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

async function sha256(text) {
  const enc = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function checkAuth(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token) return false;
  const storedHash = await env.EVERYDAY_KV.get(PASSWORD_HASH_KEY);
  if (!storedHash) {
    // Erstes Mal: kein Passwort gesetzt, akzeptiere und setze es
    const newHash = await sha256(token);
    await env.EVERYDAY_KV.put(PASSWORD_HASH_KEY, newHash);
    return true;
  }
  const givenHash = await sha256(token);
  return timingSafeEqual(givenHash, storedHash);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    if (url.pathname === "/api/data" && request.method === "GET") {
      const ok = await checkAuth(request, env);
      if (!ok) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { ...corsHeaders(), "Content-Type": "application/json" } });
      const data = await env.EVERYDAY_KV.get(DATA_KEY);
      return new Response(data || "null", { headers: { ...corsHeaders(), "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/data" && request.method === "POST") {
      const ok = await checkAuth(request, env);
      if (!ok) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { ...corsHeaders(), "Content-Type": "application/json" } });
      const body = await request.text();
      try { JSON.parse(body); } catch (e) {
        return new Response(JSON.stringify({ error: "invalid json" }), { status: 400, headers: { ...corsHeaders(), "Content-Type": "application/json" } });
      }
      await env.EVERYDAY_KV.put(DATA_KEY, body);
      return new Response(JSON.stringify({ ok: true, savedAt: new Date().toISOString() }), { headers: { ...corsHeaders(), "Content-Type": "application/json" } });
    }

    // Statische Datei ausliefern (index.html etc.) über ASSETS-Binding
    return env.ASSETS.fetch(request);
  }
};
