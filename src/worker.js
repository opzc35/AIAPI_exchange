const SESSION_COOKIE = "aiapi_session";
const SESSION_TTL_DAYS = 30;

export default {
  async fetch(request, env) {
    try {
      if (!env.DB) {
        return json(
          { error: "Missing D1 binding. Configure DB in wrangler.toml and deploy again." },
          500,
        );
      }

      if (!env.APP_SECRET || env.APP_SECRET.length < 16) {
        return json(
          { error: "Missing APP_SECRET. Set a long random secret with `wrangler secret put APP_SECRET`." },
          500,
        );
      }

      await ensureSchema(env.DB);

      const url = new URL(request.url);
      const session = await getSession(request, env);

      if (request.method === "GET" && url.pathname === "/") {
        return html(renderAppHtml());
      }

      if (request.method === "GET" && url.pathname === "/api/health") {
        return json({ ok: true, now: new Date().toISOString() });
      }

      if (request.method === "POST" && url.pathname === "/api/auth/register") {
        return handleRegister(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/auth/login") {
        return handleLogin(request, env);
      }

      if (request.method === "POST" && url.pathname === "/api/auth/logout") {
        return handleLogout(request, env);
      }

      if (request.method === "GET" && url.pathname === "/api/me") {
        requireUser(session);
        return handleMe(session, env);
      }

      if (request.method === "GET" && url.pathname === "/api/channels") {
        requireUser(session);
        return handleListChannels(session, env);
      }

      if (request.method === "POST" && url.pathname === "/api/channels") {
        requireUser(session);
        return handleCreateChannel(request, session, env);
      }

      if (request.method === "GET" && url.pathname === "/api/admin/users") {
        requireAdmin(session);
        return handleAdminUsers(env);
      }

      if (request.method === "POST" && url.pathname === "/api/admin/credit") {
        requireAdmin(session);
        return handleAdminCredit(request, env);
      }

      const proxyMatch = url.pathname.match(/^\/api\/proxy\/(\d+)$/);
      if (request.method === "POST" && proxyMatch) {
        requireUser(session);
        return handleProxyRequest(request, env, session.user, Number(proxyMatch[1]));
      }

      return json({ error: "Not found" }, 404);
    } catch (error) {
      const status = error.statusCode || 500;
      return json({ error: error.message || "Internal error" }, status);
    }
  },
};

async function handleRegister(request, env) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password || password.length < 8) {
    throw httpError(400, "Email and password (minimum 8 chars) are required.");
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (existing) {
    throw httpError(409, "Email already exists.");
  }

  const countRow = await env.DB.prepare("SELECT COUNT(*) AS count FROM users").first();
  const isFirstUser = Number(countRow?.count || 0) === 0;

  const passwordHash = await sha256Hex(password);
  const result = await env.DB.prepare(
    "INSERT INTO users (email, password_hash, is_admin) VALUES (?, ?, ?)",
  )
    .bind(email, passwordHash, isFirstUser ? 1 : 0)
    .run();

  const user = await env.DB.prepare(
    "SELECT id, email, is_admin, balance_cents, created_at FROM users WHERE id = ?",
  )
    .bind(result.meta.last_row_id)
    .first();

  const session = await createSession(user.id, env);
  return json(
    {
      ok: true,
      user: serializeUser(user),
      bootstrap_admin: Boolean(isFirstUser),
    },
    201,
    { "Set-Cookie": buildSessionCookie(session.token, session.expiresAt) },
  );
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  const user = await env.DB.prepare(
    "SELECT id, email, is_admin, balance_cents, password_hash, created_at FROM users WHERE email = ?",
  )
    .bind(email)
    .first();

  if (!user) {
    throw httpError(401, "Invalid credentials.");
  }

  const passwordHash = await sha256Hex(password);
  if (passwordHash !== user.password_hash) {
    throw httpError(401, "Invalid credentials.");
  }

  const session = await createSession(user.id, env);
  return json(
    { ok: true, user: serializeUser(user) },
    200,
    { "Set-Cookie": buildSessionCookie(session.token, session.expiresAt) },
  );
}

async function handleLogout(request, env) {
  const token = getCookie(request.headers.get("Cookie"), SESSION_COOKIE);
  if (token) {
    const tokenHash = await sha256Hex(token);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie":
        `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
    },
  );
}

async function handleMe(session, env) {
  const user = session.user;
  const myChannels = await env.DB.prepare(
    `SELECT id, name, provider, base_url, endpoint_path, default_model,
            price_input_cents_per_1k, price_output_cents_per_1k, is_active, created_at
     FROM channels
     WHERE owner_user_id = ?
     ORDER BY id DESC`,
  )
    .bind(user.id)
    .all();

  const recentUsage = await env.DB.prepare(
    `SELECT usage_logs.id, usage_logs.channel_id, channels.name AS channel_name, usage_logs.model,
            usage_logs.input_tokens, usage_logs.output_tokens, usage_logs.total_cost_cents,
            usage_logs.status, usage_logs.created_at
     FROM usage_logs
     JOIN channels ON channels.id = usage_logs.channel_id
     WHERE usage_logs.requester_user_id = ?
     ORDER BY usage_logs.id DESC
     LIMIT 20`,
  )
    .bind(user.id)
    .all();

  return json({
    ok: true,
    user: serializeUser(user),
    my_channels: myChannels.results || [],
    usage_logs: recentUsage.results || [],
  });
}

async function handleListChannels(session, env) {
  const channels = await env.DB.prepare(
    `SELECT channels.id, channels.name, channels.provider, channels.base_url, channels.endpoint_path,
            channels.default_model, channels.price_input_cents_per_1k, channels.price_output_cents_per_1k,
            channels.is_active, channels.created_at, users.email AS owner_email
     FROM channels
     JOIN users ON users.id = channels.owner_user_id
     WHERE channels.is_active = 1
     ORDER BY channels.id DESC`,
  ).all();

  return json({
    ok: true,
    balance_cents: session.user.balance_cents,
    channels: channels.results || [],
  });
}

async function handleCreateChannel(request, session, env) {
  const body = await readJson(request);
  const provider = String(body.provider || "").trim().toLowerCase();
  const name = String(body.name || "").trim();
  const baseUrl = sanitizeBaseUrl(body.base_url, provider);
  const endpointPath = sanitizeEndpointPath(body.endpoint_path, provider);
  const defaultModel = String(body.default_model || "").trim() || null;
  const apiKey = String(body.api_key || "").trim();
  const priceIn = toNonNegativeInteger(body.price_input_cents_per_1k, "Invalid input token price.");
  const priceOut = toNonNegativeInteger(body.price_output_cents_per_1k, "Invalid output token price.");

  if (!name || !apiKey) {
    throw httpError(400, "Name and API key are required.");
  }

  if (!["openai", "anthropic"].includes(provider)) {
    throw httpError(400, "Provider must be openai or anthropic.");
  }

  const encryptedKey = await encryptText(apiKey, env.APP_SECRET);
  await env.DB.prepare(
    `INSERT INTO channels (
       owner_user_id, name, provider, base_url, endpoint_path, default_model,
       api_key_encrypted, price_input_cents_per_1k, price_output_cents_per_1k
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      session.user.id,
      name,
      provider,
      baseUrl,
      endpointPath,
      defaultModel,
      encryptedKey,
      priceIn,
      priceOut,
    )
    .run();

  return json({ ok: true }, 201);
}

async function handleAdminUsers(env) {
  const users = await env.DB.prepare(
    `SELECT id, email, is_admin, balance_cents, created_at
     FROM users
     ORDER BY id ASC`,
  ).all();

  return json({
    ok: true,
    users: (users.results || []).map(serializeUser),
  });
}

async function handleAdminCredit(request, env) {
  const body = await readJson(request);
  const userId = toNonNegativeInteger(body.user_id, "Invalid user id.");
  const amount = toInteger(body.amount_cents, "Invalid amount.");

  const user = await env.DB.prepare(
    "SELECT id, email, is_admin, balance_cents, created_at FROM users WHERE id = ?",
  )
    .bind(userId)
    .first();

  if (!user) {
    throw httpError(404, "User not found.");
  }

  const nextBalance = Number(user.balance_cents) + amount;
  if (nextBalance < 0) {
    throw httpError(400, "Balance cannot go below zero.");
  }

  await env.DB.prepare("UPDATE users SET balance_cents = ? WHERE id = ?")
    .bind(nextBalance, userId)
    .run();

  return json({
    ok: true,
    user: serializeUser({ ...user, balance_cents: nextBalance }),
  });
}

async function handleProxyRequest(request, env, requester, channelId) {
  const channel = await env.DB.prepare(
    `SELECT id, owner_user_id, name, provider, base_url, endpoint_path, default_model,
            api_key_encrypted, price_input_cents_per_1k, price_output_cents_per_1k, is_active
     FROM channels
     WHERE id = ?`,
  )
    .bind(channelId)
    .first();

  if (!channel || Number(channel.is_active) !== 1) {
    throw httpError(404, "Channel not found.");
  }

  if (Number(requester.balance_cents) <= 0) {
    throw httpError(402, "Insufficient balance. Ask an admin to recharge your account.");
  }

  const payload = await readJson(request);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw httpError(400, "Request body must be a JSON object.");
  }

  if (!payload.model && channel.default_model) {
    payload.model = channel.default_model;
  }

  const apiKey = await decryptText(channel.api_key_encrypted, env.APP_SECRET);
  const upstreamUrl = `${channel.base_url}${channel.endpoint_path}`;
  const headers = buildProviderHeaders(channel.provider, apiKey, request.headers.get("Content-Type"));

  const upstreamResponse = await fetch(upstreamUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });

  const rawText = await upstreamResponse.text();
  let upstreamJson;
  try {
    upstreamJson = rawText ? JSON.parse(rawText) : {};
  } catch {
    upstreamJson = { raw_text: rawText };
  }

  if (!upstreamResponse.ok) {
    await env.DB.prepare(
      `INSERT INTO usage_logs (requester_user_id, channel_id, model, status)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(requester.id, channel.id, String(payload.model || ""), "upstream_error")
      .run();

    return json(
      {
        error: "Upstream request failed.",
        channel_id: channel.id,
        upstream_status: upstreamResponse.status,
        upstream_body: upstreamJson,
      },
      upstreamResponse.status,
    );
  }

  const usage = normalizeUsage(channel.provider, upstreamJson);
  const totalCost =
    chargeForTokens(usage.input_tokens, channel.price_input_cents_per_1k) +
    chargeForTokens(usage.output_tokens, channel.price_output_cents_per_1k);
  const nextBalance = Number(requester.balance_cents) - totalCost;

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO usage_logs (
         requester_user_id, channel_id, model, input_tokens, output_tokens, total_cost_cents, status
       ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      requester.id,
      channel.id,
      String(payload.model || channel.default_model || ""),
      usage.input_tokens,
      usage.output_tokens,
      totalCost,
      "success",
    ),
    env.DB.prepare("UPDATE users SET balance_cents = ? WHERE id = ?")
      .bind(nextBalance, requester.id),
  ]);

  return json({
    ok: true,
    channel: {
      id: channel.id,
      name: channel.name,
      provider: channel.provider,
    },
    usage,
    charged_cents: totalCost,
    balance_cents: nextBalance,
    upstream: upstreamJson,
  });
}

async function ensureSchema(db) {
  const exists = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'")
    .first();

  if (exists) {
    return;
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      balance_cents INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS channels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      provider TEXT NOT NULL CHECK (provider IN ('openai', 'anthropic')),
      base_url TEXT NOT NULL,
      endpoint_path TEXT NOT NULL,
      default_model TEXT,
      api_key_encrypted TEXT NOT NULL,
      price_input_cents_per_1k INTEGER NOT NULL,
      price_output_cents_per_1k INTEGER NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    `CREATE TABLE IF NOT EXISTS usage_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      requester_user_id INTEGER NOT NULL,
      channel_id INTEGER NOT NULL,
      model TEXT,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      total_cost_cents INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (requester_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
    )`,
    "CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)",
    "CREATE INDEX IF NOT EXISTS idx_channels_owner_user_id ON channels(owner_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_usage_logs_requester_user_id ON usage_logs(requester_user_id)",
  ];

  for (const statement of statements) {
    await db.prepare(statement).run();
  }
}

async function getSession(request, env) {
  const token = getCookie(request.headers.get("Cookie"), SESSION_COOKIE);
  if (!token) {
    return null;
  }

  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT sessions.id, sessions.expires_at, users.id AS user_id, users.email, users.is_admin,
            users.balance_cents, users.created_at
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token_hash = ?`,
  )
    .bind(tokenHash)
    .first();

  if (!row) {
    return null;
  }

  if (Date.parse(row.expires_at) <= Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    return null;
  }

  return {
    user: {
      id: row.user_id,
      email: row.email,
      is_admin: row.is_admin,
      balance_cents: row.balance_cents,
      created_at: row.created_at,
    },
  };
}

async function createSession(userId, env) {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 86400000).toISOString();

  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
  )
    .bind(userId, tokenHash, expiresAt)
    .run();

  return { token, expiresAt };
}

function requireUser(session) {
  if (!session?.user) {
    throw httpError(401, "Login required.");
  }
}

function requireAdmin(session) {
  requireUser(session);
  if (Number(session.user.is_admin) !== 1) {
    throw httpError(403, "Admin access required.");
  }
}

function serializeUser(user) {
  return {
    id: Number(user.id),
    email: String(user.email),
    is_admin: Number(user.is_admin) === 1,
    balance_cents: Number(user.balance_cents || 0),
    created_at: user.created_at || null,
  };
}

function buildSessionCookie(token, expiresAt) {
  const maxAge = SESSION_TTL_DAYS * 86400;
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}; Expires=${new Date(expiresAt).toUTCString()}`;
}

function buildProviderHeaders(provider, apiKey, contentType) {
  const headers = {
    "Content-Type": contentType || "application/json",
  };

  if (provider === "openai") {
    headers.Authorization = `Bearer ${apiKey}`;
    return headers;
  }

  if (provider === "anthropic") {
    headers["x-api-key"] = apiKey;
    headers["anthropic-version"] = "2023-06-01";
    return headers;
  }

  throw httpError(400, "Unsupported provider.");
}

function normalizeUsage(provider, payload) {
  if (provider === "openai") {
    const usage = payload.usage || {};
    return {
      input_tokens: Number(usage.prompt_tokens || usage.input_tokens || 0),
      output_tokens: Number(usage.completion_tokens || usage.output_tokens || 0),
    };
  }

  if (provider === "anthropic") {
    const usage = payload.usage || {};
    return {
      input_tokens: Number(usage.input_tokens || 0),
      output_tokens: Number(usage.output_tokens || 0),
    };
  }

  return {
    input_tokens: 0,
    output_tokens: 0,
  };
}

function chargeForTokens(tokens, centsPer1k) {
  return Math.ceil((Number(tokens || 0) * Number(centsPer1k || 0)) / 1000);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function sanitizeBaseUrl(value, provider) {
  const fallback =
    provider === "anthropic" ? "https://api.anthropic.com" : "https://api.openai.com";
  const raw = String(value || fallback).trim().replace(/\/+$/, "");

  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "https:") {
      throw new Error("HTTPS required");
    }
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    throw httpError(400, "Invalid base URL.");
  }
}

function sanitizeEndpointPath(value, provider) {
  const fallback = provider === "anthropic" ? "/v1/messages" : "/v1/chat/completions";
  const path = String(value || fallback).trim();
  if (!path.startsWith("/")) {
    throw httpError(400, "Endpoint path must start with /.");
  }
  return path;
}

function toNonNegativeInteger(value, message) {
  const num = Number(value);
  if (!Number.isInteger(num) || num < 0) {
    throw httpError(400, message);
  }
  return num;
}

function toInteger(value, message) {
  const num = Number(value);
  if (!Number.isInteger(num)) {
    throw httpError(400, message);
  }
  return num;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw httpError(400, "Invalid JSON body.");
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function html(content, status = 200) {
  return new Response(content, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function getCookie(cookieHeader, key) {
  if (!cookieHeader) {
    return null;
  }

  const parts = cookieHeader.split(";").map((part) => part.trim());
  for (const part of parts) {
    const [name, ...rest] = part.split("=");
    if (name === key) {
      return rest.join("=");
    }
  }
  return null;
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64UrlEncode(bytes);
}

async function sha256Hex(input) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function deriveAesKey(secret) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", hash, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptText(plainText, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(secret);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plainText),
  );
  const packed = new Uint8Array(iv.length + cipher.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(cipher), iv.length);
  return base64Encode(packed);
}

async function decryptText(encoded, secret) {
  const packed = base64Decode(encoded);
  const iv = packed.slice(0, 12);
  const data = packed.slice(12);
  const key = await deriveAesKey(secret);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(plain);
}

function base64Encode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64Decode(encoded) {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlEncode(bytes) {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function renderAppHtml() {
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>AIAPI Exchange</title>
    <style>
      :root {
        --bg: #f2efe8;
        --panel: rgba(255, 252, 246, 0.86);
        --ink: #1c1917;
        --muted: #6b6257;
        --line: rgba(28, 25, 23, 0.12);
        --accent: #0f766e;
        --accent-strong: #115e59;
        --warn: #b45309;
        --error: #b91c1c;
        --shadow: 0 20px 60px rgba(28, 25, 23, 0.12);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Segoe UI", "PingFang SC", "Hiragino Sans GB", sans-serif;
        color: var(--ink);
        background:
          radial-gradient(circle at top left, rgba(15, 118, 110, 0.18), transparent 30%),
          radial-gradient(circle at bottom right, rgba(180, 83, 9, 0.14), transparent 26%),
          linear-gradient(135deg, #f7f2e7 0%, #eee5d3 100%);
        min-height: 100vh;
      }
      .shell {
        width: min(1180px, calc(100% - 32px));
        margin: 32px auto;
        display: grid;
        gap: 20px;
      }
      .hero, .panel {
        background: var(--panel);
        backdrop-filter: blur(18px);
        border: 1px solid var(--line);
        border-radius: 22px;
        box-shadow: var(--shadow);
      }
      .hero {
        padding: 28px;
        display: grid;
        gap: 14px;
      }
      .hero h1 {
        margin: 0;
        font-size: clamp(28px, 5vw, 54px);
        line-height: 0.94;
        letter-spacing: -0.04em;
      }
      .hero p {
        margin: 0;
        color: var(--muted);
        max-width: 820px;
        font-size: 15px;
      }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
      }
      .panel {
        padding: 20px;
      }
      h2, h3 {
        margin: 0 0 12px;
        font-size: 18px;
      }
      form {
        display: grid;
        gap: 10px;
      }
      label {
        display: grid;
        gap: 6px;
        font-size: 13px;
        color: var(--muted);
      }
      input, select, textarea, button {
        font: inherit;
      }
      input, select, textarea {
        width: 100%;
        padding: 12px 13px;
        border: 1px solid var(--line);
        border-radius: 14px;
        background: rgba(255,255,255,0.82);
        color: var(--ink);
      }
      textarea {
        min-height: 150px;
        resize: vertical;
      }
      button {
        border: 0;
        border-radius: 999px;
        background: var(--accent);
        color: white;
        padding: 12px 16px;
        cursor: pointer;
        transition: transform .15s ease, background .15s ease;
      }
      button:hover {
        background: var(--accent-strong);
        transform: translateY(-1px);
      }
      .ghost {
        background: transparent;
        color: var(--ink);
        border: 1px solid var(--line);
      }
      .row {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }
      .pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 9px 12px;
        border-radius: 999px;
        background: rgba(15, 118, 110, 0.08);
        color: var(--accent-strong);
        font-size: 13px;
      }
      .hidden { display: none !important; }
      .cards {
        display: grid;
        gap: 12px;
      }
      .card {
        padding: 14px;
        border-radius: 16px;
        border: 1px solid var(--line);
        background: rgba(255,255,255,0.66);
      }
      .meta {
        color: var(--muted);
        font-size: 13px;
      }
      pre {
        margin: 0;
        padding: 14px;
        border-radius: 16px;
        background: #171717;
        color: #f5f5f5;
        overflow: auto;
        font-size: 12px;
      }
      .notice {
        padding: 12px 14px;
        border-radius: 14px;
        background: rgba(180, 83, 9, 0.1);
        color: var(--warn);
        font-size: 13px;
      }
      .error {
        color: var(--error);
        font-size: 13px;
      }
      @media (max-width: 720px) {
        .shell { width: min(100% - 18px, 1180px); margin: 14px auto; }
        .hero, .panel { border-radius: 18px; padding: 16px; }
      }
    </style>
  </head>
  <body>
    <main class="shell">
      <section class="hero">
        <div class="pill">Cloudflare Worker + D1</div>
        <h1>AIAPI Exchange</h1>
        <p>用户可以上传自己的 OpenAI / Anthropic 渠道并设置价格，其他用户统一调用；管理员负责为用户充值额度。第一个注册用户会自动成为管理员。</p>
      </section>

      <section class="grid">
        <div class="panel" id="authPanel">
          <h2>登录 / 注册</h2>
          <div class="grid">
            <form id="registerForm">
              <h3>注册</h3>
              <label>邮箱<input name="email" type="email" required /></label>
              <label>密码<input name="password" type="password" minlength="8" required /></label>
              <button type="submit">创建账号</button>
            </form>
            <form id="loginForm">
              <h3>登录</h3>
              <label>邮箱<input name="email" type="email" required /></label>
              <label>密码<input name="password" type="password" required /></label>
              <button type="submit">登录</button>
            </form>
          </div>
          <p class="error" id="authError"></p>
        </div>

        <div class="panel hidden" id="accountPanel">
          <div class="row">
            <div class="pill" id="meEmail">未登录</div>
            <div class="pill" id="meBalance">额度: 0 分</div>
            <div class="pill hidden" id="meAdmin">管理员</div>
          </div>
          <div class="row" style="margin-top: 16px;">
            <button class="ghost" id="refreshButton" type="button">刷新面板</button>
            <button class="ghost" id="logoutButton" type="button">退出登录</button>
          </div>
          <p class="notice">计费单位为“分”。例如 123 表示 1.23 元。当前实现使用 D1 + Worker，适合作为 Cloudflare MVP。</p>
        </div>
      </section>

      <section class="grid hidden" id="mainPanel">
        <div class="panel">
          <h2>上传渠道</h2>
          <form id="channelForm">
            <label>渠道名称<input name="name" required placeholder="例如：OpenAI 官方 / 自建代理" /></label>
            <label>供应商
              <select name="provider">
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
              </select>
            </label>
            <label>基础地址<input name="base_url" placeholder="默认自动填官方地址" /></label>
            <label>接口路径<input name="endpoint_path" placeholder="/v1/chat/completions 或 /v1/messages" /></label>
            <label>默认模型<input name="default_model" placeholder="例如 gpt-4.1-mini / claude-sonnet-4-5" /></label>
            <label>渠道 API Key<input name="api_key" type="password" required /></label>
            <label>输入价格（分 / 1K tokens）<input name="price_input_cents_per_1k" type="number" min="0" value="1" required /></label>
            <label>输出价格（分 / 1K tokens）<input name="price_output_cents_per_1k" type="number" min="0" value="2" required /></label>
            <button type="submit">保存渠道</button>
          </form>
          <p class="error" id="channelError"></p>
        </div>

        <div class="panel">
          <h2>可调用渠道</h2>
          <div class="cards" id="channelsList"></div>
        </div>

        <div class="panel">
          <h2>统一代理调用</h2>
          <form id="proxyForm">
            <label>选择渠道
              <select name="channel_id" id="proxyChannelSelect"></select>
            </label>
            <label>JSON 请求体
              <textarea name="payload" id="payloadInput">{ "messages": [{ "role": "user", "content": "你好" }] }</textarea>
            </label>
            <button type="submit">发起调用</button>
          </form>
          <p class="error" id="proxyError"></p>
          <pre id="proxyOutput">等待调用结果...</pre>
        </div>

        <div class="panel">
          <h2>我的渠道</h2>
          <div class="cards" id="myChannelsList"></div>
        </div>

        <div class="panel">
          <h2>最近调用</h2>
          <div class="cards" id="usageList"></div>
        </div>

        <div class="panel hidden" id="adminPanel">
          <h2>管理员充值</h2>
          <form id="creditForm">
            <label>用户
              <select name="user_id" id="creditUserSelect"></select>
            </label>
            <label>变动额度（分，可负数）<input name="amount_cents" type="number" value="1000" required /></label>
            <button type="submit">提交额度变更</button>
          </form>
          <p class="error" id="creditError"></p>
          <div class="cards" id="usersList" style="margin-top: 14px;"></div>
        </div>
      </section>
    </main>

    <script>
      const state = {
        me: null,
        channels: [],
        users: [],
      };

      const el = (id) => document.getElementById(id);

      async function api(path, options = {}) {
        const response = await fetch(path, {
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
          },
          ...options,
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(data.error || "请求失败");
        }
        return data;
      }

      function centsToText(cents) {
        return (Number(cents || 0) / 100).toFixed(2) + " 元";
      }

      async function refreshApp() {
        try {
          const me = await api("/api/me", { method: "GET" });
          state.me = me.user;
          state.myChannels = me.my_channels || [];
          state.usageLogs = me.usage_logs || [];
          const channelData = await api("/api/channels", { method: "GET" });
          state.channels = channelData.channels || [];
          if (state.me.is_admin) {
            const admin = await api("/api/admin/users", { method: "GET" });
            state.users = admin.users || [];
          } else {
            state.users = [];
          }
          render();
        } catch (error) {
          state.me = null;
          render();
        }
      }

      function render() {
        const loggedIn = Boolean(state.me);
        el("authPanel").classList.toggle("hidden", loggedIn);
        el("accountPanel").classList.toggle("hidden", !loggedIn);
        el("mainPanel").classList.toggle("hidden", !loggedIn);

        if (!loggedIn) {
          return;
        }

        el("meEmail").textContent = state.me.email;
        el("meBalance").textContent = "额度: " + centsToText(state.me.balance_cents);
        el("meAdmin").classList.toggle("hidden", !state.me.is_admin);
        el("adminPanel").classList.toggle("hidden", !state.me.is_admin);

        el("channelsList").innerHTML = state.channels.map((channel) => \`
          <div class="card">
            <strong>\${channel.name}</strong>
            <div class="meta">提供者：\${channel.owner_email} | \${channel.provider} | \${channel.default_model || "未设默认模型"}</div>
            <div class="meta">地址：\${channel.base_url}\${channel.endpoint_path}</div>
            <div class="meta">价格：输入 \${channel.price_input_cents_per_1k} 分 / 1K，输出 \${channel.price_output_cents_per_1k} 分 / 1K</div>
          </div>
        \`).join("") || '<div class="card">暂无可用渠道</div>';

        el("myChannelsList").innerHTML = (state.myChannels || []).map((channel) => \`
          <div class="card">
            <strong>\${channel.name}</strong>
            <div class="meta">\${channel.provider} | \${channel.default_model || "未设默认模型"}</div>
            <div class="meta">\${channel.base_url}\${channel.endpoint_path}</div>
          </div>
        \`).join("") || '<div class="card">你还没有上传渠道</div>';

        el("usageList").innerHTML = (state.usageLogs || []).map((item) => \`
          <div class="card">
            <strong>#\${item.id} \${item.channel_name}</strong>
            <div class="meta">模型：\${item.model || "未记录"} | 输入：\${item.input_tokens} | 输出：\${item.output_tokens}</div>
            <div class="meta">扣费：\${centsToText(item.total_cost_cents)} | 状态：\${item.status}</div>
          </div>
        \`).join("") || '<div class="card">暂无调用记录</div>';

        const options = state.channels.map((channel) => \`<option value="\${channel.id}">\${channel.name} (#\${channel.id})</option>\`).join("");
        el("proxyChannelSelect").innerHTML = options;

        if (state.me.is_admin) {
          const userOptions = state.users.map((user) => \`<option value="\${user.id}">\${user.email} (\${centsToText(user.balance_cents)})</option>\`).join("");
          el("creditUserSelect").innerHTML = userOptions;
          el("usersList").innerHTML = state.users.map((user) => \`
            <div class="card">
              <strong>\${user.email}</strong>
              <div class="meta">角色：\${user.is_admin ? "管理员" : "用户"} | 余额：\${centsToText(user.balance_cents)}</div>
            </div>
          \`).join("");
        }
      }

      el("registerForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        el("authError").textContent = "";
        const form = new FormData(event.target);
        try {
          await api("/api/auth/register", {
            method: "POST",
            body: JSON.stringify({
              email: form.get("email"),
              password: form.get("password"),
            }),
          });
          event.target.reset();
          await refreshApp();
        } catch (error) {
          el("authError").textContent = error.message;
        }
      });

      el("loginForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        el("authError").textContent = "";
        const form = new FormData(event.target);
        try {
          await api("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({
              email: form.get("email"),
              password: form.get("password"),
            }),
          });
          event.target.reset();
          await refreshApp();
        } catch (error) {
          el("authError").textContent = error.message;
        }
      });

      el("channelForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        el("channelError").textContent = "";
        const form = new FormData(event.target);
        try {
          await api("/api/channels", {
            method: "POST",
            body: JSON.stringify(Object.fromEntries(form.entries())),
          });
          event.target.reset();
          await refreshApp();
        } catch (error) {
          el("channelError").textContent = error.message;
        }
      });

      el("proxyForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        el("proxyError").textContent = "";
        const form = new FormData(event.target);
        try {
          const payload = JSON.parse(String(form.get("payload") || "{}"));
          const data = await api("/api/proxy/" + form.get("channel_id"), {
            method: "POST",
            body: JSON.stringify(payload),
          });
          el("proxyOutput").textContent = JSON.stringify(data, null, 2);
          await refreshApp();
        } catch (error) {
          el("proxyError").textContent = error.message;
        }
      });

      el("creditForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        el("creditError").textContent = "";
        const form = new FormData(event.target);
        try {
          await api("/api/admin/credit", {
            method: "POST",
            body: JSON.stringify({
              user_id: Number(form.get("user_id")),
              amount_cents: Number(form.get("amount_cents")),
            }),
          });
          await refreshApp();
        } catch (error) {
          el("creditError").textContent = error.message;
        }
      });

      el("logoutButton").addEventListener("click", async () => {
        await api("/api/auth/logout", { method: "POST", body: "{}" });
        state.me = null;
        render();
      });

      el("refreshButton").addEventListener("click", refreshApp);

      refreshApp();
    </script>
  </body>
</html>`;
}
