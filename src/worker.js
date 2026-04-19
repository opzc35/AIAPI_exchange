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
        --bg: #f6f9fc;
        --panel: #fff;
        --ink: #1a1f36;
        --muted: #697386;
        --subtle: #8792a2;
        --border: #e3e8ee;
        --line: #c1c9d2;
        --accent: #635bff;
        --accent-light: #e6e8ff;
        --accent-hover: #7a73ff;
        --success: #3ecf8e;
        --success-light: #e6f9f0;
        --warn: #f5a623;
        --warn-light: #fef4e8;
        --error: #df1b41;
        --error-light: #fde8ee;
        --radius: 6px;
        --radius-lg: 8px;
        --shadow: 0 1px 3px rgba(50,50,93,.08), 0 1px 1px rgba(0,0,0,.05);
        --shadow-lg: 0 4px 6px rgba(50,50,93,.11), 0 1px 3px rgba(0,0,0,.08);
      }

      * { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
        color: var(--ink);
        background: var(--bg);
        min-height: 100vh;
        -webkit-font-smoothing: antialiased;
      }

      a { color: var(--accent); text-decoration: none; }
      a:hover { text-decoration: underline; }

      .shell {
        max-width: 1100px;
        margin: 0 auto;
        padding: 0 24px;
      }

      /* Header */
      .header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 0;
        background: var(--panel);
        border-bottom: 1px solid var(--border);
        margin-bottom: 32px;
      }
      .header-logo {
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .header-logo-icon {
        width: 28px;
        height: 28px;
        background: var(--accent);
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-size: 12px;
        color: #fff;
      }
      .header-title {
        font-size: 16px;
        font-weight: 600;
        color: var(--ink);
      }
      .header-actions {
        display: flex;
        gap: 8px;
        align-items: center;
      }

      /* Badge */
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 3px 10px;
        font-size: 12px;
        font-weight: 500;
        border-radius: 999px;
        border: 1px solid var(--border);
        color: var(--muted);
        background: var(--bg);
      }
      .badge-admin {
        color: var(--accent);
        border-color: var(--accent-light);
        background: var(--accent-light);
      }
      .badge-success {
        color: var(--success);
        border-color: var(--success-light);
        background: var(--success-light);
      }

      /* Nav Tabs */
      .nav-tabs {
        display: flex;
        gap: 0;
        border-bottom: 2px solid var(--border);
        margin-bottom: 24px;
      }
      .nav-tab {
        padding: 10px 20px;
        font-size: 14px;
        font-weight: 500;
        color: var(--muted);
        cursor: pointer;
        border-bottom: 2px solid transparent;
        margin-bottom: -2px;
        transition: color 0.15s, border-color 0.15s;
        user-select: none;
      }
      .nav-tab:hover {
        color: var(--ink);
      }
      .nav-tab.active {
        color: var(--accent);
        border-bottom-color: var(--accent);
      }

      /* Grid */
      .grid-2 {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
      }
      .grid-3 {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 16px;
      }

      /* Panel */
      .panel {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: var(--radius-lg);
        padding: 24px;
        box-shadow: var(--shadow);
      }

      /* Section */
      .section {
        margin-bottom: 24px;
      }

      /* Titles */
      h2 {
        font-size: 18px;
        font-weight: 600;
        color: var(--ink);
        margin-bottom: 16px;
      }

      /* Form */
      form {
        display: grid;
        gap: 14px;
      }
      label {
        display: grid;
        gap: 4px;
        font-size: 13px;
        font-weight: 500;
        color: var(--muted);
      }

      /* Input */
      input, select, textarea {
        width: 100%;
        padding: 8px 12px;
        font-size: 14px;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        background: var(--panel);
        color: var(--ink);
        outline: none;
        transition: border-color 0.2s, box-shadow 0.2s;
      }
      input:focus, select:focus, textarea:focus {
        border-color: var(--accent);
        box-shadow: 0 0 0 3px var(--accent-light);
      }
      textarea {
        min-height: 120px;
        resize: vertical;
        font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
        font-size: 13px;
        line-height: 1.5;
        background: var(--bg);
      }

      /* Button */
      button {
        font-size: 14px;
        font-weight: 500;
        border: 1px solid var(--accent);
        border-radius: var(--radius);
        padding: 8px 18px;
        cursor: pointer;
        transition: background 0.15s, box-shadow 0.15s;
        background: var(--accent);
        color: #fff;
      }
      button:hover {
        background: var(--accent-hover);
        box-shadow: var(--shadow-lg);
      }
      .btn-outline {
        background: var(--panel);
        color: var(--accent);
        border-color: var(--border);
      }
      .btn-outline:hover {
        background: var(--accent-light);
        color: var(--accent);
        border-color: var(--accent);
        box-shadow: none;
      }
      .btn-ghost {
        background: transparent;
        color: var(--muted);
        border-color: var(--border);
      }
      .btn-ghost:hover {
        background: var(--bg);
        color: var(--ink);
        border-color: var(--line);
        box-shadow: none;
      }

      /* Info row */
      .info-row {
        display: flex;
        gap: 12px;
        align-items: center;
        flex-wrap: wrap;
        margin-bottom: 16px;
      }

      /* Table */
      .table-wrap {
        overflow-x: auto;
        border-radius: var(--radius-lg);
        border: 1px solid var(--border);
        background: var(--panel);
      }
      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
      }
      thead th {
        font-weight: 600;
        color: var(--muted);
        text-align: left;
        padding: 10px 14px;
        border-bottom: 1px solid var(--border);
        background: var(--bg);
        font-size: 12px;
        letter-spacing: 0.02em;
      }
      tbody td {
        padding: 10px 14px;
        border-bottom: 1px solid var(--border);
        color: var(--ink);
      }
      tbody tr:last-child td {
        border-bottom: 0;
      }
      tbody tr:hover {
        background: var(--bg);
      }

      /* Pre / Terminal */
      pre {
        margin: 0;
        padding: 16px;
        border-radius: var(--radius-lg);
        background: #1a1f36;
        border: 1px solid var(--border);
        color: #cdd6e4;
        overflow: auto;
        font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
        font-size: 13px;
        line-height: 1.6;
        box-shadow: var(--shadow);
      }

      /* Notice */
      .notice {
        padding: 10px 14px;
        border-radius: var(--radius);
        border: 1px solid var(--warn-light);
        background: var(--warn-light);
        color: #9a6b1e;
        font-size: 13px;
        line-height: 1.5;
      }

      /* Error */
      .error {
        color: var(--error);
        font-size: 13px;
        margin-top: 8px;
      }

      /* Divider */
      .divider {
        border: 0;
        border-top: 1px solid var(--border);
        margin: 24px 0;
      }

      /* Empty */
      .empty {
        padding: 32px 0;
        text-align: center;
        color: var(--subtle);
        font-size: 14px;
      }

      /* Auth */
      .auth-wrap {
        display: flex;
        justify-content: center;
        padding: 48px 0;
      }
      .auth-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 24px;
        max-width: 600px;
      }

      /* Status dot */
      .status-dot {
        display: inline-block;
        width: 6px;
        height: 6px;
        border-radius: 50%;
        margin-right: 4px;
      }
      .status-dot.success { background: var(--success); }
      .status-dot.error { background: var(--error); }
      .status-dot.warn { background: var(--warn); }

      .hidden { display: none !important; }

      @media (max-width: 640px) {
        .shell { padding: 0 16px; }
        .auth-grid { grid-template-columns: 1fr; max-width: 100%; }
        .grid-2 { grid-template-columns: 1fr; }
        .grid-3 { grid-template-columns: 1fr; }
        .panel { padding: 16px; }
        .nav-tabs { flex-wrap: wrap; }
        .nav-tab { padding: 8px 12px; font-size: 13px; }
      }
    </style>
  </head>
  <body>
    <main class="shell">
      <!-- Header -->
      <header class="header">
        <div class="header-logo">
          <div class="header-logo-icon">AI</div>
          <span class="header-title">AIAPI Exchange</span>
        </div>
        <div class="header-actions" id="headerActions">
          <span class="badge badge-admin hidden" id="meAdmin">Admin</span>
          <span class="badge badge-success hidden" id="headerBalance">--</span>
          <button class="btn-ghost hidden" id="logoutButton" type="button">Logout</button>
        </div>
      </header>

      <!-- Auth Panel -->
      <section class="hidden" id="authPanel">
        <div class="auth-wrap">
          <div class="auth-grid">
            <div class="panel">
              <h2>Create Account</h2>
              <form id="registerForm">
                <label>Email<input name="email" type="email" required /></label>
                <label>Password<input name="password" type="password" minlength="8" required /></label>
                <button type="submit">Register</button>
              </form>
              <p class="error" id="authError"></p>
            </div>
            <div class="panel">
              <h2>Login</h2>
              <form id="loginForm">
                <label>Email<input name="email" type="email" required /></label>
                <label>Password<input name="password" type="password" required /></label>
                <button type="submit">Login</button>
              </form>
            </div>
          </div>
        </div>
      </section>

      <!-- Logged-in content -->
      <section class="hidden" id="loggedInContent">
        <!-- Account info bar -->
        <div class="info-row">
          <span class="badge" id="meEmail">--</span>
          <span class="badge badge-success" id="meBalanceBadge">Balance: 0</span>
          <button class="btn-ghost" id="refreshButton" type="button">Refresh</button>
        </div>
        <p class="notice">Billing unit is "cents". 123 cents = 1.23 yuan. Powered by Cloudflare Workers + D1.</p>

        <hr class="divider" />

        <!-- Nav Tabs -->
        <div class="nav-tabs" id="navTabs">
          <div class="nav-tab active" data-tab="dashboard" onclick="switchTab('dashboard')">Dashboard</div>
          <div class="nav-tab" data-tab="channels" onclick="switchTab('channels')">Channels</div>
          <div class="nav-tab" data-tab="proxy" onclick="switchTab('proxy')">Proxy</div>
          <div class="nav-tab hidden" id="adminTab" data-tab="admin" onclick="switchTab('admin')">Admin</div>
        </div>

        <!-- Dashboard Tab -->
        <div class="tab-content" id="tab-dashboard">
          <div class="section">
            <h2>Available Channels</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Name</th><th>Provider</th><th>Model</th><th>Endpoint</th><th>Input Price</th><th>Output Price</th></tr>
                </thead>
                <tbody id="channelsList"></tbody>
              </table>
            </div>
          </div>
          <div class="section">
            <h2>Recent Usage</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>#</th><th>Channel</th><th>Model</th><th>Input</th><th>Output</th><th>Cost</th><th>Status</th></tr>
                </thead>
                <tbody id="usageList"></tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Channels Tab -->
        <div class="tab-content hidden" id="tab-channels">
          <div class="section">
            <div class="panel">
              <h2>Add Channel</h2>
              <form id="channelForm">
                <div class="grid-2">
                  <label>Name<input name="name" required placeholder="e.g. OpenAI Official" /></label>
                  <label>Provider
                    <select name="provider">
                      <option value="openai">OpenAI</option>
                      <option value="anthropic">Anthropic</option>
                    </select>
                  </label>
                  <label>Base URL<input name="base_url" placeholder="Default: official API address" /></label>
                  <label>Endpoint Path<input name="endpoint_path" placeholder="/v1/chat/completions" /></label>
                  <label>Default Model<input name="default_model" placeholder="e.g. gpt-4.1-mini" /></label>
                  <label>API Key<input name="api_key" type="password" required /></label>
                  <label>Input Price (cents/1K tokens)<input name="price_input_cents_per_1k" type="number" min="0" value="1" required /></label>
                  <label>Output Price (cents/1K tokens)<input name="price_output_cents_per_1k" type="number" min="0" value="2" required /></label>
                </div>
                <button type="submit" style="margin-top:12px;">Save Channel</button>
              </form>
              <p class="error" id="channelError"></p>
            </div>
          </div>
          <div class="section">
            <h2>My Channels</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Name</th><th>Provider</th><th>Model</th><th>Endpoint</th></tr>
                </thead>
                <tbody id="myChannelsList"></tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Proxy Tab -->
        <div class="tab-content hidden" id="tab-proxy">
          <div class="section">
            <div class="panel">
              <h2>Proxy Request</h2>
              <form id="proxyForm">
                <label>Channel
                  <select name="channel_id" id="proxyChannelSelect"></select>
                </label>
                <label>JSON Payload
                  <textarea name="payload" id="payloadInput">{ "messages": [{ "role": "user", "content": "Hello" }] }</textarea>
                </label>
                <button type="submit">Send Request</button>
              </form>
              <p class="error" id="proxyError"></p>
              <pre id="proxyOutput" style="margin-top:16px;">Awaiting response...</pre>
            </div>
          </div>
        </div>

        <!-- Admin Tab -->
        <div class="tab-content hidden" id="tab-admin">
          <div class="section">
            <div class="panel">
              <h2>Admin \u2014 Credit Management</h2>
              <form id="creditForm">
                <div class="grid-2">
                  <label>User
                    <select name="user_id" id="creditUserSelect"></select>
                  </label>
                  <label>Amount (cents, can be negative)<input name="amount_cents" type="number" value="1000" required /></label>
                </div>
                <button type="submit" style="margin-top:12px;">Apply Credit</button>
              </form>
              <p class="error" id="creditError"></p>
            </div>
          </div>
          <div class="section">
            <h2>All Users</h2>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Email</th><th>Role</th><th>Balance</th></tr>
                </thead>
                <tbody id="usersList"></tbody>
              </table>
            </div>
          </div>
        </div>
      </section>
    </main>

    <script>
      const state = { me: null, channels: [], users: [], activeTab: "dashboard" };
      const el = (id) => document.getElementById(id);

      function switchTab(tabName) {
        state.activeTab = tabName;
        document.querySelectorAll(".nav-tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tabName));
        document.querySelectorAll(".tab-content").forEach(c => c.classList.toggle("hidden", c.id !== "tab-" + tabName));
      }

      async function api(path, options = {}) {
        const response = await fetch(path, {
          credentials: "include",
          headers: { "Content-Type": "application/json", ...(options.headers || {}) },
          ...options,
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || "Request failed");
        return data;
      }

      function centsToText(cents) {
        return (Number(cents || 0) / 100).toFixed(2) + " yuan";
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
        el("loggedInContent").classList.toggle("hidden", !loggedIn);
        el("logoutButton").classList.toggle("hidden", !loggedIn);
        el("headerBalance").classList.toggle("hidden", !loggedIn);

        if (!loggedIn) return;

        el("meEmail").textContent = state.me.email;
        el("meBalanceBadge").textContent = "Balance: " + centsToText(state.me.balance_cents);
        el("headerBalance").textContent = centsToText(state.me.balance_cents);
        el("meAdmin").classList.toggle("hidden", !state.me.is_admin);
        el("adminTab").classList.toggle("hidden", !state.me.is_admin);

        if (!state.me.is_admin && state.activeTab === "admin") {
          switchTab("dashboard");
        }

        el("channelsList").innerHTML = state.channels.length
          ? state.channels.map(c => \`<tr>
              <td>\${c.name}</td>
              <td>\${c.provider}</td>
              <td>\${c.default_model || "default"}</td>
              <td style="font-size:12px;color:var(--subtle);">\${c.base_url}\${c.endpoint_path}</td>
              <td>\${c.price_input_cents_per_1k}c/1K</td>
              <td>\${c.price_output_cents_per_1k}c/1K</td>
            </tr>\`).join("")
          : '<tr><td colspan="6" class="empty">No channels available</td></tr>';

        el("myChannelsList").innerHTML = (state.myChannels || []).length
          ? state.myChannels.map(c => \`<tr>
              <td>\${c.name}</td>
              <td>\${c.provider}</td>
              <td>\${c.default_model || "default"}</td>
              <td style="font-size:12px;color:var(--subtle);">\${c.base_url}\${c.endpoint_path}</td>
            </tr>\`).join("")
          : '<tr><td colspan="4" class="empty">You haven\'t added any channels</td></tr>';

        el("usageList").innerHTML = (state.usageLogs || []).length
          ? state.usageLogs.map(item => \`<tr>
              <td>\${item.id}</td>
              <td>\${item.channel_name}</td>
              <td>\${item.model || "unknown"}</td>
              <td>\${item.input_tokens}</td>
              <td>\${item.output_tokens}</td>
              <td>\${centsToText(item.total_cost_cents)}</td>
              <td><span class="status-dot \${item.status === 'success' ? 'success' : 'error'}"></span>\${item.status}</td>
            </tr>\`).join("")
          : '<tr><td colspan="7" class="empty">No usage logs yet</td></tr>';

        el("proxyChannelSelect").innerHTML = state.channels.map(c => \`<option value="\${c.id}">\${c.name} (#\${c.id})</option>\`).join("");

        if (state.me.is_admin) {
          el("creditUserSelect").innerHTML = state.users.map(u => \`<option value="\${u.id}">\${u.email} (\${centsToText(u.balance_cents)})</option>\`).join("");
          el("usersList").innerHTML = state.users.map(u => \`<tr>
              <td>\${u.email}</td>
              <td>\${u.is_admin ? "Admin" : "User"}</td>
              <td>\${centsToText(u.balance_cents)}</td>
            </tr>\`).join("");
        }
      }

      el("registerForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        el("authError").textContent = "";
        const form = new FormData(event.target);
        try {
          await api("/api/auth/register", {
            method: "POST",
            body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
          });
          event.target.reset();
          await refreshApp();
        } catch (error) { el("authError").textContent = error.message; }
      });

      el("loginForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        el("authError").textContent = "";
        const form = new FormData(event.target);
        try {
          await api("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
          });
          event.target.reset();
          await refreshApp();
        } catch (error) { el("authError").textContent = error.message; }
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
        } catch (error) { el("channelError").textContent = error.message; }
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
        } catch (error) { el("proxyError").textContent = error.message; }
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
        } catch (error) { el("creditError").textContent = error.message; }
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