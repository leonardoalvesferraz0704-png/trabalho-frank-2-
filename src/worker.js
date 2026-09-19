// src/worker.js
// Implementa, em um único arquivo, o mesmo contrato de seguranca descrito
// no laboratorio original (PKCE S256, state, nonce, sessoes opacas no D1),
// adaptado porque a conta Cloudflare nao oferece mais o roteamento
// automatico por pastas (Pages Functions classico).

const TX_COOKIE = "__Host-oauth-tx";
const SESSION_COOKIE = "__Host-session";
const TX_TTL_SECONDS = 600; // 10 minutos
const SESSION_TTL_SECONDS = 28800; // 8 horas

const PROVIDERS = {
  google: {
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
    scope: "openid email profile"
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    userEndpoint: "https://api.github.com/user"
  }
};

// ---------- utilidades de codificacao e hash ----------

function base64url(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlToBytes(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomToken() {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256Bytes(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

async function sha256Hex(value) {
  const bytes = await sha256Bytes(value);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function pkceChallenge(verifier) {
  return base64url(await sha256Bytes(verifier));
}

// ---------- cookies ----------

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};
  header.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) cookies[name] = value;
  });
  return cookies;
}

function setCookieHeader(name, value, { maxAge, sameSite = "Lax" } = {}) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "Secure", `SameSite=${sameSite}`];
  if (typeof maxAge === "number") parts.push(`Max-Age=${maxAge}`);
  return parts.join("; ");
}

function clearCookieHeader(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// ---------- respostas auxiliares ----------

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extraHeaders }
  });
}

function notFound() {
  return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
}

// ---------- inicio do login ----------

async function handleLoginStart(request, env, provider) {
  if (!PROVIDERS[provider]) return notFound();

  const clientId = env[`${provider.toUpperCase()}_CLIENT_ID`];
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  const txId = randomToken();
  const state = randomToken();
  const codeVerifier = randomToken();
  const nonce = provider === "google" ? randomToken() : null;
  const challenge = await pkceChallenge(codeVerifier);

  const idHash = await sha256Hex(txId);
  const stateHash = await sha256Hex(state);
  const expiresAt = Math.floor(Date.now() / 1000) + TX_TTL_SECONDS;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

  const authUrl = new URL(PROVIDERS[provider].authorizationEndpoint);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", PROVIDERS.google.scope);
    authUrl.searchParams.set("nonce", nonce);
  }
  // GitHub: sem scope (perfil publico) e sem nonce.

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": setCookieHeader(TX_COOKIE, txId, { maxAge: TX_TTL_SECONDS, sameSite: "Lax" }),
      "Cache-Control": "no-store"
    }
  });
}

// ---------- validacao do id_token do Google (JWKS, sem bibliotecas) ----------

async function fetchGoogleJwks() {
  const discovery = await fetch(PROVIDERS.google.discoveryUrl).then((r) => r.json());
  const jwks = await fetch(discovery.jwks_uri).then((r) => r.json());
  return { issuer: discovery.issuer, jwks };
}

function decodeJwtPart(part) {
  const bytes = base64urlToBytes(part);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}

async function importRsaKey(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function validateGoogleIdToken(idToken, env, expectedNonce) {
  const segments = idToken.split(".");
  if (segments.length !== 3) throw new Error("id_token malformado");
  const [headerPart, payloadPart, signaturePart] = segments;

  const header = decodeJwtPart(headerPart);
  const payload = decodeJwtPart(payloadPart);

  if (header.alg !== "RS256") throw new Error("algoritmo inesperado");

  const { issuer, jwks } = await fetchGoogleJwks();
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("chave publica nao encontrada");

  const key = await importRsaKey(jwk);
  const data = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  const signature = base64urlToBytes(signaturePart);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
  if (!valid) throw new Error("assinatura invalida");

  const now = Math.floor(Date.now() / 1000);
  const clockSkew = 120;

  if (payload.iss !== issuer && payload.iss !== `https://${issuer}`) {
    throw new Error("emissor invalido");
  }
  if (payload.aud !== env.GOOGLE_CLIENT_ID) throw new Error("audiencia invalida");
  if (typeof payload.exp !== "number" || payload.exp + clockSkew < now) throw new Error("token expirado");
  if (typeof payload.iat !== "number" || payload.iat - clockSkew > now) throw new Error("iat invalido");
  if (payload.nonce !== expectedNonce) throw new Error("nonce invalido");

  return payload; // contem sub, email, name, etc.
}

// ---------- callback ----------

async function handleCallback(request, env, provider) {
  if (!PROVIDERS[provider]) return notFound();

  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (error || !code || !state) {
    return new Response("Requisicao de retorno invalida.", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const cookies = parseCookies(request);
  const txId = cookies[TX_COOKIE];
  if (!txId) {
    return new Response("Cookie de transacao ausente.", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const idHash = await sha256Hex(txId);
  const row = await env.DB.prepare(
    `SELECT provider, state_hash, nonce, code_verifier, expires_at FROM oauth_transactions WHERE id_hash = ?`
  ).bind(idHash).first();

  const now = Math.floor(Date.now() / 1000);
  if (!row || row.expires_at < now || row.provider !== provider) {
    return new Response("Transacao ausente ou expirada.", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  const stateHash = await sha256Hex(state);
  if (stateHash !== row.state_hash) {
    await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();
    return new Response("state invalido.", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  // Apaga a transacao antes de concluir (impede reuso).
  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();

  const clientId = env[`${provider.toUpperCase()}_CLIENT_ID`];
  const clientSecret = env[`${provider.toUpperCase()}_CLIENT_SECRET`];
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    code_verifier: row.code_verifier
  });

  const tokenResponse = await fetch(PROVIDERS[provider].tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body: tokenBody
  });

  if (!tokenResponse.ok) {
    return new Response("Falha na troca do codigo.", { status: 400, headers: { "Cache-Control": "no-store" } });
  }
  const tokenData = await tokenResponse.json();

  let issuer, subject, email = null, displayName = null;

  if (provider === "google") {
    const claims = await validateGoogleIdToken(tokenData.id_token, env, row.nonce);
    issuer = "https://accounts.google.com";
    subject = claims.sub;
    email = claims.email ?? null;
    displayName = claims.name ?? null;
  } else {
    // GitHub: usa o access_token so para consultar /user, depois revoga.
    if (!tokenData.access_token || !/^bearer$/i.test(tokenData.token_type || "")) {
      return new Response("Resposta de token invalida.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }
    const userResponse = await fetch(PROVIDERS.github.userEndpoint, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "oauth-pages-lab"
      }
    });
    if (!userResponse.ok) {
      return new Response("Falha ao consultar perfil do GitHub.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }
    const userData = await userResponse.json();
    if (typeof userData.id !== "number") {
      return new Response("Perfil do GitHub invalido.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    issuer = "https://github.com";
    subject = String(userData.id);
    email = userData.email ?? null;
    displayName = userData.name ?? userData.login ?? null;

    const revokeResponse = await fetch(
      `https://api.github.com/applications/${clientId}/grant`,
      {
        method: "DELETE",
        headers: {
          Authorization: "Basic " + btoa(`${clientId}:${clientSecret}`),
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "Content-Type": "application/json",
          "User-Agent": "oauth-pages-lab"
        },
        body: JSON.stringify({ access_token: tokenData.access_token })
      }
    );
    if (revokeResponse.status !== 204) {
      return new Response("Falha ao revogar autorizacao do GitHub.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }
  }

  // Cria a sessao opaca.
  const sessionId = randomToken();
  const sessionHash = await sha256Hex(sessionId);
  const sessionExpires = now + SESSION_TTL_SECONDS;

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(sessionHash, issuer, subject, email, displayName, sessionExpires, now).run();

  const headers = new Headers();
  headers.append("Set-Cookie", clearCookieHeader(TX_COOKIE));
  headers.append("Set-Cookie", setCookieHeader(SESSION_COOKIE, sessionId, { maxAge: SESSION_TTL_SECONDS, sameSite: "Strict" }));
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}

// ---------- /api/me ----------

async function handleMe(request, env) {
  const cookies = parseCookies(request);
  const sessionId = cookies[SESSION_COOKIE];
  if (!sessionId) return jsonResponse({ error: "sem sessao" }, 401);

  const sessionHash = await sha256Hex(sessionId);
  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(
    `SELECT issuer, subject, email, display_name, expires_at FROM sessions WHERE id_hash = ?`
  ).bind(sessionHash).first();

  if (!row || row.expires_at < now) return jsonResponse({ error: "sessao invalida" }, 401);

  return jsonResponse({
    issuer: row.issuer,
    subject: row.subject,
    email: row.email,
    displayName: row.display_name
  });
}

// ---------- logout ----------

async function handleLogout(request, env) {
  if (request.method !== "POST") return notFound();

  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return jsonResponse({ error: "origem invalida" }, 403);
  }

  const cookies = parseCookies(request);
  const sessionId = cookies[SESSION_COOKIE];
  if (sessionId) {
    const sessionHash = await sha256Hex(sessionId);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(sessionHash).run();
  }

  const headers = new Headers();
  headers.append("Set-Cookie", clearCookieHeader(SESSION_COOKIE));
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Type", "application/json");

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// ---------- roteador principal ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/health" && request.method === "GET") {
      return jsonResponse({ status: "ok" });
    }

    if (path === "/api/me" && request.method === "GET") {
      return handleMe(request, env);
    }

    if (path === "/oauth/logout" && request.method === "POST") {
      return handleLogout(request, env);
    }

    const loginMatch = path.match(/^\/oauth\/login\/([^/]+)$/);
    if (loginMatch && request.method === "GET") {
      return handleLoginStart(request, env, loginMatch[1]);
    }

    const callbackMatch = path.match(/^\/oauth\/callback\/([^/]+)$/);
    if (callbackMatch && request.method === "GET") {
      return handleCallback(request, env, callbackMatch[1]);
    }

    return notFound();
  }
};
