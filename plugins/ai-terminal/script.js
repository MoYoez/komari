const server = require("server");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

if (typeof server.terminal !== "function") throw new Error("AI Terminal requires the OAuth PTY fork of Komari with server.terminal support");

const PREFIX = "/api/ai-terminal";
const CONSENT_TTL = 300;
const CODE_TTL = 60;
const SECONDS_PER_MINUTE = 60;
const SECONDS_PER_DAY = 86400;
const ACCESS_SCOPE = "access:read";
const PTY_SCOPES = ["pty:read", "pty:write"];
const QUERY_PURPOSE = "查询可用机器和已有授权";
const SCOPE_INFO = {
  "access:read": {title: "查询机器与授权", description: "查看允许访问的机器及本应用已有的授权，不读取终端输出或执行命令"},
  "pty:read": {title: "查看终端", description: "读取本次授权的会话状态和终端输出"},
  "pty:write": {title: "控制终端", description: "打开会话、输入命令、调整尺寸和关闭终端"},
};
const SCOPES = Object.keys(SCOPE_INFO);
const config = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json"), "utf8"));
const pageStyles = fs.readFileSync(path.join(__dirname, "styles.css"), "utf8");
const TERMINAL_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 8 4 4-4 4m6 0h4"/></svg>';
const grantsPath = path.join(__storageDir__, "grants.json");
const pending = new Map();
const codes = new Map();
const revokeForms = new Map();
if (!fs.existsSync(grantsPath)) fs.writeFileSync(grantsPath, "[]");
let grants = JSON.parse(fs.readFileSync(grantsPath, "utf8"));

if (new URL(config.admin_origin).origin !== config.admin_origin || ![config.access_token_ttl_seconds, config.query_token_ttl_seconds].every(v => Number.isInteger(v) && v > 0)) {
  throw new Error("Set admin_origin and positive access_token_ttl_seconds/query_token_ttl_seconds in config.json");
}
for (const client of config.clients) {
  if (!client.id || !client.name || client.redirect_uris.length === 0 || client.hosts.length === 0 || client.scopes.length === 0) throw new Error("Incomplete OAuth client configuration");
  for (const host of client.hosts) if (!config.hosts.some(h => h.uuid === host)) throw new Error("OAuth client references an unknown host");
  for (const scope of client.scopes) if (!SCOPES.includes(scope)) throw new Error("Unsupported configured scope: " + scope);
  for (const uri of client.redirect_uris) {
    const url = new URL(uri);
    if (url.hash || url.username || url.password || (url.protocol !== "https:" && !(url.protocol === "http:" && url.hostname === "127.0.0.1"))) throw new Error("Unsupported redirect URI: " + uri);
  }
}

function now() { return Math.floor(Date.now() / 1000); }
function random() { return crypto.randomBytes(32).toString("hex"); }
function digest(value, encoding) { return crypto.createHash("sha256").update(value).digest(encoding); }
function save(next) { fs.writeFileSync(grantsPath, JSON.stringify(next, null, 2)); grants = next; }
function fail(status, code, message) { const error = new Error(message); error.status = status; error.code = code; throw error; }
function escape(value) { return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
function json(res, status, value) { res.statusCode = status; res.setHeader("Content-Type", "application/json; charset=utf-8"); res.end(JSON.stringify(value)); }
function redirect(res, url) { res.statusCode = 303; res.setHeader("Location", url.toString()); res.end(); }
function page(res, title, body) {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · Komari</title><style>${pageStyles}</style></head><body><div class="shell"><header class="masthead"><a class="brand" href="/admin"><span class="brand-icon">${TERMINAL_ICON}</span>Komari</a><span class="product-name">AI Terminal</span></header><main><h1>${escape(title)}</h1>${body}</main><footer class="page-footer"><a class="text-link" href="/admin">返回 Komari</a><span>你的主机，由你掌控</span></footer></div></body></html>`);
}
function route(method, suffix, handler) {
  server.route(method, PREFIX + suffix, async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try { await handler(req, res); }
    catch (error) {
      if (!error.status) console.error(String(error));
      json(res, error.status || 500, {error: error.code || "server_error", error_description: error.message});
    }
  });
}
function administrator(req) {
  if (req.context.role !== "admin" || !req.context.user_uuid) fail(401, "login_required", "Log in to Komari on the administrator domain, then reopen the authorization URL.");
  return req.context.user_uuid;
}
function form(req) {
  if (!String(req.headers["content-type"]).startsWith("application/x-www-form-urlencoded")) fail(400, "invalid_request", "Expected application/x-www-form-urlencoded");
  return new URLSearchParams(req.body);
}
function body(req) {
  if (!String(req.headers["content-type"]).startsWith("application/json")) fail(400, "invalid_request", "Expected application/json");
  try { return JSON.parse(req.body); } catch (_) { fail(400, "invalid_request", "Invalid JSON body"); }
}
function collectExpired() {
  for (const store of [pending, codes, revokeForms]) for (const [id, value] of store) if (value.expires_at <= now()) store.delete(id);
}
async function bearer(req, scope) {
  const header = req.headers.authorization;
  if (typeof header !== "string" || !/^Bearer /i.test(header)) fail(401, "invalid_token", "An OAuth bearer token is required");
  const tokenHash = digest(header.slice(7), "hex");
  const grant = grants.find(g => g.token_hash === tokenHash);
  if (!grant || grant.expires_at <= now()) fail(401, "invalid_token", "The token is unknown, expired or revoked; authorize again");
  if (!grant.scopes.includes(scope)) fail(403, "insufficient_scope", "Required scope: " + scope);
  return grant;
}
async function ownedSession(grant, id) {
  const sessions = await server.terminal("list", {owner: grant.id});
  const session = sessions.find(s => s.id === id);
  if (!session || !grant.hosts.includes(session.client_uuid)) fail(404, "session_not_found", "No authorized session with this ID");
  return session;
}
async function allowedHosts(uuids) {
  const nodes = await server.call("admin:listClients");
  return uuids.map(uuid => {
    const node = nodes.find(n => n.uuid === uuid);
    if (!node) fail(400, "unknown_host", "The configured host no longer exists in Komari: " + uuid);
    return {uuid: node.uuid, name: node.name};
  });
}
async function revokeGrant(id) {
  save(grants.filter(g => g.id !== id));
  await server.terminal("closeOwner", {owner: id});
}

route("GET", "/oauth/authorize", async (req, res) => {
  const user = administrator(req);
  collectExpired();
  const q = req.query;
  const client = config.clients.find(c => c.id === q.client_id);
  if (!client || !client.redirect_uris.includes(q.redirect_uri)) fail(400, "invalid_request", "Unregistered client or redirect URI");
  if (q.response_type !== "code") fail(400, "unsupported_response_type", "Only authorization code is supported");
  if (q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge)) fail(400, "invalid_request", "PKCE S256 is required");
  if (!q.state || !q.scope) fail(400, "invalid_request", "state and scope are required");
  const scopes = q.scope.split(" ");
  if (!scopes.every(s => client.scopes.includes(s))) fail(400, "invalid_scope", "Unsupported scope");
  const queryOnly = scopes.includes(ACCESS_SCOPE);
  if (queryOnly && scopes.length !== 1) fail(400, "invalid_scope", "Query access and PTY access require separate grants");
  if (!queryOnly && (!q.hosts || !q.purpose || !q.purpose.trim())) fail(400, "invalid_request", "PTY requests must specify hosts and purpose");
  const requestedHosts = queryOnly ? client.hosts : q.hosts.split(",");
  if (!requestedHosts.length || !requestedHosts.every(h => client.hosts.includes(h))) fail(400, "invalid_request", "Requested hosts are outside this client's allowlist");
  const purpose = queryOnly ? QUERY_PURPOSE : q.purpose.trim();
  const tokenTtl = queryOnly ? config.query_token_ttl_seconds : config.access_token_ttl_seconds;
  const hosts = await allowedHosts(requestedHosts);
  const nonce = random();
  pending.set(nonce, {client_id: client.id, redirect_uri: q.redirect_uri, challenge: q.code_challenge, state: q.state, scopes, hosts: requestedHosts, purpose, token_ttl_seconds: tokenTtl, user_uuid: user, expires_at: now() + CONSENT_TTL});
  const hostFields = hosts.map(h => `<label class="selection"><input type="checkbox" name="host" value="${escape(h.uuid)}" checked><span><strong>${escape(h.name)}</strong><small>${queryOnly ? "允许查询此机器的名称与授权信息" : "通过 Komari Agent 连接"}</small></span></label>`).join("");
  const scopeFields = scopes.map(s => `<label class="selection"><input type="checkbox" name="scope" value="${escape(s)}" checked><span><strong>${SCOPE_INFO[s].title}</strong><small>${SCOPE_INFO[s].description}</small></span></label>`).join("");
  const connectionDetails = hosts.map(h => `<p>${escape(h.name)}<br><code>${escape(h.uuid)}</code></p>`).join("");
  const duration = queryOnly ? `${tokenTtl / SECONDS_PER_DAY} 天` : `${tokenTtl / SECONDS_PER_MINUTE} 分钟`;
  page(res, queryOnly ? "授权查询访问" : "确认终端申请", `
    <p class="lead">${queryOnly ? "允许 AI 查询机器和已有权限，方便之后预填操作申请。" : "AI 已预填目标机器、权限和用途，请确认本次申请。"}</p>
    <div class="client-card"><div><span class="supporting">请求访问的应用</span><strong class="client-name">${escape(client.name)}</strong></div><span class="chip">${duration}</span></div>
    <div class="request-purpose"><span class="supporting">申请用途</span><p>${escape(purpose)}</p></div>
    <form method="post"><input type="hidden" name="nonce" value="${nonce}">
      <fieldset><legend>${queryOnly ? "可查询的机器" : "本次操作的机器"}</legend>${hostFields}</fieldset>
      <fieldset><legend>允许的操作</legend>${scopeFields}</fieldset>
      <label class="field"><span>二次验证码</span><input type="text" name="code" placeholder="启用 2FA 后填写" autocomplete="one-time-code" inputmode="numeric"></label>
      <p class="helper">未启用两步验证时可留空。</p>
      <p class="notice">${queryOnly ? "此授权仅用于查询，不允许访问 PTY。实际终端操作仍需你单独确认短期授权。" : "终端继承主机 Agent 的系统权限。你可以随时撤销授权，同时关闭对应的终端会话。"}</p>
      <details><summary>连接信息</summary><div class="connection-details">${connectionDetails}<p>权限：<code>${escape(scopes.join(" "))}</code></p><p>授权回调<br><code>${escape(q.redirect_uri)}</code></p></div></details>
      <div class="actions"><button class="secondary" name="decision" value="deny">取消</button><button name="decision" value="approve">${queryOnly ? "允许查询" : "授权本次操作"} <span aria-hidden="true">→</span></button></div>
    </form><div class="inline-link"><a class="text-link" href="${PREFIX}/oauth/grants">管理已有授权</a></div>`);
});

route("POST", "/oauth/authorize", async (req, res) => {
  const user = administrator(req);
  const f = form(req);
  const nonce = f.get("nonce");
  const request = pending.get(nonce);
  if (!request || request.user_uuid !== user || request.expires_at <= now()) fail(400, "invalid_request", "Consent request is missing or expired");
  const target = new URL(request.redirect_uri);
  target.searchParams.set("state", request.state);
  if (f.get("decision") === "deny") { pending.delete(nonce); target.searchParams.set("error", "access_denied"); redirect(res, target); return; }
  if (f.get("decision") !== "approve") fail(400, "invalid_request", "Explicit approval or denial is required");
  const hosts = f.getAll("host");
  const scopes = f.getAll("scope");
  if (!hosts.length || !hosts.every(h => request.hosts.includes(h))) fail(400, "invalid_request", "Select allowed hosts");
  if (!scopes.length || !scopes.every(s => request.scopes.includes(s))) fail(400, "invalid_scope", "Select requested scopes");
  pending.delete(nonce);
  await server.terminal("authorize", {user_uuid: user, code: f.get("code") || ""});
  const code = random();
  codes.set(code, {client_id: request.client_id, redirect_uri: request.redirect_uri, challenge: request.challenge, user_uuid: user, remote_ip: req.context.remote_ip, hosts, scopes, purpose: request.purpose, token_ttl_seconds: request.token_ttl_seconds, expires_at: now() + CODE_TTL});
  target.searchParams.set("code", code);
  redirect(res, target);
});

route("POST", "/oauth/token", async (req, res) => {
  collectExpired();
  const f = form(req);
  if (f.get("grant_type") !== "authorization_code") fail(400, "unsupported_grant_type", "Only authorization_code is supported");
  const code = codes.get(f.get("code"));
  if (!code || code.client_id !== f.get("client_id") || code.redirect_uri !== f.get("redirect_uri")) fail(400, "invalid_grant", "Invalid, expired or consumed authorization code");
  const verifier = f.get("code_verifier");
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) fail(400, "invalid_grant", "Invalid PKCE verifier");
  const challenge = digest(verifier, "base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  if (challenge !== code.challenge) fail(400, "invalid_grant", "PKCE verification failed");
  const token = random();
  const grant = {id: crypto.randomUUID(), token_hash: digest(token, "hex"), client_id: code.client_id, user_uuid: code.user_uuid, remote_ip: code.remote_ip, hosts: code.hosts, scopes: code.scopes, purpose: code.purpose, created_at: now(), expires_at: now() + code.token_ttl_seconds};
  save(grants.concat([grant]));
  codes.delete(f.get("code"));
  json(res, 200, {access_token: token, token_type: "Bearer", expires_in: code.token_ttl_seconds, expires_at: grant.expires_at, scope: grant.scopes.join(" "), allowed_hosts: grant.hosts, grant_id: grant.id});
});

route("POST", "/oauth/revoke", async (req, res) => {
  const f = form(req);
  if (!f.get("token")) fail(400, "invalid_request", "token is required");
  const grant = grants.find(g => g.token_hash === digest(f.get("token"), "hex"));
  // RFC 7009 deliberately returns success for unknown/already revoked tokens.
  if (grant) await revokeGrant(grant.id);
  json(res, 200, {});
});

route("GET", "/access", async (req, res) => {
  const grant = await bearer(req, ACCESS_SCOPE);
  const client = config.clients.find(c => c.id === grant.client_id);
  if (!client) fail(403, "client_not_registered", "This OAuth client is no longer registered");
  const hosts = await allowedHosts(grant.hosts.filter(h => client.hosts.includes(h)));
  const visibleIds = hosts.map(h => h.uuid);
  const activeGrants = grants.filter(g => g.user_uuid === grant.user_uuid && g.client_id === grant.client_id && g.expires_at > now() && g.hosts.every(h => visibleIds.includes(h)));
  json(res, 200, {
    client_id: client.id,
    hosts,
    requestable_scopes: client.scopes.filter(s => PTY_SCOPES.includes(s)),
    pty_token_ttl_seconds: config.access_token_ttl_seconds,
    query_expires_at: grant.expires_at,
    grants: activeGrants.map(g => ({id: g.id, hosts: g.hosts, scopes: g.scopes, created_at: g.created_at, expires_at: g.expires_at, purpose: g.purpose})),
  });
});

route("GET", "/oauth/grants", async (req, res) => {
  const user = administrator(req);
  collectExpired();
  const nonce = random();
  revokeForms.set(nonce, {user_uuid: user, expires_at: now() + CONSENT_TTL});
  const rows = grants.filter(g => g.user_uuid === user && g.expires_at > now()).map(g => `<article class="grant-card">
    <div class="grant-heading"><h2>${escape(g.client_id)}</h2><span class="chip">${g.scopes.includes(ACCESS_SCOPE) ? "查询授权" : "终端授权"} · ${g.hosts.length} 台</span></div>
    <p class="grant-purpose">${escape(g.purpose)}</p>
    <p class="grant-meta">${g.scopes.map(s => SCOPE_INFO[s].title).join(" · ")}<br>有效至 ${escape(new Date(g.expires_at * 1000).toISOString().slice(0, 16).replace("T", " "))} UTC</p>
    <details><summary>查看授权详情</summary><div class="connection-details"><p>权限：<code>${escape(g.scopes.join(" "))}</code></p>${g.hosts.map(h => `<p><code>${escape(h)}</code></p>`).join("")}</div></details>
    <form method="post" action="${PREFIX}/oauth/revoke-grant"><input type="hidden" name="nonce" value="${nonce}"><input type="hidden" name="grant_id" value="${escape(g.id)}"><div class="actions"><button class="tonal">${g.scopes.includes(ACCESS_SCOPE) ? "撤销查询授权" : "撤销授权并关闭终端"}</button></div></form>
  </article>`).join("");
  page(res, "管理访问授权", `<p class="lead">分别管理长期查询授权与短期终端授权。</p>${rows || `<div class="empty-state"><div class="brand-icon">${TERMINAL_ICON}</div><h2>还没有已授权的应用</h2><p>完成一次授权后，你可以在这里查看或撤销访问。</p></div>`}`);
});

route("POST", "/oauth/revoke-grant", async (req, res) => {
  const user = administrator(req);
  const f = form(req);
  const formState = revokeForms.get(f.get("nonce"));
  if (!formState || formState.user_uuid !== user || formState.expires_at <= now()) fail(400, "invalid_request", "Reload the grants page before revoking");
  const grant = grants.find(g => g.id === f.get("grant_id") && g.user_uuid === user);
  if (!grant) fail(404, "grant_not_found", "Grant not found");
  await revokeGrant(grant.id);
  revokeForms.delete(f.get("nonce"));
  redirect(res, new URL(PREFIX + "/oauth/grants", config.admin_origin));
});

route("GET", "/pty/sessions", async (req, res) => {
  const grant = await bearer(req, "pty:read");
  const sessions = await server.terminal("list", {owner: grant.id});
  json(res, 200, sessions.filter(s => grant.hosts.includes(s.client_uuid)));
});

route("POST", "/pty/open", async (req, res) => {
  const grant = await bearer(req, "pty:write");
  const input = body(req);
  if (!grant.hosts.includes(input.client_uuid)) fail(403, "host_not_authorized", "This host was not authorized");
  json(res, 201, await server.terminal("open", {owner: grant.id, client_uuid: input.client_uuid, cols: input.cols, rows: input.rows, user_uuid: grant.user_uuid, remote_ip: grant.remote_ip, expires_at: grant.expires_at}));
});

for (const action of ["read", "write", "resize", "close"]) {
  route("POST", "/pty/" + action, async (req, res) => {
    const grant = await bearer(req, action === "read" ? "pty:read" : "pty:write");
    const input = body(req);
    await ownedSession(grant, input.id);
    const params = {owner: grant.id, id: input.id};
    if (action === "read") params.wait_ms = input.wait_ms;
    if (action === "write") params.data_base64 = input.data_base64;
    if (action === "resize") { params.cols = input.cols; params.rows = input.rows; }
    json(res, 200, await server.terminal(action, params));
  });
}

console.log("AI Terminal routes registered");
