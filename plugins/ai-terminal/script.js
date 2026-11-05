const server = require("server");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

if (typeof server.terminal !== "function") throw new Error("AI Terminal requires the OAuth PTY fork of Komari with server.terminal support");

const PREFIX = "/api/ai-terminal";
const CONSENT_TTL = 300;
const CODE_TTL = 60;
const SCOPES = ["pty:read", "pty:write"];
const config = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json"), "utf8"));
const grantsPath = path.join(__storageDir__, "grants.json");
const pending = new Map();
const codes = new Map();
const revokeForms = new Map();
if (!fs.existsSync(grantsPath)) fs.writeFileSync(grantsPath, "[]");
let grants = JSON.parse(fs.readFileSync(grantsPath, "utf8"));

if (new URL(config.admin_origin).origin !== config.admin_origin || !Number.isInteger(config.access_token_ttl_seconds) || config.access_token_ttl_seconds <= 0) {
  throw new Error("Set admin_origin and a positive access_token_ttl_seconds in config.json");
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
  res.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)}</title><style>body{margin:0;background:#f6f5fa;color:#252336;font:16px/1.7 system-ui,sans-serif}main{max-width:640px;margin:6vh auto;padding:32px;background:white;border-radius:16px}h1{font-size:24px}label{display:block;margin:12px 0}input[type=text]{padding:8px;border:1px solid #ddd;border-radius:6px}button{padding:10px 18px;border:0;border-radius:8px;background:#7052b8;color:white;cursor:pointer;margin-right:8px}button[value=deny]{background:#ece9f4;color:#252336}code{overflow-wrap:anywhere}small{color:#666}article{border-top:1px solid #eee;padding:12px 0}@media(max-width:700px){main{margin:12px;padding:24px}}</style><main><h1>${escape(title)}</h1>${body}</main></html>`);
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
  const nonce = random();
  pending.set(nonce, {client_id: client.id, redirect_uri: q.redirect_uri, challenge: q.code_challenge, state: q.state, scopes, hosts: client.hosts, user_uuid: user, expires_at: now() + CONSENT_TTL});
  const hosts = config.hosts.filter(h => client.hosts.includes(h.uuid));
  const hostFields = hosts.map(h => `<label><input type="checkbox" name="host" value="${escape(h.uuid)}" checked> ${escape(h.name)} <small>${escape(h.uuid)}</small></label>`).join("");
  const scopeFields = scopes.map(s => `<label><input type="checkbox" name="scope" value="${escape(s)}" checked> ${s === "pty:write" ? "打开终端、输入命令、调整尺寸及关闭终端" : "查看本次授权的终端状态及输出"} <small>${escape(s)}</small></label>`).join("");
  page(res, "授权 AI Terminal", `<p><strong>${escape(client.name)}</strong> 请求访问以下主机的终端。</p><p>有效期 ${config.access_token_ttl_seconds / 60} 分钟。终端继承各主机 Agent 的系统权限；授权可随时撤销。</p><form method="post"><input type="hidden" name="nonce" value="${nonce}"><h2>主机</h2>${hostFields}<h2>权限</h2>${scopeFields}<label>二次验证码（已开启 2FA 时填写）<br><input type="text" name="code" autocomplete="one-time-code" inputmode="numeric"></label><p><small>回调：<code>${escape(q.redirect_uri)}</code></small></p><button name="decision" value="approve">授权</button><button name="decision" value="deny">取消</button></form><p><a href="${PREFIX}/oauth/grants">管理已有授权</a></p>`);
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
  codes.set(code, {client_id: request.client_id, redirect_uri: request.redirect_uri, challenge: request.challenge, user_uuid: user, remote_ip: req.context.remote_ip, hosts, scopes, expires_at: now() + CODE_TTL});
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
  const grant = {id: crypto.randomUUID(), token_hash: digest(token, "hex"), client_id: code.client_id, user_uuid: code.user_uuid, remote_ip: code.remote_ip, hosts: code.hosts, scopes: code.scopes, created_at: now(), expires_at: now() + config.access_token_ttl_seconds};
  save(grants.concat([grant]));
  codes.delete(f.get("code"));
  json(res, 200, {access_token: token, token_type: "Bearer", expires_in: config.access_token_ttl_seconds, expires_at: grant.expires_at, scope: grant.scopes.join(" "), allowed_hosts: grant.hosts, grant_id: grant.id});
});

route("POST", "/oauth/revoke", async (req, res) => {
  const f = form(req);
  if (!f.get("token")) fail(400, "invalid_request", "token is required");
  const grant = grants.find(g => g.token_hash === digest(f.get("token"), "hex"));
  // RFC 7009 deliberately returns success for unknown/already revoked tokens.
  if (grant) await revokeGrant(grant.id);
  json(res, 200, {});
});

route("GET", "/oauth/grants", async (req, res) => {
  const user = administrator(req);
  collectExpired();
  const nonce = random();
  revokeForms.set(nonce, {user_uuid: user, expires_at: now() + CONSENT_TTL});
  const rows = grants.filter(g => g.user_uuid === user && g.expires_at > now()).map(g => `<article><strong>${escape(g.client_id)}</strong><p>${escape(g.scopes.join(" "))}<br>主机：${g.hosts.map(escape).join(", ")}<br>过期：${escape(new Date(g.expires_at * 1000).toISOString())}</p><form method="post" action="${PREFIX}/oauth/revoke-grant"><input type="hidden" name="nonce" value="${nonce}"><input type="hidden" name="grant_id" value="${escape(g.id)}"><button>撤销授权并关闭终端</button></form></article>`).join("");
  page(res, "AI Terminal 授权", `<p>撤销会立即关闭该授权创建的终端。</p>${rows || "<p>没有有效授权。</p>"}<p><a href="/admin">返回 Komari</a></p>`);
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
