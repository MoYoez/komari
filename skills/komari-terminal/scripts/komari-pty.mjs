#!/usr/bin/env node
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFile, realpath, unlink, writeFile } from 'node:fs/promises';

const LOGIN_TIMEOUT_MS = 5 * 60 * 1000;
const MILLISECONDS_PER_SECOND = 1000;
const ACCESS_SCOPE = 'access:read';
const PTY_SCOPES = ['pty:read', 'pty:write'];
const LOGIN_COMMAND = 'login';
const AUTHORIZE_COMMAND = 'authorize HOSTS_CSV SCOPES_CSV DURATION PURPOSE';
const ACCESS_CREDENTIALS_FILE = 'access-credentials.json';
const PTY_CREDENTIALS_FILE = 'credentials.json';
const LOOPBACK_HOST = '127.0.0.1';
const CALLBACK_PATH = '/callback';
const MAX_PORT = 65535;
const INITIAL_COLS = 120;
const INITIAL_ROWS = 30;
const DEFAULT_WAIT_MS = 0;
const RANDOM_BYTES = 32;
const CTRL_C = 0x03;
const CONFIG_FIELDS = ['authorization_url', 'api_base', 'client_id', 'redirect_uri'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ARGUMENT_COUNTS = {
  login: [0], access: [0], authorize: [4], 'logout-access': [0],
  list: [0], open: [1], read: [1, 2], write: [2],
  command: [2], interrupt: [1], resize: [3], close: [1], logout: [0],
};

function print(value) {
  console.log(JSON.stringify(value));
}

function integer(value, name, minimum) {
  const number = Number(value);
  if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(number) || number < minimum) {
    throw new Error(`${name} must be an integer >= ${minimum}.`);
  }
  return number;
}

function csv(value, name) {
  const items = value.split(',');
  if (items.some((item) => !item || item !== item.trim()) || new Set(items).size !== items.length) {
    throw new Error(`${name} requires distinct comma-separated values without whitespace.`);
  }
  return items;
}

function parseArguments() {
  const args = process.argv.slice(2);
  let configPath = new URL('../config.json', import.meta.url);
  if (args[0] === '--config') {
    args.shift();
    configPath = args.shift();
    if (!configPath) throw new Error('--config requires a path.');
  }
  const name = args.shift();
  if (!Object.hasOwn(ARGUMENT_COUNTS, name)) {
    throw new Error(`Expected command: ${Object.keys(ARGUMENT_COUNTS).join(', ')}.`);
  }
  if (!ARGUMENT_COUNTS[name].includes(args.length)) {
    if (name === 'authorize') throw new Error(`Required: ${AUTHORIZE_COMMAND}.`);
    throw new Error(`Invalid argument count for ${name}.`);
  }
  if (name !== 'authorize' && args.length > 0 && args[0].length === 0) throw new Error('ID must not be empty.');

  let endpoint = `/pty/${name}`;
  let body;
  let authorization;
  switch (name) {
    case 'authorize': {
      const hosts = csv(args[0], 'HOSTS_CSV');
      const scopes = csv(args[1], 'SCOPES_CSV');
      if (!hosts.every((host) => UUID.test(host))) throw new Error('HOSTS_CSV must contain UUIDs.');
      if (!args[3].trim()) throw new Error('PURPOSE must not be empty.');
      authorization = { hosts, scopes, duration: args[2], purpose: args[3] };
      break;
    }
    case 'list':
      endpoint = '/pty/sessions';
      break;
    case 'open':
      if (!UUID.test(args[0])) throw new Error('CLIENT_UUID must be a UUID.');
      body = { client_uuid: args[0], cols: INITIAL_COLS, rows: INITIAL_ROWS };
      break;
    case 'read':
      body = { id: args[0], wait_ms: args.length === 2 ? integer(args[1], 'WAIT_MS', 0) : DEFAULT_WAIT_MS };
      break;
    case 'write':
    case 'command':
      endpoint = '/pty/write';
      body = { id: args[0], data_base64: Buffer.from(args[1] + (name === 'command' ? '\n' : ''), 'utf8').toString('base64') };
      break;
    case 'interrupt':
      endpoint = '/pty/write';
      body = { id: args[0], data_base64: Buffer.from([CTRL_C]).toString('base64') };
      break;
    case 'resize':
      body = { id: args[0], cols: integer(args[1], 'COLS', 1), rows: integer(args[2], 'ROWS', 1) };
      break;
    case 'close':
      body = { id: args[0] };
      break;
  }
  return { name, configPath, endpoint, body, authorization };
}

async function loadConfig(source) {
  const path = await realpath(source);
  const config = JSON.parse(await readFile(path, 'utf8'));
  if (config === null || typeof config !== 'object' || Object.keys(config).length !== CONFIG_FIELDS.length ||
      !CONFIG_FIELDS.every((key) => typeof config[key] === 'string' && config[key].trim().length > 0)) {
    throw new Error(`Config requires exactly: ${CONFIG_FIELDS.join(', ')}.`);
  }
  for (const key of ['authorization_url', 'api_base']) {
    const url = new URL(config[key]);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`${key} must be an absolute HTTP(S) URL.`);
    if (key === 'api_base' && (url.search || url.hash || config[key].endsWith('/'))) {
      throw new Error('api_base must have no trailing slash, query, or fragment.');
    }
  }
  const callback = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/callback$/.exec(config.redirect_uri);
  if (!callback || Number(callback[1]) > MAX_PORT) {
    throw new Error('redirect_uri must be http://127.0.0.1:PORT/callback with a fixed port from 1 to 65535.');
  }
  return {
    config, port: Number(callback[1]),
    credentialsPath: path.replace(/[^/\\]+$/, PTY_CREDENTIALS_FILE),
    accessCredentialsPath: path.replace(/[^/\\]+$/, ACCESS_CREDENTIALS_FILE),
  };
}

function validateCredentials(credentials, authorizationCommand) {
  if (credentials === null || typeof credentials !== 'object' ||
      typeof credentials.access_token !== 'string' || credentials.access_token.length === 0 ||
      typeof credentials.token_type !== 'string' || credentials.token_type.toLowerCase() !== 'bearer' ||
      !Number.isSafeInteger(credentials.expires_at) || credentials.expires_at <= 0 ||
      typeof credentials.scope !== 'string' || credentials.scope.length === 0 ||
      !Array.isArray(credentials.allowed_hosts) || !credentials.allowed_hosts.every((host) => typeof host === 'string' && UUID.test(host)) ||
      typeof credentials.grant_id !== 'string' || credentials.grant_id.length === 0) {
    throw new Error('Invalid OAuth credentials.');
  }
  const scopes = credentials.scope.split(' ');
  const matches = authorizationCommand === LOGIN_COMMAND
    ? credentials.scope === ACCESS_SCOPE
    : scopes.every((scope) => PTY_SCOPES.includes(scope));
  if (!matches) throw new Error('Credentials have the wrong scope for this authorization layer.');
}

function requireUnexpired(credentials, authorizationCommand) {
  if (credentials.expires_at <= Math.floor(Date.now() / MILLISECONDS_PER_SECOND)) {
    throw new Error(`Token expired; run ${authorizationCommand}.`);
  }
}

async function loadCredentials(path, authorizationCommand) {
  try {
    const credentials = JSON.parse(await readFile(path, 'utf8'));
    validateCredentials(credentials, authorizationCommand);
    return credentials;
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`No local credentials; run ${authorizationCommand}.`);
    if (error instanceof SyntaxError) throw new Error(`Invalid credentials JSON; run ${authorizationCommand}.`);
    throw new Error(`${error.message} Run ${authorizationCommand}.`);
  }
}

async function request(config, endpoint, options, authorizationCommand) {
  const response = await fetch(`${config.api_base}${endpoint}`, options);
  if (!response.ok) {
    const failure = await response.json();
    const hint = authorizationCommand !== null && [401, 403].includes(response.status)
      ? `; run ${authorizationCommand}.` : '';
    throw new Error(`${endpoint}: HTTP ${response.status}; ${failure.error}: ${failure.error_description}${hint}`);
  }
  return response;
}

async function receiveCode(config, port, authorizationUrl, state, signal) {
  let server;
  let onAbort;
  try {
    return await new Promise((resolve, reject) => {
      onAbort = () => reject(signal.reason);
      signal.addEventListener('abort', onAbort, { once: true });
      server = createServer((req, res) => {
        try {
          const callback = new URL(req.url, config.redirect_uri);
          if (req.method !== 'GET' || callback.origin !== new URL(config.redirect_uri).origin || callback.pathname !== CALLBACK_PATH) {
            throw new Error('Unsupported OAuth callback; expected GET /callback.');
          }
          const params = callback.searchParams;
          if (params.getAll('state').length !== 1 || params.get('state') !== state) {
            throw new Error('OAuth callback state mismatch.');
          }
          if (params.has('error')) throw new Error(`OAuth authorization failed: ${params.get('error')}.`);
          if (params.getAll('code').length !== 1 || !params.get('code')) {
            throw new Error('OAuth callback requires one authorization code.');
          }
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('Authorization received. Return to the CLI.');
          resolve(params.get('code'));
        } catch (error) {
          res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('Authorization failed. Return to the CLI.');
          reject(error);
        }
      });
      server.once('error', reject);
      server.listen(port, LOOPBACK_HOST, () => print({ authorization_url: authorizationUrl.href }));
    });
  } finally {
    signal.removeEventListener('abort', onAbort);
    if (server.listening) server.close();
  }
}

async function authorizeOAuth(config, port, credentialsPath, requested, authorizationCommand) {
  const verifier = randomBytes(RANDOM_BYTES).toString('base64url');
  const state = randomBytes(RANDOM_BYTES).toString('base64url');
  const authorizationUrl = new URL(config.authorization_url);
  const params = {
    response_type: 'code', client_id: config.client_id, redirect_uri: config.redirect_uri,
    ...requested, state, code_challenge_method: 'S256',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
  };
  for (const [key, value] of Object.entries(params)) authorizationUrl.searchParams.set(key, value);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('Authorization timed out after five minutes.')), LOGIN_TIMEOUT_MS);
  try {
    const code = await receiveCode(config, port, authorizationUrl, state, controller.signal);
    const response = await request(config, '/oauth/token', {
      method: 'POST', signal: controller.signal,
      body: new URLSearchParams({
        grant_type: 'authorization_code', client_id: config.client_id,
        redirect_uri: config.redirect_uri, code, code_verifier: verifier,
      }),
    }, null);
    const token = await response.json();
    const credentials = {
      access_token: token.access_token, token_type: token.token_type,
      expires_at: token.expires_at,
      scope: token.scope, allowed_hosts: token.allowed_hosts, grant_id: token.grant_id,
    };
    validateCredentials(credentials, authorizationCommand);
    await writeFile(credentialsPath, `${JSON.stringify(credentials, null, 2)}\n`, 'utf8');
    return {
      token_type: credentials.token_type, expires_at: credentials.expires_at,
      scope: credentials.scope, allowed_hosts: credentials.allowed_hosts, grant_id: credentials.grant_id,
    };
  } catch (error) {
    throw new Error(`${error.message} Run ${authorizationCommand}.`);
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  const operation = parseArguments();
  const { config, port, credentialsPath, accessCredentialsPath } = await loadConfig(operation.configPath);
  if (operation.name === 'login') {
    const result = await authorizeOAuth(config, port, accessCredentialsPath, { scope: ACCESS_SCOPE }, LOGIN_COMMAND);
    print({ logged_in: true, ...result });
    return;
  }

  if (operation.name === 'access' || operation.name === 'authorize') {
    const credentials = await loadCredentials(accessCredentialsPath, LOGIN_COMMAND);
    requireUnexpired(credentials, LOGIN_COMMAND);
    const response = await request(config, '/access', {
      method: 'GET', headers: { Authorization: `${credentials.token_type} ${credentials.access_token}` },
    }, LOGIN_COMMAND);
    const access = await response.json();
    if (operation.name === 'access') {
      print(access);
      return;
    }
    const { hosts, scopes, duration, purpose } = operation.authorization;
    for (const host of hosts) {
      if (!access.hosts.some((allowed) => allowed.uuid === host)) {
        throw new Error(`authorize: host ${host} is not allowed by /access.`);
      }
    }
    for (const scope of scopes) {
      if (!PTY_SCOPES.includes(scope) || !access.requestable_scopes.includes(scope)) {
        throw new Error(`authorize: scope ${scope} is not allowed by /access.`);
      }
    }
    if (!access.pty_durations.some((allowed) => allowed.value === duration)) {
      throw new Error('authorize: DURATION must be 60m, 12h or 24h as returned by /access.');
    }
    const result = await authorizeOAuth(config, port, credentialsPath, {
      scope: scopes.join(' '), hosts: hosts.join(','), duration, purpose,
    }, AUTHORIZE_COMMAND);
    print({ authorized: true, ...result });
    return;
  }

  if (operation.name === 'logout' || operation.name === 'logout-access') {
    const path = operation.name === 'logout-access' ? accessCredentialsPath : credentialsPath;
    const authorizationCommand = operation.name === 'logout-access' ? LOGIN_COMMAND : AUTHORIZE_COMMAND;
    const credentials = await loadCredentials(path, authorizationCommand);
    await request(config, '/oauth/revoke', {
      method: 'POST', body: new URLSearchParams({ token: credentials.access_token }),
    }, authorizationCommand);
    await unlink(path);
    print({ logged_out: true });
    return;
  }

  const credentials = await loadCredentials(credentialsPath, AUTHORIZE_COMMAND);
  requireUnexpired(credentials, AUTHORIZE_COMMAND);
  const options = { headers: { Authorization: `${credentials.token_type} ${credentials.access_token}` } };
  if (operation.name === 'list') {
    options.method = 'GET';
  } else {
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(operation.body);
  }
  const response = await request(config, operation.endpoint, options, AUTHORIZE_COMMAND);
  const result = await response.json();
  if (operation.name === 'read') {
    if (result === null || typeof result.data_base64 !== 'string' || !BASE64.test(result.data_base64)) {
      throw new Error('Read response requires a standard base64 data_base64 string.');
    }
    result.output = Buffer.from(result.data_base64, 'base64').toString('utf8');
  }
  print(result);
}

main().catch((error) => {
  console.error(JSON.stringify({ error: error.message }));
  process.exitCode = 1;
});
