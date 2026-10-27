#!/usr/bin/env node
/**
 * dsh-lan-auth — a password gate in front of a loopback-only DeepSeek Harness
 * (DSH) Web GUI, so LAN and Tailscale devices can sign in with a shared
 * password instead of a one-time pairing link.
 *
 * Flow:
 *   unauthenticated  -> 303 to /__unlock, which serves a password form
 *   correct password -> signed HttpOnly cookie (default 1 year) -> 303 to /
 *   authenticated    -> transparent HTTP + WebSocket proxy to the loopback GUI
 *
 * Why a separate process: the harness is designed to bind loopback only (it
 * rejects wildcard binds), and its own browser-session cookie is authority
 * bound. This gate terminates the network-facing side, keeps the harness
 * cookie server-side, rewrites Host/Origin to the loopback authority, and
 * injects that cookie — so devices only ever hold the gate's own cookie.
 *
 * State files live in $DSH_LAN_AUTH_STATE_DIR (default ~/.config/dsh-lan-auth):
 *   secret          HMAC key for the device cookie
 *   password        scrypt record
 *   harness-cookie  cached harness browser-session cookie
 */

'use strict';

const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const HOME = os.homedir();

/** Read a positive integer from the environment, else the fallback. */
function envInt(name, fallback) {
  const raw = process.env[name]?.trim();
  if (raw === undefined || raw.length === 0) return fallback;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

const STATE_DIR = process.env.DSH_LAN_AUTH_STATE_DIR?.trim() || path.join(HOME, '.config', 'dsh-lan-auth');
const SECRET_FILE = path.join(STATE_DIR, 'secret');
const PASSWORD_FILE = path.join(STATE_DIR, 'password');
const HARNESS_COOKIE_FILE = path.join(STATE_DIR, 'harness-cookie');

// Interfaces are enumerated at startup and re-checked periodically, so a DHCP
// change or a Tailscale reconnect is picked up without editing this file.
// Extra literals (e.g. a stable address) come from the environment.
const EXTRA_HOSTS = (process.env.DSH_LAN_AUTH_EXTRA_HOSTS ?? '')
  .split(',')
  .map((value) => value.trim())
  .filter((value) => value.length > 0);
const LISTEN_PORT = envInt('DSH_LAN_AUTH_PORT', 3080);

// The loopback GUI this gate fronts. Keep it on the loopback authority: the
// harness authenticates by authority, and the injected cookie is minted for it.
const UPSTREAM = process.env.DSH_LAN_AUTH_UPSTREAM?.trim() || '127.0.0.1:3080';
const upstreamSeparator = UPSTREAM.lastIndexOf(':');
const UPSTREAM_HOST = upstreamSeparator === -1 ? UPSTREAM : UPSTREAM.slice(0, upstreamSeparator);
const UPSTREAM_PORT = upstreamSeparator === -1 ? 3080 : Number(UPSTREAM.slice(upstreamSeparator + 1));
const UPSTREAM_AUTHORITY = `${UPSTREAM_HOST}:${String(UPSTREAM_PORT)}`;
const UPSTREAM_ORIGIN = `http://${UPSTREAM_AUTHORITY}`;

/** systemd user unit whose startup log carries the harness launch token. */
const HARNESS_UNIT = process.env.DSH_LAN_AUTH_UNIT?.trim() || 'dsh-web';

const COOKIE_NAME = process.env.DSH_LAN_AUTH_COOKIE?.trim() || 'dsh_lan_auth';
const COOKIE_MAX_AGE_SECONDS = envInt('DSH_LAN_AUTH_MAX_AGE_DAYS', 365) * 24 * 60 * 60;
const LOGIN_PATH = '/__unlock';
const LOGOUT_PATH = '/__lock';

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX_FAILS = 8;
const BODY_LIMIT_BYTES = 4096;

// ---------------------------------------------------------------- utilities

function ensureStateDir() {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
}

function readSecret() {
  ensureStateDir();
  try {
    const value = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    const buf = Buffer.from(value, 'base64url');
    if (buf.byteLength === 32) return buf;
  } catch {}
  const created = crypto.randomBytes(32);
  fs.writeFileSync(SECRET_FILE, created.toString('base64url'), { mode: 0o600 });
  return created;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function sign(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest();
}

function makeCookieToken(secret) {
  const now = Date.now();
  const payload = {
    v: 1,
    sid: crypto.randomBytes(9).toString('base64url'),
    iat: now,
    exp: now + COOKIE_MAX_AGE_SECONDS * 1000,
  };
  const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'));
  return `${body}.${b64url(sign(secret, body))}`;
}

function verifyCookieToken(secret, token) {
  if (typeof token !== 'string') return undefined;
  const dot = token.indexOf('.');
  if (dot <= 0) return undefined;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  let expected;
  try {
    expected = b64url(sign(secret, body));
  } catch {
    return undefined;
  }
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.byteLength !== b.byteLength || !crypto.timingSafeEqual(a, b)) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload || payload.v !== 1 || typeof payload.exp !== 'number' || payload.exp < Date.now()) return undefined;
    return payload;
  } catch {
    return undefined;
  }
}

function readCookie(header, name) {
  if (typeof header !== 'string') return undefined;
  for (const segment of header.split(';')) {
    const at = segment.indexOf('=');
    if (at === -1) continue;
    if (segment.slice(0, at).trim() !== name) continue;
    return segment.slice(at + 1).trim();
  }
  return undefined;
}

function serializeCookie(name, value, maxAgeSeconds) {
  return `${name}=${value}; Max-Age=${String(maxAgeSeconds)}; Path=/; HttpOnly; SameSite=Lax`;
}

// ----------------------------------------------------------------- password

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: 256 * 1024 * 1024,
  });
  return `scrypt$${String(SCRYPT.N)}$${String(SCRYPT.r)}$${String(SCRYPT.p)}$${b64url(salt)}$${b64url(hash)}`;
}

function loadPasswordRecord() {
  try {
    const text = fs.readFileSync(PASSWORD_FILE, 'utf8').trim();
    const parts = text.split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return undefined;
    return {
      N: Number(parts[1]),
      r: Number(parts[2]),
      p: Number(parts[3]),
      salt: Buffer.from(parts[4], 'base64url'),
      hash: Buffer.from(parts[5], 'base64url'),
    };
  } catch {
    return undefined;
  }
}

function verifyPassword(record, password) {
  if (record === undefined || password.length === 0) return false;
  let actual;
  try {
    actual = crypto.scryptSync(password, record.salt, record.hash.byteLength, {
      N: record.N,
      r: record.r,
      p: record.p,
      maxmem: 256 * 1024 * 1024,
    });
  } catch {
    return false;
  }
  return actual.byteLength === record.hash.byteLength && crypto.timingSafeEqual(actual, record.hash);
}

function setPassword(password) {
  ensureStateDir();
  if (password.length < 6) throw new Error('密码至少 6 个字符');
  fs.writeFileSync(PASSWORD_FILE, hashPassword(password), { mode: 0o600 });
}

// ------------------------------------------------------- harness cookie cache

function journalLaunchToken() {
  try {
    const out = execFileSync('journalctl', ['--user', '-u', HARNESS_UNIT, '-n', '400', '--no-pager'], {
      encoding: 'utf8',
      timeout: 5000,
    });
    const matches = [...out.matchAll(/dsh web:\s*https?:\/\/[^\s]*[?&]token=([A-Za-z0-9_-]+)/g)];
    if (matches.length === 0) return undefined;
    return matches[matches.length - 1][1];
  } catch {
    return undefined;
  }
}

function redeemLaunchToken(token) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: UPSTREAM_HOST,
        port: UPSTREAM_PORT,
        method: 'GET',
        path: `/?token=${encodeURIComponent(token)}`,
        headers: { host: UPSTREAM_AUTHORITY, 'cache-control': 'no-store' },
      },
      (res) => {
        res.resume();
        const cookies = res.headers['set-cookie'];
        if (!Array.isArray(cookies) || cookies.length === 0) {
          reject(new Error(`launch-token exchange returned ${String(res.statusCode)} without a cookie`));
          return;
        }
        const value = cookies.map((c) => c.split(';')[0]).join('; ');
        resolve(value);
      },
    );
    req.on('error', reject);
    req.end();
  });
}

let harnessCookieCache;

async function refreshHarnessCookie(reason) {
  const token = journalLaunchToken();
  if (token === undefined) throw new Error('找不到 dsh web 的启动 token（journalctl --user -u dsh-web）');
  const cookie = await redeemLaunchToken(token);
  harnessCookieCache = cookie;
  try {
    ensureStateDir();
    fs.writeFileSync(HARNESS_COOKIE_FILE, cookie, { mode: 0o600 });
  } catch {}
  console.log(`[auth] harness cookie refreshed (${reason})`);
  return cookie;
}

async function harnessCookie() {
  if (harnessCookieCache !== undefined) return harnessCookieCache;
  try {
    return await refreshHarnessCookie('startup');
  } catch (error) {
    try {
      const cached = fs.readFileSync(HARNESS_COOKIE_FILE, 'utf8').trim();
      if (cached.length > 0) {
        console.log(`[auth] refresh failed (${error.message}); using cached harness cookie`);
        harnessCookieCache = cached;
        return cached;
      }
    } catch {}
    throw error;
  }
}

// -------------------------------------------------------------- rate limiting

const attempts = new Map();

function clientKey(req) {
  const address = req.socket.remoteAddress ?? 'unknown';
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function rateLimited(key) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (entry === undefined || now - entry.windowStart > RATE_WINDOW_MS) return false;
  return entry.fails >= RATE_MAX_FAILS;
}

function recordFailure(key) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (entry === undefined || now - entry.windowStart > RATE_WINDOW_MS) {
    attempts.set(key, { fails: 1, windowStart: now });
    return;
  }
  entry.fails += 1;
}

function clearFailures(key) {
  attempts.delete(key);
}

// --------------------------------------------------------------------- pages

function loginPage({ error, next }) {
  const message = error ? `<p class="err">${error}</p>` : '';
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeepSeek Harness · 访问密码</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
         background:#f6f7f9; color:#1a1a1a; }
  @media (prefers-color-scheme: dark) { body { background:#141517; color:#ececec; } .card{ background:#1d1f22 !important; box-shadow:none !important; border-color:#2c2f33 !important;} input{ background:#141517 !important; color:#ececec !important; border-color:#3a3d42 !important;} }
  .card { width:min(92vw,380px); background:#fff; border:1px solid #e6e8eb; border-radius:14px;
          padding:28px 26px; box-shadow:0 10px 30px rgba(0,0,0,.06); }
  h1 { font-size:18px; margin:0 0 4px; }
  p.sub { margin:0 0 20px; font-size:13px; opacity:.6; }
  label { display:block; font-size:13px; margin:0 0 6px; opacity:.75; }
  input[type=password] { width:100%; box-sizing:border-box; padding:11px 12px; font-size:16px;
          border:1px solid #d6d9dd; border-radius:9px; background:#fff; color:inherit; }
  input[type=password]:focus { outline:2px solid #4c6ef5; outline-offset:1px; border-color:#4c6ef5; }
  button { width:100%; margin-top:16px; padding:11px 12px; font-size:15px; font-weight:600; border:0;
           border-radius:9px; background:#4c6ef5; color:#fff; cursor:pointer; }
  button:active { transform:translateY(1px); }
  .err { color:#e03131; font-size:13px; margin:0 0 12px; }
  .hint { margin:18px 0 0; font-size:12px; opacity:.5; }
</style></head>
<body>
  <form class="card" method="post" action="${LOGIN_PATH}">
    <h1>DeepSeek Harness</h1>
    <p class="sub">局域网 / Tailscale 访问，请输入访问密码</p>
    ${message}
    <label for="password">访问密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    <button type="submit">进入</button>
    <p class="hint">登录状态会记住一年，下次自动进入。</p>
  </form>
</body></html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function sendHtml(res, status, html) {
  const body = Buffer.from(html, 'utf8');
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': String(body.byteLength),
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
  });
  res.end(body);
}

function safeNext(value) {
  if (typeof value !== 'string' || value.length === 0) return '/';
  if (!value.startsWith('/') || value.startsWith('//')) return '/';
  return value;
}

// -------------------------------------------------------------------- proxy

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
  'expect',
]);

function upstreamHeaders(rawHeaders, harness) {
  const headers = {};
  for (const [key, value] of Object.entries(rawHeaders)) {
    const lower = key.toLowerCase();
    if (lower === 'host' || lower === 'cookie' || lower === 'origin' || lower === 'referer') continue;
    if (HOP_BY_HOP.has(lower)) continue;
    headers[lower] = value;
  }
  headers.host = UPSTREAM_AUTHORITY;
  headers.cookie = harness;
  if (typeof rawHeaders.origin === 'string') headers.origin = UPSTREAM_ORIGIN;
  if (typeof rawHeaders.referer === 'string') {
    const rest = rawHeaders.referer.replace(/^https?:\/\/[^/]+/u, '');
    headers.referer = UPSTREAM_ORIGIN + (rest.startsWith('/') ? rest : '/');
  }
  return headers;
}

function responseHeaders(rawHeaders) {
  const headers = {};
  for (const [key, value] of Object.entries(rawHeaders)) {
    const lower = key.toLowerCase();
    if (HOP_BY_HOP.has(lower)) continue;
    if (lower === 'set-cookie') {
      const kept = (Array.isArray(value) ? value : [value]).filter(
        (cookie) => !/^dsh-auth-/iu.test(cookie) && !/^dsh_pair=/u.test(cookie),
      );
      if (kept.length > 0) headers['set-cookie'] = kept;
      continue;
    }
    headers[lower] = value;
  }
  return headers;
}

async function proxyRequest(req, res, retry = true) {
  let cookie;
  try {
    cookie = await harnessCookie();
  } catch (error) {
    res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`harness 认证不可用: ${error.message}\n`);
    return;
  }
  const headers = upstreamHeaders(req.headers, cookie);
  const upstream = http.request(
    { host: UPSTREAM_HOST, port: UPSTREAM_PORT, method: req.method, path: req.url, headers },
    (up) => {
      if (up.statusCode === 401 && retry) {
        up.resume();
        refreshHarnessCookie('401')
          .then(() => proxyRequest(req, res, false))
          .catch(() => {
            res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
            res.end('unauthorized\n');
          });
        return;
      }
      res.writeHead(up.statusCode ?? 502, responseHeaders(up.headers));
      up.pipe(res);
    },
  );
  upstream.on('error', (error) => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`upstream error: ${error.message}\n`);
  });
  req.pipe(upstream);
}

function proxyUpgrade(req, socket, head) {
  harnessCookie()
    .then((cookie) => {
      const up = net.connect(UPSTREAM_PORT, UPSTREAM_HOST, () => {
        const headers = upstreamHeaders(req.headers, cookie);
        const lines = [`GET ${req.url} HTTP/1.1`];
        for (const [key, value] of Object.entries(headers)) {
          const list = Array.isArray(value) ? value : [value];
          for (const item of list) lines.push(`${key}: ${item}`);
        }
        // restore the upgrade handshake headers that upstreamHeaders strips
        if (typeof req.headers.upgrade === 'string') lines.push(`upgrade: ${req.headers.upgrade}`);
        lines.push(`connection: upgrade`);
        lines.push('', '');
        up.write(lines.join('\r\n'));
        if (head && head.length > 0) up.write(head);
        up.pipe(socket);
        socket.pipe(up);
        up.on('error', () => socket.destroy());
        socket.on('error', () => up.destroy());
      });
      up.on('error', () => socket.destroy());
    })
    .catch(() => socket.destroy());
}

// -------------------------------------------------------------------- routes

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseForm(text) {
  const params = new URLSearchParams(text);
  return { password: params.get('password') ?? '', next: safeNext(params.get('next') ?? '/') };
}

const secret = readSecret();

async function handleRequest(req, res) {
  const url = new URL(req.url ?? '/', 'http://device.invalid');
  const cookieValue = readCookie(req.headers.cookie, COOKIE_NAME);
  const session = verifyCookieToken(secret, cookieValue);

  if (url.pathname === LOGOUT_PATH) {
    res.writeHead(303, {
      'set-cookie': serializeCookie(COOKIE_NAME, '', 0),
      location: LOGIN_PATH,
      'cache-control': 'no-store',
    });
    res.end();
    return;
  }

  if (url.pathname === LOGIN_PATH) {
    if (req.method === 'GET') {
      sendHtml(res, 200, loginPage({ error: '', next: safeNext(url.searchParams.get('next') ?? '/') }));
      return;
    }
    if (req.method === 'POST') {
      const key = clientKey(req);
      if (rateLimited(key)) {
        sendHtml(res, 429, loginPage({ error: '尝试次数过多，请 10 分钟后再试', next: '/' }));
        return;
      }
      let form;
      try {
        form = parseForm(await readBody(req));
      } catch {
        sendHtml(res, 400, loginPage({ error: '请求无效', next: '/' }));
        return;
      }
      const record = loadPasswordRecord();
      if (record === undefined) {
        sendHtml(res, 500, loginPage({ error: '尚未设置访问密码，请在服务器上运行 --set-password', next: '/' }));
        return;
      }
      if (!verifyPassword(record, form.password)) {
        recordFailure(key);
        console.log(`[auth] failed login from ${key}`);
        sendHtml(res, 401, loginPage({ error: '密码错误', next: form.next }));
        return;
      }
      clearFailures(key);
      console.log(`[auth] login ok from ${key}`);
      const token = makeCookieToken(secret);
      res.writeHead(303, {
        'set-cookie': serializeCookie(COOKIE_NAME, token, COOKIE_MAX_AGE_SECONDS),
        location: form.next,
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
      });
      res.end();
      return;
    }
    res.writeHead(405, { allow: 'GET, POST' });
    res.end();
    return;
  }

  if (session === undefined) {
    const next = safeNext(url.pathname + url.search);
    res.writeHead(303, { location: `${LOGIN_PATH}?next=${encodeURIComponent(next)}`, 'cache-control': 'no-store' });
    res.end();
    return;
  }

  await proxyRequest(req, res);
}

function handleUpgrade(req, socket, head) {
  const session = verifyCookieToken(secret, readCookie(req.headers.cookie, COOKIE_NAME));
  if (session === undefined) {
    socket.end('HTTP/1.1 401 Unauthorized\r\nconnection: close\r\n\r\n');
    return;
  }
  proxyUpgrade(req, socket, head);
}

// ---------------------------------------------------------------- listening

const servers = new Map();

/**
 * Addresses worth listening on: every non-loopback IPv4 except container
 * bridges and link-local ones, plus EXTRA_HOSTS. Container bridge names are
 * skipped so a container cannot reach the GUI directly.
 */
function candidateHosts() {
  const hosts = new Set(EXTRA_HOSTS);
  for (const [name, entries] of Object.entries(os.networkInterfaces())) {
    if (/^(lo|docker|br-|veth|virbr|cni|podman)/iu.test(name)) continue;
    for (const entry of entries ?? []) {
      if (entry.family !== 'IPv4' || entry.internal) continue;
      if (entry.address.startsWith('169.254.')) continue;
      hosts.add(entry.address);
    }
  }
  return [...hosts];
}

/** Reconcile listeners with the current set of interface addresses. */
function syncListeners() {
  const wanted = new Set(candidateHosts());
  for (const [host, listener] of servers) {
    if (wanted.has(host)) continue;
    servers.delete(host);
    listener.close(() => console.log(`[auth] stopped listening on ${host}`));
  }
  for (const host of wanted) {
    if (servers.has(host)) continue;
    listen(host);
  }
}

function listen(host) {
  const listener = http.createServer(handleRequest);
  listener.on('upgrade', handleUpgrade);
  listener.on('clientError', (error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  listener.on('error', (error) => {
    console.error(`[auth] cannot listen on ${host}:${String(LISTEN_PORT)}: ${error.message}`);
    servers.delete(host);
    try {
      listener.close();
    } catch {}
  });
  listener.listen(LISTEN_PORT, host, () => {
    console.log(`[auth] listening on http://${host}:${String(LISTEN_PORT)} -> ${UPSTREAM_AUTHORITY}`);
  });
  servers.set(host, listener);
}

if (process.argv[2] === '--set-password') {
  const value = process.argv[3] ?? process.env.DSH_LAN_PASSWORD;
  if (value === undefined || value.length === 0) {
    console.error('usage: server.js --set-password <password>');
    process.exit(2);
  }
  setPassword(value);
  console.log('访问密码已设置');
  process.exit(0);
}

if (process.argv[2] === '--check-password') {
  console.log(loadPasswordRecord() === undefined ? '未设置' : '已设置');
  process.exit(0);
}

harnessCookie().catch((error) => console.error(`[auth] ${error.message}`));

syncListeners();
setInterval(syncListeners, 60000).unref();

function shutdown() {
  for (const listener of servers.values()) listener.close();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
