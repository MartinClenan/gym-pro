import http from 'node:http';
import { createHmac, pbkdf2, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2Async = promisify(pbkdf2);
const PBKDF2_ITERATIONS = 310_000;
const SESSION_TTL_SECONDS = 30 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;
const MAX_BODY_BYTES = 64 * 1024;
const ALLOWED_QUERY_KEYS = new Set(['pageSize', 'offset']);
const loginAttempts = new Map();

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error('Falta configurar la variable ' + name + '.');
  return value;
}

const config = {
  port: Number(process.env.PORT || 3000),
  origin: requiredEnv('ALLOWED_ORIGIN'),
  baseId: requiredEnv('AIRTABLE_BASE_ID'),
  airtableToken: requiredEnv('AIRTABLE_PERSONAL_ACCESS_TOKEN'),
  sociosTableId: requiredEnv('SOCIOS_TABLE_ID'),
  pagosTableId: requiredEnv('PAGOS_TABLE_ID'),
  sessionSecret: requiredEnv('SESSION_SECRET'),
  users: JSON.parse(requiredEnv('AUTH_USERS_JSON')),
};

if (config.sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET debe tener al menos 32 caracteres.');
}
if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
  throw new Error('PORT no es válido.');
}
if (!config.origin.startsWith('https://') && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(config.origin)) {
  throw new Error('ALLOWED_ORIGIN debe usar HTTPS, salvo en desarrollo local.');
}
if (!config.users || typeof config.users !== 'object' || Array.isArray(config.users) || !Object.keys(config.users).length) {
  throw new Error('AUTH_USERS_JSON debe contener al menos un usuario.');
}
for (const [username, user] of Object.entries(config.users)) {
  if (!/^[a-z0-9._-]{2,40}$/i.test(username) || !user || typeof user !== 'object' ||
      typeof user.salt !== 'string' || typeof user.hash !== 'string' || user.rol !== 'admin') {
    throw new Error('Cada usuario de AUTH_USERS_JSON debe tener salt, hash y rol admin.');
  }
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  res.end(JSON.stringify(payload));
}

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin !== config.origin) {
    sendJson(res, 403, { message: 'Origen no autorizado.' });
    return false;
  }
  res.setHeader('Access-Control-Allow-Origin', config.origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
  res.setHeader('Vary', 'Origin');
  return true;
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error('Solicitud demasiado grande.'), { status: 413 });
    chunks.push(chunk);
  }
  if (!size) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('El contenido enviado no es JSON válido.'), { status: 400 });
  }
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function sign(value) {
  return createHmac('sha256', config.sessionSecret).update(value).digest('base64url');
}

function issueSession(username, user) {
  const now = Math.floor(Date.now() / 1000);
  const head = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify({ sub: username, role: user.rol, iat: now, exp: now + SESSION_TTL_SECONDS }));
  const unsigned = head + '.' + body;
  return unsigned + '.' + sign(unsigned);
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

function verifySession(req) {
  const header = req.headers.authorization || '';
  const match = /^Bearer ([A-Za-z0-9._-]+)$/.exec(header);
  if (!match) return null;
  const parts = match[1].split('.');
  if (parts.length !== 3 || !safeEqual(sign(parts[0] + '.' + parts[1]), parts[2])) return null;
  try {
    const head = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (head.alg !== 'HS256' || !payload.sub || payload.role !== 'admin' ||
        !Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    const user = config.users[payload.sub];
    if (!user || user.rol !== payload.role) return null;
    return { username: payload.sub, role: payload.role };
  } catch {
    return null;
  }
}

function checkLoginLimit(req, username) {
  const address = req.socket.remoteAddress || 'unknown';
  const key = address + ':' + username;
  const now = Date.now();
  if (!loginAttempts.has(key) && loginAttempts.size >= 5000) {
    const oldestKey = loginAttempts.keys().next().value;
    if (oldestKey) loginAttempts.delete(oldestKey);
  }
  const current = loginAttempts.get(key);
  if (!current || current.until <= now) {
    loginAttempts.set(key, { count: 1, until: now + LOGIN_WINDOW_MS });
    return false;
  }
  current.count += 1;
  return current.count > LOGIN_MAX_ATTEMPTS;
}

function isValidRecordId(value) {
  return /^rec[A-Za-z0-9_-]{8,40}$/.test(value);
}

function validateRecords(body, method) {
  if (!body || !Array.isArray(body.records) || body.records.length < 1 || body.records.length > 10) return false;
  return body.records.every((record) => {
    if (!record || typeof record !== 'object' || !record.fields || typeof record.fields !== 'object' || Array.isArray(record.fields)) return false;
    if (method === 'PATCH' && !isValidRecordId(record.id)) return false;
    return Object.keys(record.fields).every((field) => /^fld[A-Za-z0-9]+$/.test(field));
  });
}

async function handleLogin(req, res) {
  const body = await readJson(req);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return sendJson(res, 401, { message: 'Usuario o contraseña incorrectos.' });
  }
  const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!/^[a-z0-9._-]{2,40}$/.test(username) || checkLoginLimit(req, username) || password.length < 12 || password.length > 256) {
    return sendJson(res, 401, { message: 'Usuario o contraseña incorrectos, o demasiados intentos.' });
  }
  const user = config.users[username];
  let valid = false;
  if (user) {
    try {
      const salt = Buffer.from(user.salt, 'base64url');
      const expected = Buffer.from(user.hash, 'base64url');
      if (salt.length >= 16 && expected.length === 32) {
        const actual = await pbkdf2Async(password, salt, PBKDF2_ITERATIONS, expected.length, 'sha256');
        valid = timingSafeEqual(actual, expected);
      }
    } catch {
      valid = false;
    }
  }
  if (!valid) return sendJson(res, 401, { message: 'Usuario o contraseña incorrectos.' });
  loginAttempts.delete((req.socket.remoteAddress || 'unknown') + ':' + username);
  return sendJson(res, 200, {
    accessToken: issueSession(username, user),
    user: { usuario: username, rol: user.rol, iniciales: user.iniciales || username.slice(0, 2).toUpperCase() },
  });
}

async function handleAirtable(req, res, url) {
  const user = verifySession(req);
  if (!user) return sendJson(res, 401, { message: 'La sesión venció. Ingresá de nuevo.' });

  const rawPath = url.pathname.slice('/api/airtable/'.length);
  const segments = rawPath.split('/').filter(Boolean).map(decodeURIComponent);
  const tableId = segments[0];
  const recordId = segments[1];
  if (![config.sociosTableId, config.pagosTableId].includes(tableId) || segments.length > 2 ||
      (recordId && !isValidRecordId(recordId))) {
    return sendJson(res, 404, { message: 'Recurso no disponible.' });
  }
  for (const key of url.searchParams.keys()) {
    if (!ALLOWED_QUERY_KEYS.has(key)) return sendJson(res, 400, { message: 'Parámetro no permitido.' });
  }
  const path = tableId + (recordId ? '/' + recordId : '') + url.search;
  const method = req.method;
  if ((!recordId && !['GET', 'POST', 'PATCH'].includes(method)) ||
      (recordId && !['GET', 'PATCH', 'DELETE'].includes(method))) {
    return sendJson(res, 405, { message: 'Operación no permitida.' });
  }

  let payload;
  if (method === 'POST' || method === 'PATCH') {
    payload = await readJson(req);
    if (!validateRecords(payload, method)) return sendJson(res, 400, { message: 'Datos de pago o socio no válidos.' });
  }

  try {
    const upstream = await fetch('https://api.airtable.com/v0/' + config.baseId + '/' + path, {
      method,
      redirect: 'error',
      headers: {
        Authorization: 'Bearer ' + config.airtableToken,
        'Content-Type': 'application/json',
      },
      body: payload ? JSON.stringify(payload) : undefined,
    });
    if (!upstream.ok) {
      return sendJson(res, upstream.status >= 400 && upstream.status < 500 ? upstream.status : 502,
        { message: 'Airtable no pudo completar la operación.' });
    }
    const text = await upstream.text();
    res.writeHead(upstream.status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(text || '{}');
  } catch {
    sendJson(res, 502, { message: 'No se pudo conectar con Airtable.' });
  }
}

const server = http.createServer(async (req, res) => {
  if (!applyCors(req, res)) return;
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname === '/api/login' && req.method === 'POST') return await handleLogin(req, res);
    if (url.pathname.startsWith('/api/airtable/')) return await handleAirtable(req, res, url);
    return sendJson(res, 404, { message: 'Ruta no encontrada.' });
  } catch (error) {
    return sendJson(res, Number(error.status) || 500,
      { message: error.status ? error.message : 'Error interno del servidor.' });
  }
});

server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.listen(config.port, '0.0.0.0', () => {
  console.log('API del gimnasio lista en el puerto ' + config.port + '.');
});
