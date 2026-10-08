import { createServer } from 'node:http';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const PORT = Number(process.env.PORT || 3000);
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 86400);
const DB_TIMEOUT_MS = Number(process.env.DB_TIMEOUT_MS || 3000);
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const MAX_BODY_BYTES = 16 * 1024;
const SERVICE_NAME = process.env.SERVICE_NAME || 'acm-server';

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function pathWithValue(path, value) {
  return `${path.replace(/\/$/, '')}/${encodeURIComponent(value)}`;
}

async function discoverDbBaseUrl() {
  const dnsUrl = requiredEnv('DNS_URL');
  const serviceName = process.env.DB_SERVICE_NAME || 'acm-db';
  const resolvePath = process.env.DNS_LOOKUP_PATH || '/lookup';
  const url = new URL(resolvePath, dnsUrl);
  url.searchParams.set('domain', serviceName);
  const response = await fetch(url, { signal: AbortSignal.timeout(DB_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`acm-dns resolution failed (${response.status})`);
  const record = await response.json();
  const address = record.destination;
  if (!address) throw new Error('acm-dns response must include destination');
  if (/^https?:\/\//.test(address)) return address.replace(/\/$/, '');
  const port = process.env.DB_PORT;
  return `http://${address}${port ? `:${port}` : ''}`;
}

async function registerService() {
  const dnsUrl = requiredEnv('DNS_URL');
  const registerPath = process.env.DNS_REGISTER_PATH || '/register';
  const registration = new URL(registerPath, dnsUrl);
  const advertisedAddress = requiredEnv('SERVICE_ADVERTISE_ADDRESS');
  const response = await fetch(registration, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ domain: SERVICE_NAME, address: advertisedAddress }),
    signal: AbortSignal.timeout(DB_TIMEOUT_MS)
  });
  if (!response.ok) throw new Error(`acm-dns registration failed (${response.status})`);
}

const dbBaseUrls = new Map();
async function getDbBaseUrl() {
  const serviceName = process.env.DB_SERVICE_NAME || 'acm-db';
  if (!dbBaseUrls.has(serviceName)) dbBaseUrls.set(serviceName, discoverDbBaseUrl());
  return dbBaseUrls.get(serviceName);
}

async function serviceRequest(serviceName, path, options = {}) {
  const base = await getDbBaseUrl(serviceName);
  const response = await fetch(new URL(path, `${base}/`), {
    ...options,
    headers: { 'content-type': 'application/json', ...options.headers },
    signal: AbortSignal.timeout(DB_TIMEOUT_MS)
  });
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!response.ok) {
    const error = new Error(data?.error || `acm-db returned ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function dbPaths() {
  return {
    register: process.env.DB_REGISTER_PATH || '/db/users',
    findUser: process.env.DB_FIND_USER_PATH || '/db/users'
  };
}

const sessions = new Map();

function sendJson(response, status, body, headers = {}) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error('Request body too large'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw Object.assign(new Error('Request body must be a JSON object'), { status: 400 });
  }
}

function validCredentials(body) {
  return typeof body.username === 'string' && body.username.trim().length > 0 &&
    typeof body.password === 'string' && body.password.length >= 8;
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}

async function verifyPassword(password, encoded) {
  if (typeof encoded !== 'string') return false;
  const [algorithm, saltHex, hashHex] = encoded.split('$');
  if (algorithm !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function getCookie(request, name) {
  const cookieHeader = request.headers.cookie || '';
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) return decodeURIComponent(part.slice(separator + 1).trim());
  }
  return null;
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://localhost');
  try {
    if (request.method === 'GET' && url.pathname === '/health') {
      return sendJson(response, 200, { status: 'ok' });
    }

    if (request.method === 'POST' && url.pathname === '/register') {
      const body = await readJson(request);
      if (!validCredentials(body)) return sendJson(response, 400, { error: 'Username and password (at least 8 characters) are required' });
      const paths = dbPaths();
      const username = body.username.trim();
      try {
        await serviceRequest('acm-db', paths.register, {
          method: 'POST',
          body: JSON.stringify({ username, password_hash: await hashPassword(body.password) })
        });
      } catch (error) {
        if (error.status === 409 || error.status === 400) return sendJson(response, 400, { error: 'Username already exists' });
        throw error;
      }
      return sendJson(response, 201, { status: 'ok', message: 'User registered successfully' });
    }

    if (request.method === 'POST' && url.pathname === '/login') {
      const body = await readJson(request);
      if (!validCredentials(body)) return sendJson(response, 401, { error: 'Invalid username or password' });
      const paths = dbPaths();
      let user;
      try {
        user = await serviceRequest('acm-db', pathWithValue(paths.findUser, body.username.trim()));
      } catch (error) {
        if (error.status === 404) return sendJson(response, 401, { error: 'Invalid username or password' });
        throw error;
      }
      const passwordHash = user?.password_hash || user?.passwordHash;
      if (!user || !(await verifyPassword(body.password, passwordHash))) {
        return sendJson(response, 401, { error: 'Invalid username or password' });
      }

      const token = randomBytes(32).toString('base64url');
      const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
      sessions.set(token, { user_id: user.user_id ?? user.id, username: user.username, expiresAt });
      const cookie = `session_id=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}${COOKIE_SECURE ? '; Secure' : ''}`;
      return sendJson(response, 200, { status: 'ok', message: 'Login successful' }, { 'set-cookie': cookie });
    }

    if (request.method === 'GET' && url.pathname === '/whoami') {
      const token = getCookie(request, 'session_id');
      if (!token) return sendJson(response, 401, { error: 'Unauthorized - Invalid or missing session cookie' });
      const session = sessions.get(token);
      if (!session || session.expiresAt <= Date.now()) {
        sessions.delete(token);
        return sendJson(response, 401, { error: 'Unauthorized - Invalid or missing session cookie' });
      }
      return sendJson(response, 200, { status: 'ok', user_id: session.user_id, username: session.username });
    }

    return sendJson(response, 404, { error: 'Not found' });
  } catch (error) {
    const status = error.status && error.status < 500 ? error.status : 503;
    if (status >= 500) console.error(`${request.method} ${url.pathname}: ${error.message}`);
    return sendJson(response, status, { error: status === 503 ? 'Authentication service dependency unavailable' : error.message });
  }
});

server.listen(PORT, '0.0.0.0', async () => {
  console.log(`acm-server listening on port ${PORT}`);
  try {
    await registerService();
    console.log(`Registered ${SERVICE_NAME} with acm-dns`);
  } catch (error) {
    console.error(`Could not register with acm-dns: ${error.message}`);
  }
});
