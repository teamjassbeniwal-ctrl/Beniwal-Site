'use strict';

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET;

if (IS_PRODUCTION && (!SESSION_SECRET || SESSION_SECRET.length < 32)) {
  console.error('FATAL: Set SESSION_SECRET to a random secret of at least 32 characters in your hosting environment.');
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.warn('WARNING: Using a development-only session secret. Set SESSION_SECRET before deployment.');
}

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'users.sqlite');
const db = new sqlite3.Database(DB_PATH);

const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) reject(err); else resolve({ lastID: this.lastID, changes: this.changes });
  });
});
const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
});

const databaseReady = run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
databaseReady.catch(err => {
  console.error('Could not initialize user database:', err.message);
  process.exit(1);
});

if (IS_PRODUCTION) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(session({
  name: 'beniwal.sid',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR, table: 'sessions' }),
  secret: SESSION_SECRET || 'development-only-change-this-secret-now',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8
  }
}));
app.use((req, res, next) => databaseReady.then(() => next()).catch(next));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: 'Too many attempts. Please wait 15 minutes and try again.' });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false, message: 'Too many registration attempts. Please try again later.' });

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}
function csrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  return req.session.csrfToken;
}
function validCsrf(req) {
  const a = Buffer.from(String(req.body._csrf || ''));
  const b = Buffer.from(String(req.session.csrfToken || ''));
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}
function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)} | Beniwal VPS</title><style>
  *{box-sizing:border-box}body{margin:0;background:#0b1020;color:#edf2ff;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:100%;max-width:440px;background:#151d33;border:1px solid #2a3656;border-radius:18px;padding:28px;box-shadow:0 18px 60px #0005}h1{margin:0 0 8px;font-size:28px}p{color:#b8c3dd;line-height:1.5}.brand{color:#8fb4ff;font-weight:bold;margin-bottom:22px}label{display:block;margin:16px 0 7px;color:#dce5ff}input{width:100%;padding:13px;border-radius:9px;border:1px solid #39496d;background:#0b1328;color:white;font-size:16px}button,.button{display:block;width:100%;margin-top:20px;padding:13px;border:0;border-radius:9px;background:#4d82ff;color:white;font-size:16px;font-weight:bold;text-align:center;text-decoration:none;cursor:pointer}.secondary{background:#263451}.error{background:#482333;color:#ffdbe3;padding:10px;border-radius:8px}.ok{background:#173c35;color:#c7ffea;padding:10px;border-radius:8px}.small{font-size:13px}.links{margin-top:18px;text-align:center}.links a{color:#9cbdff}.toplink{color:#9cbdff}.muted{font-size:12px;color:#9aa8c6;margin-top:20px}
  </style></head><body><main class="card"><div class="brand">BENIWAL VPS</div>${body}<div class="muted">Use a unique password. Never share your password or login code.</div></main></body></html>`;
}
function authForm(kind, req, message = '') {
  const isRegister = kind === 'register';
  const title = isRegister ? 'Create your account' : 'Welcome back';
  const error = message ? `<p class="error" role="alert">${escapeHtml(message)}</p>` : '';
  return page(isRegister ? 'Register' : 'Login', `<h1>${title}</h1><p>${isRegister ? 'Create your own account to continue.' : 'Sign in to access your account.'}</p>${error}<form method="post" action="/${kind}" autocomplete="on"><input type="hidden" name="_csrf" value="${escapeHtml(csrfToken(req))}"><label for="email">Email address</label><input id="email" name="email" type="email" required maxlength="254" autocomplete="email" value="${escapeHtml(req.body?.email || '')}"><label for="password">Password</label><input id="password" name="password" type="password" required minlength="${isRegister ? 10 : 1}" maxlength="128" autocomplete="${isRegister ? 'new-password' : 'current-password'}">${isRegister ? '<p class="small">Use at least 10 characters. A longer, unique password is safer.</p>' : ''}<button type="submit">${isRegister ? 'Create account' : 'Log in securely'}</button></form><div class="links">${isRegister ? 'Already have an account? <a href="/login">Log in</a>' : 'New here? <a href="/register">Create an account</a>'}</div>`);
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
}
function saveSession(req) {
  return new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
}

// The login screen is intentionally the first page. The existing marketing page stays at /home.
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => req.session.userId ? res.redirect('/dashboard') : res.send(authForm('login', req)));
app.post('/login', loginLimiter, async (req, res, next) => {
  try {
    if (!validCsrf(req)) return res.status(403).send(authForm('login', req, 'Session expired. Refresh the page and try again.'));
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (email.length > 254 || password.length > 128) return res.status(400).send(authForm('login', req, 'Invalid email or password.'));
    const user = await get('SELECT id, email, password_hash FROM users WHERE email = ?', [email]);
    const ok = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!user || !ok) return res.status(401).send(authForm('login', req, 'Invalid email or password.'));
    await regenerateSession(req);
    req.session.userId = user.id;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    await saveSession(req);
    res.redirect('/dashboard');
  } catch (err) { next(err); }
});

app.get('/register', (req, res) => req.session.userId ? res.redirect('/dashboard') : res.send(authForm('register', req)));
app.post('/register', registerLimiter, async (req, res, next) => {
  try {
    if (!validCsrf(req)) return res.status(403).send(authForm('register', req, 'Session expired. Refresh the page and try again.'));
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || password.length < 10 || password.length > 128) {
      return res.status(400).send(authForm('register', req, 'Enter a valid email and a password of 10–128 characters.'));
    }
    const passwordHash = await bcrypt.hash(password, 12);
    let result;
    try { result = await run('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, passwordHash]); }
    catch (err) {
      if (err && err.code === 'SQLITE_CONSTRAINT') return res.status(409).send(authForm('register', req, 'An account with this email already exists. Please log in.'));
      throw err;
    }
    await regenerateSession(req);
    req.session.userId = result.lastID;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    await saveSession(req);
    res.redirect('/dashboard');
  } catch (err) { next(err); }
});

app.get('/dashboard', requireAuth, async (req, res, next) => {
  try {
    const user = await get('SELECT id, email, created_at FROM users WHERE id = ?', [req.session.userId]);
    if (!user) { req.session.destroy(() => res.redirect('/login')); return; }
    const body = `<h1>Your dashboard</h1><p>You are logged in with a real account.</p><div class="ok">Login successful</div><p><strong>Email:</strong><br>${escapeHtml(user.email)}</p><p><strong>Account created:</strong><br>${escapeHtml(user.created_at)}</p><form method="post" action="/logout"><input type="hidden" name="_csrf" value="${escapeHtml(csrfToken(req))}"><button class="secondary" type="submit">Log out</button></form><p class="links"><a href="/home">Visit website home</a></p>`;
    res.send(page('Dashboard', body));
  } catch (err) { next(err); }
});
app.post('/logout', requireAuth, (req, res) => {
  if (!validCsrf(req)) return res.status(403).send('Session expired. Go back and try again.');
  req.session.destroy(err => {
    res.clearCookie('beniwal.sid', { httpOnly: true, secure: IS_PRODUCTION, sameSite: 'lax' });
    if (err) return res.status(500).send('Could not log out. Please try again.');
    res.redirect('/login');
  });
});

// Keep existing public assets and landing page available at /home.
app.get('/home', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use(express.static(path.join(__dirname, 'public'), { index: false, dotfiles: 'deny' }));
app.use((req, res) => res.status(404).send(page('Not found', '<h1>Page not found</h1><p>The page you requested does not exist.</p><a class="button" href="/login">Back to login</a>')));
app.use((err, req, res, next) => {
  console.error('Request failed:', err && err.message);
  if (res.headersSent) return next(err);
  res.status(500).send(page('Error', '<h1>Something went wrong</h1><p>Please try again later.</p>'));
});

app.listen(PORT, '0.0.0.0', () => console.log(`Beniwal VPS secure login server listening on port ${PORT}`));
