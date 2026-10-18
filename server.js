const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 8000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters long.');
}
if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set. Set a long random secret in your hosting environment before production use.');
}

const db = new sqlite3.Database(path.join(DATA_DIR, 'users.sqlite'));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
});

app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use(session({
  name: 'beniwal.sid',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'local-development-only-change-this-secret-please',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait 15 minutes and try again.' }
});

function validEmail(email) {
  return typeof email === 'string' && email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function publicUser(row) {
  return { id: row.id, email: row.email, createdAt: row.created_at };
}
function getUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) =>
      err ? reject(err) : resolve(row));
  });
}
function createUser(email, passwordHash) {
  return new Promise((resolve, reject) => {
    db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, passwordHash], function (err) {
        if (err) return reject(err);
        resolve(this.lastID);
      });
  });
}
function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT id, email, created_at FROM users WHERE id = ?', [id],
      (err, row) => err ? reject(err) : resolve(row));
  });
}

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 10 || password.length > 72) {
      return res.status(400).json({ error: 'Password must be 10–72 characters long.' });
    }
    if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ error: 'Use at least one letter and one number in your password.' });
    }
    const hash = await bcrypt.hash(password, 12);
    const id = await createUser(email, hash);
    req.session.regenerate(async err => {
      if (err) return res.status(500).json({ error: 'Could not start your session. Please try again.' });
      req.session.userId = id;
      res.status(201).json({ message: 'Account created successfully.', user: { id, email } });
    });
  } catch (err) {
    if (err && err.code === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ error: 'An account with this email already exists. Please log in.' });
    }
    console.error('Registration error:', err.message);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!validEmail(email) || !password) {
      return res.status(400).json({ error: 'Enter your email and password.' });
    }
    const user = await getUserByEmail(email);
    const ok = user && await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Email or password is incorrect.' });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Could not start your session. Please try again.' });
      req.session.userId = user.id;
      res.json({ message: 'Logged in successfully.', user: publicUser(user) });
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });
  try {
    const user = await getUserById(req.session.userId);
    if (!user) return req.session.destroy(() => res.status(401).json({ error: 'Not logged in.' }));
    res.json({ user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ error: 'Could not load account.' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Could not log out. Please try again.' });
    res.clearCookie('beniwal.sid', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
    res.json({ message: 'Logged out.' });
  });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`Beniwal VPS running on port ${PORT}`));
