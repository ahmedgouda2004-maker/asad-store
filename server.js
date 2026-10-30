const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');

const { DATABASE_URL, JWT_SECRET, ADMIN_USER, ADMIN_PASS, ADMIN_EMAIL, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM } = process.env;
for (const [k, v] of Object.entries({ DATABASE_URL, JWT_SECRET, ADMIN_USER, ADMIN_PASS, ADMIN_EMAIL })) {
  if (!v) { console.error(`Missing env var: ${k}`); process.exit(1); }
}

const CUSTOM_PRICE = 650; // L.E per custom cap
const pool = new Pool({ connectionString: DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } });
const mailer = SMTP_HOST ? nodemailer.createTransport({ host: SMTP_HOST, port: +(SMTP_PORT || 587), secure: +(SMTP_PORT || 587) === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } }) : null;

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const wrap = f => (q, s, n) => f(q, s, n).catch(e => {
  if (!e.status) console.error(e);
  s.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' });
});
const auth = role => (q, s, n) => {
  try { q.user = jwt.verify((q.headers.authorization || '').slice(7), JWT_SECRET); }
  catch { return s.status(401).json({ error: 'Please log in' }); }
  if (role && q.user.role !== role) return s.status(403).json({ error: 'Not allowed' });
  n();
};
const hits = new Map();
const limit = (max, ms) => (q, s, n) => {
  const k = q.ip + q.path, t = Date.now(), a = (hits.get(k) || []).filter(x => t - x < ms);
  a.push(t); hits.set(k, a);
  a.length > max ? s.status(429).json({ error: 'Too many attempts. Try again later.' }) : n();
};
const token = u => jwt.sign({ id: u.id, username: u.username, role: u.role }, JWT_SECRET, { expiresIn: '7d' });
const hashCode = (email, code) => crypto.createHmac('sha256', JWT_SECRET).update(email + code).digest('hex');

// ---------- Auth ----------
app.post('/api/signup', limit(8, 600000), wrap(async (q, s) => {
  const username = String(q.body.username || '').trim().toLowerCase();
  const email = String(q.body.email || '').trim().toLowerCase();
  const password = String(q.body.password || '');
  if (!/^[a-z0-9_]{3,20}$/.test(username)) fail(400, 'Username must be 3-20 letters, numbers or _');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'Enter a valid email address');
  if (password.length < 8) fail(400, 'Password must be at least 8 characters');
  const dup = await pool.query('select 1 from users where username=$1 or email=$2', [username, email]);
  if (dup.rowCount) fail(409, 'Username or email is already registered');
  const code = String(crypto.randomInt(100000, 1000000));
  await pool.query(
    `insert into pending(email,username,pass_hash,code_hash,expires,attempts) values($1,$2,$3,$4,now()+interval '10 minutes',0)
     on conflict(email) do update set username=$2,pass_hash=$3,code_hash=$4,expires=now()+interval '10 minutes',attempts=0`,
    [email, username, await bcrypt.hash(password, 10), hashCode(email, code)]);
  if (mailer) {
    try {
      await mailer.sendMail({ from: MAIL_FROM || SMTP_USER, to: email, subject: 'Your ASAD verification code',
        text: `Your ASAD verification code is ${code}. It expires in 10 minutes.` });
    } catch (e) { console.error(e); fail(502, 'Could not send the verification email. Try again.'); }
  } else if (process.env.NODE_ENV !== 'production') console.log(`[dev] OTP for ${email}: ${code}`);
  else fail(500, 'Email service is not configured');
  s.json({ ok: true });
}));

app.post('/api/verify', limit(15, 600000), wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase(), code = String(q.body.code || '').trim();
  const { rows: [p] } = await pool.query('select * from pending where email=$1', [email]);
  if (!p || new Date(p.expires) < new Date()) fail(400, 'Code expired. Sign up again.');
  if (p.attempts >= 5) fail(429, 'Too many wrong codes. Sign up again.');
  if (hashCode(email, code) !== p.code_hash) {
    await pool.query('update pending set attempts=attempts+1 where email=$1', [email]);
    fail(400, 'Wrong code');
  }
  const { rows: [u] } = await pool.query(
    `insert into users(username,email,pass_hash,role) values($1,$2,$3,'customer') returning id,username,role`,
    [p.username, email, p.pass_hash]).catch(() => fail(409, 'Account already exists'));
  await pool.query('delete from pending where email=$1', [email]);
  s.json({ token: token(u), user: { username: u.username, role: u.role } });
}));

app.post('/api/login', limit(10, 600000), wrap(async (q, s) => {
  const username = String(q.body.username || '').trim().toLowerCase();
  const { rows: [u] } = await pool.query('select * from users where username=$1 or email=$1', [username]);
  if (!u || !(await bcrypt.compare(String(q.body.password || ''), u.pass_hash))) fail(401, 'Wrong username or password');
  s.json({ token: token(u), user: { username: u.username, role: u.role } });
}));

app.get('/api/me', auth(), (q, s) => s.json({ username: q.user.username, role: q.user.role }));

// ---------- Products ----------
app.get('/api/products', auth(), wrap(async (q, s) => {
  s.json((await pool.query('select id,name,price,image_url,design from products order by id')).rows);
}));

app.post('/api/products', auth('admin'), wrap(async (q, s) => {
  const { name, price, image_url, design } = q.body;
  const p = Math.floor(+price);
  if (!name || String(name).length > 80) fail(400, 'Enter a product name');
  if (!(p > 0 && p < 1000000)) fail(400, 'Enter a valid price in L.E');
  if (image_url && !/^https:\/\/\S+$/.test(image_url)) fail(400, 'Image link must start with https://');
  const d = design || {};
  if (!/^#[0-9a-f]{6}$/i.test(d.color || '')) fail(400, 'Pick a cap color');
  const clean = { color: d.color, front: String(d.front || '').slice(0, 18), thread: /^#[0-9a-f]{6}$/i.test(d.thread || '') ? d.thread : null };
  const { rows: [r] } = await pool.query('insert into products(name,price,image_url,design) values($1,$2,$3,$4) returning *',
    [String(name).trim(), p, image_url || null, clean]);
  s.json(r);
}));

// ---------- Orders ----------
app.post('/api/orders', auth(), limit(20, 600000), wrap(async (q, s) => {
  const { items, phone, address } = q.body;
  if (!Array.isArray(items) || !items.length || items.length > 30) fail(400, 'Your cart is empty');
  if (!/^[0-9+ ]{8,15}$/.test(phone || '')) fail(400, 'Enter a valid phone number');
  if (!address || address.length < 5 || address.length > 300) fail(400, 'Enter your delivery address');
  const { rows: ps } = await pool.query('select id,name,price from products');
  let total = 0; const out = [];
  for (const it of items) {
    const qty = Math.floor(it.qty);
    if (!(qty >= 1 && qty <= 20)) fail(400, 'Invalid quantity');
    if (it.type === 'product') {
      const p = ps.find(x => x.id === it.id); if (!p) fail(400, 'A product in your cart is no longer available');
      out.push({ name: p.name, unit: p.price, qty }); total += p.price * qty;
    } else if (it.type === 'custom') {
      if (!/^#[0-9a-f]{6}$/i.test(it.color || '') || String(it.front || '').length > 18 || String(it.back || '').length > 18) fail(400, 'Invalid custom cap');
      out.push({ name: 'ASAD custom cap', color: it.color, front: String(it.front || ''), back: String(it.back || ''), unit: CUSTOM_PRICE, qty });
      total += CUSTOM_PRICE * qty;
    } else fail(400, 'Invalid item');
  }
  const { rows: [o] } = await pool.query('insert into orders(user_id,items,total,phone,address) values($1,$2,$3,$4,$5) returning id,total',
    [q.user.id, JSON.stringify(out), total, phone, address.trim()]);
  s.json(o);
}));

// ---------- Admin ----------
app.get('/api/admin/summary', auth('admin'), wrap(async (q, s) => {
  const users = (await pool.query('select id,username,email,role,created_at from users order by id desc')).rows;
  const orders = (await pool.query('select o.id,u.username,o.items,o.total,o.phone,o.address,o.created_at from orders o join users u on u.id=o.user_id order by o.id desc')).rows;
  s.json({ users, orders, sales: orders.reduce((a, o) => a + o.total, 0) });
}));

// ---------- Boot ----------
async function init() {
  await pool.query(`
    create table if not exists users(id serial primary key, username text unique not null, email text unique not null, pass_hash text not null, role text not null default 'customer', created_at timestamptz default now());
    create table if not exists pending(email text primary key, username text not null, pass_hash text not null, code_hash text not null, expires timestamptz not null, attempts int default 0);
    create table if not exists products(id serial primary key, name text not null, price int not null, image_url text, design jsonb not null, created_at timestamptz default now());
    create table if not exists orders(id serial primary key, user_id int references users(id), items jsonb not null, total int not null, phone text, address text, created_at timestamptz default now());`);
  await pool.query(
    `insert into users(username,email,pass_hash,role) values($1,$2,$3,'admin')
     on conflict(username) do update set pass_hash=$3,email=$2,role='admin'`,
    [ADMIN_USER.toLowerCase(), ADMIN_EMAIL.toLowerCase(), await bcrypt.hash(ADMIN_PASS, 10)]);
  if (!(await pool.query('select 1 from products limit 1')).rowCount) {
    const seed = [
      ['ASAD Claw Cap - Black', 450, { color: '#161616', front: '', arabic: 'أسد', claw: 'front', thread: '#d11a2a' }],
      ['ASAD "MIND ABOVE." Cap - Grey', 400, { color: '#8e8e8e', front: 'MIND ABOVE.', thread: '#f4f4f2' }],
      ['ASAD Red Embroidery Cap - Grey', 450, { color: '#8e8e8e', front: 'ASAD', claw: 'side', thread: '#d11a2a' }]
    ];
    for (const [n, p, d] of seed) await pool.query('insert into products(name,price,design) values($1,$2,$3)', [n, p, d]);
  }
}
const port = process.env.PORT || 3000;
init().then(() => app.listen(port, () => console.log(`ASAD running on :${port}`))).catch(e => { console.error(e); process.exit(1); });
