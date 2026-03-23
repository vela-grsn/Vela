// ============================================================
// VELA — Complete Backend Server
// Run your whole life.
// Powered by Grassion
//
// HOW TO USE:
// 1. Upload this file to GitHub as: server.js
// 2. Deploy repo on Railway
// 3. Add env variables in Railway Variables tab
// ============================================================

const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));

// ============================================================
// DATABASE CONNECTION
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ============================================================
// DATABASE SCHEMA — Paste this in Supabase SQL Editor once
// ============================================================
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  plan VARCHAR(20) DEFAULT 'trial',
  trial_start BIGINT,
  fcm_token TEXT,
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  last_active TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS units (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  start_time TIMESTAMP,
  end_time TIMESTAMP,
  deadline TIMESTAMP,
  duration_minutes INTEGER,
  recurrence_rule JSONB,
  priority INTEGER DEFAULT 3,
  status VARCHAR(30) DEFAULT 'active',
  is_important BOOLEAN DEFAULT false,
  bubble_alert BOOLEAN DEFAULT false,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications_queue (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  unit_id UUID REFERENCES units(id) ON DELETE CASCADE,
  trigger_time TIMESTAMP NOT NULL,
  type VARCHAR(30) NOT NULL,
  title VARCHAR(500),
  body TEXT,
  status VARCHAR(20) DEFAULT 'pending',
  sent_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS budget_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(100),
  amount DECIMAL(12,2) NOT NULL,
  type VARCHAR(20) DEFAULT 'expense',
  bill_due_date INTEGER,
  is_recurring BOOLEAN DEFAULT false,
  paid BOOLEAN DEFAULT false,
  month INTEGER,
  year INTEGER,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS health_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(20) NOT NULL,
  amount INTEGER,
  calories INTEGER,
  food_name VARCHAR(255),
  meal_type VARCHAR(20),
  logged_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_vault (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  site_name VARCHAR(255) NOT NULL,
  username VARCHAR(255),
  encrypted_password TEXT NOT NULL,
  icon VARCHAR(10),
  notes TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analytics_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  action VARCHAR(50) NOT NULL,
  unit_type VARCHAR(50),
  metadata JSONB DEFAULT '{}',
  timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  plan VARCHAR(20) NOT NULL,
  razorpay_payment_id VARCHAR(255),
  status VARCHAR(20) DEFAULT 'active',
  amount_paid DECIMAL(10,2),
  started_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_units_user ON units(user_id);
CREATE INDEX IF NOT EXISTS idx_units_type ON units(type);
CREATE INDEX IF NOT EXISTS idx_units_status ON units(status);
CREATE INDEX IF NOT EXISTS idx_notif_trigger ON notifications_queue(trigger_time, status);
CREATE INDEX IF NOT EXISTS idx_analytics_user ON analytics_events(user_id, timestamp);
`;

async function initDB() {
  try {
    await pool.query(SCHEMA);
    console.log('✅ VELA Database ready');
  } catch (err) {
    console.error('DB init error:', err.message);
  }
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET || 'VelaGrassion2026SecretKey_ChangeThis';

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.plan !== 'admin' && req.user.email !== process.env.ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const trialStart = Date.now();
    
    // Check if this is the admin email — give admin plan
    const plan = email === process.env.ADMIN_EMAIL ? 'admin' : 'trial';
    
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, plan, trial_start) VALUES ($1,$2,$3,$4,$5) RETURNING id, name, email, plan',
      [name, email, hash, plan, trialStart]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan }, JWT_SECRET, { expiresIn: '30d' });
    
    await pool.query('INSERT INTO analytics_events (user_id, action) VALUES ($1,$2)', [user.id, 'signup']);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    
    await pool.query('UPDATE users SET last_active=NOW() WHERE id=$1', [user.id]);
    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, trial_start: user.trial_start } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const result = await pool.query('SELECT id, name, email, plan, trial_start, settings, created_at FROM users WHERE id=$1', [req.user.id]);
  res.json(result.rows[0]);
});

// ============================================================
// MAKE YOURSELF ADMIN — call once with your email
// ============================================================
app.post('/api/auth/make-admin', auth, adminOnly, async (req, res) => {
  const { target_email } = req.body;
  await pool.query("UPDATE users SET plan='admin' WHERE email=$1", [target_email]);
  res.json({ success: true, message: target_email + ' is now admin forever' });
});

// ============================================================
// UNITS — The core of everything
// ============================================================
app.get('/api/units', auth, async (req, res) => {
  const { type, status } = req.query;
  let q = 'SELECT * FROM units WHERE user_id=$1';
  const params = [req.user.id];
  let i = 2;
  if (type) { q += ` AND type=$${i++}`; params.push(type); }
  if (status) { q += ` AND status=$${i++}`; params.push(status); }
  q += ' ORDER BY start_time ASC NULLS LAST, created_at DESC';
  const result = await pool.query(q, params);
  res.json(result.rows);
});

app.get('/api/units/today', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM units WHERE user_id=$1 AND (DATE(start_time)=CURRENT_DATE OR (deadline>=NOW() AND status='active')) AND status!='archived' ORDER BY start_time ASC NULLS LAST`,
    [req.user.id]
  );
  res.json(result.rows);
});

app.post('/api/units', auth, async (req, res) => {
  const { type, title, description, start_time, end_time, deadline, duration_minutes, recurrence_rule, priority, is_important, bubble_alert, metadata } = req.body;
  const result = await pool.query(
    `INSERT INTO units (user_id,type,title,description,start_time,end_time,deadline,duration_minutes,recurrence_rule,priority,is_important,bubble_alert,metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [req.user.id, type, title, description, start_time, end_time, deadline, duration_minutes, recurrence_rule, priority||3, is_important||false, bubble_alert||false, metadata||{}]
  );
  const unit = result.rows[0];
  await scheduleNotifs(unit, req.user.id);
  await pool.query('INSERT INTO analytics_events (user_id,action,unit_type,unit_id) VALUES ($1,$2,$3,$4)', [req.user.id, 'created', type, unit.id]);
  res.json(unit);
});

app.put('/api/units/:id', auth, async (req, res) => {
  const updates = req.body;
  const fields = Object.keys(updates).filter(k => !['id','user_id','created_at'].includes(k));
  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });
  const setClause = fields.map((f,i) => `${f}=$${i+2}`).join(', ');
  const result = await pool.query(
    `UPDATE units SET ${setClause}, updated_at=NOW() WHERE id=$1 AND user_id='${req.user.id}' RETURNING *`,
    [req.params.id, ...fields.map(f => updates[f])]
  );
  res.json(result.rows[0]);
});

app.patch('/api/units/:id/complete', auth, async (req, res) => {
  const result = await pool.query("UPDATE units SET status='completed',updated_at=NOW() WHERE id=$1 AND user_id=$2 RETURNING *", [req.params.id, req.user.id]);
  await pool.query('INSERT INTO analytics_events (user_id,action,unit_type,unit_id) VALUES ($1,$2,$3,$4)', [req.user.id, 'completed', result.rows[0]?.type, req.params.id]);
  res.json(result.rows[0]);
});

app.delete('/api/units/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM units WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ============================================================
// NOTIFICATION ENGINE
// ============================================================
async function scheduleNotifs(unit, userId) {
  const notifs = [];
  const now = new Date();

  // Competitions — 4 alerts, 2 days before deadline
  if (unit.type === 'competition' && unit.deadline) {
    const dl = new Date(unit.deadline);
    const twoDays = new Date(dl.getTime() - 2*24*60*60*1000);
    for (let i = 0; i < 4; i++) {
      notifs.push({ time: new Date(twoDays.getTime() + i*3*60*60*1000), type: 'urgent', title: `⚡ Competition deadline in 2 days!`, body: unit.title });
    }
    notifs.push({ time: new Date(dl.getTime() - 24*60*60*1000), type: 'push', title: `🔴 Last day: ${unit.title}`, body: 'Deadline is tomorrow!' });
    notifs.push({ time: new Date(dl.getTime() - 2*60*60*1000), type: 'urgent', title: `🚨 FINAL HOURS: ${unit.title}`, body: 'Deadline in 2 hours!' });
  }

  // Meetings — 1hr + 10min before
  if ((unit.type === 'meeting' || unit.type === 'events') && unit.start_time) {
    const start = new Date(unit.start_time);
    notifs.push({ time: new Date(start.getTime() - 60*60*1000), type: 'push', title: `💼 Meeting in 1 hour`, body: unit.title });
    notifs.push({ time: new Date(start.getTime() - 10*60*1000), type: 'push', title: `⚡ Meeting in 10 minutes`, body: unit.title });
  }

  // Floating bubble — 15min before any important event
  if (unit.bubble_alert && unit.start_time) {
    const start = new Date(unit.start_time);
    notifs.push({ time: new Date(start.getTime() - 15*60*1000), type: 'bubble', title: unit.title, body: 'Starting in 15 minutes' });
  }

  // Food expiry — daily reminder
  if (unit.type === 'food' && unit.metadata?.expiry_date) {
    const expiry = new Date(unit.metadata.expiry_date);
    for (let d = 3; d >= 0; d--) {
      const t = new Date(expiry.getTime() - d*24*60*60*1000);
      t.setHours(9,0,0,0);
      if (t > now) notifs.push({ time: t, type: 'soft', title: `🥘 Use ${unit.title} today`, body: unit.metadata.meal_idea || 'Before it expires!' });
    }
  }

  // Birthdays
  if (unit.type === 'birthday' && unit.start_time) {
    const bday = new Date(unit.start_time);
    bday.setHours(8,0,0,0);
    if (bday > now) notifs.push({ time: bday, type: 'push', title: `🎂 ${unit.title}'s birthday today!`, body: "Don't forget to wish them!" });
  }

  // Bills due
  if (unit.type === 'bill' && unit.metadata?.due_date) {
    const due = new Date(unit.metadata.due_date);
    const reminder = new Date(due.getTime() - 3*24*60*60*1000);
    reminder.setHours(9,0,0,0);
    if (reminder > now) notifs.push({ time: reminder, type: 'push', title: `💳 Bill due in 3 days`, body: `${unit.title} — ₹${unit.metadata.amount}` });
  }

  for (const n of notifs) {
    if (n.time > now) {
      await pool.query(
        'INSERT INTO notifications_queue (user_id,unit_id,trigger_time,type,title,body) VALUES ($1,$2,$3,$4,$5,$6)',
        [userId, unit.id, n.time, n.type, n.title, n.body]
      );
    }
  }
}

// ============================================================
// CRON — Send pending notifications every minute
// ============================================================
cron.schedule('* * * * *', async () => {
  try {
    const due = await pool.query(`SELECT n.*, u.fcm_token FROM notifications_queue n JOIN users u ON n.user_id=u.id WHERE n.trigger_time<=NOW() AND n.status='pending' LIMIT 100`);
    for (const n of due.rows) {
      if (n.fcm_token) await sendFCM(n.fcm_token, n.title, n.body, n.type);
      await pool.query("UPDATE notifications_queue SET status='sent',sent_at=NOW() WHERE id=$1", [n.id]);
    }
  } catch (err) {
    console.error('Notification cron error:', err.message);
  }
});

async function sendFCM(token, title, body, type) {
  // Plug in Firebase Admin SDK when ready:
  // const admin = require('firebase-admin');
  // await admin.messaging().send({ token, notification: { title, body }, data: { type } });
  console.log(`📲 FCM → ${title}: ${body}`);
}

// ============================================================
// BUDGET ROUTES
// ============================================================
app.get('/api/budget', auth, async (req, res) => {
  const now = new Date();
  const result = await pool.query('SELECT * FROM budget_items WHERE user_id=$1 AND (month=$2 OR month IS NULL) ORDER BY created_at DESC', [req.user.id, now.getMonth()+1]);
  res.json(result.rows);
});

app.post('/api/budget', auth, async (req, res) => {
  const { name, category, amount, type, bill_due_date, is_recurring } = req.body;
  const now = new Date();
  const result = await pool.query(
    'INSERT INTO budget_items (user_id,name,category,amount,type,bill_due_date,is_recurring,month,year) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
    [req.user.id, name, category, amount, type||'expense', bill_due_date, is_recurring||false, now.getMonth()+1, now.getFullYear()]
  );
  res.json(result.rows[0]);
});

app.patch('/api/budget/:id/paid', auth, async (req, res) => {
  const result = await pool.query('UPDATE budget_items SET paid=true WHERE id=$1 AND user_id=$2 RETURNING *', [req.params.id, req.user.id]);
  res.json(result.rows[0]);
});

// ============================================================
// HEALTH ROUTES
// ============================================================
app.get('/api/health/logs', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM health_logs WHERE user_id=$1 AND DATE(logged_at)=CURRENT_DATE ORDER BY logged_at DESC', [req.user.id]);
  res.json(result.rows);
});

app.post('/api/health/log', auth, async (req, res) => {
  const { type, amount, calories, food_name, meal_type } = req.body;
  const result = await pool.query(
    'INSERT INTO health_logs (user_id,type,amount,calories,food_name,meal_type) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [req.user.id, type, amount, calories, food_name, meal_type]
  );
  res.json(result.rows[0]);
});

// ============================================================
// PASSWORD VAULT
// ============================================================
app.get('/api/vault', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM password_vault WHERE user_id=$1 ORDER BY site_name', [req.user.id]);
  res.json(result.rows);
});

app.post('/api/vault', auth, async (req, res) => {
  const { site_name, username, encrypted_password, icon, notes } = req.body;
  const result = await pool.query(
    'INSERT INTO password_vault (user_id,site_name,username,encrypted_password,icon,notes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [req.user.id, site_name, username, encrypted_password, icon, notes]
  );
  res.json(result.rows[0]);
});

app.delete('/api/vault/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM password_vault WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ============================================================
// PAYMENTS — RAZORPAY
// ============================================================
app.post('/api/payments/create-order', auth, async (req, res) => {
  const { plan } = req.body;
  const prices = { monthly: 29900, annual: 199900 };

  // When Razorpay keys are added, uncomment:
  // const Razorpay = require('razorpay');
  // const rz = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
  // const order = await rz.orders.create({ amount: prices[plan], currency: 'INR', receipt: uuidv4() });

  const order = { id: 'order_test_' + Date.now(), amount: prices[plan] || 29900, currency: 'INR' };
  res.json({ order, key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder' });
});

app.post('/api/payments/verify', auth, async (req, res) => {
  const { razorpay_payment_id, plan } = req.body;
  const expires = plan === 'annual'
    ? new Date(Date.now() + 365*24*60*60*1000)
    : new Date(Date.now() + 30*24*60*60*1000);
  await pool.query("UPDATE users SET plan='premium' WHERE id=$1", [req.user.id]);
  await pool.query('INSERT INTO subscriptions (user_id,plan,razorpay_payment_id,expires_at) VALUES ($1,$2,$3,$4)', [req.user.id, plan, razorpay_payment_id, expires]);
  res.json({ success: true });
});

// ============================================================
// FCM TOKEN
// ============================================================
app.post('/api/user/fcm-token', auth, async (req, res) => {
  await pool.query('UPDATE users SET fcm_token=$1 WHERE id=$2', [req.body.token, req.user.id]);
  res.json({ success: true });
});

// ============================================================
// SETTINGS
// ============================================================
app.put('/api/user/settings', auth, async (req, res) => {
  await pool.query('UPDATE users SET settings=$1 WHERE id=$2', [req.body, req.user.id]);
  res.json({ success: true });
});

// ============================================================
// ANALYTICS
// ============================================================
app.get('/api/analytics/summary', auth, async (req, res) => {
  const [stats, byType] = await Promise.all([
    pool.query(`SELECT COUNT(*) FILTER(WHERE status='completed') as completed, COUNT(*) FILTER(WHERE status='missed') as missed, COUNT(*) as total FROM units WHERE user_id=$1 AND created_at>=NOW()-INTERVAL '30 days'`, [req.user.id]),
    pool.query('SELECT type, COUNT(*) as count FROM units WHERE user_id=$1 GROUP BY type', [req.user.id])
  ]);
  const s = stats.rows[0];
  res.json({
    completion_rate: s.total > 0 ? Math.round((s.completed/s.total)*100) : 0,
    completed: parseInt(s.completed),
    missed: parseInt(s.missed),
    total: parseInt(s.total),
    by_type: byType.rows
  });
});

// ============================================================
// ADMIN PANEL
// ============================================================
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  const [users, active, revenue, features, recent] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM users'),
    pool.query("SELECT COUNT(*) FROM users WHERE last_active>=NOW()-INTERVAL '24 hours'"),
    pool.query("SELECT COALESCE(SUM(amount_paid),0) as mrr FROM subscriptions WHERE started_at>=DATE_TRUNC('month',NOW())"),
    pool.query('SELECT type, COUNT(*) as count FROM units GROUP BY type ORDER BY count DESC'),
    pool.query('SELECT id,name,email,plan,created_at,last_active FROM users ORDER BY created_at DESC LIMIT 20'),
  ]);
  res.json({
    total_users: parseInt(users.rows[0].count),
    active_today: parseInt(active.rows[0].count),
    mrr: parseFloat(revenue.rows[0].mrr),
    feature_usage: features.rows,
    recent_signups: recent.rows
  });
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { search, limit=50 } = req.query;
  let q = 'SELECT id,name,email,plan,created_at,last_active FROM users';
  const params = [];
  if (search) { q += ' WHERE name ILIKE $1 OR email ILIKE $1'; params.push(`%${search}%`); }
  q += ` ORDER BY created_at DESC LIMIT ${limit}`;
  const result = await pool.query(q, params);
  res.json(result.rows);
});

app.patch('/api/admin/users/:id/plan', auth, adminOnly, async (req, res) => {
  await pool.query('UPDATE users SET plan=$1 WHERE id=$2', [req.body.plan, req.params.id]);
  res.json({ success: true });
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'VELA', version: '1.0.0', powered_by: 'Grassion' }));
app.get('/', (req, res) => res.json({ app: 'VELA Backend', tagline: 'Run your whole life.', status: 'running' }));

// ============================================================
// START SERVER
// ============================================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, async () => {
  await initDB();
  console.log(`🚀 VELA Backend running on port ${PORT}`);
  console.log(`💜 Run your whole life. | Powered by Grassion`);
});

module.exports = app;
